// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package ipv6

/*
  MLD and MLDv2
  Supports
    1. Exclude {}, meaning include all (*) all sources
	2. Include a vector of sources of address, the API is [(s1,g),(s2,g)] meaning include to mc-group g a source s1 and s2

	scale:
	  1. unlimited number of groups
      2. ~1k sources per group (in case of INCLUDE)
*/

import (
	"bytes"
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sort"
	"unsafe"
)

const (
	MLD_VERSION_1                  = 1
	MLD_VERSION_2                  = 2
	IGMP_TYPE_DVMRP                = 0x13
	IGMP_HEADER_MINLEN             = 8
	MLD_V2_QUERY_MINLEN            = 8 + 16 + 4
	MLD_QUERY_MINLEN               = 8 + 16
	MLD_REPORT_MINLEN              = 8 + 16 + 4
	MLD_SRC_SIZE                   = 16
	IGMP_MC_ADDR_MASK              = 0xE0000000
	IGMP_MC_DEST_HOST              = 0xE0000001
	IGMP_NULL_HOST                 = 0x00000000
	MLD_GRPREC_HDRLEN              = 4 + 16
	MLD_QUERY_ADDR                 = 16
	IGMP_DO_NOTHING                = 0    /* don't send a record */
	IGMP_MODE_IS_INCLUDE           = 1    /* MODE_IN */
	IGMP_MODE_IS_EXCLUDE           = 2    /* MODE_EX */
	IGMP_CHANGE_TO_INCLUDE_MODE    = 3    /* TO_IN */
	IGMP_CHANGE_TO_EXCLUDE_MODE    = 4    /* TO_EX */
	IGMP_ALLOW_NEW_SOURCES         = 5    /* ALLOW_NEW */
	IGMP_BLOCK_OLD_SOURCES         = 6    /* BLOCK_OLD */
	IGMP_HOST_LEAVE_MESSAGE        = 0x17 /* Leave-group message     */
	IGMP_v2_HOST_MEMBERSHIP_REPORT = 0x16 /* Ver. 2 membership report */
	IPV6_HEADER_SIZE               = 40
	IPV6_OPTION_ROUTER             = 8 /* plus router alert */
)

type MldNsInit struct {
	Mtu           uint16         `json:"mtu" validate:"gte=256,lte=9000"`
	DesignatorMac core.MACKey    `json:"dmac"`
	Vec           []core.Ipv6Key `json:"vec"`     // add mc
	Version       uint16         `json:"version"` // the init version, 1 or 2 (default)
}

var IN6_IS_ADDR_UNSPECIFIED = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var MLD2_RESPONSE_ADDR = []byte{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16}
var MLD1_ALL_ROUTERS = []byte{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}

// return ticks (not in time), burst each tick , bool
// if ticks is zero it is only one shut
//
// totalrecords: total number of records to send
// recordPerPacket: maximum records per packet
// intervalMsec: total time in msec to spread the total records
// minTickMsc: the min ticks in msec
// maxPPS: max pps alowed
// return:
// timerTick: howmany ticks each interval(min tickMsec)- 0 mean we have one shut and 1 packet to send
// pktsPerTick : how many packets (maximum recordPerPacket) should be sent every timer
// breachMaxRate: true of false. in case it is true the rate won't breach the rate
func calcTimerInfo(totalrecords uint32,
	recordPerPacket uint32,
	intervalMsec uint32,
	minTickMsec uint32,
	maxPPS uint32) (timerticks uint32, pktsPerTick uint32, breachMaxRate bool) {

	if recordPerPacket > totalrecords {
		return 0, 1, false
	}

	bursts := float32(totalrecords) / float32(recordPerPacket)

	tickMs := float32(intervalMsec) / (bursts)

	ticks := tickMs / float32(minTickMsec)

	if ticks > 1.0 {

		timerticks = uint32(math.Floor(float64(ticks)))
		pktsPerTick = 1
		breachMaxRate = false
	} else {
		factor := float32(math.Round(1.0/float64(ticks) + 0.5))
		PPS := factor * 1000.0 / float32(minTickMsec)
		if PPS > float32(maxPPS) {
			factor *= float32(maxPPS) / PPS
			factor := float32(factor - 0.5)
			if factor < 1.0 {
				factor = 1.0
			}
			breachMaxRate = true
		}
		timerticks = 1
		pktsPerTick = uint32(factor)
	}
	return timerticks, pktsPerTick, breachMaxRate
}

type MldSGRecord struct {
	G core.Ipv6Key `json:"g"`
	S core.Ipv6Key `json:"s"`
}

type mldNsStats struct {
	pktRxTotal    uint64
	pktRxTooshort uint64
	pktRxBadttl   uint64
	pktRxBadsum   uint64
	pktRxNoKey    uint64
	/*
	* Query statistics.
	 */
	pktRxv1Queries         uint64
	pktRxv2Queries         uint64
	pktRxbadQueries        uint64
	pktRxgenQueries        uint64
	pktRxgroupQueries      uint64
	pktRxgsrQueries        uint64
	pktRxgsrDropQueries    uint64
	pktRxquerieActiveTimer uint64

	/*
	* Report statistics.
	 */
	pktRxReports              uint64 /* received membership reports */
	pktRxNora                 uint64 /* received w/o Router Alert option */
	pktRxSndReports           uint64 /* sent membership reports */
	pktSndAddRemoveReports    uint64 /* explicit reports dur to add/remove command */
	pktNoDesignatorClient     uint64 /* There is no designator client with this MAC addr */
	pktNoDesignatorClientIPv6 uint64 /* there designator client does not have valid IPv4 addr */

	opsAdd       uint64 /* add mc addr*/
	opsRemove    uint64 /* add mc addr*/
	opsAddErr    uint64
	opsRemoveErr uint64

	opsRateIsTooHigh uint64

	opsAddSG       uint64 /* add mc (s,g)*/
	opsRemoveSG    uint64 /* remove mc (s,g)*/
	opsAddErrSG    uint64 /* add erro (s,g) */
	opsRemoveErrSG uint64 /* emove error (s,g)*/

	pktRxSndReportsSGChangeToInclude uint64 /* sent change to include state */ /*TBD*/
	pktRxSndReportsSGAdd             uint64
	pktRxSndReportsSGRemove          uint64
	pktRxSndReportsSGQuery           uint64
}

func NewMldNsStatsDb(o *mldNsStats) *core.CCounterDb {
	db := core.NewCCounterDb("mld")

	db.Add(&core.CCounterRec{
		Counter:  &o.opsAddSG,
		Name:     "opsAddSG",
		Help:     "add mc (s,g) ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsRemoveSG,
		Name:     "opsRemoveSG",
		Help:     "remove mc (s,g) ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsAddErrSG,
		Name:     "opsAddErrSG",
		Help:     "error add mc (s,g) ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsRemoveErrSG,
		Name:     "opsRemoveErrSG",
		Help:     "error remove mc (s,g) ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSndReportsSGQuery,
		Name:     "pktRxSndReportsSGQuery",
		Help:     "(s,g)- query records",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSndReportsSGRemove,
		Name:     "pktRxSndReportsSGRemove",
		Help:     "(s,g)- remove records",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSndReportsSGAdd,
		Name:     "pktRxSndReportsSGAdd",
		Help:     "(s,g)- add records",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSndReportsSGChangeToInclude,
		Name:     "pktRxSndReportsSGChangeToInclude",
		Help:     "(s,g)- change to include",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxTotal,
		Name:     "pktRxTotal",
		Help:     "total messages received",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxTooshort,
		Name:     "pktRxTooshort",
		Help:     "received with too few bytes",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadttl,
		Name:     "pktRxBadttl",
		Help:     "received with ttl other than 1",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadsum,
		Name:     "pktRxBadsum",
		Help:     "received with bad checksum",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNoKey,
		Name:     "pktRxNoKey",
		Help:     "received mld but can't find port,vlan keys",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxv1Queries,
		Name:     "pktRxv1Queries",
		Help:     "received MLD queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxv2Queries,
		Name:     "pktRxv2Queries",
		Help:     "received IGMPv2 queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxbadQueries,
		Name:     "pktRxbadQueries",
		Help:     "received invalid queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxgenQueries,
		Name:     "pktRxgenQueries",
		Help:     "received general queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxgroupQueries,
		Name:     "pktRxgroupQueries",
		Help:     "received group queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxgsrQueries,
		Name:     "pktRxgsrQueries",
		Help:     "received group-source queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxgsrDropQueries,
		Name:     "pktRxgsrDropQueries",
		Help:     "dropped group-source queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxquerieActiveTimer,
		Name:     "pktRxquerieActiveTimer",
		Help:     "rcv querie while active timer",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxReports,
		Name:     "pktRxReports",
		Help:     "received membership reports",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNora,
		Name:     "pktRxNora",
		Help:     "received w/o Router Alert option ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktSndAddRemoveReports,
		Name:     "pktSndAddRemoveReports",
		Help:     "explicit reports due to add/remove command",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSndReports,
		Name:     "pktRxSndReports",
		Help:     "sent membership reports",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsAdd,
		Name:     "opsAdd",
		Help:     "add mc ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsRemove,
		Name:     "opsRemove",
		Help:     "remove mc ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsAddErr,
		Name:     "opsAddErr",
		Help:     "add mc with error",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsRemoveErr,
		Name:     "opsRemoveErr",
		Help:     "remove mc with error ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktNoDesignatorClient,
		Name:     "pktNoDesignatorClient",
		Help:     "No designator client was defined. MLD will not work without it",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktNoDesignatorClientIPv6,
		Name:     "pktNoDesignatorClientIPv6",
		Help:     "no designator client with this valid IPv4 addr ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.opsRateIsTooHigh,
		Name:     "opsRateIsTooHigh",
		Help:     "rate of multicast is too high, duration should be higher",
		Unit:     "opts",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

func covertToIgmpEntry(dlist *core.DList) *MldEntry {
	return (*MldEntry)(unsafe.Pointer(dlist))
}

type MapMldS map[core.Ipv6Key]bool

const (
	MLD_ENTRY_MODE_INCLUDE_ALL = 1 // mode EXCLUDE {}, (*)
	MLD_ENTRY_MODE_INCLUDE_S   = 2 // include [s1,s2,s3]
)

type MldEntryDataJson struct {
	Ipv6       core.Ipv6Key    `json:"ipv6"`
	Management bool            `json:"management"`
	Refc       uint16          `json:"refc"`
	Mode       uint8           `json:"mode"`
	S          *[]core.Ipv6Key `json:"sv,omitempty"`
}

//MldEntry includes one ipv6 mc addr. It could be owned by management (rpc) or by external clients (e.g. IPv6 ND)
// external clients will increment the refc while management will use the bool
type MldEntry struct {
	dlist      core.DList // must be first
	Ipv6       core.Ipv6Key
	epocQuery  uint32
	management bool   /* added by management, could not be added twice ref=0, management=1 is for management adding . management=0,ref=1 for clients */
	refc       uint16 /* ref counter for none management clients.  add ref/remove ref*/
	maps       MapMldS
}

func (o *MldEntry) getJson() *MldEntryDataJson {
	var j MldEntryDataJson
	j.Ipv6 = o.Ipv6
	j.Mode = o.getMode()
	j.Refc = o.refc
	j.Management = o.management
	j.S = nil
	if o.getMode() == MLD_ENTRY_MODE_INCLUDE_S {
		j.S = new([]core.Ipv6Key)
		for k := range o.maps {
			*j.S = append(*j.S, k)
		}
	}
	return &j
}

func (o *MldEntry) getMode() uint8 {
	if o.maps == nil {
		return MLD_ENTRY_MODE_INCLUDE_ALL
	} else {
		return MLD_ENTRY_MODE_INCLUDE_S
	}
}

func (o *MldEntry) getSourceVec() []core.Ipv6Key {
	var vec []core.Ipv6Key
	for k := range o.maps {
		vec = append(vec, k)
	}
	return vec
}

// return count, size
func (o *MldEntry) calcNumSources(freePyld uint16, srec uint16) (uint16, uint16) {
	if freePyld < (MLD_V2_QUERY_MINLEN + MLD_SRC_SIZE) {
		return 0, 0
	}
	cnt := (freePyld - MLD_V2_QUERY_MINLEN) / MLD_SRC_SIZE
	if cnt > srec {
		cnt = srec
	}
	size := MLD_V2_QUERY_MINLEN + (cnt * MLD_SRC_SIZE)
	return cnt, size
}

func (o *MldEntry) allocMap() {
	if o.maps == nil {
		o.maps = make(MapMldS)
	}
}

func (o *MldEntry) addSource(ns *core.CNSCtx, s core.Ipv6Key) error {
	if o.getMode() == MLD_ENTRY_MODE_INCLUDE_ALL {
		return fmt.Errorf(" ns:%v can't add source %v for include all g:%v ", ns.Key.StringRpc(), s, o.Ipv6)
	}
	_, ok := o.maps[s]
	if ok {
		return fmt.Errorf(" ns:%v source-ipv6 %v already exist for g: %v", ns.Key.StringRpc(), s, o.Ipv6)
	}
	o.maps[s] = true
	return nil
}

func (o *MldEntry) removeSource(ns *core.CNSCtx, s core.Ipv6Key) error {
	if o.getMode() == MLD_ENTRY_MODE_INCLUDE_ALL {
		return fmt.Errorf(" ns:%v can't add source %v for include all g: %v ", ns.Key.StringRpc(), s, o.Ipv6)
	}
	_, ok := o.maps[s]
	if !ok {
		return fmt.Errorf(" ns:%v source-ipv6 %v does not exist g:%v", ns.Key.StringRpc(), s, o.Ipv6)
	}
	delete(o.maps, s)
	return nil
}

func (o *MldEntryDataJson) SetJson(ent *MldEntry) {
	*o = *ent.getJson()
}

type MapIgmp map[core.Ipv6Key]*MldEntry

//IgmpFlowTbl  map/dlist of the mld entries
type IgmpFlowTbl struct {
	ns         *core.CNSCtx
	mapIgmp    MapIgmp
	head       core.DList
	activeIter *core.DList /* pointer to the next object, in case of active */
	epoc       uint32      /* operation epoc for add/remove/rpc iterator */
	epocQuery  uint32
	stats      *mldNsStats
	sgCount    uint32 // how many entries we have in ICNLUDE (s) state
}

func NewIgmpTable() *IgmpFlowTbl {
	o := new(IgmpFlowTbl)
	var stats mldNsStats
	o.OnCreate(&stats)
	return o
}

func (o *IgmpFlowTbl) incEpocQuery() {
	o.epocQuery++
}

func (o *IgmpFlowTbl) OnCreate(stats *mldNsStats) {
	o.mapIgmp = make(MapIgmp)
	o.head.SetSelf()
	o.activeIter = nil
	o.stats = stats
}

func (o *IgmpFlowTbl) addMcSG(ipv6 core.Ipv6Key, s core.Ipv6Key) (bool, error) {
	r := false
	e, ok := o.mapIgmp[ipv6]
	if ok {
		if e.management != true {
			return r, fmt.Errorf(" ns:%v add(s,g) (%v,%v) should be be added by RPC", o.ns.Key.StringRpc(), s, ipv6)
		}

		if e.getMode() != MLD_ENTRY_MODE_INCLUDE_S {
			return r, fmt.Errorf(" ns:%v add(s,g) (%v,%v) in the wrong mode", o.ns.Key.StringRpc(), s, ipv6)
		}
	} else {
		e = new(MldEntry)
		e.Ipv6 = ipv6
		e.epocQuery = o.epocQuery
		e.allocMap() // create maps
		e.management = true
		o.mapIgmp[ipv6] = e
		o.head.AddLast(&e.dlist)
		r = true
	}
	err1 := e.addSource(o.ns, s)
	if err1 == nil && r {
		o.sgCount++
	}
	return r, err1
}

// remove (G,S)
func (o *IgmpFlowTbl) removeMcSG(ipv6 core.Ipv6Key, s core.Ipv6Key) (bool, error) {
	r := false
	e, ok := o.mapIgmp[ipv6]
	if ok {
		if e.getMode() != MLD_ENTRY_MODE_INCLUDE_S {
			return r, fmt.Errorf(" ns:%v remove(s,g) (%v,%v) in the wrong mode", o.ns.Key.StringRpc(), s, ipv6)
		}
		if e.management != true {
			return r, fmt.Errorf(" ns:%v add(s,g) (%v,%v) should be be added by RPC", o.ns.Key.StringRpc(), s, ipv6)
		}
	} else {
		return r, fmt.Errorf(" ns:%v add(s,g) (%v) group does not exits", o.ns.Key.StringRpc(), ipv6)
	}
	err := e.removeSource(o.ns, s)
	if len(e.maps) == 0 {
		r = true
	}
	return r, err
}

func (o *IgmpFlowTbl) addMc(ipv6 core.Ipv6Key, man bool) (error, bool) {
	obj, ok := o.mapIgmp[ipv6]
	if ok {
		if !man {
			obj.refc++
			return nil, false
		} else {
			if !obj.management {
				obj.management = true
				return nil, false
			} else {
				if obj.getMode() != MLD_ENTRY_MODE_INCLUDE_ALL {
					return fmt.Errorf(" ns:%v mc-ipv6 %v already is in filter mode", o.ns.Key.StringRpc(), ipv6), false
				}
				return fmt.Errorf(" ns:%v mc-ipv6 %v already exist by management", o.ns.Key.StringRpc(), ipv6), false
			}
		}
	}
	// create new entry
	e := new(MldEntry)
	e.Ipv6 = ipv6
	e.epocQuery = o.epocQuery
	o.mapIgmp[ipv6] = e
	if man {
		e.management = true
	} else {
		e.refc = 1
	}
	o.head.AddLast(&e.dlist)
	return nil, true
}

func (o *IgmpFlowTbl) removeMc(ipv6 core.Ipv6Key, man bool) (bool, error) {
	e, ok := o.mapIgmp[ipv6]
	if !ok {
		return false, fmt.Errorf(" ns:%v mc-ipv6 %v does not exist", o.ns.Key.StringRpc(), ipv6)
	}
	if man {
		if !e.management {
			return false, fmt.Errorf(" ns:%v mc-ipv6 %v wasn't added by management and can't be removed", o.ns.Key.StringRpc(), ipv6)

		} else {
			e.management = false
		}
	} else {
		if e.refc > 0 {
			e.refc--
		} else {
			panic(" mld remove without adding from external sources")
		}
	}
	var r bool
	if e.refc == 0 && !e.management {
		r = true
		if e.getMode() == MLD_ENTRY_MODE_INCLUDE_S {
			o.sgCount--
		}
		delete(o.mapIgmp, ipv6)
		/* handle the iterator in case of remove */
		if o.activeIter == &e.dlist {
			// it is going to be removed
			o.activeIter = e.dlist.Next()
		}
		o.head.RemoveNode(&e.dlist)
	}
	return r, nil
}

//dumpAll for debug and testing
func (o *IgmpFlowTbl) dumpAll() {

	var it core.DListIterHead
	cnt := 0
	for it.Init(&o.head); it.IsCont(); it.Next() {
		e := covertToIgmpEntry(it.Val())
		fmt.Printf(" %v:%v:%v:%v \n", cnt, e.Ipv6, e.management, e.refc)
		cnt++
	}
}

type mldPktBuilder struct {
	e        *MldEntry
	freePyld uint16
	maxPyld  uint16
	pktv     []MldEntryDataJson
	group    core.Ipv6Key
	s        []core.Ipv6Key
}

type mldCacheNsTimer struct {
}

func (o *mldCacheNsTimer) OnEvent(a, b interface{}) {
	obj := a.(*mldNsCtx)
	obj.onCacheTimerUpdate(b)
}

type mldNsCtx struct {
	base             *PluginIpv6Ns
	designatorMac    core.MACKey // designator MAC key to client id
	timerw           *core.TimerCtx
	tbl              IgmpFlowTbl
	mldVersion       uint16
	mtu              uint16
	maxresp          uint32 /* in msec  */
	qqi              uint32 /* interval  */
	qrv              uint8  /* qrv */
	activeQuery      bool   /* true in case there is a active query */
	started          bool
	stats            mldNsStats
	timer            core.CHTimerObj
	ticks            uint32
	pktPerTick       uint32
	ipv6pktTemplate  []byte
	ipv6Offset       uint16
	activeEpocQuery  uint32
	rpcIterEpoc      uint32
	iter             core.DListIterHead
	iterReady        bool
	cdb              *core.CCounterDb
	addCacheVec      []core.Ipv6Key
	addTimerCache    core.CHTimerObj // timer for batching add
	addCacheCB       mldCacheNsTimer
	removeCacheVec   []core.Ipv6Key
	removeTimerCache core.CHTimerObj // timer for batching remove
	removeCacheCB    mldCacheNsTimer
}

func (o *mldNsCtx) onCacheTimerUpdate(b interface{}) {
	val := b.(int)
	if val == 0 {
		// add
		o.flushAddCache()
	} else {
		// remove
		o.flushRemoveCache()
	}
}

// on main timer
func (o *mldNsCtx) OnEvent(a, b interface{}) {
	var finish bool
	finish = o.startQueryReport()
	if finish {
		o.activeQuery = false
	} else {
		// restart the timer
		o.timerw.StartTicks(&o.timer, o.ticks)
	}
}

func (o *mldNsCtx) Init(base *PluginIpv6Ns, ctx *core.CThreadCtx, initJson []byte) {
	init := MldNsInit{Mtu: 1500, Version: MLD_VERSION_2}

	if len(initJson) > 0 {
		// init json was provided
		err := ctx.UnmarshalValidate(initJson, &init)
		if err != nil {
			return
		}
	}

	o.base = base
	o.tbl.OnCreate(&o.stats)
	o.tbl.ns = o.base.Ns
	if !init.DesignatorMac.IsZero() {
		o.designatorMac = init.DesignatorMac
	}
	if len(init.Vec) > 0 {
		o.addMc(init.Vec)
	}
	o.mldVersion = init.Version
	o.mtu = init.Mtu
	o.qrv = 2
	o.qqi = 125
	o.maxresp = 10000
	o.timerw = ctx.GetTimerCtx()
	o.timer.SetCB(o, 0, 0) // set the callback to OnEvent
	o.addCacheVec = []core.Ipv6Key{}
	o.removeCacheVec = []core.Ipv6Key{}

	o.addTimerCache.SetCB(&o.addCacheCB, o, 0)
	o.removeTimerCache.SetCB(&o.removeCacheCB, o, 1)

	o.preparePacketTemplate()
	o.cdb = NewMldNsStatsDb(&o.stats)

}

func (o *mldNsCtx) addMcSG(ivec []*MldSGRecord) error {
	var err error
	var first bool
	vec := []*MldSGRecord{}
	fvec := []core.Ipv6Key{}
	maxIds := int(o.getMaxIdsSG()) // vector is always smaller than vec so we can send them together as two packets
	o.tbl.epoc++
	for _, r := range ivec {
		if r != nil {
			first, err = o.tbl.addMcSG(r.G, r.S)
			if err != nil {
				o.stats.opsAddErrSG++
				o.SendMcPacketSG(fvec, vec, false)
				return err
			}
			o.stats.opsAddSG++
			if first {
				fvec = append(fvec, r.G) // add the first group to vector
			}
			vec = append(vec, r)
			if len(vec) == maxIds {
				o.SendMcPacketSG(fvec, vec, false)
				vec = vec[:0]
				fvec = fvec[:0]
			}
		}
	}
	o.SendMcPacketSG(fvec, vec, false)
	return nil
}

//remove MldSGRecord
func (o *mldNsCtx) removeMcSG(ivec []*MldSGRecord) error {
	var err error
	vec := []*MldSGRecord{}
	o.tbl.epoc++
	maxIds := int(o.getMaxIdsSG())
	for _, r := range ivec {
		if r != nil {
			_, err = o.tbl.removeMcSG(r.G, r.S)
			if err != nil {
				o.stats.opsRemoveErr++
				o.SendMcPacketSG(nil, vec, true)
				return err
			}
			o.stats.opsRemoveSG++
			vec = append(vec, r)
			if len(vec) == maxIds {
				o.SendMcPacketSG(nil, vec, true)
				vec = vec[:0]
			}
		}
	}
	o.SendMcPacketSG(nil, vec, true)
	return nil
}

func (o *mldNsCtx) IterReset() bool {
	o.rpcIterEpoc = o.tbl.epoc
	o.iter.Init(&o.tbl.head)
	if o.tbl.head.IsEmpty() {
		o.iterReady = false
		return true
	}
	o.iterReady = true
	return false
}

func (o *mldNsCtx) IterIsStopped() bool {
	return !o.iterReady
}

func (o *mldNsCtx) GetNext(n uint16) ([]MldEntryDataJson, error) {
	r := make([]MldEntryDataJson, 0)

	if !o.iterReady {
		return r, fmt.Errorf(" Iterator is not ready- reset the iterator")
	}

	if o.rpcIterEpoc != o.tbl.epoc {
		return r, fmt.Errorf(" iterator was interupted , reset and start again ")
	}
	cnt := 0
	for {
		if !o.iter.IsCont() {
			o.iterReady = false // require a new reset
			break
		}
		cnt++
		if cnt > int(n) {
			break
		}
		ent := covertToIgmpEntry(o.iter.Val())
		var entryDataJSON MldEntryDataJson
		entryDataJSON.SetJson(ent)
		r = append(r, entryDataJSON)
		o.iter.Next()
	}
	return r, nil
}

func (o *mldNsCtx) preparePacketTemplate() {

	l2 := o.base.Ns.GetL2Header(true, uint16(layers.EthernetTypeIPv6)) //
	o.ipv6Offset = uint16(len(l2))

	mldv2Header := core.PacketUtlBuild(
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0xC0,
			FlowLabel:    0,
			Length:       8,
			NextHeader:   layers.IPProtocolIPv6HopByHop,
			HopLimit:     1,
			SrcIP:        net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstIP:        net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},

		gopacket.Payload([]byte{0x3a, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00,
			0x8f, 0, 0, 0,
			0, 0, 0, 0,
		}),
	)
	o.ipv6pktTemplate = append(l2, mldv2Header...)

}

func (o *mldNsCtx) OnRemove(ctx *core.PluginCtx) {
	// stop timers
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	if o.removeTimerCache.IsRunning() {
		o.timerw.Stop(&o.removeTimerCache)
		o.flushRemoveCache()
	}
	if o.addTimerCache.IsRunning() {
		o.timerw.Stop(&o.addTimerCache)
		o.flushAddCache()
	}
}

// add to a temporary location for burst
func (o *mldNsCtx) addMcCache(ipv6 core.Ipv6Key) {
	o.addCacheVec = append(o.addCacheVec, ipv6)
	if !o.addTimerCache.IsRunning() {
		o.timerw.StartTicks(&o.addTimerCache, 1)
	}
}

// flush the cache
func (o *mldNsCtx) flushAddCache() {
	if len(o.addCacheVec) > 0 {
		o.addMcInternal(o.addCacheVec) // add client information
		o.addCacheVec = o.addCacheVec[:0]
	}
}

// add to a temporary location for burst
func (o *mldNsCtx) removeMcCache(ipv6 core.Ipv6Key) {
	o.removeCacheVec = append(o.removeCacheVec, ipv6)
	if !o.removeTimerCache.IsRunning() {
		o.timerw.StartTicks(&o.removeTimerCache, 1)
	}
}

// flush the cache
func (o *mldNsCtx) flushRemoveCache() {
	if len(o.removeCacheVec) > 0 {
		o.removeMcInternal(o.removeCacheVec) // add client information
		o.removeCacheVec = o.removeCacheVec[:0]
	}
}

func (o *mldNsCtx) addMcInternal(vecIpv6 []core.Ipv6Key) error {
	return o.addMcVec(vecIpv6, false)
}

func (o *mldNsCtx) addMc(vecIpv6 []core.Ipv6Key) error {
	return o.addMcVec(vecIpv6, true)
}

func (o *mldNsCtx) addMcVec(vecIpv6 []core.Ipv6Key, man bool) error {

	var err error
	var add bool

	vec := []core.Ipv6Key{}
	maxIds := int(o.getMaxIPv6Ids())
	o.tbl.epoc++
	for _, ipv6 := range vecIpv6 {
		err, add = o.tbl.addMc(ipv6, man)
		if err != nil {
			o.stats.opsAddErr++
			o.SendMcPacket(vec, false, false)
			return err
		}
		if add {
			o.stats.opsAdd++
			vec = append(vec, ipv6)
			if len(vec) == maxIds {
				o.SendMcPacket(vec, false, false)
				vec = vec[:0]
			}
		}
	}
	o.SendMcPacket(vec, false, false)
	return nil
}

func (o *mldNsCtx) removeMcInternal(vecIpv6 []core.Ipv6Key) error {
	return o.removeMcVec(vecIpv6, false)
}

func (o *mldNsCtx) RemoveMc(vecIpv6 []core.Ipv6Key) error {
	return o.removeMcVec(vecIpv6, true)
}

func (o *mldNsCtx) removeMcVec(vecIpv6 []core.Ipv6Key, man bool) error {
	var err error
	var r bool
	vec := []core.Ipv6Key{}
	o.tbl.epoc++
	maxIds := int(o.getMaxIPv6Ids())
	for _, ipv6 := range vecIpv6 {
		r, err = o.tbl.removeMc(ipv6, man)
		if err != nil {
			o.stats.opsRemoveErr++
			o.SendMcPacket(vec, true, false)
			return err
		}
		if r {
			o.stats.opsRemove++
			vec = append(vec, ipv6)
			if len(vec) == maxIds {
				o.SendMcPacket(vec, true, false)
				vec = vec[:0]
			}
		}
	}
	o.SendMcPacket(vec, true, false)
	return nil
}

func (o *mldNsCtx) IsValidQueryEpoc(v uint32) bool {
	var d uint32
	d = o.activeEpocQuery - v
	if d > 0x80000000 {
		return false
	}
	return true
}
func (o *mldNsCtx) startQueryReport() bool {
	if !o.activeQuery {
		panic(" mldNsCtx start while active")
	}
	if o.started {
		/* in this first time reset the iterator */
		o.tbl.activeIter = o.tbl.head.Next()
		o.activeEpocQuery = o.tbl.epocQuery
		o.tbl.incEpocQuery()
		o.started = false
	}
	/* up to max ids -- derive from MTU */
	maxIds := int(o.getMaxIPv6Ids())
	finish := false

	// send burst of packets
	for i := 0; i < int(o.pktPerTick); i++ {
		vec := []core.Ipv6Key{}
		for {
			itr := o.tbl.activeIter
			if itr == &o.tbl.head {
				finish = true
				break
			}
			entry := covertToIgmpEntry(itr)
			if o.IsValidQueryEpoc(entry.epocQuery) {
				vec = append(vec, entry.Ipv6)
				if len(vec) == maxIds {
					o.tbl.activeIter = o.tbl.activeIter.Next()
					break
				}
			}
			o.tbl.activeIter = o.tbl.activeIter.Next()
		}
		if (o.mldVersion == MLD_VERSION_2) && (o.tbl.sgCount > 0) {
			o.SendMcPacketSGQuery(vec)
		} else {
			o.SendMcPacket(vec, false, true)
		}
		if finish {
			break
		}
	}
	return finish
}

func (o *mldNsCtx) HandleRxIgmpV1Query(ps *core.ParserPacketState) int {
	o.stats.pktRxv1Queries++
	o.stats.pktRxgsrDropQueries++
	/* not supported for now */
	return 0
}

func (o *mldNsCtx) getPktSize(ids uint16) uint16 {
	pyload := o.getMldHdr() + ids*MLD_GRPREC_HDRLEN
	return (pyload)
}

func (o *mldNsCtx) getMaxIPv6Ids() uint16 {
	if o.mldVersion == MLD_VERSION_2 {
		pyload := o.getMaxPyload()
		return pyload / MLD_GRPREC_HDRLEN
	} else {
		return 1
	}
}

func (o *mldNsCtx) getMldHdr() uint16 {
	return (14 + 2*4 + IPV6_HEADER_SIZE + IPV6_OPTION_ROUTER + MLD_V2_QUERY_MINLEN + 16)
}

func (o *mldNsCtx) getMaxPyload() uint16 {
	pyload := o.mtu - o.getMldHdr()
	return pyload
}

func (o *mldNsCtx) getMaxIdsSG() uint16 {
	if o.mldVersion == MLD_VERSION_2 {
		pyload := o.getMaxPyload()
		return pyload / (MLD_GRPREC_HDRLEN + MLD_QUERY_ADDR)
	} else {
		return 1
	}
}

func (o *mldNsCtx) getPktSizeSg(ids uint16) uint16 {
	pyload := o.getMldHdr() + ids*(MLD_GRPREC_HDRLEN+MLD_QUERY_ADDR)
	return (pyload)
}

func (o *mldNsCtx) HandleRxMldCmn(isGenQuery bool, mldAddr core.Ipv6Key) int {

	if isGenQuery {
		if o.activeQuery {
			/* can't handle query while there is another query */
			o.stats.pktRxquerieActiveTimer++
			return 0
		}
		var startTick uint32
		cnt := uint32(len(o.tbl.mapIgmp))
		if cnt > 0 {
			maxIds := o.getMaxIPv6Ids()
			maxRespMsec := o.maxresp

			timerticks, pktsPerTick, breachMaxRate := calcTimerInfo(cnt, uint32(maxIds),
				maxRespMsec,
				o.timerw.MinTickMsec(),
				core.PLUGIN_MAX_PPS)

			if breachMaxRate {
				o.stats.opsRateIsTooHigh++
			}

			if timerticks == 0 {
				/* only one report is needed */
				if o.base.Tctx.Simulation {
					startTick = uint32(1) / o.timerw.MinTickMsec()
				} else {
					startTick = uint32(rand.Intn(int(maxRespMsec))+1) / o.timerw.MinTickMsec()
				}
				o.ticks = 0
				o.pktPerTick = 1
			} else {
				/* more than one report is needed  */
				o.ticks = timerticks
				o.pktPerTick = pktsPerTick
				startTick = timerticks
			}
			o.activeQuery = true
			o.started = true
			if o.timer.IsRunning() {
				panic(" mld timer is running ")
			}
			o.timerw.StartTicks(&o.timer, startTick)
		}

	} else {
		e, ok := o.tbl.mapIgmp[mldAddr]
		if ok {
			if (e.getMode() == MLD_ENTRY_MODE_INCLUDE_ALL) ||
				(o.mldVersion == MLD_VERSION_1) {
				vec := []core.Ipv6Key{mldAddr}
				o.SendMcPacket(vec, false, true)
			} else {
				vec := []core.Ipv6Key{mldAddr}
				o.SendMcPacketSGQuery(vec)
			}
		}
	}
	return 0
}

func (o *mldNsCtx) SendMcPacketSGChangeToInclude(vec []core.Ipv6Key) {
	o.SendMcPacket(vec, true, false)
}

func (o *mldNsCtx) SendMcPacketv1(client *core.CClient,
	vec []core.Ipv6Key, remove bool, query bool) {

	rcds := len(vec)
	if rcds != 1 {
		panic(" should be at least 1 addr ")
	}

	if query {
		o.stats.pktRxSndReports++
	} else {
		o.stats.pktSndAddRemoveReports++
	}

	pktSize := o.getPktSize(1)
	m := o.base.Ns.AllocMbuf(pktSize)
	m.Append(o.ipv6pktTemplate)
	var l6 core.Ipv6Key
	client.GetIpv6LocalLink(&l6)
	ad6 := vec[0]

	dst := [6]byte{0x33, 0x33, ad6[12], ad6[13], ad6[14], ad6[15]}
	p := m.GetData()
	copy(p[0:6], dst[:])
	copy(p[6:12], o.designatorMac[:])

	ipv6 := layers.IPv6Header(p[o.ipv6Offset : o.ipv6Offset+IPV6_HEADER_SIZE])

	copy(ipv6.SrcIP(), l6[:])

	if remove {
		copy(ipv6.DstIP(), MLD1_ALL_ROUTERS)
	} else {
		copy(ipv6.DstIP(), ad6[:])
	}

	pyld := 8 + (MLD_QUERY_ADDR) + IPV6_OPTION_ROUTER
	ipv6.SetPyloadLength(uint16(pyld))
	m.Append(ad6[:])

	np := m.GetData()

	rcof := o.ipv6Offset + IPV6_HEADER_SIZE + IPV6_OPTION_ROUTER

	if remove {
		np[rcof] = uint8(layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage)
	} else {
		np[rcof] = uint8(layers.ICMPv6TypeMLDv1MulticastListenerReportMessage)
	}

	cs := layers.PktChecksumTcpUdpV6(np[rcof:], 0, ipv6, IPV6_OPTION_ROUTER, 58)
	binary.BigEndian.PutUint16(np[rcof+2:rcof+4], cs)
	o.base.Tctx.Veth.Send(m)
}

func (o *mldNsCtx) getClient() *core.CClient {
	client := o.base.Ns.CLookupByMac(&o.designatorMac)
	if client == nil {
		o.stats.pktNoDesignatorClient++
		return nil
	}
	return client
}

func (o *mldNsCtx) SendMcPacket(vec []core.Ipv6Key, remove bool, query bool) {

	client := o.getClient()
	if client == nil {
		return
	}

	rcds := len(vec)
	if rcds == 0 {
		/* nothing to do */
		return
	}

	if o.mldVersion == MLD_VERSION_1 {
		o.SendMcPacketv1(client, vec, remove, query)
		return
	}

	if rcds > int(o.getMaxIPv6Ids()) {
		panic(" mldNsCtx rcds> o.getMaxIPv6Ids() ")
	}

	if query {
		o.stats.pktRxSndReports++
	} else {
		o.stats.pktSndAddRemoveReports++
	}

	pktSize := o.getPktSize(uint16(rcds))
	m := o.base.Ns.AllocMbuf(pktSize)
	m.Append(o.ipv6pktTemplate)
	var l6 core.Ipv6Key
	client.GetIpv6LocalLink(&l6)

	dst := [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x16}
	p := m.GetData()
	copy(p[0:6], dst[:])
	copy(p[6:12], o.designatorMac[:])

	ipv6 := layers.IPv6Header(p[o.ipv6Offset : o.ipv6Offset+IPV6_HEADER_SIZE])

	copy(ipv6.SrcIP(), l6[:])

	copy(ipv6.DstIP(), MLD2_RESPONSE_ADDR)

	pyld := 8 + (MLD_GRPREC_HDRLEN * rcds) + IPV6_OPTION_ROUTER
	ipv6.SetPyloadLength(uint16(pyld))

	for _, mc := range vec {
		grouprec := [4]byte{}
		/* set the type */
		if query {
			if remove {
				grouprec[0] = IGMP_MODE_IS_INCLUDE
			} else {
				grouprec[0] = IGMP_MODE_IS_EXCLUDE
			}
		} else {
			if remove {
				grouprec[0] = IGMP_CHANGE_TO_INCLUDE_MODE
			} else {
				grouprec[0] = IGMP_CHANGE_TO_EXCLUDE_MODE
			}
		}
		m.Append(grouprec[:])
		m.Append(mc[:])
	}
	np := m.GetData()

	rcof := o.ipv6Offset + IPV6_HEADER_SIZE + IPV6_OPTION_ROUTER
	binary.BigEndian.PutUint16(np[rcof+6:rcof+8], uint16(rcds)) // set number of ele
	cs := layers.PktChecksumTcpUdpV6(np[rcof:], 0, ipv6, IPV6_OPTION_ROUTER, 58)
	binary.BigEndian.PutUint16(np[rcof+2:rcof+4], cs)
	o.base.Tctx.Veth.Send(m)
}

func (o *mldNsCtx) SendMcPacketSG(fvec []core.Ipv6Key, vec []*MldSGRecord, remove bool) {

	client := o.getClient()
	if client == nil {
		return
	}

	if (fvec != nil) && (remove == false) {
		// change mode to INCLUDE for all the groups
		o.SendMcPacketSGChangeToInclude(fvec)
	}

	rcds := len(vec)
	if rcds == 0 {
		/* nothing to do */
		return
	}
	if rcds > int(o.getMaxIdsSG()) {
		panic(" PluginMldNs rcds> o.getMaxIdsSG() ")
	}
	if remove {
		o.stats.pktRxSndReportsSGRemove++
	} else {
		o.stats.pktRxSndReportsSGAdd++
	}
	pktSize := o.getPktSizeSg(uint16(rcds))
	m := o.base.Ns.AllocMbuf(pktSize)
	m.Append(o.ipv6pktTemplate)
	var l6 core.Ipv6Key
	client.GetIpv6LocalLink(&l6)

	dst := [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x16}
	p := m.GetData()
	copy(p[0:6], dst[:])
	copy(p[6:12], o.designatorMac[:])

	ipv6 := layers.IPv6Header(p[o.ipv6Offset : o.ipv6Offset+IPV6_HEADER_SIZE])

	copy(ipv6.SrcIP(), l6[:])

	copy(ipv6.DstIP(), MLD2_RESPONSE_ADDR)

	pyld := 8 + ((MLD_GRPREC_HDRLEN + MLD_QUERY_ADDR) * rcds) + IPV6_OPTION_ROUTER
	ipv6.SetPyloadLength(uint16(pyld))

	for idx, _ := range vec {
		e := vec[idx]
		grouprec := [4]byte{0, 0, 0, 1}
		/* set the type */
		if remove {
			grouprec[0] = IGMP_BLOCK_OLD_SOURCES
		} else {
			grouprec[0] = IGMP_ALLOW_NEW_SOURCES
		}
		m.Append(grouprec[:])
		m.Append(e.G[:])
		m.Append(e.S[:])
	}
	np := m.GetData()

	rcof := o.ipv6Offset + IPV6_HEADER_SIZE + IPV6_OPTION_ROUTER
	binary.BigEndian.PutUint16(np[rcof+6:rcof+8], uint16(rcds)) // set number of ele
	cs := layers.PktChecksumTcpUdpV6(np[rcof:], 0, ipv6, IPV6_OPTION_ROUTER, 58)
	binary.BigEndian.PutUint16(np[rcof+2:rcof+4], cs)
	o.base.Tctx.Veth.Send(m)
}

func (o *mldNsCtx) flushEntries(pb *mldPktBuilder) {
	// build packet and send it

	// TBD to remove!!!!!
	if false {
		for idx, _ := range pb.pktv {
			e := &((pb.pktv)[idx])
			if e.Mode == MLD_ENTRY_MODE_INCLUDE_ALL {
				fmt.Printf(" %v-* \n", e.Ipv6)
			} else {
				fmt.Printf(" %v-[ ", e.Ipv6)
				for _, mc := range *e.S {
					fmt.Printf(" %v,", mc)
				}
				fmt.Printf("] \n")
			}
		}

	}

	client := o.getClient()
	if client == nil {
		return
	}

	o.stats.pktRxSndReportsSGQuery++

	pktSize := o.mtu // take the maximum packet
	m := o.base.Ns.AllocMbuf(pktSize)
	m.Append(o.ipv6pktTemplate)
	var l6 core.Ipv6Key
	client.GetIpv6LocalLink(&l6)

	dst := [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x16}
	p := m.GetData()
	copy(p[0:6], dst[:])
	copy(p[6:12], o.designatorMac[:])

	ipv6 := layers.IPv6Header(p[o.ipv6Offset : o.ipv6Offset+IPV6_HEADER_SIZE])

	copy(ipv6.SrcIP(), l6[:])

	copy(ipv6.DstIP(), MLD2_RESPONSE_ADDR)
	bytes := uint16(0)
	for idx, _ := range pb.pktv {
		e := &((pb.pktv)[idx])
		/* set the type */
		grouprec := [4]byte{}
		if e.Mode == MLD_ENTRY_MODE_INCLUDE_ALL {
			/* set the type */
			grouprec[0] = IGMP_MODE_IS_EXCLUDE
			m.Append(grouprec[:])
			m.Append(e.Ipv6[:])
			bytes += MLD_GRPREC_HDRLEN
		} else {
			grouprec[0] = IGMP_MODE_IS_INCLUDE
			binary.BigEndian.PutUint16(grouprec[2:4], uint16(len(*e.S)))
			m.Append(grouprec[:])
			m.Append(e.Ipv6[:])
			bytes += (MLD_GRPREC_HDRLEN + MLD_QUERY_ADDR*uint16(len(*e.S)))
			for _, mc := range *e.S {
				m.Append(mc[:])
			}
		}
	}
	np := m.GetData()

	ipv6.SetPyloadLength(IPV6_OPTION_ROUTER + IGMP_HEADER_MINLEN + uint16(bytes))

	rcof := o.ipv6Offset + IPV6_HEADER_SIZE + IPV6_OPTION_ROUTER
	binary.BigEndian.PutUint16(np[rcof+6:rcof+8], uint16(len(pb.pktv))) // set number of ele
	cs := layers.PktChecksumTcpUdpV6(np[rcof:], 0, ipv6, IPV6_OPTION_ROUTER, 58)
	binary.BigEndian.PutUint16(np[rcof+2:rcof+4], cs)

	o.base.Tctx.Veth.Send(m)

	// reset
	pb.freePyld = pb.maxPyld
	pb.pktv = pb.pktv[:0]
}

func (o *mldNsCtx) pushEntry(pb *mldPktBuilder) {
	if pb.s == nil {
		//IGMP_ENTRY_MODE_INCLUDE_ALL
		if pb.freePyld < MLD_REPORT_MINLEN {
			o.flushEntries(pb)
		}

		pb.pktv = append(pb.pktv, *pb.e.getJson())
		pb.freePyld -= MLD_REPORT_MINLEN
	} else {
		if len(pb.s) == 0 {
			o.flushEntries(pb)
		} else {
			var j MldEntryDataJson
			j.Ipv6 = pb.e.Ipv6
			j.Mode = pb.e.getMode()
			j.S = new([]core.Ipv6Key)
			for _, k := range pb.s {
				*j.S = append(*j.S, k)
			}
			pb.pktv = append(pb.pktv, j)
			pb.freePyld -= (MLD_REPORT_MINLEN + uint16(len(pb.s)*MLD_SRC_SIZE))
		}
	}
}

//
// each group could be either EXCLUDE or INCLUDE
// need to build packets on the fly base on the each entry information
func (o *mldNsCtx) SendMcPacketSGQuery(vec []core.Ipv6Key) {

	client := o.getClient()
	if client == nil {
		return
	}

	rcds := len(vec)
	if rcds == 0 {
		/* nothing to do */
		return
	}
	maxPyld := o.getMaxPyload()
	// free bytes in pyload
	var pb mldPktBuilder
	pb.freePyld = maxPyld
	pb.maxPyld = maxPyld

	for _, mc := range vec {
		e, ok := o.tbl.mapIgmp[mc]
		if ok {
			if e.getMode() == MLD_ENTRY_MODE_INCLUDE_ALL {
				// just push one entry
				pb.e = e
				pb.group = e.Ipv6
				pb.s = nil
				o.pushEntry(&pb)

			} else {
				svec := e.getSourceVec()

				if o.base.Tctx.Simulation {
					sort.Slice(svec, func(i, j int) bool {
						if bytes.Compare(svec[i][:], svec[j][:]) < 0 {
							return (true)
						}
						return false
					})
				}

				lvec := uint16(len(svec))
				// in case vector is zero there is nothing to do
				if lvec > 0 {
					index := uint16(0)
					for {
						if index == lvec {
							break
						}
						cnt, _ := e.calcNumSources(pb.freePyld, lvec-index)
						pb.e = e
						pb.group = e.Ipv6

						if cnt == 0 {
							pb.s = []core.Ipv6Key{}
							o.pushEntry(&pb)
						} else {
							pb.s = svec[index : index+cnt]
							o.pushEntry(&pb)
							index += cnt
						}
					}
				}
			}
		} //ok
	} // loop
	o.flushEntries(&pb)
}

func (o *mldNsCtx) HandleRxMldV1Query(ps *core.ParserPacketState,
	mldh layers.Mldv2Header,
	ipv6 layers.IPv6Header,
	mldlen uint16) int {

	var isGenQuery bool
	isGenQuery = false

	if bytes.Compare(mldh.GetGroup(), IN6_IS_ADDR_UNSPECIFIED) == 0 {
		o.stats.pktRxgenQueries++
		isGenQuery = true
	} else {
		o.stats.pktRxgsrQueries++
	}

	o.mldVersion = MLD_VERSION_1
	maxresp := mldMantExp(mldh.GetMaxResTime())

	o.maxresp = uint32(maxresp)

	var mldKey core.Ipv6Key
	copy(mldKey[:], mldh.GetGroup())

	return o.HandleRxMldCmn(isGenQuery, mldKey)
}

func mldMantExp8(v uint8) uint32 {

	if v >= 128 {
		return uint32((v & 0xf)) << (((v & 0xf0) >> 4) + 3)
	} else {
		return uint32(v)
	}
}

func mldMantExp(v uint16) uint32 {

	if v >= 32768 {
		return (uint32((v & 0x0fff)) | 0x00001000) << ((((v & 0xf000) >> 12) & 0x07) + 3)
	} else {
		return uint32(v)
	}
}

func (o *mldNsCtx) HandleRxMld2Query(ps *core.ParserPacketState,
	mldh layers.Mldv2Header,
	ipv6 layers.IPv6Header,
	mldlen uint16) int {

	var maxresp, qqi, nsrc uint32

	maxresp = mldMantExp(mldh.GetMaxResTime())

	qrv := mldh.GetMisc() & 0x7
	if qrv < 2 {
		qrv = 2
	}

	qqi = mldMantExp8(mldh.Getqqi())

	nsrc = uint32(mldh.GetNumSrc())

	var isGenQuery bool
	isGenQuery = false

	if bytes.Compare(mldh.GetGroup(), IN6_IS_ADDR_UNSPECIFIED) == 0 {
		if nsrc > 0 {
			o.stats.pktRxbadQueries++
			return 0
		}
		o.stats.pktRxgenQueries++
		isGenQuery = true
	} else {
		if nsrc == 0 {
			o.stats.pktRxgroupQueries++
		} else {
			o.stats.pktRxgsrQueries++
		}
	}

	o.mldVersion = MLD_VERSION_2
	o.qqi = qqi
	o.qrv = qrv
	o.maxresp = maxresp

	var mldKey core.Ipv6Key
	copy(mldKey[:], mldh.GetGroup())

	return o.HandleRxMldCmn(isGenQuery, mldKey)
}

/* HandleRxMldPacket -1 for parser error, 0 valid  */
func (o *mldNsCtx) HandleRxMldPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/
	mld := p[ps.L4:]

	mldh := layers.Mldv2Header(mld)
	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+IPV6_HEADER_SIZE])

	var optionbytes uint16
	if ps.L4-ps.L3 > 40 {
		optionbytes = ps.L4 - ps.L3 - 40
	}
	mldlen := ipv6.PayloadLength() - optionbytes

	mldType := mldh.GetType()

	// should have router alert in query
	if (ipv6.HopLimit() != 1) || ((ps.Flags & core.IPV6_M_RTALERT_ML) == 0) {
		o.stats.pktRxBadttl++
		return core.PARSER_ERR
	}

	var queryver int
	queryver = 0

	mldcode := mldh.GetCode()

	switch mldType {
	case uint8(layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage):
		if mldlen == MLD_QUERY_MINLEN {
			if mldcode == 0 {
				queryver = MLD_VERSION_1
			} else {
				o.stats.pktRxTooshort++
				return -1
			}
		} else {
			if mldlen >= MLD_V2_QUERY_MINLEN {
				queryver = MLD_VERSION_2
			} else {
				o.stats.pktRxTooshort++
				return -1
			}
		}
		switch queryver {
		case MLD_VERSION_1:
			o.stats.pktRxv1Queries++
			return o.HandleRxMldV1Query(ps, mldh, ipv6, mldlen)
		case MLD_VERSION_2:
			o.stats.pktRxv2Queries++
			nsrc := mldh.GetNumSrc()
			if (nsrc * MLD_QUERY_ADDR) > (mldlen - MLD_V2_QUERY_MINLEN) {
				o.stats.pktRxTooshort++
				return -1
			}
			return o.HandleRxMld2Query(ps, mldh, ipv6, mldlen)
		}
	case uint8(layers.ICMPv6TypeMLDv1MulticastListenerReportMessage):
		o.stats.pktRxReports++
	case uint8(layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage):
		o.stats.pktRxReports++
	case uint8(layers.ICMPv6TypeMLDv2MulticastListenerReportMessageV2):
		o.stats.pktRxNora++
	}
	return 0
}
