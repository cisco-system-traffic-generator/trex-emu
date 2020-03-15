// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package ipv6

/*
  MLD and MLDv2
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
	"unsafe"

	"github.com/intel-go/fastjson"
)

const (
	MLD_VERSION_1                  = 1
	MLD_VERSION_2                  = 2
	IGMP_TYPE_DVMRP                = 0x13
	IGMP_HEADER_MINLEN             = 8
	MLD_V2_QUERY_MINLEN            = 8 + 16 + 4
	MLD_QUERY_MINLEN               = 8 + 16
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
	Mtu           uint16         `json:"mtu" validate:"required,gte=256,lte=9000"`
	DesignatorMac core.MACKey    `json:"dmac"`
	Vec           []core.Ipv6Key `json:"vec"` // add mc
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

type mldNsInit struct {
	Mtu           uint16         `json:"mtu" validate:"required,gte=256,lte=9000"`
	DesignatorMac core.MACKey    `json:"dmac"`
	Vec           []core.Ipv4Key `json:"vec"` // add mc
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
}

func NewMldNsStatsDb(o *mldNsStats) *core.CCounterDb {
	db := core.NewCCounterDb("mld")

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
		Help:     "no designator client with this MAC addr ",
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

//MldEntry includes one ipv6 mc addr. It could be owned by management (rpc) or by external clients (e.g. IPv6 ND)
// external clients will increment the refc while management will use the bool
type MldEntry struct {
	dlist      core.DList // must be first
	Ipv6       core.Ipv6Key
	epocQuery  uint32
	management bool   /* added by management, could not be added twice ref=0, management=1 is for management adding . management=0,ref=1 for clients */
	refc       uint16 /* ref counter for none management clients.  add ref/remove ref*/
}

type MapIgmp map[core.Ipv6Key]*MldEntry

//IgmpFlowTbl  map/dlist of the mld entries
type IgmpFlowTbl struct {
	mapIgmp    MapIgmp
	head       core.DList
	activeIter *core.DList /* pointer to the next object, in case of active */
	epoc       uint32      /* operation epoc for add/remove/rpc iterator */
	epocQuery  uint32
	stats      *mldNsStats
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
				return fmt.Errorf(" mc-ipv6 %v already exist by management", ipv6), false
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
		return false, fmt.Errorf(" mc-ipv6 %v does not exist", ipv6)
	}
	if man {
		if !e.management {
			return false, fmt.Errorf(" mc-ipv6 %v wasn't added by management and can't be removed", ipv6)

		} else {
			e.management = false
		}
	} else {
		if e.refc > 0 {
			e.refc--
		} else {
			panic("mld remove without adding from external sources")
		}
	}
	var r bool
	if e.refc == 0 && !e.management {
		r = true
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
	var init MldNsInit
	err := fastjson.Unmarshal(initJson, &init)

	o.base = base
	o.tbl.OnCreate(&o.stats)
	o.mldVersion = MLD_VERSION_2
	o.mtu = 1500
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
	if err == nil {
		if init.Mtu > 0 {
			o.mtu = init.Mtu
		}
		if !init.DesignatorMac.IsZero() {
			o.designatorMac = init.DesignatorMac
		}
		if len(init.Vec) > 0 {
			o.addMc(init.Vec)
		}
	}
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

func (o *mldNsCtx) GetNext(n uint16) ([]core.Ipv6Key, error) {
	r := make([]core.Ipv6Key, 0)

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
		r = append(r, ent.Ipv6)
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
			TrafficClass: 0,
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
		o.SendMcPacket(vec, false, true)
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
	pyload := 14 + 2*4 + IPV6_HEADER_SIZE + IPV6_OPTION_ROUTER + MLD_V2_QUERY_MINLEN + 16 + ids*MLD_GRPREC_HDRLEN
	return (pyload)
}

func (o *mldNsCtx) getMaxIPv6Ids() uint16 {
	if o.mldVersion == MLD_VERSION_2 {
		pyload := o.mtu - (14 + 2*4 + IPV6_HEADER_SIZE + IPV6_OPTION_ROUTER + MLD_V2_QUERY_MINLEN + 16)
		return pyload / MLD_GRPREC_HDRLEN
	} else {
		return 1
	}
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
				startTick = uint32(rand.Intn(int(maxRespMsec))+1) / o.timerw.MinTickMsec()
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
		vec := []core.Ipv6Key{mldAddr}
		o.SendMcPacket(vec, false, true)
	}
	return 0
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

func (o *mldNsCtx) SendMcPacket(vec []core.Ipv6Key, remove bool, query bool) {

	client := o.base.Ns.CLookupByMac(&o.designatorMac)
	if client == nil {
		o.stats.pktNoDesignatorClient++
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
