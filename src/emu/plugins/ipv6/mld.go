package ipv6

/*
  MLD and MLDv2
*/

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"fmt"
	"math"
	"math/rand"
	"net"
	"unsafe"
)

const (
	MLD_VERSION_1                  = 1
	MLD_VERSION_2                  = 2
	IGMP_TYPE_DVMRP                = 0x13
	IGMP_HEADER_MINLEN             = 8
	MLD_V2_QUERY_MINLEN            = 8 + 16
	IGMP_MC_ADDR_MASK              = 0xE0000000
	IGMP_MC_DEST_HOST              = 0xE0000001
	IGMP_NULL_HOST                 = 0x00000000
	MLD_GRPREC_HDRLEN              = 4 + 16
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
	pktNoDesignatorClientIPv4 uint64 /* there designator client does not have valid IPv4 addr */

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
		Help:     "received igmp but can't find port,vlan keys",
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
		Counter:  &o.pktNoDesignatorClientIPv4,
		Name:     "pktNoDesignatorClientIPv4",
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
	management bool   /* added by management, could not be added twice */
	refc       uint16 /* ref counter for none management clients.  add ref/remove ref*/
}

type MapIgmp map[core.Ipv6Key]*MldEntry

//IgmpFlowTbl  map/dlist of the igmp entries
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

func (o *IgmpFlowTbl) addMc(ipv6 core.Ipv6Key, man bool) error {
	obj, ok := o.mapIgmp[ipv6]
	if ok {
		if !man {
			obj.refc++
			return nil
		} else {
			if !obj.management {
				obj.management = true
				return nil
			} else {
				return fmt.Errorf(" mc-ipv6 %v already exist by management", ipv6)
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
	return nil
}

func (o *IgmpFlowTbl) removeMc(ipv6 core.Ipv6Key, man bool) error {
	e, ok := o.mapIgmp[ipv6]
	if !ok {
		return fmt.Errorf(" mc-ipv6 %v does not exist", ipv6)
	}
	if man {
		if !e.management {
			return fmt.Errorf(" mc-ipv6 %v wasn't added by management and can't be removed", ipv6)

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
	if e.refc == 0 && !e.management {
		delete(o.mapIgmp, ipv6)
		/* handle the iterator in case of remove */
		if o.activeIter == &e.dlist {
			// it is going to be removed
			o.activeIter = e.dlist.Next()
		}
		o.head.RemoveNode(&e.dlist)
	}
	return nil
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

type mldNsCtx struct {
	base            *PluginIpv6Ns
	designatorMac   core.MACKey // designator MAC key to client id
	timerw          *core.TimerCtx
	tbl             IgmpFlowTbl
	mldVersion      uint16
	mtu             uint16
	maxresp         uint32 /* in 1/10ths of a second  */
	qqi             uint32 /* interval  */
	qrv             uint8  /* qrv */
	activeQuery     bool   /* true in case there is a active query */
	started         bool
	stats           mldNsStats
	timer           core.CHTimerObj
	ticks           uint32
	pktPerTick      uint32
	ipv6pktTemplate []byte
	ipv6Offset      uint16
	activeEpocQuery uint32
	rpcIterEpoc     uint32
	iter            core.DListIterHead
	iterReady       bool
}

func (o *mldNsCtx) Init(base *PluginIpv6Ns, ctx *core.CThreadCtx, initJson []byte) {
	o.base = base
	o.tbl.OnCreate(&o.stats)
	o.mldVersion = MLD_VERSION_2
	o.mtu = 1500
	o.qrv = 2
	o.qqi = 125
	o.maxresp = 100
	o.timerw = ctx.GetTimerCtx()
	o.preparePacketTemplate()
	/*
		  TBD need to fix the init json from master
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
	*/
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

	l2 := o.base.Ns.GetL2Header(true, uint16(layers.EthernetTypeIPv4)) // TBD need to fix this
	o.ipv6Offset = uint16(len(l2))

	igmpHeader := core.PacketUtlBuild(
		&layers.IPv4{Version: 4, IHL: 6, TTL: 1, Id: 0xcc,
			SrcIP:    net.IPv4(0, 0, 0, 0),
			DstIP:    net.IPv4(0, 0, 0, 0),
			Length:   44,
			Protocol: layers.IPProtocolIGMP,
			Options: []layers.IPv4Option{{ /* router alert */
				OptionType:   0x94,
				OptionData:   []byte{0, 0},
				OptionLength: 4},
			},
		},
	)
	o.ipv6pktTemplate = append(l2, igmpHeader...)
}

func (o *mldNsCtx) OnRemove(ctx *core.PluginCtx) {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

/*OnTimerUpdate called on timer expiration */
func (o *mldNsCtx) onTimerUpdate() {
	var finish bool
	finish = o.startQueryReport()
	if finish {
		o.activeQuery = false
	} else {
		// restart the timer
		o.timerw.StartTicks(&o.timer, o.ticks)
	}
}

func (o *mldNsCtx) addMc(vecIpv6 []core.Ipv6Key) error {

	var err error
	vec := []core.Ipv6Key{}
	maxIds := int(o.getMaxIPv6Ids())
	o.tbl.epoc++
	for _, ipv6 := range vecIpv6 {
		err = o.tbl.addMc(ipv6, true)
		if err != nil {
			o.stats.opsAddErr++
			o.SendMcPacket(vec, false, false)
			return err
		}
		o.stats.opsAdd++
		vec = append(vec, ipv6)
		if len(vec) == maxIds {
			o.SendMcPacket(vec, false, false)
			vec = vec[:0]
		}
	}
	o.SendMcPacket(vec, false, false)
	return nil
}

func (o *mldNsCtx) RemoveMc(vecIpv6 []core.Ipv6Key) error {
	var err error
	vec := []core.Ipv6Key{}
	o.tbl.epoc++
	maxIds := int(o.getMaxIPv6Ids())
	for _, ipv6 := range vecIpv6 {
		err = o.tbl.removeMc(ipv6, true)
		if err != nil {
			o.stats.opsRemoveErr++
			o.SendMcPacket(vec, true, false)
			return err
		}
		o.stats.opsRemove++
		vec = append(vec, ipv6)
		if len(vec) == maxIds {
			o.SendMcPacket(vec, true, false)
			vec = vec[:0]
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
		vec := []uint32{}
		for {
			itr := o.tbl.activeIter
			if itr == &o.tbl.head {
				finish = true
				break
			}
			entry := covertToIgmpEntry(itr)
			if o.IsValidQueryEpoc(entry.epocQuery) {
				vec = append(vec, entry.Ipv4.Uint32())
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

func (o *mldNsCtx) HandleRxIgmpCmn(isGenQuery bool, igmpAddr uint32) int {

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
			maxRespMsec := o.maxresp * 100

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
				panic(" igmp timer is running ")
			}
			o.timerw.StartTicks(&o.timer, startTick)
		}

	} else {
		vec := []uint32{igmpAddr}
		o.SendMcPacket(vec, false, true)
	}
	return 0
}

func (o *mldNsCtx) SendMcPacket(vec []core.Ipv6Key, remove bool, query bool) {

	client := o.Ns.CLookupByMac(&o.designatorMac)
	if client == nil {
		o.stats.pktNoDesignatorClient++
		return
	}
	if client.Ipv4.IsZero() {
		o.stats.pktNoDesignatorClientIPv4++
		return
	}

	rcds := len(vec)
	if rcds == 0 {
		/* nothing to do */
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
	m := o.Tctx.MPool.Alloc(pktSize)
	m.Append(o.ipv4pktTemplate)
	dst := [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x16}
	if o.igmpVersion != IGMP_VERSION_3 {
		if remove {
			dst[5] = 2
		} else {
			mcid := vec[0]
			dst[3] = uint8((mcid >> 16) & 0x7f)
			dst[4] = uint8((mcid >> 8) & 0xff)
			dst[5] = uint8((mcid) & 0xff)
		}
	}
	p := m.GetData()
	copy(p[0:6], dst[:])
	copy(p[6:12], o.designatorMac[:])

	ipv4 := layers.IPv4Header(p[o.ipv4Offset : o.ipv4Offset+IPV4_HEADER_SIZE])

	ipv4.SetIPSrc(client.Ipv4.Uint32())
	if o.igmpVersion != IGMP_VERSION_3 {
		if remove {
			ipv4.SetIPDst(0xe0000002)
		} else {
			ipv4.SetIPDst(vec[0])
		}
	} else {
		ipv4.SetIPDst(0xe0000016)
	}

	if o.igmpVersion == IGMP_VERSION_3 {
		pyld := IGMP_V3_REPORT_MINLEN + (IGMP_V3_REPORT_MINLEN * rcds)
		ipv4.SetLength(uint16(IPV4_HEADER_SIZE + pyld))
		ipv4.UpdateChecksum()

		reportHeader := [8]byte{uint8(layers.IGMPMembershipReportV3),
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		binary.BigEndian.PutUint16(reportHeader[6:8], uint16(rcds))
		m.Append(reportHeader[:])
		for _, mc := range vec {
			grouprec := [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
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
			binary.BigEndian.PutUint32(grouprec[4:8], uint32(mc))
			m.Append(grouprec[:])
		}
		np := m.GetData()
		cs := layers.PktChecksum(np[o.ipv4Offset+IPV4_HEADER_SIZE:], 0)
		binary.BigEndian.PutUint16(np[o.ipv4Offset+IPV4_HEADER_SIZE+2:o.ipv4Offset+IPV4_HEADER_SIZE+4], cs)
	} else {
		if rcds > 1 {
			panic(" mldNsCtx rcds should be 1 for IGMPv2 ")
		}
		ipv4.SetLength(IPV4_HEADER_SIZE + IGMP_V3_REPORT_MINLEN)
		ipv4.UpdateChecksum()
		grouprec := [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if remove {
			grouprec[0] = IGMP_HOST_LEAVE_MESSAGE
		} else {
			grouprec[0] = IGMP_v2_HOST_MEMBERSHIP_REPORT
		}
		binary.BigEndian.PutUint32(grouprec[4:8], uint32(vec[0]))
		binary.BigEndian.PutUint16(grouprec[2:4], layers.PktChecksum(grouprec[:], 0))
		m.Append(grouprec[:])
	}
	o.Tctx.Veth.Send(m)
}

func (o *mldNsCtx) HandleRxIgmpV2Query(ps *core.ParserPacketState) int {
	m := ps.M
	p := m.GetData()
	igmp := p[ps.L4:]
	igmph := layers.IGMPHeader(igmp)
	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+IPV4_HEADER_SIZE-4])
	var isGenQuery bool
	isGenQuery = false

	if igmph.GetGroup() == IGMP_NULL_HOST {
		if ipv4.GetIPDst() != IGMP_MC_DEST_HOST {
			o.stats.pktRxbadQueries++
			return 0
		}
		o.stats.pktRxgenQueries++
		isGenQuery = true
	} else {
		o.stats.pktRxgroupQueries++
	}
	o.igmpVersion = IGMP_VERSION_2
	o.maxresp = uint32(igmph.GetCode())

	return o.HandleRxIgmpCmn(isGenQuery, igmph.GetGroup())
}

func igmpMantExp(v uint8) uint32 {

	if v >= 128 {
		return uint32((v & 0xf)) << (((v & 0xf0) >> 4) + 3)
	} else {
		return uint32(v)
	}
}

func (o *mldNsCtx) HandleRxIgmpV3Query(ps *core.ParserPacketState) int {
	m := ps.M
	p := m.GetData()
	igmp := p[ps.L4:]
	igmph := layers.IGMPHeader(igmp)
	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+IPV4_HEADER_SIZE-4])

	var maxresp, qqi, nsrc uint32

	maxresp = igmpMantExp(igmph.GetCode())

	qrv := igmph.GetMisc() & 0x7
	if qrv < 2 {
		qrv = 2
	}

	qqi = igmpMantExp(igmph.Getqqi())

	nsrc = uint32(igmph.GetNumSrc())

	var isGenQuery bool
	isGenQuery = false

	if igmph.GetGroup() == IGMP_NULL_HOST {
		if ipv4.GetIPDst() != IGMP_MC_DEST_HOST {
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
	o.igmpVersion = IGMP_VERSION_3
	o.qqi = qqi
	o.qrv = qrv
	o.maxresp = maxresp

	return o.HandleRxIgmpCmn(isGenQuery, igmph.GetGroup())
}

/* HandleRxIgmpPacket -1 for parser error, 0 valid  */
func (o *mldNsCtx) HandleRxIgmpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/

	//igmplen := m.PktLen() - uint32(ps.L4)
	igmp := p[ps.L4:]

	/* checksum */
	cs := layers.PktChecksum(igmp, 0)
	if cs != 0 {
		o.stats.pktRxBadsum++
		return core.PARSER_ERR
	}

	igmph := layers.IGMPHeader(igmp)
	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+IPV4_HEADER_SIZE-4])
	igmplen := uint32(ipv4.GetLength() - ipv4.GetHeaderLen())

	igmpType := igmph.GetType()

	if (igmpType != IGMP_TYPE_DVMRP) &&
		(ipv4.GetTTL() != 1) {
		o.stats.pktRxBadttl++
		return core.PARSER_ERR
	}

	var queryver int
	queryver = 0

	igmpcode := igmph.GetCode()

	switch igmpType {
	case uint8(layers.IGMPMembershipQuery):
		if igmplen == IGMP_HEADER_MINLEN {
			if igmpcode == 0 {
				queryver = IGMP_VERSION_1
			} else {
				queryver = IGMP_VERSION_2
			}
		} else {
			if igmplen >= IGMP_V3_QUERY_MINLEN {
				queryver = IGMP_VERSION_3
			} else {
				o.stats.pktRxTooshort++
				return -1
			}
		}
		switch queryver {
		case IGMP_VERSION_1:
			o.stats.pktRxv1v2Queries++
			return o.HandleRxIgmpV1Query(ps)

		case IGMP_VERSION_2:
			o.stats.pktRxv1v2Queries++
			return o.HandleRxIgmpV2Query(ps)
		case IGMP_VERSION_3:
			o.stats.pktRxv3Queries++
			nsrc := igmph.GetNumSrc()
			if uint32(nsrc)*4 > (igmplen - IGMP_V3_QUERY_MINLEN) {
				o.stats.pktRxTooshort++
				return -1
			}
			return o.HandleRxIgmpV3Query(ps)
		}
	case uint8(layers.IGMPMembershipReportV1):
		// TBD need to add
		o.stats.pktRxReports++
	case uint8(layers.IGMPMembershipReportV2):
		// TBD need to add
		o.stats.pktRxReports++
	case uint8(layers.IGMPMembershipReportV3):
		o.stats.pktRxNora++

	}
	/* source ip should be a valid ipv4 */
	return 0
}

// HandleRxIgmpPacket Parser call this function with mbuf from the pool
func HandleRxIgmpPacket(ps *core.ParserPacketState) int {
	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(IGMP_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	igmpPlug := nsplg.Ext.(*mldNsCtx)
	return igmpPlug.HandleRxIgmpPacket(ps)
}
