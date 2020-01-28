package igmp

/*
Support a simplified version of IPv4 IGMP v3/v2/v1 RFC3376
v3 does not support EXCLUDE/INCLUDE per client
The implementation is in the namespace domain (shared for all the clients on the same network)
One client ipv4/mac is the designator to answer the queries for all the clients.
However this implementation can scale
*/

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"math/rand"
	"net"
	"time"
	"unsafe"

	"github.com/intel-go/fastjson"
)

const (
	IGMP_PLUG                      = "igmp"
	IGMP_VERSION_1                 = 1
	IGMP_VERSION_2                 = 2
	IGMP_VERSION_3                 = 3 /* Default */
	IGMP_TYPE_DVMRP                = 0x13
	IGMP_HEADER_MINLEN             = 8
	IGMP_V3_QUERY_MINLEN           = 12
	IGMP_MC_ADDR_MASK              = 0xE0000000
	IGMP_MC_DEST_HOST              = 0xE0000001
	IGMP_NULL_HOST                 = 0x00000000
	IGMP_GRPREC_HDRLEN             = 8
	IGMP_V3_REPORT_MINLEN          = 8
	IGMP_DO_NOTHING                = 0    /* don't send a record */
	IGMP_MODE_IS_INCLUDE           = 1    /* MODE_IN */
	IGMP_MODE_IS_EXCLUDE           = 2    /* MODE_EX */
	IGMP_CHANGE_TO_INCLUDE_MODE    = 3    /* TO_IN */
	IGMP_CHANGE_TO_EXCLUDE_MODE    = 4    /* TO_EX */
	IGMP_ALLOW_NEW_SOURCES         = 5    /* ALLOW_NEW */
	IGMP_BLOCK_OLD_SOURCES         = 6    /* BLOCK_OLD */
	IGMP_HOST_LEAVE_MESSAGE        = 0x17 /* Leave-group message     */
	IGMP_v2_HOST_MEMBERSHIP_REPORT = 0x16 /* Ver. 2 membership report */
	IPV4_HEADER_SIZE               = 24   /* plus router alert */
)

type IgmpNsStats struct {
	pktRxTotal    uint64 /* total IGMP messages received */
	pktRxTooshort uint64 /* received with too few bytes */
	pktRxBadttl   uint64 /* received with ttl other than 1 */
	pktRxBadsum   uint64 /* received with bad checksum */
	pktRxNoKey    uint64 /* received igmp but can't find port,vlan keys */
	/*
	* Query statistics.
	 */
	pktRxv1Queries         uint64 /* received IGMPv1/IGMPv2 queries */
	pktRxv1v2Queries       uint64 /* received IGMPv1/IGMPv2 queries */
	pktRxv3Queries         uint64 /* received IGMPv3 queries */
	pktRxbadQueries        uint64 /* received invalid queries */
	pktRxgenQueries        uint64 /* received general queries */
	pktRxgroupQueries      uint64 /* received group queries */
	pktRxgsrQueries        uint64 /* received group-source queries */
	pktRxgsrDropQueries    uint64 /* dropped group-source queries */
	pktRxquerieActiveTimer uint64 /* rcv querie while active timer */

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
}

func NewIgmpNsStatsDb(o *IgmpNsStats) *core.CCounterDb {
	db := core.NewCCounterDb("igmp")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxTotal,
		Name:     "pktRxTotal",
		Help:     "total IGMP messages received",
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
		Help:     "received IGMPv1/IGMPv2 queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxv1v2Queries,
		Name:     "pktRxv1v2Queries",
		Help:     "received IGMPv1/IGMPv2 queries",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxv3Queries,
		Name:     "pktRxv3Queries",
		Help:     "received IGMPv3 queries",
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

	return db
}

func covertToIgmpEntry(dlist *core.DList) *IgmpEntry {
	return (*IgmpEntry)(unsafe.Pointer(dlist))
}

//IgmpEntry includes one ipv4 mc addr
type IgmpEntry struct {
	dlist     core.DList // must be first
	Ipv4      core.Ipv4Key
	epocQuery uint32
}

type MapIgmp map[core.Ipv4Key]*IgmpEntry

//IgmpFlowTbl  map/dlist of the igmp entries
type IgmpFlowTbl struct {
	mapIgmp    MapIgmp
	head       core.DList
	activeIter *core.DList /* pointer to the next object, in case of active */
	epoc       uint32      /* operation epoc for add/remove/rpc iterator */
	epocQuery  uint32
	stats      *IgmpNsStats
}

func NewIgmpTable() *IgmpFlowTbl {
	o := new(IgmpFlowTbl)
	var stats IgmpNsStats
	o.OnCreate(&stats)
	return o
}

func (o *IgmpFlowTbl) incEpocQuery() {
	o.epocQuery++
}

func (o *IgmpFlowTbl) OnCreate(stats *IgmpNsStats) {
	o.mapIgmp = make(MapIgmp)
	o.head.SetSelf()
	o.activeIter = nil
	o.stats = stats
}

func (o *IgmpFlowTbl) addMc(ipv4 core.Ipv4Key) error {
	_, ok := o.mapIgmp[ipv4]
	if ok {
		return fmt.Errorf(" mc-ipv4 %v already exist", ipv4)
	}
	// create new entry
	e := new(IgmpEntry)
	e.Ipv4 = ipv4
	e.epocQuery = o.epocQuery
	o.mapIgmp[ipv4] = e
	o.head.AddLast(&e.dlist)
	return nil
}

func (o *IgmpFlowTbl) removeMc(ipv4 core.Ipv4Key) error {
	e, ok := o.mapIgmp[ipv4]
	if !ok {
		return fmt.Errorf(" mc-ipv4 %v does not exist", ipv4)
	}
	delete(o.mapIgmp, ipv4)
	/* handle the iterator in case of remove */
	if o.activeIter == &e.dlist {
		// it is going to be removed
		o.activeIter = e.dlist.Next()
	}
	o.head.RemoveNode(&e.dlist)
	return nil
}

//dumpAll for debug and testing
func (o *IgmpFlowTbl) dumpAll() {

	var it core.DListIterHead
	cnt := 0
	for it.Init(&o.head); it.IsCont(); it.Next() {
		e := covertToIgmpEntry(it.Val())
		fmt.Printf(" %v:%v \n", cnt, e.Ipv4)
		cnt++
	}
}

// PluginIgmpClient icmp information per client
type PluginIgmpClient struct {
	core.PluginBase
	igmpNsPlug *PluginIgmpNs
}

var igmpEvents = []string{}

/*NewIgmpClient create plugin */
func NewIgmpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIgmpClient)
	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, igmpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(IGMP_PLUG)
	o.igmpNsPlug = nsplg.Ext.(*PluginIgmpNs)
	o.OnCreate()
	return &o.PluginBase
}

/*OnEvent support event change of IP  */
func (o *PluginIgmpClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginIgmpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, igmpEvents)
}

func (o *PluginIgmpClient) OnCreate() {
}

type PluginIgmpNsTimer struct {
}

func (o *PluginIgmpNsTimer) OnEvent(a, b interface{}) {
	pigmp := a.(*PluginIgmpNs)
	pigmp.onTimerUpdate()
}

// PluginIgmpNs icmp information per namespace
type PluginIgmpNs struct {
	core.PluginBase
	designatorMac   core.MACKey // designator MAC key to client id
	timerw          *core.TimerCtx
	tbl             IgmpFlowTbl
	igmpVersion     uint16
	mtu             uint16
	maxresp         uint32 /* in 1/10ths of a second  */
	qqi             uint32 /* interval  */
	qrv             uint8  /* qrv */
	activeQuery     bool   /* true in case there is a active query */
	started         bool
	stats           IgmpNsStats
	cdb             *core.CCounterDb
	cdbv            *core.CCounterDbVec
	timer           core.CHTimerObj
	timerCb         PluginIgmpNsTimer
	tickMsec        uint32
	ipv4pktTemplate []byte
	ipv4Offset      uint16
	activeEpocQuery uint32
	rpcIterEpoc     uint32
	iter            core.DListIterHead
	iterReady       bool
}

func NewIgmpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIgmpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.cdb = NewIgmpNsStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("igmp")
	o.cdbv.Add(o.cdb)
	o.tbl.OnCreate(&o.stats)
	o.igmpVersion = IGMP_VERSION_3
	o.mtu = 1500
	o.qrv = 2
	o.qqi = 125
	o.maxresp = 100
	o.timerw = ctx.Tctx.GetTimerCtx()
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.preparePacketTemplate()
	return &o.PluginBase
}

func (o *PluginIgmpNs) IterReset() bool {
	o.rpcIterEpoc = o.tbl.epoc
	o.iter.Init(&o.tbl.head)
	if o.tbl.head.IsEmpty() {
		o.iterReady = false
		return true
	}
	o.iterReady = true
	return false
}

func (o *PluginIgmpNs) IterIsStopped() bool {
	return !o.iterReady
}

func (o *PluginIgmpNs) GetNext(n uint16) ([]core.Ipv4Key, error) {
	r := make([]core.Ipv4Key, 0)

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
		r = append(r, ent.Ipv4)
		o.iter.Next()
	}
	return r, nil
}

func (o *PluginIgmpNs) preparePacketTemplate() {

	l2 := o.Ns.GetL2Header(true, uint16(layers.EthernetTypeIPv4))
	o.ipv4Offset = uint16(len(l2))

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
	o.ipv4pktTemplate = append(l2, igmpHeader...)
}

func (o *PluginIgmpNs) OnRemove(ctx *core.PluginCtx) {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *PluginIgmpNs) OnEvent(msg string, a, b interface{}) {

}

/*OnTimerUpdate called on timer expiration */
func (o *PluginIgmpNs) onTimerUpdate() {
	var finish bool
	finish = o.startQueryReport()
	if finish {
		o.activeQuery = false
	} else {
		// restart the timer
		o.timerw.Start(&o.timer, time.Duration(o.tickMsec)*time.Millisecond)
	}
}

func (o *PluginIgmpNs) addMc(vecIpv4 []core.Ipv4Key) error {

	var err error
	vec := []uint32{}
	maxIds := int(o.getMaxIPv4Ids())
	o.tbl.epoc++
	for _, ipv4 := range vecIpv4 {
		err = o.tbl.addMc(ipv4)
		if err != nil {
			o.stats.opsAddErr++
			o.SendMcPacket(vec, false, false)
			return err
		}
		o.stats.opsAdd++
		vec = append(vec, ipv4.Uint32())
		if len(vec) == maxIds {
			o.SendMcPacket(vec, false, false)
			vec = vec[:0]
		}
	}
	o.SendMcPacket(vec, false, false)
	return nil
}

func (o *PluginIgmpNs) RemoveMc(vecIpv4 []core.Ipv4Key) error {
	var err error
	vec := []uint32{}
	o.tbl.epoc++
	maxIds := int(o.getMaxIPv4Ids())
	for _, ipv4 := range vecIpv4 {
		err = o.tbl.removeMc(ipv4)
		if err != nil {
			o.stats.opsRemoveErr++
			o.SendMcPacket(vec, true, false)
			return err
		}
		o.stats.opsRemove++
		vec = append(vec, ipv4.Uint32())
		if len(vec) == maxIds {
			o.SendMcPacket(vec, true, false)
			vec = vec[:0]
		}
	}
	o.SendMcPacket(vec, true, false)
	return nil
}
func (o *PluginIgmpNs) IsValidQueryEpoc(v uint32) bool {
	var d uint32
	d = o.activeEpocQuery - v
	if d > 0x80000000 {
		return false
	}
	return true
}
func (o *PluginIgmpNs) startQueryReport() bool {
	if !o.activeQuery {
		panic(" PluginIgmpNs start while active")
	}
	if o.started {
		/* in this first time reset the iterator */
		o.tbl.activeIter = o.tbl.head.Next()
		o.activeEpocQuery = o.tbl.epocQuery
		o.tbl.incEpocQuery()
		o.started = false
	}
	/* up to max ids -- derive from MTU */
	maxIds := int(o.getMaxIPv4Ids())
	finish := false
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
	return finish
}

func (o *PluginIgmpNs) SetTruncated() {

}

func (o *PluginIgmpNs) HandleRxIgmpV1Query(ps *core.ParserPacketState) int {
	o.stats.pktRxv1Queries++
	o.stats.pktRxgsrDropQueries++
	/* not supported for now */
	return 0
}

func (o *PluginIgmpNs) getPktSize(ids uint16) uint16 {
	pyload := 14 + IPV4_HEADER_SIZE + 4 + 2*4 + IGMP_V3_QUERY_MINLEN + 16 + ids*IGMP_V3_REPORT_MINLEN
	return (pyload)
}

func (o *PluginIgmpNs) getMaxIPv4Ids() uint16 {
	if o.igmpVersion == IGMP_VERSION_3 {
		pyload := o.mtu - (14 + 2*4 + IPV4_HEADER_SIZE + IGMP_V3_QUERY_MINLEN + 16)
		return pyload / IGMP_GRPREC_HDRLEN
	} else {
		return 1
	}
}

func (o *PluginIgmpNs) HandleRxIgmpCmn(isGenQuery bool, igmpAddr uint32) int {

	if isGenQuery {
		if o.activeQuery {
			/* can't handle query while there is another query */
			o.stats.pktRxquerieActiveTimer++
			return 0
		}
		var startMsec uint32
		cnt := uint32(len(o.tbl.mapIgmp))
		if cnt > 0 {
			maxIds := o.getMaxIPv4Ids()
			maxRespMsec := o.maxresp * 100

			devPerTick := cnt / uint32(maxIds)

			if devPerTick == 0 {
				/* only one report is needed */
				startMsec = uint32(rand.Intn(int(maxRespMsec)) + 1)
				o.tickMsec = 0
			} else {
				/* more than one report is needed  */
				o.tickMsec = maxRespMsec / (devPerTick + 1)
				startMsec = o.tickMsec
			}
			o.activeQuery = true
			o.started = true
			if o.timer.IsRunning() {
				panic(" igmp timer is running ")
			}
			o.timerw.Start(&o.timer, time.Duration(startMsec)*time.Millisecond)
		}

	} else {
		vec := []uint32{igmpAddr}
		o.SendMcPacket(vec, false, true)
	}
	return 0
}

func (o *PluginIgmpNs) SendMcPacket(vec []uint32, remove bool, query bool) {

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
	if rcds > int(o.getMaxIPv4Ids()) {
		panic(" PluginIgmpNs rcds> o.getMaxIPv4Ids() ")
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
			panic(" PluginIgmpNs rcds should be 1 for IGMPv2 ")
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

func (o *PluginIgmpNs) HandleRxIgmpV2Query(ps *core.ParserPacketState) int {
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
	fmt.Printf(" version 2 \n")
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

func (o *PluginIgmpNs) HandleRxIgmpV3Query(ps *core.ParserPacketState) int {
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
func (o *PluginIgmpNs) HandleRxIgmpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/

	//igmplen := m.PktLen() - uint32(ps.L4)
	igmp := p[ps.L4:]

	/* checksum */
	cs := layers.PktChecksum(igmp, 0)
	if cs != 0 {
		o.stats.pktRxBadsum++
		return -1
	}

	igmph := layers.IGMPHeader(igmp)
	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+IPV4_HEADER_SIZE-4])
	igmplen := uint32(ipv4.GetLength() - ipv4.GetHeaderLen())

	igmpType := igmph.GetType()

	if (igmpType != IGMP_TYPE_DVMRP) &&
		(ipv4.GetTTL() != 1) {
		o.stats.pktRxBadttl++
		return -1
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
		return -1
	}
	nsplg := ns.PluginCtx.Get(IGMP_PLUG)
	if nsplg == nil {
		return -1
	}
	igmpPlug := nsplg.Ext.(*PluginIgmpNs)
	return igmpPlug.HandleRxIgmpPacket(ps)
}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginIgmpCReg struct{}
type PluginIgmpNsReg struct{}

func (o PluginIgmpCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewIgmpClient(ctx, initJson)
}

func (o PluginIgmpNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewIgmpNs(ctx, initJson)
}

/*******************************************/
/* ICMP RPC commands */
type (
	ApiIgmpNsCntHandler struct{}
	ApiIgmpNsCntParams  struct {
		Meta bool     `json:"meta"`
		Zero bool     `json:"zero"`
		Mask []string `json:"mask"` // get only specific counters blocks if it is empty get all
	}

	ApiIgmpNsAddHandler struct{}
	ApiIgmpNsAddParams  struct {
		Vec []core.Ipv4Key `json:"vec"`
	}

	ApiIgmpNsRemoveHandler struct{}
	ApiIgmpNsRemoveParams  struct {
		Vec []core.Ipv4Key `json:"vec"`
	}

	ApiIgmpNsIterHandler struct{}
	ApiIgmpNsIterParams  struct {
		Reset bool   `json:"reset"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	}
	ApiIgmpNsIterResult struct {
		Empty  bool           `json:"empty"`
		Stoped bool           `json:"stoped"`
		Vec    []core.Ipv4Key `json:"data"`
	}

	ApiIgmpSetHandler struct{}
	ApiIgmpSetParams  struct {
		Mtu           uint16      `json:"mtu" validate:"required,gte=256,lte=9000"`
		DesignatorMac core.MACKey `json:"dmac"`
	}

	ApiIgmpGetHandler struct{}

	ApiIgmpGetResult struct {
		Mtu           uint16      `json:"mtu"`
		DesignatorMac core.MACKey `json:"dmac"`
		Version       uint8       `json:"version"`
	}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginIgmpNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, IGMP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginIgmpNs)

	return arpNs, nil
}

func getClient(ctx interface{}, params *fastjson.RawMessage) (*PluginIgmpClient, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, IGMP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpClient := plug.Ext.(*PluginIgmpClient)

	return arpClient, nil
}

func (h ApiIgmpSetHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiIgmpSetParams

	tctx := ctx.(*core.CThreadCtx)

	igmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	if p.Mtu > 0 {
		igmpNs.mtu = p.Mtu
	}

	if !p.DesignatorMac.IsZero() {
		igmpNs.designatorMac = p.DesignatorMac
	}
	return nil, nil
}

func (h ApiIgmpGetHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var res ApiIgmpGetResult

	igmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}

	res.Mtu = igmpNs.mtu
	res.DesignatorMac = igmpNs.designatorMac
	res.Version = uint8(igmpNs.igmpVersion)

	return &res, nil
}

func (h ApiIgmpNsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiIgmpNsCntParams
	tctx := ctx.(*core.CThreadCtx)

	igmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	cdbv := igmpNs.cdbv

	if p.Meta {
		return cdbv.MarshalMeta(), nil
	}

	if p.Mask == nil || len(p.Mask) == 0 {
		return cdbv.MarshalValues(p.Zero), nil
	} else {
		return cdbv.MarshalValuesMask(p.Zero, p.Mask), nil
	}
}

func (h ApiIgmpNsAddHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiIgmpNsAddParams
	tctx := ctx.(*core.CThreadCtx)

	igmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	err1 = igmpNs.addMc(p.Vec)

	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	return nil, nil
}

func (h ApiIgmpNsRemoveHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiIgmpNsRemoveParams
	tctx := ctx.(*core.CThreadCtx)

	igmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	err1 = igmpNs.RemoveMc(p.Vec)

	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	return nil, nil
}

func (h ApiIgmpNsIterHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiIgmpNsIterParams
	var res ApiIgmpNsIterResult

	tctx := ctx.(*core.CThreadCtx)

	igmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	if p.Reset {
		res.Empty = igmpNs.IterReset()
	}
	if res.Empty {
		return &res, nil
	}
	if igmpNs.IterIsStopped() {
		res.Stoped = true
		return &res, nil
	}

	keys, err2 := igmpNs.GetNext(p.Count)
	if err2 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err2.Error(),
		}
	}
	res.Vec = keys
	return &res, nil
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(IGMP_PLUG,
		core.PluginRegisterData{Client: PluginIgmpCReg{},
			Ns:     PluginIgmpNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command like ping etc
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("igmp_ns_cnt", ApiIgmpNsCntHandler{}, false)       // get counters/meta
	core.RegisterCB("igmp_ns_add", ApiIgmpNsAddHandler{}, false)       // add mc
	core.RegisterCB("igmp_ns_remove", ApiIgmpNsRemoveHandler{}, false) // remove mc
	core.RegisterCB("igmp_ns_iter", ApiIgmpNsIterHandler{}, false)     // iterator
	core.RegisterCB("igmp_ns_get_cfg", ApiIgmpGetHandler{}, false)     // Get
	core.RegisterCB("igmp_ns_set_cfg", ApiIgmpSetHandler{}, false)     // Set

	/* register callback for rx side*/
	core.ParserRegister("igmp", HandleRxIgmpPacket)
}
