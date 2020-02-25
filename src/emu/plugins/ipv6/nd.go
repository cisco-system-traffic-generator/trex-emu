package ipv6

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"net"
	"time"
	"unsafe"
)

var defaultRetryTimerSec = [...]uint8{1, 1, 1, 1, 3, 5, 7, 17}

const (
	defaultCompleteTimer = 10 * time.Minute
	defaultLearnTimer    = 1 * time.Minute
	stateLearned         = 16 /* valid timer in query */
	stateIncomplete      = 17
	stateComplete        = 18
	stateRefresh         = 19 /* re-query wait for results to get back to stateQuery */
)

// refresh the time here
// I would like to make this table generic, let try to the table without generic first
// then optimize it

type NdCacheFlow struct {
	dlist  core.DList
	head   core.DList /* pointer */
	timer  core.CHTimerObj
	ipv6   core.Ipv6Key // key
	state  uint8
	index  uint8
	touch  bool
	refc   uint32
	action core.CClientDg
}

type MapNdTbl map[core.Ipv6Key]*NdCacheFlow

type Ipv6NsStats struct {
	eventsChangeSrc      uint64
	eventsChangeDgIPv6   uint64
	timerEventLearn      uint64
	timerEventIncomplete uint64
	timerEventComplete   uint64
	timerEventRefresh    uint64

	addLearn                   uint64
	addIncomplete              uint64
	moveIncompleteAfterRefresh uint64
	moveComplete               uint64
	moveLearned                uint64

	pktRxErrTooShort             uint64
	pktRxErrNoBroadcast          uint64
	pktRxErrWrongOp              uint64
	pktRxErrWrongHopLimit        uint64
	pktRxRouterLifetimeZero      uint64
	pktRxErrRouterLifetimeTooBig uint64
	pktRxErrRouternotLinklocal   uint64
	pktRxRouterSolicitation      uint64
	pktRxRouterAdvertisement     uint64
	pktRxNeighborAdvertisement   uint64
	pktRxNeighborSolicitation    uint64

	pktRxArpQuery         uint64
	pktRxArpQueryNotForUs uint64
	pktRxArpReply         uint64
	pktTxArpQuery         uint64
	pktTxGArp             uint64
	pktTxReply            uint64
	tblActive             uint64
	tblAdd                uint64
	tblRemove             uint64
	associateWithClient   uint64
	disasociateWithClient uint64
}

func NewIpv6NsStatsDb(o *Ipv6NsStats) *core.CCounterDb {
	db := core.NewCCounterDb("ipv6nd")
	db.Add(&core.CCounterRec{
		Counter:  &o.eventsChangeSrc,
		Name:     "eventsChangeSrc",
		Help:     "change src ipv6 events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.eventsChangeDgIPv6,
		Name:     "eventsChangeDgIPv6",
		Help:     "change dgw ipv6 events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventLearn,
		Name:     "timerEventLearn",
		Help:     "timer events learn",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventIncomplete,
		Name:     "timerEventIncomplete",
		Help:     "timer events incomplete",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventComplete,
		Name:     "timerEventComplete",
		Help:     "timer events complete",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.timerEventRefresh,
		Name:     "timerEventRefresh",
		Help:     "timer events refresh",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.addLearn,
		Name:     "addLearn",
		Help:     "add learn to table ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.addIncomplete,
		Name:     "addIncomplete",
		Help:     "add incomplete to table ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.moveIncompleteAfterRefresh,
		Name:     "moveIncompleteAfterRefresh",
		Help:     "move incomplete after refresh  ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.moveComplete,
		Name:     "moveComplete",
		Help:     "move complete ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.moveLearned,
		Name:     "moveLearned",
		Help:     "move learn ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrTooShort,
		Name:     "pktRxErrTooShort",
		Help:     "rx error packet is too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrNoBroadcast,
		Name:     "pktRxErrNoBroadcast",
		Help:     "rx error packet is no broadcast",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrWrongOp,
		Name:     "pktRxErrWrongOp",
		Help:     "rx error packet with wrong opcode",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxArpQuery,
		Name:     "pktRxArpQuery",
		Help:     "rx ipv6 nd query ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxArpQueryNotForUs,
		Name:     "pktRxArpQueryNotForUs",
		Help:     "rx ipv6 nd query not for our clients",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxArpReply,
		Name:     "pktRxArpReply",
		Help:     "rx ipv6 nd reply",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxArpQuery,
		Name:     "pktTxNdQuery",
		Help:     "tx ipv6 nd query",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxGArp,
		Name:     "pktTxNd",
		Help:     "tx ipv6 nd garp",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxReply,
		Name:     "pktTxReply",
		Help:     "tx ipv6 nd reply",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblActive,
		Name:     "tblActive",
		Help:     "ipv6 nd table active",
		Unit:     "entries",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblAdd,
		Name:     "tblAdd",
		Help:     "ipv6 nd table add",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblRemove,
		Name:     "tblRemove",
		Help:     "ipv6 nd table remove",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.associateWithClient,
		Name:     "associateWithClient",
		Help:     "associate with client",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.disasociateWithClient,
		Name:     "disasociateWithClient",
		Help:     "disassociate with client",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborSolicitation,
		Name:     "pktRxNeighborSolicitation",
		Help:     "rx neighbor solicitation",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNeighborAdvertisement,
		Name:     "pktRxNeighborAdvertisement",
		Help:     "Rx neighbor advertisement",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRouterAdvertisement,
		Name:     "pktRxRouterAdvertisement",
		Help:     "Rx router advertisement",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRouterSolicitation,
		Name:     "pktRxRouterSolicitation",
		Help:     "Rx router solicitation",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrRouternotLinklocal,
		Name:     "pktRxErrRouternotLinklocal",
		Help:     "router advertisement not from local link",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrRouterLifetimeTooBig,
		Name:     "pktRxErrRouterLifetimeTooBig",
		Help:     "router advertisement lifetime is too big",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRouterLifetimeZero,
		Name:     "pktRxRouterLifetimeZero",
		Help:     "router advertisement lifetime is zero not selected router",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrWrongHopLimit,
		Name:     "pktRxErrWrongHopLimit",
		Help:     "ipv6 hop limit should be 255",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

// Ipv6NsCacheFlow manage the ipv6 -> mac with timeout for outside case
// inside are resolved
type Ipv6NsCacheFlow struct {
	timerw        *core.TimerCtx
	tbl           MapNdTbl
	head          core.DList
	completeTicks uint32 /* timer to send query */
	learnTimer    uint32
	second        uint32 /* timer to remove */
	stats         *Ipv6NsStats
}

func (o *Ipv6NsCacheFlow) Create(timerw *core.TimerCtx) {
	o.timerw = timerw
	o.tbl = make(MapNdTbl)
	o.head.SetSelf()
	o.completeTicks = timerw.DurationToTicks(defaultCompleteTimer)
	o.learnTimer = timerw.DurationToTicks(defaultLearnTimer)
	o.second = timerw.DurationToTicks(time.Second)
}

func (o *Ipv6NsCacheFlow) OnRemove() {
	for k := range o.tbl {
		flow := o.tbl[k]
		o.OnRemoveFlow(flow)
	}
}

func (o *Ipv6NsCacheFlow) OnRemoveFlow(flow *NdCacheFlow) {
	/* make sure the timer is stopped as it is linked to another resource */
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	}
}

// OnRemove called when there is no ref to this object
func (o *Ipv6NsCacheFlow) OnDeleteFlow(flow *NdCacheFlow) {
	if flow.refc != 0 {
		panic(" Ipv6NsCacheFlow ref counter should be zero ")
	}
	o.head.RemoveNode(&flow.dlist)
	flow.action.IpdgResolved = false
	flow.action.IpdgMac.Clear()
	_, ok := o.tbl[flow.ipv6]
	if ok {
		delete(o.tbl, flow.ipv6)
		o.stats.tblRemove++
		o.stats.tblActive--
	} else {
		// somthing is wrong here, can't find the flow
		panic(" Ipv6NsCacheFlow can't find the flow for removing ")
	}
}

/*AssociateWithClient  associate the flow with a client
and return if this is the first and require to send GARP and Query*/
func (o *Ipv6NsCacheFlow) AssociateWithClient(flow *NdCacheFlow) bool {
	if flow.state == stateLearned {
		if flow.refc != 0 {
			panic("AssociateWithClient ref should be zero in learn mode")
		}
		flow.refc = 1
		o.MoveToComplete(flow)
	} else {
		flow.refc += 1
	}
	return false
}

// AddNew in case it does not found
// state could be  stateLearnedor incomplete
func (o *Ipv6NsCacheFlow) AddNew(ipv6 core.Ipv6Key,
	IpdgMac *core.MACKey, state uint8) *NdCacheFlow {
	_, ok := o.tbl[ipv6]
	if ok {
		panic(" ipv6cacheflow  already exits   ")
	}

	o.stats.tblAdd++
	o.stats.tblActive++
	flow := new(NdCacheFlow)
	flow.ipv6 = ipv6
	flow.state = state
	flow.head.SetSelf()
	if IpdgMac != nil {
		flow.action.IpdgResolved = true
		flow.action.IpdgMac = *IpdgMac
	} else {
		flow.action.IpdgResolved = false
	}
	flow.timer.SetCB(o, flow, 0)

	o.tbl[ipv6] = flow
	o.head.AddLast(&flow.dlist)
	if state == stateLearned {
		o.stats.addLearn++
		flow.refc = 0
		o.timerw.StartTicks(&flow.timer, o.learnTimer)
	} else {
		if state == stateIncomplete {
			flow.refc = 1
			o.stats.addIncomplete++
			ticks := o.GetNextTicks(flow)
			o.timerw.StartTicks(&flow.timer, ticks)
		} else {
			panic(" not valid state ")
		}
	}
	return flow
}

func (o *Ipv6NsCacheFlow) MoveToLearn(flow *NdCacheFlow) {
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	} else {
		panic("MoveToLearn timer should always on")
	}
	flow.touch = false
	o.timerw.StartTicks(&flow.timer, o.learnTimer)
	flow.state = stateLearned
	o.stats.moveLearned++
}

func (o *Ipv6NsCacheFlow) MoveToComplete(flow *NdCacheFlow) {
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	} else {
		panic("MoveToComplete timer should always on")
	}
	flow.touch = false
	o.timerw.StartTicks(&flow.timer, o.completeTicks)
	flow.state = stateComplete
	o.stats.moveComplete++
}

func (o *Ipv6NsCacheFlow) NdLearn(flow *NdCacheFlow, mac *core.MACKey) {

	flow.action.IpdgResolved = true
	flow.action.IpdgMac = *mac
	switch flow.state {
	case stateLearned:
		flow.touch = true
	case stateIncomplete:
		o.MoveToComplete(flow)
	case stateComplete:
		flow.touch = true
	case stateRefresh:
		o.MoveToComplete(flow)
	default:
		panic("NdLearn ")
	}
}

// Lookup for a resolution
func (o *Ipv6NsCacheFlow) Lookup(ipv6 core.Ipv6Key) *NdCacheFlow {
	v, ok := o.tbl[ipv6]
	if ok {
		/* read does not update the timer only packets */
		return v
	}
	return nil
}

/*SendQuery on behalf of the first client */
func (o *Ipv6NsCacheFlow) SendQuery(flow *NdCacheFlow) {
	if flow.state == stateRefresh || flow.state == stateIncomplete {
		if flow.head.IsEmpty() {
			panic("SendQuery no valid list  ")
		}
		/* take the first and query */
		cplg := pluginArpClientCastfromDlist(flow.head.Next())
		cplg.SendQuery()
	} else {
		panic("SendQuery in not valid state ")
	}
}

func (o *Ipv6NsCacheFlow) GetNextTicks(flow *NdCacheFlow) uint32 {
	index := flow.index
	maxl := uint8((len(defaultRetryTimerSec) - 1))
	if index < maxl {
		index++
	} else {
		index = maxl
	}
	flow.index = index
	sec := defaultRetryTimerSec[index]
	ticks := o.timerw.DurationToTicks(time.Duration(sec) * time.Second)
	return ticks
}

func (o *Ipv6NsCacheFlow) handleRefreshState(flow *NdCacheFlow) {
	ticks := o.GetNextTicks(flow)
	o.timerw.StartTicks(&flow.timer, ticks)
	o.SendQuery(flow)
	if flow.index > 2 {
		/* don't use the old data */
		flow.state = stateIncomplete
		o.stats.moveIncompleteAfterRefresh++
		flow.action.IpdgResolved = false
		flow.action.IpdgMac.Clear()
	}
}

/* OnEvent timer callback */
func (o *Ipv6NsCacheFlow) OnEvent(a, b interface{}) {
	flow := a.(*NdCacheFlow)
	switch flow.state {
	case stateLearned:
		o.stats.timerEventLearn++
		if flow.touch {
			flow.touch = false
			o.timerw.StartTicks(&flow.timer, o.learnTimer)
		} else {
			o.OnDeleteFlow(flow)
		}
	case stateIncomplete:
		o.stats.timerEventIncomplete++
		ticks := o.GetNextTicks(flow)
		o.timerw.StartTicks(&flow.timer, ticks)
		o.SendQuery(flow)
	case stateComplete:
		o.stats.timerEventComplete++
		if flow.touch {
			flow.touch = false
			o.timerw.StartTicks(&flow.timer, o.completeTicks)
		} else {
			flow.state = stateRefresh
			flow.index = 0
			o.handleRefreshState(flow)
		}
	case stateRefresh:
		o.stats.timerEventRefresh++
		o.handleRefreshState(flow)

	default:
		panic("Ipv6nd on event  ")
	}
}

func pluginArpClientCastfromDlist(o *core.DList) *NdClientCtx {
	var s NdClientCtx
	return (*NdClientCtx)(unsafe.Pointer(uintptr(unsafe.Pointer(o)) - unsafe.Offsetof(s.dlist)))
}

// NdClientCtx nd information per client
type NdClientCtx struct {
	base   *PluginIpv6Client
	dlist  core.DList /* to link to NdCacheFlow */
	nsPlug *NdNsCtx
	mld    *mldNsCtx
}

func (o *NdClientCtx) preparePacketTemplate() {
	//l2 := o.base.Client.GetL2Header(true, uint16(layers.EthernetTypeARP))
	//arpOffset := len(l2)
	/*o.pktOffset = uint16(arpOffset)
	arpHeader := core.PacketUtlBuild(&layers.ARP{
		AddrType:          0x1,
		Protocol:          0x800,
		HwAddressSize:     0x6,
		ProtAddressSize:   0x4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   o.Client.Mac[:],
		SourceProtAddress: []uint8{0x0, 0x0, 0x0, 0x0},
		DstHwAddress:      []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		DstProtAddress:    []uint8{0x00, 0x00, 0x00, 0x00}})
	o.arpPktTemplate = append(l2, arpHeader...)
	o.arpHeader = layers.ArpHeader(o.arpPktTemplate[arpOffset : arpOffset+28])*/
}

func (o *NdClientCtx) Init(base *PluginIpv6Client,
	nsPlug *NdNsCtx,
	ctx *core.CThreadCtx,
	mld *mldNsCtx,
	initJson []byte) {
	o.base = base
	o.mld = mld
	o.dlist.SetSelf()
	o.preparePacketTemplate()
	o.nsPlug = nsPlug
	o.OnCreate()
}

/*OnEvent support event change of IP  */
func (o *NdClientCtx) OnEvent(msg string, a, b interface{}) {
	/*
		switch msg {
		case core.MSG_UPDATE_IPV6_ADDR:
			oldIPv6 := a.(core.Ipv6Key)
			newIPv6 := b.(core.Ipv6Key)
			if newIPv6.IsZero() != oldIPv6.IsZero() {
				o.NdNsCtx.stats.eventsChangeSrc++
				o.OnChangeDGSrcIPv4(o.Client.DgIpv4,
					o.Client.DgIpv6,
					!oldIPv6.IsZero(),
					!newIPv6.IsZero())
			}

		case core.MSG_UPDATE_DGIPV6_ADDR:
			oldIPv6 := a.(core.Ipv6Key)
			newIPv6 := b.(core.Ipv6Key)
			if newIPv6 != oldIPv6 {
				o.NdNsCtx.stats.eventsChangeDgIPv6++
				o.OnChangeDGSrcIPv4(oldIPv6,
					newIPv6,
					!o.Client.Ipv6.IsZero(),
					!o.Client.Ipv6.IsZero()) // TBD which IPv6 I need to take
			}

		}
	*/

}

var arpEvents = []string{core.MSG_UPDATE_IPV6_ADDR, core.MSG_UPDATE_DGIPV6_ADDR}

/*OnChangeDGSrcIPv4 - called in case there is a change in DG or srcIPv4 */
func (o *NdClientCtx) OnChangeDGSrcIPv6(oldDgIpv6 core.Ipv6Key,
	newDgIpv6 core.Ipv6Key,
	oldIsSrcIPv6 bool,
	NewIsSrcIPv6 bool) {
	if oldIsSrcIPv6 && !oldDgIpv6.IsZero() {
		// remove
		//TBD need to fix
		//o.arpNsPlug.DisassociateClient(o, oldDgIpv4)
	}
	if NewIsSrcIPv6 && !newDgIpv6.IsZero() {
		//there is a valid src IPv4 and valid new DG
		//TBD need to fix
		//o.arpNsPlug.AssociateClient(o)
	}
}

func (o *NdClientCtx) OnPrePreRemove(ctx *core.PluginCtx) {

}

func (o *NdClientCtx) OnPreRemove(ctx *core.PluginCtx) {

}

func (o *NdClientCtx) OnPostCreate(ctx *core.PluginCtx) {
	o.mld.flushAddCache()
}

func (o *NdClientCtx) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	o.OnChangeDGSrcIPv6(o.base.Client.DgIpv6,
		o.base.Client.DgIpv6,
		!o.base.Client.Ipv6.IsZero(),
		false)
	//ctx.UnregisterEvents(&o.PluginBase, arpEvents)
}

func (o *NdClientCtx) OnCreate() {

	mac := o.base.Client.Mac
	// set des
	// all nodes
	o.mld.addMcCache(core.Ipv6Key{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	// solicited node addr
	o.mld.addMcCache(core.Ipv6Key{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, mac[3], mac[4], mac[5]})

	if !o.nsPlug.IsRouterSolActive() {
		// if it is not, start it
		o.nsPlug.StartRouterSol(mac)
	}

	// resolve the current default GW if exits
	if o.base.Client.Ipv6ForceDGW {
		return
	}

	// resolve the ipv6 default gateway if exits
	/*var oldDgIpv6 core.Ipv6Key
	o.OnChangeDGSrcIPv6(oldDgIpv6,
		o.base.Client.DgIpv6,
		false,
		!o.base.Client.Ipv6.IsZero())*/
}

func (o *NdClientCtx) SendGArp() {
	/*
		if !o.Client.Ipv4.IsZero() {
			o.arpNsPlug.stats.pktTxGArp++
			o.arpHeader.SetOperation(1)
			o.arpHeader.SetSrcIpAddress(o.Client.Ipv4.Uint32())
			o.arpHeader.SetDstIpAddress(o.Client.Ipv4.Uint32())
			o.arpHeader.SetDestAddress([]byte{0, 0, 0, 0, 0, 0})
			o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
		} else {
			panic("  SendGArp() arp wasn't sent ")
		}*/
}

func (o *NdClientCtx) SendQuery() {
	/*if !o.Client.DgIpv4.IsZero() {
		o.arpNsPlug.stats.pktTxArpQuery++
		o.arpHeader.SetOperation(1)
		o.arpHeader.SetSrcIpAddress(o.Client.Ipv4.Uint32())
		o.arpHeader.SetDstIpAddress(o.Client.DgIpv4.Uint32())
		o.arpHeader.SetDestAddress([]byte{0, 0, 0, 0, 0, 0})
		o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	} else {
		panic("  SendQuery() arp wasn't sent ")
	}*/
}

func (o *NdClientCtx) Respond(arpHeader *layers.ArpHeader) {

	/*o.arpNsPlug.stats.pktTxReply++

	o.arpHeader.SetOperation(2)
	o.arpHeader.SetSrcIpAddress(o.Client.Ipv4.Uint32())
	o.arpHeader.SetDstIpAddress(arpHeader.GetSrcIpAddress())
	o.arpHeader.SetDestAddress(arpHeader.GetSourceAddress())

	eth := layers.EthernetHeader(o.arpPktTemplate[0:12])

	eth.SetDestAddress(arpHeader.GetSourceAddress())
	o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	eth.SetBroadcast() /* back to default as broadcast */
}

func (o *NdClientCtx) SendRouterSolicitation() {

}

type RouterAdNsTimer struct {
}

func (o *RouterAdNsTimer) OnEvent(a, b interface{}) {
	ns := a.(*NdNsCtx)
	ns.onRouterAdTimerUpdate()
}

// NdNsCtx arp information per namespace
type NdNsCtx struct {
	base           *PluginIpv6Ns
	timerw         *core.TimerCtx
	tbl            Ipv6NsCacheFlow
	stats          Ipv6NsStats
	cdb            *core.CCounterDb
	routerAd       core.CClientIpv6Nd
	routeAdTimerCB RouterAdNsTimer
	routerAdTicks  uint32
	routerAdCnt    uint32
	timerRouterSo  core.CHTimerObj // timer to ask solicitation from the router
	routerSoMac    core.MACKey
}

func (o *NdNsCtx) Init(base *PluginIpv6Ns, ctx *core.CThreadCtx, initJson []byte) {
	o.base = base
	o.timerw = ctx.GetTimerCtx()
	o.tbl.Create(o.timerw)
	o.tbl.stats = &o.stats
	o.cdb = NewIpv6NsStatsDb(&o.stats)

	o.timerRouterSo.SetCB(&o.routeAdTimerCB, o, 0) // set the callback to OnEvent
	o.routerAdTicks = o.timerw.DurationToTicks(10 * time.Second)
}

func (o *NdNsCtx) IsRouterSolActive() bool {
	if !o.routerSoMac.IsZero() {
		return true
	}
	return false
}

func (o *NdNsCtx) StartRouterSol(routerSoMac core.MACKey) {
	o.routerSoMac = routerSoMac
	o.routerAdCnt = 0
	o.timerw.StartTicks(&o.timerRouterSo, o.routerAdTicks)
}

// callback in case of advTimer
func (o *NdNsCtx) onRouterAdTimerUpdate() {
	o.routerAdCnt++
	if o.routerAdCnt < 5 {
		o.SendRouterSolicitation(o.routerSoMac)
		o.timerw.StartTicks(&o.timerRouterSo, o.routerAdTicks)
	}
}

func (o *NdNsCtx) OnRemove(ctx *core.PluginCtx) {
	// stop timers
	if o.timerRouterSo.IsRunning() {
		o.timerw.Stop(&o.timerRouterSo)
	}

	o.tbl.OnRemove()
}

func (o *NdNsCtx) OnEvent(msg string, a, b interface{}) {

}

func (o *NdNsCtx) SendRouterSolicitation(srcMac core.MACKey) {

	// dynamic allocated because it is rare to have this message (once to trigger per namespace)
	l2 := o.base.Ns.GetL2Header(false, uint16(layers.EthernetTypeIPv6))
	ipoffset := len(l2)
	copy(l2[0:6], []byte{0x33, 0x33, 0, 0, 0, 2})
	copy(l2[6:12], srcMac[:])

	rsHeader := core.PacketUtlBuild(

		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       8,
			NextHeader:   layers.IPProtocolICMPv6,
			HopLimit:     255,
			SrcIP:        net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstIP:        net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		},

		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0)},

		&layers.ICMPv6RouterSolicitation{},
	)
	ipv6pktrs := append(l2, rsHeader...)

	pktSize := len(ipv6pktrs) + 16
	m := o.base.Tctx.MPool.Alloc(uint16(pktSize))
	m.Append(ipv6pktrs)
	p := m.GetData()

	ipv6 := layers.IPv6Header(p[ipoffset : ipoffset+IPV6_HEADER_SIZE])
	ipv6.SetPyloadLength(uint16(8))

	rcof := ipoffset + IPV6_HEADER_SIZE
	// update checksum
	cs := layers.PktChecksumTcpUdpV6(p[rcof:], 0, ipv6, 0, uint8(layers.IPProtocolICMPv6))
	binary.BigEndian.PutUint16(p[rcof+2:rcof+4], cs)
	o.base.Tctx.Veth.Send(m)
}

/*DisassociateClient remove association from the client. client now have the new data
 */
func (o *NdNsCtx) DisassociateClient(arpc *NdClientCtx,
	oldDgIpv4 core.Ipv4Key) {
	/*
		if oldDgIpv4.IsZero() {
			panic("DisassociateClient old ipv6 is not valid")
		}
		flow := o.tbl.Lookup(oldDgIpv4)
		if flow.refc == 0 {
			panic(" ref count can't be zero before remove")
		}
		flow.head.RemoveNode(&arpc.dlist)
		flow.refc--
		if flow.refc == 0 {
			// move to Learn
			if !flow.head.IsEmpty() {
				panic(" head should be empty ")
			}
			o.tbl.MoveToLearn(flow)
		} else {
			if flow.head.IsEmpty() {
				panic(" head should not be empty ")
			}
		}
		o.stats.disasociateWithClient++
		arpc.Client.DGW = nil
	*/
}

/*AssociateClient associate a new client object with a NdCacheFlow
  client object should be with valid source ipv6 and valid default gateway
  1. if object NdCacheFlow exists move it's state to complete and add ref counter
  2. if object NdCacheFlow does not exsits create new with ref=1 and return it
  3. if this is the first, generate GARP and
*/
func (o *NdNsCtx) AssociateClient(arpc *NdClientCtx) {
	/*
		if arpc.Client.Ipv4.IsZero() || arpc.Client.DgIpv4.IsZero() {
			panic("AssociateClient should have valid source ipv6 and default gateway ")
		}
		var firstUnresolve bool
		firstUnresolve = false
		ipv6 := arpc.Client.DgIpv4
		flow := o.tbl.Lookup(ipv6)
		if flow != nil {
			firstUnresolve = o.tbl.AssociateWithClient(flow)
		} else {
			flow = o.tbl.AddNew(ipv6, nil, stateIncomplete)
			firstUnresolve = true
		}

		o.stats.associateWithClient++
		flow.head.AddLast(&arpc.dlist)

		if firstUnresolve {
			arpc.SendGArp()
			arpc.SendQuery()
		}

		arpc.Client.DGW = &flow.action*/
}

func (o *NdNsCtx) NdLearn(arpHeader *layers.ArpHeader) {

	/*
		var ipv6 core.Ipv4Key
		var mkey core.MACKey
		ipv6.SetUint32(arpHeader.GetSrcIpAddress())
		copy(mkey[0:6], arpHeader.GetSourceAddress())

		flow := o.tbl.Lookup(ipv6)

		if flow != nil {
			o.tbl.NdLearn(flow, &mkey)
		} else {
			o.tbl.AddNew(ipv6, &mkey, stateLearned)
		}
	*/
}

func (o *NdNsCtx) SetTruncated() {

}

//HandleRxIpv6NdPacket there is no need to free  buffer
func (o *NdNsCtx) HandleRxIpv6NdPacket(ps *core.ParserPacketState, code layers.ICMPv6TypeCode) int {

	m := ps.M
	p := m.GetData()
	nd := p[ps.L4+4:]
	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+40])

	switch code {

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0):
		o.stats.pktRxRouterSolicitation++
		return core.PARSER_OK // nothing to do

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0):
		o.stats.pktRxRouterAdvertisement++

		var ra layers.ICMPv6RouterAdvertisement
		err := ra.DecodeFromBytes(nd, o)
		if err != nil {
			o.stats.pktRxErrTooShort++
			return core.PARSER_ERR
		}

		if ipv6.HopLimit() != 255 {
			o.stats.pktRxErrWrongHopLimit++
			return core.PARSER_ERR
		}

		ipaddr := net.IP(ipv6.SrcIP())

		if !ipaddr.IsLinkLocalUnicast() {
			o.stats.pktRxErrRouternotLinklocal++
			return core.PARSER_ERR
		}

		if ra.RouterLifetime > 9000 {
			o.stats.pktRxErrRouterLifetimeTooBig++
			return core.PARSER_ERR
		}

		if ra.RouterLifetime == 0 {
			o.stats.pktRxRouterLifetimeZero++
			return core.PARSER_OK // nothing to do
		}

		// we got the first RouterAdv
		if o.timerRouterSo.IsRunning() {
			o.timerw.Stop(&o.timerRouterSo)
		}

		for _, opt := range ra.Options {
			switch opt.Type {

			case layers.ICMPv6OptSourceAddress, layers.ICMPv6OptTargetAddress:
				if len(opt.Data) == 6 {
					copy(o.routerAd.DgMac[:], opt.Data[:])
				}
			case layers.ICMPv6OptPrefixInfo:
				if len(opt.Data) == 30 {
					prefixLen := uint8(opt.Data[0])
					//onLink := (opt.Data[1]&0x80 != 0)
					//autonomous := (opt.Data[1]&0x40 != 0)
					validLifetime := binary.BigEndian.Uint32(opt.Data[2:6])
					preferredLifetime := binary.BigEndian.Uint32(opt.Data[6:10])
					prefix := net.IP(opt.Data[14:])

					if prefixLen <= 64 && (validLifetime > 0) && (preferredLifetime > 0) {
						// valid prefix
						o.routerAd.PrefixLen = prefixLen
						if len(prefix) == 16 {
							copy(o.routerAd.PrefixIpv6[:], prefix[:])
						}
					}
				}
			case layers.ICMPv6OptRedirectedHeader:
				// could invoke IP decoder on data... probably best not to
				break
			case layers.ICMPv6OptMTU:
				if len(opt.Data) == 6 {
					o.routerAd.MTU = uint16(binary.BigEndian.Uint32(opt.Data[2:]))
				}

			}
		}

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0):
		o.stats.pktRxNeighborSolicitation++
		// TBD is it ours need to answer
		return core.PARSER_OK

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0):
		o.stats.pktRxNeighborAdvertisement++
		// TBD is it answer for us?
		return core.PARSER_OK //

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRedirect, 0):
		return core.PARSER_OK

	default:
		panic(" HandleRxIpv6NdPacket not supported ")
	}

	/*
		arpHeader := layers.ArpHeader(p[l3:])
		ethHeader := layers.EthernetHeader(p[0:6])

		switch arpHeader.GetOperation() {
		case layers.ARPRequest:
			if !ethHeader.IsBroadcast() {
				o.stats.pktRxErrNoBroadcast++
				return
			}
			o.stats.pktRxArpQuery++
			// learn the request information
			o.NdLearn(&arpHeader)

			var ipv6 core.Ipv4Key

			ipv6.SetUint32(arpHeader.GetDstIpAddress())

			client := o.Ns.CLookupByIPv4(&ipv6)
			if client != nil {
				cplg := client.PluginCtx.Get(ARP_PLUG)
				if cplg != nil {
					arpCPlug := cplg.Ext.(*NdClientCtx)
					arpCPlug.Respond(&arpHeader)
				}
			} else {
				o.stats.pktRxArpQueryNotForUs++
			}

		case layers.ARPReply:
			if ethHeader.IsBroadcast() {
				o.stats.pktRxErrNoBroadcast++
				return
			}
			o.stats.pktRxArpReply++
			o.NdLearn(&arpHeader)

		default:
			o.stats.pktRxErrWrongOp++
		}*/

	return core.PARSER_OK
}
