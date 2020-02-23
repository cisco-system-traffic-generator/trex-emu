package arp

import (
	"emu/core"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"time"
	"unsafe"

	"github.com/intel-go/fastjson"
)

var defaultRetryTimerSec = [...]uint8{1, 1, 1, 1, 3, 5, 7, 17}

const (
	ARP_PLUG             = "arp"
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

type ArpFlow struct {
	dlist  core.DList
	head   core.DList /* pointer to PerClientARP object */
	timer  core.CHTimerObj
	ipv4   core.Ipv4Key // key
	state  uint8
	index  uint8
	touch  bool
	refc   uint32
	action core.CClientDg
}

type MapArpTbl map[core.Ipv4Key]*ArpFlow

type ArpNsStats struct {
	eventsChangeSrc      uint64
	eventsChangeDgIPv4   uint64
	timerEventLearn      uint64
	timerEventIncomplete uint64
	timerEventComplete   uint64
	timerEventRefresh    uint64

	addLearn                   uint64
	addIncomplete              uint64
	moveIncompleteAfterRefresh uint64
	moveComplete               uint64
	moveLearned                uint64

	pktRxErrTooShort    uint64
	pktRxErrNoBroadcast uint64
	pktRxErrWrongOp     uint64

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

func NewArpNsStatsDb(o *ArpNsStats) *core.CCounterDb {
	db := core.NewCCounterDb("arp")
	db.Add(&core.CCounterRec{
		Counter:  &o.eventsChangeSrc,
		Name:     "eventsChangeSrc",
		Help:     "change src ipv4 events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.eventsChangeDgIPv4,
		Name:     "eventsChangeDgIPv4",
		Help:     "change dgw ipv4 events",
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
		Help:     "rx arp query ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxArpQueryNotForUs,
		Name:     "pktRxArpQueryNotForUs",
		Help:     "rx arp query not for our clients",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxArpReply,
		Name:     "pktRxArpReply",
		Help:     "rx arp reply",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxArpQuery,
		Name:     "pktTxArpQuery",
		Help:     "tx arp query",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxGArp,
		Name:     "pktTxGArp",
		Help:     "tx arp garp",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxReply,
		Name:     "pktTxReply",
		Help:     "tx arp reply",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblActive,
		Name:     "tblActive",
		Help:     "arp table active",
		Unit:     "entries",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblAdd,
		Name:     "tblAdd",
		Help:     "arp table add",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.tblRemove,
		Name:     "tblRemove",
		Help:     "arp table remove",
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
	return db
}

// ArpFlowTable manage the ipv4-> mac with timeout for outside case
// inside are resolved
type ArpFlowTable struct {
	timerw        *core.TimerCtx
	tbl           MapArpTbl
	head          core.DList
	completeTicks uint32 /* timer to send query */
	learnTimer    uint32
	second        uint32 /* timer to remove */
	stats         *ArpNsStats
}

func (o *ArpFlowTable) Create(timerw *core.TimerCtx) {
	o.timerw = timerw
	o.tbl = make(MapArpTbl)
	o.head.SetSelf()
	o.completeTicks = timerw.DurationToTicks(defaultCompleteTimer)
	o.learnTimer = timerw.DurationToTicks(defaultLearnTimer)
	o.second = timerw.DurationToTicks(time.Second)
}

func (o *ArpFlowTable) OnRemove() {
	for k := range o.tbl {
		flow := o.tbl[k]
		o.OnRemoveFlow(flow)
	}
}

func (o *ArpFlowTable) OnRemoveFlow(flow *ArpFlow) {
	/* make sure the timer is stopped as it is linked to another resource */
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	}
}

// OnRemove called when there is no ref to this object
func (o *ArpFlowTable) OnDeleteFlow(flow *ArpFlow) {
	if flow.refc != 0 {
		panic(" ARP ref counter should be zero ")
	}
	o.head.RemoveNode(&flow.dlist)
	flow.action.IpdgResolved = false
	flow.action.IpdgMac.Clear()
	_, ok := o.tbl[flow.ipv4]
	if ok {
		delete(o.tbl, flow.ipv4)
		o.stats.tblRemove++
		o.stats.tblActive--
	} else {
		// somthing is wrong here, can't find the flow
		panic(" arp can't find the flow for removing ")
	}
}

/*AssociateWithClient  associate the flow with a client
and return if this is the first and require to send GARP and Query*/
func (o *ArpFlowTable) AssociateWithClient(flow *ArpFlow) bool {
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
func (o *ArpFlowTable) AddNew(ipv4 core.Ipv4Key,
	IpdgMac *core.MACKey, state uint8) *ArpFlow {
	_, ok := o.tbl[ipv4]
	if ok {
		panic(" arpflow  already exits   ")
	}

	o.stats.tblAdd++
	o.stats.tblActive++
	flow := new(ArpFlow)
	flow.ipv4 = ipv4
	flow.state = state
	flow.head.SetSelf()
	if IpdgMac != nil {
		flow.action.IpdgResolved = true
		flow.action.IpdgMac = *IpdgMac
	} else {
		flow.action.IpdgResolved = false
	}
	flow.timer.SetCB(o, flow, 0)

	o.tbl[ipv4] = flow
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

func (o *ArpFlowTable) MoveToLearn(flow *ArpFlow) {
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

func (o *ArpFlowTable) MoveToComplete(flow *ArpFlow) {
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

func (o *ArpFlowTable) ArpLearn(flow *ArpFlow, mac *core.MACKey) {

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
		panic("ArpLearn ")
	}
}

// Lookup for a resolution
func (o *ArpFlowTable) Lookup(ipv4 core.Ipv4Key) *ArpFlow {
	v, ok := o.tbl[ipv4]
	if ok {
		/* read does not update the timer only packets */
		return v
	}
	return nil
}

/*SendQuery on behalf of the first client */
func (o *ArpFlowTable) SendQuery(flow *ArpFlow) {
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

func (o *ArpFlowTable) GetNextTicks(flow *ArpFlow) uint32 {
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

func (o *ArpFlowTable) handleRefreshState(flow *ArpFlow) {
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
func (o *ArpFlowTable) OnEvent(a, b interface{}) {
	flow := a.(*ArpFlow)
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
		panic("Arp on event  ")
	}
}

func pluginArpClientCastfromDlist(o *core.DList) *PluginArpClient {
	var s PluginArpClient
	return (*PluginArpClient)(unsafe.Pointer(uintptr(unsafe.Pointer(o)) - unsafe.Offsetof(s.dlist)))
}

// PluginArpClient arp information per client
type PluginArpClient struct {
	core.PluginBase
	dlist          core.DList /* to link to ArpFlow */
	arpEnable      bool
	arpPktTemplate []byte           // template packet with
	arpHeader      layers.ArpHeader // point to template packet
	pktOffset      uint16
	arpNsPlug      *PluginArpNs
}

func (o *PluginArpClient) preparePacketTemplate() {
	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeARP))
	arpOffset := len(l2)
	o.pktOffset = uint16(arpOffset)
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
	o.arpHeader = layers.ArpHeader(o.arpPktTemplate[arpOffset : arpOffset+28])
}

/*NewArpClient create plugin */
func NewArpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginArpClient)
	o.arpEnable = true
	o.dlist.SetSelf()
	o.InitPluginBase(ctx, o)            /* init base object*/
	o.RegisterEvents(ctx, arpEvents, o) /* register events, only if exits*/
	o.preparePacketTemplate()
	nsplg := o.Ns.PluginCtx.GetOrCreate(ARP_PLUG)
	o.arpNsPlug = nsplg.Ext.(*PluginArpNs)
	o.OnCreate()
	return &o.PluginBase
}

/*OnEvent support event change of IP  */
func (o *PluginArpClient) OnEvent(msg string, a, b interface{}) {

	switch msg {
	case core.MSG_UPDATE_IPV4_ADDR:
		oldIPv4 := a.(core.Ipv4Key)
		newIPv4 := b.(core.Ipv4Key)
		if newIPv4.IsZero() != oldIPv4.IsZero() {
			/* there was a change in Source IPv4 */
			o.arpNsPlug.stats.eventsChangeSrc++
			o.OnChangeDGSrcIPv4(o.Client.DgIpv4,
				o.Client.DgIpv4,
				!oldIPv4.IsZero(),
				!newIPv4.IsZero())
		}

	case core.MSG_UPDATE_DGIPV4_ADDR:
		oldIPv4 := a.(core.Ipv4Key)
		newIPv4 := b.(core.Ipv4Key)
		if newIPv4 != oldIPv4 {
			/* there was a change in Source IPv4 */
			o.arpNsPlug.stats.eventsChangeDgIPv4++
			o.OnChangeDGSrcIPv4(oldIPv4,
				newIPv4,
				!o.Client.Ipv4.IsZero(),
				!o.Client.Ipv4.IsZero())
		}

	}

}

var arpEvents = []string{core.MSG_UPDATE_IPV4_ADDR, core.MSG_UPDATE_DGIPV4_ADDR}

/*OnChangeDGSrcIPv4 - called in case there is a change in DG or srcIPv4 */
func (o *PluginArpClient) OnChangeDGSrcIPv4(oldDgIpv4 core.Ipv4Key,
	newDgIpv4 core.Ipv4Key,
	oldIsSrcIPv4 bool,
	NewIsSrcIPv4 bool) {
	if oldIsSrcIPv4 && !oldDgIpv4.IsZero() {
		// remove
		o.arpNsPlug.DisassociateClient(o, oldDgIpv4)
	}
	if NewIsSrcIPv4 && !newDgIpv4.IsZero() {
		//there is a valid src IPv4 and valid new DG
		o.arpNsPlug.AssociateClient(o)
	}
}

func (o *PluginArpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	o.OnChangeDGSrcIPv4(o.Client.DgIpv4,
		o.Client.DgIpv4,
		!o.Client.Ipv4.IsZero(),
		false)
	ctx.UnregisterEvents(&o.PluginBase, arpEvents)
}

func (o *PluginArpClient) OnCreate() {
	if o.Client.ForceDGW {
		return
	}
	var oldDgIpv4 core.Ipv4Key
	oldDgIpv4.SetUint32(0)
	o.OnChangeDGSrcIPv4(oldDgIpv4,
		o.Client.DgIpv4,
		false,
		!o.Client.Ipv4.IsZero())
}

func (o *PluginArpClient) SendGArp() {
	if !o.Client.Ipv4.IsZero() {
		o.arpNsPlug.stats.pktTxGArp++
		o.arpHeader.SetOperation(1)
		o.arpHeader.SetSrcIpAddress(o.Client.Ipv4.Uint32())
		o.arpHeader.SetDstIpAddress(o.Client.Ipv4.Uint32())
		o.arpHeader.SetDestAddress([]byte{0, 0, 0, 0, 0, 0})
		o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	} else {
		panic("  SendGArp() arp wasn't sent ")
	}
}

func (o *PluginArpClient) SendQuery() {
	if !o.Client.DgIpv4.IsZero() {
		o.arpNsPlug.stats.pktTxArpQuery++
		o.arpHeader.SetOperation(1)
		o.arpHeader.SetSrcIpAddress(o.Client.Ipv4.Uint32())
		o.arpHeader.SetDstIpAddress(o.Client.DgIpv4.Uint32())
		o.arpHeader.SetDestAddress([]byte{0, 0, 0, 0, 0, 0})
		o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	} else {
		panic("  SendQuery() arp wasn't sent ")
	}
}

func (o *PluginArpClient) Respond(arpHeader *layers.ArpHeader) {

	o.arpNsPlug.stats.pktTxReply++

	o.arpHeader.SetOperation(2)
	o.arpHeader.SetSrcIpAddress(o.Client.Ipv4.Uint32())
	o.arpHeader.SetDstIpAddress(arpHeader.GetSrcIpAddress())
	o.arpHeader.SetDestAddress(arpHeader.GetSourceAddress())

	eth := layers.EthernetHeader(o.arpPktTemplate[0:12])

	eth.SetDestAddress(arpHeader.GetSourceAddress())
	o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	eth.SetBroadcast() /* back to default as broadcast */
}

// PluginArpNs arp information per namespace
type PluginArpNs struct {
	core.PluginBase
	arpEnable bool
	tbl       ArpFlowTable
	stats     ArpNsStats
	cdb       *core.CCounterDb
}

func NewArpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginArpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.arpEnable = true
	o.tbl.Create(ctx.Tctx.GetTimerCtx())
	o.tbl.stats = &o.stats
	o.cdb = NewArpNsStatsDb(&o.stats)
	return &o.PluginBase
}

func (o *PluginArpNs) OnRemove(ctx *core.PluginCtx) {
	o.tbl.OnRemove()
}

func (o *PluginArpNs) OnEvent(msg string, a, b interface{}) {

}

/*DisassociateClient remove association from the client. client now have the new data
 */
func (o *PluginArpNs) DisassociateClient(arpc *PluginArpClient,
	oldDgIpv4 core.Ipv4Key) {

	if oldDgIpv4.IsZero() {
		panic("DisassociateClient old ipv4 is not valid")
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
}

/*AssociateClient associate a new client object with a ArpFlow
  client object should be with valid source ipv4 and valid default gateway
  1. if object ArpFlow exists move it's state to complete and add ref counter
  2. if object ArpFlow does not exsits create new with ref=1 and return it
  3. if this is the first, generate GARP and
*/
func (o *PluginArpNs) AssociateClient(arpc *PluginArpClient) {
	if arpc.Client.Ipv4.IsZero() || arpc.Client.DgIpv4.IsZero() {
		panic("AssociateClient should have valid source ipv4 and default gateway ")
	}
	var firstUnresolve bool
	firstUnresolve = false
	ipv4 := arpc.Client.DgIpv4
	flow := o.tbl.Lookup(ipv4)
	if flow != nil {
		firstUnresolve = o.tbl.AssociateWithClient(flow)
	} else {
		/* we don't have resolution, add new in state stateIncomplete */
		flow = o.tbl.AddNew(ipv4, nil, stateIncomplete)
		firstUnresolve = true
	}

	o.stats.associateWithClient++
	flow.head.AddLast(&arpc.dlist)

	if firstUnresolve {
		arpc.SendGArp()
		arpc.SendQuery()
	}

	arpc.Client.DGW = &flow.action
}

func (o *PluginArpNs) ArpLearn(arpHeader *layers.ArpHeader) {

	var ipv4 core.Ipv4Key
	var mkey core.MACKey
	ipv4.SetUint32(arpHeader.GetSrcIpAddress())
	copy(mkey[0:6], arpHeader.GetSourceAddress())

	flow := o.tbl.Lookup(ipv4)

	if flow != nil {
		o.tbl.ArpLearn(flow, &mkey)
	} else {
		/* we didn't find, create an entery with ref=0 and add it with smaller timer */
		o.tbl.AddNew(ipv4, &mkey, stateLearned)
	}
}

//HandleRxArpPacket there is no need to free  buffer
func (o *PluginArpNs) HandleRxArpPacket(m *core.Mbuf, l3 uint16) {
	if m.PktLen() < uint32(layers.ARPHeaderSize+l3) {
		o.stats.pktRxErrTooShort++
		return
	}

	p := m.GetData()
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
		o.ArpLearn(&arpHeader)

		var ipv4 core.Ipv4Key

		ipv4.SetUint32(arpHeader.GetDstIpAddress())

		client := o.Ns.CLookupByIPv4(&ipv4)
		if client != nil {
			cplg := client.PluginCtx.Get(ARP_PLUG)
			if cplg != nil {
				arpCPlug := cplg.Ext.(*PluginArpClient)
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
		o.ArpLearn(&arpHeader)

	default:
		o.stats.pktRxErrWrongOp++
	}
}

// PluginArpThread  per thread
/*type PluginArpThread struct {
	core.PluginBase
}*/

// HandleRxArpPacket Parser call this function with mbuf from the pool
// Either by register functions -- maybe it would be better to register the function
// Rx side
func HandleRxArpPacket(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(ARP_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	arpnPlug := nsplg.Ext.(*PluginArpNs)
	arpnPlug.HandleRxArpPacket(ps.M, ps.L3)
	return 0
}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginArpCReg struct{}
type PluginArpNsReg struct{}

func (o PluginArpCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewArpClient(ctx, initJson)
}

func (o PluginArpNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewArpNs(ctx, initJson)
}

/*******************************************/
/* ARP RPC commands */
type (
	ApiArpNsSetCfgHandler struct{}
	ApiArpNsSetCfgParams  struct { /* +tunnel*/
		Enable bool `json:"enable"`
	}

	ApiArpNsGetCfgHandler struct{}

	/* Get counters metadata */
	ApiArpNsCntMetaHandler struct{}

	/* Get counters  */
	ApiArpNsCntValueHandler struct{}
	ApiArpNsCntValueParams  struct { /* +tunnel*/
		Zero bool `json:"zero"` /* dump zero too */
	}

	ApiArpCCmdQueryHandler struct{} /* +tunnel*/
	ApiArpCCmdQueryParams  struct {
		Garp bool `json:"garp"`
	}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginArpNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, ARP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginArpNs)

	return arpNs, nil
}

func getClient(ctx interface{}, params *fastjson.RawMessage) (*PluginArpClient, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetClientPlugin(params, ARP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpClient := plug.Ext.(*PluginArpClient)

	return arpClient, nil
}

func (h ApiArpNsSetCfgHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var arpobj ApiArpNsSetCfgParams
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, ARP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err = tctx.UnmarshalValidate(*params, &arpobj)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginArpNs)

	arpNs.arpEnable = arpobj.Enable

	return nil, nil
}

func (h ApiArpNsGetCfgHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	arpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}
	return &ApiArpNsSetCfgParams{Enable: arpNs.arpEnable}, nil
}

func (h ApiArpNsCntMetaHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	arpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}
	return arpNs.cdb, nil
}

func (h ApiArpNsCntValueHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiArpNsCntValueParams
	tctx := ctx.(*core.CThreadCtx)

	arpNs, err := getNs(ctx, params)
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

	return arpNs.cdb.MarshalValues(p.Zero), nil
}

func (h ApiArpCCmdQueryHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiArpCCmdQueryParams
	tctx := ctx.(*core.CThreadCtx)

	arpC, err := getClient(ctx, params)
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

	if p.Garp {
		arpC.SendGArp()
	} else {
		arpC.SendQuery()
	}
	return nil, nil
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(ARP_PLUG,
		core.PluginRegisterData{Client: PluginArpCReg{},
			Ns:     PluginArpNsReg{},
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
	core.RegisterCB("arp_ns_set_cfg", ApiArpNsSetCfgHandler{}, true)
	core.RegisterCB("arp_ns_get_cfg", ApiArpNsGetCfgHandler{}, true)
	core.RegisterCB("arp_ns_get_cnt_meta", ApiArpNsCntMetaHandler{}, true)
	core.RegisterCB("arp_ns_get_cnt_val", ApiArpNsCntValueHandler{}, true)
	core.RegisterCB("arp_c_cmd_query", ApiArpCCmdQueryHandler{}, true)

	/* register callback for rx side*/
	core.ParserRegister("arp", HandleRxArpPacket)
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("arp")
}
