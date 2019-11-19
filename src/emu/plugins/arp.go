package plugins

import (
	"emu/core"
	"external/google/gopacket/layers"
	"fmt"
	"time"
	"unsafe"
)

var defaultRetryTimerSec = [...]uint8{1, 1, 3, 5, 7, 17}

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
	action *core.CClientDgIPv4
}

type MapArpTbl map[core.Ipv4Key]*ArpFlow

// ArpFlowTable manage the ipv4-> mac with timeout for outside case
// inside are resolved
type ArpFlowTable struct {
	timerw        *core.TimerCtx
	tbl           MapArpTbl
	head          core.DList
	completeTicks uint32 /* timer to send query */
	learnTimer    uint32
	second        uint32 /* timer to remove */
}

func (o *ArpFlowTable) Create(timerw *core.TimerCtx) {
	o.timerw = timerw
	o.tbl = make(MapArpTbl)
	o.head.SetSelf()
	o.completeTicks = timerw.DurationToTicks(defaultCompleteTimer)
	o.learnTimer = timerw.DurationToTicks(defaultLearnTimer)
	o.second = timerw.DurationToTicks(time.Second)
}

// OnDelete called when there is no ref to this object
func (o *ArpFlowTable) OnDelete(action *core.CClientDgIPv4) {
	flow := action.O.(*ArpFlow)
	if flow.action.Refc != 0 {
		panic(" ARP ref counter should be zero ")
	}
	o.head.RemoveNode(&flow.dlist)
	flow.action.Ipv4dgResolved = false
	flow.action.Ipv4dgMac.Clear()
	_, ok := o.tbl[flow.ipv4]
	if ok {
		delete(o.tbl, flow.ipv4)
	} else {
		// somthing is wrong here, can't find the flow
		panic(" arp can't find the flow for removing ")
	}
}

/*AssociateWithClient  associate the flow with a client
and return if this is the first and require to send GARP and Query*/
func (o *ArpFlowTable) AssociateWithClient(flow *ArpFlow) bool {
	if flow.state == stateLearned {
		if flow.action.Refc != 0 {
			panic("AssociateWithClient ref should be zero in learn mode")
		}
		flow.action.Refc = 1
		o.MoveToComplete(flow)
	} else {
		flow.action.Refc += 1
	}
	return false
}

// AddNew in case it does not found
// state could be  stateLearnedor incomplete
func (o *ArpFlowTable) AddNew(ipv4 core.Ipv4Key,
	Ipv4dgMac *core.MACKey, state uint8) *ArpFlow {
	_, ok := o.tbl[ipv4]
	if ok {
		panic(" arpflow  already exits   ")
	}

	flow := new(ArpFlow)
	flow.ipv4 = ipv4
	flow.state = state
	flow.head.SetSelf()
	flow.action = new(core.CClientDgIPv4)
	flow.action.O = flow // back pointer
	flow.action.CB = o
	if Ipv4dgMac != nil {
		flow.action.Ipv4dgResolved = true
		flow.action.Ipv4dgMac = *Ipv4dgMac
	} else {
		flow.action.Ipv4dgResolved = false
	}
	flow.timer.SetCB(o, flow, 0)

	o.tbl[ipv4] = flow
	o.head.AddLast(&flow.dlist)
	if state == stateLearned {
		flow.action.Refc = 0
		o.timerw.StartTicks(&flow.timer, o.learnTimer)
	} else {
		if state == stateIncomplete {
			flow.action.Refc = 1
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
	}
	flow.touch = false
	o.timerw.StartTicks(&flow.timer, o.learnTimer)
	flow.state = stateLearned
}

func (o *ArpFlowTable) MoveToComplete(flow *ArpFlow) {
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	}
	flow.touch = false
	o.timerw.StartTicks(&flow.timer, o.completeTicks)
	flow.state = stateComplete
}

func (o *ArpFlowTable) ArpLearn(flow *ArpFlow, mac *core.MACKey) {

	flow.action.Ipv4dgResolved = true
	flow.action.Ipv4dgMac = *mac
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
		flow.action.Ipv4dgResolved = false
		flow.action.Ipv4dgMac.Clear()
	}
}

/* OnEvent timer callback */
func (o *ArpFlowTable) OnEvent(a, b interface{}) {
	flow := a.(*ArpFlow)
	switch flow.state {
	case stateLearned:
		if flow.touch {
			flow.touch = false
			o.timerw.StartTicks(&flow.timer, o.learnTimer)
		} else {
			// TBD remove
		}
	case stateIncomplete:
		ticks := o.GetNextTicks(flow)
		o.timerw.StartTicks(&flow.timer, ticks)
		o.SendQuery(flow)
	case stateComplete:
		if flow.touch {
			flow.touch = false
			o.timerw.StartTicks(&flow.timer, o.completeTicks)
		} else {
			flow.state = stateRefresh
			flow.index = 0
			o.handleRefreshState(flow)
		}
	case stateRefresh:
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
	arpc := new(PluginArpClient)
	arpc.arpEnable = true
	arpc.dlist.SetSelf()
	arpc.Client = ctx.Client
	arpc.Ns = arpc.Client.Ns
	arpc.Tctx = arpc.Ns.ThreadCtx
	arpc.Ext = arpc
	arpc.I = arpc
	arpc.preparePacketTemplate()
	arpc.arpNsPlug = nil
	/* TBD need to create in does not exits */
	nsplg := arpc.Ns.PluginCtx.GetOrCreate(ARP_PLUG)
	if nsplg == nil {
		panic(" can't get ARP Ns plugin ")
	}
	arpc.arpNsPlug = nsplg.Ext.(*PluginArpNs)
	/* register events */
	ctx.RegisterEvents(&arpc.PluginBase, arpEvents)
	return &arpc.PluginBase
}

/* events */
func (o *PluginArpClient) OnEvent(msg string, a, b interface{}) {

	switch msg {
	case core.MSG_UPDATE_IPV4_ADDR:
		oldIPv4 := a.(core.Ipv4Key)
		newIPv4 := b.(core.Ipv4Key)
		if newIPv4.IsZero() != oldIPv4.IsZero() {
			/* there was a change in Source IPv4 */
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

func (o *PluginArpClient) OnDelete(ctx *core.PluginCtx) {
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
	// TBD register the events
	o.OnChangeDGSrcIPv4(oldDgIpv4,
		o.Client.DgIpv4,
		false,
		!o.Client.Ipv4.IsZero())
}

func (o *PluginArpClient) SendGArp() {
	if !o.Client.Ipv4.IsZero() {
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
}

func NewArpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginArpNs)
	o.arpEnable = true
	o.tbl.Create(ctx.Tctx.GetTimerCtx())
	return &o.PluginBase
}

/*DisassociateClient remove association from the client
 */
func (o *PluginArpNs) DisassociateClient(arpc *PluginArpClient,
	oldDgIpv4 core.Ipv4Key) {
	if arpc.Client.Ipv4.IsZero() && arpc.Client.DgIpv4.IsZero() {
		panic("DisassociateClient should not have a valid source ipv4 and default gateway ")
	}
	if oldDgIpv4.IsZero() {
		panic("DisassociateClient old ipv4 is not valid")
	}
	flow := o.tbl.Lookup(oldDgIpv4)
	if flow.action.Refc != 0 {
		panic(" ref count is not zero")
	}
	flow.head.RemoveNode(&arpc.dlist)
	flow.action.Refc--
	if flow.action.Refc == 0 {
		// move to Learn
		if !flow.head.IsEmpty() {
			panic(" head should be empty ")
		}
		o.tbl.MoveToLearn(flow)
	}
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

	flow.head.AddLast(&arpc.dlist)

	if firstUnresolve {
		arpc.SendGArp()
		arpc.SendQuery()
	}

	arpc.Client.DGW = flow.action
}

func (o *PluginArpNs) ArpLearn(arpHeader *layers.ArpHeader) {

	var ipv4 core.Ipv4Key
	var mkey core.MACKey
	ipv4.SetUint32(arpHeader.GetDstIpAddress())
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
		// TBD-counters
		return
	}

	p := m.GetData()
	arpHeader := layers.ArpHeader(p[l3:])
	ethHeader := layers.EthernetHeader(p[0:6])

	switch arpHeader.GetOperation() {
	case layers.ARPRequest:
		if !ethHeader.IsBroadcast() {
			// TBD-counter
			return
		}
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
			//TBD-counter request-not-for-us
		}

	case layers.ARPReply:
		if ethHeader.IsBroadcast() {
			// TBD-counter
			return
		}
		o.ArpLearn(&arpHeader)

	default:
		// TBD-counter
	}
}

// PluginArpThread  per thread
type PluginArpThread struct {
	core.PluginBase
}

// HandleRxArpPacket Parser call this function with mbuf from the pool
// Either by register functions -- maybe it would be better to register the function
// Rx side
func HandleRxArpPacket(tctx *core.CThreadCtx,
	tun *core.CTunnelKey,
	m *core.Mbuf,
	l3 uint16, // 0 is not valid
	l4 uint16, // 0 is not valid
	l7 uint16) {

	defer m.FreeMbuf()

}

func ARPTest() {

	return
	tctx := core.NewThreadCtx(0, 4510)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)
	tctx.AddNs(&key, ns)
	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 0}, core.Ipv4Key{16, 0, 0, 1}, core.Ipv6Key{})
	ns.AddClient(client)

	/* prepare client plugin */
	var arpPlugin PluginArpClient

	arpPlugin.Client = client
	arpPlugin.Ns = ns
	arpPlugin.Tctx = tctx

	arpPlugin.preparePacketTemplate()

	core.PacketUtl("arp_t0", arpPlugin.arpPktTemplate)
	arpPlugin.arpHeader.SetOperation(2)
	core.PacketUtl("arp_op2", arpPlugin.arpPktTemplate)
	arpPlugin.arpHeader.SetSrcIpAddress(0x22334455)
	arpPlugin.arpHeader.SetDstIpAddress(0x99887766)
	arpPlugin.arpHeader.SetDestAddress([]byte{1, 2, 3, 4, 5, 6})
	core.PacketUtl("arp_src", arpPlugin.arpPktTemplate)

	fmt.Printf("c: %+v \n", client)
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

func init() {

	core.PluginRegister(ARP_PLUG,
		core.PluginRegisterData{Client: PluginArpCReg{},
			Ns:     PluginArpNsReg{},
			Thread: nil}) /* no need for thread context for now */

}
