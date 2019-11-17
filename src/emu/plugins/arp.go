package plugins

import (
	"emu/core"
	"external/google/gopacket/layers"
	"fmt"
	"time"
)

var defaultRetryTimerSec = [...]uint8{1, 1, 3, 5, 7, 17}

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

type ArpFlow struct {
	dlist  core.DList
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

func (o *ArpFlowTable) Update(ipv4 core.Ipv4Key,
	Ipv4dgMac core.MACKey) {
	v, ok := o.tbl[ipv4]
	if ok {
		v.action.Ipv4dgResolved = true
		v.action.Ipv4dgMac = Ipv4dgMac
		v.state = stateIncomplete // make sure the state is query
	} else {
		panic(" update flow does not exists")
	}
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

// AddNew in case it does not found
// state could be  stateLearnedor incomplete
func (o *ArpFlowTable) AddNew(ipv4 core.Ipv4Key,
	Ipv4dgMac *core.MACKey, state uint8) {
	_, ok := o.tbl[ipv4]
	if ok {
		panic(" arpflow  already exits   ")
	}

	flow := new(ArpFlow)
	flow.ipv4 = ipv4
	flow.state = state
	flow.action = new(core.CClientDgIPv4)
	flow.action.O = flow // back pointer
	flow.action.CB = o
	flow.action.Ipv4dgResolved = true
	flow.action.Ipv4dgMac = *Ipv4dgMac
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
	return
}

func (o *ArpFlowTable) MoveToComplete(flow *ArpFlow) {
	if flow.timer.IsRunning() {
		o.timerw.Stop(&flow.timer)
	}
	flow.touch = false
	o.timerw.StartTicks(&flow.timer, o.completeTicks)
	flow.state = stateIncomplete
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

func (o *ArpFlowTable) SendQuery(flow *ArpFlow) {
	// TBD - query
	// need the first client in the link list
	/* take the first client and run client->SendQuery */

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

// PluginArpClient arp information per client
type PluginArpClient struct {
	core.PluginBase
	arpEnable      bool
	arpPktTemplate []byte           // template packet with
	arpHeader      layers.ArpHeader // point to template packet
	pktOffset      uint16
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

func (o *PluginArpClient) OnDelete() {
	/*nsplg := o.Ns.PluginCtx.Get("arp")
	if nsplg != nil {
		arpNsPlug := nsplg.Ext.(*PluginArpNs)
	}*/
}

func (o *PluginArpClient) OnCreate() {
	if o.Client.ForceDGW {
		return
	}
	nsplg := o.Ns.PluginCtx.Get("arp")
	if nsplg != nil {
		arpNsPlug := nsplg.Ext.(*PluginArpNs)
		/* need to resolve this */
		if !o.Client.DgIpv4.IsZero() {
			ipv4 := o.Client.DgIpv4
			flow := arpNsPlug.tbl.Lookup(ipv4)
			if flow != nil {
				//flow // move from learn to complete
				//flow.add.client to the list
				// flow.ref++
			} else {
				//arpNsPlug.tbl.AddNew()
				//
			}
		}
	}
}

// send GArp
func (o *PluginArpClient) SendGArp() {
	if !o.Client.Ipv4.IsZero() {
		o.arpHeader.SetOperation(1)
		o.arpHeader.SetSrcIpAddress(o.Client.Ipv4.Uint32())
		o.arpHeader.SetDstIpAddress(o.Client.Ipv4.Uint32())
		o.arpHeader.SetDestAddress([]byte{0, 0, 0, 0, 0, 0})
		o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	} else {
		// TBD arp wasn't sent
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
		// TBD arp wasn't sent
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
			cplg := client.PluginCtx.Get("arp")
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

func init() {

}
