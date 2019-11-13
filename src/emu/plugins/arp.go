package plugins

import (
	"emu/core"
	"encoding/binary"
	"encoding/hex"
	"external/google/gopacket/layers"
	"fmt"
	"time"
)

const (
	defaultQueryTimer  = 10 * time.Minute
	defaultRemoveTimer = 5 * time.Minute
	defaultMinTimer    = 2 * time.Minute

	stateQuery  = 16 /* valid timer in query */
	stateRemove = 17 /* re-query wait for results to get back to stateQuery */
)

// refresh the time here
// I would like to make this table generic, let try to the table without generic first
// then optimize it

type ArpFlow struct {
	dlist  core.DList
	timer  core.CHTimerObj
	ipv4   core.Ipv4Key // key
	state  uint8
	utick  uint64
	action *core.CClientDgIPv4
}

type MapArpTbl map[core.Ipv4Key]*ArpFlow

// ArpFlowTable manage the ipv4-> mac with timeout for outside case
// inside are resolved
type ArpFlowTable struct {
	timerw      *core.TimerCtx
	tbl         MapArpTbl
	head        core.DList
	queryTicks  uint32 /* timer to send query */
	removeticks uint32 /* timer to remove */
	minTicks    uint32
}

func (o *ArpFlowTable) Create(timerw *core.TimerCtx) {
	o.timerw = timerw
	o.tbl = make(MapArpTbl)
	o.head.SetSelf()
	o.queryTicks = timerw.DurationToTicks(defaultQueryTimer)
	o.removeticks = timerw.DurationToTicks(defaultRemoveTimer)
	o.minTicks = timerw.DurationToTicks(defaultMinTimer)
}

func (o *ArpFlowTable) Update(ipv4 core.Ipv4Key,
	Ipv4dgMac core.MACKey) {
	v, ok := o.tbl[ipv4]
	if ok {
		v.action.Ipv4dgResolved = true
		v.action.Ipv4dgMac = Ipv4dgMac
		v.utick = o.timerw.Ticks // update ticks
		v.state = stateQuery     // make sure the state is query
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
func (o *ArpFlowTable) AddNew(ipv4 core.Ipv4Key,
	Ipv4dgMac core.MACKey) {
	_, ok := o.tbl[ipv4]
	if ok {
		panic(" arpflow  already exits   ")
	}

	flow := new(ArpFlow)
	flow.ipv4 = ipv4
	flow.utick = o.timerw.Ticks
	flow.state = stateQuery
	flow.action = new(core.CClientDgIPv4)
	flow.action.Refc = 1
	flow.action.O = flow // back pointer
	flow.action.CB = o
	flow.action.Ipv4dgResolved = true
	flow.action.Ipv4dgMac = Ipv4dgMac
	flow.timer.SetCB(o, flow, 0)

	o.tbl[ipv4] = flow
	o.head.AddLast(&flow.dlist)
	o.timerw.StartTicks(&flow.timer, o.queryTicks)
	return
}

// Lookup for a resolution
func (o *ArpFlowTable) Lookup(ipv4 core.Ipv4Key) *core.CClientDgIPv4 {
	v, ok := o.tbl[ipv4]
	if ok {
		/* read does not update the timer only packets */
		return v.action
	}
	return nil
}

//onQuery restart query
func (o *ArpFlowTable) onQuery(flow *ArpFlow) {
	fmt.Printf(" generate query ")
}

// flow can't be resolved
func (o *ArpFlowTable) onDeadFlow(flow *ArpFlow) {
	flow.action.Ipv4dgResolved = false
	flow.action.Ipv4dgMac.Clear()
	o.onQuery(flow) // trigger a resolution
	o.timerw.StartTicks(&flow.timer, o.removeticks)
}

/* OnEvent timer callback */
func (o *ArpFlowTable) OnEvent(a, b interface{}) {
	flow := a.(*ArpFlow)
	if flow.state == stateQuery {
		dticks := o.timerw.Ticks - flow.utick
		if (dticks) > uint64(0.9*float32(o.queryTicks)) {
			// timeout
			flow.state = stateRemove
			flow.utick = o.timerw.Ticks
			o.onQuery(flow)
			o.timerw.StartTicks(&flow.timer, o.removeticks)
		} else {
			// restart
			newticks := o.queryTicks - uint32(dticks)
			if newticks < o.minTicks {
				newticks = o.minTicks
			}
			if newticks > o.queryTicks {
				newticks = o.queryTicks
			}
			//flow.utick should not update, we restart the timer for the residue
			o.timerw.StartTicks(&flow.timer, newticks)
		}
	} else {
		if flow.state == stateRemove {
			dticks := o.timerw.Ticks - flow.utick
			if (dticks) > uint64(0.9*float32(o.removeticks)) {
				o.onDeadFlow(flow)
			} else {
				newticks := o.removeticks - uint32(dticks)
				if newticks < o.minTicks {
					newticks = o.minTicks
				}
				if newticks > o.removeticks {
					newticks = o.removeticks
				}
				//flow.utick should not update, we restart the timer for the residue
				o.timerw.StartTicks(&flow.timer, newticks)
			}
		} else {
			panic(" arp state is not valid ")
		}
	}
}

// PluginArpClient arp information per client
type PluginArpClient struct {
	core.PluginBase
	arpEnable bool
	arpUni    []byte
	arpQuery  []byte
}

// PluginArpNs arp information per namespace
type PluginArpNs struct {
	core.PluginBase

	arpEnable bool
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

}

func ARPTest1(src core.MACKey,
	dst core.MACKey,
	next layers.EthernetType,
	tun *core.CTunnelKey) []byte {
	var tund core.CTunnelData
	tun.Get(&tund)
	b := []byte{}
	b = append(b, dst[:]...)
	b = append(b, src[:]...)
	for _, val := range tund.Vlans {
		if val != 0 {
			b = append(b, 0, 0, 0, 0)
			binary.BigEndian.PutUint32(b[len(b)-4:], val)
		}
	}
	b = append(b, 0, 0)
	binary.BigEndian.PutUint16(b[len(b)-2:], uint16(next))
	return b
}

func ARPTest() {
	var tun core.CTunnelKey
	tun.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000011, 0x88a80022}})

	b := ARPTest1(core.MACKey{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		core.MACKey{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
		layers.EthernetTypeARP,
		&tun)
	fmt.Printf(hex.Dump(b))
}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

func init() {

}
