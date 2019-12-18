package arp

import (
	"emu/core"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"flag"
	"fmt"
	"net"
	"testing"
	"time"
)

var monitor int

type ArpTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           ArpTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

type ArpTestCb func(tctx *core.CThreadCtx, test *ArpTestBase) int

func (o *ArpTestBase) Run(t *testing.T) {

	var simVeth VethArpSim
	simVeth.DropAll = o.dropAll
	var simrx core.VethIFSim
	simrx = &simVeth
	if o.match > 0 {
		simVeth.match = o.match
	}
	tctx, _ := createSimulationEnv(&simrx, o.clientsToSim)
	if o.cb != nil {
		o.cb(tctx, o)
	}
	m := false
	if monitor > 0 {
		m = true
	}
	tctx.Veth.SetDebug(m, o.capture)
	tctx.MainLoopSim(o.duration)
	defer tctx.Delete()
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})

	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}
	nsplg := ns.PluginCtx.Get(ARP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	arpnPlug := nsplg.Ext.(*PluginArpNs)
	arpnPlug.cdb.Dump()
	tctx.SimRecordAppend(arpnPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)
	tctx.AddNs(&key, ns)
	for j := 0; j < num; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)
		var dg core.Ipv4Key
		if num == 1 {
			dg = core.Ipv4Key{16, 0, 0, 2}
		} else {
			dg = core.Ipv4Key{16, 1, a, b}
		}
		client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, a, b},
			core.Ipv4Key{16, 0, a, b},
			core.Ipv6Key{},
			dg)
		ns.AddClient(client)
		client.PluginCtx.CreatePlugins([]string{"arp"}, [][]byte{})
	}
	tctx.RegisterParserCb("arp")
	return tctx, nil
}

type VethArpSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func (o *VethArpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}

	var arpHeader layers.ArpHeader
	var arpHeader1 layers.ArpHeader
	arpHeader = m.GetData()[22:]
	if arpHeader.GetOperation() == 1 && (arpHeader.GetDstIpAddress() == 0x10000002) {
		o.cnt++
		if o.cnt != 0 {
			if o.cnt > o.match && o.cnt < (o.match+5) {
				m.FreeMbuf()
				return nil
			}

		}
		m1 := m.DeepClone()
		eth := layers.EthernetHeader(m1.GetData()[0:12])
		eth.SetDestAddress(arpHeader.GetSourceAddress())
		eth.SetSrcAddress([]byte{0, 0, 2, 0, 0, 0})
		arpHeader1 = m1.GetData()[22:]
		arpHeader1.SetOperation(2)
		arpHeader1.SetDestAddress(arpHeader.GetSourceAddress())
		arpHeader1.SetDstIpAddress(arpHeader.GetSrcIpAddress())
		arpHeader1.SetSourceAddress([]byte{0, 0, 2, 0, 0, 0})
		arpHeader1.SetSrcIpAddress(0x10000002)
		m.FreeMbuf()
		return m1
	}
	m.FreeMbuf()
	return nil
}

/*TestPluginArp1 - does not answer to default gateway, should repeat query */
func TestPluginArp1(t *testing.T) {
	a := &ArpTestBase{
		testname:     "arp1",
		dropAll:      true,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     1 * time.Minute,
		clientsToSim: 1,
	}
	a.Run(t)
}

func TestPluginArp2(t *testing.T) {

	a := &ArpTestBase{
		testname:     "arp2",
		dropAll:      false,
		monitor:      false,
		match:        2,
		capture:      true,
		duration:     60 * time.Minute,
		clientsToSim: 1,
	}
	a.Run(t)
}

func TestPluginArp3(t *testing.T) {
	a := &ArpTestBase{
		testname:     "arp3",
		dropAll:      true,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Minute,
		clientsToSim: 10,
	}
	a.Run(t)

}

type ArpQueryCtx struct {
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
}

func (o *ArpQueryCtx) OnEvent(a, b interface{}) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	var ipv4 []uint8
	if a == nil {
		ipv4 = []uint8{16, 0x00, 0x00, 0x00}
	} else {
		ipv4 = []uint8{16, 0x00, 0x00, 0x05}
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 0, 0, 2, 0, 0},
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(1),
			Type:           layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(2),
			Type:           layers.EthernetTypeARP,
		},

		&layers.ARP{
			AddrType:          0x1,
			Protocol:          0x800,
			HwAddressSize:     0x6,
			ProtAddressSize:   0x4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   net.HardwareAddr{0, 0, 0, 2, 0, 0},
			SourceProtAddress: []uint8{0x10, 0x0, 0x0, 0x2},
			DstHwAddress:      []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			DstProtAddress:    ipv4})

	m := o.tctx.MPool.Alloc(uint16(128))
	m.SetVPort(1)
	m.Append(buf.Bytes())
	//core.PacketUtl("arp1", buf.Bytes())
	o.tctx.Veth.OnRx(m)

	timerw := o.tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(10 * time.Second)
	timerw.StartTicks(&o.timer, ticks)
}

func Cb4(tctx *core.CThreadCtx, test *ArpTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(1 * time.Second)
	var arpctx ArpQueryCtx
	arpctx.timer.SetCB(&arpctx, test.cbArg1, test.cbArg2)
	arpctx.tctx = tctx
	timerw.StartTicks(&arpctx.timer, ticks)
	return 0
}

func TestPluginArp4(t *testing.T) {

	a := &ArpTestBase{
		testname:     "arp4",
		dropAll:      true,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     1 * time.Minute,
		clientsToSim: 1,
		cb:           Cb4,
	}
	a.Run(t)

}

func TestPluginArp5(t *testing.T) {

	a := &ArpTestBase{
		testname:     "arp5",
		dropAll:      true,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     1 * time.Minute,
		clientsToSim: 1,
		cb:           Cb4,
		cbArg1:       1,
	}
	a.Run(t)

}

type ArpRpcCtx struct {
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
}

func (o *ArpRpcCtx) OnEvent(a, b interface{}) {
	fmt.Printf("add request \n")

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"arp_ns_get_cfg", 
	"params": {"tun": {"vport":1,"tci":[1,2]} }, 
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"arp_ns_get_cnt_meta", 
	"params": {"tun": {"vport":1,"tci":[1,2]} }, "id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"arp_ns_get_cnt_val", 
	"params": {"tun": {"vport":1,"tci":[1,2]},"zero": true }, "id": 3 }`))
}

func rpcQueue1(tctx *core.CThreadCtx, test *ArpTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(50 * time.Second)
	var arpctx ArpRpcCtx
	arpctx.timer.SetCB(&arpctx, test.cbArg1, test.cbArg2)
	arpctx.tctx = tctx
	timerw.StartTicks(&arpctx.timer, ticks)
	return 0
}

func TestPluginArp6(t *testing.T) {
	a := &ArpTestBase{
		testname:     "arp6",
		dropAll:      true,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     1 * time.Minute,
		clientsToSim: 1,
		cb:           rpcQueue1,
		cbArg1:       1,
	}
	a.Run(t)

}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
