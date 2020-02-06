package icmp

import (
	"emu/core"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"flag"
	"net"
	"testing"
	"time"
)

var monitor int

type IcmpTestBase struct {
	testname     string
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           IcmpTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

type IcmpTestCb func(tctx *core.CThreadCtx, test *IcmpTestBase) int

func (o *IcmpTestBase) Run(t *testing.T, compare bool) {

	var simVeth VethIcmpSim
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
	nsplg := ns.PluginCtx.Get(ICMP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	icmpPlug := nsplg.Ext.(*PluginIcmpNs)
	icmpPlug.cdb.Dump()
	tctx.SimRecordAppend(icmpPlug.cdb.MarshalValues(false))
	if compare {
		tctx.SimRecordCompare(o.testname, t)
	}
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
		client.PluginCtx.CreatePlugins([]string{"icmp"}, [][]byte{})
	}
	tctx.RegisterParserCb("icmp")
	return tctx, nil
}

type VethIcmpSim struct {
	cnt   uint8
	match uint8
	tctx  *core.CThreadCtx
}

func (o *VethIcmpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	m.FreeMbuf()
	return nil
}

type IcmpQueryCtx struct {
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
	cnt   uint16
	match uint8
}

func (o *IcmpQueryCtx) OnEvent(a, b interface{}) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if o.match == 0 {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 0, 2, 0, 0},
				DstMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
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
				Type:           layers.EthernetTypeIPv4,
			},

			&layers.IPv4{Version: 4,
				IHL:      5,
				TTL:      128,
				Id:       0xcc,
				SrcIP:    net.IPv4(16, 0, 0, 2),
				DstIP:    net.IPv4(16, 0, 0, 0),
				Protocol: layers.IPProtocolICMPv4},

			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 1, Seq: o.cnt},

			gopacket.Payload([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
		)
	} else {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 0, 2, 0, 0},
				DstMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
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
				Type:           layers.EthernetTypeIPv4,
			},

			&layers.IPv4{Version: 4,
				IHL:      5,
				TTL:      128,
				Id:       0xcc,
				SrcIP:    net.IPv4(16, 0, 0, 2),
				DstIP:    net.IPv4(16, 0, 0, 0),
				Protocol: layers.IPProtocolICMPv4},

			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampRequest, 0), Id: 1, Seq: o.cnt},

			gopacket.Payload([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		)
	}

	o.cnt += 1

	m := o.tctx.MPool.Alloc(uint16(256))
	m.SetVPort(1)
	m.Append(buf.Bytes())
	o.tctx.Veth.OnRx(m)

	timerw := o.tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(10 * time.Second)
	timerw.StartTicks(&o.timer, ticks)
}

func Cb4(tctx *core.CThreadCtx, test *IcmpTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(1 * time.Second)
	var arpctx IcmpQueryCtx
	arpctx.match = test.match
	arpctx.cnt = 0xabcd
	arpctx.timer.SetCB(&arpctx, test.cbArg1, test.cbArg2)
	arpctx.tctx = tctx
	timerw.StartTicks(&arpctx.timer, ticks)
	return 0
}

/*TestPluginIcmp1 - does not answer to default gateway, should repeat query */
func TestPluginIcmp1(t *testing.T) {
	a := &IcmpTestBase{
		testname:     "icmp1",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     1 * time.Minute,
		clientsToSim: 1,
		cb:           Cb4,
	}
	a.Run(t, true)
}

func TestPluginIcmp2(t *testing.T) {
	a := &IcmpTestBase{
		testname:     "icmp2",
		monitor:      false,
		match:        1,
		capture:      true,
		duration:     1 * time.Minute,
		clientsToSim: 1,
		cb:           Cb4,
	}
	a.Run(t, false) // the timestamp making a new json due to the timestamp. skip the it
}


func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
