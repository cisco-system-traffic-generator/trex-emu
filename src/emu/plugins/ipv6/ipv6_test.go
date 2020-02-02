package ipv6

import (
	"emu/core"
	"encoding/binary"
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
	nsplg := ns.PluginCtx.Get(IPV6_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	icmpPlug := nsplg.Ext.(*PluginIpv6Ns)
	icmpPlug.cdb.Dump()
	tctx.SimRecordAppend(icmpPlug.cdb.MarshalValues(false))
	tctx.GetCounterDbVec().Dump()

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
			core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			dg)
		ns.AddClient(client)
		client.PluginCtx.CreatePlugins([]string{"ipv6"}, [][]byte{})
	}
	tctx.RegisterParserCb("icmpv6")
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
	opts := gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: false}

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
				Type:           layers.EthernetTypeIPv6,
			},

			&layers.IPv6{
				Version:      6,
				TrafficClass: 0,
				FlowLabel:    0,
				Length:       8,
				NextHeader:   layers.IPProtocolICMPv6,
				HopLimit:     64,
				SrcIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				DstIP: net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			},

			&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)},

			&layers.ICMPv6Echo{Identifier: 0x1234,
				SeqNumber: 0x4567 + o.cnt},

			gopacket.Payload([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
		)

		pkt := buf.Bytes()
		off := 14 + 8
		ipv6 := layers.IPv6Header(pkt[off : off+40])
		ipv6.SetPyloadLength(uint16(len(pkt) - off - 40))

		cs := layers.PktChecksumTcpUdpV6(pkt[off+40:], 0, ipv6)
		binary.BigEndian.PutUint16(pkt[off+42:off+44], cs)

	} else {
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
func TestPluginIcmpv6_1(t *testing.T) {
	a := &IcmpTestBase{
		testname:     "icmpv6_1",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     1 * time.Minute,
		clientsToSim: 1,
		cb:           Cb4,
	}
	a.Run(t, true)
}

func TestPluginIcmpv6_2(t *testing.T) {
	a := &IcmpTestBase{
		testname:     "icmpv6_1",
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
