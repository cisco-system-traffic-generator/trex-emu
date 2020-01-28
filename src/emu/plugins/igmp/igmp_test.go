package igmp

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

func TestPluginIgmp1(t *testing.T) {
	tbl := NewIgmpTable()
	fmt.Printf("0: %v \n", tbl.addMc([4]byte{1, 0, 0, 1}))
	fmt.Printf("1: %v \n", tbl.addMc([4]byte{1, 0, 0, 1}))
	fmt.Printf("2: %v \n", tbl.addMc([4]byte{1, 0, 0, 3}))
	tbl.dumpAll()
	fmt.Printf("3: %v \n", tbl.removeMc([4]byte{1, 0, 0, 3}))
	tbl.dumpAll()
	fmt.Printf("4: %v \n", tbl.removeMc([4]byte{1, 0, 0, 3}))
	tbl.dumpAll()
}

func TestPluginIgmp2(t *testing.T) {
	tbl := NewIgmpTable()
	fmt.Printf("0: %v \n", tbl.addMc([4]byte{1, 0, 0, 1}))
	fmt.Printf("1: %v \n", tbl.addMc([4]byte{1, 0, 0, 3}))
	e, ok := tbl.mapIgmp[[4]byte{1, 0, 0, 1}]
	if ok {
		fmt.Printf(" e : %+v \n", e)
		tbl.activeIter = &e.dlist
		fmt.Printf(" p : %p \n", tbl.activeIter)
		e1 := covertToIgmpEntry(tbl.activeIter)
		fmt.Printf(" %v \n", e1.Ipv4)
	}
	fmt.Printf("3: %v \n", tbl.removeMc([4]byte{1, 0, 0, 1}))
	e2 := covertToIgmpEntry(tbl.activeIter)
	fmt.Printf(" %v \n", e2.Ipv4)
}

func d1(vec *[]uint32) {
	fmt.Printf(" h %v \n", *vec)
}

type IgmpTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           IgmpTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

type IgmpTestCb func(tctx *core.CThreadCtx, test *IgmpTestBase) int

func (o *IgmpTestBase) Run(t *testing.T) {

	var simVeth VethIgmpSim
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
	nsplg := ns.PluginCtx.Get(IGMP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	igmpPlug := nsplg.Ext.(*PluginIgmpNs)
	igmpPlug.cdb.Dump()
	tctx.GetCounterDbVec().Dump()

	tctx.SimRecordAppend(igmpPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)

	tctx.AddNs(&key, ns)
	dg := core.Ipv4Key{16, 0, 0, 2}

	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 1},
		core.Ipv4Key{16, 0, 0, 1},
		core.Ipv6Key{},
		dg)
	ns.AddClient(client)
	ns.PluginCtx.CreatePlugins([]string{"igmp"}, [][]byte{})
	client.PluginCtx.CreatePlugins([]string{"igmp"}, [][]byte{})
	ns.Dump()
	tctx.RegisterParserCb("igmp")

	nsplg := ns.PluginCtx.Get(IGMP_PLUG)
	if nsplg == nil {
		panic(" can't find plugin")
	}
	nsPlug := nsplg.Ext.(*PluginIgmpNs)
	nsPlug.designatorMac = core.MACKey{0, 0, 1, 0, 0, 1}

	vecIpv4 := []core.Ipv4Key{}
	fmt.Printf(" number of mc : %d \n", num)
	for j := 0; j < num; j++ {
		vecIpv4 = append(vecIpv4, core.Ipv4Key{239, 0, uint8(((j >> 8) & 0xff)), uint8(j)})
	}
	nsPlug.addMc(vecIpv4)
	return tctx, nil
}

type VethIgmpSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func (o *VethIgmpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}
	m.FreeMbuf()
	return nil
}

type IgmpQueryCtx struct {
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
	test  *IgmpTestBase
}

func (o *IgmpQueryCtx) OnEvent(a, b interface{}) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true,
		ComputeChecksums: true}

	if o.test.match == 3 {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 0, 2, 0, 0},
				DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
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

			&layers.IPv4{Version: 4, IHL: 6, TTL: 1, Id: 0xcc,
				SrcIP:    net.IPv4(16, 0, 0, 10),
				DstIP:    net.IPv4(224, 0, 0, 1),
				Length:   44,
				Protocol: layers.IPProtocolIGMP,
				Options: []layers.IPv4Option{{ /* router alert */
					OptionType:   0x94,
					OptionData:   []byte{0, 0},
					OptionLength: 4},
				}},

			gopacket.Payload([]byte{0x11, 0x64, 0xee, 0x9b, 0x00, 0x00, 0x00, 0x00}),
		)

	} else {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 0, 2, 0, 0},
				DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
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

			&layers.IPv4{Version: 4, IHL: 6, TTL: 1, Id: 0xcc,
				SrcIP:    net.IPv4(16, 0, 0, 10),
				DstIP:    net.IPv4(224, 0, 0, 1),
				Length:   44,
				Protocol: layers.IPProtocolIGMP,
				Options: []layers.IPv4Option{{ /* router alert */
					OptionType:   0x94,
					OptionData:   []byte{0, 0},
					OptionLength: 4},
				}},

			gopacket.Payload([]byte{0x11, 0x18, 0xec, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x02, 0x14, 0x00, 0x00}),
		)
	}
	m := o.tctx.MPool.Alloc(uint16(256))
	m.SetVPort(1)
	m.Append(buf.Bytes())
	//core.PacketUtl("arp1", buf.Bytes())
	o.tctx.Veth.OnRx(m)

	timerw := o.tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(10 * time.Second)
	timerw.StartTicks(&o.timer, ticks)
}

func Cb4(tctx *core.CThreadCtx, test *IgmpTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(1 * time.Second)
	var arpctx IgmpQueryCtx
	arpctx.timer.SetCB(&arpctx, test.cbArg1, test.cbArg2)
	arpctx.tctx = tctx
	arpctx.test = test
	timerw.StartTicks(&arpctx.timer, ticks)
	return 0
}

func TestPluginIgmp3(t *testing.T) {
	a := &IgmpTestBase{
		testname:     "igmp3",
		dropAll:      true,
		monitor:      false,
		match:        2,
		capture:      true,
		duration:     60 * time.Second,
		clientsToSim: 1000,
		cb:           Cb4,
	}
	a.Run(t)
}

func TestPluginIgmp4(t *testing.T) {
	a := &IgmpTestBase{
		testname:     "igmp4",
		dropAll:      true,
		monitor:      false,
		match:        3, /* mark as IGMPv2 version */
		capture:      true,
		duration:     60 * time.Second,
		clientsToSim: 100,
		cb:           Cb4,
	}
	a.Run(t)
}

type IgmpRpcCtx struct {
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
	test  *IgmpTestBase
}

func (o *IgmpRpcCtx) OnEvent(a, b interface{}) {
	fmt.Printf("add request \n")

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"igmp_ns_get_cfg", 
	"params": {"tun": {"vport":1,"tci":[1,2]} }, 
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"igmp_ns_set_cfg", 
	"params": {"tun": {"vport":1,"tci":[1,2]}, "mtu":10 }, "id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"igmp_ns_set_cfg", 
	"params": {"tun": {"vport":1,"tci":[1,2]}, "mtu":512 ,"dmac":[0,0,1,0,0,1] }, "id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"igmp_ns_get_cfg", 
	"params": {"tun": {"vport":1,"tci":[1,2]} }, 
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"igmp_ns_cnt", 
	"params": {"tun": {"vport":1,"tci":[1,2]}, "meta":true }, 
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0", 
	"method":"igmp_ns_cnt", 
	"params": {"tun": {"vport":1,"tci":[1,2]}, "meta":false, "zero":false }, 
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0",
	"method":"igmp_ns_add",
	"params": {"tun": {"vport":1,"tci":[1,2]}, "vec": [ [239,0,1,1],[239,0,1,2] ] },
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0",
	"method":"igmp_ns_add",
	"params": {"tun": {"vport":1,"tci":[1,2]}, "vec": [ [239,0,1,1],[239,0,1,2] ] },
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0",
	"method":"igmp_ns_remove",
	"params": {"tun": {"vport":1,"tci":[1,2]}, "vec": [ [239,0,1,1],[239,0,1,2] ] },
	"id": 3 }`))

	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0",
	"method":"igmp_ns_iter",
	"params": {"tun": {"vport":1,"tci":[1,2]}, "reset": true, "count" : 99},
	"id": 3 }`))
	o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0",
	"method":"igmp_ns_iter",
	"params": {"tun": {"vport":1,"tci":[1,2]}, "reset": false, "count" : 100},
	"id": 3 }`))

}

func rpcQueue(tctx *core.CThreadCtx, test *IgmpTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(50 * time.Second)
	var arpctx IgmpRpcCtx
	arpctx.timer.SetCB(&arpctx, test.cbArg1, test.cbArg2)
	arpctx.tctx = tctx
	arpctx.test = test
	timerw.StartTicks(&arpctx.timer, ticks)
	return 0
}

func TestPluginIgmp5(t *testing.T) {
	a := &IgmpTestBase{
		testname:     "igmp5",
		dropAll:      true,
		monitor:      false,
		match:        3, /* mark as IGMPv2 version */
		capture:      true,
		duration:     60 * time.Second,
		clientsToSim: 100,
		cb:           rpcQueue,
		cbArg1:       1,
	}
	a.Run(t)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
