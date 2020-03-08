package dhcpv6

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"flag"
	"fmt"
	"net"
	"testing"
	"time"
)

var monitor int

type DhcpTestBase struct {
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

type IgmpTestCb func(tctx *core.CThreadCtx, test *DhcpTestBase) int

func (o *DhcpTestBase) Run(t *testing.T) {

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
	simVeth.tctx = tctx
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
	c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, 0, 1})
	nsplg := c.PluginCtx.Get(DHCPV6_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	dhcpPlug := nsplg.Ext.(*PluginDhcpClient)
	dhcpPlug.cdbv.Dump()
	tctx.GetCounterDbVec().Dump()

	//tctx.SimRecordAppend(igmpPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)

	tctx.AddNs(&key, ns)
	dg := core.Ipv4Key{0, 0, 0, 0}

	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 1},
		core.Ipv4Key{0, 0, 0, 0},
		core.Ipv6Key{},
		dg)
	ns.AddClient(client)
	ns.PluginCtx.CreatePlugins([]string{"dhcpv6"}, [][]byte{})
	client.PluginCtx.CreatePlugins([]string{"dhcpv6"}, [][]byte{})
	ns.Dump()
	tctx.RegisterParserCb("dhcpv6")

	nsplg := ns.PluginCtx.Get(DHCPV6_PLUG)
	if nsplg == nil {
		panic(" can't find plugin")
	}
	//nsPlug := nsplg.Ext.(*PluginDhcpNs)

	return tctx, nil
}

type VethIgmpSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func genMbuf(tctx *core.CThreadCtx, pkt []byte) *core.Mbuf {
	m := tctx.MPool.Alloc(uint16(len(pkt)))
	m.SetVPort(1)
	m.Append(pkt)
	return m
}

func Ipv6SA(s string) []byte {
	ip := net.ParseIP(s)
	if len(ip) != 16 {
		panic(" not ipv6 addr")
	}
	return ip
}

func (o *VethIgmpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {

	src := Ipv6SA("FE80::01")
	dst := Ipv6SA("FE80::200:1ff:fe00:1")

	var mr *core.Mbuf
	mr = nil
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}

	off := 14 + 8 + 40 + 8

	if m.PktLen() <= uint32(off) {
		m.FreeMbuf()
		return nil
	}

	p := m.GetData()[off:]

	var dhcph layers.DHCPv6
	err := dhcph.DecodeFromBytes(p, gopacket.NilDecodeFeedback)
	if err != nil {
		fmt.Printf(" err : %s \n", err.Error())
		m.FreeMbuf()
		return nil
	}

	var dhcpmt layers.DHCPv6MsgType
	dhcpmt = dhcph.MsgType

	xid := XidToUint32(dhcph.TransactionID)
	switch o.match {
	case 0:
		if dhcpmt == layers.DHCPv6MsgTypeSolicit {
			pkt := GenerateOfferPacket(xid, src, dst, int(layers.DHCPv6MsgTypeAdverstise))
			mr = genMbuf(o.tctx, pkt)
		} else {
			if dhcpmt == layers.DHCPv6MsgTypeRequest {
				pkt := GenerateOfferPacket(xid, src, dst, int(layers.DHCPv6MsgTypeReply))
				mr = genMbuf(o.tctx, pkt)
			}
		}
	case 1:

	case 2:
		if dhcpmt == layers.DHCPv6MsgTypeSolicit {
			pkt := GenerateOfferPacket(xid, src, dst, int(layers.DHCPv6MsgTypeAdverstise))
			mr = genMbuf(o.tctx, pkt)
		}
	}

	m.FreeMbuf()
	return mr
}

func TestPluginDhcpv6_1(t *testing.T) {
	a := &DhcpTestBase{
		testname:     "dhcpv6_1",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t)
}

func TestPluginDhcpv6_2(t *testing.T) {
	a := &DhcpTestBase{
		testname:     "dhcpv6_2",
		dropAll:      false,
		monitor:      false,
		match:        1,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t)
}

func TestPluginDhcpv6_3(t *testing.T) {
	a := &DhcpTestBase{
		testname:     "dhcpv6_3",
		dropAll:      false,
		monitor:      false,
		match:        2,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t)
}

func getL2() []byte {
	l2 := []byte{0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 2, 0x81, 00, 0x00, 0x01, 0x81, 00, 0x00, 0x02, 0x86, 0xdd}
	return l2
}

func GenerateOfferPacket(xid uint32, src net.IP, dst net.IP, dt int) []byte {

	dhcp := &layers.DHCPv6{MsgType: layers.DHCPv6MsgType(dt),
		TransactionID: []byte{(byte((xid & 0xff0000) >> 16)), byte((xid & 0xff00) >> 8), byte(xid & 0xff)}}

	clientid := &layers.DHCPv6DUID{Type: layers.DHCPv6DUIDTypeLL, HardwareType: []byte{0, 1}, LinkLayerAddress: []byte{0, 0, 1, 0, 0, 1}}
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptClientID, clientid.Encode()))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptOro, []byte{0, 0x11, 0, 0x17, 0, 0x18, 0x00, 0x27}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptVendorClass, []byte{0x00, 0x00, 0x01, 0x37, 0x00, 0x08, 0x4d, 0x53, 0x46, 0x54, 0x20, 0x35, 0x2e, 0x30}))

	ianao := []byte{0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x05, 0x00, 0x18, 0x20, 0x01, 0x0d, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x01, 0x77, 0x00, 0x00, 0x02, 0x58}

	//binary.BigEndian.PutUint32(ianao[0:4], o.iaid)

	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptIANA, ianao))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptElapsedTime, []byte{0x00, 0x00}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPv6Option(layers.DHCPv6OptServerID, []byte{0x00, 0x01, 0x00, 0x01, 0x21, 0x54, 0xee, 0xe7, 0x00, 0x0c, 0x29, 0x70, 0x3d, 0xd8}))

	ipv6pkt := core.PacketUtlBuild(

		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       8,
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     1,
			SrcIP:        src,
			DstIP:        dst,
		},

		&layers.UDP{SrcPort: 547, DstPort: 546},
		dhcp,
	)

	l2 := getL2()

	p := append(l2, ipv6pkt...)
	ipoffset := len(l2)

	pktSize := len(p)

	ipv6 := layers.IPv6Header(p[ipoffset : ipoffset+IPV6_HEADER_SIZE])

	// set local ip
	copy(p[0:6], []byte{0, 0, 1, 0, 0, 1})

	rcof := ipoffset + IPV6_HEADER_SIZE
	binary.BigEndian.PutUint16(p[rcof+4:rcof+6], uint16(pktSize-rcof))
	ipv6.SetPyloadLength(uint16(pktSize - rcof))
	ipv6.FixUdpL4Checksum(p[rcof:], 0)

	return p
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
