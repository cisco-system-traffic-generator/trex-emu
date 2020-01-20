package core

import (
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"fmt"
	"net"
	"testing"
)

var arp uint16
var lastTun CTunnelKey
var lastL3 uint16
var lastL4 uint16
var lastL7 uint16

func arpSupported(ps *ParserPacketState) int {
	arp++
	lastL3 = ps.L3
	lastL4 = ps.L4
	lastL7 = ps.L7

	lastTun = *ps.Tun
	fmt.Printf("call arp %s\n", ps.Tun.String())
	return -1
}

func TestParserArp(t *testing.T) {
	tctx := NewThreadCtx(0, 4510, false, nil, false)
	var parser Parser
	parser.tctx = tctx
	parser.arp = arpSupported
	m1 := tctx.MPool.Alloc(128)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	//ip.SerializeTo(buf, opts)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{0, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(7),
			Type:           layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(7),
			Type:           layers.EthernetTypeDot1Q,
		},

		&layers.Dot1Q{
			Priority:       uint8(3),
			DropEligible:   false,
			VLANIdentifier: uint16(0x01ff),
			Type:           layers.EthernetTypeARP,
		},

		&layers.ARP{
			AddrType:          0x1,
			Protocol:          0x800,
			HwAddressSize:     0x6,
			ProtAddressSize:   0x4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   net.HardwareAddr{0, 1, 1, 1, 1, 1},
			SourceProtAddress: []uint8{0x0, 0x0, 0x0, 0x0},
			DstHwAddress:      []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			DstProtAddress:    []uint8{0x00, 0x00, 0x00, 0x00}})

	data := buf.Bytes()
	m1.Append(data)
	m1.SetVPort(7)
	m1.Dump()
	parser.ParsePacket(m1)

	if parser.stats.errToManyDot1q != 1 {
		t.Fatalf(" errToManyDot1q should be 1")
	} else {
		t.Log("OK")
	}

}

func TestParserArp1(t *testing.T) {
	tctx := NewThreadCtx(0, 4510, false, nil)
	var parser Parser
	parser.tctx = tctx
	parser.arp = arpSupported
	m1 := tctx.MPool.Alloc(128)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	//ip.SerializeTo(buf, opts)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{0, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(7),
			Type:           layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(3),
			VLANIdentifier: uint16(0xfff),
			Type:           layers.EthernetTypeARP,
		},

		&layers.ARP{
			AddrType:          0x1,
			Protocol:          0x800,
			HwAddressSize:     0x6,
			ProtAddressSize:   0x4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   net.HardwareAddr{0, 1, 1, 1, 1, 1},
			SourceProtAddress: []uint8{0x0, 0x0, 0x0, 0x0},
			DstHwAddress:      []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			DstProtAddress:    []uint8{0x00, 0x00, 0x00, 0x00}})

	data := buf.Bytes()
	m1.Append(data)
	//m1.Dump()
	m1.SetVPort(7)
	arp = 0
	parser.ParsePacket(m1)
	fmt.Printf(" %d", arp)
	if arp != 1 {
		t.Fatalf(" arp cb should be called ")
	}

	var tunData CTunnelData
	tunData.Vport = 7
	tunData.Vlans[0] = 0x81000007
	tunData.Vlans[1] = 0x81000fff

	var extun CTunnelKey
	extun.Set(&tunData)

	if lastTun != extun {
		t.Fatalf(" ERROR expected last tun is not right ")
	}
}

func TestParserIcmp(t *testing.T) {
	tctx := NewThreadCtx(0, 4510, false, nil)
	var parser Parser
	parser.tctx = tctx
	parser.icmp = arpSupported
	m1 := tctx.MPool.Alloc(128)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true,
		ComputeChecksums: true}
	//ip.SerializeTo(buf, opts)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{0, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(7),
			Type:           layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(3),
			VLANIdentifier: uint16(0xfff),
			Type:           layers.EthernetTypeIPv4,
		},

		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc, SrcIP: net.IPv4(16, 0, 0, 1), DstIP: net.IPv4(48, 0, 0, 1), Length: 44,
			Protocol: layers.IPProtocolICMPv4},

		&layers.ICMPv4{TypeCode: layers.ICMPv4TypeEchoRequest, Id: 1, Seq: 0x11},

		gopacket.Payload([]byte{1, 2, 3, 4}),
	)

	data := buf.Bytes()
	//PacketUtl("icmp1", data)
	m1.Append(data)
	m1.SetVPort(7)

	//m1.DumpK12(1)
	arp = 0
	parser.ParsePacket(m1)
	fmt.Printf(" %d", arp)
	if arp != 1 {
		t.Fatalf(" cb should be called ")
	}

	var tunData CTunnelData
	tunData.Vport = 7
	tunData.Vlans[0] = 0x81000007
	tunData.Vlans[1] = 0x81000fff

	var extun CTunnelKey
	extun.Set(&tunData)

	if lastTun != extun {
		t.Fatalf(" ERROR expected last tun is not right ")

	}
	exp := [3]uint16{22, 42, 50}
	last := [3]uint16{lastL3, lastL4, lastL7}
	if exp != last {
		t.Fatalf(" ERROR expected %v != %v ", exp, last)
	}
}

func TestParserDhcp1(t *testing.T) {
	tctx := NewThreadCtx(0, 4510, false, nil)
	var parser Parser
	parser.tctx = tctx
	parser.dhcp = arpSupported

	buf := gopacket.NewSerializeBuffer()
	/*opts := gopacket.SerializeOptions{FixLengths: true,
	ComputeChecksums: true}*/
	opts := gopacket.SerializeOptions{FixLengths: true}

	dhcp := &layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, Xid: 0x12345678,
		ClientIP: net.IP{0, 0, 0, 0}, YourClientIP: net.IP{0, 0, 0, 0}, NextServerIP: net.IP{0, 0, 0, 0}, RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		ServerName:   make([]byte, 64), File: make([]byte, 128)}
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptPad, nil))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptParamsRequest,
		[]byte{byte(layers.DHCPOptSubnetMask), byte(layers.DHCPOptBroadcastAddr), byte(layers.DHCPOptTimeOffset),
			byte(layers.DHCPOptRouter), byte(layers.DHCPOptDomainName), byte(layers.DHCPOptDNS), byte(layers.DHCPOptDomainSearch),
			byte(layers.DHCPOptHostname), byte(layers.DHCPOptNetBIOSTCPNS), byte(layers.DHCPOptInterfaceMTU), byte(layers.DHCPOptClasslessStaticRoute),
			byte(layers.DHCPOptNTPServers)}))

	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{0, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(7),
			Type:           layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(3),
			VLANIdentifier: uint16(0x1),
			Type:           layers.EthernetTypeIPv4,
		},

		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc, SrcIP: net.IPv4(16, 0, 0, 1), DstIP: net.IPv4(48, 0, 0, 1),
			Protocol: layers.IPProtocolUDP},

		&layers.UDP{SrcPort: 67, DstPort: 68},
		dhcp,
	)

	data := buf.Bytes()
	ipv4 := layers.IPv4Header(data[22 : 22+20])
	ipv4.UpdateChecksum()
	m1 := tctx.MPool.Alloc(uint16(len(data)))
	//PacketUtl("dhcp2", data)
	//fmt.Printf(" %v \n", data)
	m1.Append(data)
	m1.SetVPort(7)

	//m1.Dump()
	arp = 0
	parser.ParsePacket(m1)

	if arp != 1 {
		t.Fatalf(" cb should be called ")
	}

	var tunData CTunnelData
	tunData.Vport = 7
	tunData.Vlans[0] = 0x81000007
	tunData.Vlans[1] = 0x81000001

	var extun CTunnelKey
	extun.Set(&tunData)

	if lastTun != extun {
		t.Fatalf(" ERROR expected last tun is not right ")

	}
	exp := [3]uint16{22, 42, 50}
	last := [3]uint16{lastL3, lastL4, lastL7}
	if exp != last {
		t.Fatalf(" ERROR expected %v != %v ", exp, last)
	}
}

func TestParserDhcpInvalidCs(t *testing.T) {
	tctx := NewThreadCtx(0, 4510, false, nil)
	var parser Parser
	parser.tctx = tctx
	parser.dhcp = arpSupported

	buf := gopacket.NewSerializeBuffer()
	/*opts := gopacket.SerializeOptions{FixLengths: true,
	ComputeChecksums: true}*/
	opts := gopacket.SerializeOptions{FixLengths: true}

	dhcp := &layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, Xid: 0x12345678,
		ClientIP: net.IP{0, 0, 0, 0}, YourClientIP: net.IP{0, 0, 0, 0}, NextServerIP: net.IP{0, 0, 0, 0}, RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		ServerName:   make([]byte, 64), File: make([]byte, 128)}
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptPad, nil))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptParamsRequest,
		[]byte{byte(layers.DHCPOptSubnetMask), byte(layers.DHCPOptBroadcastAddr), byte(layers.DHCPOptTimeOffset),
			byte(layers.DHCPOptRouter), byte(layers.DHCPOptDomainName), byte(layers.DHCPOptDNS), byte(layers.DHCPOptDomainSearch),
			byte(layers.DHCPOptHostname), byte(layers.DHCPOptNetBIOSTCPNS), byte(layers.DHCPOptInterfaceMTU), byte(layers.DHCPOptClasslessStaticRoute),
			byte(layers.DHCPOptNTPServers)}))

	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{0, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(0),
			VLANIdentifier: uint16(7),
			Type:           layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			Priority:       uint8(3),
			VLANIdentifier: uint16(0x1),
			Type:           layers.EthernetTypeIPv4,
		},

		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc, SrcIP: net.IPv4(16, 0, 0, 1), DstIP: net.IPv4(48, 0, 0, 1),
			Protocol: layers.IPProtocolUDP},

		&layers.UDP{SrcPort: 67, DstPort: 68},
		dhcp,
	)

	data := buf.Bytes()
	//ipv4 := layers.IPv4Header(data[22 : 22+20])
	//ipv4.UpdateChecksum()
	m1 := tctx.MPool.Alloc(uint16(len(data)))
	//PacketUtl("dhcp2", data)
	//fmt.Printf(" %v \n", data)
	m1.SetVPort(7)
	m1.Append(data)
	arp = 0
	parser.ParsePacket(m1)
	//fmt.Printf("%+v \n", parser.stats)

	if parser.stats.errIPv4cs != 1 {
		t.Fatalf(" ipv4 checksum should be wrong ")
	}

}
