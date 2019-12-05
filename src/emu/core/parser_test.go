package core

import (
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"fmt"
	"net"
	"testing"
)

func arpSupported(tctx *CThreadCtx,
	tun *CTunnelKey,
	m *Mbuf,
	l3 uint16,
	l4 uint16,
	l7 uint16) int {

	fmt.Printf("arp %s\n", tun.String())
	return -1
}

func TestParserArp(t *testing.T) {
	tctx := NewThreadCtx(0, 4510, true)
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
	m1.Dump()
	parser.ParsePacket(7, m1)
	
	fmt.Printf("1  %+v \n", parser.stats)

}
