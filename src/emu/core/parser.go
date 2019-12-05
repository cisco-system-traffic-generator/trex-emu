package core

import (
	"encoding/binary"
	"external/google/gopacket/layers"
	"fmt"
)

/*ParserCb callback function for a protocol. In case the return value is zero, it means the protocol handle the packet
  and there is no need to free the mbuf. if the return value is not zero the parser will handle the mbuf free */
type ParserCb func(tctx *CThreadCtx,
	tun *CTunnelKey,
	m *Mbuf,
	l3 uint16,
	l4 uint16,
	l7 uint16) int

type ParserStats struct {
	NotSupportedProtocol  uint64
	errArpTooShort        uint64
	errIcmpv4TooShort     uint64
	errUdpTooShort        uint64
	errDot1qTooShort      uint64
	errToManyDot1q        uint64
	errIPv4TooShort       uint64
	errIPv4HeaderTooShort uint64
	errIPv4cs             uint64
	errTCP                uint64
	errUDP                uint64
}

/* counters */
type Parser struct {
	tctx *CThreadCtx

	stats ParserStats
	/* call backs */
	arp  ParserCb
	icmp ParserCb
	igmp ParserCb
	dhcp ParserCb
	tcp  ParserCb
	udp  ParserCb
}

func parserNotSupported(tctx *CThreadCtx,
	tun *CTunnelKey,
	m *Mbuf,
	l3 uint16,
	l4 uint16,
	l7 uint16) int {
	return -1
}

func (o *Parser) Init(tctx *CThreadCtx) {
	o.tctx = tctx
	o.arp = getProto("arp")
	o.icmp = parserNotSupported
	o.igmp = parserNotSupported
	o.dhcp = parserNotSupported
	o.tcp = parserNotSupported
	o.udp = parserNotSupported

}

func (o *Parser) parsePacketL4(tun *CTunnelKey, l3, l4 uint16,
	m *Mbuf,
	nextHdr uint8) int {
	packetSize := m.PktLen()
	p := m.GetData()

	switch layers.IPProtocol(nextHdr) {
	case layers.IPProtocolICMPv4:
		if packetSize < uint32(l4+8) {
			o.stats.errIcmpv4TooShort++
			return -1
		}
		return o.icmp(o.tctx, tun, m, l3, l4, l4+8)
	case layers.IPProtocolIGMP:
		if packetSize < uint32(l4+8) {
			o.stats.errIcmpv4TooShort++
			return -1
		}
		return o.igmp(o.tctx, tun, m, l3, l4, 0)
	case layers.IPProtocolTCP:
		o.stats.errTCP++
		return -1
	case layers.IPProtocolUDP:
		if packetSize < uint32(l4+8) {
			o.stats.errUdpTooShort++
			return (-1)
		}
		udp := layers.UDPHeader(p[l4 : l4+8])
		if (udp.SrcPort() == 67) && (udp.DstPort() == 68) {
			return o.dhcp(o.tctx, tun, m, l3, l4, l4+8)
		}
		o.stats.errUDP++
		return -1
	case layers.IPProtocolICMPv6:
		return -1
	}
	return (0)
}

func (o *Parser) ParsePacket(vport uint16, m *Mbuf) int {
	var tun CTunnelKey
	var l3, l4 uint16
	var d CTunnelData
	d.Vport = vport
	finished := false
	valnIndex := 0
	packetSize := m.PktLen()
	offset := uint16(14)
	p := m.GetData()
	ethHeader := layers.EthernetHeader(p[0:14])
	var nextHdr layers.EthernetType
	nextHdr = layers.EthernetType(ethHeader.GetNextProtocol())
	for {
		if finished {
			break
		}
		switch nextHdr {
		case layers.EthernetTypeARP:
			if packetSize < uint32(offset+layers.ARPHeaderSize) {
				o.stats.errArpTooShort++
				return -1
			}
			l3 = offset
			tun.Set(&d)
			return o.arp(o.tctx, &tun, m, l3, 0, 0)
		case layers.EthernetTypeDot1Q, layers.EthernetTypeQinQ:
			if packetSize < uint32(offset+4) {
				o.stats.errDot1qTooShort++
				return -1
			}
			if valnIndex > 1 {
				o.stats.errToManyDot1q++
				return -1
			}
			val := binary.BigEndian.Uint32(p[offset-2:offset+2]) & 0xffff3fff
			d.Vlans[valnIndex] = val
			valnIndex++
			nextHdr = layers.EthernetType(binary.BigEndian.Uint16(p[offset+2 : offset+4]))
			offset += 4
		case layers.EthernetTypeIPv4:
			l3 = offset
			if packetSize < uint32(offset+20) {
				o.stats.errIPv4TooShort++
				return -1
			}
			ipv4 := layers.IPv4Header(p[offset:])
			hdr := ipv4.GetHeaderLen()
			if hdr < 20 {
				o.stats.errIPv4HeaderTooShort++
				return -1
			}
			if packetSize < uint32(offset+hdr) {
				o.stats.errIPv4HeaderTooShort++
				return -1
			}
			if packetSize < uint32(offset+ipv4.GetLength()) {
				o.stats.errIPv4TooShort++
				return -1
			}
			if !ipv4.IsValidHeaderChecksum() {
				o.stats.errIPv4cs++
				return -1
			}

			l4 = offset + hdr
			offset = l4
			tun.Set(&d)
			return o.parsePacketL4(&tun, l3, l4, m, ipv4.GetNextProtocol())
		case layers.EthernetTypeIPv6:
			l3 = offset
			if packetSize < uint32(offset+20) {
				/* TO DO erro*/
			}

		default:
		}
	}
	return 0
}

type parserProtocols struct {
	M map[string]ParserCb
}

var parserDb parserProtocols

func getProto(proto string) ParserCb {
	_, ok := parserDb.M[proto]
	if !ok {
		err := fmt.Sprintf(" parser protocol %s is no register ", proto)
		panic(err)
	}
	return parserDb.M[proto]
}

func ParserRegister(proto string, cb ParserCb) {
	_, ok := parserDb.M[proto]
	if ok {
		s := fmt.Sprintf(" Can't register the same protocol twice %s ", proto)
		panic(s)
	}
	fmt.Sprintf(" register protocol %s ", proto)
	parserDb.M[proto] = cb
}
