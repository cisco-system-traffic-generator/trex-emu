package core

import (
	"encoding/binary"
	"external/google/gopacket/layers"
	"fmt"
	"runtime"
)

const (
	IPV6_HEADER_SIZE    = 40
	IPV6_EXT_HOP_BY_HOP = 0
	IPV6_EXT_DST        = 60
	IPV6_EXT_ROUTING    = 43
	IPV6_EXT_Fragment   = 44
	IPV6_EXT_AH         = 51
	IPV6_EXT_ESP        = 50
	IPV6_EXT_MOBILE     = 135
	IPV6_EXT_HOST       = 139
	IPV6_EXT_SHIM       = 140
	IPV6_EXT_JUMBO      = 194
	IPV6_EXT_END        = 59
)

type ParserPacketState struct {
	Tctx  *CThreadCtx
	Tun   *CTunnelKey
	M     *Mbuf
	L3    uint16 // offset 0 is not valid (ip)
	L4    uint16 // offset 0 is not valid (tcp/udp)
	L7    uint16 // offset
	L7Len uint16 // 0 if not relevant
}

/*ParserCb callback function for a protocol. In case the return value is zero, it means the protocol handle the packet
  and there is no need to free the mbuf. if the return value is not zero the parser will handle the mbuf free */
type ParserCb func(ps *ParserPacketState) int

type ParserStats struct {
	errInternalHandler    uint64
	errParser             uint64
	errArpTooShort        uint64
	errIcmpv4TooShort     uint64
	errIgmpv4TooShort     uint64
	errUdpTooShort        uint64
	errDot1qTooShort      uint64
	errToManyDot1q        uint64
	errIPv4TooShort       uint64
	errIPv4HeaderTooShort uint64
	errIPv4cs             uint64
	errTCP                uint64
	errUDP                uint64
	arpPkts               uint64
	arpBytes              uint64
	icmpPkts              uint64
	icmpBytes             uint64
	igmpPkts              uint64
	igmpBytes             uint64
	dhcpPkts              uint64
	dhcpBytes             uint64
	tcpPkts               uint64
	tcpBytes              uint64
	udpPkts               uint64
	udpBytes              uint64
	udpCsErr              uint64
	tcpCsErr              uint64
	errIPv6TooShort       uint64
	errIPv6HopLimitDrop   uint64
	errIPv6Empty          uint64
	errIPv6OptJumbo       uint64
	errIcmpv6TooShort     uint64
	errIcmpv6Cse          uint64
	errIcmpv6Unsupported  uint64
	Icmpv6Pkt             uint64
	Icmpv6Bytes           uint64
}

func newParserStatsDb(o *ParserStats) *CCounterDb {
	db := NewCCounterDb("parser")
	db.Add(&CCounterRec{
		Counter:  &o.errInternalHandler,
		Name:     "errInternalHandler",
		Help:     "internal handler",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errParser,
		Name:     "errParser",
		Help:     "parser error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errArpTooShort,
		Name:     "errArpTooShort",
		Help:     "arp too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIcmpv4TooShort,
		Name:     "errIcmpv4TooShort",
		Help:     "icmpv4 too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIgmpv4TooShort,
		Name:     "errIgmpv4TooShort",
		Help:     "igmpv4 too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errUdpTooShort,
		Name:     "errUdpTooShort",
		Help:     "udp too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errDot1qTooShort,
		Name:     "errDot1qTooShort",
		Help:     "dot1q too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errToManyDot1q,
		Name:     "errToManyDot1q",
		Help:     "dot1q too long",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv4TooShort,
		Name:     "errIPv4TooShort",
		Help:     "ipv4 too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv4HeaderTooShort,
		Name:     "errIPv4HeaderTooShort",
		Help:     "ipv4 header too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv4cs,
		Name:     "errIPv4cs",
		Help:     "ipv4 checksum error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errTCP,
		Name:     "errTCP",
		Help:     "tcp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errUDP,
		Name:     "errUDP",
		Help:     "udp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.arpPkts,
		Name:     "arpPkts",
		Help:     "arp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.arpBytes,
		Name:     "arpBytes",
		Help:     "arp bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.icmpPkts,
		Name:     "icmpPkts",
		Help:     "icmp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.icmpBytes,
		Name:     "icmpBytes",
		Help:     "icmp bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.igmpPkts,
		Name:     "igmpPkts",
		Help:     "igmp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.igmpBytes,
		Name:     "igmpBytes",
		Help:     "igmp bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.dhcpPkts,
		Name:     "dhcpPkts",
		Help:     "dhcp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.dhcpBytes,
		Name:     "dhcpBytes",
		Help:     "dhcp bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.tcpPkts,
		Name:     "tcpPkts",
		Help:     "tcp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.tcpBytes,
		Name:     "tcpBytes",
		Help:     "tcp bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.udpPkts,
		Name:     "udpPkts",
		Help:     "udp packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.udpBytes,
		Name:     "udpBytes",
		Help:     "udp bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv6TooShort,
		Name:     "errIPv6TooShort",
		Help:     "ipv6 too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv6HopLimitDrop,
		Name:     "errIPv6HopLimitDrop",
		Help:     "ipv6 hop limit",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv6Empty,
		Name:     "errIPv6Empty",
		Help:     "ipv6 no payload",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIcmpv6TooShort,
		Name:     "errIcmpv6TooShort",
		Help:     "icmpv6 too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIcmpv6Cse,
		Name:     "errIcmpv6Cse",
		Help:     "Icmpv6 checksum error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIcmpv6Unsupported,
		Name:     "errIcmpv6Unsupported",
		Help:     "Icmpv6 unsupported type/code",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.Icmpv6Pkt,
		Name:     "Icmpv6Pkt",
		Help:     "Icmpv6 pkts",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.Icmpv6Bytes,
		Name:     "Icmpv6Bytes",
		Help:     "Icmpv6 bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv6OptJumbo,
		Name:     "errIPv6OptJumbo",
		Help:     "Icmpv6 jumbo option is not supported ",
		Unit:     "pkt",
		DumpZero: false,
		Info:     ScERROR})

	return db
}

/* counters */
type Parser struct {
	tctx *CThreadCtx

	stats ParserStats
	/* call backs */
	arp    ParserCb
	icmp   ParserCb
	igmp   ParserCb
	dhcp   ParserCb
	tcp    ParserCb
	udp    ParserCb
	icmpv6 ParserCb
	Cdb    *CCounterDb
}

func parserNotSupported(ps *ParserPacketState) int {
	return -1
}

func (o *Parser) Register(protocol string) {
	if protocol == "arp" {
		o.arp = getProto("arp")
	}
	if protocol == "icmp" {
		o.icmp = getProto("icmp")
	}
	if protocol == "igmp" {
		o.igmp = getProto("igmp")
	}
	if protocol == "dhcp" {
		o.dhcp = getProto("dhcp")
	}
	if protocol == "icmpv6" {
		o.icmpv6 = getProto("icmpv6")
	}
}

func (o *Parser) Init(tctx *CThreadCtx) {
	o.tctx = tctx
	o.arp = parserNotSupported
	o.icmp = parserNotSupported
	o.igmp = parserNotSupported
	o.dhcp = parserNotSupported
	o.tcp = parserNotSupported
	o.udp = parserNotSupported
	o.icmpv6 = parserNotSupported
	o.Cdb = newParserStatsDb(&o.stats)
}

func (o *Parser) parsePacketL4(ps *ParserPacketState,
	nextHdr uint8, pcs uint32, l4len uint16) int {

	packetSize := ps.M.PktLen()
	p := ps.M.GetData()

	switch layers.IPProtocol(nextHdr) {
	case layers.IPProtocolICMPv4:
		if packetSize < uint32(ps.L4+8) {
			o.stats.errIcmpv4TooShort++
			return -1
		}
		o.stats.icmpPkts++
		o.stats.icmpBytes += uint64(packetSize)
		ps.L7 = ps.L4 + 8
		return o.icmp(ps)
	case layers.IPProtocolIGMP:
		if packetSize < uint32(ps.L4+8) {
			o.stats.errIcmpv4TooShort++
			return -1
		}
		o.stats.igmpPkts++
		o.stats.igmpBytes += uint64(packetSize)
		return o.igmp(ps)
	case layers.IPProtocolTCP:
		o.stats.errTCP++
		o.stats.tcpPkts++
		o.stats.tcpBytes += uint64(packetSize)
		return -1
	case layers.IPProtocolUDP:
		if packetSize < uint32(ps.L4+8) {
			o.stats.errUdpTooShort++
			return (-1)
		}
		ps.L7Len = l4len - 8
		udp := layers.UDPHeader(p[ps.L4 : ps.L4+8])
		if udp.Checksum() > 0 {
			if layers.PktChecksum(p[ps.L4:ps.L4+l4len], pcs) != 0 {
				o.stats.udpCsErr++
				return -1
			}
		}
		o.stats.udpPkts++
		o.stats.udpBytes += uint64(packetSize)
		if (udp.SrcPort() == 67) && (udp.DstPort() == 68) {
			o.stats.dhcpPkts++
			o.stats.dhcpBytes += uint64(packetSize)
			ps.L7 = ps.L4 + 8
			return o.dhcp(ps)
		}
		o.stats.errUDP++
		return -1
	case layers.IPProtocolICMPv6:
		if packetSize < uint32(ps.L4+4) {
			o.stats.errIcmpv6TooShort++
			return -1
		}
		if layers.PktChecksum(p[ps.L4:ps.L4+l4len], pcs) != 0 {
			o.stats.errIcmpv6Cse++
			return -1
		}
		Pkttype := p[ps.L4]

		switch Pkttype {

		case
			layers.ICMPv6TypeDestinationUnreachable,
			layers.ICMPv6TypePacketTooBig,
			layers.ICMPv6TypeTimeExceeded,
			layers.ICMPv6TypeParameterProblem,
			layers.ICMPv6TypeEchoRequest,
			layers.ICMPv6TypeEchoReply,
			layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage,
			layers.ICMPv6TypeMLDv1MulticastListenerReportMessage,
			layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage,
			layers.ICMPv6TypeRouterSolicitation,
			layers.ICMPv6TypeRouterAdvertisement,
			layers.ICMPv6TypeNeighborSolicitation,
			layers.ICMPv6TypeNeighborAdvertisement:
			o.stats.Icmpv6Pkt++
			o.stats.Icmpv6Bytes += uint64(packetSize)
			return (o.icmpv6(ps))
		default:
			o.stats.errIcmpv6Unsupported++
			return -1
		}
		return -1
	}
	return (0)
}

/*
ParsePacket
return values

   0   process by the parser callback
   -1  parser error
   -2  internal parser error
*/
func (o *Parser) ParsePacket(m *Mbuf) int {
	var tun CTunnelKey
	var d CTunnelData
	d.Vport = m.port
	finished := false
	valnIndex := 0
	packetSize := m.PktLen()
	offset := uint16(14)
	p := m.GetData()
	var ps ParserPacketState
	ps.Tctx = o.tctx
	ps.Tun = &tun
	ps.M = m

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
			ps.L3 = offset
			tun.Set(&d)
			o.stats.arpPkts++
			o.stats.arpBytes += uint64(packetSize)
			return o.arp(&ps)
		case layers.EthernetTypeDot1Q, layers.EthernetTypeQinQ:
			if packetSize < uint32(offset+4) {
				o.stats.errDot1qTooShort++
				return -1
			}
			if valnIndex > 1 {
				o.stats.errToManyDot1q++
				return -1
			}
			val := binary.BigEndian.Uint32(p[offset-2:offset+2]) & 0xffff0fff
			d.Vlans[valnIndex] = val
			valnIndex++
			nextHdr = layers.EthernetType(binary.BigEndian.Uint16(p[offset+2 : offset+4]))
			offset += 4
		case layers.EthernetTypeIPv4:
			ps.L3 = offset
			if packetSize < uint32(offset+20) {
				o.stats.errIPv4TooShort++
				return -1
			}
			ipv4 := layers.IPv4Header(p[offset : offset+20])
			if ipv4.Version() != 4 {
				o.stats.errIPv4HeaderTooShort++
				return -1
			}
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
			if hdr != 20 {
				ipv4 = layers.IPv4Header(p[offset : offset+hdr])
			}

			if !ipv4.IsValidHeaderChecksum() {
				o.stats.errIPv4cs++
				return -1
			}
			l4len := ipv4.GetLength() - ipv4.GetHeaderLen()
			ps.L4 = offset + hdr
			offset = ps.L4
			tun.Set(&d)

			return o.parsePacketL4(&ps, ipv4.GetNextProtocol(), ipv4.GetPhCs(), l4len)
		case layers.EthernetTypeIPv6:
			ps.L3 = offset
			if packetSize < uint32(offset+IPV6_HEADER_SIZE) {
				o.stats.errIPv6TooShort++
				return -1
			}
			ipv6 := layers.IPv6Header(p[offset : offset+IPV6_HEADER_SIZE])
			if ipv6.Version() != 6 {
				o.stats.errIPv6TooShort++
				return -1
			}
			if packetSize < uint32(offset+IPV6_HEADER_SIZE+ipv6.PayloadLength()) {
				o.stats.errIPv6TooShort++
				return -1
			}
			if ipv6.HopLimit() == 0 {
				o.stats.errIPv6HopLimitDrop++
				return -1
			}

			l4 := ps.L3 + IPV6_HEADER_SIZE
			l4len := ipv6.PayloadLength()
			tun.Set(&d)

			nh := ipv6.NextHeader()
			var osize uint16
			doloop := true
			for doloop {
				switch nh {
				case IPV6_EXT_HOP_BY_HOP,
					IPV6_EXT_DST,
					IPV6_EXT_ROUTING,
					IPV6_EXT_Fragment,
					IPV6_EXT_AH,
					IPV6_EXT_ESP,
					IPV6_EXT_MOBILE,
					IPV6_EXT_HOST,
					IPV6_EXT_SHIM:
					if l4len < 8 {
						o.stats.errIPv6TooShort++
						return -1
					}
					ipv6ex := layers.IPv6ExtHeader(p[l4 : l4+2])
					hl := ipv6ex.HeaderLen()
					if l4len < hl {
						o.stats.errIPv6TooShort++
						return -1
					}
					nh = ipv6ex.NextHeader()
					l4len -= hl
					osize += hl
					l4 += hl
				case IPV6_EXT_JUMBO:
					// not supported
					o.stats.errIPv6OptJumbo++
					return (-1)

				case IPV6_EXT_END:
					o.stats.errIPv6Empty++
					return (0)
				default:
					doloop = false
					break
				}
			}
			ps.L4 = l4
			return o.parsePacketL4(&ps, nh, ipv6.GetPhCs(osize, nh), l4len)
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

func init() {
	if runtime.NumGoroutine() != 1 {
		panic(" NumGoroutine() should be 1 on init time, require lock  ")
	}
	parserDb.M = make(map[string]ParserCb)
}
