package core

import (
	"encoding/binary"
	"external/google/gopacket/layers"
	"fmt"
	"runtime"
)

type ParserPacketState struct {
	Tctx *CThreadCtx
	Tun  *CTunnelKey
	M    *Mbuf
	L3   uint16 // 0 is not valid
	L4   uint16 // 0 is not valid
	L7   uint16
}

/*ParserCb callback function for a protocol. In case the return value is zero, it means the protocol handle the packet
  and there is no need to free the mbuf. if the return value is not zero the parser will handle the mbuf free */
type ParserCb func(ps *ParserPacketState) int

type ParserStats struct {
	errInternalHandler    uint64
	errParser             uint64
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

	return db
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
	Cdb  *CCounterDb
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
}

func (o *Parser) Init(tctx *CThreadCtx) {
	o.tctx = tctx
	o.arp = parserNotSupported
	o.icmp = parserNotSupported
	o.igmp = parserNotSupported
	o.dhcp = parserNotSupported
	o.tcp = parserNotSupported
	o.udp = parserNotSupported
	o.Cdb = newParserStatsDb(&o.stats)
}

func (o *Parser) parsePacketL4(ps *ParserPacketState,
	nextHdr uint8) int {
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
		udp := layers.UDPHeader(p[ps.L4 : ps.L4+8])
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

			ps.L4 = offset + hdr
			offset = ps.L4
			tun.Set(&d)
			return o.parsePacketL4(&ps, ipv4.GetNextProtocol())
		case layers.EthernetTypeIPv6:
			ps.L3 = offset
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

func init() {
	if runtime.NumGoroutine() != 1 {
		panic(" NumGoroutine() should be 1 on init time, require lock  ")
	}
	parserDb.M = make(map[string]ParserCb)
}
