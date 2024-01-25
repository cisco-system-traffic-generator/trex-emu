// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.
// August 2021 Eolo S.p.A. and Altran Italia S.p.A.
// - added reference to ppp parser at line 476
// - modify if logic into function parserNotSupported at line 506
// - modify Init method at line 525
// - modify ParsePacket method at line 668

package core

import (
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/ip4defrag"
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

const (
	IPV6_OPTION_NONE  = 0
	IPV6_OPTION_PAD   = 1
	IPV6_ROUTER_ALERT = 5
)

const (
	PARSER_ERR = -1
	PARSER_OK  = 0
)

// FLAGS of IPv6
const (
	IPV6_M_RTALERT_ML uint32 = 0x1
)

type ParserPacketState struct {
	Tctx       *CThreadCtx
	Tun        *CTunnelKey
	M          *Mbuf
	L3         uint16 // offset 0 is not valid (ip)
	L4         uint16 // offset 0 is not valid (tcp/udp)
	L7         uint16 // offset
	L7Len      uint16 // 0 if not relevant
	Flags      uint32
	NextHeader uint8 // next header for ipv6
}

/*ParserCb callback function for a protocol. In case the return value is zero, it means the protocol handle the packet
  and there is no need to free the mbuf. if the return value is not zero the parser will handle the mbuf free */
type ParserCb func(ps *ParserPacketState) int

type ParserStats struct {
	errInternalHandler    uint64
	errParser             uint64
	errEAPolTooShort      uint64
	errArpTooShort        uint64
	errIcmpv4TooShort     uint64
	errIgmpv4TooShort     uint64
	errUdpTooShort        uint64
	errTcpTooShort        uint64
	errDot1qTooShort      uint64
	errToManyDot1q        uint64
	errIPv4TooShort       uint64
	errIPv4HeaderTooShort uint64
	errIPv4Fragment       uint64
	errIPv4cs             uint64
	errTCP                uint64
	errUDP                uint64
	eapolPkts             uint64
	eapolBytes            uint64

	arpPkts               uint64
	arpBytes              uint64
	icmpPkts              uint64
	icmpBytes             uint64
	igmpPkts              uint64
	igmpBytes             uint64
	dhcpPkts              uint64
	dhcpBytes             uint64
	dhcpSrvPkts           uint64
	dhcpSrvBytes          uint64
	mDnsPkts              uint64
	mDnsBytes             uint64
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
	errIPv6Fragment       uint64
	errIcmpv6TooShort     uint64
	errIcmpv6Cse          uint64
	errIcmpv4Cse          uint64
	errIcmpv6Unsupported  uint64
	Icmpv6Pkt             uint64
	Icmpv6Bytes           uint64
	errL4ProtoUnsupported uint64
	errL3ProtoUnsupported uint64
	errPacketIsTooShort   uint64
}

func newParserStatsDb(o *ParserStats) *CCounterDb {
	db := NewCCounterDb("parser")

	db.Add(&CCounterRec{
		Counter:  &o.errEAPolTooShort,
		Name:     "errEAPolTooShort",
		Help:     "eap packets are too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.eapolPkts,
		Name:     "eapolPkts",
		Help:     "eapol packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.eapolBytes,
		Name:     "eapolBytes",
		Help:     "eapol bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

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
		Counter:  &o.errTcpTooShort,
		Name:     "errTcpTooShort",
		Help:     "udp too short",
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
		Counter:  &o.dhcpSrvPkts,
		Name:     "dhcpSrvPkts",
		Help:     "Dhcp server packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.dhcpSrvBytes,
		Name:     "dhcpSrvBytes",
		Help:     "Dhcp server bytes",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.mDnsPkts,
		Name:     "mDnsPkts",
		Help:     "mDns packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO})

	db.Add(&CCounterRec{
		Counter:  &o.mDnsBytes,
		Name:     "mDnsBytes",
		Help:     "mDns bytes",
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
		Counter:  &o.errIcmpv4Cse,
		Name:     "errIcmpv4Cse",
		Help:     "Icmpv4 checksum error",
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

	db.Add(&CCounterRec{
		Counter:  &o.errIPv6Fragment,
		Name:     "errIPv6Fragment",
		Help:     "ipv6 fragment is not supported",
		Unit:     "pkt",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errIPv4Fragment,
		Name:     "errIPv4Fragment",
		Help:     "ipv4 fragment is not supported",
		Unit:     "pkt",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errL3ProtoUnsupported,
		Name:     "errL3ProtoUnsupported",
		Help:     "L3 proto is not supported",
		Unit:     "pkt",
		DumpZero: false,
		Info:     ScERROR})

	db.Add(&CCounterRec{
		Counter:  &o.errPacketIsTooShort,
		Name:     "errPacketIsTooShort",
		Help:     "packet is too short for parsing",
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
	arp     ParserCb
	icmp    ParserCb
	igmp    ParserCb
	dhcp    ParserCb
	dhcpsrv ParserCb
	dhcpv6  ParserCb
	mdns    ParserCb
	tcp     ParserCb
	udp     ParserCb
	icmpv6  ParserCb
	eapol   ParserCb
	ppp     ParserCb
	Cdb     *CCounterDb

	Defrag *ip4defrag.IPv4Defragmenter
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
	if protocol == "dhcpsrv" {
		o.dhcpsrv = getProto("dhcpsrv")
	}
	if protocol == "icmpv6" {
		o.icmpv6 = getProto("icmpv6")
	}
	if protocol == "dhcpv6" {
		o.dhcpv6 = getProto("dhcpv6")
	}
	if protocol == "dot1x" {
		o.eapol = getProto("dot1x")
	}
	if protocol == "mdns" {
		o.mdns = getProto("mdns")
	}

	if protocol == "ppp" {
		o.ppp = getProto("ppp")
	}

	if protocol == "transport" {
		o.tcp = getProto("transport")
		o.udp = getProto("transport")
	}
}

func (o *Parser) Init(tctx *CThreadCtx) {
	o.tctx = tctx
	o.arp = parserNotSupported
	o.icmp = parserNotSupported
	o.igmp = parserNotSupported
	o.dhcp = parserNotSupported
	o.dhcpsrv = parserNotSupported
	o.tcp = parserNotSupported
	o.udp = parserNotSupported
	o.icmpv6 = parserNotSupported
	o.dhcpv6 = parserNotSupported
	o.mdns = parserNotSupported
	o.ppp = parserNotSupported
	o.Cdb = newParserStatsDb(&o.stats)
	o.Defrag = ip4defrag.NewIPv4Defragmenter()
}

func (o *Parser) parsePacketL4(ps *ParserPacketState,
	nextHdr uint8, pcs uint32, l4len uint16, layer3 uint16) int {

	packetSize := ps.M.PktLen()
	p := ps.M.GetData()
	ps.NextHeader = nextHdr

	switch layers.IPProtocol(nextHdr) {
	case layers.IPProtocolICMPv4:
		if packetSize < uint32(ps.L4+8) {
			o.stats.errIcmpv4TooShort++
			return PARSER_ERR
		}

		if layers.PktChecksum(p[ps.L4:ps.L4+l4len], 0) != 0 {
			o.stats.errIcmpv4Cse++
			return PARSER_ERR
		}

		o.stats.icmpPkts++
		o.stats.icmpBytes += uint64(packetSize)
		ps.L7 = ps.L4 + 8
		return o.icmp(ps)
	case layers.IPProtocolIGMP:
		if packetSize < uint32(ps.L4+8) {
			o.stats.errIcmpv4TooShort++
			return PARSER_ERR
		}
		o.stats.igmpPkts++
		o.stats.igmpBytes += uint64(packetSize)
		return o.igmp(ps)
	case layers.IPProtocolTCP:
		if l4len < uint16(20) {
			o.stats.errTcpTooShort++
			return PARSER_ERR
		}
		do := p[ps.L4+12]
		tcplen := (do >> 4) << 2
		if l4len < uint16(tcplen) {
			o.stats.errTcpTooShort++
			return PARSER_ERR
		}
		ps.L7 = ps.L4 + uint16(tcplen)
		ps.L7Len = l4len - uint16(tcplen)

		if layers.PktChecksum(p[ps.L4:ps.L4+l4len], pcs) != 0 {
			o.stats.tcpCsErr++
			return PARSER_ERR
		}

		o.stats.tcpPkts++
		o.stats.tcpBytes += uint64(packetSize)
		return o.tcp(ps)
	case layers.IPProtocolUDP:
		if packetSize < uint32(ps.L4+8) {
			o.stats.errUdpTooShort++
			return PARSER_ERR
		}
		ps.L7Len = l4len - 8
		udp := layers.UDPHeader(p[ps.L4 : ps.L4+8])
		if udp.Checksum() > 0 {
			if layers.PktChecksum(p[ps.L4:ps.L4+l4len], pcs) != 0 {
				o.stats.udpCsErr++
				return PARSER_ERR
			}
		}
		o.stats.udpPkts++
		o.stats.udpBytes += uint64(packetSize)
		ps.L7 = ps.L4 + 8

		if udp.DstPort() == 5353 {
			o.stats.mDnsPkts++
			o.stats.mDnsBytes += uint64(packetSize)
			return o.mdns(ps)
		}

		if layer3 == uint16(layers.EthernetTypeIPv6) {
			if (udp.SrcPort() == 547) && (udp.DstPort() == 546) {
				o.stats.dhcpPkts++
				o.stats.dhcpBytes += uint64(packetSize)
				return o.dhcpv6(ps)
			}
		} else {
			if (udp.SrcPort() == 67) && (udp.DstPort() == 68) {
				// S -> C, parse by client
				o.stats.dhcpPkts++
				o.stats.dhcpBytes += uint64(packetSize)
				return o.dhcp(ps)
			}
			if udp.DstPort() == 67 && (udp.SrcPort() == 67 || udp.SrcPort() == 68) {
				// C -> S, parse by server.
				// If C -> S without relay, the source port is 68.
				// If C -> S with relay, the relay changes the source port to 67.
				o.stats.dhcpSrvPkts++
				o.stats.dhcpSrvBytes += uint64(packetSize)
				return o.dhcpsrv(ps)
			}
		}

		return o.udp(ps)

	case layers.IPProtocolICMPv6:
		if packetSize < uint32(ps.L4+4) {
			o.stats.errIcmpv6TooShort++
			return PARSER_ERR
		}
		if layers.PktChecksum(p[ps.L4:ps.L4+l4len], pcs) != 0 {
			o.stats.errIcmpv6Cse++
			return PARSER_ERR
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
			return PARSER_ERR
		}
		return -1
	default:
		o.stats.errL4ProtoUnsupported++
		return PARSER_ERR
	}
	return (0)
}

func processIpv6Options(p []byte, flags *uint32) int {
	size := len(p)
	i := 0
	nh := p[0]
	for {
		switch nh {
		case IPV6_OPTION_NONE:
			i++
		case IPV6_ROUTER_ALERT:
			*flags |= IPV6_M_RTALERT_ML
			return (0)
		default:
			i = i + 2 + int(p[i+1])
		}
		if i > (size - 1) {
			return (-1)
		}
		nh = p[i]
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
	vlanIndex := 0
	packetSize := m.PktLen()

	offset := uint16(14)
	p := m.GetData()
	var ps ParserPacketState
	ps.Tctx = o.tctx
	ps.Tun = &tun
	ps.M = m

	if packetSize < 14 {
		o.stats.errPacketIsTooShort++
		return PARSER_ERR
	}

	ethHeader := layers.EthernetHeader(p[0:14])
	var nextHdr layers.EthernetType
	nextHdr = layers.EthernetType(ethHeader.GetNextProtocol())
	for {
		switch nextHdr {
		case layers.EthernetTypeEAPOL:
			if packetSize < uint32(offset+4) {
				o.stats.errEAPolTooShort++
				return PARSER_ERR
			}
			ps.L3 = offset
			tun.Set(&d)
			o.stats.eapolPkts++
			o.stats.eapolBytes += uint64(packetSize)
			return o.eapol(&ps)

		case layers.EthernetTypeARP:
			if packetSize < uint32(offset+layers.ARPHeaderSize) {
				o.stats.errArpTooShort++
				return PARSER_ERR
			}
			ps.L3 = offset
			tun.Set(&d)
			o.stats.arpPkts++
			o.stats.arpBytes += uint64(packetSize)
			return o.arp(&ps)
		case layers.EthernetTypeDot1Q, layers.EthernetTypeQinQ:
			if packetSize < uint32(offset+4) {
				o.stats.errDot1qTooShort++
				return PARSER_ERR
			}
			if vlanIndex > 1 {
				o.stats.errToManyDot1q++
				return PARSER_ERR
			}
			val := binary.BigEndian.Uint32(p[offset-2:offset+2]) & 0xffff0fff
			d.Vlans[vlanIndex] = val
			vlanIndex++
			nextHdr = layers.EthernetType(binary.BigEndian.Uint16(p[offset+2 : offset+4]))
			if nextHdr == layers.EthernetTypePPPoEDiscovery || nextHdr == layers.EthernetTypePPPoESession {
				tun.Set(&d)
				return o.ppp(&ps)
			}
			offset += 4
		case layers.EthernetTypePPPoEDiscovery, layers.EthernetTypePPPoESession:
			tun.Set(&d)
			return o.ppp(&ps)
		case layers.EthernetTypeIPv4:
			ps.L3 = offset
			if packetSize < uint32(offset+20) {
				o.stats.errIPv4TooShort++
				return PARSER_ERR
			}
			ipv4 := layers.IPv4Header(p[offset : offset+20])
			if ipv4.Version() != 4 {
				o.stats.errIPv4HeaderTooShort++
				return PARSER_ERR
			}
			hdr := ipv4.GetHeaderLen()
			if hdr < 20 {
				o.stats.errIPv4HeaderTooShort++
				return PARSER_ERR
			}
			if packetSize < uint32(offset+hdr) {
				o.stats.errIPv4HeaderTooShort++
				return PARSER_ERR
			}
			if packetSize < uint32(offset+ipv4.GetLength()) {
				o.stats.errIPv4TooShort++
				return PARSER_ERR
			}
			if hdr != 20 {
				ipv4 = layers.IPv4Header(p[offset : offset+hdr])
			}

			if !ipv4.IsValidHeaderChecksum() {
				o.stats.errIPv4cs++
				return PARSER_ERR
			}
			if ipv4.IsFragment() {
				// Only handles fragmented IP packet containing UDP
				if ipv4.GetNextProtocol() != uint8(layers.IPProtocolUDP) {
					o.stats.errIPv4Fragment++
					return PARSER_ERR
				}

				packet := gopacket.NewPacket(m.GetData(), layers.LayerTypeEthernet, gopacket.NoCopy)
				ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
				if ipv4Layer == nil {
					return PARSER_ERR
				}
				in := ipv4Layer.(*layers.IPv4)
				out, err := o.Defrag.DefragIPv4(in)
				if err != nil {
					return PARSER_ERR
				}
				if out == nil {
					// Packet is fragmented, wait for next fragment
					return PARSER_OK
				}

				// Decode defragmented packet
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					return PARSER_ERR
				}
				nextDecoder := out.NextLayerType()
				err = nextDecoder.Decode(out.Payload, pb)
				if err != nil {
					return PARSER_ERR
				}
				// TODO: Call DiscardOlderThan

				// Encode defragmented packet to buffer
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
				err = gopacket.SerializePacket(buf, opts, packet)

				// Allocated a new Mbuf for the defragmented packet
				m = o.tctx.MPool.Alloc(offset + hdr + uint16(len(buf.Bytes())))
				defer m.FreeMbuf()
				m.Append(p[0 : offset+hdr]) // Append ethernet and ipv4 header
				m.Append(buf.Bytes())       // Append defragmented payload

				p = m.GetData()
				ipv4 = layers.IPv4Header(p[offset : offset+hdr])
				ipv4.SetLength(hdr + uint16(len(buf.Bytes()))) // Set correct payload length
				ps.M = m
			}
			l4len := ipv4.GetLength() - ipv4.GetHeaderLen()
			ps.L4 = offset + hdr
			offset = ps.L4
			tun.Set(&d)

			return o.parsePacketL4(&ps, ipv4.GetNextProtocol(), ipv4.GetPhCs(), l4len, uint16(nextHdr))
		case layers.EthernetTypeIPv6:
			ps.L3 = offset
			if packetSize < uint32(offset+IPV6_HEADER_SIZE) {
				o.stats.errIPv6TooShort++
				return PARSER_ERR
			}
			ipv6 := layers.IPv6Header(p[offset : offset+IPV6_HEADER_SIZE])
			if ipv6.Version() != 6 {
				o.stats.errIPv6TooShort++
				return PARSER_ERR
			}
			if packetSize < uint32(offset+IPV6_HEADER_SIZE+ipv6.PayloadLength()) {
				o.stats.errIPv6TooShort++
				return PARSER_ERR
			}
			if ipv6.HopLimit() == 0 {
				o.stats.errIPv6HopLimitDrop++
				return PARSER_ERR
			}

			l4 := ps.L3 + IPV6_HEADER_SIZE
			l4len := ipv6.PayloadLength()
			tun.Set(&d)

			nh := ipv6.NextHeader()
			var osize uint16
			doloop := true
			for doloop {
				switch nh {
				case IPV6_EXT_HOP_BY_HOP:
					if l4len < 8 {
						o.stats.errIPv6TooShort++
						return PARSER_ERR
					}
					ipv6ex := layers.IPv6ExtHeader(p[l4 : l4+2])
					hl := ipv6ex.HeaderLen()
					if l4len < hl {
						o.stats.errIPv6TooShort++
						return PARSER_ERR
					}
					nh = ipv6ex.NextHeader()
					processIpv6Options(p[l4+2:l4+hl], &ps.Flags)

					l4len -= hl
					osize += hl
					l4 += hl

				case IPV6_EXT_DST,
					IPV6_EXT_ROUTING,
					IPV6_EXT_AH,
					IPV6_EXT_ESP,
					IPV6_EXT_MOBILE,
					IPV6_EXT_HOST,
					IPV6_EXT_SHIM:
					if l4len < 8 {
						o.stats.errIPv6TooShort++
						return PARSER_ERR
					}
					ipv6ex := layers.IPv6ExtHeader(p[l4 : l4+2])
					hl := ipv6ex.HeaderLen()
					if l4len < hl {
						o.stats.errIPv6TooShort++
						return PARSER_ERR
					}
					nh = ipv6ex.NextHeader()
					processIpv6Options(p[l4+2:l4+hl], &ps.Flags)

					l4len -= hl
					osize += hl
					l4 += hl
				case IPV6_EXT_Fragment:
					o.stats.errIPv6Fragment++
					return PARSER_ERR

				case IPV6_EXT_JUMBO:
					// not supported
					o.stats.errIPv6OptJumbo++
					return PARSER_ERR

				case IPV6_EXT_END:
					o.stats.errIPv6Empty++
					return PARSER_ERR
				default:
					doloop = false
					break
				}
			}
			ps.L4 = l4
			return o.parsePacketL4(&ps, nh, ipv6.GetPhCs(osize, nh), l4len, uint16(nextHdr))
		default:
			o.stats.errL3ProtoUnsupported++
			return PARSER_ERR
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
