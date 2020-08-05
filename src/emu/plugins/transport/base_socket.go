// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"external/google/gopacket/layers"
	"net"
	"strconv"
)

func (o *baseSocket) init(client *core.CClient, ctx *TransportCtx) {
	o.client = client
	o.ns = client.Ns
	o.tctx = o.ns.ThreadCtx
	o.ctx = ctx
}

func (o *baseSocket) setIoctlBase(m IoctlMap) error {

	// TOS
	val, prs := m[IP_IOCTL_TOS]
	if prs {
		tos, ok := val.(int)
		if ok {
			if o.ipv6 {
				ipv6 := layers.IPv6Header(o.pktTemplate[o.l3Offset : o.l3Offset+core.IPV6_HEADER_SIZE])
				ipv6.SetTOS(uint8(tos))
			} else {
				ipv4 := layers.IPv4Header(o.pktTemplate[o.l3Offset : o.l3Offset+20])
				ipv4.SetTOS(uint8(tos))
				ipv4.UpdateChecksum()
			}
		}
	}

	// TTL
	val, prs = m[IP_IOCTL_TTL]
	if prs {
		ttl, ok := val.(int)
		if ok {
			if o.ipv6 {
				ipv6 := layers.IPv6Header(o.pktTemplate[o.l3Offset : o.l3Offset+core.IPV6_HEADER_SIZE])
				ipv6.SetHopLimit(uint8(ttl))
			} else {
				ipv4 := layers.IPv4Header(o.pktTemplate[o.l3Offset : o.l3Offset+20])
				ipv4.SetTTL(uint8(ttl))
				ipv4.UpdateChecksum()
			}
		}
	}

	return nil
}

func (o *baseSocket) getIoctlBase(m IoctlMap) error {
	// TOS/TTL
	if o.ipv6 {
		ipv6 := layers.IPv6Header(o.pktTemplate[o.l3Offset : o.l3Offset+core.IPV6_HEADER_SIZE])
		m[IP_IOCTL_TOS] = int(ipv6.TOS())
		m[IP_IOCTL_TTL] = int(ipv6.HopLimit())
	} else {
		ipv4 := layers.IPv4Header(o.pktTemplate[o.l3Offset : o.l3Offset+20])
		m[IP_IOCTL_TOS] = int(ipv4.GetTOS())
		m[IP_IOCTL_TTL] = int(ipv4.GetTTL())
	}
	return nil
}

func (o *baseSocket) setPortAlloc(enable bool) {
	o.srcPortAlloc = enable
}

func (o *baseSocket) setTupleIpv4(src core.Ipv4Key,
	dst core.Ipv4Key,
	srcPort uint16,
	dstPort uint16) {
	o.src = src
	o.dst = dst
	o.srcPort = srcPort
	o.dstPort = dstPort
	o.ipv6 = false
}

func (o *baseSocket) setTupleIpv6(src core.Ipv6Key,
	dst core.Ipv6Key,
	srcPort uint16,
	dstPort uint16) {
	o.srcIPv6 = src
	o.dstIPv6 = dst
	o.srcPort = srcPort
	o.dstPort = dstPort
	o.ipv6 = true
}

func (o *baseSocket) buildIpv4Template(udp bool) {
	l2 := o.client.GetL2Header(false, uint16(layers.EthernetTypeIPv4))
	o.l3Offset = uint16(len(l2)) /* IPv4*/

	ipv4h := &layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc,
		SrcIP:    net.IPv4(o.src[0], o.src[1], o.src[2], o.src[3]),
		DstIP:    net.IPv4(o.dst[0], o.dst[1], o.dst[2], o.dst[3]),
		Protocol: o.getNextHeader(udp)}

	var dr []byte
	if udp {
		dr = core.PacketUtlBuild(
			ipv4h,
			&layers.UDP{SrcPort: layers.UDPPort(o.srcPort), DstPort: layers.UDPPort(o.dstPort)},
		)
	} else {
		dr = core.PacketUtlBuild(
			ipv4h,
			&layers.TCP{DataOffset: 5, SrcPort: layers.TCPPort(o.srcPort), DstPort: layers.TCPPort(o.dstPort)},
		)
	}

	o.l4Offset = o.l3Offset + 20

	o.pktTemplate = append(l2, dr...)
}

func (o *baseSocket) getNextHeader(udp bool) layers.IPProtocol {
	if udp {
		return layers.IPProtocolUDP
	} else {
		return layers.IPProtocolTCP
	}
}

func (o *baseSocket) buildIpv6Template(udp bool) {
	l2 := o.client.GetL2Header(false, uint16(layers.EthernetTypeIPv6))
	o.l3Offset = uint16(len(l2)) /* IPv6*/

	ipv6h := &layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       8,
		NextHeader:   o.getNextHeader(udp),
		HopLimit:     1,
		SrcIP:        o.srcIPv6[:],
		DstIP:        o.dstIPv6[:]}

	var dr []byte
	if udp {
		dr = core.PacketUtlBuild(
			ipv6h,
			&layers.UDP{SrcPort: layers.UDPPort(o.srcPort), DstPort: layers.UDPPort(o.dstPort)},
		)
	} else {
		dr = core.PacketUtlBuild(
			ipv6h,
			&layers.TCP{DataOffset: 5, SrcPort: layers.TCPPort(o.srcPort), DstPort: layers.TCPPort(o.dstPort)},
		)
	}

	o.l4Offset = o.l3Offset + 40

	o.pktTemplate = append(l2, dr...)
}

func (o *baseSocket) initphase2(udp bool) {
	if o.ipv6 {
		o.buildIpv6Template(udp)
	} else {
		o.buildIpv4Template(udp)
	}
}

type baseSocketLocalAddr struct {
	net string
	s   *baseSocket
}

func (o *baseSocketLocalAddr) Network() string {
	return o.net
}

func (o *baseSocketLocalAddr) String() string {
	if o.s.ipv6 {
		return "[" + o.s.srcIPv6.ToIP().String() + "]:" + strconv.Itoa(int(o.s.srcPort))
	} else {
		return o.s.src.ToIP().String() + ":" + strconv.Itoa(int(o.s.srcPort))
	}
}

type baseSocketRemoteAddr struct {
	net string
	s   *baseSocket
}

func (o *baseSocketRemoteAddr) Network() string {
	return o.net
}

func (o *baseSocketRemoteAddr) String() string {
	if o.s.ipv6 {
		return "[" + o.s.dstIPv6.ToIP().String() + "]:" + strconv.Itoa(int(o.s.dstPort))
	} else {
		return o.s.dst.ToIP().String() + ":" + strconv.Itoa(int(o.s.dstPort))
	}
}

func (o *baseSocket) removeFlowAssociation(udp bool, flow interface{}) {
	nh := uint8(o.getNextHeader(udp))
	if o.ipv6 {
		var tuple c5tuplekeyv6
		buildTuplev6(o.dstIPv6,
			o.srcIPv6,
			o.dstPort,
			o.srcPort,
			nh, &tuple)
		o.ctx.removeFlowv6(&tuple, flow)

	} else {
		var tuple c5tuplekeyv4
		buildTuplev4(o.dst,
			o.src,
			o.dstPort,
			o.srcPort,
			nh, &tuple)
		o.ctx.removeFlowv4(&tuple, flow)
	}
}
