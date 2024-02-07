// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"net"
)

type udpPkt struct {
	m       *core.Mbuf
	datalen uint16
	udph    layers.UDPHeader
}

type UdpSocket struct {
	baseSocket
	isClosed bool
}

func (o *UdpSocket) init(client *core.CClient, ctx *TransportCtx) {
	o.baseSocket.init(client, ctx)
}

func (o *UdpSocket) SetIoctl(m IoctlMap) error {
	return o.baseSocket.setIoctlBase(m)
}

func (o *UdpSocket) GetIoctl(m IoctlMap) error {
	return o.baseSocket.getIoctlBase(m)
}

func (o *UdpSocket) connect() SocketErr {
	return SeOK
}

func (o *UdpSocket) initphase2(cb ISocketCb, dstMac *core.MACKey) {
	o.cb = cb
	o.baseSocket.initphase2(true, dstMac)
}

func (o *UdpSocket) LocalAddr() net.Addr {
	var l baseSocketLocalAddr
	l.net = "udp"
	l.s = &o.baseSocket
	return &l
}

func (o *UdpSocket) RemoteAddr() net.Addr {
	var l baseSocketRemoteAddr
	l.net = "udp"
	l.s = &o.baseSocket
	return &l
}

func (o *UdpSocket) GetCap() SocketCapType {
	return 0
}

func (o *UdpSocket) listen() SocketErr {
	return SeOK
}

// GetL7MTU returns the L7 MTU that is available for this socket.
func (o *UdpSocket) GetL7MTU() uint16 {
	var ipMTU uint16
	ipHeaderLen := o.l4Offset - o.l3Offset
	if o.ipv6 {
		// IPv6 client
		ipMTU = o.client.GetIPv6MTU()
	} else {
		// IPv4 client
		ipMTU = o.client.MTU

	}
	if ipMTU < (ipHeaderLen + UDP_HEADER_LEN) {
		// make sure we never overflow
		return 0
	}
	return ipMTU - (ipHeaderLen + UDP_HEADER_LEN)

}

func (o *UdpSocket) GetSocket() interface{} {
	return o
}

func (o *UdpSocket) Write(buf []byte) (res SocketErr, queued bool) {
	if o.isClosed {
		return SeCONNECTION_IS_CLOSED, false
	}
	if o.resolve() == false {
		return SeUNRESOLVED, false
	}
	var pkt udpPkt

	mtu := o.GetL7MTU()
	if uint16(len(buf)) > mtu {
		if o.ipv6 {
			o.ctx.udpStats.udp_drop_msg_bigger_mtu++
			return SeENOBUFS, false
		}
		// Send large data in multiple IPv4 packets, fragmented

		// The payload size in a fragment need to be a multiple of 8
		maxPayloadSize := uint16(mtu/8) * 8
		payload := buf[:maxPayloadSize]
		payloadSize := uint16(len(payload))
		pkt.datalen = uint16(len(buf))

		// Send first fragment containing UDP header
		o.buildDpktFirstFragment(&pkt, payload)
		o.ctx.udpStats.udp_sndpack++
		o.ctx.udpStats.udp_sndbyte += uint64(payloadSize)
		o.tctx.Veth.Send(pkt.m)
		dataSent := payloadSize

		// Send trailing segments
		for {
			if dataSent+maxPayloadSize > pkt.datalen {
				payload = buf[dataSent:]
			} else {
				payload = buf[dataSent : dataSent+maxPayloadSize]
			}
			payloadSize = uint16(len(payload))

			o.buildDpktTrailingFragment(&pkt, payload, dataSent+UDP_HEADER_LEN)
			o.ctx.udpStats.udp_sndpack++
			o.ctx.udpStats.udp_sndbyte += uint64(payloadSize)
			o.tctx.Veth.Send(pkt.m)

			dataSent += payloadSize
			if dataSent >= pkt.datalen {
				break // All data is sent
			}
		}

		return SeOK, true
	}

	o.buildDpkt(&pkt, buf)
	o.ctx.udpStats.udp_sndpack++
	o.ctx.udpStats.udp_sndbyte += uint64(len(buf))
	o.send(&pkt)
	return SeOK, true
}

func (o *UdpSocket) Close() SocketErr {
	if o.isClosed {
		return SeCONNECTION_IS_CLOSED
	}

	if o.srcPortAlloc {
		o.ctx.srcPorts.freePort(UDP_PROTO, o.srcPort)
	}
	o.removeFlowAssociation(true, o)

	o.isClosed = true
	return (SeOK)

}

func (o *UdpSocket) Shutdown() SocketErr {
	return o.Close()
}

// nothing to do, there is no timer
func (o *UdpSocket) onRemove() {
}

func (o *UdpSocket) send(pkt *udpPkt) int {
	// fix checksum
	m := pkt.m
	p := m.GetData()
	if o.ipv6 == false {
		l3 := o.l3Offset
		l4 := o.l4Offset
		ipv4 := layers.IPv4Header(p[l3 : l3+20])
		/* update checksum */
		binary.BigEndian.PutUint16(p[l4+6:l4+8], 0)
		cs := layers.PktChecksumTcpUdp(p[l4:], 0, ipv4)
		binary.BigEndian.PutUint16(p[l4+6:l4+8], cs)
	} else {
		l4 := o.l4Offset
		l3 := o.l3Offset
		ipv6 := layers.IPv6Header(p[l3 : l3+40])
		ipv6.FixUdpL4Checksum(p[l4:], 0)
	}

	o.tctx.Veth.Send(m)
	return 0
}

func (o *UdpSocket) buildDpktFirstFragment(pkt *udpPkt, data []byte) int {
	tl := uint16(len(o.pktTemplate))
	dl := uint16(len(data))
	m := o.ns.AllocMbuf(tl + dl)
	m.Append(o.pktTemplate) // template with IP and UDP header
	m.Append(data)
	pkt.m = m

	p := m.GetData()
	l3 := o.l3Offset

	// Update fragment flags
	f := (uint16(layers.IPv4MoreFragments) << 13)
	binary.BigEndian.PutUint16(p[l3+6:l3+8], f)

	// Update UDP header length
	binary.BigEndian.PutUint16(p[l3+24:l3+26], pkt.datalen+UDP_HEADER_LEN)

	// Update IPv4 header
	ipv4 := layers.IPv4Header(p[l3 : l3+20])
	ipv4.SetLength(20 + uint16(len(data)) + UDP_HEADER_LEN)
	ipv4.UpdateChecksum()

	return 0
}

func (o *UdpSocket) buildDpktTrailingFragment(pkt *udpPkt, data []byte, dataSent uint16) int {
	tl := uint16(len(o.pktTemplate)) - UDP_HEADER_LEN
	dl := uint16(len(data))
	m := o.ns.AllocMbuf(tl + dl)
	m.Append(o.pktTemplate[:tl]) // template without UDP header
	m.Append(data)
	pkt.m = m

	p := m.GetData()
	l3 := o.l3Offset
	payload_size := uint16(len(data))

	// Update fragment offset and flag if more fragments are required
	f := dataSent / 8
	if dataSent+payload_size < pkt.datalen {
		f += (uint16(layers.IPv4MoreFragments) << 13)
	}
	binary.BigEndian.PutUint16(p[l3+6:l3+8], f)

	// Update IPv4 header
	ipv4 := layers.IPv4Header(p[l3 : l3+20])
	ipv4.SetLength(20 + payload_size)
	ipv4.UpdateChecksum()

	return 0
}

func (o *UdpSocket) buildDpkt(pkt *udpPkt, data []byte) int {
	dl := uint16(len(data))
	m := o.ns.AllocMbuf(uint16(len(o.pktTemplate)) + dl)
	m.Append(o.pktTemplate) // template
	m.Append(data)
	p := m.GetData()
	l4 := o.l4Offset
	pkt.m = m
	pkt.udph = layers.UDPHeader(p[l4 : l4+UDP_HEADER_LEN])
	pkt.datalen = dl
	o.updatePktLen(pkt)
	return 0
}

func (o *UdpSocket) updatePktLen(pkt *udpPkt) {
	m := pkt.m
	p := m.GetData()
	if o.ipv6 == false { //ipv4
		l3 := o.l3Offset
		ipv4 := layers.IPv4Header(p[l3 : l3+20])
		ipv4.SetLength(20 + UDP_HEADER_LEN + pkt.datalen)
		binary.BigEndian.PutUint16(p[l3+24:l3+26], uint16(pkt.datalen+8))
		ipv4.UpdateChecksum()
	} else {
		l3 := o.l3Offset
		ipv6 := layers.IPv6Header(p[l3 : l3+40])
		ipv6.SetPyloadLength(UDP_HEADER_LEN + pkt.datalen)
		binary.BigEndian.PutUint16(p[l3+44:l3+46], uint16(pkt.datalen+8))
	}
}

func (o *UdpSocket) resolve() bool {
	if o.resolved {
		return true
	}
	if o.multicast {
		o.resolved = true
		return true
	}

	if o.ipv6 == false {
		mac, ok := o.client.ResolveIPv4DGMac()
		if ok {
			layers.EthernetHeader(o.pktTemplate).SetDestAddress(mac[:])
			o.resolved = true
			return true
		} else {
			o.ctx.udpStats.udp_drop_unresolved++
		}
	} else {
		mac, ok := o.client.ResolveIPv6DGMac()
		if ok {
			layers.EthernetHeader(o.pktTemplate).SetDestAddress(mac[:])
			o.resolved = true
			return true
		} else {
			o.ctx.udpStats.udp_drop_unresolved++
		}
	}
	return false
}

func (o *UdpSocket) GetLastError() SocketErr {
	return (SeOK)
}

func (o *UdpSocket) input(ps *core.ParserPacketState) int {
	// nothing to do
	if ps.L7Len > 0 {
		m := ps.M
		p := m.GetData()
		o.ctx.udpStats.udp_rcvpkt++
		o.ctx.udpStats.udp_rcvbyte += uint64(len(p[ps.L7:]))
		if o.cb != nil {
			o.cb.OnRxData(p[ps.L7:])
		}
	}
	return (0)
}

func (o *UdpSocket) getProto() uint8 {
	return UDP_PROTO
}

func (o *UdpSocket) getServerIoctl() IoctlMap {
	return o.serverIoctl
}

func (o *UdpSocket) clearServerIoctl() {
	o.serverIoctl = nil
}
