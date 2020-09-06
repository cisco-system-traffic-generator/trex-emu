// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package ipv6

/* ipv6 support

RFC 4443: Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6)
RFC 4861: Neighbor Discovery for IP Version 6 (IPv6)
RFC 4862: IPv6 Stateless Address Autoconfiguration.

not implemented:

RFC4941: random local ipv6 using md5

*/

import (
	"emu/core"
	"emu/plugins/ping"
	"encoding/binary"
	"errors"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"net"

	"github.com/intel-go/fastjson"
)

const (
	IPV6_PLUG = "ipv6"
)

type pingNsStats struct {
	pktRxIcmpQuery          uint64
	pktTxIcmpResponse       uint64
	pktTxIcmpQuery          uint64
	pktRxIcmpResponse       uint64
	pktRxErrTooShort        uint64
	pktRxErrUnhandled       uint64
	pktRxErrMulticastB      uint64
	pktRxNoClientUnhandled  uint64
	pktRxIcmpDstUnreachable uint64
}

func NewpingNsStatsDb(o *pingNsStats) *core.CCounterDb {
	db := core.NewCCounterDb("pingv6")
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxIcmpQuery,
		Name:     "pktRxIcmpQuery",
		Help:     "rx query",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxIcmpResponse,
		Name:     "pktTxIcmpResponse",
		Help:     "tx response",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxIcmpQuery,
		Name:     "pktTxIcmpQuery",
		Help:     "tx query",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxIcmpResponse,
		Name:     "pktRxIcmpResponse",
		Help:     "rx response",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrTooShort,
		Name:     "pktRxErrTooShort",
		Help:     "rx too short",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrUnhandled,
		Name:     "pktRxErrUnhandled",
		Help:     "rx wrong opcode",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNoClientUnhandled,
		Name:     "pktRxNoClientUnhandled",
		Help:     "rx no client ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrMulticastB,
		Name:     "pktRxErrMulticastB",
		Help:     "src ip is not valid ",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxIcmpDstUnreachable,
		Name:     "pktRxIcmpDstUnreachable",
		Help:     "rx destination unreachable",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

// PluginIpv6Client icmp information per client
type PluginIpv6Client struct {
	core.PluginBase
	ipv6NsPlug *PluginIpv6Ns
	nd         NdClientCtx
	pingData   *ApiIpv6StartPingHandler
	ping       *ping.Ping
}

var icmpEvents = []string{core.MSG_UPDATE_IPV6_ADDR,
	core.MSG_UPDATE_DGIPV6_ADDR,
	core.MSG_UPDATE_DIPV6_ADDR}

/*NewIpv6Client create plugin */
func NewIpv6Client(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIpv6Client)
	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, icmpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(IPV6_PLUG)
	o.ipv6NsPlug = nsplg.Ext.(*PluginIpv6Ns)
	o.nd.Init(o, &o.ipv6NsPlug.nd, o.Tctx, &o.ipv6NsPlug.mld, initJson)
	o.OnCreate()
	return &o.PluginBase
}

/*OnEvent support event change of IP  */
func (o *PluginIpv6Client) OnEvent(msg string, a, b interface{}) {
	o.nd.OnEvent(msg, a, b)
}

func (o *PluginIpv6Client) OnRemove(ctx *core.PluginCtx) {
	o.StopPing()
	/* force removing the link to the client */
	o.nd.OnRemove(ctx)
	ctx.UnregisterEvents(&o.PluginBase, icmpEvents)
}

func (o *PluginIpv6Client) OnCreate() {
}

//StartPing creates a ping object in case there isn't any.
func (o *PluginIpv6Client) StartPing(data *ApiIpv6StartPingHandler) bool {
	if o.ping != nil {
		return false
	}
	o.pingData = data
	params := ping.PingParams{Amount: data.Amount, Pace: data.Pace, Timeout: data.Timeout}
	o.ping = ping.NewPing(params, o.Ns, o)
	o.ping.StartPinging()
	return true
}

func (o *PluginIpv6Client) StopPing() bool {
	if o.ping == nil {
		return false
	}
	o.ping.OnRemove()
	return true
}

func (o *PluginIpv6Client) GetPingCounters(params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	if o.ping == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "No available ping at the moment. Expired or not started.",
		}
	}
	return o.ping.GetPingCounters(params)
}

//handleEchoReply passes the packet to handle to Ping in case it is has an active Ping.
func (o *PluginIpv6Client) handleEchoReply(seq, id uint16, payload []byte) bool {
	stats := o.ipv6NsPlug.stats
	if len(payload) < 16 {
		stats.pktRxErrTooShort++
		return false
	}
	if o.ping != nil {
		o.ping.HandleEchoReply(seq, id, payload)
		return true
	} else {
		stats.pktRxErrUnhandled++
		return false
	}
}

//handleDestinationUnreachable passes the packet to handle to Ping in case it is has an active Ping.
func (o *PluginIpv6Client) handleDestinationUnreachable(id uint16) bool {
	if o.ping != nil {
		o.ping.HandleDestinationUnreachable(id)
		return true
	}
	o.ipv6NsPlug.stats.pktRxErrUnhandled++
	return false
}

// PreparePacketTemplate implements ping.PingClientIF.PreparePacketTemplate by creating an ICMPv6 packet with the id and seq received.
// It must put the magic as the first 8 bytes of the payload.
// It returns the offset of the icmpHeader in the packet and the packet.
func (o *PluginIpv6Client) PreparePingPacketTemplate(id, seq uint16, magic uint64) (icmpHeaderOffset int, pkt []byte) {
	srcIPv6 := o.pingData.Src
	dstIPv6 := o.pingData.Dst
	pkt = o.Client.GetL2Header(false, uint16(layers.EthernetTypeIPv6))
	if !o.Client.IsDGIpv6(dstIPv6) {
		dstMac, ok := o.Client.ResolveIPv6DGMac()
		if ok {
			layers.EthernetHeader(pkt).SetDestAddress(dstMac[:])
		}
	} else {
		dgIpv6, dgMac, ok := o.Client.ResolveDGv6()
		if ok {
			dstIPv6 = dgIpv6
			layers.EthernetHeader(pkt).SetDestAddress(dgMac[:])
		}
	}
	ipHeaderOffset := len(pkt)
	ipHeader := core.PacketUtlBuild(
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       0,
			NextHeader:   layers.IPProtocolICMPv6,
			HopLimit:     ping.DefaultPingTTL,
			SrcIP: net.IP{srcIPv6[0], srcIPv6[1], srcIPv6[2], srcIPv6[3], srcIPv6[4], srcIPv6[5], srcIPv6[6], srcIPv6[7],
				srcIPv6[8], srcIPv6[9], srcIPv6[10], srcIPv6[11], srcIPv6[12], srcIPv6[13], srcIPv6[14], srcIPv6[15]},
			DstIP: net.IP{dstIPv6[0], dstIPv6[1], dstIPv6[2], dstIPv6[3], dstIPv6[4], dstIPv6[5], dstIPv6[6], dstIPv6[7],
				dstIPv6[8], dstIPv6[9], dstIPv6[10], dstIPv6[11], dstIPv6[12], dstIPv6[13], dstIPv6[14], dstIPv6[15]},
		})
	pkt = append(pkt, ipHeader...)
	icmpHeaderOffset = len(pkt)
	icmpHeader := core.PacketUtlBuild(
		&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)})
	icmpEcho := core.PacketUtlBuild(
		&layers.ICMPv6Echo{Identifier: id, SeqNumber: seq})
	icmpHeader = append(icmpHeader, icmpEcho...)
	payload := make([]byte, int(o.pingData.PayloadSize))
	// Put a magic in our packets to verify that they contain valid timestamps.
	binary.BigEndian.PutUint64(payload, magic)
	icmpHeader = append(icmpHeader, payload...)
	pkt = append(pkt, icmpHeader...)
	ipv6Header := layers.IPv6Header(pkt[ipHeaderOffset : ipHeaderOffset+40])
	ipv6Header.SetPyloadLength(uint16(len(pkt) - icmpHeaderOffset))
	ipv6Header.FixIcmpL4Checksum(pkt[icmpHeaderOffset:], 0)
	return icmpHeaderOffset, pkt
}

// UpdateTxIcmpQuery implements ping.PingClientIF.UpdateTxIcmpQuery by incrementing the Tx Query every time an echo request is sent.
func (o *PluginIpv6Client) UpdateTxIcmpQuery(pktSent uint64) {
	o.ipv6NsPlug.stats.pktTxIcmpQuery += pktSent

}

// OnPingRemove implements ping.PingClientIF.OnPingRemove by updating the ping
// corresponding fields when a ping is finishing or is stopped..
func (o *PluginIpv6Client) OnPingRemove() {
	o.ping = nil
	o.pingData = nil
}

// PluginIpv6Ns information per namespace
type PluginIpv6Ns struct {
	core.PluginBase
	stats pingNsStats
	cdb   *core.CCounterDb
	cdbv  *core.CCounterDbVec
	mld   mldNsCtx
	nd    NdNsCtx
}

func NewIpv6Ns(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIpv6Ns)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.cdb = NewpingNsStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("ipv6")
	o.mld.Init(o, o.Tctx, initJson)
	o.nd.Init(o, o.Tctx, initJson)

	o.cdbv.Add(o.cdb)
	o.cdbv.Add(o.mld.cdb)
	o.cdbv.Add(o.nd.cdb)
	return &o.PluginBase
}

func (o *PluginIpv6Ns) OnRemove(ctx *core.PluginCtx) {
	o.mld.OnRemove(ctx)
	o.nd.OnRemove(ctx)
}

func (o *PluginIpv6Ns) OnEvent(msg string, a, b interface{}) {
	o.nd.OnEvent(msg, a, b)
}

func (o *PluginIpv6Ns) SetTruncated() {

}

func (o *PluginIpv6Ns) HandleEcho(ps *core.ParserPacketState, ts bool) {
	mc := ps.M.DeepClone()
	p := mc.GetData()

	eth := layers.EthernetHeader(p[0:12])
	eth.SwapSrcDst()
	if eth.IsBroadcast() || eth.IsMcast() {
		o.stats.pktRxErrMulticastB++
		mc.FreeMbuf()
		return
	}

	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+40])
	ipv6.SwapSrcDst()
	p[ps.L4] = layers.ICMPv6TypeEchoReply

	if ipv6.NextHeader() != uint8(layers.IPProtocolICMPv6) {
		if ps.L4-ps.L3 > 40 {
			optionbytes := ps.L4 - ps.L3 - 40
			ipv6.SetNextHeader(uint8(layers.IPProtocolICMPv6))
			pyldbytes := ipv6.PayloadLength() - optionbytes
			ipv6.SetPyloadLength(pyldbytes)
			copy(p[ps.L3+40:], p[ps.L4:])
			mc.Trim(optionbytes)
			ps.L4 = ps.L3 + 40
		} else {
			o.stats.pktRxErrTooShort++
			mc.FreeMbuf()
			return
		}
	}

	// update checksum
	newCs := layers.UpdateInetChecksum(
		binary.BigEndian.Uint16(p[ps.L4+2:ps.L4+4]),
		uint16(layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)),
		uint16(layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)))
	binary.BigEndian.PutUint16(p[ps.L4+2:ps.L4+4], newCs)

	o.stats.pktRxIcmpQuery++
	o.stats.pktTxIcmpResponse++
	o.Tctx.Veth.Send(mc)
}

//HandleEchoReply handles an ICMP Echo-Reply that is received in the ICMP namespace.
func (o *PluginIpv6Ns) HandleEchoReply(ps *core.ParserPacketState) int {
	p := ps.M.GetData()
	eth := layers.EthernetHeader(p[0:12])

	var dstMac core.MACKey
	copy(dstMac[:], eth.GetDestAddress()[:6])

	/*
					An incoming Echo Reply should look like this:
					0 1 2 3 4 5 6 7
					+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		ICMPv6->	|     Type      |     Code      |          Checksum             |
					+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		ICMPv6Echo->|           Identifier          |        Sequence Number        |
					+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					|                             Magic                             |
					+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					|                             Magic                             |
					+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					|                           Timestamp                           |
					+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					|                           Timestamp                           |
					+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					|   Data ...
					+-+-+-+-+

			As such the minimal size of L4 should be 24 bytes.

	*/
	if len(p[ps.L4:]) < 24 {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	var icmpv6Echo layers.ICMPv6Echo
	icmpv6Echo.DecodeFromBytes(p[ps.L4+4:], o) // No need to check for error as it is done previously.

	if c, err := o.GetIcmpClientByMac(dstMac); err != nil {
		o.stats.pktRxNoClientUnhandled++
		return core.PARSER_OK
	} else {
		if c.handleEchoReply(icmpv6Echo.SeqNumber, icmpv6Echo.Identifier, icmpv6Echo.Payload) {
			o.stats.pktRxIcmpResponse++
		}
		return core.PARSER_OK
	}
}

//HandleDestinationUnreachable handles an ICMP Destination Unreachable that is received in the ICMP namespace.
func (o *PluginIpv6Ns) HandleDestinationUnreachable(ps *core.ParserPacketState) int {
	p := ps.M.GetData()
	eth := layers.EthernetHeader(p[0:12])

	var dstMac core.MACKey
	copy(dstMac[:], eth.GetDestAddress()[:6])

	/*
						An incoming Destination Unreachable message should look like this:
						0 1 2 3 4 5 6 7
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		DstUnreachable	|     Type      |     Code      |          Checksum             |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						|                             Unused                            |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		IPv6			|                             IPv6 x5                           |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		ICMPv6			|     Type      |     Code      |          Checksum             |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		ICMPv6Echo->	|           Identifier          |        Sequence Number        |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						|                             Magic                             |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						|                             Magic                             |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						|                           Timestamp                           |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						|                           Timestamp                           |
						+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
						|   Data ...
						+-+-+-+-+

		Hence , after 52 bytes of Dst Unreachable we will see an ICMP Header nested,
		which should be an Echo Request with minimal length 24 as explained in
		HandleEchoReply
	*/
	if len(p[ps.L4:]) < 72 {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	var icmpv6Echo layers.ICMPv6Echo
	icmpv6Echo.DecodeFromBytes(p[ps.L4+52:], o)

	if icmpClient, err := o.GetIcmpClientByMac(dstMac); err != nil {
		o.stats.pktRxNoClientUnhandled++
		return core.PARSER_OK
	} else {
		if icmpClient.handleDestinationUnreachable(icmpv6Echo.Identifier) {
			o.stats.pktRxIcmpDstUnreachable++
		}
		return core.PARSER_OK
	}
}

/* HandleRxIcmpPacket -1 for parser error, 0 valid  */
func (o *PluginIpv6Ns) HandleRxIpv6Packet(ps *core.ParserPacketState) int {

	m := ps.M

	p := m.GetData()
	var icmpv6 layers.ICMPv6
	err := icmpv6.DecodeFromBytes(p[ps.L4:], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+40])

	switch icmpv6.TypeCode {
	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0):
		var ipv6key core.Ipv6Key

		/* need to look for 2 type of IPvs */
		copy(ipv6key[:], ipv6.DstIP())

		client := o.Ns.CLookupByIPv6LocalGlobal(&ipv6key)
		if client == nil {
			o.stats.pktRxNoClientUnhandled++
			return 0
		}

		tome := client.IsUnicastToMe(p)
		if !tome {
			o.stats.pktRxNoClientUnhandled++
			return 0
		}

		/* multicast */
		if ipv6.SrcIP()[0] == 0xff {
			o.stats.pktRxErrMulticastB++
			return 0
		}

		o.HandleEcho(ps, false)
	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeMLDv1MulticastListenerQueryMessage, 0),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeMLDv1MulticastListenerReportMessage, 0),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeMLDv1MulticastListenerDoneMessage, 0),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeMLDv2MulticastListenerReportMessageV2, 0):
		return o.mld.HandleRxMldPacket(ps) // MLD, MLDv2

	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRedirect, 0):
		return o.nd.HandleRxIpv6NdPacket(ps, icmpv6.TypeCode) // MLD, MLDv2
	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0):
		res := o.HandleEchoReply(ps)
		if res == core.PARSER_ERR {
			return core.PARSER_ERR
		}
	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeNoRouteToDst),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeAdminProhibited),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeBeyondScopeOfSrc),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeAddressUnreachable),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeSrcAddressFailedPolicy),
		layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeRejectRouteToDst):
		res := o.HandleDestinationUnreachable(ps)
		if res == core.PARSER_ERR {
			return core.PARSER_ERR
		}

	default:
		o.stats.pktRxErrUnhandled++
	}

	return 0
}

// HandleRxIcmpPacket Parser call this function with mbuf from the pool
// Either by register functions -- maybe it would be better to register the function
// Rx side
func HandleRxIcmpv6Packet(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(IPV6_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	icmpPlug := nsplg.Ext.(*PluginIpv6Ns)
	return icmpPlug.HandleRxIpv6Packet(ps)
}

//GetIcmpClientByMac is a method of the ICMP Namespace that returns the Icmp Client given its MAC address.
func (o *PluginIpv6Ns) GetIcmpClientByMac(mackey core.MACKey) (*PluginIpv6Client, error) {

	client := o.Ns.CLookupByMac(&mackey)

	if client == nil {
		return nil, errors.New("No Client Found with given MAC.")
	}

	cplg := client.PluginCtx.Get(IPV6_PLUG)
	if cplg == nil {
		return nil, errors.New("Plugin not registered in context.")
	}
	ipv6CPlug := cplg.Ext.(*PluginIpv6Client)
	return ipv6CPlug, nil
}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginIpv6CReg struct{}
type PluginIpv6NsReg struct{}

func (o PluginIpv6CReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewIpv6Client(ctx, initJson)
}

func (o PluginIpv6NsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewIpv6Ns(ctx, initJson)
}

/*******************************************/
/* ICMP RPC commands */
type (
	ApiIpv6NsCntHandler struct{}

	// add (g,s)
	ApiMldNsAddSGHandler struct{}
	ApiMldNsAddSGParams  struct {
		Vec []*MldSGRecord `json:"vec"`
	}

	// remove(g,s)
	ApiMldNsRemoveSGHandler struct{}
	ApiMldNsRemoveSGParams  struct {
		Vec []*MldSGRecord `json:"vec"`
	}

	ApiMldNsAddHandler struct{}
	ApiMldNsAddParams  struct {
		Vec []core.Ipv6Key `json:"vec"`
	}

	ApiMldNsRemoveHandler struct{}
	ApiMldNsRemoveParams  struct {
		Vec []core.Ipv6Key `json:"vec"`
	}

	ApiMldNsIterHandler struct{}
	ApiMldNsIterParams  struct {
		Reset bool   `json:"reset"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	}
	ApiMldNsIterResult struct {
		Empty   bool               `json:"empty"`
		Stopped bool               `json:"stopped"`
		Vec     []MldEntryDataJson `json:"data"`
	}

	ApiMldSetHandler struct{}
	ApiMldSetParams  struct {
		Mtu           uint16      `json:"mtu" validate:"required,gte=256,lte=9000"`
		DesignatorMac core.MACKey `json:"dmac"`
	}

	ApiMldGetHandler struct{}

	ApiMldGetResult struct {
		Mtu           uint16      `json:"mtu"`
		DesignatorMac core.MACKey `json:"dmac"`
		Version       uint8       `json:"version"`
	}

	ApiNdNsIterHandler struct{} // iterate on the nd ipv6 cache table
	ApiNdNsIterParams  struct {
		Reset bool   `json:"reset"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	}
	ApiNdNsIterResult struct {
		Empty   bool             `json:"empty"`
		Stopped bool             `json:"stopped"`
		Vec     []Ipv6NsCacheRec `json:"data"`
	}

	ApiIpv6StartPingHandler struct {
		Amount      uint32       `json:"amount"  validate:"ne=0"`       // Amount of echo requests to send
		Pace        float32      `json:"pace"    validate:"ne=0"`       // Pace of sending the Echo-Requests in packets per second.
		Dst         core.Ipv6Key `json:"dst"`                           // The destination IPv6
		Src         core.Ipv6Key `json:"src"`                           // The source IPv6
		Timeout     uint8        `json:"timeout" validate:"ne=0"`       // Timeout from last ping until the stats are deleted.
		PayloadSize uint16       `json:"payloadSize" validate:"gte=16"` // Payload size bytes
	}

	ApiIpv6StopPingHandler struct{}

	ApiIpv6GetPingStatsHandler struct{}
)

func getNsPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginIpv6Ns, error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, IPV6_PLUG)

	if err != nil {
		return nil, err
	}

	ipv6Ns := plug.Ext.(*PluginIpv6Ns)

	return ipv6Ns, nil
}

func getClient(ctx interface{}, params *fastjson.RawMessage) (*PluginIpv6Client, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetClientPlugin(params, IPV6_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	icmpClient := plug.Ext.(*PluginIpv6Client)

	return icmpClient, nil
}

func (h ApiIpv6NsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	c, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return c.cdbv.GeneralCounters(err, tctx, params, &p)
}

func (h ApiMldNsAddSGHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiMldNsAddSGParams
	tctx := ctx.(*core.CThreadCtx)

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	err1 = ipv6Ns.mld.addMcSG(p.Vec)

	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	return nil, nil
}

func (h ApiMldNsAddHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiMldNsAddParams
	tctx := ctx.(*core.CThreadCtx)

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	err1 = ipv6Ns.mld.addMc(p.Vec)

	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	return nil, nil
}

func (h ApiMldNsRemoveHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiMldNsRemoveParams
	tctx := ctx.(*core.CThreadCtx)

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	err1 = ipv6Ns.mld.RemoveMc(p.Vec)

	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	return nil, nil
}

func (h ApiMldNsRemoveSGHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiMldNsRemoveSGParams
	tctx := ctx.(*core.CThreadCtx)

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	err1 = ipv6Ns.mld.removeMcSG(p.Vec)

	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	return nil, nil
}

func (h ApiMldNsIterHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiMldNsIterParams
	var res ApiMldNsIterResult

	tctx := ctx.(*core.CThreadCtx)

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	if p.Reset {
		res.Empty = ipv6Ns.mld.IterReset()
	}
	if res.Empty {
		return &res, nil
	}
	if ipv6Ns.mld.IterIsStopped() {
		res.Stopped = true
		return &res, nil
	}

	entries, err2 := ipv6Ns.mld.GetNext(p.Count)
	if err2 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err2.Error(),
		}
	}
	res.Vec = entries
	return &res, nil
}

func (h ApiMldSetHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiMldSetParams

	tctx := ctx.(*core.CThreadCtx)

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	if p.Mtu > 0 {
		ipv6Ns.mld.mtu = p.Mtu
	}

	if !p.DesignatorMac.IsZero() {
		ipv6Ns.mld.designatorMac = p.DesignatorMac
	}
	return nil, nil
}

func (h ApiMldGetHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var res ApiMldGetResult

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	res.Mtu = ipv6Ns.mld.mtu
	res.DesignatorMac = ipv6Ns.mld.designatorMac
	res.Version = uint8(ipv6Ns.mld.mldVersion)

	return &res, nil
}

func (h ApiNdNsIterHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiNdNsIterParams
	var res ApiNdNsIterResult

	tctx := ctx.(*core.CThreadCtx)

	ipv6Ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	if p.Reset {
		res.Empty = ipv6Ns.nd.tbl.IterReset()
	}
	if res.Empty {
		return &res, nil
	}
	if ipv6Ns.nd.tbl.IterIsStopped() {
		res.Stopped = true
		return &res, nil
	}

	keys, err2 := ipv6Ns.nd.tbl.GetNext(p.Count)
	if err2 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err2.Error(),
		}
	}
	res.Vec = keys
	return &res, nil
}

/* ServeJSONRPC for ApiIpv6StartPingHandler starts a Ping instance.
Returns True if it successfully started the ping, else False. */
func (h ApiIpv6StartPingHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*core.CThreadCtx)

	c, err := getClient(ctx, params)
	if err != nil {
		return nil, err
	}

	dgIpv6, dgOk := c.Client.ResolveDGIPv6()

	p := ApiIpv6StartPingHandler{Amount: ping.DefaultPingAmount, Pace: ping.DefaultPingPace, Dst: dgIpv6,
		Src: c.Client.ResolveSourceIPv6(), Timeout: ping.DefaultPingTimeout, PayloadSize: ping.DefaultPingPayloadSize}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}
	if !dgOk && dgIpv6 == p.Dst {
		return dgOk, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "Destination address not provided and default gateway not resolved/set.",
		}
	}
	ok := c.Client.OwnsIPv6(p.Src)
	if !ok {
		return ok, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "Can't use this source IPv6 for this client.",
		}
	}
	ok = c.StartPing(&p)
	if !ok {
		return ok, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "Client is already pinging or in timeout.",
		}
	}
	return ok, nil
}

/* ServeJSONRPC for ApiIpv6StopPingHandler stops an ongoing ping.
Returns True if it successfully stopped the ping, else False. */
func (h ApiIpv6StopPingHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClient(ctx, params)
	if err != nil {
		return nil, err
	}
	ok := c.StopPing()
	if !ok {
		return ok, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "There is no active pinging.",
		}
	}
	return ok, nil
}

/* ServeJSONRPC for ApiIpv6GetPingStatsHandler returns the statistics of an ongoing ping. If there is no ongoing ping
it will return an error */
func (h ApiIpv6GetPingStatsHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClient(ctx, params)
	if err != nil {
		return nil, err
	}

	return c.GetPingCounters(params)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(IPV6_PLUG,
		core.PluginRegisterData{Client: PluginIpv6CReg{},
			Ns:     PluginIpv6NsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command like ping etc
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("ipv6_ns_cnt", ApiIpv6NsCntHandler{}, false)               // get counter mld/icmp/nd
	core.RegisterCB("ipv6_mld_ns_sg_add", ApiMldNsAddSGHandler{}, false)       // add (g,s) mc
	core.RegisterCB("ipv6_mld_ns_sg_remove", ApiMldNsRemoveSGHandler{}, false) // remove (g,s) mc
	core.RegisterCB("ipv6_mld_ns_add", ApiMldNsAddHandler{}, false)            // mld add
	core.RegisterCB("ipv6_mld_ns_remove", ApiMldNsRemoveHandler{}, false)      // mld remove
	core.RegisterCB("ipv6_mld_ns_iter", ApiMldNsIterHandler{}, false)          // mld iterator
	core.RegisterCB("ipv6_mld_ns_get_cfg", ApiMldGetHandler{}, false)          // mld Get
	core.RegisterCB("ipv6_mld_ns_set_cfg", ApiMldSetHandler{}, false)          // mld Set
	core.RegisterCB("ipv6_nd_ns_iter", ApiNdNsIterHandler{}, false)            // nd ipv6 cache table iterator
	core.RegisterCB("ipv6_start_ping", ApiIpv6StartPingHandler{}, true)        // start ping
	core.RegisterCB("ipv6_stop_ping", ApiIpv6StopPingHandler{}, true)          // stop ping
	core.RegisterCB("ipv6_get_ping_stats", ApiIpv6GetPingStatsHandler{}, true) // get ping stats

	/* register callback for rx side*/
	core.ParserRegister("icmpv6", HandleRxIcmpv6Packet) // support mld/icmp/nd
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("icmpv6")
}
