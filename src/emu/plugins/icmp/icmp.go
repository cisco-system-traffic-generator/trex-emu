// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package icmp

/* basic support for ICMP

EchoRequest
TimestampRequest
Ping

*/

import (
	"emu/core"
	"emu/plugins/ping"
	"encoding/binary"
	"errors"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"net"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	ICMP_PLUG = "icmp"
)

type IcmpNsStats struct {
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

func NewIcmpNsStatsDb(o *IcmpNsStats) *core.CCounterDb {
	db := core.NewCCounterDb("icmp")
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

// PluginIcmpClient icmp information per client
type PluginIcmpClient struct {
	core.PluginBase
	icmpNsPlug *PluginIcmpNs
	ping       *ping.Ping
	pingData   *ApiIcmpClientStartPingHandler
}

var icmpEvents = []string{}

/*NewIcmpClient create plugin */
func NewIcmpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIcmpClient)
	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, icmpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(ICMP_PLUG)
	o.icmpNsPlug = nsplg.Ext.(*PluginIcmpNs)
	o.OnCreate()
	return &o.PluginBase
}

/*OnEvent support event change of IP  */
func (o *PluginIcmpClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginIcmpClient) OnRemove(ctx *core.PluginCtx) {
	o.StopPing()
	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, icmpEvents)
}

func (o *PluginIcmpClient) OnCreate() {
}

//StartPing creates a ping object in case there isn't any.
func (o *PluginIcmpClient) StartPing(data *ApiIcmpClientStartPingHandler) bool {
	if o.ping != nil {
		return false
	}
	o.pingData = data
	params := ping.PingParams{Amount: data.Amount, Pace: data.Pace, Timeout: data.Timeout}
	o.ping = ping.NewPing(params, o.Ns, o)
	o.ping.StartPinging()
	return true
}

func (o *PluginIcmpClient) StopPing() bool {
	if o.ping == nil {
		return false
	}
	o.ping.OnRemove()
	return true
}

func (o *PluginIcmpClient) GetPingCounters(params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	if o.ping == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "No available ping at the moment. Expired or not started.",
		}
	}
	return o.ping.GetPingCounters(params)
}

//handleEchoReply passes the packet to handle to Ping in case it is has an active Ping.
func (o *PluginIcmpClient) handleEchoReply(seq, id uint16, payload []byte) bool {
	stats := o.icmpNsPlug.stats
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
func (o *PluginIcmpClient) handleDestinationUnreachable(id uint16) bool {
	if o.ping != nil {
		o.ping.HandleDestinationUnreachable(id)
		return true
	}
	o.icmpNsPlug.stats.pktRxErrUnhandled++
	return false
}

// PreparePacketTemplate implements ping.PingClientIF.PreparePacketTemplate by creating an ICMPv4 packet with the id and seq received.
// It must put the magic as the first 8 bytes of the payload.
// It returns the offset of the icmpHeader in the packet and the packet.
func (o *PluginIcmpClient) PreparePingPacketTemplate(id, seq uint16, magic uint64) (icmpHeaderOffset int, pkt []byte) {
	myIPv4 := o.Client.Ipv4
	dstIPv4 := o.pingData.Dst
	pkt = o.Client.GetL2Header(false, uint16(layers.EthernetTypeIPv4))
	dstMac, ok := o.Client.ResolveIPv4DGMac()
	if ok {
		layers.EthernetHeader(pkt).SetDestAddress(dstMac[:])
	}
	ipHeaderOffset := len(pkt)
	ipHeader := core.PacketUtlBuild(
		&layers.IPv4{Version: 4, IHL: 5,
			TTL:      ping.DefaultPingTTL,
			Id:       0xcc,
			SrcIP:    net.IPv4(myIPv4[0], myIPv4[1], myIPv4[2], myIPv4[3]),
			DstIP:    net.IPv4(dstIPv4[0], dstIPv4[1], dstIPv4[2], dstIPv4[3]),
			Protocol: layers.IPProtocolICMPv4})
	pkt = append(pkt, ipHeader...)
	icmpHeaderOffset = len(pkt)
	icmpHeader := core.PacketUtlBuild(
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: id, Seq: seq})
	pkt = append(pkt, icmpHeader...)
	payload := make([]byte, int(o.pingData.PktSize)-len(pkt))
	binary.BigEndian.PutUint64(payload, magic) // Put a magic in our packets to verify that they contain valid timestamps
	pkt = append(pkt, payload...)
	layers.ICMPv4Header(pkt[icmpHeaderOffset:]).UpdateChecksum()
	ipv4Header := layers.IPv4Header(pkt[ipHeaderOffset : ipHeaderOffset+20])
	ipv4Header.SetLength(uint16(len(pkt) - ipHeaderOffset))
	ipv4Header.UpdateChecksum()
	return icmpHeaderOffset, pkt
}

// UpdateTxIcmpQuery implements ping.PingClientIF.UpdateTxIcmpQuery by incrementing the Tx Query every time an echo request is sent.
func (o *PluginIcmpClient) UpdateTxIcmpQuery(pktSent uint64) {
	o.icmpNsPlug.stats.pktTxIcmpQuery += pktSent

}

//OnPingRemove implements ping.PingClientIF.OnPingRemove by updating the ping
//corresponding fields when a ping is finishing or is stopped..
func (o *PluginIcmpClient) OnPingRemove() {
	o.ping = nil
	o.pingData = nil
}

// PluginIcmpNs icmp information per namespace
type PluginIcmpNs struct {
	core.PluginBase
	stats IcmpNsStats
	cdb   *core.CCounterDb
	cdbv  *core.CCounterDbVec
}

func NewIcmpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIcmpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.cdb = NewIcmpNsStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("icmp")
	o.cdbv.Add(o.cdb)
	return &o.PluginBase
}

func (o *PluginIcmpNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginIcmpNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginIcmpNs) SetTruncated() {

}

func iptime() uint32 {
	t := time.Now().UnixNano()
	sec := t / int64(time.Second)
	msec := (t - sec*int64(time.Second)) / int64(time.Millisecond)
	r := uint32((sec%(24*60*60))*1000 + msec)
	return r
}

func (o *PluginIcmpNs) HandleEcho(ps *core.ParserPacketState, ts bool) {
	mc := ps.M.DeepClone()
	p := mc.GetData()

	eth := layers.EthernetHeader(p[0:12])
	eth.SwapSrcDst()
	if eth.IsBroadcast() || eth.IsMcast() {
		o.stats.pktRxErrMulticastB++
		mc.FreeMbuf()
		return
	}

	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])
	ipv4.SwapSrcDst()
	icmp := layers.ICMPv4Header(p[ps.L4:])
	if !ts {
		ncode := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0)
		ocode := icmp.GetTypeCode()
		icmp.SetTypeCode(ncode)
		icmp.UpdateChecksum2(uint16(ocode), uint16(ncode))
	} else {
		ncode := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampReply, 0)
		icmp.SetTypeCode(ncode)
		if len(icmp) < 20 {
			o.stats.pktRxErrTooShort++
			mc.FreeMbuf()
			return
		}
		ipt := iptime()
		binary.BigEndian.PutUint32(icmp[12:16], ipt)
		binary.BigEndian.PutUint32(icmp[16:20], ipt)
		icmp.UpdateChecksum()
	}
	o.stats.pktRxIcmpQuery++
	o.stats.pktTxIcmpResponse++
	o.Tctx.Veth.Send(mc)
}

//HandleEchoReply handles an ICMP Echo-Reply that is received in the ICMP namespace.
func (o *PluginIcmpNs) HandleEchoReply(ps *core.ParserPacketState) int {
	p := ps.M.GetData()
	eth := layers.EthernetHeader(p[0:12])

	var dstMac core.MACKey
	copy(dstMac[:], eth.GetDestAddress()[:6])

	var ipv4 layers.IPv4
	err := ipv4.DecodeFromBytes(p[ps.L3:ps.L3+20], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	var icmpv4 layers.ICMPv4
	err = icmpv4.DecodeFromBytes(p[ps.L4:], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	if icmpClient, err := o.GetIcmpClientByMac(dstMac); err != nil {
		o.stats.pktRxNoClientUnhandled++
		return core.PARSER_OK
	} else {
		if icmpClient.handleEchoReply(icmpv4.Seq, icmpv4.Id, icmpv4.Payload) {
			o.stats.pktRxIcmpResponse++
		}
		return core.PARSER_OK
	}
}

//HandleDestinationUnreachable handles an ICMP Destination Unreacheable that is received in the ICMP namespace.
func (o *PluginIcmpNs) HandleDestinationUnreachable(ps *core.ParserPacketState) int {
	p := ps.M.GetData()
	eth := layers.EthernetHeader(p[0:12])

	var dstMac core.MACKey
	copy(dstMac[:], eth.GetDestAddress()[:6])

	var ipv4 layers.IPv4
	err := ipv4.DecodeFromBytes(p[ps.L3:ps.L3+20], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	// We will do a hack here for destination unreachable like packets, they have an ICMP Header nested in an ICMP Header,
	// here we parse the nested one.
	var icmpv4 layers.ICMPv4
	err = icmpv4.DecodeFromBytes(p[ps.L4+28:], o) // This doesn't support Destination Unreachable like packets,
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	if icmpClient, err := o.GetIcmpClientByMac(dstMac); err != nil {
		o.stats.pktRxNoClientUnhandled++
		return core.PARSER_OK
	} else {
		if icmpClient.handleDestinationUnreachable(icmpv4.Id) {
			o.stats.pktRxIcmpDstUnreachable++
		}
		return core.PARSER_OK
	}
}

/* HandleRxIcmpPacket -1 for parser error, 0 valid  */
func (o *PluginIcmpNs) HandleRxIcmpPacket(ps *core.ParserPacketState) int {

	m := ps.M

	if m.PktLen() < uint32(ps.L7) {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	p := m.GetData()
	var icmpv4 layers.ICMPv4
	err := icmpv4.DecodeFromBytes(p[ps.L4:], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])

	var ipv4Key core.Ipv4Key
	ipv4Key.SetUint32(ipv4.GetIPDst())
	client := o.Ns.CLookupByIPv4(&ipv4Key)
	if client == nil {
		o.stats.pktRxNoClientUnhandled++
		return 0
	}

	tome := client.IsUnicastToMe(p)
	if !tome {
		o.stats.pktRxNoClientUnhandled++
		return 0
	}

	ipv4Key.SetUint32(ipv4.GetIPSrc())

	/* source ip should be a valid ipv4 */
	srcip := net.IPv4(ipv4Key[0], ipv4Key[1], ipv4Key[2], ipv4Key[3])
	if !srcip.IsGlobalUnicast() {
		o.stats.pktRxErrMulticastB++
		return 0
	}

	switch icmpv4.TypeCode {
	case layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0):
		o.HandleEcho(ps, false)
	case layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampRequest, 0):
		o.HandleEcho(ps, true)
	case layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0):
		res := o.HandleEchoReply(ps)
		if res == core.PARSER_ERR {
			return core.PARSER_ERR
		}
	case layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHost):
		res := o.HandleDestinationUnreachable(ps)
		if res == core.PARSER_ERR {
			return core.PARSER_ERR
		}
	default:
		o.stats.pktRxErrUnhandled++
	}

	return 0
}

//GetIcmpClientByMac is a method of the ICMP Namespace that returns the Icmp Client given its MAC address.
func (o *PluginIcmpNs) GetIcmpClientByMac(mackey core.MACKey) (*PluginIcmpClient, error) {

	client := o.Ns.CLookupByMac(&mackey)

	if client == nil {
		return nil, errors.New("No Client Found with given MAC.")
	}

	cplg := client.PluginCtx.Get(ICMP_PLUG)
	if cplg == nil {
		return nil, errors.New("Plugin not registered in context.")
	}
	icmpCPlug := cplg.Ext.(*PluginIcmpClient)
	return icmpCPlug, nil
}

// HandleRxIcmpPacket Parser call this function with mbuf from the pool
// Either by register functions -- maybe it would be better to register the function
// Rx side
func HandleRxIcmpPacket(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(ICMP_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	icmpPlug := nsplg.Ext.(*PluginIcmpNs)
	return icmpPlug.HandleRxIcmpPacket(ps)
}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginIcmpCReg struct{}
type PluginIcmpNsReg struct{}

func (o PluginIcmpCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewIcmpClient(ctx, initJson)
}

func (o PluginIcmpNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewIcmpNs(ctx, initJson)
}

/*******************************************/
/* ICMP RPC commands */
type (
	/* Get counters metadata */
	ApiIcmpNsCntMetaHandler struct{}

	/* Get counters  */
	ApiIcmpNsCntValueHandler struct{}
	ApiIcmpNsCntValueParams  struct { /* +tunnel*/
		Zero bool `json:"zero"` /* dump zero too */
	}
	ApiIcmpClientStartPingHandler struct {
		Amount  uint32       `json:"amount"  validate:"ne=0"`   // Amount of echo requests to send
		Pace    float32      `json:"pace"    validate:"ne=0"`   // Pace of sending the Echo-Requests in packets per second.
		Dst     core.Ipv4Key `json:"dst"`                       // The destination IPv4
		Timeout uint8        `json:"timeout" validate:"ne=0"`   // Timeout from last ping until the stats are deleted.
		PktSize uint16       `json:"pktSize" validate:"gte=64"` // PktSize in bytes
	}

	ApiIcmpClientStopPingHandler struct{}

	ApiIcmpClientGetPingStatsHandler struct{}

	ApiIcmpNsCntHandler struct{}
)

func getNsPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginIcmpNs, error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, ICMP_PLUG)

	if err != nil {
		return nil, err
	}

	icmpNs := plug.Ext.(*PluginIcmpNs)

	return icmpNs, nil
}

func getClient(ctx interface{}, params *fastjson.RawMessage) (*PluginIcmpClient, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetClientPlugin(params, ICMP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	icmpClient := plug.Ext.(*PluginIcmpClient)

	return icmpClient, nil
}

/* ServeJSONRPC for ApiIcmpClientStartPingHandler starts a Ping instance.
Returns True if it sucessfully started the ping, else False. */
func (h ApiIcmpClientStartPingHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*core.CThreadCtx)

	icmpClient, err := getClient(ctx, params)
	if err != nil {
		return nil, err
	}

	p := ApiIcmpClientStartPingHandler{Amount: ping.DefaultPingAmount, Pace: ping.DefaultPingPace, Dst: icmpClient.Client.DgIpv4,
		Timeout: ping.DefaultPingTimeout, PktSize: ping.DefaultPingPktSize}

	err1 := tctx.UnmarshalValidate(*params, &p)
	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}
	return icmpClient.StartPing(&p), nil
}

/* ServeJSONRPC for ApiIcmpClientStopPingHandler stops an ongoing ping.
Returns True if it sucessfully stopped the ping, else False. */
func (h ApiIcmpClientStopPingHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	icmpClient, err := getClient(ctx, params)
	if err != nil {
		return nil, err
	}

	return icmpClient.StopPing(), nil
}

/* ServeJSONRPC for ApiIcmpClientGetPingStatsHandler returns the statistics of an ongoing ping. If there is no ongoing ping
it will return an error */
func (h ApiIcmpClientGetPingStatsHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	icmpClient, err := getClient(ctx, params)
	if err != nil {
		return nil, err
	}

	return icmpClient.GetPingCounters(params)
}

func (h ApiIcmpNsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("icmp")
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(ICMP_PLUG,
		core.PluginRegisterData{Client: PluginIcmpCReg{},
			Ns:     PluginIcmpNsReg{},
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

	core.RegisterCB("icmp_ns_cnt", ApiIcmpNsCntHandler{}, true)
	core.RegisterCB("icmp_c_start_ping", ApiIcmpClientStartPingHandler{}, true)
	core.RegisterCB("icmp_c_stop_ping", ApiIcmpClientStopPingHandler{}, true)
	core.RegisterCB("icmp_c_get_ping_stats", ApiIcmpClientGetPingStatsHandler{}, true)

	/* register callback for rx side*/
	core.ParserRegister("icmp", HandleRxIcmpPacket)
}
