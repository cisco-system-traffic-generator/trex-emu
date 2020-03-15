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
	"encoding/binary"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"

	"github.com/intel-go/fastjson"
)

const (
	IPV6_PLUG = "ipv6"
)

type pingNsStats struct {
	pktRxIcmpQuery         uint64
	pktTxIcmpResponse      uint64
	pktTxIcmpQuery         uint64
	pktRxIcmpResponse      uint64
	pktRxErrTooShort       uint64
	pktRxErrUnhandled      uint64
	pktRxErrMulticastB     uint64
	pktRxNoClientUnhandled uint64
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

	return db
}

// PluginIpv6Client icmp information per client
type PluginIpv6Client struct {
	core.PluginBase
	ipv6NsPlug *PluginIpv6Ns
	nd         NdClientCtx
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
	/* force removing the link to the client */
	o.nd.OnRemove(ctx)
	ctx.UnregisterEvents(&o.PluginBase, icmpEvents)
}

func (o *PluginIpv6Client) OnCreate() {
}

func (o *PluginIpv6Client) SendPing(dst uint32) {
	if !o.Client.Ipv4.IsZero() {
		//TBD o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
		//TBD need to add callback per client for resolve ip,mac
	}
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
		Empty   bool           `json:"empty"`
		Stopped bool           `json:"stopped"`
		Vec     []core.Ipv6Key `json:"data"`
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

	keys, err2 := ipv6Ns.mld.GetNext(p.Count)
	if err2 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err2.Error(),
		}
	}
	res.Vec = keys
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

	core.RegisterCB("ipv6_ns_cnt", ApiIpv6NsCntHandler{}, false)          // get counter mld/icmp/nd
	core.RegisterCB("ipv6_mld_ns_add", ApiMldNsAddHandler{}, false)       // mld add
	core.RegisterCB("ipv6_mld_ns_remove", ApiMldNsRemoveHandler{}, false) // mld remove
	core.RegisterCB("ipv6_mld_ns_iter", ApiMldNsIterHandler{}, false)     // mld iterator
	core.RegisterCB("ipv6_mld_ns_get_cfg", ApiMldGetHandler{}, false)     // mld Get
	core.RegisterCB("ipv6_mld_ns_set_cfg", ApiMldSetHandler{}, false)     // mld Set
	core.RegisterCB("ipv6_nd_ns_iter", ApiNdNsIterHandler{}, false)       // nd ipv6 cache table iterator

	/* register callback for rx side*/
	core.ParserRegister("icmpv6", HandleRxIcmpv6Packet) // support mld/icmp/nd
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("icmpv6")
}
