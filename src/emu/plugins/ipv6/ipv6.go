package ipv6

/* ipv6 support

RFC 4443: Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6)
RFC 4861: Neighbor Discovery for IP Version 6 (IPv6)
RFC 4862: IPv6 Stateless Address Autoconfiguration.

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
}

var icmpEvents = []string{}

/*NewIpv6Client create plugin */
func NewIpv6Client(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIpv6Client)
	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, icmpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(IPV6_PLUG)
	o.ipv6NsPlug = nsplg.Ext.(*PluginIpv6Ns)
	o.OnCreate()
	return &o.PluginBase
}

/*OnEvent support event change of IP  */
func (o *PluginIpv6Client) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginIpv6Client) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
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
}

func NewIpv6Ns(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIpv6Ns)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.cdb = NewpingNsStatsDb(&o.stats)
	return &o.PluginBase
}

func (o *PluginIpv6Ns) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginIpv6Ns) OnEvent(msg string, a, b interface{}) {

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

	var ipv6key core.Ipv6Key

	/* need to look for 2 type of IPvs */
	copy(ipv6key[:], ipv6.DstIP())

	client := o.Ns.CLookupByIPv6(&ipv6key)
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

	switch icmpv6.TypeCode {
	case layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0):
		o.HandleEcho(ps, false)
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
	/* Get counters metadata */
	ApiIcmpNsCntMetaHandler struct{}

	/* Get counters  */
	ApiIcmpNsCntValueHandler struct{}
	ApiIcmpNsCntValueParams  struct { /* +tunnel*/
		Zero bool `json:"zero"` /* dump zero too */
	}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginIpv6Ns, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, IPV6_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	icmpNs := plug.Ext.(*PluginIpv6Ns)

	return icmpNs, nil
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

func (h ApiIcmpNsCntMetaHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	icmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}
	return icmpNs.cdb, nil
}

func (h ApiIcmpNsCntValueHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiIcmpNsCntValueParams
	tctx := ctx.(*core.CThreadCtx)

	icmpNs, err := getNs(ctx, params)
	if err != nil {
		return nil, err
	}

	err1 := tctx.UnmarshalValidate(*params, &p)

	if err1 != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err1.Error(),
		}
	}

	return icmpNs.cdb.MarshalValues(p.Zero), nil
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
	//core.RegisterCB("icmp_ns_get_cnt_meta", ApiIcmpNsCntMetaHandler{}, true)
	//core.RegisterCB("icmp_ns_get_cnt_val", ApiIcmpNsCntValueHandler{}, true)

	/* register callback for rx side*/
	core.ParserRegister("icmpv6", HandleRxIcmpv6Packet)
}
