package icmp

import (
	"emu/core"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"

	"github.com/intel-go/fastjson"
)

const (
	ICMP_PLUG = "icmp"
)

type IcmpNsStats struct {
	pktRxIcmpQuery         uint64
	pktTxIcmpResponse      uint64
	pktTxIcmpQuery         uint64
	pktRxIcmpResponse      uint64
	pktRxErrTooShort       uint64
	pktRxErrUnhandled      uint64
	pktRxNoClientUnhandled uint64
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
	return db
}

// PluginArpClient icmp information per client
type PluginIcmpClient struct {
	core.PluginBase
	//icmpPktTemplate []byte // template packet with
	//icmpHeader      layers.ICMPv4 // point to template packet
	//pktOffset  uint16
	icmpNsPlug *PluginIcmpNs
	//ipv4Header layers.IPv4Header
	//icmpHeader layers.IcmpHeader
}

func (o *PluginIcmpClient) preparePacketTemplate() {
	/*l3, ipoffset := o.Client.GetIPv4Header(false, uint8(layers.IPProtocolICMPv4))
	o.pktOffset = uint16(arpOffset)
	icmpHeader := core.PacketUtlBuild(
		&layers.ICMPv4{TypeCode: layers.ICMPv4TypeEchoRequest, Id: 1, Seq: 0x11}
	)
	icmpPktTemplate = append(l3, icmpHeader...)
	o.ipv4Header = layers.IPv4Header(o.arpPktTemplate[ipoffset : ipoffset+20])*/
}

var icmpEvents = []string{}

/*NewArpClient create plugin */
func NewIcmpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIcmpClient)
	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, icmpEvents, o) /* register events, only if exits*/
	//o.preparePacketTemplate()
	nsplg := o.Ns.PluginCtx.GetOrCreate(ICMP_PLUG)
	o.icmpNsPlug = nsplg.Ext.(*PluginIcmpNs)
	//o.OnCreate()
	return &o.PluginBase
}

/*OnEvent support event change of IP  */
func (o *PluginIcmpClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginIcmpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, icmpEvents)
}

func (o *PluginIcmpClient) OnCreate() {
}

func (o *PluginIcmpClient) SendPing(dst uint32) {
	if !o.Client.Ipv4.IsZero() {
		//TBD
		//o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	}
}

func (o *PluginIcmpClient) Respond() {

	//o.arpNsPlug.stats.pktTxReply++
	//o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
	//eth.SetBroadcast() /* back to default as broadcast */
}

// PluginArpNs icmp information per namespace
type PluginIcmpNs struct {
	core.PluginBase
	stats IcmpNsStats
	cdb   *core.CCounterDb
}

func NewIcmpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginIcmpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.cdb = NewIcmpNsStatsDb(&o.stats)
	return &o.PluginBase
}

func (o *PluginIcmpNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginIcmpNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginIcmpNs) SetTruncated() {

}

func (o *PluginIcmpNs) HandleEcho(ps *core.ParserPacketState) {
	mc := m.DeepClone()
	p := mc.GetData()

	eth := layers.EthernetHeader(p[0:12])
	eth.SwapSrcDst()
	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])
	ipv4.SwapSrcDst()
	icmp := layers.ICMPv4Header(p[ps.L4:])
	icmp.SetTypeCode(layers.ICMPv4TypeEchoReply)
	icmp.UpdateChecksum2(uint16(layers.ICMPv4TypeEchoRequest), uint16(layers.ICMPv4TypeEchoReply))
}

func (o *PluginIcmpNs) HandleRxIcmpPacket(ps *core.ParserPacketState) {

	m := ps.M

	if m.PktLen() < uint32(ps.L7) {
		o.stats.pktRxErrTooShort++
		return
	}

	p := m.GetData()
	var icmpv4 layers.ICMPv4
	err := icmpv4.DecodeFromBytes(p[ps.L4:], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return
	}

	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])

	var ipv4Key core.Ipv4Key
	ipv4Key.SetUint32(ipv4.GetIPDst())
	client := o.Ns.CLookupByIPv4(&ipv4Key)
	if client == nil {
		o.stats.pktRxNoClientUnhandled++
		return
	}

	switch icmpv4.TypeCode {
	case layers.ICMPv4TypeEchoRequest:
		o.HandleEcho(ps)
	case layers.ICMPv4TypeTimestampRequest:

	case layers.ICMPv4TypeInfoRequest:

	default:
		o.stats.pktRxErrUnhandled++
	}

}

// PluginArpThread  per thread
/*type PluginArpThread struct {
	core.PluginBase
}*/

// HandleRxArpPacket Parser call this function with mbuf from the pool
// Either by register functions -- maybe it would be better to register the function
// Rx side
func HandleRxIcmpPacket(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return -2
	}
	nsplg := ns.PluginCtx.Get(ICMP_PLUG)
	if nsplg == nil {
		return -2
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
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginIcmpNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, ICMP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginIcmpNs)

	return arpNs, nil
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

	arpClient := plug.Ext.(*PluginIcmpClient)

	return arpClient, nil
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
	core.RegisterCB("icmp_ns_get_cnt_meta", ApiIcmpNsCntMetaHandler{}, true)
	core.RegisterCB("icmp_ns_get_cnt_val", ApiIcmpNsCntValueHandler{}, true)

	/* register callback for rx side*/
	core.ParserRegister("icmp", HandleRxIcmpPacket)
}
