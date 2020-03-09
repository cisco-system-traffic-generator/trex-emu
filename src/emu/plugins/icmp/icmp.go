package icmp

/* basic support for ICMP, ping does not work right now. just answer to

EchoRequest
TimestampRequest

TBD - need to add support for ping command

*/

import (
	"emu/core"
	"encoding/binary"
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
	pktRxIcmpQuery         uint64
	pktTxIcmpResponse      uint64
	pktTxIcmpQuery         uint64
	pktRxIcmpResponse      uint64
	pktRxErrTooShort       uint64
	pktRxErrUnhandled      uint64
	pktRxErrMulticastB     uint64
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

// PluginIcmpClient icmp information per client
type PluginIcmpClient struct {
	core.PluginBase
	icmpNsPlug *PluginIcmpNs
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
	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, icmpEvents)
}

func (o *PluginIcmpClient) OnCreate() {
}

func (o *PluginIcmpClient) SendPing(dst uint32) {
	if !o.Client.Ipv4.IsZero() {
		//TBD o.Tctx.Veth.SendBuffer(false, o.Client, o.arpPktTemplate)
		//TBD need to add callback per client for resolve ip,mac
	}
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

	default:
		o.stats.pktRxErrUnhandled++
	}

	return 0
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

	/* register callback for rx side*/
	core.ParserRegister("icmp", HandleRxIcmpPacket)
}
