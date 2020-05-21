// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package dot1x

/*
RFC 8415  dot1x client with

EAP-MD5
EAP-MSCHAPv2


*/

import (
	"bytes"
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	DOT1X_PLUG = "dot1x"
	/* state of each client */
	// state machine
	EAP_WAIT_FOR_IDENTITY = 1
	EAP_WAIT_FOR_METHOD   = 2
	EAP_WAIT_FOR_RESULTS  = 3
	EAP_DONE_OK           = 4
	EAP_DONE_FAIL         = 5

	// EAP plugin states
	METHOD_DONE     = 1
	METHOD_INIT     = 5
	METHOD_CONT     = 6
	METHOD_MAY_CONT = 7

	// default timers
	TIMEOUT_TIMER_SEC = 10
	MAX_STARTS_CNT    = 3

	EAP_TYPE_MD5      = 4
	EAP_TYPE_MSCHAPV2 = 26

	MAX_EAPOL_VER      = 3
	EAPSIZE_PKT_HEADER = 5

	EAP_MD5_MASK      = 1
	EAP_MSCHAPv2_MASK = 2
)

var dot1xDefaultDestMAC = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}

type Dot1xCfg struct {
	User       *string `json:"user"`       // user name
	Password   *string `json:"password"`   // password
	Nthash     *string `json:"nthash"`     // hash string for MSCHAPv2
	Flags      uint32  `json:"flags"`      // not used
	TimeoutSec uint32  `json:"timeo_idle"` // timeout for success in sec
	MaxStart   uint32  `json:"max_start"`  // max number of retries
}

type Dot1xStats struct {
	pktRxParserErr         uint64
	pktRxIvalidVersionErr  uint64
	pktRxIgnore            uint64
	pktRxEAPtooShortErr    uint64
	pktRxParserInvalidCode uint64
	pktNoUserNameErr       uint64
	pktTxIdentity          uint64
	pktTxNack              uint64
	pktSuccessWrongState   uint64
	pktFaliureWrongState   uint64
	pktMethodWrongstate    uint64
	pktMethodNoPassword    uint64
	pktMethodWrongLen      uint64
	pktMethodFailErr       uint64
}

func NewDot1xStatsDb(o *Dot1xStats) *core.CCounterDb {
	db := core.NewCCounterDb("dot1x")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktMethodFailErr,
		Name:     "pktMethodFailErr",
		Help:     "rx method failed in success packet",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktMethodNoPassword,
		Name:     "pktMethodNoPassword",
		Help:     "rx method has no password",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktMethodWrongLen,
		Name:     "pktMethodWrongLen",
		Help:     "rx method wrong len",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxParserErr,
		Name:     "pktRxParserErr",
		Help:     "rx parse error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxIvalidVersionErr,
		Name:     "pktRxIvalidVersionErr",
		Help:     "rx invalid version ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxIgnore,
		Name:     "pktRxIgnore",
		Help:     "rx ignore",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxEAPtooShortErr,
		Name:     "pktRxEAPtooShortErr",
		Help:     "rx packet too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxParserInvalidCode,
		Name:     "pktRxParserInvalidCode",
		Help:     "rx parser invalid code",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktNoUserNameErr,
		Name:     "pktNoUserNameErr",
		Help:     "not user name provided",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxIdentity,
		Name:     "pktTxIdentity",
		Help:     "tx send identity",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxNack,
		Name:     "pktTxNack",
		Help:     "tx send nack",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktSuccessWrongState,
		Name:     "pktSuccessWrongState",
		Help:     "rx success in wrong stats",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktFaliureWrongState,
		Name:     "pktFaliureWrongState",
		Help:     "faliure in the wrong state ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktMethodWrongstate,
		Name:     "pktMethodWrongstate",
		Help:     "getting method in the wrong state  ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

type PluginDot1xClientTimer struct {
}

func (o *PluginDot1xClientTimer) OnEvent(a, b interface{}) {
	pi := a.(*PluginDot1xClient)
	pi.onTimerEvent()
}

type Dot1xMethodData struct {
	plug *PluginDot1xClient
	eap  *layers.EAP
}

type Dot1xMethodIF interface {

	// the name of the method, e.g. "eap-md5"
	GetName() string

	BuildResp(d *Dot1xMethodData) (bool, bool, []byte)
	Success(d *Dot1xMethodData) bool

	OnRemove()
}

type MethodToHandler map[uint8]Dot1xMethodIF

type Dot1xClientInfo struct {
	State          uint8 `json:"state"`
	SelectedMethod uint8 `json:"method"`
	EapVer         uint8 `json:"eap_version"`
}

//PluginDot1xClient information per client
type PluginDot1xClient struct {
	core.PluginBase
	nsPlug  *PluginDot1xNs
	cfg     Dot1xCfg
	timerw  *core.TimerCtx
	timer   core.CHTimerObj
	stats   Dot1xStats
	cdb     *core.CCounterDb
	cdbv    *core.CCounterDbVec
	timerCb PluginDot1xClientTimer
	smState uint8 // state of the state machine
	smCnt   uint8

	lastId           uint8
	selectedMethod   uint8 // plugin
	methodState      uint8
	mapHandler       MethodToHandler
	eapVer           uint8
	startPktTemplate []byte
	eapPktTemplate   []byte
	l3Offset         uint16
	nack             []byte
}

var dot1xEvents = []string{}

/*Dot1x create plugin */
func NewDot1xClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginDot1xClient)
	o.InitPluginBase(ctx, o)              /* init base object*/
	o.RegisterEvents(ctx, dot1xEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(DOT1X_PLUG)
	o.nsPlug = nsplg.Ext.(*PluginDot1xNs)
	o.LoadCfg(initJson)
	o.OnCreate()

	return &o.PluginBase
}

func (o *PluginDot1xClient) LoadCfg(initJson []byte) {

	o.cfg.TimeoutSec = TIMEOUT_TIMER_SEC
	o.cfg.MaxStart = MAX_STARTS_CNT
	fastjson.Unmarshal(initJson, &o.cfg)
}

func (o *PluginDot1xClient) OnCreate() {
	o.timerw = o.Tctx.GetTimerCtx()

	// build local source ipv6
	o.preparePacketTemplate()
	o.cdb = NewDot1xStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("dot1x")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent

	o.mapHandler = make(MethodToHandler)
	// add the handlers

	if o.cfg.Flags&EAP_MD5_MASK == 0 {
		o.mapHandler[EAP_TYPE_MD5] = NewEapMd5()
	}
	if o.cfg.Flags&EAP_MSCHAPv2_MASK == 0 {
		o.mapHandler[EAP_TYPE_MSCHAPV2] = NewEapMschapv2()
	}

	if o.cfg.Flags&EAP_MD5_MASK == 0 {
		o.nack = []byte{EAP_TYPE_MD5}
	} else {
		o.nack = []byte{EAP_TYPE_MSCHAPV2}
	}

	o.eapVer = MAX_EAPOL_VER
	o.smCnt = 0
	o.StartSm()
}

func (o *PluginDot1xClient) changeToInit() {
	o.selectedMethod = 0
	o.methodState = 0
	o.lastId = 0xff
	o.smState = EAP_WAIT_FOR_IDENTITY
}

func (o *PluginDot1xClient) StartSm() {
	o.changeToInit()
	o.SendStartPacket()
	o.restartTimer()
}

func (o *PluginDot1xClient) changeState(newstate uint8) {
	o.smState = newstate
}

func (o *PluginDot1xClient) preparePacketTemplate() {

	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeEAPOL))
	copy(l2[0:6], dot1xDefaultDestMAC[:])
	o.l3Offset = uint16(len(l2))
	eapPkt := core.PacketUtlBuild(
		&layers.EAPOL{
			Version: o.eapVer,
			Type:    layers.EAPOLTypeStart,
			Length:  0},
	)

	o.startPktTemplate = append(l2, eapPkt...)
	o.eapPktTemplate = append(l2, eapPkt...)
	o.eapPktTemplate = append(o.eapPktTemplate, 0, 0, 0, 0, 0)
}

func (o *PluginDot1xClient) SendStartPacket() {

	m := o.Ns.AllocMbuf(uint16(len(o.startPktTemplate)))
	m.Append(o.startPktTemplate)
	p := m.GetData()
	p[o.l3Offset] = o.eapVer // set the new version
	o.Tctx.Veth.Send(m)
}

func (o *PluginDot1xClient) SendLogoffPacket() {

	m := o.Ns.AllocMbuf(uint16(len(o.startPktTemplate)))
	m.Append(o.startPktTemplate)
	p := m.GetData()
	p[o.l3Offset] = o.eapVer // set the new version
	p[o.l3Offset+1] = byte(layers.EAPOLTypeLogOff)
	o.Tctx.Veth.Send(m)
}

func (o *PluginDot1xClient) SendResponsePacket(code uint8,
	id uint8,
	eaptype uint8,
	d []byte) {

	if (len(d) + len(o.eapPktTemplate)) > 1520 {
		//o.stats.
		return
	}
	pktsize := uint16(len(o.eapPktTemplate) + len(d))

	m := o.Ns.AllocMbuf(pktsize)
	m.Append(o.eapPktTemplate)
	p := m.GetData()
	l3 := o.l3Offset
	leneap := uint16(len(d) + EAPSIZE_PKT_HEADER)
	p[l3] = o.eapVer // set the new version
	p[l3+1] = byte(layers.EAPOLTypeEAP)
	binary.BigEndian.PutUint16(p[l3+2:l3+4], leneap)
	p[l3+4] = code
	p[l3+5] = id
	binary.BigEndian.PutUint16(p[l3+6:l3+8], leneap)
	p[l3+8] = eaptype
	m.Append(d)
	o.Tctx.Veth.Send(m)
}

/*OnEvent support event change of IP  */
func (o *PluginDot1xClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginDot1xClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, dot1xEvents)
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *PluginDot1xClient) makeSurereTimerIsRunning() {
	if o.timer.IsRunning() {
		return
	}
	o.timerw.Start(&o.timer, time.Duration(o.cfg.TimeoutSec)*time.Second)
}

func (o *PluginDot1xClient) restartTimer() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.timerw.Start(&o.timer, time.Duration(o.cfg.TimeoutSec)*time.Second)
}

//onTimerEvent on timer event callback
func (o *PluginDot1xClient) onTimerEvent() {

	if (o.smState == EAP_DONE_OK) ||
		(o.smState == EAP_DONE_FAIL) {
		return
		// no need to restart the timer
	}

	o.smCnt++
	if uint32(o.smCnt) < o.cfg.MaxStart {
		// restart
		o.StartSm()
	}

}

func (o *PluginDot1xClient) HandleRxDot1xPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()

	var eapol layers.EAPOL

	if len(p) < 4 {
		o.stats.pktRxParserErr++
		return core.PARSER_ERR
	}

	err := eapol.DecodeFromBytes(p[ps.L3:ps.L3+4], gopacket.NilDecodeFeedback)

	if err != nil {
		o.stats.pktRxParserErr++
		return core.PARSER_ERR
	}

	if (eapol.Version < 1) || (eapol.Version > MAX_EAPOL_VER) {
		o.stats.pktRxIvalidVersionErr++
		return core.PARSER_ERR
	}
	o.eapVer = eapol.Version

	if eapol.Type != layers.EAPOLTypeEAP {
		o.stats.pktRxIgnore++
		return core.PARSER_ERR
	}

	if eapol.Length < 4 {
		o.stats.pktRxEAPtooShortErr++
		return core.PARSER_ERR
	}

	if uint32(eapol.Length+ps.L3+4) > ps.M.PktLen() {
		o.stats.pktRxEAPtooShortErr++
		return core.PARSER_ERR
	}

	var eap layers.EAP

	if len(p) < 8 {
		o.stats.pktRxEAPtooShortErr++
		return core.PARSER_ERR
	}

	err = eap.DecodeFromBytes(p[ps.L3+4:], gopacket.NilDecodeFeedback)

	if err != nil {
		o.stats.pktRxParserErr++
		return core.PARSER_ERR
	}
	o.lastId = eap.Id

	switch eap.Code {
	case layers.EAPCodeRequest:
		o.handleRequest(&eap)
	case layers.EAPCodeSuccess:
		o.handleSuccess(&eap)
		o.smCnt = 0
	case layers.EAPCodeFailure:
		o.handleFailure(&eap)
	default:
		o.stats.pktRxParserInvalidCode++
	}

	return (0)
}

func (o *PluginDot1xClient) sendNack(eap *layers.EAP) {
	o.stats.pktTxNack++
	o.SendResponsePacket(uint8(layers.EAPCodeResponse),
		eap.Id, uint8(layers.EAPTypeNACK),
		o.nack)
}

func (o *PluginDot1xClient) handleFailure(eap *layers.EAP) {
	if o.smState != EAP_WAIT_FOR_RESULTS {
		o.stats.pktSuccessWrongState++
		return
	}

	o.smState = EAP_DONE_FAIL
}

func (o *PluginDot1xClient) handleSuccess(eap *layers.EAP) {
	if o.smState != EAP_WAIT_FOR_RESULTS {
		o.stats.pktSuccessWrongState++
		return
	}

	var suc bool
	suc = true

	if eap.Length > 4 {
		t := o.selectedMethod
		mhandler, ok := o.mapHandler[t]
		if ok {
			var obj Dot1xMethodData
			obj.eap = eap
			obj.plug = o
			suc = mhandler.Success(&obj)
		}
	}

	if suc {
		o.smState = EAP_DONE_OK
	} else {
		o.stats.pktMethodFailErr++
		o.smState = EAP_DONE_FAIL
	}
}

func (o *PluginDot1xClient) handleRequest(eap *layers.EAP) {
	if eap.Type == layers.EAPTypeIdentity {
		// accepted on all states
		if o.cfg.User != nil {
			o.stats.pktTxIdentity++
			o.SendResponsePacket(uint8(layers.EAPCodeResponse),
				eap.Id, uint8(layers.EAPTypeIdentity),
				[]byte(*o.cfg.User))
			o.smState = EAP_WAIT_FOR_METHOD
			o.makeSurereTimerIsRunning()
		} else {
			o.stats.pktNoUserNameErr++

		}
	} else {
		// look for method
		if o.smState != EAP_WAIT_FOR_METHOD {
			o.stats.pktMethodWrongstate++
			return
		}
		t := uint8(eap.Type)
		mhandler, ok := o.mapHandler[t]
		if !ok {
			o.sendNack(eap)
			return
		}

		var obj Dot1xMethodData
		obj.eap = eap
		obj.plug = o
		ok, finish, res := mhandler.BuildResp(&obj)
		if !ok {
			o.sendNack(eap)
		} else {
			o.SendResponsePacket(uint8(layers.EAPCodeResponse),
				eap.Id, t,
				res)
			if finish {
				o.smState = EAP_WAIT_FOR_RESULTS
			}
			o.selectedMethod = t
		}
	}

}

// PluginDot1xNs information per namespace
type PluginDot1xNs struct {
	core.PluginBase
}

func NewDot1xNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginDot1xNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase
}

func (o *PluginDot1xNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginDot1xNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginDot1xNs) SetTruncated() {

}

func (o *PluginDot1xNs) HandleRxDot1xPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/
	/* UDP checksum was verified in the parser */
	var mackey core.MACKey
	copy(mackey[:], p[0:6])
	var client *core.CClient

	if bytes.Equal(p[0:6], dot1xDefaultDestMAC) {
		client = o.Ns.GetFirstClient() // we don't support multicast .. for  // TBD this should be tested
	} else {
		client = o.Ns.CLookupByMac(&mackey)
	}
	if client == nil {
		return core.PARSER_ERR
	}

	cplg := client.PluginCtx.Get(DOT1X_PLUG)
	if cplg == nil {
		return core.PARSER_ERR
	}
	plug := cplg.Ext.(*PluginDot1xClient)
	return plug.HandleRxDot1xPacket(ps)
}

// HandleRxDot1xPacket Parser call this function with mbuf from the pool
func HandleRxDot1xPacket(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(DOT1X_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	dhcpPlug := nsplg.Ext.(*PluginDot1xNs)
	return dhcpPlug.HandleRxDot1xPacket(ps)

}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginDot1xCReg struct{}
type PluginDot1xNsReg struct{}

func (o PluginDot1xCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewDot1xClient(ctx, initJson)
}

func (o PluginDot1xNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewDot1xNs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */
type (
	ApiDot1xClientCntHandler  struct{}
	ApiDot1xClientInfoHandler struct{}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginDot1xNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, DOT1X_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginDot1xNs)

	return arpNs, nil
}

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginDot1xClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, DOT1X_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginDot1xClient)

	return pClient, nil
}

func (h ApiDot1xClientInfoHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var plugs []*core.PluginBase
	var err error
	tctx := ctx.(*core.CThreadCtx)
	plugs, err = tctx.GetClientsPlugin(params, DOT1X_PLUG)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	res := make([]Dot1xClientInfo, len(plugs))
	for i, p := range plugs {
		rp := &res[i]
		var pc *PluginDot1xClient
		pc = p.Ext.(*PluginDot1xClient)
		rp.State = pc.smState
		rp.SelectedMethod = pc.selectedMethod
		rp.EapVer = pc.eapVer
	}

	return res, nil
}

func (h ApiDot1xClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return c.cdbv.GeneralCounters(err, tctx, params, &p)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(DOT1X_PLUG,
		core.PluginRegisterData{Client: PluginDot1xCReg{},
			Ns:     PluginDot1xNsReg{},
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

	core.RegisterCB("dot1x_client_info", ApiDot1xClientInfoHandler{}, false) // get info per array

	core.RegisterCB("dot1x_client_cnt", ApiDot1xClientCntHandler{}, false) // get counters/meta
	// TBD getter for the client info

	/* register callback for rx side*/
	core.ParserRegister("dot1x", HandleRxDot1xPacket)
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("dot1x")
}
