// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package transport_example

/*

example of transport

*/

import (
	"bytes"
	"emu/core"
	"emu/plugins/transport"
	"external/osamingo/jsonrpc"

	"github.com/intel-go/fastjson"
)

const (
	TRANS_E_PLUG = "transe"
)

type TransEInit struct {
	Addr     string `json:"addr"`
	DataSize uint32 `json:"size"`
	Loops    uint32 `json:"loops"`
}

type TransEStats struct {
	rxByteTotal        uint64
	txByteTotal        uint64
	pktRxEvent         uint64
	pktTxEvent         uint64
	pktRxErrNotTheSame uint64
	pktRxErrBigger     uint64
	pktTxErrSend       uint64
	pktClient          uint64
}

func NewTransENsStatsDb(o *TransEStats) *core.CCounterDb {
	db := core.NewCCounterDb("transe")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktClient,
		Name:     "pktClient",
		Help:     "pktClient",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxByteTotal,
		Name:     "rxByteTotal",
		Help:     "rxByteTotal",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.txByteTotal,
		Name:     "txByteTotal",
		Help:     "txByteTotal",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxEvent,
		Name:     "pktRxEvent",
		Help:     "pktRxEvent",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxEvent,
		Name:     "pktTxEvent",
		Help:     "pktTxEvent",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrNotTheSame,
		Name:     "pktRxErrNotTheSame",
		Help:     "pktRxErrNotTheSame",
		Unit:     "opts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrBigger,
		Name:     "pktRxErrBigger",
		Help:     "pktRxErrBigger",
		Unit:     "opts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxErrSend,
		Name:     "pktTxErrSend",
		Help:     "pktTxErrSend",
		Unit:     "opts",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

// PluginDhcpClient information per client
type PluginTransportEClient struct {
	core.PluginBase
	tranNsPlug *PluginTransportENs
	ctx        *transport.TransportCtx
	s          transport.SocketApi
	cfg        TransEInit
	b          []byte
	loops      uint32
	rxcnt      uint32
}

var events = []string{core.MSG_DG_MAC_RESOLVED}

/*NewDhcpClient create plugin */
func NewTransportEClient(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {

	o := new(PluginTransportEClient)
	o.InitPluginBase(ctx, o)         /* init base object*/
	o.RegisterEvents(ctx, events, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(TRANS_E_PLUG)
	o.tranNsPlug = nsplg.Ext.(*PluginTransportENs)

	o.cfg = TransEInit{Addr: "48.0.0.1:80", DataSize: 10, Loops: 1}
	ctx.Tctx.UnmarshalValidate(initJson, &o.cfg)
	o.b = make([]byte, o.cfg.DataSize)
	for i := 0; i < int(o.cfg.DataSize-1); i++ {
		o.b[i] = 97 + byte(i%22)
	}
	o.b[o.cfg.DataSize-1] = byte('\n')
	o.loops = 0

	return &o.PluginBase, nil
}

func (o *PluginTransportEClient) startLoop() {
	o.rxcnt = 0
	r, _ := o.s.Write(o.b)
	o.tranNsPlug.stats.pktTxEvent++
	o.tranNsPlug.stats.txByteTotal += uint64(len(o.b))

	if r != transport.SeOK {
		o.tranNsPlug.stats.pktTxErrSend++
	}
}

func (o *PluginTransportEClient) OnRxEvent(event transport.SocketEventType) {

	if (event & transport.SocketEventConnected) > 0 {
		o.startLoop()
	}

	if event&transport.SocketRemoteDisconnect > 0 {
		// remote disconnected before connection
		o.s.Close()
	}

	if (event & transport.SocketClosed) > 0 {
		o.s = nil
	}

}

func (o *PluginTransportEClient) OnRxData(d []byte) {
	// do somthing with the data
	lenb := uint32(len(d))
	lenbuffer := uint32(len(o.b))
	s := o.rxcnt
	e := o.rxcnt + lenb

	o.tranNsPlug.stats.pktRxEvent++
	o.tranNsPlug.stats.rxByteTotal += uint64(lenb)

	if e > lenbuffer {
		o.tranNsPlug.stats.pktRxErrBigger++
	}

	if bytes.Compare(d[:], o.b[s:e]) != 0 {
		o.tranNsPlug.stats.pktRxErrNotTheSame++
	}
	o.rxcnt += lenb
	if o.rxcnt == lenbuffer {
		o.loops += 1
		if o.loops == o.cfg.Loops {
			o.tranNsPlug.stats.pktClient++
			o.s.Close()
		} else {
			o.startLoop()
		}
	}
}

func (o *PluginTransportEClient) OnTxEvent(event transport.SocketEventType) {
	if event&transport.SocketTxMore > 0 {
		// do somthing
	}
}

/*OnEvent support of messages */
func (o *PluginTransportEClient) OnEvent(msg string, a, b interface{}) {
	switch msg {
	case core.MSG_DG_MAC_RESOLVED:
		bitMask, ok := a.(uint8)
		if !ok {
			// failed at type assertion
			return
		}
		resolvedIPv4 := (bitMask & core.RESOLVED_IPV4_DG_MAC) == core.RESOLVED_IPV4_DG_MAC
		if resolvedIPv4 {
			// now we can dial
			o.ctx = transport.GetTransportCtx(o.Client)
			s, err := o.ctx.Dial("tcp", o.cfg.Addr, o, nil, nil, 0)
			if err != nil {
				return
			}
			o.s = s
		}
	}
}

func (o *PluginTransportEClient) OnRemove(ctx *core.PluginCtx) {

}

// PluginTransportENs icmp information per namespace
type PluginTransportENs struct {
	core.PluginBase
	stats TransEStats
	cdb   *core.CCounterDb
	cdbv  *core.CCounterDbVec
}

func NewTransportENs(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginTransportENs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.cdb = NewTransENsStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("stats")
	o.cdbv.Add(o.cdb)
	return &o.PluginBase, nil
}

func (o *PluginTransportENs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginTransportENs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginTransportENs) SetTruncated() {

}

type (
	ApiTranseNsCntHandler struct{}
)

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginTransportECReg struct{}
type PluginTransportENsReg struct{}

func (o PluginTransportECReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewTransportEClient(ctx, initJson)
}

func (o PluginTransportENsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewTransportENs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */

func getNsPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginTransportENs, error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, TRANS_E_PLUG)

	if err != nil {
		return nil, err
	}

	arpNs := plug.Ext.(*PluginTransportENs)
	return arpNs, nil
}

func (h ApiTranseNsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)

	nsPlug, err := getNsPlugin(ctx, params)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return nsPlug.cdbv.GeneralCounters(err, tctx, params, &p)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(TRANS_E_PLUG,
		core.PluginRegisterData{Client: PluginTransportECReg{},
			Ns:     PluginTransportENsReg{},
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

	core.RegisterCB("transe_ns_cnt", ApiTranseNsCntHandler{}, true)

	/* register callback for rx side*/
}

func Register(ctx *core.CThreadCtx) {
}
