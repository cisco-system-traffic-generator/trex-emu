// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

// This file includes the callback and RPC
// it will work only if client ask for UDP or TCP transport
package transport

import (
	"emu/core"
	"external/osamingo/jsonrpc"
	"fmt"

	"github.com/intel-go/fastjson"
)

const (
	TRANS_PLUG = "transport"
)

type PluginTransNs struct {
	core.PluginBase
}

func NewTransNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginTransNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase
}

func (o *PluginTransNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginTransNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginTransNs) SetTruncated() {

}

type PluginTransClient struct {
	core.PluginBase
	initJson []byte
	ns       *PluginTransNs
}

func NewTransClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginTransClient)
	o.InitPluginBase(ctx, o) /* init base object*/
	o.RegisterEvents(ctx, []string{}, o)
	nsplg := o.Ns.PluginCtx.GetOrCreate(TRANS_PLUG)
	o.ns = nsplg.Ext.(*PluginTransNs)

	o.initJson = append(o.initJson, initJson...)
	return &o.PluginBase
}

func (o *PluginTransClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginTransClient) OnRemove(ctx *core.PluginCtx) {
	tl := o.Client.GetTransportCtx()
	if tl == nil {
		return
	}
	tx := tl.(*TransportCtx)
	tx.onRemove()
}

func (o *PluginTransClient) handleRxTransPacket(ps *core.ParserPacketState) int {
	tl := o.Client.GetTransportCtx()
	if tl == nil {
		return -1
	}
	tx := tl.(*TransportCtx)
	return tx.handleRxPacket(ps)
}

func (o *PluginTransNs) handleRxTransPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/
	/* UDP checksum was verified in the parser */
	
	// lookup by MAC
	var mackey core.MACKey
	copy(mackey[:], p[0:6])

	client := o.Ns.CLookupByMac(&mackey)

	if client == nil {
		return core.PARSER_ERR
	}

	/*	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])

		var ipv4Key core.Ipv4Key
		ipv4Key.SetUint32(ipv4.GetIPDst())
		client := o.Ns.CLookupByIPv4(&ipv4Key)
		if client == nil {
			return 0
		}
	*/
	cplg := client.PluginCtx.Get(TRANS_PLUG)
	if cplg == nil {
		return core.PARSER_ERR
	}
	transCPlug := cplg.Ext.(*PluginTransClient)
	return transCPlug.handleRxTransPacket(ps)
}

func HandleRxTransPacket(ps *core.ParserPacketState) int {
	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(TRANS_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	transPlug := nsplg.Ext.(*PluginTransNs)
	return transPlug.handleRxTransPacket(ps)
}

type PluginTransCReg struct{}
type PluginTransNsReg struct{}

func (o PluginTransCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewTransClient(ctx, initJson)
}

func (o PluginTransNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewTransNs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */

type (
	ApiTransClientCntHandler struct{}
)

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*TransportCtx, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, TRANS_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginTransClient)

	tx := getTransportCtxIfExist(pClient.Client)
	if tx == nil {
		return nil, fmt.Errorf(" client does not have a transport context")
	}

	return tx, nil
}

func (h ApiTransClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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
	core.PluginRegister(TRANS_PLUG,
		core.PluginRegisterData{Client: PluginTransCReg{},
			Ns:     PluginTransNsReg{},
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

	core.RegisterCB("transport_client_cnt", ApiTransClientCntHandler{}, false) // get counters/meta

	/* register callback for rx side*/
	core.ParserRegister("transport", HandleRxTransPacket)
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("transport")
}
