// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package transport_example

/*

example of transport

*/

import (
	"emu/core"
	"emu/plugins/transport"
)

const (
	TRANS_E_PLUG = "transe"
)

type TransEInit struct {
	Addr     string `json:"addr"`
	DataSize uint32 `json:"size"`
}

type TransportEStats struct {
}

func NewTransportEStatsDb(o *TransportEStats) *core.CCounterDb {
	db := core.NewCCounterDb("transporte")

	return db
}

//PluginDhcpClient information per client
type PluginTransportEClient struct {
	core.PluginBase
	tranNsPlug *PluginTransportENs
	ctx        *transport.TransportCtx
	s          transport.SocketApi
	cfg        TransEInit
}

var events = []string{core.MSG_DG_MAC_RESOLVED}

/*NewDhcpClient create plugin */
func NewTransportEClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginTransportEClient)
	o.InitPluginBase(ctx, o)         /* init base object*/
	o.RegisterEvents(ctx, events, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(TRANS_E_PLUG)
	o.tranNsPlug = nsplg.Ext.(*PluginTransportENs)

	o.cfg = TransEInit{Addr: "48.0.0.1:80", DataSize: 10}
	ctx.Tctx.UnmarshalValidate(initJson, &o.cfg)

	return &o.PluginBase
}

func (o *PluginTransportEClient) OnRxEvent(event transport.SocketEventType) {

	if (event & transport.SocketEventConnected) > 0 {
		var b []byte
		b = make([]byte, o.cfg.DataSize)
		for i := 0; i < int(o.cfg.DataSize); i++ {
			b[i] = byte(i)
		}
		o.s.Write(b)
		o.s.Close()
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
			s, err := o.ctx.Dial("tcp", o.cfg.Addr, o, nil)
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
}

func NewTransportENs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginTransportENs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase
}

func (o *PluginTransportENs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginTransportENs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginTransportENs) SetTruncated() {

}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginTransportECReg struct{}
type PluginTransportENsReg struct{}

func (o PluginTransportECReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewTransportEClient(ctx, initJson)
}

func (o PluginTransportENsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewTransportENs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */

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

	//core.RegisterCB("dhcp_client_cnt", ApiDhcpClientCntHandler{}, false) // get counters/meta

	/* register callback for rx side*/
}

func Register(ctx *core.CThreadCtx) {
}
