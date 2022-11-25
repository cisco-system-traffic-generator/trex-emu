// Copyright (c) 2021 Eolo S.p.A. and Altran Italia S.p.A. and/or them affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package point2point

import (
	"emu/core"
	"fmt"

	"external/google/gopacket/layers"
)

// PluginPPPClientTimer is unclear
type PluginPPPClientTimer struct {
}

type LogLevel string

const (
	INFO     LogLevel = "INFO"
	WARNING  LogLevel = "WARNING"
	ERROR    LogLevel = "ERROR"
	CRITICAL LogLevel = "CRITICAL"
)

// LogTimeFormatted is standard formatter for plugin
func LogTimeFormatted(logLevel LogLevel, format string, a ...interface{}) {
	//s := fmt.Sprintf(format, a)
	//fmt.Println(time.Now().Format(time.RFC3339) + fmt.Sprintf(" [%s] -> %s ", logLevel, s))
}

/*OnEvent support event change during PPP Session */
func (o *PluginPPPClientTimer) OnEvent(a, b interface{}) {
	pi := a.(*PluginPPPClient)
	pi.onTimerEvent()
}

// onTimerEvent on timer event callback
func (o *PluginPPPClient) onTimerEvent() {

	switch o.state {
	case PPPStateInit:
		// initial status if event is triggered send PADI
		o.sendPADI()
	case PPPStatePADI:
		// if still here send PADI again
		o.sendPADI()
	case PPPStatePADO:
		// send PADR
		o.sendPADR()
	case PPPStatePADR:
		// send PADR again
		o.sendPADR()
	case PPPStatePADS:
		// send LCP Configuration Request
		// move to PPPStateLCPNegotiation
		o.sendLCPConfReq(true)
	case PPPStateLCPNegotiation:
		// Evaluate status LCP Configuration
		// if one ack for direction is sent step next status
		o.evaluateLCPNegotiationOver()
	case PPPStatePAPSent:
		// send Again PAP Request
		if o.authMethod == layers.PPPTypePAP {
			o.sendPAPReq()
		} else {
			msg := fmt.Sprintf("Unsupported Authentication Protocol on Mac %v", o.Client.Mac)
			LogTimeFormatted(ERROR, msg)
			panic(msg)
		}
	case PPPStateIPCPNegotiation:
		// send Again IPCP configuration request/ack
		o.sendIPCPConfReq()
	case PPPStateLinkUp:
		// send LCP Echo Request
		//o.SendLCPEchoRequest()
	case PPPStatePADTSent:
		// Send Again PADT (max nr of times)
		o.sendPADT()
	case PPPStatePADTReceived:
		// this is final state reached after last message sent and before client shutdown
	}
}

// HandleRxPPPPacket handled Rx packets at namespace
func (o *PluginPPPNs) HandleRxPPPPacket(ps *core.ParserPacketState) int {
	m := ps.M
	p := m.GetData()

	var mackey core.MACKey
	copy(mackey[:], p[0:6])

	client := o.Ns.CLookupByMac(&mackey)

	if client == nil {
		return core.PARSER_ERR
	}

	cplg := client.PluginCtx.Get(PPPPlugin)
	if cplg == nil {
		return core.PARSER_ERR
	}
	pppCPlug := cplg.Ext.(*PluginPPPClient)
	return pppCPlug.HandleRxPPPPacket(ps)
}

// PluginPPPNs information per namespace
type PluginPPPNs struct {
	core.PluginBase
}

// NewPPPNs handles creation of namespace
func NewPPPNs(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	LogTimeFormatted(INFO, ">> NewPPPNs >> Plugin PPP Ns")

	o := new(PluginPPPNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase, nil
}

func (o *PluginPPPNs) OnRemove(ctx *core.PluginCtx) {
	LogTimeFormatted(INFO, ">> OnRemove >> Plugin PPP Ns")
}

func (o *PluginPPPNs) OnEvent(msg string, a, b interface{}) {
	LogTimeFormatted(INFO, ">> OnEvent >> Plugin PPP Ns")
}

func (o *PluginPPPNs) SetTruncated() {
	LogTimeFormatted(INFO, ">> SetTruncated >> Plugin PPP Ns")
}

type PluginPPPCReg struct{}
type PluginPPPNsReg struct{}

func (o PluginPPPCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {

	return NewPPPClient(ctx, initJson)
}

func (o PluginPPPNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {

	return NewPPPNs(ctx, initJson)
}

// HandleRxPPPPacket Parser call this function with mbuf from the pool
func HandleRxPPPPacket(ps *core.ParserPacketState) int {
	ns := ps.Tctx.GetNs(ps.Tun)

	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(PPPPlugin)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	pppPlug := nsplg.Ext.(*PluginPPPNs)
	return pppPlug.HandleRxPPPPacket(ps)

}

/*
func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginPPPNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, PPPPlugin)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	pppNs := plug.Ext.(*PluginPPPNs)

	return pppNs, nil
}
*/
/*
func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginPPPClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, PPPPlugin)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginPPPClient)

	return pClient, nil
}
*/
