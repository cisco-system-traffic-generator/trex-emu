// Copyright (c) 2021 Eolo S.p.A. and Altran Italia S.p.A. and/or them affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package point2point

import (
	"emu/core"
	"external/osamingo/jsonrpc"
	"github.com/intel-go/fastjson"
)

type (
	ApiClientGetPPPSessionID struct {}
	ApiClientGetPPPClientIP struct {}
	ApiClientGetPPPServerMac struct {}
)

/* ServeJSONRPC for ApiIcmpClientGetPingStatsHandler returns the statistics of an ongoing ping. If there is no ongoing ping
it will return an error */
func (h ApiClientGetPPPSessionID) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetClientPlugin(params, PPPPlugin)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	pppClient := plug.Ext.(*PluginPPPClient)

	return pppClient.GetPPPSessionID(), nil
}

func (h ApiClientGetPPPClientIP) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetClientPlugin(params, PPPPlugin)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	pppClient := plug.Ext.(*PluginPPPClient)

	return pppClient.GetPPPClientIP(), nil
}

func (h ApiClientGetPPPServerMac) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetClientPlugin(params, PPPPlugin)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	pppClient := plug.Ext.(*PluginPPPClient)

	return pppClient.GetPPPServerMac(), nil
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(PPPPlugin,
		core.PluginRegisterData{Client: PluginPPPCReg{},
			Ns:     PluginPPPNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* register callback to provide PPP Session ID and Assigned IP Address (when ready) */
	core.RegisterCB("ppp_c_client_session", ApiClientGetPPPSessionID{}, false)
	core.RegisterCB("ppp_c_client_ip", ApiClientGetPPPClientIP{}, false)
	core.RegisterCB("ppp_c_server_mac", ApiClientGetPPPServerMac{}, false)

	/* register callback for rx side*/
	core.ParserRegister("ppp", HandleRxPPPPacket)
}

// Register is a common entry for TRex EMU shell?
func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("ppp")
}
