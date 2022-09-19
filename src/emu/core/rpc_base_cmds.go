// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.
// August 2021 Eolo S.p.A. and Altran Italia S.p.A.
// - modified ApiGetVersionResult object to return value defined at build time at line 132

package core

import (
	"external/osamingo/jsonrpc"
	"fmt"
	"time"

	"github.com/intel-go/fastjson"
)

type (
	ApiSyncHandler struct{}
	ApiSyncParams  struct {
		Name  string `json:"name"`
		Major uint8  `json:"major"`
		Minor uint8  `json:"minor"`
	}

	ApiGetVersionHandler struct{}
	ApiGetVersionParams  struct{}
	ApiGetVersionResult  struct {
		Version   string `json:"version"`
		Builddate string `json:"build_date"`
		Buildtime string `json:"build_time"`
		Buildby   string `json:"built_by"`
		Mode      string `json:"mode"`
	}

	ApiPingHandler struct{}
	ApiPingParams  struct{}
	ApiPingResult  struct {
		Timestamp float64 `json:"ts"`
	}

	ApiShutdownHandler struct{}
	ApiShutdownParams  struct {
		Time uint32 `json:"time"` // time in seconds left until the shutdown
	}

	/* Namespace Commands */
	ApiNsAddHandler struct{}
	ApiNsAddParams  struct{} /* [key tunnel] */

	ApiNsRemoveHandler struct{}
	ApiNsRemoveParams  struct{} /* [key tunnel] */

	ApiNsIterHandler struct{}
	ApiNsIterParams  struct {
		Reset bool   `json:"reset"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	}
	ApiNsIterResult struct {
		Empty   bool `json:"empty"`
		Stopped bool `json:"stopped"`

		Vec []*CTunnelDataJson `json:"data"`
	}

	ApiNsGetInfoHandler struct{}
	ApiNsGetInfoParams  struct{} /* [key tunnel] */
	ApiNsGetInfoResult  struct {
		NsInfo []CNsInfo `json:"ns_info"`
	}

	/* Ns Default Plugins */
	ApiNsSetDefPlugHandler struct{}
	ApiNsSetDefPlugParams  struct {
		DefPlugs MapJsonPlugs `json:"def_plugs"`
	}
	ApiNsGetDefPlugHandler struct{}
	ApiNsGetDefPlugResult  struct {
		DefPlugs MapJsonPlugs `json:"def_plugs"`
	}

	/* Client Commands */
	ApiClientAddHandler struct{}
	ApiClientAddParams  struct{} /* key tunnel, [ClientCmd] */

	ApiClientRemoveHandler struct{}
	ApiClientRemoveParams  struct{} /* key tunnel, [MAC] */

	ApiClientGetInfoHandler struct{}
	ApiClientGetInfoParams  struct{} /* key tunnel, [MAC] */
	ApiClientGetInfoResult  struct {
		ClientInfo []CClientInfo `json:"client_info"`
	}

	/* Client Default Plugins */
	ApiClientSetDefPlugHandler struct{}
	ApiClientSetDefPlugParams  struct {
		DefPlugs MapJsonPlugs `json:"def_plugs"`
	} /* key tunnel */
	ApiClientGetDefPlugHandler struct{}
	ApiClientGetDefPlugParams  struct{} /* key tunnel */
	ApiClientGetDefPlugResult  struct {
		DefPlugs MapJsonPlugs `json:"def_plugs"`
	}

	ApiClientIterHandler struct{}
	ApiClientIterParams  struct {
		Reset bool   `json:"reset"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	}
	ApiClientIterResult struct {
		Empty   bool      `json:"empty"`
		Stopped bool      `json:"stopped"`
		Vec     []*MACKey `json:"data"`
	}

	ApiCntHandler struct{}
	ApiCntParams  struct {
		Meta  bool     `json:"meta"`
		Zero  bool     `json:"zero"`
		Mask  []string `json:"mask"`  // get only specific counters blocks if it is empty get all
		Clear bool     `json:"clear"` // clear all counters
	}

	ApiResourceMonitorGetHandler   struct{}
	ApiResourceMonitorResetHandler struct{}
)

func (h ApiResourceMonitorGetHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiCntParams
	tctx := ctx.(*CThreadCtx)
	err := tctx.GetResourceMonitor().Update(false)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	return tctx.GetResourceMonitor().GetCountersDbVec().GeneralCounters(err, tctx, params, &p)
}

func (h ApiResourceMonitorResetHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	tctx := ctx.(*CThreadCtx)
	err := tctx.GetResourceMonitor().Update(true)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	return nil, nil
}

// ping
func (h ApiPingHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	return ApiPingResult{
		Timestamp: float64(time.Now().Second()),
	}, nil
}

// GetVersion
func (h ApiGetVersionHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	// replaced by build script
	return ApiGetVersionResult{
		Version:   "v0.1",
		Builddate: "05.05.2019",
		Buildtime: "16:00",
		Buildby:   "hhaim",
		Mode:      "emulation",
	}, nil
}

const EMU_MAJOR_VER uint8 = 1
const EMU_MINOR_VER uint8 = 1
const EMU_NAME = "EMU"

// AsyncHandler
func (h ApiSyncHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	tctx := ctx.(*CThreadCtx)
	api := tctx.rpc.mr.GetAPI()
	if len(api) == 0 {
		// generate handler
		api = RandSeq(10)
		tctx.apiHandler = api
		tctx.rpc.mr.SetAPI(api)
	}
	var p ApiSyncParams
	if err := jsonrpc.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	// agreed
	valid := false
	if (p.Major == EMU_MAJOR_VER) && (p.Minor <= EMU_MINOR_VER) && (p.Name == "EMU") {
		valid = true
	}

	if valid {
		return jsonrpc.ApiSyncResult{
			Api: tctx.apiHandler,
		}, nil
	} else {
		msg := fmt.Sprintf("Server API %s:(%d:%d) does not match the client API %s:(%d:%d) ",
			EMU_NAME, EMU_MAJOR_VER, EMU_MINOR_VER,
			p.Name, p.Major, p.Minor)
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: msg,
		}
	}
}

func (h ApiNsAddHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*CThreadCtx)
	err := tctx.AddNsRpcSlice(params)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	return nil, nil
}

func (h ApiNsRemoveHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*CThreadCtx)
	err := tctx.RemoveNsRpcSlice(params)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return nil, nil
}

func (h ApiNsIterHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiNsIterParams
	var res ApiNsIterResult
	tctx := ctx.(*CThreadCtx)
	err := tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	if p.Reset {
		res.Empty = !tctx.IterReset()
	}
	if res.Empty {
		return &res, nil
	}
	if tctx.IterIsStopped() {
		res.Stopped = true
		return &res, nil
	}

	var keys []*CTunnelKey
	res.Vec = make([]*CTunnelDataJson, 0)
	keys, err = tctx.GetNext(p.Count)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	/* covert to json format */
	for _, o := range keys {
		k := new(CTunnelDataJson)
		o.GetJson(k)
		res.Vec = append(res.Vec, k)
	}
	return &res, nil
}

func (h ApiNsGetInfoHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*CThreadCtx)
	keys, err := tctx.UnmarshalTunnels(*params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	var res ApiNsGetInfoResult
	res.NsInfo = make([]CNsInfo, len(keys))
	for i, key := range keys {
		ns := tctx.GetNs(&key)
		if ns == nil {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: "error can't find a valid namespace for this tunnel",
			}
		}

		res.NsInfo[i] = *ns.GetInfo()
	}

	return res.NsInfo, nil
}

func (h ApiShutdownHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	tctx := ctx.(*CThreadCtx)
	var p ApiShutdownParams
	err := tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	time := time.Duration(p.Time) * time.Second
	tctx.Shutdown(time)
	return nil, nil
}

func (h ApiNsSetDefPlugHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	tctx := ctx.(*CThreadCtx)
	var p ApiNsSetDefPlugParams
	err := tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	tctx.DefNsPlugs = &p.DefPlugs
	return nil, nil
}

func (h ApiNsGetDefPlugHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	tctx := ctx.(*CThreadCtx)
	var res ApiNsGetDefPlugResult
	res.DefPlugs = *tctx.DefNsPlugs

	return res, nil
}

func (h ApiClientAddHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*CThreadCtx)
	ns, err := tctx.GetNsRpc(params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	var newc CClientCmds

	err = tctx.UnmarshalValidate(*params, &newc)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	for _, c := range newc.Clients {
		client := NewClientCmd(ns, &c)

		err = ns.AddClient(client)
		if err != nil {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: err.Error(),
			}
		}

		var plugMap *MapJsonPlugs
		if c.Plugins == nil {
			/* client didn't supply plugins, use defaults */
			plugMap = ns.DefClientPlugs
		} else {
			/* client supply plugins, use them */
			plugMap = c.Plugins
		}

		if plugMap != nil {
			for plName, plData := range *plugMap {
				err = client.PluginCtx.addPlugin(plName, *plData)
				if err != nil {
					return nil, &jsonrpc.Error{
						Code:    jsonrpc.ErrorCodeInternal,
						Message: err.Error(),
					}
				}
			}
		}

		// After creating the clients and adding the plugins, we can try to attempt resolving.
		client.AttemptResolve()
	}
	return nil, nil
}

func (h ApiClientRemoveHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	ns, keys, err := getNsAndMacs(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	for _, key := range keys {
		client := ns.CLookupByMac(&key)
		if client == nil {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: "client does exits ",
			}
		}

		err = ns.RemoveClient(client)
		if err != nil {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: err.Error(),
			}
		}
	}
	return nil, nil
}

func (h ApiClientGetInfoHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	ns, keys, err := getNsAndMacs(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	res := make([]CClientInfo, len(keys))
	for i, key := range keys {
		client := ns.GetClient(&key)
		if client == nil {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: fmt.Sprintf("client with mac: %v doesn't exists", key),
			}
		}
		res[i] = *client.GetInfo()
	}

	return res, nil
}

func (h ApiClientSetDefPlugHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	tctx := ctx.(*CThreadCtx)
	var p ApiClientSetDefPlugParams
	err := tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	ns, err := tctx.GetNsRpc(params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	if ns == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidParams,
			Message: "namespace doesn't exists for set client default plugins ",
		}
	}
	ns.DefClientPlugs = &p.DefPlugs
	return nil, nil
}

func (h ApiClientGetDefPlugHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	tctx := ctx.(*CThreadCtx)
	ns, err := tctx.GetNsRpc(params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	if ns == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidParams,
			Message: "namespace doesn't exists for iteration",
		}
	}
	var p ApiClientGetDefPlugResult
	p.DefPlugs = *ns.DefClientPlugs
	return p, nil
}

func (h ApiClientIterHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiClientIterParams
	var res ApiClientIterResult
	tctx := ctx.(*CThreadCtx)

	ns, err := tctx.GetNsRpc(params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	if ns == nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidParams,
			Message: "namespace doesn't exists",
		}
	}

	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	if p.Reset {
		res.Empty = !ns.IterReset()
	}
	if res.Empty {
		return &res, nil
	}
	if ns.IterIsStopped() {
		res.Stopped = true
		return &res, nil
	}
	res.Vec, err = ns.GetNext(p.Count)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	/* covert to json format */
	return &res, nil
}

func (h ApiCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiCntParams
	tctx := ctx.(*CThreadCtx)

	return tctx.GetCounterDbVec().GeneralCounters(nil, tctx, params, &p)
}

func getNsAndMacs(ctx interface{}, params *fastjson.RawMessage) (*CNSCtx, []MACKey, error) {
	tctx := ctx.(*CThreadCtx)
	ns, err := tctx.GetNsRpc(params)
	if err != nil {
		return nil, nil, err
	}
	if ns == nil {
		return nil, nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidParams,
			Message: "namespace doesn't exists",
		}
	}

	keys, err := tctx.UnmarshalMacKeys(*params)
	if err != nil {
		return nil, nil, err
	}
	return ns, keys, nil
}

func init() {
	RegisterCB("api_sync_v2", ApiSyncHandler{}, true)
	RegisterCB("get_version", ApiGetVersionHandler{}, true)
	RegisterCB("ping", ApiPingHandler{}, false)
	RegisterCB("shutdown", ApiShutdownHandler{}, false)

	RegisterCB("ctx_add", ApiNsAddHandler{}, false)
	RegisterCB("ctx_remove", ApiNsRemoveHandler{}, false)
	RegisterCB("ctx_iter", ApiNsIterHandler{}, false)
	RegisterCB("ctx_get_info", ApiNsGetInfoHandler{}, false)
	RegisterCB("ctx_set_def_plugins", ApiNsSetDefPlugHandler{}, false)
	RegisterCB("ctx_get_def_plugins", ApiNsGetDefPlugHandler{}, false)
	RegisterCB("ctx_cnt", ApiCntHandler{}, false) // get counters

	RegisterCB("ctx_resource_monitor_get", ApiResourceMonitorGetHandler{}, false)
	RegisterCB("ctx_resource_monitor_reset", ApiResourceMonitorResetHandler{}, false)

	RegisterCB("ctx_client_add", ApiClientAddHandler{}, false)
	RegisterCB("ctx_client_remove", ApiClientRemoveHandler{}, false)
	RegisterCB("ctx_client_get_info", ApiClientGetInfoHandler{}, false)
	RegisterCB("ctx_client_set_def_plugins", ApiClientSetDefPlugHandler{}, false)
	RegisterCB("ctx_client_get_def_plugins", ApiClientGetDefPlugHandler{}, false)
	RegisterCB("ctx_client_iter", ApiClientIterHandler{}, false)
	/* TBD add client_update */

}
