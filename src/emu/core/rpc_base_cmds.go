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

	ApiNsAddHandler struct{}
	ApiNsAddParams  struct{} /* key tunnel */

	ApiNsRemoveHandler struct{}
	ApiNsRemoveParams  struct{} /* key tunnel*/

	ApiNsIterHandler struct{}
	ApiNsIterParams  struct {
		Reset bool   `json:"reset" validate:"required"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	}
	ApiNsIterResult struct {
		Empty  bool `json:"empty"`
		Stoped bool `json:"stoped"`

		Vec []*CTunnelDataJson `json:"data"`
	}

	ApiClientAddHandler struct{}
	ApiClientAddParams  struct{} /* key tunnel,ClientCmd */

	ApiClientRemoveHandler struct{}
	ApiClientRemoveParams  struct{} /* key tunnel,MAC*/

	ApiClientIterHandler struct{}
	ApiClientIterParams  struct {
		Reset bool   `json:"reset" validate:"required"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	}
	ApiClientIterResult struct {
		Empty  bool      `json:"empty"`
		Stoped bool      `json:"stoped"`
		Vec    []*MACKey `json:"data"`
	}
)

// ping
func (h ApiPingHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	return ApiPingResult{
		Timestamp: float64(time.Now().Second()),
	}, nil
}

// GetVersion
func (h ApiGetVersionHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	return ApiGetVersionResult{
		Version:   "v0.1",
		Builddate: "05.05.2019",
		Buildtime: "16:00",
		Buildby:   "hhaim",
		Mode:      "emulation",
	}, nil
}

const EMU_MAJOR_VER uint8 = 0
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
	_, err := tctx.AddNsRpc(params)

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
	err := tctx.RemoveNsRpc(params)

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
		res.Empty = tctx.IterReset()
	}
	if res.Empty {
		return &res, nil
	}
	if tctx.IterIsStopped() {
		res.Stoped = true
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

func (h ApiClientAddHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*CThreadCtx)
	ns, err := tctx.GetNsRpc(params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	var newc CClientCmd

	err = tctx.UnmarshalValidate(*params, &newc)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	client := NewClient(ns, newc.Mac, newc.Ipv4, newc.Ipv6, newc.DgIpv4)

	err = ns.AddClient(client)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	/* TBD - register plugins */
	return nil, nil
}

func (h ApiClientRemoveHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	tctx := ctx.(*CThreadCtx)
	ns, err := tctx.GetNsRpc(params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	var key MACKey
	err = tctx.UnmarshalMacKey(*params, &key)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	client := ns.CLookupByMac(&key)
	if client == nil {
		if err != nil {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: "client does exits ",
			}
		}
	}

	err = ns.RemoveClient(client)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return nil, nil
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

	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	if p.Reset {
		res.Empty = ns.IterReset()
	}
	if res.Empty {
		return &res, nil
	}
	if ns.IterIsStopped() {
		res.Stoped = true
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

func init() {
	RegisterCB("api_sync_v2", ApiSyncHandler{}, true)
	RegisterCB("get_version", ApiGetVersionHandler{}, false)
	RegisterCB("ping", ApiPingHandler{}, false)

	RegisterCB("ns_add", ApiNsAddHandler{}, false)
	RegisterCB("ns_remove", ApiNsRemoveHandler{}, false)
	RegisterCB("ns_iter", ApiNsIterHandler{}, false)

	RegisterCB("client_add", ApiClientAddHandler{}, false)
	RegisterCB("client_remove", ApiClientRemoveHandler{}, false)
	RegisterCB("client_iter", ApiClientIterHandler{}, false)
	/* TBD add client_update */

	/*RegisterCB("client_remove", ApiPingHandler{}, false)
	RegisterCB("client_iter", ApiPingHandler{}, false)

	RegisterCB("ctx_get_counters", ApiPingHandler{}, false)*/

}
