package rpc

import (
	"emu/core"
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

var apiHandler string
var RcpCtx CZmqJsonRPC2

// AsyncHandler
func (h ApiSyncHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	api := RcpCtx.mr.GetAPI()
	if len(api) == 0 {
		// generate handler
		api = core.RandSeq(10)
		apiHandler = api
		RcpCtx.mr.SetAPI(api)
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
			Api: apiHandler,
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

func init() {
	RegisterCB("api_sync_v2", ApiSyncHandler{}, true)
	RegisterCB("get_version", ApiGetVersionHandler{}, false)
	RegisterCB("ping", ApiPingHandler{}, false)
}
