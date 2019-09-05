package jsonrpc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/intel-go/fastjson"
	"github.com/osamingo/jsonrpc"
)

// Handler links a method of JSON-RPC request.
type Handler interface {
	ServeJSONRPC(c context.Context, params *fastjson.RawMessage) (result interface{}, err *Error)
}

// ServeBytes provides basic JSON-RPC handling of bytes and return bytes.
// context is nill in this case
func (mr *MethodRepository) ServeBytes(req []byte) []byte {

	rs, batch, err := ParseRequestBytes(req)
	if err != nil {
		b, _ := GetResponseBytes([]*Response{
			{
				Version: jsonrpc.Version,
				Error:   err,
			},
		}, false)
		return b
	}

	resp := make([]*Response, len(rs))
	for i := range rs {
		resp[i] = mr.InvokeMethod(nil, rs[i])
	}

	b, _ := GetResponseBytes(resp, batch)

	return b
}

// ServeString provides basic JSON-RPC handling of string to string
func (mr *MethodRepository) ServeString(req string) string {
	return string(mr.ServeBytes([]byte(req)))
}

// ServeHTTP provides basic JSON-RPC handling.
func (mr *MethodRepository) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	rs, batch, err := ParseRequest(r)
	if err != nil {
		err := SendResponse(w, []*Response{
			{
				Version: Version,
				Error:   err,
			},
		}, false)
		if err != nil {
			fmt.Fprint(w, "Failed to encode error objects")
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	resp := make([]*Response, len(rs))
	for i := range rs {
		resp[i] = mr.InvokeMethod(r.Context(), rs[i])
	}

	if err := SendResponse(w, resp, batch); err != nil {
		fmt.Fprint(w, "Failed to encode result objects")
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// InvokeMethod invokes JSON-RPC method.
func (mr *MethodRepository) InvokeMethod(c context.Context, r *Request) *Response {
	var h Handler
	res := NewResponse(r)
	h, res.Error = mr.TakeMethod(r)
	if res.Error != nil {
		return res
	}
	res.Result, res.Error = h.ServeJSONRPC(WithRequestID(c, r.ID), r.Params)
	if res.Error != nil {
		res.Result = nil
	}
	return res
}
