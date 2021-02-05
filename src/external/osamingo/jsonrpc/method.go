package jsonrpc

import (
	"errors"
)

type (
	// A MethodRepository has JSON-RPC method functions.
	MethodRepository struct {
		r       map[string]Metadata
		Verbose bool // Verbose mode, print the RPC req/res to standart output.
		Capture bool // Capture the RPC req/res into rpcRec
		// A slice that records RPC req/res.  This is part of `ctx`.
		// But `ctx` can't be type casted to its original type (circular dep.) hence we pass it as
		// a parameter and we append directly to it.
		rpcRec *[]interface{}
		api    string
		ctx    interface{}
	}
	// Metadata has method meta data.
	Metadata struct {
		Handler Handler
		NoApi   bool
	}
)

// NewMethodRepository returns new MethodRepository.
func NewMethodRepository() *MethodRepository {
	return &MethodRepository{
		r: map[string]Metadata{},
	}
}

// SetCtx set context, pass to each callback
func (mr *MethodRepository) SetCtx(i interface{}) {
	mr.ctx = i
}

// SetRpcRecorder sets the RPC recorder which in case Capture is set, will
// record the RPC rec/res.
func (mr *MethodRepository) SetRpcRecorder(rec *[]interface{}) {
	mr.rpcRec = rec
}

// TakeMethod takes jsonrpc.Func in MethodRepository.
func (mr *MethodRepository) TakeMethod(r *Request) (Handler, *Error, bool) {
	if r.Method == "" || r.Version != Version {
		return nil, ErrInvalidParams(), false
	}

	md, ok := mr.r[r.Method]
	if !ok {
		return nil, ErrMethodNotFound(), false
	}

	return md.Handler, nil, md.NoApi
}

//SetAPI set the random value of the API
func (mr *MethodRepository) SetAPI(api string) {
	mr.api = api
}

//GetAPI get the random API key
func (mr *MethodRepository) GetAPI() string {
	return mr.api
}

// RegisterMethod registers jsonrpc.Func to MethodRepository.
func (mr *MethodRepository) RegisterMethod(method string, h Handler, noApi bool) error {
	if method == "" || h == nil {
		return errors.New("jsonrpc: method name and function should not be empty")
	}
	mr.r[method] = Metadata{
		Handler: h,
		NoApi:   noApi,
	}
	return nil
}

// Methods returns registered methods.
func (mr *MethodRepository) Methods() map[string]Metadata {
	ml := make(map[string]Metadata, len(mr.r))
	for k, md := range mr.r {
		ml[k] = md
	}
	return ml
}
