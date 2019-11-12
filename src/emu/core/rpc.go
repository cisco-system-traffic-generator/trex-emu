package core

import (
	"external/osamingo/jsonrpc"
	zmq "external/pebbe/zmq4"
	"fmt"
	"log"
)

var method_repo []cRpcMethodRec = make([]cRpcMethodRec, 0)

type cRpcMethodRec struct {
	method string
	h      jsonrpc.Handler
	noApi  bool
}

type CZmqJsonRPC2 struct {
	ctx        *zmq.Context
	socket     *zmq.Socket
	serverPort uint16
	mr         *jsonrpc.MethodRepository
	cn         chan []byte
}

func RegisterCB(method string, h jsonrpc.Handler, noApi bool) {
	method_repo = append(method_repo, cRpcMethodRec{method, h, noApi})
}

func (o *CZmqJsonRPC2) SetCtx(i interface{}) {
	o.mr.SetCtx(i)
}

// NewZmqRpc create a zmq server in port
func (o *CZmqJsonRPC2) NewZmqRpc(serverPort uint16) {
	context, err := zmq.NewContext()
	socket, err := context.NewSocket(zmq.REP)
	o.cn = make(chan []byte)

	if err != nil {
		panic(err)
	}

	if socket == nil {
		panic(" zmq client is nil")
	}

	o.ctx = context
	o.socket = socket
	o.serverPort = serverPort
	bindStr := fmt.Sprintf("tcp://*:%d", o.serverPort)
	socket.Bind(bindStr)

	mr := jsonrpc.NewMethodRepository()
	o.mr = mr
	o.mr.Verbose = true

	for _, rec := range method_repo {
		if o.mr.Verbose {
			fmt.Printf("register %s \n", rec.method)
		}
		if err := mr.RegisterMethod(rec.method, rec.h, rec.noApi); err != nil {
			log.Fatalln(err)
		}
	}
}

func (o *CZmqJsonRPC2) rxThread() {
	for {
		msg, _ := o.socket.RecvBytes(0)
		o.cn <- msg
		res := <-o.cn
		o.socket.SendBytes(res, 0)
	}
}

// GetC return the channel
func (o *CZmqJsonRPC2) GetC() chan []byte {
	return o.cn
}

// StartRxThread start a thread to handle the Req/Res
func (o *CZmqJsonRPC2) StartRxThread() {
	go o.rxThread()
}

// Delete  this is an help
func (o *CZmqJsonRPC2) Delete() {
	o.socket.Close()
}

// HandleReqToChan input buffer return resonse to chan
func (o *CZmqJsonRPC2) HandleReqToChan(req []byte) {
	res := o.mr.ServeBytesCompress(req)
	o.cn <- res
}

// HandleReq input buffer return buffer
func (o *CZmqJsonRPC2) HandleReq(req []byte) []byte {
	return (o.mr.ServeBytesCompress(req))
}

// HandleReqRes this is an help
func (o *CZmqJsonRPC2) HandleReqRes() {
	msg, _ := o.socket.RecvBytes(0)
	res := o.HandleReq(msg)
	o.socket.SendBytes(res, 0)
}
