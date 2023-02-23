// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package core

import (
	"external/osamingo/jsonrpc"
	"fmt"
	"log"
	"time"

	zmq "github.com/pebbe/zmq4"
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
	chMain2Rx  chan []byte
	chRx2Main  chan []byte
}

func RegisterCB(method string, h jsonrpc.Handler, noApi bool) {
	method_repo = append(method_repo, cRpcMethodRec{method, h, noApi})
}

func (o *CZmqJsonRPC2) SetCtx(i interface{}) {
	o.mr.SetCtx(i)
}

// SetRpcRecorder sets the RPC recorder for the method repository.
func (o *CZmqJsonRPC2) SetRpcRecorder(rpcRec *[]interface{}) {
	o.mr.SetRpcRecorder(rpcRec)
}

// NewZmqRpc create a zmq server in port
func (o *CZmqJsonRPC2) NewZmqRpc(serverPort uint16) {
	o.chMain2Rx = make(chan []byte)
	o.chRx2Main = make(chan []byte)

	context, err := zmq.NewContext()
	socket, err := context.NewSocket(zmq.REP)

	if err != nil {
		panic(err)
	}

	if socket == nil {
		panic("zmq client is nil")
	}

	o.ctx = context
	o.socket = socket
	o.serverPort = serverPort
	bindStr := fmt.Sprintf("tcp://*:%d", o.serverPort)
	if err = socket.Bind(bindStr); err != nil {
		errStr := fmt.Sprintf("Failed to create ZMQ RPC server - %v", err.Error())
		log.Fatalln(errStr)
	}

	mr := jsonrpc.NewMethodRepository()
	o.mr = mr
	o.mr.Verbose = false

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
		msg, err := o.socket.RecvBytes(0)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
		} else {
			o.chRx2Main <- msg
			res := <-o.chMain2Rx
			o.socket.SendBytes(res, 0)

		}
	}
}

// GetC return the channel
func (o *CZmqJsonRPC2) GetC() chan []byte {
	return o.chRx2Main
}

// StartRxThread start a thread to handle the Req/Res
func (o *CZmqJsonRPC2) StartRxThread() {
	go o.rxThread()
}

// Delete  this is an help
func (o *CZmqJsonRPC2) Delete() {
	o.socket.Close()
	o.ctx.Term()
}

// HandleReqToChan input buffer return resonse to chan
func (o *CZmqJsonRPC2) HandleReqToChan(req []byte) {
	res := o.mr.ServeBytesCompress(req)
	o.chMain2Rx <- res
}

// HandleReq input buffer return buffer
func (o *CZmqJsonRPC2) HandleReq(req []byte) []byte {
	return (o.mr.ServeBytesCompress(req))
}

// HandleReqRes this is an help
func (o *CZmqJsonRPC2) HandleReqRes() {
	msg, err := o.socket.RecvBytes(0)
	if err != nil {
		time.Sleep(10 * time.Millisecond)
	} else {
		res := o.HandleReq(msg)
		o.socket.SendBytes(res, 0)
	}
}
