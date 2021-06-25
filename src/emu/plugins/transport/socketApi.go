// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"errors"
	"net"
)

type SocketCapType uint16

const (
	SocketCapStream     = 0x1 // socket is stream based
	SocketCapConnection = 0x2 // socket is stream connection oriented (need to wait for SocketEventConnected)
)

// Socket error value
type SocketErr uint8

// TLSType known values.
const (
	SeOK                   SocketErr = 0
	SeALREADY_OPEN         SocketErr = 1
	SeECONNREFUSED         SocketErr = 2
	SeECONNRESET           SocketErr = 3
	SeETIMEDOUT            SocketErr = 4
	SeECONNABORTED         SocketErr = 5
	SeENOBUFS              SocketErr = 6
	SeCONNECTION_IS_CLOSED SocketErr = 7
	SeWRITE_WHILE_DRAIN    SocketErr = 8
	SeUNRESOLVED           SocketErr = 9
)

// String shows the register type nicely formatted
func (tt SocketErr) String() string {
	switch tt {
	default:
		return "Unknown"
	case SeOK:
		return "ok"
	case SeALREADY_OPEN:
		return "Socket already open"
	case SeECONNREFUSED:
		return "Socket connection refused"
	case SeECONNRESET:
		return "Socket reset"
	case SeETIMEDOUT:
		return "Socket timeout"
	case SeECONNABORTED:
		return "Socket connection aborted"
	case SeENOBUFS:
		return "Socket no buffers"
	case SeCONNECTION_IS_CLOSED:
		return "Socket is already closed"
	case SeWRITE_WHILE_DRAIN:
		return "Socket queue is full, wait for tx event"
	case SeUNRESOLVED:
		return "Socket destination MAC address unresolved."
	}
}

func (tt SocketErr) Error() error {
	return errors.New(tt.String())
}

type SocketEventType uint16

const (
	SocketEventConnected   = 0x1  // socket is connected, in case of TCP e.g. after syn,syn-ack
	SocketRemoteDisconnect = 0x10 //remote close the connection
	SocketRxMask           = 0x1F | SocketClosed

	SocketTxEmpty = 0x20 // the Tx queue queue is empty
	SocketTxMore  = 0x40 // the Tx queue queue watermark is low

	SocketTxMask = (SocketTxEmpty | SocketTxMore)

	SocketRxData = 0x80  // event of data
	SocketClosed = 0x100 // socket closed, need to verify GetLastError() for no errors, could be called due to an error
)

func (o SocketEventType) String() string {
	s := "["
	if o&SocketEventConnected > 0 {
		s += "SocketEventConnected "
	}
	if o&SocketRemoteDisconnect > 0 {
		s += "SocketRemoteDisconnect "
	}
	if o&SocketTxEmpty > 0 {
		s += "SocketTxEmpty "
	}
	if o&SocketTxMore > 0 {
		s += "SocketTxMore "
	}

	if o&SocketRxData > 0 {
		s += "SocketRxData "
	}
	if o&SocketRxData > 0 {
		s += "SocketRxData "
	}

	s += "]"
	return s
}

type IoctlMap map[string]interface{}

type ISocketCb interface {
	// callback in case of Rx side events
	OnRxEvent(event SocketEventType)
	// callback in case of new data
	OnRxData(d []byte)
	// callback in case of new tx events
	OnTxEvent(event SocketEventType)
}

type IServerSocketCb interface {
	// callback in case of a new flow, return callback or nil
	OnAccept(socket SocketApi) ISocketCb
}

type SocketApi interface {

	// public
	Close() SocketErr    // close the connection **after** all the tx queue was flushed, SocketClosed event will be called
	Shutdown() SocketErr // shutdown connection immediately, there is no need to wait for tx queue
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	GetCap() SocketCapType // get the capability of the socket e.g. SocketCapStream
	GetLastError() SocketErr
	SetIoctl(m IoctlMap) error // set ioctl options to the socket e.g. {"no_delay":0}
	GetIoctl(m IoctlMap) error // get the value for each key
	/*
		queued: true, the buffer was queued in the socket internal buffer, it is possible to queue more without a need to wait.
				In this case the buffer was copied to the internal buffer and can be touched
				false the buffer queued but there is a need to wait for SocketTxMore for writing more as the queue is full.
				      the buffer can't be used until you get  SocketTxMore event
				writing after this state will return an error SeWRITE_WHILE_DRAIN
	*/
	Write(buf []byte) (err SocketErr, queued bool)
	GetL7MTU() uint16       // Returns the L7 MTU.
	IsIPv6() bool           // Returns True if the IP layer is IPv6, False if it is IPv4.
	GetSocket() interface{} // return internal raw socket *TcpSocket for testing
}

// internal API for socket
type internalSocketApi interface {
	init(client *core.CClient, ctx *TransportCtx)
	connect() SocketErr
	initphase2(cb ISocketCb, dstMac *core.MACKey)

	setTupleIpv4(src core.Ipv4Key,
		dst core.Ipv4Key,
		srcPort uint16,
		dstPort uint16)
	setTupleIpv6(src core.Ipv6Key,
		dst core.Ipv6Key,
		srcPort uint16,
		dstPort uint16)

	setPortAlloc(enable bool)
	getProto() uint8
	listen() SocketErr
	getServerIoctl() IoctlMap
	clearServerIoctl()
}

// GetTransportCtx Allocate transport layer and add it to client
func GetTransportCtx(c *core.CClient) *TransportCtx {
	ti := c.GetTransportCtx()
	var cfg TransportCtxCfg
	if ti == nil {
		tc := newCtx(c)
		// take the json from the plugin
		plug := c.PluginCtx.Get(TRANS_PLUG)

		if plug != nil && plug.Ext != nil {
			pClient := plug.Ext.(*PluginTransClient)
			json := pClient.initJson
			if json != nil {
				c.Ns.ThreadCtx.UnmarshalValidate(json, &cfg)
				tc.setCfg(&cfg)
			}
		}
		c.SetTransportCtx(tc)
		return tc
	}
	return ti.(*TransportCtx)
}

func getTransportCtxIfExist(c *core.CClient) *TransportCtx {
	ti := c.GetTransportCtx()
	if ti == nil {
		return nil
	}
	return ti.(*TransportCtx)
}
