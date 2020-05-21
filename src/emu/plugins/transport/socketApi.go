// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"errors"
	"net"
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

type ISocketCb interface {
	// callback in case of Rx side events
	OnRxEvent(event SocketEventType)
	// callback in case of new data
	OnRxData(d []byte)
	// callback in case of new tx events
	OnTxEvent(event SocketEventType)
}

type SocketApi interface {
	Connect() SocketErr  // connect to remote addr, for client side
	Listen() SocketErr   //
	Close() SocketErr    // close connection **after** all the tx queue was flushed, SocketClosed event will be called
	Shutdown() SocketErr // shutdown connection immediately, there is no wait for tx queue
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	IsStream() bool       // return true if it is stream based (e.g. tcp) or message based (e.g udp)
	NeedConnection() bool // tcp return true, udp return false
	GetLastError() SocketErr
	SetIoctl(m map[string]interface{}) error // set ioctl options to the socket e.g. {"no_delay":0}
	GetIoctl(m map[string]interface{}) error // get the value for each key
	/*
		queued: true, the buffer was queued in the socket internal buffer, it is possible to queue more without a need to wait
				false the buffer queued but there is a need to wait for SocketTxMore for writing more as the queue is full.
				writing after this state will return an error SeWRITE_WHILE_DRAIN
	*/
	Write(buf []byte) (err SocketErr, queued bool)
}
