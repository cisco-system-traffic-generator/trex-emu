// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

// simple pool for allocating source port.
// there is an assumption that each client will use small number of ports
// because of that we keep table for all the protocols and assume it is small, so speed is not a factor

type srcPortmap map[uint16]bool

const (
	SRC_PORT_MIN   = 0xFF00 // to make the filter easy (from trex->emu)
	SRC_PORT_MAX   = 0xFFFE
	SRC_PORT_RETRY = 1000
)

type srcPortManager struct {
	m       srcPortmap
	ctx     *TransportCtx
	srcPort uint16
}

func (o *srcPortManager) init(ctx *TransportCtx) {
	o.m = make(srcPortmap)
	o.ctx = ctx
	o.srcPort = SRC_PORT_MIN
}

func (o *srcPortManager) incPort() {
	o.srcPort++
	if o.srcPort > SRC_PORT_MAX {
		o.srcPort = SRC_PORT_MIN
	}
}

// return 0 in case of error
func (o *srcPortManager) allocPort(proto uint8) uint16 {

	for i := 0; i < SRC_PORT_RETRY; i++ {
		var port uint16
		port = o.srcPort
		_, ok := o.m[port]
		if ok == false {
			o.m[port] = true
			o.srcPort++
			o.ctx.flowTableStats.src_port_active++
			o.ctx.flowTableStats.src_port_alloc++
			return port
		}
		o.incPort()
	}
	o.ctx.flowTableStats.src_port_err_get++
	return (0) // the src port is full
}

func (o *srcPortManager) freePort(proto uint8, port uint16) {

	val, ok := o.m[port]
	if ok {
		if val == true {
			o.ctx.flowTableStats.src_port_active--
			o.ctx.flowTableStats.src_port_free++
			delete(o.m, port)
		}
	} else {
		o.ctx.flowTableStats.src_port_err_return++
		// error
	}
}
