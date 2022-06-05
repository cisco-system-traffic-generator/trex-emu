// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package appsim

import (
	"emu/core"
	"external/google/gopacket/layers"
	"fmt"
	"time"

	"emu/plugins/transport"

	"github.com/intel-go/fastjson"
)

// simulator for appL7Sim class to verify that it works fine with
// a simple json as an input and output to a pcap file

type simContext struct {
	program     map[string]interface{}
	template_id uint32
	is_client   bool
	ctx         *transport.TransportCtx
	Client      *core.CClient
	Ns          *core.CNSCtx
	Tctx        *core.CThreadCtx
	sim         *transportSim
	ioctl       map[string]interface{}
	stas        *AppsimStats
}

type iSockeApp interface {
	setPlug(ctx *PluginAppsimClient)
	setSim(ctx *simContext)
	setSocket(socket transport.SocketApi)
	setCtx(ctx *core.CThreadCtx)
	start()
	stop()
	onRemove()
	getCb() transport.ISocketCb
	getServerAcceptCb() transport.IServerSocketCb
}

func isValidTid(template_id uint32, program map[string]interface{}) bool {
	tl := (program)["templates"].([]interface{})
	if template_id < uint32(len(tl)) {
		return true
	}
	return false
}

func getServerPort(template_id uint32, program map[string]interface{}) string {
	tl := (program)["templates"].([]interface{})
	tid := tl[template_id]
	tido := tid.(map[string]interface{})
	ct := tido["server_template"].(map[string]interface{})
	ass := ct["assoc"].([]interface{})
	port := ass[0].(map[string]interface{})
	return fmt.Sprintf(":%v", uint64(port["port"].(float64)))
}

func getAppIoctl(template_id uint32, server bool,
	program map[string]interface{}) map[string]interface{} {
	// parse the template id and provide the tunable if exists
	var tunablel []interface{}

	if val, ok := (program)["tunable_list"]; ok {
		tunablel = val.([]interface{})
	} else {
		return nil
	}

	tl := (program)["templates"].([]interface{})
	tid := tl[template_id]
	tido := tid.(map[string]interface{})

	if server {
		ct := tido["server_template"].(map[string]interface{})
		if val, ok := ct["tunable_index"]; ok {
			index := int(val.(float64))
			return tunablel[index].(map[string]interface{})
		} else {
			return nil
		}
	} else {
		ct := tido["client_template"].(map[string]interface{})
		if val, ok := ct["tunable_index"]; ok {
			index := int(val.(float64))
			return tunablel[index].(map[string]interface{})
		} else {
			return nil
		}
	}
	return nil
}

func newSimCtx(app iSockeApp, c *core.CClient, server bool,
	params *transportSimParam,
	program map[string]interface{},
) *simContext {
	o := new(simContext)
	o.stas = new(AppsimStats)
	o.program = program
	o.template_id = 0
	o.Client = c
	o.Ns = c.Ns
	o.Tctx = c.Ns.ThreadCtx
	o.ctx = transport.GetTransportCtx(o.Client)
	app.setCtx(o.Tctx)
	app.setSim(o)
	net := "tcp"
	if params.udp {
		net = "udp"
	}
	var ioctl map[string]interface{}
	ioctl = getAppIoctl(o.template_id, server, program)

	if server {

		o.is_client = false
		o.ctx.Listen(net, ":80", app.getServerAcceptCb())
		if ioctl != nil {
			o.ioctl = ioctl // save it for the callback
		}
	} else {
		o.is_client = true
		d := "48.0.0.1:80"
		if params.ipv6 {
			d = "[2001:db8::3000:1]:80"
		}
		ap, err := o.ctx.Dial(net, d, app.getCb(), ioctl, nil, 0)
		if err != nil {
			fmt.Printf(" ERROR %v \n", err)
			return nil
		}

		app.setSocket(ap)
	}
	return o
}

type transportSimParam struct {
	emu_debug    bool
	name         string
	debug        bool
	ipv6         bool
	udp          bool
	program_json string
}

type transportSim struct {
	cnt       uint32
	param     *transportSimParam
	client    *simContext
	server    *simContext
	tctx      *core.CThreadCtx
	timer     core.CHTimerObj
	test      uint32
	clientApp iSockeApp
	serverApp iSockeApp
}

type socketAppL7 struct {
	sim     *simContext
	params  *transportSimParam
	socket  transport.SocketApi
	tctx    *core.CThreadCtx
	appl7   appL7Sim
	simPlug *PluginAppsimClient
}

func (o *socketAppL7) setCtx(ctx *core.CThreadCtx) {
	o.tctx = ctx
}

func (o *socketAppL7) OnFinish(app *appL7Sim) {
	//if o.simPlug != nil {
	//
	//}
}

func (o *socketAppL7) start() {
	o.appl7.onCreate(o.sim.program, o.sim.template_id, o.sim.is_client,
		o.socket,
		o.tctx,
		o, o.sim.stas)
	o.appl7.start()
}

//setPlug(ctx *PluginAppsimClient)
func (o *socketAppL7) setPlug(ctx *PluginAppsimClient) {
	o.simPlug = ctx
}

func (o *socketAppL7) setSim(ctx *simContext) {
	o.sim = ctx
}

func (o *socketAppL7) setSocket(socket transport.SocketApi) {
	o.socket = socket
}

func (o *socketAppL7) OnAccept(socket transport.SocketApi) transport.ISocketCb {
	o.socket = socket
	if o.sim.ioctl != nil {
		o.socket.SetIoctl(o.sim.ioctl)
	}
	o.appl7.onServerAccept(socket)
	return &o.appl7
}

func (o *socketAppL7) getServerAcceptCb() transport.IServerSocketCb {
	return o
}

func (o *socketAppL7) getCb() transport.ISocketCb {
	return &o.appl7
}

func (o *socketAppL7) onRemove() {
	o.appl7.onDelete()
}

func (o *socketAppL7) stop() {
}

func newApp(params *transportSimParam) iSockeApp {
	o := new(socketAppL7)
	if params.emu_debug {
		o.appl7.flags = o.appl7.flags | taLOG_ENABLE
	}
	return o
}

func newTransportSim(params *transportSimParam) *transportSim {
	o := new(transportSim)
	o.param = params
	var simrx core.VethIFSim
	simrx = o
	o.tctx = core.NewThreadCtx(0, 4510, true, &simrx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(o.tctx, &key)
	o.tctx.AddNs(&key, ns)

	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 1},
		core.Ipv4Key{16, 0, 0, 1},
		core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 16, 0x00, 0x00, 0x01},
		core.Ipv4Key{16, 0, 0, 2})
	client.ForceDGW = true
	client.Ipv4ForcedgMac = core.MACKey{0, 0, 1, 0, 0, 2}
	client.Ipv6ForceDGW = true
	client.Ipv6ForcedgMac = client.Ipv4ForcedgMac

	server := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 2},
		core.Ipv4Key{48, 0, 0, 1},
		core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 48, 0x00, 0x00, 0x01},
		core.Ipv4Key{48, 0, 0, 2})
	server.ForceDGW = true
	server.Ipv6ForceDGW = true
	server.Ipv4ForcedgMac = core.MACKey{0, 0, 1, 0, 0, 1}
	server.Ipv6ForcedgMac = server.Ipv4ForcedgMac

	ns.AddClient(client)
	ns.AddClient(server)

	var a fastjson.RawMessage
	a = fastjson.RawMessage(params.program_json)

	var out map[string]interface{}
	err1 := IsValidAppSimJson(&a, &out)
	if err1 != nil {
		fmt.Printf(" %v", err1)
		panic(" json is not valid")
	}

	o.clientApp = newApp(params)
	o.serverApp = newApp(params)

	o.server = newSimCtx(o.serverApp, server, true, params, out)
	o.client = newSimCtx(o.clientApp, client, false, params, out)

	o.timer.SetCB(o, nil, nil)

	o.clientApp.start()
	o.serverApp.start()
	return o
}

func (o *transportSim) OnEvent(a, b interface{}) {
}

// move packet from c->s and s->c
type pktEventTxRx struct {
	cnt          uint32
	sim          *transportSim
	m            *core.Mbuf
	timer        core.CHTimerObj
	sendToServer bool
}

func (o *pktEventTxRx) OnEvent(a, b interface{}) {

	var ps core.ParserPacketState
	ps.Tctx = o.sim.tctx
	ps.Tun = &o.sim.client.Ns.Key
	ps.M = o.m
	ps.L3 = 14 + 8
	isudp := o.sim.param.udp
	if o.sim.param.ipv6 {

		ps.L4 = ps.L3 + 40
		tcp := layers.TcpHeader(o.m.GetData()[ps.L3:ps.L4])
		ps.NextHeader = tcp.GetNextHeader()
	} else {
		ps.L4 = ps.L3 + 20
	}
	if isudp {
		ps.L7 = ps.L4 + 8

	} else {
		do := o.m.GetData()[ps.L4+12]
		tcplen := (do >> 4) << 2
		ps.L7 = ps.L4 + uint16(tcplen)
	}
	ps.L7Len = ps.M.DataLen() - ps.L7

	/*	if (o.sim.param.drop > 0.0) && (rand.Float32() < o.sim.param.drop) {
		fmt.Printf(" drop pkt : %d, to_server: %v\n", o.cnt, o.sendToServer)
		o.m.FreeMbuf()
		return
	}*/

	if o.sendToServer {
		o.sim.server.ctx.DebugSimulationHandleRxPacket(&ps)
	} else {
		o.sim.client.ctx.DebugSimulationHandleRxPacket(&ps)
	}
	ps.M.FreeMbuf()
}

func (o *transportSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	o.cnt++
	//if o.cnt == 2 {
	//   fmt.Printf(" this is it ! \n")
	//}
	e := new(pktEventTxRx)
	e.sim = o
	e.m = m
	e.cnt = o.cnt
	e.sendToServer = false
	if m.GetData()[5] == 2 { // dst MAC is 2
		e.sendToServer = true
	}
	e.timer.SetCB(e, nil, nil)
	o.tctx.GetTimerCtx().Start(&e.timer, time.Duration(500)*time.Millisecond) // delay in 5 msec
	return nil
}
