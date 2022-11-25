// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package appsim

/*
Transport simulation layer for application, similar to the TRex ASTF mode.

for example it would be possible to simulate a HTTP/SSDP program

	prog_c = ASTFProgram()
	prog_c.send(http_req)
	prog_c.recv(len(http_response))

	prog_s = ASTFProgram()
	prog_s.recv(len(http_req))
	prog_s.send(http_response)

*/

import (
	"emu/core"
	"encoding/base64"
	"external/osamingo/jsonrpc"
	"fmt"
	"math/rand"
	"time"

	"emu/plugins/transport"

	"github.com/intel-go/fastjson"
)

const (
	APPSIM_PLUG = "appsim"
	/* state of each client */
)

type AppsimRec struct {
	Cps    float64 `json:"cps"`    // new connection per second
	CSType string  `json:"t"`      // "c" for client and "s" for server
	Tid    uint32  `json:"tid"`    //template id from global ns program
	Ipv6   bool    `json:"ipv6"`   //is ipv6
	Stream bool    `json:"stream"` //udp or tcp
	DestIP string  `json:"dst"`    //dest ip either ipv4 or ipv6 (base on ipv6 value)
	Limit  uint32  `json:"limit"`  //limit the number of new flows. zero means unlimited
}

type AppsimInit struct {
	Data map[string]AppsimRec `json:"data"`
}

type appsimStream struct {
	cps      float64
	isClient bool
	tid      uint32
	ipv6     bool
	stream   bool
	dst      string
	limit    uint32

	timerw *core.TimerCtx
	plug   *PluginAppsimClient
	timer  core.CHTimerObj
}

func (o *appsimStream) onCreate(plug *PluginAppsimClient) {
	o.plug = plug
	o.timerw = o.plug.timerw
	o.timer.SetCB(o, 0, 0) // Set callback for timer
}

func (o *appsimStream) startTicks() {
	ticks := o.timerw.DurationToTicks(time.Duration(int64(1000.0/o.cps)) * time.Millisecond)
	if ticks == 0 {
		ticks = 1
	}
	o.timerw.StartTicks(&o.timer, ticks)
}

func (o *appsimStream) onRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *appsimStream) createNewFlow() {
	// create a sim object
	sim := new(simContext)
	sim.stas = &o.plug.stats
	sim.program = o.plug.getGlobalProgram()

	sim.template_id = o.tid
	sim.Client = o.plug.Client
	sim.Ns = o.plug.Ns
	sim.Tctx = o.plug.Ns.ThreadCtx
	sim.ctx = transport.GetTransportCtx(o.plug.Client)
	app := new(socketAppL7)
	app.setCtx(sim.Tctx)
	app.setSim(sim)

	net := "tcp"
	if !o.stream {
		net = "udp"
	}
	var ioctl map[string]interface{}
	ioctl = getAppIoctl(sim.template_id, !o.isClient, sim.program)

	sim.is_client = true
	d := o.dst
	fmt.Printf(" %+v \n", ioctl)
	ap, err := sim.ctx.Dial(net, d, app.getCb(), ioctl, nil, 0)
	if err != nil {
		fmt.Printf(" error dial %v \n ", err)
		o.plug.stats.eventDropConnectionErr++
	}
	app.setSocket(ap)
	app.start()
}

func (o *appsimStream) OnEvent(a, b interface{}) {

	o.createNewFlow()
	var restart bool
	restart = true
	if o.limit > 0 {
		if o.limit > 1 {
			o.limit--
		} else {
			restart = false
		}
	}
	if restart {
		o.startTicks()
	}
}

type appsimDb map[string]*appsimStream

type AppsimNsStats struct {
	errLoadApp uint64
}

func NewAppSimNsStatsDb(o *AppsimNsStats) *core.CCounterDb {
	db := core.NewCCounterDb(APPSIM_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.errLoadApp,
		Name:     "errLoadApp",
		Help:     "loading app error ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})
	return db
}

type AppsimStats struct {
	eventTx                uint64
	eventRx                uint64
	BytesTx                uint64
	BytesRx                uint64
	eventDropConnectionErr uint64
	eventUdpKeepAliveErr   uint64
	eventNewFlow           uint64
	eventDelFlow           uint64
	eventInvalidApp        uint64
	eventInvalidtid        uint64
}

func NewAppSimStatsDb(o *AppsimStats) *core.CCounterDb {
	db := core.NewCCounterDb(APPSIM_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.eventInvalidtid,
		Name:     "eventInvalidtid",
		Help:     "invalid tid in client json ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventInvalidApp,
		Name:     "eventInvalidApp",
		Help:     "invalid app json ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventTx,
		Name:     "eventTx",
		Help:     "write event ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventRx,
		Name:     "event Rx",
		Help:     "event rx",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.BytesTx,
		Name:     "bytesTx",
		Help:     "tx bytes ",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.BytesRx,
		Name:     "bytesRx",
		Help:     "rx bytes ",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventDropConnectionErr,
		Name:     "DropConnection",
		Help:     "drop connection ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventUdpKeepAliveErr,
		Name:     "UdpKeepaliveConnection",
		Help:     "udp keepalive error",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventNewFlow,
		Name:     "eventNewFlow",
		Help:     "new flow ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.eventDelFlow,
		Name:     "delFlow",
		Help:     "del flow ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

const apVAR_NUM_SIZE = 2

type tcp_app_state int

const (
	te_NONE             = 0
	te_WAIT_FOR_CONNECT = 16
	te_SEND             = 17 /* sending trafic task could be long*/
	te_WAIT_RX          = 18 /* wait for traffic to be Rx */
	te_DELAY            = 19
	te_CLOSED           = 20
)

func (o tcp_app_state) String() string {
	switch o {
	case te_NONE:
		return "NONE"
	case te_WAIT_FOR_CONNECT:
		return "WAIT_FOR_CONNECT"
	case te_SEND:
		return "SEND"
	case te_WAIT_RX:
		return "WAIT_RX"
	case te_DELAY:
		return "DELAY"
	case te_CLOSED:
		return "CLOSED"
	}
	return fmt.Sprintf("unknow %v", int(o))
}

type tcp_app_flags = uint16

const (
	taRX_DISABLED         = 0x2
	taTIMER_INIT_WAS_DONE = 0x4
	taDO_RX_CLEAR         = 0x400
	taLOG_ENABLE          = 0x800
)

type iAppL7SimCb interface {
	// callback in case of a new flow, return callback or nil
	OnFinish(app *appL7Sim)
}

type appL7Sim struct {
	bufferList         [][]byte
	stat               *AppsimStats
	program            map[string]interface{}
	cmda               []interface{}
	template_id        uint32
	is_client          bool
	timerw             *core.TimerCtx
	vars               [apVAR_NUM_SIZE]uint64
	tick_vars          [apVAR_NUM_SIZE]uint64
	timer              core.CHTimerObj
	udp_ka_timer       core.CHTimerObj
	l7check_enable     bool
	flags              tcp_app_flags
	state              tcp_app_state
	debug_id           uint8
	cmd_index          uint32
	cmd_rx_bytes       uint64
	cmd_rx_bytes_wm    uint64
	socket             transport.SocketApi
	tctx               *core.CThreadCtx
	cb                 iAppL7SimCb
	no_close           bool
	timerCb            UDPKeepAliveTimer
	udp_keepalive      bool
	udp_keepalive_msec uint32
}

type UDPKeepAliveTimer struct {
}

func (o *UDPKeepAliveTimer) OnEvent(a, b interface{}) {
	pi := a.(*appL7Sim)
	pi.onUDPKeepAliveTimerEvent()
}

func (o *appL7Sim) onCreate(program map[string]interface{},
	template_id uint32,
	is_client bool,
	socket transport.SocketApi,
	tctx *core.CThreadCtx,
	cb iAppL7SimCb,
	stat *AppsimStats,
) {
	o.stat = stat
	o.program = program
	o.template_id = template_id
	o.is_client = is_client
	o.timerw = tctx.GetTimerCtx()
	o.socket = socket
	o.tctx = tctx
	o.timer.SetCB(o, 0, 0) // Set callback for timer
	o.udp_ka_timer.SetCB(&o.timerCb, o, 0)
	o.cb = cb
}

func (o *appL7Sim) onUDPKeepAliveTimerEvent() {
	if o.udp_keepalive == false {
		o.udpKeealiveTimerRestart()
	} else {
		if o.isLog() {
			fmt.Printf(" client :(%v) udp keepalive event \n", o.is_client)
		}
		o.stat.eventUdpKeepAliveErr++
		o.changeState(te_CLOSED)
		o.socket.Close()
		// end
	}
}

func (o *appL7Sim) udpKeealiveTimerRestart() {
	if o.udp_keepalive_msec == 0 {
		return
	}
	if o.udp_ka_timer.IsRunning() {
		o.timerw.Stop(&o.udp_ka_timer)
	}
	ticks := o.timerw.DurationToTicks(time.Duration(int64(o.udp_keepalive_msec)) * time.Millisecond)
	if ticks == 0 {
		ticks = 1
	}
	o.udp_keepalive = true
	o.timerw.StartTicks(&o.udp_ka_timer, ticks)
}

func (o *appL7Sim) onDelete() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	if o.udp_ka_timer.IsRunning() {
		o.timerw.Stop(&o.udp_ka_timer)
	}
}

func (o *appL7Sim) isStream() bool {
	if o.socket.GetCap()&transport.SocketCapStream == 1 {
		return true
	} else {
		return false
	}
}

func (o *appL7Sim) start() {
	bl := (o.program)["buf_list"].([]interface{})
	for _, k := range bl {
		var b []byte
		b, _ = base64.StdEncoding.DecodeString(k.(string))
		o.bufferList = append(o.bufferList, b)
	}

	tl := (o.program)["templates"].([]interface{})
	tid := tl[o.template_id]
	tido := tid.(map[string]interface{})
	pindex := 0

	if o.is_client {
		ct := tido["client_template"].(map[string]interface{})
		pindex = int(ct["program_index"].(float64))
	} else {
		ct := tido["server_template"].(map[string]interface{})
		pindex = int(ct["program_index"].(float64))
	}

	pl := (o.program)["program_list"].([]interface{})
	cmds := pl[pindex].(map[string]interface{})
	o.cmda = cmds["commands"].([]interface{})
	if o.socket != nil {
		o.onNewSocket()
	}
}

func (o *appL7Sim) onNewSocket() {
	if o.isStream() { //  client or server need to wait
		o.changeState(te_WAIT_FOR_CONNECT)
	} else {
		o.processCmds()
		o.stat.eventNewFlow++
	}
}

func (o *appL7Sim) onServerAccept(socket transport.SocketApi) {
	o.socket = socket
	o.onNewSocket()
}

// timer callback
func (o *appL7Sim) OnEvent(a, b interface{}) {
	o.processCmds()
}

func (o *appL7Sim) getBuffer(bufIndex uint32) []byte {
	return o.bufferList[bufIndex]
}

func (o *appL7Sim) processDelayRand(min_usec float64, max_usec float64) {
	var choosen float64
	if max_usec <= min_usec {
		choosen = min_usec
	} else {
		choosen = (rand.Float64() * (max_usec - min_usec)) + min_usec
	}

	ticks := o.timerw.DurationToTicks(time.Duration(int64(choosen)) * time.Microsecond)
	if ticks == 0 {
		ticks = 1
	}
	o.timerw.StartTicks(&o.timer, ticks)
	o.changeState(te_DELAY)
}

func (o *appL7Sim) processDelay(usec float64) {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}

	// at least one tick
	ticks := o.timerw.DurationToTicks(time.Duration(int64(usec)) * time.Microsecond)
	if ticks == 0 {
		ticks = 1
	}
	o.timerw.StartTicks(&o.timer, ticks)
	o.changeState(te_DELAY)
}

// next command
func (o *appL7Sim) checkRxCondition() bool {

	if o.cmd_rx_bytes >= o.cmd_rx_bytes_wm {
		o.cmd_rx_bytes -= o.cmd_rx_bytes_wm
		if o.flags&taDO_RX_CLEAR > 0 {
			o.cmd_rx_bytes = 0
			o.flags &= (^(uint16)(taDO_RX_CLEAR))
		}
		return true
	}
	return false
}

func (o *appL7Sim) processRx(min_bytes uint64, clear bool) bool {
	if clear {
		o.flags |= taDO_RX_CLEAR
	} else {
		o.flags &= (^(uint16)(taDO_RX_CLEAR))
	}
	o.changeState(te_WAIT_RX)
	o.cmd_rx_bytes_wm = min_bytes

	r := o.checkRxCondition()
	return r
}

// processOneCmd exec one command return
// True : in case of a need for nextCmd
// False : there is no next command
func (o *appL7Sim) processOneCmd(cmd map[string]interface{}) bool {
	cmd_name := cmd["name"].(string)
	o.udp_keepalive = false

	if o.isLog() {
		fmt.Printf(" client :(%v) index: %d cmd: %+v \n", o.is_client, o.cmd_index, cmd)
	}

	switch cmd_name {
	case "tx":
		bi := uint32(cmd["buf_index"].(float64))
		b := o.getBuffer(bi)
		o.stat.BytesTx += uint64(len(b))
		o.stat.eventTx += 1
		r, queued := o.socket.Write(b)
		if r != 0 {
			panic("error to write to socket ")
		}

		if queued {
			return true
		} else {
			if o.isLog() {
				fmt.Printf(" client :(%v) tx_queue_full \n", o.is_client)
			}

			o.changeState(te_SEND)
		}

	case "rx":
		min_bytes := uint64(cmd["min_bytes"].(float64))
		clear := false
		if val, ok := cmd["clear"]; ok {
			clear = val.(bool)
		}
		if o.processRx(min_bytes, clear) {
			return true
		}
		break

	case "delay":
		o.processDelay(cmd["usec"].(float64))
		break

	case "delay_rnd":
		o.processDelayRand(cmd["min_usec"].(float64), cmd["max_usec"].(float64))

	case "keepalive":

		msec := uint64(cmd["msec"].(float64))
		/*rx_mode := false
		if val, ok := cmd["rx_mode"]; ok {
			rx_mode = val.(bool)
		}*/
		if msec > 0 {
			o.udp_keepalive_msec = uint32(msec)
			o.udpKeealiveTimerRestart()
		}
		return true
		break

	case "tx_msg":
		o.state = te_NONE
		bi := uint32(cmd["buf_index"].(float64))
		b := o.getBuffer(bi)
		if !o.isStream() {
			o.stat.BytesTx += uint64(len(b))
			o.stat.eventTx += 1
			o.socket.Write(b)
		}
		return true
		break

	case "rx_msg":
		min_pkts := uint64(cmd["min_pkts"].(float64))
		clear := false
		if val, ok := cmd["clear"]; ok {
			clear = val.(bool)
		}
		if o.processRx(min_pkts, clear) {
			return true
		}

		break

	case "close_msg":
		o.changeState(te_CLOSED)
		o.socket.Close()
		return true
		break

	case "connect":
		return true
		break
	case "reset":
		o.changeState(te_CLOSED)
		o.socket.Shutdown()
		return true
		break
	case "nc":
		o.no_close = true
		return true
		break
	case "set_var":
		varId := uint64(cmd["id"].(float64))
		varVal := uint64(cmd["val"].(float64))
		if varId < uint64(apVAR_NUM_SIZE) {
			o.vars[varId] = varVal
		}
		return true
		break

	case "set_tick_var":
		varId := uint64(cmd["id"].(float64))
		if varId < uint64(apVAR_NUM_SIZE) { //TBD
			//o.tick_vars[varId] = o.timerw.getTick()
		}
		return true
		break

	case "jmp_nz":

		varId := uint64(cmd["id"].(float64))
		varOffset := uint32(cmd["offset"].(float64))
		if o.isLog() {
			fmt.Printf(" client :(%v) jmp_nz val-id: %d val: %v \n", o.is_client, varId, o.vars[varId])
		}
		o.vars[varId]--
		if o.vars[varId] > 0 {
			o.cmd_index += (varOffset - 1)
			o.checkCmdIndexOverflow()
		}
		return true
		break

	case "jmp_dp":
		break

	case "tx_mode":
		break

	default:
		break
	}
	return false
}

func (o *appL7Sim) isLog() bool {
	if o.flags&taLOG_ENABLE > 0 {
		return true
	} else {
		return false
	}
}

func (o *appL7Sim) doCloseFlow() {
	if o.isLog() {
		fmt.Printf(" client :(%v) OnFlowClose \n", o.is_client)
	}
	if o.is_client {
		return
	}

	if o.state == te_CLOSED {
		return
	}
	if !o.no_close {
		o.changeState(te_CLOSED)
		o.socket.Close()
	} else {
		if o.isLog() {
			fmt.Printf(" client :(%v) no close \n", o.is_client)
		}
	}
}

func (o *appL7Sim) checkCmdIndexOverflow() {
	if o.cmd_index > uint32(len(o.cmda)) {
		o.cmd_index = uint32(len(o.cmda))
	}
}

func (o *appL7Sim) isLastCommand() bool {
	if o.cmd_index >= uint32(len(o.cmda)) {
		return true
	}
	return false
}

func (o *appL7Sim) checkLastCmd() bool {
	if o.state == te_CLOSED {
		return true
	}
	if o.isLastCommand() {
		o.doCloseFlow()
		return true
	}
	return false
}

// return in case we finished
func (o *appL7Sim) nextCmd() bool {
	if !o.isLastCommand() {
		o.cmd_index++
	}

	if o.isLastCommand() {
		return true
	}
	return false
}

// transport events - start
func (o *appL7Sim) OnRxEvent(event transport.SocketEventType) {
	o.udp_keepalive = false
	if o.isLog() {
		fmt.Printf(" client :(%v) OnRxEvent %s  \n", o.is_client, event.String())
	}

	if (event & transport.SocketEventConnected) > 0 {
		if o.state == te_WAIT_FOR_CONNECT {
			o.stat.eventNewFlow++
			o.processCmds()
		} else {
			panic("event & transport.SocketEventConnected in the wrong state")
		}
	}

	if event&transport.SocketRemoteDisconnect > 0 {
		// remote disconnected
		if o.is_client {
			if o.state != te_CLOSED {
				o.socket.Close()
			}
		} else {
			if o.state != te_CLOSED {
				o.doCloseFlow()
			}
		}
	}

	if (event & transport.SocketClosed) > 0 {
		err := o.socket.GetLastError()
		if err != transport.SeOK {
			o.stat.eventDropConnectionErr++
		}
		o.cb.OnFinish(o) // will be called on shutdown
		o.socket = nil
		o.stat.eventDelFlow++
	}

}

func (o *appL7Sim) changeState(new_state tcp_app_state) {
	if o.isLog() {
		fmt.Printf(" client :(%v) old_state: %v new_state: %v  \n", o.is_client, o.state.String(), new_state.String())
	}
	o.state = new_state
}

func (o *appL7Sim) OnRxData(d []byte) {
	o.udp_keepalive = false
	if o.isLog() {
		fmt.Printf(" client :(%v) OnRxData %v  \n", o.is_client, len(d))
	}

	o.stat.BytesRx += uint64(len(d))
	o.stat.eventRx += 1

	if o.isStream() {
		o.cmd_rx_bytes += uint64(len(d))
	} else {
		o.cmd_rx_bytes += 1
	}

	if o.state == te_WAIT_RX {
		if o.checkRxCondition() {
			o.processCmds()
		}
	}
}

func (o *appL7Sim) OnTxEvent(event transport.SocketEventType) {

	if o.isLog() {
		fmt.Printf(" client :(%v) OnTxEvent %s  \n", o.is_client, event.String())
	}

	if event&transport.SocketTxMore > 0 {
		if o.state == te_SEND {
			o.processCmds()
		}
	}

}

//////////////////////////////////////////////

func (o *appL7Sim) processCmds() {
	var next bool
	last := o.checkLastCmd()
	if last {
		return
	}
	for {
		next = o.processOneCmd(o.getCurCmd())
		if !next {
			break
		}
		if o.nextCmd() {
			last = true
			o.checkLastCmd()
			break
		}
	}
	if !last {
		o.nextCmd()
	}
}

func (o *appL7Sim) getCurCmdName() string {
	one_cmd := o.cmda[o.cmd_index].(map[string]interface{})
	return (one_cmd["name"].(string))
}

func (o *appL7Sim) getCurCmd() map[string]interface{} {
	one_cmd := o.cmda[o.cmd_index].(map[string]interface{})
	return (one_cmd)
}

type PluginAppsimClientTimer struct {
}

// PluginAppsimClient information per client
type PluginAppsimClient struct {
	core.PluginBase
	appsimNsPlug      *PluginAppsimNs
	timerw            *core.TimerCtx
	init              AppsimInit
	timer             core.CHTimerObj
	stats             AppsimStats
	cdb               *core.CCounterDb
	cdbv              *core.CCounterDbVec
	timerCb           PluginAppsimClientTimer
	db                appsimDb
	dgMacResolvedIpv4 bool
	dgMacResolvedIpv6 bool
}

var appsimEvents = []string{core.MSG_DG_MAC_RESOLVED}

func (o *PluginAppsimClientTimer) OnEvent(a, b interface{}) {
	//pi := a.(*PluginAppsimClient)last
	//pi.onTimerEvent()
}

/*NewAppSimClient create plugin */
func NewAppSimClient(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginAppsimClient)
	err := fastjson.Unmarshal(initJson, &o.init)
	if err != nil {
		return nil, err
	}
	o.InitPluginBase(ctx, o)               /* init base object*/
	o.RegisterEvents(ctx, appsimEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(APPSIM_PLUG)
	o.appsimNsPlug = nsplg.Ext.(*PluginAppsimNs)
	o.OnCreate()
	if o.Client.ForceDGW {
		o.OnResolve(false)
	}

	if o.Client.Ipv6ForceDGW {
		o.OnResolve(true)
	}

	return &o.PluginBase, nil
}

func (o *PluginAppsimClient) getGlobalProgram() map[string]interface{} {
	return o.appsimNsPlug.program
}

func (o *PluginAppsimClient) createStream(v *AppsimRec) *appsimStream {

	obj := new(appsimStream)
	obj.cps = v.Cps
	if v.CSType == "c" {
		obj.isClient = true
	}
	obj.tid = v.Tid
	obj.ipv6 = v.Ipv6
	obj.stream = v.Stream
	obj.dst = v.DestIP
	obj.limit = v.Limit
	obj.plug = o

	program := o.getGlobalProgram()
	if program == nil {
		o.stats.eventInvalidApp++
		return nil
	}
	if !isValidTid(obj.tid, program) {
		o.stats.eventInvalidtid++
		return nil
	}
	obj.onCreate(o)

	if obj.isClient {
		obj.startTicks()
		return obj
	}
	// server
	// create a sim object
	sim := new(simContext)
	sim.stas = &o.stats
	sim.program = program

	sim.template_id = obj.tid
	sim.Client = o.Client
	sim.Ns = o.Ns
	sim.Tctx = o.Ns.ThreadCtx
	sim.ctx = transport.GetTransportCtx(o.Client)
	app := new(socketAppL7)
	app.setCtx(sim.Tctx)
	app.setSim(sim)

	net := "tcp"
	if !obj.stream {
		net = "udp"
	}
	var ioctl map[string]interface{}
	ioctl = getAppIoctl(sim.template_id, !obj.isClient, sim.program)

	sim.is_client = false
	sport := getServerPort(obj.tid, program)
	sim.ctx.Listen(net, sport, app.getServerAcceptCb())
	if ioctl != nil {
		sim.ioctl = ioctl // save it for the callback
	}
	return obj
}

func (o *PluginAppsimClient) OnResolve(ipv6 bool) {
	if ipv6 {
		o.dgMacResolvedIpv6 = true
	} else {
		o.dgMacResolvedIpv4 = true
	}
	for k, v := range o.init.Data {
		_, ok := o.db[k]
		if !ok {
			if (ipv6 && v.Ipv6) || (!ipv6 && !v.Ipv6) {
				s := o.createStream(&v)
				// add only the first
				if s != nil {
					o.db[k] = s
				}
			}
		}
	}
}

func (o *PluginAppsimClient) OnCreate() {
	o.timerw = o.Tctx.GetTimerCtx()

	o.cdb = NewAppSimStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec(APPSIM_PLUG)
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.db = make(appsimDb)

}

/*OnEvent support event change of IP  */
func (o *PluginAppsimClient) OnEvent(msg string, a, b interface{}) {

	switch msg {
	case core.MSG_DG_MAC_RESOLVED:
		bitMask, ok := a.(uint8)
		if !ok {
			// failed at type assertion
			return
		}
		resolvedIPv4 := (bitMask & core.RESOLVED_IPV4_DG_MAC) == core.RESOLVED_IPV4_DG_MAC
		resolvedIPv6 := (bitMask & core.RESOLVED_IPV6_DG_MAC) == core.RESOLVED_IPV6_DG_MAC
		if resolvedIPv4 && !o.dgMacResolvedIpv4 {
			o.OnResolve(false)
		}
		if resolvedIPv6 && !o.dgMacResolvedIpv6 {
			o.OnResolve(true)
		}

	}

}

func (o *PluginAppsimClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the ink to the client */
	ctx.UnregisterEvents(&o.PluginBase, appsimEvents)
	// TBD send release message
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}

	for _, v := range o.db {
		v.onRemove()
	}
	o.db = nil
}

func (o *PluginAppsimClient) restartTimer(sec uint32) {
	if sec == 0 {
		return
	}
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.timerw.Start(&o.timer, time.Duration(sec)*time.Second)
}

// PluginAppsimNs icmp information per namespace
type PluginAppsimNs struct {
	core.PluginBase
	stats   AppsimNsStats
	cdb     *core.CCounterDb
	cdbv    *core.CCounterDbVec
	program map[string]interface{} // pointer to the global program
}

func NewAppSimNs(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginAppsimNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	o.cdb = NewAppSimNsStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec(APPSIM_PLUG)
	o.cdbv.Add(o.cdb)

	// load the global program
	err := IsValidAppSimJson((*fastjson.RawMessage)(&initJson), &o.program)
	if err != nil {
		o.stats.errLoadApp++
	}
	return &o.PluginBase, err
}

func (o *PluginAppsimNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginAppsimNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginAppsimNs) SetTruncated() {

}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginAppsimCReg struct{}
type PluginAppsimNsReg struct{}

func (o PluginAppsimCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewAppSimClient(ctx, initJson)
}

func (o PluginAppsimNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewAppSimNs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */
type (
	ApiAppsimClientCntHandler struct{}
	ApiAppsimNsCntHandler     struct{}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginAppsimNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, APPSIM_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginAppsimNs)

	return arpNs, nil
}

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginAppsimClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, APPSIM_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginAppsimClient)

	return pClient, nil
}

func (h ApiAppsimClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return c.cdbv.GeneralCounters(err, tctx, params, &p)
}

func (h ApiAppsimNsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	ns, err := getNs(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return ns.cdbv.GeneralCounters(err, tctx, params, &p)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(APPSIM_PLUG,
		core.PluginRegisterData{Client: PluginAppsimCReg{},
			Ns:     PluginAppsimNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command like ping etc
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("appsim_client_cnt", ApiAppsimClientCntHandler{}, false) // get counters/meta
	core.RegisterCB("appsim_ns_cnt", ApiAppsimClientCntHandler{}, false)     // get counters/meta

}

func Register(ctx *core.CThreadCtx) {
	//pass
}
