// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"encoding/binary"
	"encoding/hex"
	"external/google/gopacket/layers"
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	TCP_PROTO = uint8(layers.IPProtocolTCP)
	UDP_PROTO = uint8(layers.IPProtocolUDP)
)

type TransportCtxCfg struct {
	TcpFastTickMsec *uint16 `json:"tcp_fasttick_msec" validate:"gte=20 &lte=100"`
	Tcpkeepalive    *uint16 `json:"tcp_keepalive" validate:"gte=10 &lte=6500"`
	TcpNoDelay      *uint8  `json:"tcp_no_delay" validate:"gte=0 &lte=4"`
	TcpNoDelayCnt   *uint16 `json:"tcp_no_delay_counter" validate:"gte=0 &lte=65000"`
	TcpInitWnd      *uint32 `json:"initwnd" validate:"gte=1 &lte=20"`
	TcpRxBufSize    *uint32 `json:"rxbufsize" validate:"gte=8192 &lte=1048576"`
	TcpTxBufSize    *uint32 `json:"txbufsize" validate:"gte=8192 &lte=1048576"`
	TcpDorfc1323    *bool   `json:"do_rfc1323"`
	TcpMss          *uint16 `json:"mss" validate:"gte=10 &lte=9000"`
}

type prototbl map[uint8]IServerSocketCb // per protocol accept callback
type serverft map[uint16]prototbl       // server open ports

// each socket need to implement this to free all the resource
type socketRemoveIf interface {
	onRemove()
}

//ipv4 key, the key in built in respect to the return packet
// source is remote, dst is local addr etc. this is the key
type c5tuplekeyv4 [4 + 4 + 4 + 1]byte

func (o *c5tuplekeyv4) getProto() uint8 {
	return (o[12])
}

func (o *c5tuplekeyv4) getSrcIp() core.Ipv4Key {
	var src core.Ipv4Key
	copy(src[:], o[0:4])
	return src
}

func (o *c5tuplekeyv4) getDstIp() core.Ipv4Key {
	var dst core.Ipv4Key
	copy(dst[:], o[4:8])
	return dst
}

func (o *c5tuplekeyv4) getSrcPort() uint16 {
	return binary.BigEndian.Uint16(o[8:10])
}

func (o *c5tuplekeyv4) getDstPort() uint16 {
	return binary.BigEndian.Uint16(o[10:12])
}

func (o *c5tuplekeyv4) String() string {
	s := hex.Dump(o[:])
	return s
}

//ipv6 -key
type c5tuplekeyv6 [16 + 16 + 4 + 1]byte

func (o *c5tuplekeyv6) String() string {
	s := hex.Dump(o[:])
	return s
}

type flowTablev4 map[c5tuplekeyv4]interface{}
type flowTablev6 map[c5tuplekeyv6]interface{}

//
func buildTuplev4(src core.Ipv4Key,
	dst core.Ipv4Key,
	srcPort uint16,
	dstPort uint16,
	proto uint8, tuple *c5tuplekeyv4) {
	copy(tuple[0:4], src[:])
	copy(tuple[4:8], dst[:])
	binary.BigEndian.PutUint16(tuple[8:10], srcPort)
	binary.BigEndian.PutUint16(tuple[10:12], dstPort)
	tuple[12] = proto
}

func buildTuplev6(src core.Ipv6Key,
	dst core.Ipv6Key,
	srcPort uint16,
	dstPort uint16,
	proto uint8, tuple *c5tuplekeyv6) {

	copy(tuple[0:16], src[:])
	copy(tuple[16:32], dst[:])
	binary.BigEndian.PutUint16(tuple[32:34], srcPort)
	binary.BigEndian.PutUint16(tuple[34:36], dstPort)
	tuple[36] = proto
}

func (o *c5tuplekeyv6) getSrcIp() core.Ipv6Key {
	var src core.Ipv6Key
	copy(src[:], o[0:16])
	return src
}

func (o *c5tuplekeyv6) getDstIp() core.Ipv6Key {
	var dst core.Ipv6Key
	copy(dst[:], o[16:32])
	return dst
}

func (o *c5tuplekeyv6) getSrcPort() uint16 {
	return binary.BigEndian.Uint16(o[32:34])
}

func (o *c5tuplekeyv6) getDstPort() uint16 {
	return binary.BigEndian.Uint16(o[34:36])
}

func (o *c5tuplekeyv6) getProto() uint8 {
	return (o[36])
}

const (
	TCP_FAST_TICK_     = 40 // in msec
	TCP_INITWND_FACTOR = 10
	TCPTV_KEEP_INIT    = (5 * PR_SLOWHZ)       /* initial connect keep alive */
	TCPTV_KEEP_IDLE    = (5 * PR_SLOWHZ)       /* dflt time before probing */
	TCPTV_KEEPINTVL    = (7 * PR_SLOWHZ)       /* default probe interval */
	TCPTV_KEEPCNT      = 8                     /* max probes before drop */
	TCP_MSS            = (1500 - 20 - 20)      // for ipv4,
	TCP_MSS_IPV6       = (1500 - 40 - 10 - 20) // for ipv6
	TCP_ISSINCR        = (122 * 1024)
)

type ctxClientTimer struct {
}

func (o *ctxClientTimer) OnEvent(a, b interface{}) {
	pi := a.(*TransportCtx)
	pi.onTimerEvent()
}

type ftStats struct {
	ft_addv4                   uint64 /* add flows */
	ft_removev4                uint64 /* remove flows v4 */
	ft_activev4                uint64 /* active flows */
	ft_add_err_already_exitsv4 uint64 /* add already exists flows */
	ft_remove_err_not_exitsv4  uint64 /* remove but does not exits */

	ft_lookupv4       uint64 /* lookup */
	ft_lookup_foundv4 uint64 /* lookup */

	ft_addv6                   uint64 /* add flows */
	ft_removev6                uint64 /* remove flows v4 */
	ft_activev6                uint64 /* active flows */
	ft_add_err_already_exitsv6 uint64 /* add already exists flows */
	ft_remove_err_not_exitsv6  uint64 /* remove but does not exits */
	ft_lookupv6                uint64 /* lookup */
	ft_lookup_foundv6          uint64 /* lookup */

	src_port_alloc      uint64 // allocation of source port
	src_port_free       uint64 // free of source port
	src_port_active     uint64 // active ports
	src_port_err_return uint64 // err in return
	src_port_err_get    uint64 // err in get (no free port)

	ft_new_tcp        uint64 // new server side tcp flow
	ft_new_tcp_no_syn uint64 // new server no syn

	ft_new_no_cb          uint64 // new server no port register
	ft_new_no_client_ipv6 uint64 // new server flow - no valid client ipv6
	ft_new_no_client_ipv4 uint64 // new server flow - no valid client ipv4
	ft_new_no_accept      uint64 // new server flow - no accept
	ft_new_ipv4           uint64 // new server flow - ipv4 ok
	ft_new_ipv6           uint64 // new server flow - ipv6 ok

	ft_new_udp uint64 // new server side udp flow

	dial               uint64 // dial
	dial_wrong_network uint64 // dial - wrong network
	dial_wrong_addr    uint64 // dial - wrong addr
}

func newftStatsDb(o *ftStats) *core.CCounterDb {
	db := core.NewCCounterDb("ft")

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_udp,
		Name:     "ft_new_tcp",
		Help:     "tcp server, new flow",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_tcp,
		Name:     "ft_new_tcp",
		Help:     "tcp server, new flow",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_tcp_no_syn,
		Name:     "ft_new_tcp_no_syn",
		Help:     "no syn in server side first packet",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_no_cb,
		Name:     "ft_new_no_cb",
		Help:     "no port listen in server side first packet",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_no_client_ipv6,
		Name:     "ft_new_no_client_ipv6",
		Help:     "no valid ipv6 addr for server side packet",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_no_client_ipv4,
		Name:     "ft_new_no_client_ipv4",
		Help:     "no valid ipv4 addr for server side packet",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_no_accept,
		Name:     "ft_new_no_accept",
		Help:     "first tcp packets wasn't accepted",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_ipv4,
		Name:     "ft_new_ipv4",
		Help:     "new tcp flowv4",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_new_ipv6,
		Name:     "ft_new_ipv6",
		Help:     "new tcp flowv6",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.dial,
		Name:     "dial",
		Help:     "dial",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.dial_wrong_network,
		Name:     "dial_wrong_network",
		Help:     "dial wrong network",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.dial_wrong_addr,
		Name:     "dial_wrong_addr",
		Help:     "dial wrong addr",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.src_port_alloc,
		Name:     "src_port_alloc",
		Help:     "alloc source port",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.src_port_free,
		Name:     "src_port_free",
		Help:     "free source port",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.src_port_active,
		Name:     "src_port_active",
		Help:     "active source ports",
		Unit:     "event",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.src_port_err_return,
		Name:     "src_port_err_return",
		Help:     "error in return port (not active)",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.src_port_err_get,
		Name:     "src_port_err_get",
		Help:     "no free source port",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_addv4,
		Name:     "ft_addv4",
		Help:     "add v4 flows",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_removev4,
		Name:     "ft_removev4",
		Help:     "remove v4 flows",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_activev4,
		Name:     "ft_activev4",
		Help:     "active v4 flows",
		Unit:     "flows",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_lookupv4,
		Name:     "ft_lookupv4",
		Help:     "lookup v4 flows",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_lookup_foundv4,
		Name:     "ft_lookup_foundv4",
		Help:     "lookup v4 flows and found",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_add_err_already_exitsv4,
		Name:     "err_already_exitsv4",
		Help:     "err add v4 flows - already exists",
		Unit:     "flows",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_remove_err_not_exitsv4,
		Name:     "err_remove_not_exitsv4",
		Help:     "err remove v4 flows - does not exists",
		Unit:     "flows",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_addv6,
		Name:     "ft_addv6",
		Help:     "add v6 flows",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_removev6,
		Name:     "ft_removev6",
		Help:     "remove v6 flows",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_activev6,
		Name:     "ft_activev6",
		Help:     "active v6 flows",
		Unit:     "flows",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_lookupv6,
		Name:     "ft_lookupv6",
		Help:     "lookup v6 flows",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_lookup_foundv6,
		Name:     "ft_lookup_foundv6",
		Help:     "lookup v6 flows and found",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_add_err_already_exitsv6,
		Name:     "err_already_exitsv6",
		Help:     "err add v6 flows - already exists",
		Unit:     "flows",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ft_remove_err_not_exitsv6,
		Name:     "err_remove_not_exitsv6",
		Help:     "err remove v6 flows - does not exists",
		Unit:     "flows",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

// TransportCtx context per client for all tansport v4 and v6
type TransportCtx struct {
	Client   *core.CClient
	Ns       *core.CNSCtx
	Tctx     *core.CThreadCtx
	tcpStats TcpStats
	udpStats UdpStats
	timerw   *core.TimerCtx
	cdbv     *core.CCounterDbVec
	cdbtcp   *core.CCounterDb
	cdbudp   *core.CCounterDb
	timer    core.CHTimerObj
	timerCb  ctxClientTimer

	/* TCP global info */
	tcp_now uint32 /* for RFC 1323 timestamps */
	tcp_iss uint32 /* tcp initial send seq # */

	tcp_tx_socket_bsize  uint32
	tcp_rx_socket_bsize  uint32
	tcprexmtthresh       uint8
	tcp_mssdflt_         uint16
	tcp_initwnd_factor   int32  /* slow start initwnd, should be 1 in default but for optimization we start at 5 */
	tcp_initwnd          uint32 /*  tcp_initwnd_factor *tcp_mssdflt*/
	tcp_rttdflt          int16
	tcp_do_rfc1323       bool
	tcp_no_delay         uint8
	tcp_no_delay_counter uint16 /* number of recv bytes to wait until ack them */
	tcp_keepinit         uint16
	tcp_keepidle         uint16 /* time before keepalive probes begin */
	tcp_keepintvl        uint16 /* time between keepalive probes */
	tcp_blackhole        int32
	tcp_keepcnt          uint16
	tcp_maxidle          uint16 /* time to drop after starting probes */
	tcp_maxpersistidle   uint16
	tcp_fast_tick_msec   uint16

	// flow table
	flowTableStats ftStats
	ftcdb          *core.CCounterDb
	ftv4           flowTablev4
	ftv6           flowTablev6
	srcPorts       srcPortManager
	serverCb       serverft // server callbacks
}

func updateInitwnd(mss uint16, initwnd uint16) uint16 {
	calc := mss * initwnd

	if calc > 48*1024 {
		calc = 48 * 1024
	}
	return (calc)
}

func newCtx(c *core.CClient) *TransportCtx {
	o := new(TransportCtx)
	o.init()
	o.Client = c
	o.Ns = c.Ns
	o.Tctx = c.Ns.ThreadCtx
	o.timerw = o.Tctx.GetTimerCtx()
	o.cdbudp = NewUdpStatsDb(&o.udpStats)
	o.cdbtcp = NewTcpStatsDb(&o.tcpStats)
	o.cdbv = core.NewCCounterDbVec("tcp")
	o.cdbv.Add(o.cdbtcp)
	o.cdbv.Add(o.cdbudp)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.restartTimer()

	o.ftcdb = newftStatsDb(&o.flowTableStats)
	o.cdbv.Add(o.ftcdb)
	o.ftv4 = make(flowTablev4)
	o.ftv6 = make(flowTablev6)
	o.srcPorts.init(o)
	o.serverCb = make(serverft)
	return o
}

func (o *TransportCtx) setCfg(cfg *TransportCtxCfg) {

	if cfg.TcpDorfc1323 != nil {
		o.tcp_do_rfc1323 = *cfg.TcpDorfc1323
	}

	if cfg.TcpFastTickMsec != nil {
		o.tcp_fast_tick_msec = *cfg.TcpFastTickMsec
	}

	if cfg.Tcpkeepalive != nil {
		o.tcp_keepidle = *cfg.Tcpkeepalive
	}

	if cfg.TcpNoDelay != nil {
		o.tcp_no_delay = *cfg.TcpNoDelay
	}

	if cfg.TcpNoDelayCnt != nil {
		o.tcp_no_delay_counter = *cfg.TcpNoDelayCnt
	}

	if cfg.TcpInitWnd != nil {
		o.tcp_initwnd = *cfg.TcpInitWnd
	}

	if cfg.TcpRxBufSize != nil {
		o.tcp_rx_socket_bsize = *cfg.TcpRxBufSize
	}

	if cfg.TcpTxBufSize != nil {
		o.tcp_tx_socket_bsize = *cfg.TcpTxBufSize
	}

	if cfg.TcpMss != nil {
		o.tcp_mssdflt_ = *cfg.TcpMss
	}

}

func (o *TransportCtx) getActiveFlows() uint64 {
	p := &o.flowTableStats
	return p.ft_activev4 + p.ft_activev6 + p.src_port_active
}

/* we assume that there relatively small number of flows per
client  so we could iterate it in atomic way wihtout stalling the scheduler*/
func (o *TransportCtx) onRemove() {
	for _, flow := range o.ftv4 {
		var or socketRemoveIf
		or = flow.(socketRemoveIf)
		or.onRemove()
	}

	for _, flow := range o.ftv6 {
		var or socketRemoveIf
		or = flow.(socketRemoveIf)
		or.onRemove()
	}

	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *TransportCtx) removeFlowv4(tuple *c5tuplekeyv4, f interface{}) bool {
	v, ok := o.ftv4[*tuple]
	if !ok {
		o.flowTableStats.ft_remove_err_not_exitsv4++
		return false // flow already exits
	}
	if v != f {
		s := fmt.Sprintf("flow table is corrupted %v %v", f, v)
		panic(s)
	}
	o.flowTableStats.ft_removev4++
	o.flowTableStats.ft_activev4--
	delete(o.ftv4, *tuple)
	return true
}

func (o *TransportCtx) removeFlowv6(tuple *c5tuplekeyv6, f interface{}) bool {
	v, ok := o.ftv6[*tuple]
	if !ok {
		o.flowTableStats.ft_remove_err_not_exitsv6++
		return false // flow already exits
	}
	if v != f {
		s := fmt.Sprintf("flow table is corrupted %v %v", f, v)
		panic(s)
	}
	o.flowTableStats.ft_removev6++
	o.flowTableStats.ft_activev6--
	delete(o.ftv6, *tuple)
	return true
}

func (o *TransportCtx) addFlowv4(tuple *c5tuplekeyv4, v interface{}) bool {
	_, ok := o.ftv4[*tuple]
	if ok {
		o.flowTableStats.ft_add_err_already_exitsv4++
		return false // flow already exits
	}
	o.flowTableStats.ft_activev4++
	o.flowTableStats.ft_addv4++
	o.ftv4[*tuple] = v
	return true
}

func (o *TransportCtx) addFlowv6(tuple *c5tuplekeyv6, v interface{}) bool {
	_, ok := o.ftv6[*tuple]
	if ok {
		o.flowTableStats.ft_add_err_already_exitsv6++
		return false // flow already exits
	}
	o.flowTableStats.ft_addv6++
	o.flowTableStats.ft_activev6++
	o.ftv6[*tuple] = v
	return true
}

// on tick 1000/PR_SLOWHZ msec
func (o *TransportCtx) onTimerEvent() {
	o.tcp_maxidle = o.tcp_keepcnt * o.tcp_keepintvl
	if o.tcp_maxidle > (TCPTV_2MSL) {
		o.tcp_maxidle = (TCPTV_2MSL)
	}

	o.tcp_iss += TCP_ISSINCR / PR_SLOWHZ /* increment iss */
	o.tcp_now++                          /* for timestamps */
	o.restartTimer()
}

func (o *TransportCtx) restartTimer() {
	o.timerw.Start(&o.timer, time.Duration(1000/PR_SLOWHZ)*time.Millisecond)
}

// init tunable
func (o *TransportCtx) init() {
	o.tcp_iss = TCP_ISSINCR // TBD replace with random random32()
	o.tcp_blackhole = 0
	o.tcp_do_rfc1323 = true
	o.tcp_fast_tick_msec = TCP_FAST_TICK_
	o.tcp_initwnd = uint32(updateInitwnd(TCP_MSS, TCP_INITWND_FACTOR))
	o.tcp_initwnd_factor = TCP_INITWND_FACTOR
	o.tcp_keepidle = TCPTV_KEEP_IDLE
	o.tcp_keepinit = TCPTV_KEEP_INIT
	o.tcp_keepintvl = TCPTV_KEEPINTVL
	o.tcp_mssdflt_ = TCP_MSS
	o.tcp_no_delay = 0
	o.tcp_rx_socket_bsize = 32 * 1024
	o.tcp_tx_socket_bsize = 32 * 1024
	o.tcprexmtthresh = 3
	o.tcp_rttdflt = int16(TCPTV_SRTTDFLT / uint16(PR_SLOWHZ))
	o.tcp_keepcnt = TCPTV_KEEPCNT          /* max idle probes */
	o.tcp_maxpersistidle = TCPTV_KEEP_IDLE /* max idle time in persist */
	o.tcp_no_delay_counter = TCP_MSS * 2
}

func (o *TransportCtx) getTcpIss() uint32 {
	o.tcp_iss++
	return o.tcp_iss
}

func (o *TransportCtx) handleRxUdpPacket(ps *core.ParserPacketState, flow interface{}) int {
	var udp *UdpSocket
	udp, ok := flow.(*UdpSocket)
	if ok == false {
		panic(" flow should be *TcpSocket ")
	}
	if udp.isClosed {
		return -1
	}
	return udp.input(ps)
}

func (o *TransportCtx) handleRxTcpPacket(ps *core.ParserPacketState, flow interface{}) int {
	var tcps *TcpSocket
	tcps, ok := flow.(*TcpSocket)
	if ok == false {
		panic(" flow should be *TcpSocket ")
	}
	if tcps.IsClose() {
		return -1
	}
	return tcps.input(ps)
}

func (o *TransportCtx) fillv4tuple(ps *core.ParserPacketState, tuplev4 *c5tuplekeyv4) int {
	m := ps.M
	p := m.GetData()
	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])

	var src core.Ipv4Key
	src.SetUint32(ipv4.GetIPSrc())
	var dst core.Ipv4Key
	dst.SetUint32(ipv4.GetIPDst())

	// valid for both TCP and UDP
	udp := layers.UDPHeader(p[ps.L4 : ps.L4+4])

	buildTuplev4(src,
		dst,
		udp.SrcPort(),
		udp.DstPort(),
		ipv4.GetNextProtocol(),
		tuplev4)

	return 0
}

func (o *TransportCtx) fillv6tuple(ps *core.ParserPacketState, tuplev6 *c5tuplekeyv6) int {

	m := ps.M
	p := m.GetData()
	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+40])

	var src core.Ipv6Key
	copy(src[:], ipv6.SrcIP())
	var dst core.Ipv6Key
	copy(dst[:], ipv6.DstIP())

	// valid for both TCP and UDP
	udp := layers.UDPHeader(p[ps.L4 : ps.L4+4])

	buildTuplev6(src,
		dst,
		udp.SrcPort(),
		udp.DstPort(),
		ps.NextHeader,
		tuplev6)

	return 0
}

func (o *TransportCtx) handleRxCmnNewFlow(ps *core.ParserPacketState,
	s internalSocketApi,
	socket SocketApi,
	dstport uint16,
	ipv6 bool,
	keyv4 *c5tuplekeyv4,
	keyv6 *c5tuplekeyv6,
	OnAccept IServerSocketCb) int {
	s.init(o.Client, o)

	if !ipv6 {
		if o.Client.Ipv4.IsZero() {
			// there is no valid ipv4 -- lookup should fail
			o.flowTableStats.ft_new_no_client_ipv4++
			return -1
		}

		s.setTupleIpv4(o.Client.Ipv4,
			keyv4.getSrcIp(),
			dstport,
			keyv4.getSrcPort())

	} else {
		// ipv6
		ipv6src, err1 := o.Client.GetSourceIPv6()
		if err1 != nil {
			o.flowTableStats.ft_new_no_client_ipv6++
			return -1
		}

		s.setTupleIpv6(ipv6src,
			keyv6.getSrcIp(),
			dstport,
			keyv6.getSrcPort())
	}
	cb := OnAccept.OnAccept(socket)

	if cb == nil {
		o.flowTableStats.ft_new_no_accept++
		s = nil
		return -1
	}
	// register the flow in flow table
	if !ipv6 {
		o.addFlowv4(keyv4, s)
		o.flowTableStats.ft_new_ipv4++
	} else {
		o.flowTableStats.ft_new_ipv6++
		o.addFlowv6(keyv6, s)
	}
	s.initphase2(cb, nil)
	// defer ioctl
	ioc := s.getServerIoctl()
	if ioc != nil {
		socket.SetIoctl(ioc)
		s.clearServerIoctl()
	}
	s.listen() // start the timers and callbacks

	return 0
}

func (o *TransportCtx) handleRxTcpNewFlow(ps *core.ParserPacketState,
	ipv6 bool,
	keyv4 *c5tuplekeyv4,
	keyv6 *c5tuplekeyv6) int {

	m := ps.M
	p := m.GetData()

	o.flowTableStats.ft_new_tcp++

	tcp := layers.TcpHeader(p[ps.L4 : ps.L4+20])
	if tcp.GetFlags()&0x3F != 0x2 {
		// no SYN in first in flow packet
		o.flowTableStats.ft_new_tcp_no_syn++
		return -1
	}

	// register a callback?
	dstport := tcp.GetDstPort()
	acceptCb := o.lookupServerPort(dstport, TCP_PROTO)

	if acceptCb == nil {
		o.flowTableStats.ft_new_no_cb++
		return -1
	}

	s := new(TcpSocket)

	if o.handleRxCmnNewFlow(ps,
		s,
		s,
		dstport,
		ipv6,
		keyv4,
		keyv6,
		acceptCb) != 0 {
		return -1
	}

	return s.input(ps) // process the packet (first syn)
}

func (o *TransportCtx) handleRxUdpNewFlow(ps *core.ParserPacketState,
	ipv6 bool,
	keyv4 *c5tuplekeyv4,
	keyv6 *c5tuplekeyv6) int {
	m := ps.M
	p := m.GetData()

	o.flowTableStats.ft_new_udp++

	udp := layers.UDPHeader(p[ps.L4 : ps.L4+4])
	// register a callback?
	dstport := udp.DstPort()
	acceptCb := o.lookupServerPort(dstport, UDP_PROTO)

	if acceptCb == nil {
		o.flowTableStats.ft_new_no_cb++
		return -1
	}

	s := new(UdpSocket)

	if o.handleRxCmnNewFlow(ps,
		s,
		s,
		dstport,
		ipv6,
		keyv4,
		keyv6,
		acceptCb) != 0 {
		return -1
	}

	return s.input(ps)
}

// per client handler, for both ipv4 and ipv6
func (o *TransportCtx) handleRxPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* checksum was tested by parser already */

	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])
	ver := ipv4.Version()
	if ver == 4 {
		var keyv4 c5tuplekeyv4
		if o.fillv4tuple(ps, &keyv4) != 0 {
			return -1
		}

		f, ok := o.ftv4[keyv4]
		o.flowTableStats.ft_lookupv4++
		if ok {
			o.flowTableStats.ft_lookup_foundv4++
			if keyv4.getProto() == uint8(layers.IPProtocolTCP) {
				// TCP
				return o.handleRxTcpPacket(ps, f)
			} else {
				return o.handleRxUdpPacket(ps, f)
			}
		} else {
			if keyv4.getProto() == uint8(layers.IPProtocolTCP) {
				o.handleRxTcpNewFlow(ps, false, &keyv4, nil)
			} else {
				o.handleRxUdpNewFlow(ps, false, &keyv4, nil)
			}
		}

	} else {
		// ipv6
		var keyv6 c5tuplekeyv6
		if o.fillv6tuple(ps, &keyv6) != 0 {
			return -1
		}
		f, ok := o.ftv6[keyv6]
		o.flowTableStats.ft_lookupv6++
		if ok {
			o.flowTableStats.ft_lookup_foundv6++
			if keyv6.getProto() == uint8(layers.IPProtocolTCP) {
				// TCP
				return o.handleRxTcpPacket(ps, f)
			} else {
				return o.handleRxUdpPacket(ps, f)
			}
		} else {
			if keyv6.getProto() == uint8(layers.IPProtocolTCP) {
				o.handleRxTcpNewFlow(ps, true, nil, &keyv6)
			} else {
				o.handleRxUdpNewFlow(ps, true, nil, &keyv6)
			}
		}
	}
	return 0
}

// network tcp,udp
// address addr:port
// dstMac &core.MACKey{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
// for example
//	Dial("tcp", "192.0.2.1:80",cb,nil, nil, 0)
//	Dial("tcp", "[2001:db8::1]:80",cb,nil, 0)
//	Dial("tcp", "[2001:db8::1]:80",cb,{"tos":12}, 0)
//	Dial("udp", "192.0.2.1:80",cb,nil, &core.MACKey{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
//	Dial("tcp", "192.0.2.1:80",cb,nil, nil, 5353)
func (o *TransportCtx) Dial(network, address string, cb ISocketCb, ioctl IoctlMap, dstMac *core.MACKey, srcPort uint16) (SocketApi, error) {

	o.flowTableStats.dial++

	switch network {
	case "tcp", "udp":
	default:
		o.flowTableStats.dial_wrong_network++
		return nil, fmt.Errorf(" unsupported %v network", network)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		o.flowTableStats.dial_wrong_addr++
		return nil, err
	}
	value, err1 := strconv.ParseUint(port, 10, 16)
	if err1 != nil {
		o.flowTableStats.dial_wrong_addr++
		return nil, err
	}
	port16 := uint16(value)
	dst := net.ParseIP(host)
	if cb == nil {
		o.flowTableStats.dial_wrong_addr++
		return nil, fmt.Errorf(" callback should not be nil ")
	}

	switch network {
	case "tcp":
		return o.dialTcp(dst, port16, cb, ioctl, dstMac, srcPort)
	case "udp":
		return o.dialUdp(dst, port16, cb, ioctl, dstMac, srcPort)
	}
	return nil, fmt.Errorf(" unsupported %v network", network)
}

func toV4(ip net.IP, ipv4 *core.Ipv4Key) {
	copy(ipv4[:], ip[0:4])
}

func toV6(ip net.IP, ipv6 *core.Ipv6Key) {
	copy(ipv6[:], ip[0:16])
}

func (o *TransportCtx) dialCmn(s internalSocketApi, socket SocketApi, dst net.IP, port uint16, cb ISocketCb, ioctl IoctlMap, dstMac *core.MACKey, srcPort uint16) (SocketApi, error) {
	s.init(o.Client, o)
	var sourceport uint16
	proto := s.getProto()
	if srcPort == 0 {
		sourceport = o.srcPorts.allocPort(proto)
		if sourceport == 0 {
			return nil, fmt.Errorf(" can't allocate free source port for client %v  ", o.Client.Mac)
		}
		s.setPortAlloc(true)
	} else {
		sourceport = srcPort
		s.setPortAlloc(false)
	}

	ipv4 := dst.To4()
	if ipv4 != nil {
		if o.Client.Ipv4.IsZero() {
			return nil, fmt.Errorf(" there is no valid ipv4 for client %v ", o.Client.Mac)
		}
		var kipv4 core.Ipv4Key
		toV4(ipv4, &kipv4)
		s.setTupleIpv4(o.Client.Ipv4,
			kipv4,
			sourceport,
			port)

		var tuple c5tuplekeyv4
		// replace source , destination, in respect to return packet
		//
		buildTuplev4(kipv4,
			o.Client.Ipv4,
			port,
			sourceport,
			proto, &tuple)

		o.addFlowv4(&tuple, s)
	} else {
		ipv6, err1 := o.Client.GetSourceIPv6()
		if err1 != nil {
			return nil, err1
		}
		var kipv6 core.Ipv6Key
		toV6(dst, &kipv6)
		s.setTupleIpv6(ipv6,
			kipv6,
			sourceport,
			port)

		var tuple c5tuplekeyv6
		buildTuplev6(kipv6,
			ipv6,
			port,
			sourceport,
			proto, &tuple)

		o.addFlowv6(&tuple, s)
	}

	s.initphase2(cb, dstMac)
	if ioctl != nil {
		socket.SetIoctl(ioctl)
	}
	s.connect()
	return socket, nil
}

func (o *TransportCtx) dialTcp(dst net.IP, port uint16, cb ISocketCb, ioctl IoctlMap, dstMac *core.MACKey, srcPort uint16) (SocketApi, error) {
	s := new(TcpSocket)
	return o.dialCmn(s, s, dst, port, cb, ioctl, dstMac, srcPort)
}

func (o *TransportCtx) dialUdp(dst net.IP, port uint16, cb ISocketCb, ioctl IoctlMap, dstMac *core.MACKey, srcPort uint16) (SocketApi, error) {
	s := new(UdpSocket)
	return o.dialCmn(s, s, dst, port, cb, ioctl, dstMac, srcPort)
}

func (o *TransportCtx) addServerCb(port uint16, proto uint8, cb IServerSocketCb) bool {
	v, ok := o.serverCb[port]
	if !ok {
		// first
		p := make(prototbl)
		p[proto] = cb
		o.serverCb[port] = p
	} else {
		_, ok := v[proto]
		if ok {
			return false // there is a another callback
		} else {
			v[proto] = cb
		}
	}
	return true
}

func (o *TransportCtx) removeServerCb(port uint16, proto uint8, cb IServerSocketCb) bool {

	v, ok := o.serverCb[port]
	if !ok {
		return false // no port
	} else {
		c, ok := v[proto]
		if ok {
			if c != cb {
				panic(" the callback was changed, imporssible ")
			}
			delete(v, proto)
			if len(v) == 0 {
				delete(o.serverCb, port)
			}
		} else {
			return false // there is no proto
		}
	}
	return true
}

func (o *TransportCtx) lookupServerPort(port uint16, proto uint8) IServerSocketCb {

	v, ok := o.serverCb[port]
	if !ok {
		return nil
	} else {
		c, ok := v[proto]
		if ok {
			return c
		} else {
			return nil
		}
	}
}

func (o *TransportCtx) parseNA(network, address string, port *uint16, proto *uint8) error {
	var proid uint8
	switch network {
	case "tcp":
		proid = TCP_PROTO
	case "udp":
		proid = UDP_PROTO
	default:
		return fmt.Errorf(" unsupported %v network", network)
	}

	host, hport, err := net.SplitHostPort(address)

	if err != nil {
		return err
	}

	if len(host) > 0 {
		return fmt.Errorf(" unsupported listen to host %v network", host)
	}

	value, err1 := strconv.ParseUint(hport, 10, 16)
	if err1 != nil {
		return err
	}
	port16 := uint16(value)

	*port = port16
	*proto = proid
	return nil
}

/*
Listen():

create a TCP server

ctx.Listen("tcp",":8080",cb)

to remove the callback

ctx.UnListen("tcp",":8080",cb)

*/
func (o *TransportCtx) Listen(network, address string, cb IServerSocketCb) error {
	var proto uint8
	var port uint16
	if err := o.parseNA(network, address, &port, &proto); err != nil {
		return err
	}
	if !o.addServerCb(port, proto, cb) {
		return fmt.Errorf(" port %v already register for %s network", port, network)
	}
	return nil
}

/*
UnListen(), see listen
*/
func (o *TransportCtx) UnListen(network, address string, cb IServerSocketCb) error {
	var proto uint8
	var port uint16
	if err := o.parseNA(network, address, &port, &proto); err != nil {
		return err
	}
	if !o.removeServerCb(port, proto, cb) {
		return fmt.Errorf(" port %v is no register for %s network", port, network)
	}
	return nil
}

func (o *TransportCtx) OnRemove(c *core.CClient) {
	o.onRemove()
}
