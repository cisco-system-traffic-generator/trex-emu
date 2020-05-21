// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"time"
)

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
	pi := a.(*transportCtx)
	pi.onTimerEvent()
}

// TransportCtx context per client for all tansport v4 and v6
type transportCtx struct {
	Client   *core.CClient
	Ns       *core.CNSCtx
	Tctx     *core.CThreadCtx
	tcpStats TcpStats
	timerw   *core.TimerCtx
	cdbv     *core.CCounterDbVec
	cdb      *core.CCounterDb
	timer    core.CHTimerObj
	timerCb  ctxClientTimer

	/* TCP global info */
	tcp_now uint32 /* for RFC 1323 timestamps */
	tcp_iss uint32 /* tcp initial send seq # */

	tcp_tx_socket_bsize  uint32
	tcp_rx_socket_bsize  uint32
	tcprexmtthresh       uint8
	tcp_mssdflt          uint16
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
	// tbd flow-tabe
}

func updateInitwnd(mss uint16, initwnd uint16) uint16 {
	calc := mss * initwnd

	if calc > 48*1024 {
		calc = 48 * 1024
	}
	return (calc)
}

func NewCtx(c *core.CClient) *transportCtx {
	o := new(transportCtx)
	o.init()
	o.Client = c
	o.Ns = c.Ns
	o.Tctx = c.Ns.ThreadCtx
	o.timerw = o.Tctx.GetTimerCtx()
	o.cdb = NewTcpStatsDb(&o.tcpStats)
	o.cdbv = core.NewCCounterDbVec("tcp")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.restartTimer()
	return o
}

// on tick 1000/PR_SLOWHZ msec
func (o *transportCtx) onTimerEvent() {
	o.tcp_maxidle = o.tcp_keepcnt * o.tcp_keepintvl
	if o.tcp_maxidle > (TCPTV_2MSL) {
		o.tcp_maxidle = (TCPTV_2MSL)
	}

	o.tcp_iss += TCP_ISSINCR / PR_SLOWHZ /* increment iss */
	o.tcp_now++                          /* for timestamps */
	o.restartTimer()
}

func (o *transportCtx) onRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *transportCtx) restartTimer() {
	o.timerw.Start(&o.timer, time.Duration(1000/PR_SLOWHZ)*time.Millisecond)
}

// init tunable
func (o *transportCtx) init() {
	o.tcp_iss = TCP_ISSINCR // TBD replace with random random32()
	o.tcp_blackhole = 0
	o.tcp_do_rfc1323 = true
	o.tcp_fast_tick_msec = TCP_FAST_TICK_
	o.tcp_initwnd = uint32(updateInitwnd(TCP_MSS, TCP_INITWND_FACTOR))
	o.tcp_initwnd_factor = TCP_INITWND_FACTOR
	o.tcp_keepidle = TCPTV_KEEP_IDLE
	o.tcp_keepinit = TCPTV_KEEP_INIT
	o.tcp_keepintvl = TCPTV_KEEPINTVL
	o.tcp_mssdflt = TCP_MSS
	o.tcp_no_delay = 0
	o.tcp_rx_socket_bsize = 32 * 1024
	o.tcp_tx_socket_bsize = 32 * 1024
	o.tcprexmtthresh = 3
	o.tcp_rttdflt = int16(TCPTV_SRTTDFLT / uint16(PR_SLOWHZ))
	o.tcp_keepcnt = TCPTV_KEEPCNT          /* max idle probes */
	o.tcp_maxpersistidle = TCPTV_KEEP_IDLE /* max idle time in persist */
	o.tcp_no_delay_counter = TCP_MSS * 2
}

func (o *transportCtx) getTcpIss() uint32 {
	o.tcp_iss++
	return o.tcp_iss
}
