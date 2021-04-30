// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"net"
	"time"
)

const (
	IP_IOCTL_TOS             = "tos"              // change the ipv4/ipv6 tos
	IP_IOCTL_TTL             = "ttl"              // change the ipv4/ipv6 ttl
	TCP_IOCTL_MSS            = "mss"              // sender tcp mss
	TCP_IOCTL_INITWND        = "initwnd"          // init window, send_window= init_wnd * mss
	TCP_IOCTL_NODELAY        = "no_delay"         // 0x1- no_delay  ,0x2 - force push by client for each packet, 0 - delay of delay counter
	TCP_IOCTL_NODELAY_CNT    = "no_delay_counter" // in case of a delay after how many bytes to force ack, by default it is 2 *MSS
	TCP_IOCTL_DELAY_ACK_MSEC = "delay_ack_msec"   // msec of fast tcp time
	TCP_IOCTL_TX_BUF_SIZE    = "txbufsize"        // tx queue in bytes, can be change only in case the queue if empty
	TCP_IOCTL_RX_BUF_SIZE    = "rxbufsize"        // rx queue in bytes
)

func (o *TcpSocket) SetIoctl(m IoctlMap) error {

	if o.socket == nil {
		o.serverIoctl = m
		return nil
	}
	o.setIoctlBase(m)

	// TOS
	// mss
	val, prs := m[TCP_IOCTL_MSS]
	if prs {
		mss, ok := val.(int)
		if ok {
			if mss > 9*1024 {
				mss = 9 * 1024
			}
			if mss > 0 {
				o.tun_mss = uint16(mss)
				o.tuneable_flags |= TUNE_MSS
			} else {
				o.tun_mss = 0
				o.tuneable_flags &= ^TUNE_MSS
			}

		}
	}

	val, prs = m[TCP_IOCTL_INITWND]
	if prs {
		initwnd, ok := val.(int)
		if ok {
			if initwnd > 20 {
				initwnd = 20
			}
			if initwnd > 0 {
				o.tun_init_window = uint16(initwnd)
				o.tuneable_flags |= TUNE_INIT_WIN
			} else {
				o.tuneable_flags &= ^TUNE_INIT_WIN
				o.tun_init_window = 0
			}
		}
	}

	val, prs = m[TCP_IOCTL_NODELAY]
	if prs {
		no_delay, ok := val.(int)
		if ok {
			if no_delay > 2 {
				no_delay = 0
			}
			if no_delay > 0 {
				o.tun_no_delay = uint16(no_delay)
				o.tuneable_flags |= TUNE_NO_DELAY
			} else {
				o.tun_no_delay = 0
				o.tuneable_flags &= ^TUNE_NO_DELAY
			}
		}
	}

	val, prs = m[TCP_IOCTL_NODELAY_CNT]
	if prs {
		no_delay_cnt, ok := val.(int)
		if ok {
			if no_delay_cnt > 0xffff {
				no_delay_cnt = 0xffff
			}
			o.tcp_no_delay_counter = uint16(no_delay_cnt)
		}
	}

	val, prs = m[TCP_IOCTL_DELAY_ACK_MSEC]
	if prs {
		ack_msec, ok := val.(int)
		if ok {
			if ack_msec < 20 {
				ack_msec = 20
			} else {
				if ack_msec > 500 {
					ack_msec = 500
				}
			}
			if ack_msec < int(o.timerw.MinTickMsec()) {
				ack_msec = int(o.timerw.MinTickMsec())
			}
			o.fastMsec = uint32(ack_msec)
		}
	}

	val, prs = m[TCP_IOCTL_TX_BUF_SIZE]
	if prs {
		txbufsize, ok := val.(int)
		if ok {
			if txbufsize < 2*1024 {
				txbufsize = 2 * 1024
			} else {
				if txbufsize > 1024*1024 {
					txbufsize = 1024 * 1024
				}
			}
			// replace only if empty
			if o.socket.so_snd.isEmpty() {
				o.socket.so_snd.onRemove()
				o.socket.so_snd.init(o.tctx, uint32(txbufsize))
				o.socket.so_snd.s = o
			}
		}
	}

	val, prs = m[TCP_IOCTL_RX_BUF_SIZE]
	if prs {
		rxbufsize, ok := val.(int)
		if ok {
			if rxbufsize < 2*1024 {
				rxbufsize = 2 * 1024
			} else {
				if rxbufsize > 1024*1024 {
					rxbufsize = 1024 * 1024
				}
			}
			o.socket.so_rcv.sb_hiwat = uint32(rxbufsize)
		}
	}

	return nil
}

func (o *TcpSocket) GetIoctl(m IoctlMap) error {
	o.getIoctlBase(m)
	if o.tun_mss > 0 {
		m[TCP_IOCTL_MSS] = int(o.tun_mss)
	} else {
		delete(m, TCP_IOCTL_MSS)
	}
	if o.tun_init_window > 0 {
		m[TCP_IOCTL_INITWND] = int(o.tun_init_window)
	} else {
		delete(m, TCP_IOCTL_INITWND)
	}
	if o.tun_no_delay > 0 {
		m[TCP_IOCTL_NODELAY] = int(o.tun_no_delay)
	} else {
		delete(m, TCP_IOCTL_NODELAY)
	}

	m[TCP_IOCTL_NODELAY_CNT] = int(o.fastMsec)
	m[TCP_IOCTL_TX_BUF_SIZE] = int(o.socket.so_snd.sb_hiwat)
	m[TCP_IOCTL_RX_BUF_SIZE] = int(o.socket.so_rcv.sb_hiwat)
	return nil
}

func (o *TcpSocket) LocalAddr() net.Addr {
	var l baseSocketLocalAddr
	l.net = "tcp"
	l.s = &o.baseSocket
	return &l
}

func (o *TcpSocket) RemoteAddr() net.Addr {
	var l baseSocketRemoteAddr
	l.net = "tcp"
	l.s = &o.baseSocket
	return &l
}

func (o *TcpSocket) GetCap() SocketCapType {
	return SocketCapStream | SocketCapConnection

}

func (o *TcpSocket) connect() SocketErr {
	sts := &o.ctx.tcpStats
	if o.state != TCPS_CLOSED {
		sts.tcps_already_opened++
		return SeALREADY_OPEN
	}

	/* Compute window scaling to request.  */
	for {
		if (o.request_r_scale < TCP_MAX_WINSHIFT) &&
			(TCP_MAXWIN<<o.request_r_scale) < o.socket.so_rcv.sb_hiwat {
			o.request_r_scale++
		} else {
			break
		}
	}

	sts.tcps_connattempt++
	o.state = TCPS_SYN_SENT
	o.timer[TCPT_KEEP] = o.ctx.tcp_keepinit
	o.iss = o.getIssNewFlow()
	o.sendseqinit()
	o.startTimers()
	o.output()
	return SeOK
}

func (o *TcpSocket) listen() SocketErr {
	sts := &o.ctx.tcpStats

	if o.state != TCPS_CLOSED {
		sts.tcps_already_opened++
		return SeALREADY_OPEN
	}

	o.state = TCPS_LISTEN
	o.startTimers()
	return SeOK
}

func (o *TcpSocket) doOutput() {
	if o.interrupt {
		o.dpc |= DPC_OUTPUT
	} else {
		o.output()
	}
}

// GetL7MTU returns the L7 MTU that is available for this socket.
func (o *TcpSocket) GetL7MTU() uint16 {
	// By definition this is the MSS.
	return o.maxseg
}

func (o *TcpSocket) GetSocket() interface{} {
	return o
}

func (o *TcpSocket) isStartClose() bool {
	if o.state > TCPS_CLOSE_WAIT || o.flags&TF_CLOSE_DEFER > 0 {
		return true
	}
	return false
}

func (o *TcpSocket) Write(buf []byte) (res SocketErr, queued bool) {

	sts := &o.ctx.tcpStats
	if o.isStartClose() {
		sts.tcps_already_closed++
		return SeCONNECTION_IS_CLOSED, false
	}

	if o.flags&TF_WRITE_DRAIN > 0 {
		sts.tcps_write_while_drain++
		return SeWRITE_WHILE_DRAIN, false
	}
	if len(buf) > 0 {
		s := o.socket.so_snd.getSize()
		r := o.socket.so_snd.writeHead(buf)

		if s == 0 && r > 0 {
			o.doOutput()
		}
		if !o.resolved {
			return SeUNRESOLVED, false
		}
		if r == len(buf) {
			return SeOK, true
		}

		o.flags |= TF_WRITE_DRAIN
		o.txqueue = buf[r:]
		return SeOK, false
	}
	return SeOK, true
}

func (o *TcpSocket) checkCloseDefer() {
	if o.flags&TF_CLOSE_DEFER > 0 {
		o.flags &= ^TF_CLOSE_DEFER
		o.dousrclosed()
	}
}

// return true in case we need to trigger the user event
func (o *TcpSocket) drainUserQueue() bool {

	if o.flags&TF_WRITE_DRAIN > 0 {
		if len(o.txqueue) > 0 {
			s := o.socket.so_snd.getSize()
			r := o.socket.so_snd.writeHead(o.txqueue)
			if s == 0 && r > 0 {
				o.doOutput()
			}
			if r == len(o.txqueue) {
				o.flags &= ^TF_WRITE_DRAIN
				o.txqueue = nil
				return true
			}
			o.txqueue = o.txqueue[r:]
			return false
		}
	}
	return true
}

/*
 * User issued close, and wish to trail through shutdown states.
  it will flush the tx queue before
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
*/
func (o *TcpSocket) Close() SocketErr {
	sts := &o.ctx.tcpStats
	if o.isStartClose() {
		sts.tcps_already_closed++
		return SeCONNECTION_IS_CLOSED
	}

	if o.interrupt == true {
		o.lastmask = o.cbmask
		o.dpc |= DPC_EVENTS
		o.usrclosed()
		return SeOK
	}
	o.cbmask = 0
	o.usrclosed()
	if (o.cbmask & SocketClosed) > 0 {
		o.cb.OnRxEvent(SocketEventType(o.cbmask))
	}
	return SeOK
}

func (o *TcpSocket) handleDpc() {
	if o.dpc > 0 {
		if o.dpc&DPC_OUTPUT > 0 {
			o.output()
		}
		if o.dpc&DPC_EVENTS > 0 {
			if ((o.lastmask & SocketClosed) == 0) && ((o.cbmask & SocketClosed) > 0) {
				o.cb.OnRxEvent(SocketEventType(o.cbmask))
			}
		}
	}
	o.dpc = 0
}

func (o *TcpSocket) GetLastError() SocketErr {
	return (o.socket.so_error)
}

func (o *TcpSocket) Shutdown() SocketErr {
	if o.state == TCPS_CLOSED {
		return SeOK
	}
	if o.interrupt == true {
		o.lastmask = o.cbmask
		o.dpc |= DPC_EVENTS
		o.drop_now(SeECONNRESET)
		return SeOK
	}
	o.cbmask = 0
	o.drop_now(SeECONNRESET)
	if (o.cbmask & SocketClosed) > 0 {
		o.cb.OnRxEvent(SocketEventType(o.cbmask))
	}
	return SeOK
}

func (o *TcpSocket) dousrclosed() {
	var output bool
	output = false

	switch o.state {
	case TCPS_CLOSED:

	case TCPS_LISTEN, TCPS_SYN_SENT:
		o.changeStateToClose()
		output = true

	case TCPS_SYN_RECEIVED, TCPS_ESTABLISHED:
		o.state = TCPS_FIN_WAIT_1
		output = true

	case TCPS_CLOSE_WAIT:
		o.state = TCPS_LAST_ACK
		output = true
	}
	if output {
		o.doOutput()
	}
}

func (o *TcpSocket) usrclosed() {

	if o.state == TCPS_ESTABLISHED {
		s := o.socket.so_snd.getSize()
		if s > 0 || len(o.txqueue) > 0 {
			// wait for flushing the tx queue
			o.flags |= TF_CLOSE_DEFER
			return
		}
	}
	o.dousrclosed()
}

func (o *TcpSocket) IsClose() bool {
	if o.state == TCPS_CLOSED {
		return true
	}
	return false
}

/*
 * Drop a TCP connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
func (o *TcpSocket) drop_now(res SocketErr) {
	sts := &o.ctx.tcpStats
	so := o.socket

	if haveRcvdSyn(o.state) {
		o.changeStateToClose()
		o.doOutput()
		sts.tcps_drops++
	} else {
		sts.tcps_conndrops++
	}
	if res == SeETIMEDOUT && o.softerror != SeOK {
		res = o.softerror
	}
	so.so_error = res
	o.close()
}

func (o *TcpSocket) changeStateToClose() bool {
	sts := &o.ctx.tcpStats
	if o.state != TCPS_CLOSED {
		o.removeFlowAssociation()
		o.cbmask |= SocketClosed
		sts.tcps_closed++
		// source port was allocated
		if o.srcPortAlloc {
			o.ctx.srcPorts.freePort(TCP_PROTO, o.srcPort)
		}
		o.onRemove()
		o.state = TCPS_CLOSED
		return true
	}
	return false
}

/*
 * Close a TCP control block:
 *  discard all space held by the tcp
 *  discard internet protocol block
 *  wake up any sleepers
 */
func (o *TcpSocket) close() {
	/* free the reassembly queue, if any */
	/* mark it as close and return zero */
	o.changeStateToClose()
}

func (o *TcpSocket) quench() {
	o.snd_cwnd = uint32(o.maxseg)
}

func (o *TcpSocket) init(client *core.CClient, ctx *TransportCtx) {
	o.baseSocket.init(client, ctx)

	o.timerw = o.tctx.GetTimerCtx()

	// set the tunables to zero
	o.tun_mss = 0
	o.tun_init_window = 0
	o.tun_no_delay = 0

	if ctx.tcp_do_rfc1323 {
		o.flags |= (TF_REQ_SCALE | TF_REQ_TSTMP)
	}

	if (ctx.tcp_no_delay & NO_DELAY_MASK_NAGLE) > 0 {
		o.flags |= TF_NODELAY
	}

	if (ctx.tcp_no_delay & NO_DELAY_MASK_PUSH) > 0 {
		o.flags |= TF_NODELAY_PUSH
	}
	o.reass_disabled = true // TBD for now

	o.srtt = TCPTV_SRTTBASE
	o.rttvar = ctx.tcp_rttdflt * PR_SLOWHZ
	o.rttmin = TCPTV_MIN
	rangeset(&o.rxtcur, uint16(o.rexmtval()),
		o.rttmin, TCPTV_REXMTMAX)

	rangeset(&o.rxtcur, ((uint16(TCPTV_SRTTBASE)>>2)+(TCPTV_SRTTDFLT<<2))>>1,
		TCPTV_MIN, TCPTV_REXMTMAX)
	o.snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT
	o.snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT
	o.tcp_no_delay_counter = ctx.tcp_no_delay_counter

	/* set the timers */
	o.fasttimer.SetCB(&o.fastTimerCb, o, 0)
	o.slowtimer.SetCB(&o.slowTimerCb, o, 0)
}

func (o *TcpSocket) startTimers() {
	o.timerw.Start(&o.slowtimer, time.Duration(SLOW_TIMER_MS)*time.Millisecond)
	o.fastMsec = uint32(o.ctx.tcp_fast_tick_msec)
	if o.fastMsec < o.timerw.MinTickMsec() {
		o.fastMsec = o.timerw.MinTickMsec()
	}
	o.timerw.Start(&o.fasttimer, time.Duration(o.fastMsec)*time.Millisecond)
}

func (o *TcpSocket) onRemove() {
	/* stop the timers */
	o.socket.so_snd.onRemove()
	if o.slowtimer.IsRunning() {
		o.timerw.Stop(&o.slowtimer)
	}
	if o.fasttimer.IsRunning() {
		o.timerw.Stop(&o.fasttimer)
	}
}

func (o *TcpSocket) onSlowTimerTick() {
	o.slowtimo()
	if o.state != TCPS_CLOSED {
		o.timerw.Start(&o.slowtimer, time.Duration(SLOW_TIMER_MS)*time.Millisecond)
	}
}

func (o *TcpSocket) onFastTimerTick() {
	o.fasttimo()
	if o.state != TCPS_CLOSED {
		o.timerw.Start(&o.fasttimer, time.Duration(o.fastMsec)*time.Millisecond)
	}
}

// detach the socket from the flow table
func (o *TcpSocket) removeFlowAssociation() {
	o.baseSocket.removeFlowAssociation(false, o)
}

// build template
func (o *TcpSocket) initphase2(cb ISocketCb, dstMac *core.MACKey) {
	o.cb = cb
	o.baseSocket.initphase2(false, dstMac)
	o.maxseg = o.ctx.tcp_mssdflt_ - (o.l4Offset - (20 + 14))
	o.socket = new(socketData)
	o.socket.so_snd.init(o.tctx, o.ctx.tcp_tx_socket_bsize)
	o.socket.so_snd.s = o
	o.socket.so_rcv.sb_hiwat = o.ctx.tcp_rx_socket_bsize
}

func (o *TcpSocket) getProto() uint8 {
	return TCP_PROTO
}

func (o *TcpSocket) getServerIoctl() IoctlMap {
	return o.serverIoctl
}

func (o *TcpSocket) clearServerIoctl() {
	o.serverIoctl = nil
}
