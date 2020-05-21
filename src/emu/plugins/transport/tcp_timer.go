// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

func (o *TcpSocket) fasttimo() {
	sts := &o.ctx.tcpStats

	if (o.flags & TF_DELACK) > 0 {
		o.flags &= ^(uint16(TF_DELACK))
		o.flags |= TF_ACKNOW
		o.pkts_cnt = 0
		sts.tcps_delack++
		o.output()
	}
}

func (o *TcpSocket) canceltimers() {
	var i int

	for i = 0; i < TCPT_NTIMERS; i++ {
		o.timer[i] = 0
	}
}

func (o *TcpSocket) timers(timer int) {
	var rexmt int
	sts := &o.ctx.tcpStats

	switch timer {

	/*
	 * 2 MSL timeout in shutdown went off.  If we're closed but
	 * still waiting for peer to close and connection has been idle
	 * too long, or if 2MSL time is up from TIME_WAIT, delete connection
	 * control block.  Otherwise, check again in a bit.
	 */
	case TCPT_2MSL:

		if o.state != TCPS_TIME_WAIT &&
			o.idle <= o.ctx.tcp_maxidle {
			o.timer[TCPT_2MSL] = o.ctx.tcp_keepintvl
		} else {
			o.close()
		}

		/*
		 * Retransmission timer went off.  Message has not
		 * been acked within retransmit interval.  Back off
		 * to a longer retransmit interval and retransmit one segment.
		 */
	case TCPT_REXMT:
		o.rxtshift++
		if o.rxtshift > TCP_MAXRXTSHIFT {
			o.rxtshift = TCP_MAXRXTSHIFT
			sts.tcps_timeoutdrop++
			o.drop_now(SeETIMEDOUT)
			break
		}
		if o.state < TCPS_ESTABLISHED {
			rexmt = int(o.rexmtval()) * tcp_syn_backoff[o.rxtshift]
			sts.tcps_rexmttimeo_syn++
		} else {
			sts.tcps_rexmttimeo++
			rexmt = int(o.rexmtval()) * tcp_backoff[o.rxtshift]
		}

		rangeset(&o.rxtcur, uint16(rexmt),
			o.rttmin, TCPTV_REXMTMAX)

		o.timer[TCPT_REXMT] = o.rxtcur
		/*
		 * If losing, let the lower level know and try for
		 * a better route.  Also, if we backed off this far,
		 * our srtt estimate is probably bogus.  Clobber it
		 * so we'll take the next rtt measurement as our srtt;
		 * move the current srtt into rttvar to keep the current
		 * retransmit times until then.
		 */
		if o.rxtshift > (TCP_MAXRXTSHIFT / 4) {
			//in_losing(tp->t_inpcb); # no need that
			o.rttvar += (o.srtt >> TCP_RTT_SHIFT)
			o.srtt = 0
		}
		o.snd_nxt = o.snd_una
		/*
		 * If timing a segment in this window, stop the timer.
		 */
		o.rtt = 0
		/*
		 * Close the congestion window down to one segment
		 * (we'll open it by one segment for each ack we get).
		 * Since we probably have a window's worth of unacked
		 * data accumulated, this "slow start" keeps us from
		 * dumping all that data as back-to-back packets (which
		 * might overwhelm an intermediate gateway).
		 *
		 * There are two phases to the opening: Initially we
		 * open by one mss on each ack.  This makes the window
		 * size increase exponentially with time.  If the
		 * window is larger than the path can handle, this
		 * exponential growth results in dropped packet(s)
		 * almost immediately.  To get more time between
		 * drops but still "push" the network to take advantage
		 * of improving conditions, we switch from exponential
		 * to linear window opening at some threshhold size.
		 * For a threshhold, we use half the current window
		 * size, truncated to a multiple of the mss.
		 *
		 * (the minimum cwnd that will give us exponential
		 * growth is 2 mss.  We don't allow the threshhold
		 * to go below this.)
		 */
		{
			win := bsd_umin(o.snd_wnd, o.snd_cwnd) / 2 / uint32(o.maxseg)
			if win < 2 {
				win = 2
			}
			o.snd_cwnd = uint32(o.maxseg)
			o.snd_ssthresh = uint32(win) * uint32(o.maxseg)
			o.dupacks = 0
		}
		o.output()

	/*
	 * Persistance timer into zero window.
	 * Force a byte to be output, if possible.
	 */
	case TCPT_PERSIST:
		sts.tcps_persisttimeo++
		/*
		 * Hack: if the peer is dead/unreachable, we do not
		 * time out if the window is closed.  After a full
		 * backoff, drop the connection if the idle time
		 * (no responses to probes) reaches the maximum
		 * backoff that we would use if retransmitting.
		 */
		if o.rxtshift == TCP_MAXRXTSHIFT &&
			(o.idle >= o.ctx.tcp_maxpersistidle ||
				int(o.idle) >= int(o.rexmtval())*tcp_totbackoff) {
			sts.tcps_persistdrop++
			o.drop_now(SeETIMEDOUT)
		} else {
			o.setpersist()
			o.force = true
			o.output()
			o.force = false
		}

	/*
	 * Keep-alive timer went off; send something
	 * or drop connection if idle for too long.
	 */
	case TCPT_KEEP:
		sts.tcps_keeptimeo++
		if o.state < TCPS_ESTABLISHED {
			goto dropit
		}
		if (o.socket.so_options & US_SO_KEEPALIVE) > 0 {
			if o.idle >= o.ctx.tcp_keepidle+o.ctx.tcp_maxidle {
				goto dropit
			}
			/*
			 * Send a packet designed to force a response
			 * if the peer is up and reachable:
			 * either an ACK if the connection is still alive,
			 * or an RST if the peer has closed the connection
			 * due to timeout or reboot.
			 * Using sequence number tp->snd_una-1
			 * causes the transmitted zero-length segment
			 * to lie outside the receive window;
			 * by the protocol spec, this requires the
			 * correspondent TCP to respond.
			 */
			sts.tcps_keepprobe++
			o.respond(o.rcv_nxt, o.snd_una-1, TH_ACK)
			o.timer[TCPT_KEEP] = o.ctx.tcp_keepintvl
		} else {
			o.timer[TCPT_KEEP] = o.ctx.tcp_keepidle
		}
		break
	dropit:
		sts.tcps_keepdrops++
		o.drop_now(SeETIMEDOUT)
	}
}

func (o *TcpSocket) slowtimo() {
	o.cbmask = 0
	o.interrupt = true
	o._slowtimo()
	if (o.cbmask & SocketClosed) > 0 {
		o.cb.OnRxEvent(SocketEventType(o.cbmask))
	}
	o.interrupt = false
	o.handleDpc()
}

func (o *TcpSocket) _slowtimo() {
	var i int
	if o.state == TCPS_LISTEN {
		return
	}

	for i = 0; i < TCPT_NTIMERS; i++ {
		if o.timer[i] > 0 {
			o.timer[i]--
			if o.timer[i] == 0 {
				o.timers(i)
				if o.state == TCPS_CLOSED {
					return
				}
			}
		}
	}
	o.idle++
	if o.rtt != 0 {
		o.rtt++
	}
}
