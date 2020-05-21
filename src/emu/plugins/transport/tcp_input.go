// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
)

func haveRcvdSyn(state int16) bool {
	if state >= TCPS_SYN_RECEIVED {
		return true
	}
	return false
}

func haveRcvdFin(state int16) bool {
	if state >= TCPS_TIME_WAIT {
		return true
	}
	return false
}

func du32(a uint32, b uint32) int16 {
	var d int32
	d = int32(a - b)
	if d > 0x7FFF {
		d = 0x7FFF
	} else {
		if d < 0 {
			d = 0
		}
	}
	return int16(d)
}

func (o *TcpSocket) update_rcv_window(m *core.Mbuf, tcph *layers.TCP, ti_len *uint16, tiflags *uint8) {
	tcph.Seq++
	if uint32(*ti_len) > o.rcv_wnd {
		var todrop int32
		todrop = int32(uint32(*ti_len) - o.rcv_wnd)
		tcp_pktmbuf_trim(m, uint16(todrop))
		*ti_len = uint16(o.rcv_wnd)
		*tiflags &= ^(uint8(TH_FIN))
		sts := &o.ctx.tcpStats
		sts.tcps_rcvpackafterwin++
		sts.tcps_rcvbyteafterwin += uint64(todrop)
	}
	o.snd_wl1 = tcph.Seq - 1
	o.rcv_up = tcph.Seq
}

func (o *TcpSocket) input(ps *core.ParserPacketState) int {
	o.cbmask = 0

	o.interrupt = true
	r := o._input(ps)
	if o.cbmask > 0 {
		if o.cbmask&SocketRxData > 0 {
			o.cb.OnRxData(ps.M.GetData()[:])
		}
		if (o.cbmask & SocketRxMask) > 0 {
			o.cb.OnRxEvent(SocketEventType(o.cbmask))
		}
		if (o.cbmask & SocketTxMask) > 0 {
			o.cb.OnTxEvent(SocketEventType(o.cbmask))
		}
	}
	o.interrupt = false
	ps.M.FreeMbuf()
	o.handleDpc()
	return (r)
}

func (o *TcpSocket) _input(ps *core.ParserPacketState) int {

	var tiwin uint32
	var addseq uint32
	var ourfinisacked bool
	var needoutput bool
	var acked uint32

	m := ps.M
	p := m.GetData()

	var tcph layers.TCP
	err := tcph.DecodeFromBytes(p[ps.L4:], gopacket.NilDecodeFeedback)
	if err != nil {
		o.ctx.tcpStats.tcps_rx_parse_err++
		return core.PARSER_ERR
	}
	off := ps.L7

	tiflags := tcph.Flags
	tiack := ((tiflags & TH_ACK) == TH_ACK)
	tisyn := ((tiflags & TH_SYN) == TH_SYN)
	tirst := ((tiflags & TH_RST) == TH_RST)
	ti_len := ps.L7Len

	var ts_present bool
	var ts_val uint32
	var ts_ecr uint32
	ts_present = false
	var iss uint32
	var todrop int32

	ts_val = 0
	ts_ecr = 0

	if !tisyn {
		tiwin = uint32(tcph.Window) << o.snd_scale
	} else {
		tiwin = uint32(tcph.Window)
	}

	tcphz := uint32(tcph.DataOffset << 2)

	if (uint32(ps.L4)+tcphz) > m.PktLen() || (tcphz < TCP_HEADER_LEN) {
		o.ctx.tcpStats.tcps_rx_parse_err++
		return core.PARSER_ERR
	}

	so := o.socket
	sts := &o.ctx.tcpStats

	if o.state == TCPS_LISTEN {

		if (tiflags & (TH_RST | TH_ACK | TH_SYN)) != TH_SYN {
			/*
			 * Note: dropwithreset makes sure we don't
			 * send a reset in response to a RST.
			 */
			if tiack {
				sts.tcps_badsyn++
				goto dropwithreset
			}
			goto drop
		}

		/* Compute proper scaling value from buffer space
		 */
		for {
			con := (o.request_r_scale < TCP_MAX_WINSHIFT) &&
				(TCP_MAXWIN<<o.request_r_scale < so.so_rcv.sb_hiwat)
			if con {
				o.request_r_scale++
			} else {
				break
			}
		}
	}

	/*
	 * Segment received on connection.
	 * Reset idle time and keep-alive timer.
	 */
	o.idle = 0
	o.timer[TCPT_KEEP] = uint16(o.ctx.tcp_keepidle)

	/*
	 * Process options if not in LISTEN state,
	 * else do it below (after getting remote address).
	 */
	if (len(tcph.Options) > 0) && (o.state != TCPS_LISTEN) {
		o.dooptions(&tcph,
			&ts_present, &ts_val, &ts_ecr)
	}

	/*
	 * Header prediction: check for the two common cases
	 * of a uni-directional data xfer.  If the packet has
	 * no control flags, is in-sequence, the window didn't
	 * change and we're not retransmitting, it's a
	 * candidate.  If the length is zero and the ack moved
	 * forward, we're the sender side of the xfer.  Just
	 * free the data acked & wake any higher level process
	 * that was blocked waiting for space.  If the length
	 * is non-zero and the ack didn't move, we're the
	 * receiver side.  If we're getting packets in-order
	 * (the reassembly queue is empty), add the data to
	 * the socket buffer and note that we need a delayed ack.
	 */
	if (o.state == TCPS_ESTABLISHED) &&
		((tiflags & (TH_SYN | TH_FIN | TH_RST | TH_URG | TH_ACK)) == TH_ACK) &&
		(!ts_present || tstmp_geq(ts_val, o.ts_recent)) &&
		(tcph.Seq == o.rcv_nxt) &&
		(tiwin > 0) && (tiwin == o.snd_wnd) &&
		(o.snd_nxt == o.snd_max) {

		/*
		 * If last ACK falls within this segment's sequence numbers,
		 *  record the timestamp.
		 */
		if ts_present && seq_leq(tcph.Seq, o.last_ack_sent) &&
			seq_lt(o.last_ack_sent, tcph.Seq+uint32(ti_len)) {
			o.ts_recent_age = o.ctx.tcp_now
			o.ts_recent = ts_val
		}

		if ti_len == 0 {
			if seq_gt(tcph.Ack, o.snd_una) &&
				seq_leq(tcph.Ack, o.snd_max) &&
				o.snd_cwnd >= o.snd_wnd {
				/*
				 * this is a pure ack for outstanding data.
				 */
				sts.tcps_predack++
				if ts_present {
					o.xmit_timer(du32(o.ctx.tcp_now, ts_ecr) + 1)

				} else if (o.rtt != 0) &&
					seq_gt(tcph.Ack, o.rtseq) {
					o.xmit_timer(o.rtt)
				}
				acked := tcph.Ack - uint32(o.snd_una)
				sts.tcps_rcvackpack++
				sts.tcps_rcvackbyte += uint64(acked)
				/* clear the dup-ack*/
				if o.dupacks > 0 {
					o.dupacks = 0
				}
				so.so_snd.sbdrop(acked)

				o.snd_una = tcph.Ack

				/*
				 * If all outstanding data are acked, stop
				 * retransmit timer, otherwise restart timer
				 * using current (possibly backed-off) value.
				 * If process is waiting for space,
				 * wakeup/selwakeup/signal.  If data
				 * are ready to send, let tcp_output
				 * decide between more output or persist.
				 */
				if o.snd_una == o.snd_max {
					o.timer[TCPT_REXMT] = 0
				} else if o.timer[TCPT_PERSIST] == 0 {
					o.timer[TCPT_REXMT] = o.rxtcur
				}

				// TBD callbacks
				/*if so.so_snd.sb_flags & SB_NOTIFY {
					sowwakeup(so)
				}*/
				if so.so_snd.getSize() > 0 {
					o.output()
				}
				return 0
			}
		} else if (tcph.Ack == o.snd_una) &&
			(o.reass_is_exists() == false) &&
			(uint32(ti_len) <= so.so_rcv.sbspace()) {
			/*
			 * this is a pure, in-sequence data packet
			 * with nothing on the reassembly queue and
			 * we have enough buffer space to take it.
			 */
			sts.tcps_preddat++
			o.rcv_nxt += uint32(ti_len)
			sts.tcps_rcvpack++
			sts.tcps_rcvbyte += uint64(ti_len)
			/*
			 * Drop TCP, IP headers and TCP options then add data
			 * to socket buffer. remove padding
			 */
			tcp_pktmbuf_fix_mbuf(m, off, ti_len)

			o.sbappend(m, ti_len)

			/*
			 * If this is a short packet, then ACK now - with Nagel
			 *  congestion avoidance sender won't send more until
			 *  he gets an ACK.
			 */

			if o.countCheckNoDelay(ti_len) ||
				((tiflags & TH_PUSH) > 0) {
				o.flags |= TF_ACKNOW
				o.output()
			} else {
				o.flags |= TF_DELACK
			}

			return 0
		}
	}

	/*
	   * Drop TCP, IP headers and TCP options. go to L7
	     remove padding
	*/
	tcp_pktmbuf_fix_mbuf(m, off, ti_len)

	/*
	 * Calculate amount of space in receive window,
	 * and then do TCP input processing.
	 * Receive window is amount of space in rcv queue,
	 * but not less than advertised window.
	 */
	{
		var win int32
		win = int32(so.so_rcv.sbspace())
		if win < 0 {
			win = 0
		}
		o.rcv_wnd = uint32(bsd_imax(int32(win), (int32)(o.rcv_adv-o.rcv_nxt)))
	}

	switch o.state {

	/*
	 * If the state is LISTEN then ignore segment if it contains an RST.
	 * If the segment contains an ACK then it is bad and send a RST.
	 * If it does not contain a SYN then it is not interesting drop it.
	 * Don't bother responding if the destination was a broadcast.
	 * Otherwise initialize tp->rcv_nxt, and tp->irs, select an initial
	 * tp->iss, and send a segment:
	 *     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
	 * Also initialize tp->snd_nxt to tp->iss+1 and tp->snd_una to tp->iss.
	 * Fill in remote peer address fields if not previously specified.
	 * Enter SYN_RECEIVED state, and process any other fields of this
	 * segment in this state.
	 */
	case TCPS_LISTEN:
		{

			if len(tcph.Options) > 0 {
				o.dooptions(&tcph,
					&ts_present, &ts_val, &ts_ecr)
			}
			if iss > 0 {
				o.iss = iss
			} else {
				o.iss = o.ctx.tcp_iss
			}
			o.ctx.tcp_iss += o.getIssNewFlow()
			o.irs = tcph.Seq
			o.sendseqinit()
			o.rcvseqinit()
			o.flags |= TF_ACKNOW
			o.state = TCPS_SYN_RECEIVED
			o.timer[TCPT_KEEP] = o.ctx.tcp_keepinit
			sts.tcps_accepts++
			o.update_rcv_window(m, &tcph, &ti_len, &tiflags)
			goto step6
		}

	/*
	 * If the state is SYN_SENT:
	 *  if seg contains an ACK, but not for our SYN, drop the input.
	 *  if seg contains a RST, then drop the connection.
	 *  if seg does not contain SYN, then drop it.
	 * Otherwise this is an acceptable SYN segment
	 *  initialize tp->rcv_nxt and tp->irs
	 *  if seg contains ack then advance tp->snd_una
	 *  if SYN has been acked change to ESTABLISHED else SYN_RCVD state
	 *  arrange for segment to be acked (eventually)
	 *  continue processing rest of data/controls, beginning with URG
	 */
	case TCPS_SYN_SENT:
		if tiack &&
			(seq_leq(tcph.Ack, o.iss) ||
				seq_gt(tcph.Ack, o.snd_max)) {
			goto dropwithreset
		}
		if tirst {
			if tiack {
				o.drop_now(SeECONNREFUSED)
			}
			goto drop
		}
		if !tisyn {
			goto drop
		}
		if tiack {
			o.snd_una = tcph.Ack
			if seq_lt(o.snd_nxt, o.snd_una) {
				o.snd_nxt = o.snd_una
			}
		}
		o.timer[TCPT_REXMT] = 0
		o.irs = tcph.Seq
		o.rcvseqinit()
		o.flags |= TF_ACKNOW
		if tiack && seq_gt(o.snd_una, o.iss) {
			sts.tcps_connects++
			o.soisconnected()
			o.state = TCPS_ESTABLISHED
			/* Do window scaling on this connection? */
			if (o.flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
				(TF_RCVD_SCALE | TF_REQ_SCALE) {
				o.snd_scale = o.requested_s_scale
				o.rcv_scale = o.request_r_scale
			}
			o.tcp_reass_no_data()
			/*
			 * if we didn't have to retransmit the SYN,
			 * use its rtt as our initial srtt & rtt var.
			 */
			if o.rtt != 0 {
				o.xmit_timer(o.rtt)
			}
		} else {
			o.state = TCPS_SYN_RECEIVED
		}

		/*
		 * Advance tcph.Seq to correspond to first data byte.
		 * If data, trim to stay within window,
		 * dropping FIN if necessary.
		 */
		o.update_rcv_window(m, &tcph, &ti_len, &tiflags)
		goto step6
	}

	/*
	 * States other than LISTEN or SYN_SENT.
	 * First check timestamp, if present.
	 * Then check that at least some bytes of segment are within
	 * receive window.  If segment begins before rcv_nxt,
	 * drop leading data (and SYN) if nothing left, just ack.
	 *
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment
	 * and it's less than ts_recent, drop it.
	 */
	if ts_present && !tirst && (o.ts_recent > 0) &&
		seq_lt(ts_val, o.ts_recent) {

		/* Check to see if ts_recent is over 24 days old.  */
		if (int32)(o.ctx.tcp_now-o.ts_recent_age) > TCP_PAWS_IDLE {
			/*
			 * Invalidate ts_recent.  If this segment updates
			 * ts_recent, the age will be reset later and ts_recent
			 * will get a valid value.  If it does not, setting
			 * ts_recent to zero will at least satisfy the
			 * requirement that zero be placed in the timestamp
			 * echo reply when ts_recent isn't valid.  The
			 * age isn't reset until we get a valid ts_recent
			 * because we don't want out-of-order segments to be
			 * dropped when ts_recent is old.
			 */
			o.ts_recent = 0
		} else {
			sts.tcps_rcvduppack++
			sts.tcps_rcvdupbyte += uint64(ti_len)
			sts.tcps_pawsdrop++
			goto dropafterack
		}
	}

	todrop = int32(o.rcv_nxt - tcph.Seq)
	if todrop > 0 {
		if tisyn {
			tiflags &= (^uint8(TH_SYN))
			tcph.Seq++
			if tcph.Urgent > 1 {
				tcph.Urgent--
			} else {
				tiflags &= (^uint8(TH_URG))
			}
			todrop--
		}
		if todrop >= int32(ti_len) {
			sts.tcps_rcvduppack++
			sts.tcps_rcvdupbyte += uint64(ti_len)
			/*
			 * If segment is just one to the left of the window,
			 * check two special cases:
			 * 1. Don't toss RST in response to 4.2-style keepalive.
			 * 2. If the only thing to drop is a FIN, we can drop
			 *    it, but check the ACK or we will get into FIN
			 *    wars if our FINs crossed (both CLOSING).
			 * In either case, send ACK to resynchronize,
			 * but keep on processing for RST or ACK.
			 */
			if ((tiflags & TH_FIN) > 0) && (todrop == int32(ti_len+1)) {
				todrop = int32(ti_len)
				tiflags &= (^uint8(TH_FIN))
			} else {
				/*
				 * Handle the case when a bound socket connects
				 * to itself. Allow packets with a SYN and
				 * an ACK to continue with the processing.
				 */
				if (todrop != 0) || (tiack == false) {
					goto dropafterack
				}
			}
			o.flags |= TF_ACKNOW
		} else {
			sts.tcps_rcvpartduppack++
			sts.tcps_rcvpartdupbyte += uint64(todrop)
		}
		/* after this operation, it could be a mbuf with len==0 in  case of mbuf_len==todrop
		   still need to free it */
		tcp_pktmbuf_adj(m, uint16(todrop))

		tcph.Seq += uint32(todrop)
		ti_len -= uint16(todrop)
		if tcph.Urgent > uint16(todrop) {
			tcph.Urgent -= uint16(todrop)
		} else {
			tiflags &= (^uint8(TH_URG))
			tcph.Urgent = 0
		}
	}

	/*
	 * If new data are received on a connection after the
	 * user processes are gone, then RST the other end.
	 */
	if (o.state > TCPS_CLOSE_WAIT) && (ti_len > 0) {
		o.close()
		sts.tcps_rcvafterclose++
		goto dropwithreset
	}

	/*
	 * If segment ends after window, drop trailing data
	 * (and PUSH and FIN) if nothing left, just ACK.
	 */
	todrop = int32((tcph.Seq + uint32(ti_len)) - (o.rcv_nxt + o.rcv_wnd))
	if todrop > 0 {
		sts.tcps_rcvpackafterwin++
		if uint32(todrop) >= uint32(ti_len) {
			sts.tcps_rcvbyteafterwin += uint64(ti_len)
			/*
			 * If a new connection request is received
			 * while in TIME_WAIT, drop the old connection
			 * and start over if the sequence numbers
			 * are above the previous ones.
			 */
			if tisyn &&
				(o.state == TCPS_TIME_WAIT) &&
				seq_gt(tcph.Seq, o.rcv_nxt) {
				iss = o.snd_nxt + o.getIssNewFlow()
				o.close()
				goto drop
			}
			/*
			 * If window is closed can only take segments at
			 * window edge, and have to drop data and PUSH from
			 * incoming segments.  Continue processing, but
			 * remember to ack.  Otherwise, drop segment
			 * and ack.
			 */
			if (o.rcv_wnd == 0) && (tcph.Seq == o.rcv_nxt) {
				o.flags |= TF_ACKNOW
				sts.tcps_rcvwinprobe++
			} else {
				goto dropafterack
			}
		} else {
			sts.tcps_rcvbyteafterwin += uint64(todrop)
		}
		tcp_pktmbuf_trim(m, uint16(todrop))
		ti_len -= uint16(todrop)
		tiflags &= ^(uint8(TH_PUSH | TH_FIN))
	}

	/*
	 * If last ACK falls within this segment's sequence numbers,
	 * record its timestamp.
	 */
	addseq = 0
	if (tiflags & (TH_SYN | TH_FIN)) != 0 {
		addseq = 1
	}

	if ts_present && seq_leq(tcph.Seq, o.last_ack_sent) &&
		seq_lt(o.last_ack_sent, tcph.Seq+uint32(ti_len)+addseq) {
		o.ts_recent_age = o.ctx.tcp_now
		o.ts_recent = ts_val
	}

	/*
	 * If the RST bit is set examine the state:
	 *    SYN_RECEIVED STATE:
	 *  If passive open, return to LISTEN state.
	 *  If active open, inform user that connection was refused.
	 *    ESTABLISHED, FIN_WAIT_1, FIN_WAIT2, CLOSE_WAIT STATES:
	 *  Inform user that connection was reset, and close tcb.
	 *    CLOSING, LAST_ACK, TIME_WAIT STATES
	 *  Close the tcb.
	 */
	if tirst {
		switch o.state {
		case TCPS_SYN_RECEIVED, TCPS_ESTABLISHED, TCPS_FIN_WAIT_1, TCPS_FIN_WAIT_2, TCPS_CLOSE_WAIT:
			so.so_error = SeECONNRESET
			o.changeStateToClose()
			sts.tcps_drops++
			o.close()
			goto drop

		case TCPS_CLOSING, TCPS_LAST_ACK, TCPS_TIME_WAIT:
			o.close()
			goto drop
		}
	}

	/*
	 * If a SYN is in the window, then this is an
	 * error and we send an RST and drop the connection.
	 */
	if tisyn {
		o.drop_now(SeECONNRESET)
		goto dropwithreset
	}

	/*
	 * If the ACK bit is off we drop the segment and return.
	 */
	if tiack == false {
		goto drop
	}

	/*
	 * Ack processing.
	 */
	switch o.state {

	/*
	 * In SYN_RECEIVED state if the ack ACKs our SYN then enter
	 * ESTABLISHED state and continue processing, otherwise
	 * send an RST.
	 */
	case TCPS_SYN_RECEIVED:
		if seq_gt(o.snd_una, tcph.Ack) ||
			seq_gt(tcph.Ack, o.snd_max) {
			goto dropwithreset
		}
		sts.tcps_connects++
		o.soisconnected_cb()
		o.maxseg = o.mss(0)
		o.state = TCPS_ESTABLISHED
		/* Do window scaling? */
		if (o.flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
			(TF_RCVD_SCALE | TF_REQ_SCALE) {
			o.snd_scale = o.requested_s_scale
			o.rcv_scale = o.request_r_scale
		}
		o.tcp_reass_no_data()
		o.snd_wl1 = tcph.Seq - 1
		fallthrough
		/* fall into ... */

	/*
	 * In ESTABLISHED state: drop duplicate ACKs ACK out of range
	 * ACKs.  If the ack is in the range
	 *  tp->snd_una < tcph.Ack <= tp->snd_max
	 * then advance tp->snd_una to tcph.Ack and drop
	 * data from the retransmission queue.  If this ACK reflects
	 * more up to date window information we update our window information.
	 */
	case TCPS_ESTABLISHED,
		TCPS_FIN_WAIT_1,
		TCPS_FIN_WAIT_2,
		TCPS_CLOSE_WAIT,
		TCPS_CLOSING,
		TCPS_LAST_ACK,
		TCPS_TIME_WAIT:
		if seq_leq(tcph.Ack, o.snd_una) {
			if (ti_len == 0) && (tiwin == o.snd_wnd) {
				if o.state != TCPS_FIN_WAIT_2 {
					sts.tcps_rcvdupack++ /* we can get ack on FIN-ACK and it should not considered dup */
				}
				/*
				 * If we have outstanding data (other than
				 * a window probe), this is a completely
				 * duplicate ack (ie, window info didn't
				 * change), the ack is the biggest we've
				 * seen and we've seen exactly our rexmt
				 * threshhold of them, assume a packet
				 * has been dropped and retransmit it.
				 * Kludge snd_nxt & the congestion
				 * window so we send only this one
				 * packet.
				 *
				 * We know we're losing at the current
				 * window size so do congestion avoidance
				 * (set ssthresh to half the current window
				 * and pull our congestion window back to
				 * the new ssthresh).
				 *
				 * Dup acks mean that packets have left the
				 * network (they're now cached at the receiver)
				 * so bump cwnd by the amount in the receiver
				 * to keep a constant cwnd packets in the
				 * network.
				 */
				if (o.timer[TCPT_REXMT] == 0) ||
					(tcph.Ack != o.snd_una) {
					o.dupacks = 0
				} else {
					o.dupacks++
					if o.dupacks == o.ctx.tcprexmtthresh {
						var onxt uint32
						onxt = o.snd_nxt
						win := bsd_umin(o.snd_wnd, o.snd_cwnd) / 2 / uint32(o.maxseg)
						if win < 2 {
							win = 2
						}
						o.snd_ssthresh = win * uint32(o.maxseg)
						o.timer[TCPT_REXMT] = 0
						o.rtt = 0
						o.snd_nxt = tcph.Ack
						o.snd_cwnd = uint32(o.maxseg)
						o.output()
						o.snd_cwnd = o.snd_ssthresh + uint32(o.maxseg)*uint32(o.dupacks)
						if seq_gt(onxt, o.snd_nxt) {
							o.snd_nxt = onxt
						}
						goto drop
					} else if o.dupacks > o.ctx.tcprexmtthresh {
						o.snd_cwnd += uint32(o.maxseg)
						o.output()
						goto drop
					}
				}
			} else {
				o.dupacks = 0
			}
		} else {
			/*
			 * If the congestion window was inflated to account
			 * for the other side's cached packets, retract it.
			 */
			if (o.dupacks > o.ctx.tcprexmtthresh) &&
				(o.snd_cwnd > o.snd_ssthresh) {
				o.snd_cwnd = o.snd_ssthresh
			}
			o.dupacks = 0
			if seq_gt(tcph.Ack, o.snd_max) {
				sts.tcps_rcvacktoomuch++
				goto dropafterack
			}
			acked = tcph.Ack - o.snd_una
			sts.tcps_rcvackpack++

			/*
			 * If we have a timestamp reply, update smoothed
			 * round trip time.  If no timestamp is present but
			 * transmit timer is running and timed sequence
			 * number was acked, update smoothed round trip time.
			 * Since we now have an rtt measurement, cancel the
			 * timer backoff (cf., Phil Karn's retransmit alg.).
			 * Recompute the initial retransmit timer.
			 */
			if ts_present {
				o.xmit_timer(du32(o.ctx.tcp_now, ts_ecr) + 1)
			} else if (o.rtt != 0) && seq_gt(tcph.Ack, o.rtseq) {
				o.xmit_timer(o.rtt)
			}

			/*
			 * If all outstanding data is acked, stop retransmit
			 * timer and remember to restart (more output or persist).
			 * If there is more data to be acked, restart retransmit
			 * timer, using current (possibly backed-off) value.
			 */
			if tcph.Ack == o.snd_max {
				o.timer[TCPT_REXMT] = 0
				needoutput = true
			} else if o.timer[TCPT_PERSIST] == 0 {
				o.timer[TCPT_REXMT] = o.rxtcur
			}
			/*
			 * When new data is acked, open the congestion window.
			 * If the window gives us less than ssthresh packets
			 * in flight, open exponentially (maxseg per packet).
			 * Otherwise open linearly: maxseg per window
			 * (maxseg * (maxseg / cwnd) per packet).
			 */
			{
				var cw uint32
				var incr uint32
				cw = o.snd_cwnd
				incr = uint32(o.maxseg)

				if cw > o.snd_ssthresh {
					incr = incr * incr / cw
				}
				o.snd_cwnd = bsd_umin(cw+incr, TCP_MAXWIN<<o.snd_scale)
			}

			if acked > so.so_snd.getSize() {
				sts.tcps_rcvackbyte += uint64(so.so_snd.getSize())
				sts.tcps_rcvackbyte_of += uint64((acked - so.so_snd.getSize()))
				o.snd_wnd -= so.so_snd.getSize()
				so.so_snd.sbdrop_all()
				ourfinisacked = true
			} else {
				sts.tcps_rcvackbyte += uint64(acked)
				so.so_snd.sbdrop(acked)
				o.snd_wnd -= acked
				ourfinisacked = false
			}
			// TBDcall back
			/*if so.so_snd.sb_flags & SB_NOTIFY {
				sowwakeup(so)
			}*/
			o.snd_una = tcph.Ack
			if seq_lt(o.snd_nxt, o.snd_una) {
				o.snd_nxt = o.snd_una
			}

			switch o.state {

			/*
			 * In FIN_WAIT_1 STATE in addition to the processing
			 * for the ESTABLISHED state if our FIN is now acknowledged
			 * then enter FIN_WAIT_2.
			 */
			case TCPS_FIN_WAIT_1:
				if ourfinisacked {
					/*
					 * If we can't receive any more
					 * data, then closing user can proceed.
					 * Starting the timer is contrary to the
					 * specification, but if we don't get a FIN
					 * we'll hang forever.
					 */
					if (so.so_state & US_SS_CANTRCVMORE) > 0 {
						o.soisdisconnected()
						o.timer[TCPT_2MSL] = uint16(o.ctx.tcp_maxidle)
					}
					o.state = TCPS_FIN_WAIT_2
				}

			/*
			 * In CLOSING STATE in addition to the processing for
			 * the ESTABLISHED state if the ACK acknowledges our FIN
			 * then enter the TIME-WAIT state, otherwise ignore
			 * the segment.
			 */
			case TCPS_CLOSING:
				if ourfinisacked {
					o.state = TCPS_TIME_WAIT
					o.canceltimers()
					o.timer[TCPT_2MSL] = TCPTV_2MSL
					o.soisdisconnected()
				}

			/*
			 * In LAST_ACK, we may still be waiting for data to drain
			 * and/or to be acked, as well as for the ack of our FIN.
			 * If our FIN is now acknowledged, delete the TCB,
			 * enter the closed state and return.
			 */
			case TCPS_LAST_ACK:
				if ourfinisacked {
					o.close()
					goto drop
				}

			/*
			 * In TIME_WAIT state the only thing that should arrive
			 * is a retransmission of the remote FIN.  Acknowledge
			 * it and restart the finack timer.
			 */
			case TCPS_TIME_WAIT:
				o.timer[TCPT_2MSL] = TCPTV_2MSL
				goto dropafterack
			}
		}
	}

step6:
	/*
	 * Update window information.
	 * Don't look at window if no ACK: TAC's send garbage on first SYN.
	 */
	if tiack &&
		(seq_lt(o.snd_wl1, tcph.Seq) ||
			((o.snd_wl1 == tcph.Seq) &&
				(seq_lt(o.snd_wl2, tcph.Ack) || ((o.snd_wl2 == tcph.Ack) && (tiwin > o.snd_wnd))))) {
		/* keep track of pure window updates */
		if (ti_len == 0) &&
			(o.snd_wl2 == tcph.Ack) && (tiwin > o.snd_wnd) {
			sts.tcps_rcvwinupd++
		}
		o.snd_wnd = tiwin
		o.snd_wl1 = tcph.Seq
		o.snd_wl2 = tcph.Ack
		if o.snd_wnd > o.max_sndwnd {
			o.max_sndwnd = o.snd_wnd
		}
		needoutput = true
	}

	/* no need to support URG for now */
	if seq_gt(o.rcv_nxt, o.rcv_up) {
		o.rcv_up = o.rcv_nxt
	}

	//dodata:                           /* XXX */

	/*
	 * Process the segment text, merging it into the TCP sequencing queue,
	 * and arranging for acknowledgment of receipt if necessary.
	 * This process logically involves adjusting tp->rcv_wnd as data
	 * is presented to the user (this happens in tcp_usrreq.c,
	 * case PRU_RCVD).  If a FIN has already been received on this
	 * connection then we just ignore the text.
	 */
	if ((ti_len > 0) || ((tiflags & TH_FIN) > 0)) &&
		!haveRcvdFin(o.state) {
		o.reass(&tcph, m, so, &tiflags, ti_len, sts)
		/*
		 * Note the amount of data that peer has sent into
		 * our window, in order to estimate the sender's
		 * buffer size.
		 */
		//len = so->so_rcv.sb_hiwat - (tp->rcv_adv - tp->rcv_nxt)
	} else {
		tiflags &= (^uint8(TH_FIN))
	}

	/*
	 * If FIN is received ACK the FIN and let the user know
	 * that the connection is closing.
	 */
	if (tiflags & TH_FIN) > 0 {
		if haveRcvdFin(o.state) == false {
			o.soremotedisconnect()
			o.flags |= TF_ACKNOW
			o.rcv_nxt++
		}
		switch o.state {

		/*
		 * In SYN_RECEIVED and ESTABLISHED STATES
		 * enter the CLOSE_WAIT state.
		 */
		case TCPS_SYN_RECEIVED,
			TCPS_ESTABLISHED:
			o.state = TCPS_CLOSE_WAIT

		/*
		 * If still in FIN_WAIT_1 STATE FIN has not been acked so
		 * enter the CLOSING state.
		 */
		case TCPS_FIN_WAIT_1:
			o.state = TCPS_CLOSING

		/*
		 * In FIN_WAIT_2 state enter the TIME_WAIT state,
		 * starting the time-wait timer, turning off the other
		 * standard timers.
		 */
		case TCPS_FIN_WAIT_2:
			o.state = TCPS_TIME_WAIT
			o.canceltimers()
			o.timer[TCPT_2MSL] = TCPTV_2MSL
			o.soisdisconnected()

		/*
		 * In TIME_WAIT state restart the 2 MSL time_wait timer.
		 */
		case TCPS_TIME_WAIT:
			o.timer[TCPT_2MSL] = TCPTV_2MSL
		}
	}

	/*if so.so_options & US_SO_DEBUG {
		o.trace(TA_INPUT, ostate, tp, ti, 0, 0)
	}*/

	/*
	 * Return any desired output.
	 */
	if needoutput || ((o.flags & TF_ACKNOW) > 0) {
		o.output()
	}
	return 0

dropafterack:
	/*
	 * Generate an ACK dropping incoming segment if it occupies
	 * sequence space, where the ACK reflects our state.
	 */
	if tirst {
		goto drop
	}
	o.flags |= TF_ACKNOW
	o.output()
	return 0

dropwithreset:
	/*
	 * Generate a RST, dropping incoming segment.
	 * Make ACK acceptable to originator of segment.
	 * Don't bother to respond if destination was broadcast/multicast.
	 */
	if tirst {
		goto drop
	}

	/* want to use 64B mbuf for response and free big MBUF */

	if tiack {
		o.respond(0, tcph.Ack, TH_RST)
	} else {
		if tisyn {
			ti_len++
		}
		o.respond(tcph.Seq+uint32(ti_len), 0, TH_RST|TH_ACK)
	}
	/* destroy temporarily created socket */
	return 0

drop:
	/*
	 * Drop space held by incoming segment and return.
	 */
	/*if tp && (so.so_options & US_SO_DEBUG) {
		o.trace(TA_DROP, ostate, tp, ti, 0, 0)
	}*/
	/* destroy temporarily created socket */
	return 1
}

/*
 * Collect new round-trip time estimate
 * and update averages and current timeout.
 */
func (o *TcpSocket) xmit_timer(rtt int16) {
	var delta uint16
	sts := &o.ctx.tcpStats
	sts.tcps_rttupdated++
	if o.srtt != 0 {
		/*
		* srtt is stored as fixed point with 3 bits after the
		* binary point (i.e., scaled by 8).  The following magic
		* is equivalent to the smoothing algorithm in rfc793 with
		* an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
		* point).  Adjust rtt to origin 0.
		 */
		delta = uint16(rtt - 1 - (o.srtt >> TCP_RTT_SHIFT))
		o.srtt += int16(delta)
		if o.srtt <= 0 {
			o.srtt = 1
		}
		/*
		* We accumulate a smoothed rtt variance (actually, a
		* smoothed mean difference), then set the retransmit
		* timer to smoothed rtt + 4 times the smoothed variance.
		* rttvar is stored as fixed point with 2 bits after the
		* binary point (scaled by 4).  The following is
		* equivalent to rfc793 smoothing with an alpha of .75
		* (rttvar = rttvar*3/4 + |delta| / 4).  This replaces
		* rfc793's wired-in beta.
		 */
		if delta < 0 {
			delta = -delta
		}
		delta -= uint16((o.rttvar >> TCP_RTTVAR_SHIFT))
		o.rttvar += int16(delta)
		if o.rttvar <= 0 {
			o.rttvar = 1
		}
	} else {
		/*
		* No rtt measurement yet - use the unsmoothed rtt.
		* Set the variance to half the rtt (so our first
		* retransmit happens at 3*rtt).
		 */
		o.srtt = rtt << TCP_RTT_SHIFT
		o.rttvar = rtt << (TCP_RTTVAR_SHIFT - 1)
	}
	o.rtt = 0
	o.rxtshift = 0

	/*
	* the retransmit should happen at rtt + 4 * rttvar.
	* Because of the way we do the smoothing, srtt and rttvar
	* will each average +1/2 tick of bias.  When we compute
	* the retransmit timer, we want 1/2 tick of rounding and
	* 1 extra tick because of +-1/2 tick uncertainty in the
	* firing of the timer.  The bias will give us exactly the
	* 1.5 tick we need.  But, because the bias is
	* statistical, we have to test that we don't drop below
	* the minimum feasible timer (which is 2 ticks).
	 */
	rangeset(&o.rxtcur, uint16(o.rexmtval()),
		o.rttmin, TCPTV_REXMTMAX)

	/*
	* We received an ack for a packet that wasn't retransmitted
	* it is probably safe to discard any error indications we've
	* received recently.  This isn't quite right, but close enough
	* for now (a route might have failed after we sent a segment,
	* and the return path might not be symmetrical).
	 */
	o.softerror = 0
}

func (o *TcpSocket) countCheckNoDelay(bytes uint16) bool {

	if o.tcp_no_delay_counter == 0 {
		return false
	}
	o.pkts_cnt += uint16(bytes)
	if o.pkts_cnt >= o.tcp_no_delay_counter {
		o.pkts_cnt -= uint16(o.tcp_no_delay_counter)

		if o.pkts_cnt >= o.tcp_no_delay_counter {
			o.pkts_cnt = 0
		}
		return true
	}
	return false
}

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This macro assumes that the value of TCP_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */

func (o *TcpSocket) rexmtval() int16 {
	return (o.srtt >> TCP_RTT_SHIFT) + o.rttvar
}

func (o *TcpSocket) getIssNewFlow() uint32 {
	return o.ctx.getTcpIss() / 4
}

func (o *TcpSocket) soisdisconnected() {
	o.cbmask |= SocketRemoteDisconnect
}

func (o *TcpSocket) soremotedisconnect() {
	o.cbmask |= SocketRemoteDisconnect
}

func (o *TcpSocket) soisconnected() {
	o.cbmask |= SocketEventConnected
}

func (o *TcpSocket) sendseqinit() {
	o.snd_up = o.iss
	o.snd_max = o.snd_up
	o.snd_nxt = o.snd_max
	o.snd_una = o.snd_nxt
}

func (o *TcpSocket) rcvseqinit() {
	o.rcv_nxt = o.irs + 1
	o.rcv_adv = o.rcv_nxt
}

/* for now reass is not supported, segment need to come in order ! */
func (o *TcpSocket) reass_is_exists() bool {
	return false
}

func (o *TcpSocket) soisconnected_cb() {
	o.cbmask |= SocketEventConnected
}

func (o *TcpSocket) dooptions(tcph *layers.TCP,
	ts_present *bool, ts_val *uint32, ts_ecr *uint32) {

	for _, obj := range tcph.Options {
		switch obj.OptionType {
		case 0, 1:
			break
		case layers.TCPOptionKindMSS:
			if obj.OptionLength == 4 {
				if (tcph.Flags & TH_SYN) > 0 {
					newmss := binary.BigEndian.Uint16(obj.OptionData[0:2])
					/* sets t_maxseg */
					o.maxseg = uint16(bsd_umin(uint32(o.maxseg), uint32(o.mss(uint32(newmss)))))
				}
			}

		case layers.TCPOptionKindWindowScale:
			if obj.OptionLength == 3 {
				if (tcph.Flags & TH_SYN) > 0 {
					o.flags |= TF_RCVD_SCALE
					o.requested_s_scale = uint8(bsd_umin(uint32(obj.OptionData[0]), TCP_MAX_WINSHIFT))
				}
			}

		case layers.TCPOptionKindTimestamps:
			if obj.OptionLength == 10 {
				if len(obj.OptionData) == 8 {
					*ts_present = true
					*ts_val = binary.BigEndian.Uint32(obj.OptionData[0:4])
					*ts_ecr = binary.BigEndian.Uint32(obj.OptionData[4:8])
				}
			}
			if (tcph.Flags & TH_SYN) > 0 {
				o.flags |= TF_RCVD_TSTMP
				o.ts_recent = *ts_val
				o.ts_recent_age = o.ctx.tcp_now
			}
		}
	}
}

/*
 * Insert segment ti into reassembly queue of tcp with
 * control block tp.  Return TH_FIN if reassembly now includes
 * a segment with FIN.  The macro form does the common case inline
 * (segment is the next to be received on an established connection,
 * and the queue is empty), avoiding linkage into and removal
 * from the queue and repetition of various conversions.
 * Set DELACK for segments received in order, but ack immediately
 * when segments are out of order (so fast retransmit can work).
 */
func (o *TcpSocket) reass(tcph *layers.TCP,
	m *core.Mbuf,
	so *socketData,
	flags *uint8,
	ti_len uint16,
	sts *TcpStats) {
	// in order
	if tcph.Seq == o.rcv_nxt &&
		o.reass_is_exists() == false &&
		o.state == TCPS_ESTABLISHED {
		if *flags&TH_PUSH > 0 {
			o.flags |= TF_ACKNOW
		} else {
			o.flags |= TF_DELACK
		}
		o.rcv_nxt += uint32(ti_len)
		*flags = tcph.Flags & TH_FIN
		sts.tcps_rcvpack++
		sts.tcps_rcvbyte += uint64(ti_len)

		if o.countCheckNoDelay(ti_len) {
			o.flags |= TF_ACKNOW
		}
		o.sbappend(m, ti_len)
	} else {
		sts.tcps_rcvoopackdrop++
		sts.tcps_rcvoobytesdrop += uint64(ti_len)
		o.flags |= TF_ACKNOW
	}
}

// nothing to do, no reass data for now
func (o *TcpSocket) tcp_reass_no_data() {

}

// TBD callback
func (o *TcpSocket) sbappend(m *core.Mbuf, l uint16) {
	if l > 0 {
		if uint16(len(m.GetData()[:])) != l {
			panic("uint16(len(m.GetData()[:])) != len ")
		}
		o.cbmask |= SocketRxData
	} else {
		o.cbmask |= SocketRemoteDisconnect
	}
}

func tcp_pktmbuf_adj(m *core.Mbuf, len uint16) {
	if uint16(m.PktLen()) < len {
		panic(" tcp_pktmbuf_adj m.PktLen() < len ")
	}
	if m.IsContiguous() || len < m.DataLen() {
		m.Adj(len)
	} else {
		panic(" tcp_pktmbuf_adj is not supported for non contiguous ")
	}
}

func tcp_pktmbuf_trim(m *core.Mbuf, len uint16) {
	if uint16(m.PktLen()) < len {
		panic(" tcp_pktmbuf_trim m.PktLen() < len ")
	}
	if m.IsContiguous() {
		m.Trim(len)
	} else {
		panic(" tcp_pktmbuf_trim is not supported for non contiguous ")
	}
}

func tcp_pktmbuf_fix_mbuf(m *core.Mbuf,
	adj_len uint16,
	l7_len uint16) {
	tcp_pktmbuf_adj(m, adj_len)

	if uint16(m.PktLen()) > l7_len {
		pad_size := m.PktLen() - uint32(l7_len)
		tcp_pktmbuf_trim(m, uint16(pad_size))
	}
}
