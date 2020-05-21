// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"encoding/binary"
	"external/google/gopacket/layers"
)

var tcp_backoff = [...]int{1, 2, 4, 8, 16, 32}

var tcp_totbackoff int = 64

var tcp_syn_backoff = [...]int{1, 1, 1, 2, 2, 3}

func bsd_umin(a uint32, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func (o *TcpSocket) send(pkt *tcpPkt) int {
	// fix checksum
	m := pkt.m
	p := m.GetData()
	if o.ipv6 == false {
		l3 := o.l3Offset
		l4 := o.l4Offset
		ipv4 := layers.IPv4Header(p[l3 : l3+20])
		/* update checsum */
		binary.BigEndian.PutUint16(p[l4+16:l4+18], 0)
		cs := layers.PktChecksumTcpUdp(p[l4:], 0, ipv4)
		binary.BigEndian.PutUint16(p[l4+16:l4+18], cs)
	} else {
		l4 := o.l4Offset
		l3 := o.l3Offset
		ipv6 := layers.IPv6Header(p[l3 : l3+40])
		ipv6.FixTcpL4Checksum(p[l4:], 0)
	}
	o.tctx.Veth.Send(m)
	return 0
}

func (o *TcpSocket) buildDpkt(off int32, datalen int32, hdrlen uint16, pkt *tcpPkt) int {
	if hdrlen < TCP_HEADER_LEN {
		panic(" tcphdrlen < TCP_HEADER_LEN !")
	}
	optlen := hdrlen - TCP_HEADER_LEN
	m := o.ns.AllocMbuf(uint16(len(o.pktTemplate)) + optlen + uint16(datalen))
	m.Append(o.pktTemplate)                 // template
	m.AppendBytes(optlen + uint16(datalen)) //option + data
	p := m.GetData()
	l4 := o.l4Offset
	l7o := l4 + hdrlen
	pkt.optlen = optlen
	pkt.m = m
	pkt.tcph = layers.TcpHeader(p[l4 : l4+TCP_HEADER_LEN])
	pkt.options = []byte(p[l4+TCP_HEADER_LEN : l4+TCP_HEADER_LEN+optlen])
	o.socket.so_snd.readOffset(uint32(off), uint32(datalen), p[l7o:]) // copy the data from the tx queue
	pkt.datalen = uint16(datalen)
	o.updatePktLen(pkt)
	return 0
}

func (o *TcpSocket) updatePktLen(pkt *tcpPkt) {
	m := pkt.m
	p := m.GetData()
	if o.ipv6 == false { //ipv4
		l3 := o.l3Offset
		ipv4 := layers.IPv4Header(p[l3 : l3+20])
		ipv4.SetLength(20 + TCP_HEADER_LEN + pkt.optlen + pkt.datalen)
		ipv4.UpdateChecksum()
	} else {
		l3 := o.l3Offset
		ipv6 := layers.IPv6Header(p[l3 : l3+40])
		ipv6.SetPyloadLength(TCP_HEADER_LEN + pkt.optlen + pkt.datalen)
	}
}

func (o *TcpSocket) buildCpkt(tcphdrlen uint16, pkt *tcpPkt) int {

	/* build a packet base on the template */
	if tcphdrlen < TCP_HEADER_LEN {
		panic(" tcphdrlen < TCP_HEADER_LEN !")
	}
	optlen := tcphdrlen - TCP_HEADER_LEN
	m := o.ns.AllocMbuf(uint16(len(o.pktTemplate)) + optlen)
	m.Append(o.pktTemplate)
	m.AppendBytes(optlen)
	p := m.GetData()
	l4 := o.l4Offset
	pkt.optlen = optlen
	pkt.datalen = 0
	pkt.m = m
	pkt.tcph = layers.TcpHeader(p[l4 : l4+TCP_HEADER_LEN])
	pkt.options = []byte(p[l4+TCP_HEADER_LEN : l4+TCP_HEADER_LEN+optlen])
	o.updatePktLen(pkt)
	return 0
}

func rangeset(tv *uint16, value uint16, tvmin uint16, tvmax uint16) {
	*tv = value
	if *tv < tvmin {
		*tv = tvmin
	} else if *tv > tvmax {
		*tv = tvmax
	}
}

/*
 * Determine a reasonable value for maxseg size.
 * If the route is known, check route for mtu.
 * If none, use an mss that can be handled on the outgoing
 * interface without forcing IP to fragment; if bigger than
 * an mbuf cluster (MCLBYTES), round down to nearest multiple of MCLBYTES
 * to utilize large mbufs.  If no route is found, route has no mtu,
 * or the destination isn't local, use a default, hopefully conservative
 * size (usually 512 or the default IP max size, but no more than the mtu
 * of the interface), as we can't discover anything about intervening
 * gateways or networks.  We also initialize the congestion/slow start
 * window to be a single segment if the destination isn't local.
 * While looking at the routing entry, we also initialize other path-dependent
 * parameters from pre-set or cached values in the routing entry.
 */
func (o *TcpSocket) mss(offer uint32) uint16 {
	if o.tuneable_flags == 0 {
		// no tunable
		o.snd_cwnd = o.ctx.tcp_initwnd
		return o.ctx.tcp_mssdflt
	} else {
		var mss uint16
		if o.tuneable_flags&TUNE_MSS > 0 {
			mss = o.tun_mss
		} else {
			mss = o.ctx.tcp_mssdflt
		}
		var initwnd uint32
		if o.tuneable_flags&TUNE_INIT_WIN > 0 {
			initwnd = uint32(o.tun_init_window)
		} else {
			initwnd = o.ctx.tcp_initwnd
		}

		if o.tuneable_flags&TUNE_NO_DELAY > 0 {
			if o.tun_no_delay&1 > 0 {
				o.flags |= TF_NODELAY
			} else {
				o.flags &= ^TF_NODELAY
			}
			if o.tun_no_delay&2 > 0 {
				o.flags |= TF_NODELAY_PUSH
			} else {
				o.flags &= ^TF_NODELAY_PUSH
			}
		}

		o.snd_cwnd = uint32(updateInitwnd(mss, uint16(initwnd)))
		return mss
	}
}

func (o *TcpSocket) output() int {
	var len int32
	var win uint32
	var off, flags int32
	var err int
	var opt [MAX_TCPOPTLEN]byte
	var optlen, hdrlen uint16
	var sendalot bool
	var idle bool
	so := o.socket

	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (o.snd_max == o.snd_una)

	if idle && int(o.idle) >= int(o.rxtcur) {
		/*
		 * We have been idle for "a while" and no acks are
		 * expected to clock out any data we send --
		 * slow start to get ack "clock" running again.
		 */
		o.snd_cwnd = uint32(o.maxseg)
	}

again:

	sendalot = false
	off = int32(o.snd_nxt - o.snd_una)
	win = bsd_umin(o.snd_wnd, o.snd_cwnd)

	flags = tcp_outflags[o.state]
	/*
	* If in persist timeout with window of 0, send 1 byte.
	* Otherwise, if window is small but nonzero
	* and timer expired, we will send what we can
	* and go to transmit state.
	 */

	/*
	 * If in persist timeout with window of 0, send 1 byte.
	 * Otherwise, if window is small but nonzero
	 * and timer expired, we will send what we can
	 * and go to transmit state.
	 */
	if o.force {
		if win == 0 {
			/*
			 * If we still have some data to send, then
			 * clear the FIN bit.  Usually this would
			 * happen below when it realizes that we
			 * aren't sending all the data.  However,
			 * if we have exactly 1 byte of unset data,
			 * then it won't clear the FIN bit below,
			 * and if we are in persist state, we wind
			 * up sending the packet without recording
			 * that we sent the FIN bit.
			 *
			 * We can't just blindly clear the FIN bit,
			 * because if we don't have any more data
			 * to send then the probe will be the FIN
			 * itself.
			 */
			if off < int32(so.so_snd.getSize()) {
				flags &= (^TH_FIN)
			}
			win = 1
		} else {
			o.timer[TCPT_PERSIST] = 0
			o.rxtshift = 0
		}
	}

	len = ((int32)(bsd_umin(so.so_snd.getSize(), win)) - off)
	if len < 0 {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be -1.  Otherwise, window shrank
		 * after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit and pull snd_nxt
		 * back to (closed) window.  We will enter persist
		 * state below.  If the window didn't close completely,
		 * just wait for an ACK.
		 */
		len = 0
		if win == 0 {
			o.timer[TCPT_REXMT] = 0
			o.snd_nxt = o.snd_una
		}
	}

	max_seg := int32(o.maxseg)
	if len > max_seg {
		len = max_seg
		sendalot = true
	}

	if seq_lt(o.snd_nxt+uint32(len), o.snd_una+uint32(so.so_snd.getSize())) {
		flags &= (^TH_FIN)
	}

	win = so.so_rcv.sbspace()

	/*
	 * Sender silly window avoidance.  If connection is idle
	 * and can send all data, a maximum segment,
	 * at least a maximum default-size segment do it,
	 * or are forced, do it; otherwise don't bother.
	 * If peer's buffer is tiny, then send
	 * when window is at least half open.
	 * If retransmitting (possibly after persist timer forced us
	 * to send into a small window), then must resend.
	 */
	if len > 0 {
		if len >= int32(o.maxseg) {
			goto send
		}
		if (idle || (o.flags&TF_NODELAY == TF_NODELAY)) &&
			len+off >= int32(so.so_snd.getSize()) {
			goto send
		}
		if o.force {
			goto send
		}
		if len >= int32(o.max_sndwnd/2) {
			goto send
		}
		if seq_lt(o.snd_nxt, o.snd_max) {
			goto send
		}
	}
	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 50% of the maximum possible
	 * window, then want to send a window update to peer.
	 */
	if win > 0 {
		/*
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP_MAXWIN << tp->rcv_scale.
		 */
		adv := int32(bsd_umin(win, ((uint32)(TCP_MAXWIN)<<o.rcv_scale))) -
			int32((o.rcv_adv - o.rcv_nxt))

		if adv >= (int32)(2*o.maxseg) {
			goto send
		}

		if (int32)(2*adv) >= ((int32)(so.so_rcv.sb_hiwat)) {
			goto send
		}
	}

	/*
	 * Send if we owe peer an ACK.
	 */
	if (o.flags & TF_ACKNOW) > 0 {
		goto send
	}
	if flags&(TH_SYN|TH_RST) > 0 {
		goto send
	}

	if seq_gt(o.snd_up, o.snd_una) {
		goto send
	}
	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, or we're retransmitting the FIN,
	 * then we need to send.
	 */
	if ((flags & TH_FIN) > 0) &&
		(((o.flags & TF_SENTFIN) == 0) || (o.snd_nxt == o.snd_una)) {
		goto send
	}

	/*
	 * TCP window updates are not reliable, rather a polling protocol
	 * using ``persist'' packets is used to insure receipt of window
	 * updates.  The three ``states'' for the output side are:
	 *  idle            not doing retransmits or persists
	 *  persisting      to move a small or zero window
	 *  (re)transmitting    and thereby not persisting
	 *
	 * tp->t_timer[TCPT_PERSIST]
	 *  is set when we are in persist state.
	 * tp->t_force
	 *  is set when we are called to send a persist packet.
	 * tp->t_timer[TCPT_REXMT]
	 *  is set when we are retransmitting
	 * The output side is idle when both timers are zero.
	 *
	 * If send window is too small, there is data to transmit, and no
	 * retransmit or persist is pending, then go to persist state.
	 * If nothing happens soon, send when timer expires:
	 * if window is nonzero, transmit what we can,
	 * otherwise force out a byte.
	 */
	if (so.so_snd.getSize() > 0) && (o.timer[TCPT_REXMT] == 0) &&
		o.timer[TCPT_PERSIST] == 0 {
		o.rxtshift = 0
		o.setpersist()
	}

	/*
	 * No reason to send a segment, just return.
	 */
	return 0

send:

	/*
	 * Before ESTABLISHED, force sending of initial options
	 * unless TCP set not to do any options.
	 * NOTE: we assume that the IP/TCP header plus TCP options
	 * always fit in a single mbuf, leaving room for a maximum
	 * link header, i.e.
	 *  max_linkhdr + sizeof (struct tcpiphdr) + optlen <= MHLEN
	 */
	optlen = 0
	hdrlen = TCP_HEADER_LEN
	if (flags & TH_SYN) > 0 {
		o.snd_nxt = o.iss
		if (o.flags & TF_NOOPT) == 0 {
			opt[0] = TCPOPT_MAXSEG
			opt[1] = 4
			binary.BigEndian.PutUint16(opt[2:4], o.mss(0))
			optlen = 4

			if ((o.flags & TF_REQ_SCALE) > 0) &&
				(((flags & TH_ACK) == 0) ||
					((o.flags & TF_RCVD_SCALE) > 0)) {
				var a uint32
				a = (TCPOPT_NOP << 24) |
					(TCPOPT_WINDOW << 16) |
					(TCPOLEN_WINDOW << 8) |
					uint32(o.request_r_scale)

				binary.BigEndian.PutUint32(opt[optlen:optlen+4], a)
				optlen += 4
			}
		}
	}

	/*
	 * Send a timestamp and echo-reply if this is a SYN and our side
	 * wants to use timestamps (TF_REQ_TSTMP is set) or both our side
	 * and our peer have sent timestamps in our SYN's.
	 */
	if ((o.flags & (TF_REQ_TSTMP | TF_NOOPT)) == TF_REQ_TSTMP) &&
		((flags & TH_RST) == 0) &&
		(((flags & (TH_SYN | TH_ACK)) == TH_SYN) ||
			((o.flags & TF_RCVD_TSTMP) > 0)) {

		l := optlen
		binary.BigEndian.PutUint32(opt[l+0:l+4], TCPOPT_TSTAMP_HDR)
		binary.BigEndian.PutUint32(opt[l+4:l+8], o.ctx.tcp_now)
		binary.BigEndian.PutUint32(opt[l+8:l+12], o.ts_recent)
		optlen += TCPOLEN_TSTAMP_APPA
	}

	hdrlen += optlen

	var pkt tcpPkt
	var tcph layers.TcpHeader

	/*
	 * Adjust data length if insertion of options will
	 * bump the packet length beyond the t_maxseg length.
	 */
	if len > int32(o.maxseg-optlen) {
		len = int32(o.maxseg - optlen)
		sendalot = true
		flags &= (^TH_FIN)
	}

	sts := &o.ctx.tcpStats
	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if len > 0 {
		if o.force && len == 1 {
			sts.tcps_sndprobe++
		} else if seq_lt(o.snd_nxt, o.snd_max) {
			sts.tcps_sndrexmitpack++
			sts.tcps_sndrexmitbyte += uint64(len)
		} else {
			sts.tcps_sndpack++
			sts.tcps_sndbyte_ok += uint64(len) /* better to be handle by application layer */
		}

		if o.buildDpkt(off, len, hdrlen, &pkt) != 0 {
			err = -1
			goto out
		}

		/*
		 * If we're sending everything we've got, set PUSH.
		 * (This will keep happy those implementations which only
		 * give data to the user when a buffer fills or
		 * a PUSH comes in.)
		 */
		/* Force PUSH in case of NODELAY of client side */
		if (off+len == int32(so.so_snd.getSize())) || ((o.flags & TF_NODELAY_PUSH) > 0) {
			flags |= TH_PUSH
		}

	} else {
		if (o.flags & TF_ACKNOW) > 0 {
			sts.tcps_sndacks++
		} else if (flags & (TH_SYN | TH_FIN | TH_RST)) > 0 {
			sts.tcps_sndctrl++
		} else if seq_gt(o.snd_up, o.snd_una) {
			sts.tcps_sndurg++
		} else {
			sts.tcps_sndwinup++
		}

		if o.buildCpkt(hdrlen, &pkt) != 0 {
			err = -1
			goto out
		}
	}

	tcph = pkt.tcph

	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if ((flags & TH_FIN) > 0) && ((o.flags & TF_SENTFIN) > 0) &&
		(o.snd_nxt == o.snd_max) {
		o.snd_nxt--
	}
	/*
	 * If we are doing retransmissions, then snd_nxt will
	 * not reflect the first unsent octet.  For ACK only
	 * packets, we do not want the sequence number of the
	 * retransmitted packet, we want the sequence number
	 * of the next unsent octet.  So, if there is no data
	 * (and no SYN or FIN), use snd_max instead of snd_nxt
	 * when filling in ti_seq.  But if we are in persist
	 * state, snd_max might reflect one byte beyond the
	 * right edge of the window, so use snd_nxt in that
	 * case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 */
	if (len > 0) || ((flags & (TH_SYN | TH_FIN)) > 0) || (o.timer[TCPT_PERSIST] > 0) {
		tcph.SetSeqNumber(uint32(o.snd_nxt))
	} else {
		tcph.SetSeqNumber(uint32(o.snd_max))
	}
	tcph.SetAckNumber(uint32(o.rcv_nxt))
	if optlen > 0 {
		copy(pkt.options[:], opt[0:optlen])
		tcph.SetHeaderLength(uint8(TCP_HEADER_LEN) + uint8(optlen))
	}
	tcph.SetFlags(uint8(flags & 0xff))

	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (win < (so.so_rcv.sb_hiwat / 4)) && (win < uint32(o.maxseg)) {
		win = 0
	}
	if win < (uint32)(o.rcv_adv-o.rcv_nxt) {
		win = (uint32)(o.rcv_adv - o.rcv_nxt)
	}
	if win > (uint32)(TCP_MAXWIN)<<o.rcv_scale {
		win = (uint32)(TCP_MAXWIN) << o.rcv_scale
	}

	tcph.SetWindowSize(uint16((win >> o.rcv_scale)))

	if seq_gt(o.snd_up, o.snd_nxt) {
		/* not support this for now - hhaim*/
		//ti->ti_urp = bsd_htons((u_short)(tp->snd_up - tp->snd_nxt));
		//ti->ti_flags |= TH_URG;
	} else {
		/*
		 * If no urgent pointer to send, then we pull
		 * the urgent pointer to the left edge of the send window
		 * so that it doesn't drift into the send window on sequence
		 * number wraparound.
		 */
		o.snd_up = o.snd_una /* drag it along */
	}

	/*
	 * In transmit state, time the transmission and arrange for
	 * the retransmit.  In persist state, just set snd_max.
	 */
	if (o.force == false) || (o.timer[TCPT_PERSIST] == 0) {
		var startseq uint32
		startseq = o.snd_nxt

		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (flags & (TH_SYN | TH_FIN)) > 0 {
			if (flags & TH_SYN) > 0 {
				o.snd_nxt++
			}
			if (flags & TH_FIN) > 0 {
				o.snd_nxt++
				o.flags |= TF_SENTFIN
			}
		}
		o.snd_nxt += uint32(len)
		if seq_gt(o.snd_nxt, o.snd_max) {
			o.snd_max = o.snd_nxt
			/*
			 * Time this transmission if not a retransmission and
			 * not currently timing anything.
			 */
			if o.rtt == 0 {
				o.rtt = 1
				o.rtseq = startseq
				sts.tcps_segstimed++
			}
		}

		/*
		 * Set retransmit timer if not currently set,
		 * and not doing an ack or a keep-alive probe.
		 * Initial value for retransmit timer is smoothed
		 * round-trip time + 2 * round-trip time variance.
		 * Initialize shift counter which is used for backoff
		 * of retransmit time.
		 */
		if (o.timer[TCPT_REXMT] == 0) &&
			o.snd_nxt != o.snd_una {
			o.timer[TCPT_REXMT] = o.rxtcur
			if o.timer[TCPT_PERSIST] > 0 {
				o.timer[TCPT_PERSIST] = 0
				o.rxtshift = 0
			}
		}
	} else {
		if seq_gt(o.snd_nxt+uint32(len), o.snd_max) {
			o.snd_max = o.snd_nxt + uint32(len)
		}
	}
	err = o.send(&pkt)

out:
	if err < 0 {
		o.quench()
		return (0)
	}
	sts.tcps_sndtotal++

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Any pending ACK has now been sent.
	 */
	if win > 0 && seq_gt(o.rcv_nxt+uint32(win), o.rcv_adv) {
		o.rcv_adv = o.rcv_nxt + uint32(win)
	}
	o.last_ack_sent = o.rcv_nxt
	o.flags &= ^(TF_ACKNOW | TF_DELACK)

	if sendalot {
		goto again
	}
	return 0
}

func (o *TcpSocket) setpersist() {
	var t int16

	t = ((o.srtt >> 2) + o.rttvar) >> 1

	/*
	* Start/restart persistance timer.
	 */
	rangeset(&o.timer[TCPT_PERSIST], uint16(t*int16(tcp_backoff[o.rxtshift])),
		TCPTV_PERSMIN, TCPTV_PERSMAX)

	if o.rxtshift < TCP_MAXRXTSHIFT {
		o.rxtshift++
	}
}

/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == 0, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection tp->t_template.  If flags are given
 * then we send a message back to the TCP which originated the
 * segment ti, and discard the mbuf containing it and any other
 * attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 */
func (o *TcpSocket) respond(ack uint32,
	seq uint32,
	flags uint8) {

	win := o.socket.so_rcv.sbspace()

	var pkt tcpPkt

	if o.buildCpkt(TCP_HEADER_LEN, &pkt) != 0 {
		return
	}
	tcph := pkt.tcph

	tcph.SetSeqNumber(uint32(seq))
	tcph.SetAckNumber(uint32(ack))
	tcph.SetFlags(flags)
	tcph.SetWindowSize(uint16(win >> o.rcv_scale))
	o.send(&pkt)
}
