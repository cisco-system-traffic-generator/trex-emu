// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"external/google/gopacket/layers"
)

const (
	TCPT_NTIMERS = 4
	TCPT_REXMT   = 0 /* retransmit */
	TCPT_PERSIST = 1 /* retransmit persistance */
	TCPT_KEEP    = 2 /* keep alive */
	TCPT_2MSL    = 3 /* 2*msl quiet time timer */

	TUNE_MSS      uint16 = 0x01
	TUNE_INIT_WIN uint16 = 0x02
	TUNE_NO_DELAY uint16 = 0x04

	DPC_EVENTS uint16 = 0x0002
	DPC_OUTPUT uint16 = 0x0003

	TF_ACKNOW       uint16 = 0x0001 /* ack peer immediately */
	TF_DELACK       uint16 = 0x0002 /* ack, but try to delay it */
	TF_NODELAY      uint16 = 0x0004 /* don't delay packets to coalesce */
	TF_NOOPT        uint16 = 0x0008 /* don't use tcp options */
	TF_SENTFIN      uint16 = 0x0010 /* have sent FIN */
	TF_REQ_SCALE    uint16 = 0x0020 /* have/will request window scaling */
	TF_RCVD_SCALE   uint16 = 0x0040 /* other side has requested scaling */
	TF_REQ_TSTMP    uint16 = 0x0080 /* have/will request timestamps */
	TF_RCVD_TSTMP   uint16 = 0x0100 /* a timestamp was received in SYN */
	TF_SACK_PERMIT  uint16 = 0x0200 /* other side said I could SACK */
	TF_NODELAY_PUSH uint16 = 0x0400 /*  */
	TF_CLOSE_NOTIFY uint16 = 0x0800 /* CLOSE was notified  */
	TF_WRITE_DRAIN  uint16 = 0x1000 /* write with a buffer to drain, not allowed to add more */
	TF_CLOSE_DEFER  uint16 = 0x2000 /* mask as closed  */

	TH_FIN        = 0x01
	TH_SYN        = 0x02
	TH_RST        = 0x04
	TH_PUSH       = 0x08
	TH_ACK        = 0x10
	TH_URG        = 0x20
	TCP_MAXWIN    = 65535 /* largest value for (unscaled) window */
	MAX_TCPOPTLEN = 32    /* max # bytes that go in options */

	TCPOPT_EOL     = 0
	TCPOPT_NOP     = 1
	TCPOPT_MAXSEG  = 2
	TCPOLEN_MAXSEG = 4
	TCPOPT_WINDOW  = 3
	TCPOLEN_WINDOW = 3
	TCP_HEADER_LEN = 20

	TCPOPT_TIMESTAMP    = 8
	TCPOLEN_TIMESTAMP   = 10
	TCPOLEN_TSTAMP_APPA = (TCPOLEN_TIMESTAMP + 2) /* appendix A */

	TCPOPT_TSTAMP_HDR = (TCPOPT_NOP<<24 | TCPOPT_NOP<<16 | TCPOPT_TIMESTAMP<<8 | TCPOLEN_TIMESTAMP)
	TCP_MAXRXTSHIFT   = 5 /* maximum retransmits */

	PR_SLOWHZ = 2 /* 2 slow timeouts per second */
	PR_FASTHZ = 5 /* 5 fast timeouts per second */

	TCPTV_SRTTBASE int16 = 0 /* base roundtrip time;
	   if 0, no idea yet */
	TCPTV_MIN        uint16 = 1                /* minimum allowable value */
	TCPTV_SRTTDFLT   uint16 = (2)              /* assumed RTT if no info */
	TCPTV_PERSMIN    uint16 = (5 * PR_SLOWHZ)  /* retransmit persistance */
	TCPTV_PERSMAX    uint16 = (10 * PR_SLOWHZ) /* maximum persist interval */
	TCP_MAX_WINSHIFT        = 14               /* maximum window shift */

	US_SS_CANTRCVMORE = 1
	TCPTV_2MSL        = 1 /* max seg lifetime (hah!) */

	TCP_PAWS_IDLE = (24 * 24 * 60 * 60 * PR_SLOWHZ)

	TCP_RTT_SCALE    = 8               /* multiplier for srtt; 3 bits frac. */
	TCP_RTT_SHIFT    = 3               /* shift for srtt; 3 bits frac. */
	TCP_RTTVAR_SCALE = 4               /* multiplier for rttvar; 2 bits */
	TCP_RTTVAR_SHIFT = 2               /* multiplier for rttvar; 2 bits */
	TCPTV_REXMTMAX   = (5 * PR_SLOWHZ) /* max allowable REXMT value */

	US_SO_DEBUG      = 0x0001 /* turn on debugging info recording */
	US_SO_ACCEPTCONN = 0x0002 /* socket has had listen() */
	US_SO_REUSEADDR  = 0x0004 /* allow local address reuse */
	US_SO_KEEPALIVE  = 0x0008 /* keep connections alive */
	US_SO_DONTROUTE  = 0x0010 /* just use interface addresses */
	US_SO_BROADCAST  = 0x0020 /* permit sending of broadcast msgs */

	NO_DELAY_MASK_NAGLE uint8 = 0x1
	NO_DELAY_MASK_PUSH  uint8 = 0x2
	SLOW_TIMER_MS             = 500
)

func seq_lt(a uint32, b uint32) bool {
	if int32(a-b) < 0 {
		return true
	}
	return false
}

func seq_leq(a uint32, b uint32) bool {
	if int32(a-b) <= 0 {
		return true
	}
	return false
}

func seq_gt(a uint32, b uint32) bool {
	if int32(a-b) > 0 {
		return true
	}
	return false
}

func tstmp_geq(a uint32, b uint32) bool {
	if int32(a-b) >= 0 {
		return true
	}
	return false
}

func seq_geq(a uint32, b uint32) bool {
	if int32(a-b) >= 0 {
		return true
	}
	return false
}

func bsd_imax(a int32, b int32) int32 {
	if a > b {
		return a
	} else {
		return b
	}
}

func bsd_umax(a uint32, b uint32) uint32 {
	if a > b {
		return a
	} else {
		return b
	}
}

type tcpPkt struct {
	m       *core.Mbuf
	optlen  uint16
	datalen uint16
	tcph    layers.TcpHeader
	options []byte
}

type tcpSlowTimer struct {
}

func (o *tcpSlowTimer) OnEvent(a, b interface{}) {
	pi := a.(*TcpSocket)
	pi.onSlowTimerTick()
}

type tcpFastTimer struct {
}

func (o *tcpFastTimer) OnEvent(a, b interface{}) {
	pi := a.(*TcpSocket)
	pi.onFastTimerTick()
}

type TcpSocket struct {

	/* template packet */
	l3Offset    uint16
	l4Offset    uint16
	pktTemplate []byte

	/* tuple */
	src core.Ipv4Key
	dst core.Ipv4Key

	srcIPv6 core.Ipv6Key
	dstIPv6 core.Ipv6Key

	srcPort uint16
	dstPort uint16
	ipv6    bool

	lastmask  uint16
	cbmask    uint16 // callbacks
	interrupt bool
	dpc       uint16

	timerw               *core.TimerCtx
	fasttimer            core.CHTimerObj
	slowtimer            core.CHTimerObj
	slowTimerCb          tcpSlowTimer
	fastTimerCb          tcpFastTimer
	fastMsec             uint32
	client               *core.CClient
	ns                   *core.CNSCtx
	tctx                 *core.CThreadCtx
	timer                [TCPT_NTIMERS]uint16
	force                bool
	dupacks              uint8
	pkts_cnt             uint16
	tcp_no_delay_counter uint16 /* number of recv bytes to wait until ack them */
	tuneable_flags       uint16

	state    int16  /* state of this connection */
	rxtshift int16  /* log(2) of rexmt exp. backoff */
	rxtcur   uint16 /* current retransmit value */
	maxseg   uint16 /* maximum segment size */
	flags    uint16

	/*
	 * The following fields are used as in the protocol specification.
	 * See RFC783, Dec. 1981, page 21.
	 */
	/* send sequence variables */
	snd_una uint32 /* send unacknowledged */
	snd_nxt uint32 /* send next */
	snd_up  uint32 /* send urgent pointer */
	snd_wl1 uint32 /* window update seg seq number */
	snd_wl2 uint32 /* window update seg ack number */
	iss     uint32 /* initial send sequence number */
	snd_wnd uint32 /* send window */
	/* receive sequence variables */
	rcv_wnd uint32 /* receive window */
	rcv_nxt uint32 /* receive next */
	rcv_up  uint32 /* receive urgent pointer */
	irs     uint32 /* initial receive sequence number */
	/*
	 * Additional variables for this implementation.
	 */
	/* receive variables */
	rcv_adv uint32 /* advertised window */
	/* retransmit variables */
	snd_max uint32 /* highest sequence number sent;
	 * used to recognize retransmits
	 */
	/* congestion control (for slow start, source quench, retransmit after loss) */
	snd_cwnd     uint32 /* congestion-controlled window */
	snd_ssthresh uint32 /* snd_cwnd size threshhold for
			* for slow start exponential to
	* linear switch
	*/
	/*
	 * transmit timing stuff.  See below for scale of srtt and rttvar.
	 * "Variance" is actually smoothed difference.
	 */
	/*====== end =============*/

	/*====== size 13 *4 = 48 bytes  */

	idle   uint16 /* inactivity time */
	rtt    int16  /* round trip time */
	srtt   int16  /* smoothed round-trip time */
	rttvar int16  /* variance in round-trip time */

	rtseq      uint32 /* sequence number being timed */
	max_sndwnd uint32 /* largest window peer has offered */
	rttmin     uint16 /* minimum rtt allowed */

	/* out-of-band data */
	softerror SocketErr /* possible error not yet reported */

	/* RFC 1323 variables */
	snd_scale         uint8 /* window scaling for send window */
	rcv_scale         uint8 /* window scaling for recv window */
	request_r_scale   uint8 /* pending window scaling */
	requested_s_scale uint8
	ts_recent         uint32 /* timestamp echo data */
	ts_recent_age     uint32 /* when last updated */
	last_ack_sent     uint32

	/*====== size 128 + 8 = 132 bytes  */

	//CTcpReass *m_tpc_reass     /* tcp reassembley object, allocated only when needed */
	//CTcpFlow  *m_flow          /* back pointer to flow*/
	reass_disabled bool /* don't reassemble ooo packet, to make payload content in order */
	ctx            *transportCtx
	socket         *socketData
	cb             ISocketCb
	txqueue        []byte /* tx pointer for user data */

	// tunables that can be set in SetIoctl
	tun_mss         uint16
	tun_init_window uint16
	tun_no_delay    uint16
}
