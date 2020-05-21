// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

/*
 * TCP FSM state definitions.
 * Per RFC793, September, 1981.
 */

const (
	TCP_NSTATES = 11

	TCPS_CLOSED       = 0 /* closed */
	TCPS_LISTEN       = 1 /* listening for connection */
	TCPS_SYN_SENT     = 2 /* active, have sent syn */
	TCPS_SYN_RECEIVED = 3 /* have send and received syn */
	/* states < TCPS_ESTABLISHED are those where connections not established */
	TCPS_ESTABLISHED = 4 /* established */
	TCPS_CLOSE_WAIT  = 5 /* rcvd fin, waiting for close */
	/* states > TCPS_CLOSE_WAIT are those where user has closed */
	TCPS_FIN_WAIT_1 = 6 /* have closed, sent fin */
	TCPS_CLOSING    = 7 /* closed xchd FIN; await FIN ACK */
	TCPS_LAST_ACK   = 8 /* had fin and close; await FIN ACK */
	/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
	TCPS_FIN_WAIT_2 = 9  /* have closed, fin is acked */
	TCPS_TIME_WAIT  = 10 /* in 2*msl quiet wait after close */
)

var tcp_outflags = [...]int32{
	TH_RST | TH_ACK, 0, TH_SYN, TH_SYN | TH_ACK,
	TH_ACK, TH_ACK,
	TH_FIN | TH_ACK, TH_FIN | TH_ACK, TH_FIN | TH_ACK, TH_ACK, TH_ACK,
}

var tcpstatename = [...]string{
	"CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
	"ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT_1", "CLOSING",
	"LAST_ACK", "FIN_WAIT_2", "TIME_WAIT",
}
