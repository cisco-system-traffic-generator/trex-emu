// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import "emu/core"

type TcpStats struct {
	tcps_connattempt uint64 /* connections initiated */
	tcps_accepts     uint64 /* connections accepted */
	tcps_connects    uint64 /* connections established */
	tcps_closed      uint64 /* conn. closed (includes drops) */
	tcps_segstimed   uint64 /* segs where we tried to get rtt */
	tcps_rttupdated  uint64 /* times we succeeded */
	tcps_delack      uint64 /* delayed acks sent */
	tcps_sndtotal    uint64 /* total packets sent */
	tcps_sndpack     uint64 /* data packets sent */

	tcps_sndbyte    uint64 /* data bytes sent by application layer  */
	tcps_sndbyte_ok uint64 /* data bytes sent by tcp  */

	tcps_sndctrl    uint64 /* control (SYN|FIN|RST) packets sent */
	tcps_sndacks    uint64 /* ack-only packets sent */
	tcps_rcvtotal   uint64 /* total packets received */
	tcps_rcvpack    uint64 /* packets received in sequence */
	tcps_rcvbyte    uint64 /* bytes received in sequence */
	tcps_rcvackpack uint64 /* rcvd ack packets */
	tcps_rcvackbyte uint64 /* bytes acked by rcvd acks */
	tcps_preddat    uint64 /* times hdr predict ok for data pkts */

	tcps_drop_unresolved uint64 /* not resolved  */

	tcps_drops          uint64 /* connections dropped */
	tcps_conndrops      uint64 /* embryonic connections dropped */
	tcps_timeoutdrop    uint64 /* conn. dropped in rxmt timeout */
	tcps_rexmttimeo     uint64 /* retransmit timeouts */
	tcps_rexmttimeo_syn uint64 /* retransmit SYN timeouts */
	tcps_persisttimeo   uint64 /* persist timeouts */
	tcps_keeptimeo      uint64 /* keepalive timeouts */
	tcps_keepprobe      uint64 /* keepalive probes sent */
	tcps_keepdrops      uint64 /* connections dropped in keepalive */
	tcps_testdrops      uint64 /* connections dropped at the end of the test due to --nc  */

	tcps_sndrexmitpack uint64 /* data packets retransmitted */
	tcps_sndrexmitbyte uint64 /* data bytes retransmitted */
	tcps_sndprobe      uint64 /* window probes sent */
	tcps_sndurg        uint64 /* packets sent with URG only */
	tcps_sndwinup      uint64 /* window update-only packets sent */

	tcps_rcvbadsum      uint64 /* packets received with ccksum errs */
	tcps_rcvbadoff      uint64 /* packets received with bad offset */
	tcps_rcvshort       uint64 /* packets received too short */
	tcps_rcvduppack     uint64 /* duplicate-only packets received */
	tcps_rcvdupbyte     uint64 /* duplicate-only bytes received */
	tcps_rcvpartduppack uint64 /* packets with some duplicate data */
	tcps_rcvpartdupbyte uint64 /* dup. bytes in part-dup. packets */
	tcps_rcvoopackdrop  uint64 /* OOO packet drop due to queue len */
	tcps_rcvoobytesdrop uint64 /* OOO bytes drop due to queue len uint64*/

	tcps_rcvoopack       uint64 /* out-of-order packets received */
	tcps_rcvoobyte       uint64 /* out-of-order bytes received */
	tcps_rcvpackafterwin uint64 /* packets with data after window */
	tcps_rcvbyteafterwin uint64 /* bytes rcvd after window */
	tcps_rcvafterclose   uint64 /* packets rcvd after "close" */
	tcps_rcvwinprobe     uint64 /* rcvd window probe packets */
	tcps_rcvdupack       uint64 /* rcvd duplicate acks */
	tcps_rcvacktoomuch   uint64 /* rcvd acks for unsent data */
	tcps_rcvwinupd       uint64 /* rcvd window update packets */
	tcps_pawsdrop        uint64 /* segments dropped due to PAWS */
	tcps_predack         uint64 /* times hdr predict ok for acks */
	tcps_persistdrop     uint64 /* timeout in persist state */
	tcps_badsyn          uint64 /* bogus SYN, e.g. premature ACK */

	tcps_reasalloc         uint64 /* allocate tcp reasembly object */
	tcps_reasfree          uint64 /* free tcp reasembly object  */
	tcps_nombuf            uint64 /* no mbuf for tcp - drop the packets */
	tcps_rcvackbyte_of     uint64 /* bytes acked by rcvd acks */
	tcps_rx_parse_err      uint64 /* rx parsing error */
	tcps_already_closed    uint64 /* close  API error */
	tcps_already_opened    uint64 /* connect/listen  API error */
	tcps_write_while_drain uint64 /* write  API error */
}

func NewTcpStatsDb(o *TcpStats) *core.CCounterDb {
	db := core.NewCCounterDb("tcp")

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_write_while_drain,
		Name:     "write_while_drain",
		Help:     "write_while_drain",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_already_opened,
		Name:     "already_opened",
		Help:     "already_opened",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_already_closed,
		Name:     "already_closed",
		Help:     "already_closed",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rx_parse_err,
		Name:     "rx_parse_err",
		Help:     "rx parsing error",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_connattempt,
		Name:     "connattempt",
		Help:     "connect attempt",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_accepts,
		Name:     "accepts",
		Help:     "accepts",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_connects,
		Name:     "connects",
		Help:     "connections established",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_segstimed,
		Name:     "segstimed",
		Help:     "segs where we tried to get rtt",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rttupdated,
		Name:     "rttupdated",
		Help:     "rtt times we succeeded",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_delack,
		Name:     "delack",
		Help:     "delayed acks sent",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndtotal,
		Name:     "sndtotal",
		Help:     "total packets sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndpack,
		Name:     "sndpack",
		Help:     "data packets sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvoopack,
		Name:     "rcvoopack",
		Help:     "out-of-order packets received",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvoobyte,
		Name:     "rcvoobyte",
		Help:     "out-of-order bytes received",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvpackafterwin,
		Name:     "rcvpackafterwin",
		Help:     "packets with data after window",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvbyteafterwin,
		Name:     "rcvbyteafterwin",
		Help:     "bytes rcvd after window ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvafterclose,
		Name:     "rcvafterclose",
		Help:     "packets rcvd after close",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvwinprobe,
		Name:     "rcvwinprobe",
		Help:     "rcvd window probe packets",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvdupack,
		Name:     "rcvdupack",
		Help:     "rcvd duplicate acks",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvacktoomuch,
		Name:     "rcvacktoomuch",
		Help:     "rcvd acks for unsent data",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvwinupd,
		Name:     "rcvwinupd",
		Help:     "rcvd window update packets",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_pawsdrop,
		Name:     "pawsdrop",
		Help:     "segments dropped due to PAWS",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_predack,
		Name:     "predack",
		Help:     "times hdr predict ok for acks",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_persistdrop,
		Name:     "persistdrop",
		Help:     "timeout in persist state",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_badsyn,
		Name:     "badsyn",
		Help:     "bogus SYN, e.g. premature ACK",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_reasalloc,
		Name:     "tcps_reasalloc",
		Help:     "allocate tcp reassembly object  ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_reasfree,
		Name:     "reasfree",
		Help:     "free tcp reasembly object  ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_nombuf,
		Name:     "nombuf",
		Help:     "no mbuf for tcp - drop the packets ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvackbyte_of,
		Name:     "rcvackbyte_of",
		Help:     "bytes acked by rcvd acks ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndrexmitpack,
		Name:     "sndrexmitpack",
		Help:     "data packets retransmitted ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndrexmitbyte,
		Name:     "sndrexmitbyte",
		Help:     "data bytes retransmitted",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndprobe,
		Name:     "sndprobe",
		Help:     "window probes sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndurg,
		Name:     "sndurg",
		Help:     "packets sent with URG only",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndwinup,
		Name:     "sndwinup",
		Help:     "window update-only packets sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvbadsum,
		Name:     "rcvbadsum",
		Help:     "packets received with ccksum errs",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvbadoff,
		Name:     "rcvbadoff",
		Help:     "packets received with bad offset ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvshort,
		Name:     "rcvshort",
		Help:     "packets received too short",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvduppack,
		Name:     "tcps_rcvduppack",
		Help:     "duplicate-only packets received  ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvdupbyte,
		Name:     "rcvdupbyte",
		Help:     "duplicate-only bytes received ",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvpartduppack,
		Name:     "rcvpartduppack",
		Help:     "packets with some duplicate data ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvpartdupbyte,
		Name:     "rcvpartdupbyte",
		Help:     "dup. bytes in part-dup. packets ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvoopackdrop,
		Name:     "rcvoopackdrop",
		Help:     "OOO bytes drop due to queue len ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvoobytesdrop,
		Name:     "rcvoobytesdrop",
		Help:     "OOO bytes drop due to queue len ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_drops,
		Name:     "drops",
		Help:     "connections dropped ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_conndrops,
		Name:     "conndrops",
		Help:     "embryonic connections dropped ",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_timeoutdrop,
		Name:     "timeoutdrop",
		Help:     "conn. dropped in rxmt timeout",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rexmttimeo,
		Name:     "rexmttimeo",
		Help:     "retransmit timeouts",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rexmttimeo_syn,
		Name:     "rexmttimeo_syn",
		Help:     "retransmit SYN timeouts",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_persisttimeo,
		Name:     "persisttimeo",
		Help:     "persist timeouts",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_keeptimeo,
		Name:     "keeptimeo",
		Help:     "keepalive timeouts",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_keepprobe,
		Name:     "keepprobe",
		Help:     "keepalive probes sent",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_keepdrops,
		Name:     "keepdrops",
		Help:     "connections dropped in keepalive",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_preddat,
		Name:     "preddat",
		Help:     "times hdr predict ok for data pkts",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvackbyte,
		Name:     "rcvackbyte",
		Help:     "bytes acked by rcvd acks",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvackpack,
		Name:     "rcvackpack",
		Help:     "rcvd ack packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvbyte,
		Name:     "rcvbyte",
		Help:     "bytes received in sequence",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvpack,
		Name:     "rcvpack",
		Help:     "packets received in sequence",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_rcvtotal,
		Name:     "rcvtotal",
		Help:     "total packets received ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndacks,
		Name:     "sndacks",
		Help:     "ack-only packets sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndctrl,
		Name:     "sndctrl",
		Help:     "control (SYN|FIN|RST) packets sent ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndbyte_ok,
		Name:     "sndbyte_ok",
		Help:     "data bytes sent by tcp ",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.tcps_sndbyte,
		Name:     "sndbyte",
		Help:     "data bytes sent by application layer",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}
