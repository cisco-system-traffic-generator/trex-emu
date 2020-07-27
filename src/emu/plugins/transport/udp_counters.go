// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import "emu/core"

type UdpStats struct {
	udp_sndpack uint64 /* data packets sent */
	udp_sndbyte uint64 /* data bytes sent by application layer  */

	udp_rcvbyte uint64 /* bytes received in sequence */
	udp_rcvpkt  uint64 /* bytes received in sequence */

	udp_drop_unresolved     uint64 /* not resolved  */
	udp_drop_msg_bigger_mtu uint64 /* msg is bigger than mtu */

}

func NewUdpStatsDb(o *UdpStats) *core.CCounterDb {
	db := core.NewCCounterDb("udp")

	db.Add(&core.CCounterRec{
		Counter:  &o.udp_sndpack,
		Name:     "udp_sndpack",
		Help:     "udp_sndpack",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.udp_sndbyte,
		Name:     "udp_sndbyte",
		Help:     "udp_sndbyte",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.udp_rcvbyte,
		Name:     "udp_rcvbyte",
		Help:     "udp_rcvbyte",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.udp_drop_unresolved,
		Name:     "udp_drop_unresolved",
		Help:     "udp_drop_unresolved",
		Unit:     "event",
		DumpZero: false,

		Info: core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.udp_drop_msg_bigger_mtu,
		Name:     "udp_drop_msg_bigger_mtu",
		Help:     "udp_drop_msg_bigger_mtu",
		Unit:     "event",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}
