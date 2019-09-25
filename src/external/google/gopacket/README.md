# GoPacket
fork 2d7fab0d91d6bb77c1df6bdeb222270a2aa13820

This library provides packet decoding capabilities for Go.
See [godoc](https://godoc.org/external/google/gopacket) for more details.

[![Build Status](https://travis-ci.org/google/gopacket.svg?branch=master)](https://travis-ci.org/google/gopacket)
[![GoDoc](https://godoc.org/external/google/gopacket?status.svg)](https://godoc.org/external/google/gopacket)

Minimum Go version required is 1.5 except for pcapgo/EthernetHandle, afpacket, and bsdbpf which need at least 1.9 due to x/sys/unix dependencies.

Originally forked from the gopcap project written by Andreas
Krennmair <ak@synflood.at> (http://github.com/akrennmair/gopcap).
