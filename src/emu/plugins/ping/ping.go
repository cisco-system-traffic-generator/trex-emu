// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package ping

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"math/rand"
	"time"

	"github.com/intel-go/fastjson"
)

// PingClientIF is an interface that should be implemented by each Ping Client, meaning someone that
// wants to use the ping functionality. For example, ICMPv4/v6 are natural Ping Clients as they both
// use the ping functionality. However most of the ping code is generic, and could be used by both clients.
// The differences would be minor, and hence a client would only need implement the following three functions
// to get the whole ping functionality.
type PingClientIF interface {
	// PreparePingPacketTemplate creates a template Ping Packet depending on the protocol, ICMPv4/ICMPv6.
	// It receives as a parameter the Identifier, Sequence number for the ICMP header, and a magic value
	// which should be put as the first 8 bytes of the ICMP data.
	// It returns the complete packet, L2 to L4 and the offset of the icmpHeader in this packet.
	PreparePingPacketTemplate(id, seq uint16, magic uint64) (icmpHeaderOffset int, pkt []byte)
	// UpdateTxIcmpQuery updates the counter of the ping client when sending an echo requests.
	UpdateTxIcmpQuery(pktSend uint64)
	// OnPingRemove is called when we finish pinging (after timeout) or a ping stop request is received.
	OnPingRemove()
}

const (
	DefaultPingAmount      = 5   // Default amount of Echo - Requests
	DefaultPingPace        = 1.0 // Default pace of packets per second to send.
	DefaultPingTimeout     = 5   // Default timeout from when the last packet was sent till the stats are deleted
	DefaultPingPayloadSize = 16  // Default payload size for Echo-Requests.
	DefaultPingTTL         = 64  // Default TTL on an Echo-Request packet.
)

// PingParams contains a part of the RPC params that are independent of the ICMP version.
type PingParams struct {
	Amount  uint32  // Amount of echo requests to send
	Pace    float32 // Pace of sending the Echo-Requests in packets per second.
	Timeout uint8   // Timeout from last ping until the stats are deleted.
}

// PingStats contains the data that will be returned to the client.
// This should be unique per each ICMPv4 Identifier.
type PingStats struct {
	requestsSent         uint32        // how many Echo Requests were sent
	requestsLeft         uint32        // how many Echo Requests are left to send
	repliesBadIdentifier uint32        // how many Echo Replies with bad identifier received
	repliesMalformedPkt  uint32        // how many malformed Echo replies were received (short or bad magic)
	repliesBadLatency    uint32        // how many Echo Replies with negative (bad) latency were received
	dstUnreachable       uint32        // how many Destination Unreachable were received
	repliesInOrder       uint32        // how many Echo Replies received in order
	repliesOutOfOrder    uint32        // how many Echo Replies received out of order
	avgLatency           time.Duration // the average latency
	avgLatencyUsec       int64         // the average latency in usec
	minLatency           time.Duration // the minimal latency
	minLatencyUsec       int64         // the minimal latency in usec
	maxLatency           time.Duration // the maximal latency
	maxLatencyUsec       int64         // the maximal latency in usec

}

//Creates a database of ping stats
func NewPingStatsDb(o *PingStats) *core.CCounterDb {
	db := core.NewCCounterDb("icmp_ping_stats")
	db.Add(&core.CCounterRec{
		Counter:  &o.requestsSent,
		Name:     "requestsSent",
		Help:     "tx echo requests sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.requestsLeft,
		Name:     "requestsLeft",
		Help:     "tx echo requests left",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.repliesBadIdentifier,
		Name:     "repliesBadIdentifier",
		Help:     "rx echo replies bad identifier",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.repliesMalformedPkt,
		Name:     "repliesMalformedPkt",
		Help:     "rx echo replies malformed packet",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.repliesBadLatency,
		Name:     "repliesBadLatency",
		Help:     "rx echo replies bad latency",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.dstUnreachable,
		Name:     "dstUnreachable",
		Help:     "rx destination unreachable",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.repliesInOrder,
		Name:     "repliesInOrder",
		Help:     "rx echo replies in order",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.repliesOutOfOrder,
		Name:     "repliesOutOfOrder",
		Help:     "rx echo replies out of order",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.avgLatencyUsec,
		Name:     "avgLatency",
		Help:     "average latency",
		Unit:     "usec",
		DumpZero: true,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.minLatencyUsec,
		Name:     "minLatency",
		Help:     "minimal latency",
		Unit:     "usec",
		DumpZero: true,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.maxLatencyUsec,
		Name:     "maxLatency",
		Help:     "maximal latency",
		Unit:     "usec",
		DumpZero: true,
		Info:     core.ScINFO})
	return db
}

// Ping offers the functionality of Ping for a client. This client can be ICMPv4 or v6,
// it only needs to implement the PingClientIF interface.
// For now it has the following constraints :
// - One Ping instance per Client (can be fixed easily)
type Ping struct {
	timer              core.CHTimerObj     // timer object
	timerw             *core.TimerCtx      // timer wheel
	icmpHeaderOffset   int                 // offset of icmpv4 in pingPkt
	magic              uint64              // magic to verify that the payload contains a valid timestamp
	identifier         uint16              // identifier of this ping instance
	sequenceNumber     uint16              // sequence number of the upcoming ping
	startingSeq        uint16              // the starting sequence number
	firstReplyReceived bool                // represents if the first reply was received
	lastSeqReceived    uint16              // the sequence number of the last received Echo Response
	ticksPerInterval   uint32              // how many ticks in each interval
	pktsPerInterval    uint32              // how many packets to send on each interval
	sentRequests       uint32              // how many Echo Requests are sent
	latencySum         time.Duration       // sum of latency of all the packets that were received
	stats              *PingStats          // statistics to return to the client.
	params             PingParams          // Params received through the JSON-RPC
	cdb                *core.CCounterDb    // Counter Database for Stats
	cdbv               *core.CCounterDbVec // Database Vector
	tctx               *core.CThreadCtx    // thread context
	ns                 *core.CNSCtx        // namespace context
	pingClient         PingClientIF        // an interface that the ping client must implement either it is ICMPv4 or ICMPv6
	pingPkt            []byte              // the ping packet that will be sent
}

// NewPing creates a new Ping instance and returns a pointer to it.
func NewPing(params PingParams, ns *core.CNSCtx, pingClient PingClientIF) *Ping {
	o := new(Ping)
	o.params = params
	o.ns = ns
	o.tctx = o.ns.ThreadCtx
	o.pingClient = pingClient
	if !o.tctx.Simulation {
		o.identifier = uint16(rand.Intn(0xffff))
		o.sequenceNumber = uint16(rand.Intn(0xffff))
	} else {
		o.identifier = 0x1234
		o.sequenceNumber = 0xabcd
	}
	o.magic = 0xc15c0c15c0be5be5
	o.startingSeq = o.sequenceNumber
	o.stats = new(PingStats)
	o.cdb = NewPingStatsDb(o.stats)
	o.cdbv = core.NewCCounterDbVec("icmp_ping_stats")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(o, 0, 0)
	o.timerw = o.tctx.GetTimerCtx()
	dTime := time.Duration(float32(time.Second) / params.Pace)
	o.ticksPerInterval, o.pktsPerInterval = o.timerw.DurationToTicksBurst(dTime)
	o.icmpHeaderOffset, o.pingPkt = o.pingClient.PreparePingPacketTemplate(o.identifier, o.sequenceNumber, o.magic)
	return o
}

// StartPinging sends the first ping and starts a timer until the next ping should be sent.
func (o *Ping) StartPinging() {
	o.sendPing()
	o.timerw.StartTicks(&o.timer, o.ticksPerInterval)
}

// OnRemove should be called when Ping has finished or it is stopped.
func (o *Ping) OnRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.pingClient.OnPingRemove()
}

/* OnEvent - Event Driven call. Possible Events:
- Time to send another Echo Request
- Stop waiting for an Echo Response, after sending all Echo Requests. */
func (o *Ping) OnEvent(a, b interface{}) {
	if o.sentRequests < o.params.Amount {
		o.sendPing()
		if o.sentRequests == o.params.Amount {
			timeout := time.Duration(o.params.Timeout) * time.Second
			ticks := o.timerw.DurationToTicks(timeout)
			o.timerw.StartTicks(&o.timer, ticks)
		} else {
			o.timerw.StartTicks(&o.timer, o.ticksPerInterval)
		}
	} else {
		// Should have collected the records by now, timeout expired.
		o.OnRemove()
	}
}

//HandleEchoReply handles an Echo Reply received upon an Echo Request we sent.
func (o *Ping) HandleEchoReply(seq, id uint16, payload []byte) {
	if id != o.identifier {
		o.stats.repliesBadIdentifier++
		return
	}
	if len(payload) < 16 {
		o.stats.repliesMalformedPkt++
		return
	}
	magic := uint64(binary.BigEndian.Uint64(payload))
	if magic != o.magic {
		o.stats.repliesMalformedPkt++
		return
	}
	timestampUnixNano := int64(binary.BigEndian.Uint64(payload[8:]))
	timestamp := time.Unix(0, timestampUnixNano)
	now := time.Now()
	if o.tctx.Simulation {
		now = time.Unix(0, 128+int64(time.Millisecond))
	}
	latency := now.Sub(timestamp)
	if latency < 0 || latency > (DefaultPingTimeout*time.Second) {
		o.stats.repliesBadLatency++
		return
	}
	if !o.firstReplyReceived {
		// This is the first Response
		if seq == o.startingSeq {
			o.stats.repliesInOrder++
		} else {
			o.stats.repliesOutOfOrder++
		}
		o.firstReplyReceived = true
	} else {
		// Not the first response, lastSeqReceived was updated
		if o.lastSeqReceived+1 == seq {
			o.stats.repliesInOrder++
		} else {
			o.stats.repliesOutOfOrder++
		}
	}
	o.lastSeqReceived = seq

	o.latencySum += latency
	if int64(o.stats.minLatency) == 0 {
		o.stats.minLatency = latency
	}
	o.stats.minLatency = MinTimeDuration(o.stats.minLatency, latency)
	o.stats.maxLatency = MaxTimeDuration(o.stats.maxLatency, latency)
}

// HandleDestinationUnreachable handles an Destination Unreacheable upon an Echo Request we sent.
func (o *Ping) HandleDestinationUnreachable(id uint16) {
	if id != o.identifier {
		o.stats.repliesBadIdentifier++
		return
	}
	o.stats.dstUnreachable++
}

// GetPingCounters returns the Ping counters.
// The params decides things like the verbosity, filtering or whether to dump zero errors.
// The counters are updated before returning them.
func (o *Ping) GetPingCounters(params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p core.ApiCntParams
	o.updateStats()
	return o.cdbv.GeneralCounters(nil, o.tctx, params, &p)
}

// sendPing calculates how many packets to send (in case of burts), updates counters of ICMPQueries,
// and calls the PingClientIF.SendPing which should send the updated packets.
func (o *Ping) sendPing() {
	pktsToSend := MinUint32(o.pktsPerInterval, o.params.Amount-o.sentRequests)
	o.sentRequests += pktsToSend
	o.pingClient.UpdateTxIcmpQuery(uint64(pktsToSend))
	timestamp := uint64(time.Now().UnixNano())
	if o.tctx.Simulation {
		timestamp = 128
	}
	for i := uint32(0); i < pktsToSend; i++ {
		// It doesn't matter if this is ICMPv4 or ICMPv6, the packets are the same except for the type code (8 for ICMPv4, 128 for ICMPv6)
		// so using ICMPv4 Header for ICMPv6 will also work with no problem whatsoever.
		icmpHeader := layers.ICMPv4Header(o.pingPkt[o.icmpHeaderOffset:])
		oldSequence := icmpHeader.GetSequenceNumber()
		icmpHeader.SetSequenceNumber(o.sequenceNumber)
		icmpHeader.UpdateChecksum2(oldSequence, o.sequenceNumber)
		o.sequenceNumber++
		oldTimestamp := icmpHeader.GetTimestamp()
		icmpHeader.SetTimestamp(uint64(timestamp)) // Put a timestamp in the payload to be able to calculate latency.
		icmpHeader.UpdateChecksum3(oldTimestamp, timestamp)

		m := o.ns.AllocMbuf(uint16(len(o.pingPkt)))
		m.Append(o.pingPkt)
		o.tctx.Veth.Send(m)
	}
}

// updateStats calculates/updates the ping statistics before they are returned,
// since counters like average need not be updated on each packet received.
func (o *Ping) updateStats() {
	o.stats.requestsSent = o.sentRequests
	o.stats.requestsLeft = o.params.Amount - o.stats.requestsSent
	totalReplies := int64(o.stats.repliesInOrder + o.stats.repliesOutOfOrder)
	if totalReplies != 0 {
		o.stats.avgLatency = o.latencySum / time.Duration(totalReplies)
	}
	o.stats.minLatencyUsec = o.stats.minLatency.Microseconds()
	o.stats.maxLatencyUsec = o.stats.maxLatency.Microseconds()
	o.stats.avgLatencyUsec = o.stats.avgLatency.Microseconds()
}

// MinTimeDuration returns the minimal between two time.Durations.
func MinTimeDuration(a, b time.Duration) time.Duration {
	if int64(a) < int64(b) {
		return a
	}
	return b
}

// MaxTimeDuration returns the maximal between two time.Durations.
func MaxTimeDuration(a, b time.Duration) time.Duration {
	if int64(a) < int64(b) {
		return b
	}
	return a
}

// MinUint32 returns the minimal between two uint32.
func MinUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
