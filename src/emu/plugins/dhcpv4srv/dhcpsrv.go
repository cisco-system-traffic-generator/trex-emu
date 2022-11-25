/*
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

package dhcpsrv

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"net"
	"sort"
	"time"
	"unsafe"

	"github.com/intel-go/fastjson"
)

/*
DHCP - Dynamic Host Configuration Protocol - https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol

Implementation based on RFC 2131, Server - https://datatracker.ietf.org/doc/html/rfc2131

Same clarifications are taken from here: https://datatracker.ietf.org/doc/html/draft-ietf-dhc-dhcpinform-clarify-01

Limitations
 - Only Ethernet as Hardware Type and chaddr as client identifier.
 - Only one DHCP Server per subnet.
 - No caching for clients whose lease finished.
*/

const (
	DHCP_SRV_PLUG       = "dhcpsrv"
	DHCPV4_CLIENT_PORT  = 68  // DHCPv4 Client Port
	DHCPV4_SERVER_PORT  = 67  // DHCPv4 Server Port
	OFFER_TIMEOUT       = 3   // Timeout to wait for a response to an Offer
	DefaultOfferedLease = 300 // Default Offered Lease, 5 minutes
	DefaultMinLease     = 60  // Default Minimal Lease, 1 minute
	DefaultMaxLease     = 600 // Default Maximal Lease, 10 minutes
)

// DHCPState for a client.
type DHCPState byte

const (
	DHCPInit DHCPState = iota
	DHCPSelecting
	DHCPRequesting
	DHCPRenewing
	DHCPRebinding
	DHCPBound
)

/*======================================================================================================
											Stats
======================================================================================================*/

// DhcpSrvStats is a struct that consolidates all the counters of an DhcpSrv.
type DhcpSrvStats struct {
	invalidInitJson     uint64 // Error while decoding client init Json
	mustNotOfferOpt     uint64 // Offer option that must not be sent provided in Init JSON
	mustNotAckInformOpt uint64 // Ack option that must not be sent to Inform provided in Init JSON
	mustNotAckReqOpt    uint64 // Ack option that must not be sent to Request provided in Init JSON
	mustNotNakOpt       uint64 // Nak option that must not be sent provided in Init JSON
	activeClients       uint64 // Active clients that are communicating with the server.
	pktRx               uint64 // Num packets received
	pktRxBroadcast      uint64 // Num of L2 broadcast packets received
	pktRxDhcpBroadcast  uint64 // Num of packets received with DHCP Broadcast flag
	pktRxBadMsgType     uint64 // Num packets received with invalid DHCP message type.
	pktRxBadChAddr      uint64 // Num packets received with non Ethernet HardwareAddress.
	pktRxBadDhcpReq     uint64 // Num DHCPREQUEST received that are invalid
	pktRxBadDhcpInform  uint64 // Num DHCPINFORM received that are invalid
	pktRxBadDhcpDecline uint64 // Num DHCPDECLINE received that are invalid
	pktRxNoClientCtx    uint64 // Num packets received with Client Identifier not found in database.
	pktRxDiscover       uint64 // Num of DHCPDISCOVER packets received
	pktRxRequest        uint64 // Num of DHCPREQUEST packets received
	pktRxDecline        uint64 // Num of DHCPDECLINE packets received
	pktRxRelease        uint64 // Num of DHCPRELEASE packets received
	pktRxInform         uint64 // Num of DHCPINFORM packets received
	pktTx               uint64 // Num packets transmitted
	pktTxOffer          uint64 // Num of DHCPOFFER packets sent
	pktTxAck            uint64 // Num of DHCPACK packets sent
	pktTxNak            uint64 // Num of DHCPNAK packets sent
	noIpAvailable       uint64 // No IPv4 available for client
	negatedIp           uint64 // Negated IPv4 as a result of DHCPDECLINE
	ciaddrMismatch      uint64 // Client Ip Address doesn't match the one provided by the server
}

// NewDnsClientStatsDb creates a new database of Dns counters.
func NewDhcpSrvStatsDb(o *DhcpSrvStats) *core.CCounterDb {
	db := core.NewCCounterDb(DHCP_SRV_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidInitJson,
		Name:     "invalidInitJson",
		Help:     "Error while decoding init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.mustNotOfferOpt,
		Name:     "mustNotOfferOpt",
		Help:     "Must NOT Offer option in Init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.mustNotAckInformOpt,
		Name:     "mustNotAckInformOpt",
		Help:     "Must NOT Ack option to DHCPINFORM in Init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.mustNotAckReqOpt,
		Name:     "mustNotAckReqOpt",
		Help:     "Must NOT Ack option to DHCPREQUEST in Init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.mustNotNakOpt,
		Name:     "mustNotNakOpt",
		Help:     "Must NOT NAK option in Init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.activeClients,
		Name:     "activeClients",
		Help:     "Num clients that are Offered/Bound/Renewing/Rebinding.",
		Unit:     "clients",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRx,
		Name:     "pktRx",
		Help:     "Rx packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBroadcast,
		Name:     "pktRxBroadcast",
		Help:     "Rx broadcast L2",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxDhcpBroadcast,
		Name:     "pktRxDhcpBroadcast",
		Help:     "Rx DHCP pkt with Broadcast Flag",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadMsgType,
		Name:     "pktRxBadMsgType",
		Help:     "Rx invalid DHCP message type",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadChAddr,
		Name:     "pktRxBadChAddr",
		Help:     "Rx invalid Hardware Address type",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadDhcpReq,
		Name:     "pktRxBadDhcpReq",
		Help:     "Rx invalid DHCPREQUEST",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadDhcpInform,
		Name:     "pktRxBadDhcpInform",
		Help:     "Rx invalid DHCPINFORM",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadDhcpDecline,
		Name:     "pktRxBadDhcpDecline",
		Help:     "Rx invalid DHCPDECLINE",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNoClientCtx,
		Name:     "pktRxNoClientCtx",
		Help:     "Client Identifier not found in database.",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxDiscover,
		Name:     "pktRxDiscover",
		Help:     "DHCPDISCOVER packets received",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRequest,
		Name:     "pktRxRequest",
		Help:     "DHCPREQUEST packets received",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxDecline,
		Name:     "pktRxDecline",
		Help:     "DHCPDECLINE packets received",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRelease,
		Name:     "pktRxRelease",
		Help:     "DHCPRELEASE packets received",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxInform,
		Name:     "pktRxInform",
		Help:     "DHCPINFORM packets received",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTx,
		Name:     "pktTx",
		Help:     "Tx packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxOffer,
		Name:     "pktTxOffer",
		Help:     "DHCPOFFER packets sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxAck,
		Name:     "pktTxAck",
		Help:     "DHCPACK packets sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxNak,
		Name:     "pktTxNak",
		Help:     "DHCPNAK packets sent",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.noIpAvailable,
		Name:     "noIpAvailable",
		Help:     "No IP available for client",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.negatedIp,
		Name:     "negatedIp",
		Help:     "Negated IP as a result of DHCPDECLINE",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ciaddrMismatch,
		Name:     "ciaddrMismatch",
		Help:     "Client Ip Addr database mismatch",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

/*======================================================================================================
											Ipv4Pool
======================================================================================================*/
// Ipv4PoolEntry is an entry in the pool. The entry contains an IPv4 but also other things. The idea
// is to be able to add, remove, lookup and iterate the pool on O(1) (real-time).
type Ipv4PoolEntry struct {
	dlist core.DList   // Note that the dlist must be kept first because of the unsafe conversion.
	ipv4  core.Ipv4Key // Ipv4
}

// convertToIpv4PoolEntry converts dlist to the Ipv4PoolEntry that contains the dlist.
// Note: For the conversion to work, the dlist must be kept first in the Ipv4PoolEntry.
func convertToIpv4PoolEntry(dlist *core.DList) *Ipv4PoolEntry {
	return (*Ipv4PoolEntry)(unsafe.Pointer(dlist))
}

// Ipv4Pool implements an Ipv4 pool with a simple fast Api to get/return IPv4s addresses.
type Ipv4Pool struct {
	pool         map[core.Ipv4Key]*Ipv4PoolEntry // Pool of available IPs
	excludedMap  map[uint32]bool                 // Excluded IPv4 addresses as uint32
	ipNet        *net.IPNet                      // Subnet
	head         core.DList                      // Head pointer to double linked list.
	subnetMask   core.Ipv4Key                    // Subnet Mask for this pool for fast lookup.
	min          core.Ipv4Key                    // Minimal Address in the Subnet.
	max          core.Ipv4Key                    // Maximal Address in the Subnet.
	firstIp      core.Ipv4Key                    // First Ip that we can offer. Not necessarily min, since min can be the Network Id.
	lastIp       core.Ipv4Key                    // Last Ip that we can offer. Not necessarily max, since max can be the Broadcast Id.
	subnetSize   uint32                          // Size of the subnet, including Network Id and Broadcast Id.
	size         uint32                          // Size of pool, total number of addresses the pool can distribute.
	exhausted    bool                            // Did we finish all the available entries?
	currPoolSize uint32                          // Amount of Ipv4 addresses already used.
}

// CreateIpv4Pool creates a new Ipv4 pool.
func CreateIpv4Pool(ipNet *net.IPNet, min, max core.Ipv4Key, excluded []core.Ipv4Key) *Ipv4Pool {
	o := new(Ipv4Pool)
	o.ipNet = ipNet
	ones, bits := o.ipNet.Mask.Size()
	o.subnetSize = 1 << (bits - ones) // Calculate Size of the Subnet
	o.head.SetSelf()                  // Set pointer to itself.

	subnetMask := net.IP(o.ipNet.Mask).To4()
	copy(o.subnetMask[:], subnetMask[0:4])
	o.min = min
	o.max = max

	// Make a simple map of excluded Ipv4s. For simplicity, this map is kept with keys of uint32.
	o.excludedMap = make(map[uint32]bool, len(excluded))
	for _, ip := range excluded {
		o.excludedMap[ip.Uint32()] = true
	}

	var networkId core.Ipv4Key
	copy(networkId[:], o.ipNet.IP.To4()[0:4])

	if o.min.Uint32() > networkId.Uint32() {
		o.firstIp = o.min
	} else {
		// Since min is part of the network, then min == networkId
		o.firstIp.SetUint32(o.min.Uint32() + 1)
	}

	var broadcastId core.Ipv4Key
	broadcastId.SetUint32(networkId.Uint32() + o.subnetSize - 1)

	if o.max.Uint32() < broadcastId.Uint32() {
		o.lastIp = o.max
	} else {
		// Since max is part of the network, then max == broadcastId
		o.lastIp.SetUint32(o.max.Uint32() - 1)
	}

	o.size = o.lastIp.Uint32() - o.firstIp.Uint32() + 1
	o.pool = make(map[core.Ipv4Key]*Ipv4PoolEntry)

	o.enlargePool()
	return o
}

// removeEntry removes an entry from the pool of available Ipv4.
// Takes O(1)
func (o *Ipv4Pool) removeEntry(entry *Ipv4PoolEntry) {
	entry, ok := o.pool[entry.ipv4]
	if !ok {
		panic("Trying to removing non-existing entry from Ipv4Pool.")
	}

	o.head.RemoveNode(&entry.dlist)

	delete(o.pool, entry.ipv4)
}

// enlargePool enlarges the pool of Ipv4 by another chunk of 256 IPv4 addresses.
// Takes O(1) amortized.
func (o *Ipv4Pool) enlargePool() {
	if o.currPoolSize == o.size {
		// Nothing to do, exhausted.
		o.exhausted = true
		return
	}

	startingIp := o.firstIp.Uint32() + o.currPoolSize

	var chunkSize uint32 = 256
	if o.size-o.currPoolSize < chunkSize {
		// Less than chunkSize IPv4s left. Last available chunk.
		chunkSize = o.size - o.currPoolSize
		o.exhausted = true
	}
	o.currPoolSize += chunkSize

	var i uint32
	var ipv4Key core.Ipv4Key
	for i = 0; i < chunkSize; i++ {
		if o.excludedMap[startingIp+i] {
			// need to skip this Ip
			continue
		}
		ipv4Key.SetUint32(startingIp + i)
		o.AddLast(ipv4Key)
	}
}

// canAdd indicates if an Ipv4 can be added to this pool. Takes O(1)
func (o *Ipv4Pool) canAdd(ipv4 core.Ipv4Key) bool {
	if _, ok := o.pool[ipv4]; ok {
		// Entry already exists
		return false
	}

	return o.Contains(ipv4)
}

// AddLast adds an Ipv4 address to the end of the pool in O(1).
// Returns True if the Ipv4 was added successfully.
func (o *Ipv4Pool) AddLast(ipv4 core.Ipv4Key) bool {
	if !o.canAdd(ipv4) {
		return false
	}
	entry := Ipv4PoolEntry{ipv4: ipv4}
	o.head.AddLast(&entry.dlist)
	o.pool[ipv4] = &entry
	return true
}

// AddFirst adds an Ipv4 address to the beginning of the pool in O(1).
// Returns True if the Ipv4 was added successfully.
func (o *Ipv4Pool) AddFirst(ipv4 core.Ipv4Key) bool {
	if !o.canAdd(ipv4) {
		return false
	}
	entry := Ipv4PoolEntry{ipv4: ipv4}
	o.head.AddFirst(&entry.dlist)
	o.pool[ipv4] = &entry
	return true
}

// GetFirst gets the first available Ipv4 address from the pool in O(1).
// In case the pool is empty, it will return an error.
func (o *Ipv4Pool) GetFirst() (ipv4 core.Ipv4Key, err error) {
	if len(o.pool) == 0 {
		// Pool is empty, maybe it was fragmented, need to check if exhausted
		if o.exhausted {
			return ipv4, fmt.Errorf("Ipv4 pool is empty.")
		} else {
			o.enlargePool()
		}

	}
	entry := convertToIpv4PoolEntry(o.head.Next())
	ipv4 = entry.ipv4
	o.removeEntry(entry)
	return ipv4, nil
}

// GetEntry gets an entry from the pool if that entry is available.
// Returns a bool indicating if the entry is available.
func (o *Ipv4Pool) GetEntry(ipv4 core.Ipv4Key) bool {
	if entry, ok := o.pool[ipv4]; ok {
		o.removeEntry(entry) // Remove entry from pool, and return true
		return true
	}
	return false
}

// GetSubnetMask returns the subnet mask for this pool.
func (o *Ipv4Pool) GetSubnetMask() core.Ipv4Key {
	return o.subnetMask
}

// InSubnet returns true if the Ipv4 is contained in this subnet.
func (o *Ipv4Pool) InSubnet(ipv4 core.Ipv4Key) bool {
	return o.ipNet.Contains(ipv4.ToIP())
}

// Contains returns true if the Ipv4 is contained in this pool.
func (o *Ipv4Pool) Contains(ipv4 core.Ipv4Key) bool {
	ipv4Uint32 := ipv4.Uint32()
	if _, ok := o.excludedMap[ipv4Uint32]; ok {
		return false
	}
	return (o.min.Uint32() <= ipv4Uint32) && (ipv4Uint32 <= o.max.Uint32())

}

// Empty returns True iff Ipv4Pool is empty.
func (o *Ipv4Pool) Empty() bool {
	return o.exhausted && len(o.pool) == 0
}

// Negate an Ipv4 as a result of a DHCPDECLINE
func (o *Ipv4Pool) Negate(ipv4 core.Ipv4Key) {
	// We don't offer an address that we already offered, so this might be something static.
	if entry, ok := o.pool[ipv4]; ok {
		o.removeEntry(entry)
	}
	o.excludedMap[ipv4.Uint32()] = true
}

/*======================================================================================================
										Dhcp Client Context
======================================================================================================*/
// DhcpClientState represents the state of any Dhcp Client that is communicating with the server.
type DhcpClientCtx struct {
	srv              *PluginDhcpSrvClient // Back pointer to server
	timerw           *core.TimerCtx       // Timer wheel
	timer            core.CHTimerObj      // Timer
	mac              core.MACKey          // Client Identifier
	pool             *Ipv4Pool            // Pool on which the client belongs to.
	ipv4             core.Ipv4Key         // Client Ipv4
	subnetMask       core.Ipv4Key         // Subnet Mask
	t1               uint32               // T1 Time - At time T1 the client moves to RENEWING state
	t2               uint32               // T1 Time - At time T2 the client moves to REBINDING state
	lease            uint32               // Lease in seconds for this client
	ticksUponBinding float64              // Ticks when the client is bound
	state            DHCPState            // Client Dhcp State
}

// CreateDhcpClientCtx creates a new Dhcp Client Context each time a new client attempts to communicate with the server.
func CreateDhcpClientCtx(srv *PluginDhcpSrvClient,
	mac core.MACKey,
	pool *Ipv4Pool,
	ipv4 core.Ipv4Key,
	subnetMask core.Ipv4Key,
	lease uint32) *DhcpClientCtx {
	o := new(DhcpClientCtx)
	o.srv = srv
	o.timerw = o.srv.Tctx.GetTimerCtx()
	o.mac = mac
	o.pool = pool
	o.ipv4 = ipv4
	o.subnetMask = subnetMask
	o.lease = lease
	o.state = DHCPSelecting // The context is created when the server offers, the client is in selecting!
	o.timer.SetCB(o, nil, nil)
	o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(OFFER_TIMEOUT*time.Second)) // Start offer timeout.
	return o
}

// GetRemainingTime gets the seconds left in the lease for the client.
func (o *DhcpClientCtx) GetRemainingTime() uint32 {
	ticksNow := o.timerw.TicksInSec()
	return o.lease - uint32(ticksNow-o.ticksUponBinding)
}

// Bind a client. This is safe even if the client is in Renewing/Rebinding state.
func (o *DhcpClientCtx) Bind() {
	o.t1, o.t2 = GetT1T2(o.lease)
	o.state = DHCPBound
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.ticksUponBinding = o.timerw.TicksInSec()
	o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(time.Duration(o.t1)*time.Second)) // Start Timer to T1.
}

// OnEvent is called when the client's state should change.
func (o *DhcpClientCtx) OnEvent(a, b interface{}) {

	switch o.state {
	case DHCPSelecting:
		// The timeout to accept the offer finished.
		o.srv.OnClientRemove(o)
	case DHCPBound:
		// T1 Expired, should move to Renewing
		o.state = DHCPRenewing
		o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(time.Duration(o.t2-o.t1)*time.Second)) // Start Timer to T2-T1
	case DHCPRenewing:
		// T2 Expired, should move to Rebinding
		o.state = DHCPRebinding
		o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(time.Duration(o.lease-o.t2)*time.Second)) // Start Timer to Lease-T2
	case DHCPRebinding:
		// Lease Expired
		o.srv.OnClientRemove(o)
	}
}

// OnRemove is called when a client's context should be removed.
func (o *DhcpClientCtx) OnRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	// Return the address to the pool.
	o.pool.AddFirst(o.ipv4)
}

// DhcpClientDb is a database that maps the clients (chaddr as client id) to their state.
type DhcpClientCtxDb map[core.MACKey]*DhcpClientCtx

/*======================================================================================================
								Dhcp Client Context Database Remover
======================================================================================================*/
// DhcpClientCtxDbRemover is an object to remove large Dhcp Client Context Databases.
type DhcpClientCtxDbRemover struct {
	db     DhcpClientCtxDb // Database to remove
	timerw *core.TimerCtx  // Timer wheel
	timer  core.CHTimerObj // Timer
}

// NewDhcpClientCtxDbRemover creates a new DhcpClientCtxDbRemover.
func NewDhcpClientCtxDbRemover(db *DhcpClientCtxDb, timerw *core.TimerCtx) *DhcpClientCtxDbRemover {
	o := new(DhcpClientCtxDbRemover)
	o.db = *db
	o.timerw = timerw
	o.timer.SetCB(o, 0, 0)
	o.OnEvent(0, 0)
	return o
}

// OnEvent is called each tick and removes THRESHOLD entries from the database.
func (o *DhcpClientCtxDbRemover) OnEvent(a, b interface{}) {
	THRESHOLD := 1000
	i := 0
	for mac, ctx := range o.db {
		if i >= THRESHOLD {
			break
		}
		ctx.OnRemove()
		delete(o.db, mac)
		i++
	}
	if len(o.db) > 0 {
		// Table is not empty.
		o.timerw.StartTicks(&o.timer, 1)
	}
}

/*======================================================================================================
										Plugin DhcpSrv Emu Client
======================================================================================================*/

// DhcpOptionParams is a simple way to represent a easy parsable DhcpOption.
type DhcpOptionParam struct {
	Type byte   `json:"type" validate:"required"` // Type of Option
	Data []byte `json:"data" validate:"required"` // Data for the Option
}

// DhcpSrvOptions consolidates the options that can be provided to a DhcpSrv. The server will
// use this options in its responses, per type.
type DhcpSrvOptions struct {
	Offer *[]DhcpOptionParam `json:"offer"` // Options for DHCPOFFER packets
	Ack   *[]DhcpOptionParam `json:"ack"`   // Options for DHCPACK packets
	Nak   *[]DhcpOptionParam `json:"nak"`   // Options for DHCPNAK packets
}

// DhcpSrvPoolParams consolidates the parameters for each input pool to the DhcpSrv.
type DhcpSrvPoolParams struct {
	Min      string   `json:"min" validate:"required"`               // Min IP address in subnet
	Max      string   `json:"max" validate:"required"`               // Max IP address in subnet
	Prefix   uint8    `json:"prefix" validate:"required,gt=0,lt=32"` // Prefix
	Excluded []string `json:"exclude"`                               // Excluded addresses from the pool. Useful for Relays, DGs etc.
}

// DhcpSrvParams represents the init json Api for the Dhcp Server Emu Client.
type DhcpSrvParams struct {
	DefaultLease uint32              `json:"default_lease"`                  // Default lease in seconds. Default to DefaultOfferedLease
	MaxLease     uint32              `json:"max_lease"`                      // Maximal lease allowed if the client requests. Default to DefaultMaxLease
	MinLease     uint32              `json:"min_lease"`                      // Minimal lease allowed if the client requests. Defaults to DefaultMinLease
	NextServerIp string              `json:"next_server_ip"`                 // Next Server Ip
	Pools        []DhcpSrvPoolParams `json:"pools" validate:"required,dive"` // Pools of CIDR
	Options      *DhcpSrvOptions     `json:"options"`                        // Options
}

// dhcpSrvEvents holds a list of events on which the DhcpSrv plugin is interested.
var dhcpSrvEvents = []string{}

// PluginDhcpSrvClient represents an Emu Client that acts as a Dhcp Server.
type PluginDhcpSrvClient struct {
	core.PluginBase                            // Plugin Base embedded struct so we get all the base functionality
	params                 DhcpSrvParams       // Init Json params
	stats                  DhcpSrvStats        // DhcpSrv params
	cdb                    *core.CCounterDb    // Counters database
	cdbv                   *core.CCounterDbVec // Counters database vector
	pools                  []*Ipv4Pool         // List of all pools
	serverPool             *Ipv4Pool           // Pool that contains the server
	clientCtxDb            DhcpClientCtxDb     // DHCP client context database.
	nextServerIp           net.IP              // Next Server Ip
	offerOpt               layers.DHCPOptions  // Options for DHCPOFFER Packets
	ackInformOpt           layers.DHCPOptions  // Options for DHCPACK Packets responding to DHCPINFORM
	ackReqOpt              layers.DHCPOptions  // Options for DHCPACK Packets responding to DHCPREQUEST
	nakOpt                 layers.DHCPOptions  // Options for DHCPNAK Packets
	offerT1OptOff          uint16              // Offset for T1 Option in Options slice for DHCPOFFER
	offerT2OptOff          uint16              // Offset for T2 Option in Options slice for DHCPOFFER
	offerLeaseOptOff       uint16              // Offset for Lease Option in Options slice for DHCPOFFER
	offerSubnetMaskOptOff  uint16              // Offset for Subnet Mask Option in Options slice for DHCPOFFER
	ackReqT1OptOff         uint16              // Offset for T1 Option in Options slice for DHCPOFFER
	ackReqT2OptOff         uint16              // Offset for T2 Option in Options slice for DHCPOFFER
	ackReqLeaseOptOff      uint16              // Offset for Lease Option in Options slice for DHCPOFFER
	ackReqSubnetMaskOptOff uint16              // Offset for Subnet Mask Option in Options slice for DHCPACK to DHCPREQUEST
}

// GetT1T2 calculates T1, T2 times based on lease.
func GetT1T2(lease uint32) (t1, t2 uint32) {
	t1 = uint32(0.5 * float64(lease))
	t2 = uint32(0.875 * float64(lease))
	return t1, t2
}

// NewDhcpSrcClient creates a new DhcpSrv Emu Client Plugin.
func NewDhcpSrvClient(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginDhcpSrvClient)
	o.InitPluginBase(ctx, o)                  // Init base object
	o.RegisterEvents(ctx, dhcpSrvEvents, o)   // Register events
	o.Ns.PluginCtx.GetOrCreate(DHCP_SRV_PLUG) // Crete Plugin in Namespace Level
	o.cdb = NewDhcpSrvStatsDb(&o.stats)       // Register Stats immediately so we can fail safely.
	o.cdbv = core.NewCCounterDbVec(DHCP_SRV_PLUG)
	o.cdbv.Add(o.cdb)

	// Set the default paramaters
	o.params.MinLease = DefaultMinLease
	o.params.MaxLease = DefaultMaxLease
	o.params.DefaultLease = DefaultOfferedLease
	o.params.NextServerIp = "0.0.0.0"

	err := o.Tctx.UnmarshalValidate(initJson, &o.params) // Unmarshal and validate init json
	if err != nil {
		o.stats.invalidInitJson++
		return nil, err
	}

	// Create everything needed by the DhcpSrv
	err = o.OnCreate()
	if err != nil {
		return nil, err
	}

	return &o.PluginBase, nil
}

// validIPv4 validates that a string is a valid IPv4 address and returns True iff this is the case.
func (o *PluginDhcpSrvClient) validIPv4(ipv4Str string) bool {
	ip := net.ParseIP(ipv4Str)
	if ip == nil {
		// Invalid IP
		o.stats.invalidInitJson++
		return false
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		// Invalid IPv4
		o.stats.invalidInitJson++
		return false
	}
	return true
}

// OnCreate is called upon the creation of a new DhcpSrv Emu client.
func (o *PluginDhcpSrvClient) OnCreate() error {
	o.clientCtxDb = make(map[core.MACKey]*DhcpClientCtx)

	if o.params.DefaultLease > o.params.MaxLease {
		o.params.MaxLease = o.params.DefaultLease
	}
	if o.params.DefaultLease < o.params.MinLease {
		o.params.MinLease = o.params.DefaultLease
	}

	for _, pool := range o.params.Pools {
		if !o.validIPv4(pool.Min) {
			return fmt.Errorf("Invalid pool min IP %s", pool.Min)
		}
		if !o.validIPv4(pool.Max) {
			return fmt.Errorf("Invalid pool max IP %s", pool.Max)
		}
		cidr := fmt.Sprintf("%s/%d", pool.Min, pool.Prefix)
		_, netIp, err := net.ParseCIDR(cidr)
		if err != nil {
			o.stats.invalidInitJson++
			return fmt.Errorf("Invalid pool CIDR %s", cidr)
		}
		if !netIp.Contains(net.ParseIP(pool.Max)) {
			o.stats.invalidInitJson++
			return fmt.Errorf("Pool max %s not in the same subnet as min %s", pool.Max, netIp)
		}
		var excludedIpv4Key []core.Ipv4Key
		var ipv4Key core.Ipv4Key
		for _, ipString := range pool.Excluded {
			if !o.validIPv4(ipString) {
				return fmt.Errorf("Invalid pool excluded IP %s", ipString)
			}
			ipv4 := net.ParseIP(ipString).To4()
			copy(ipv4Key[:], ipv4[0:4])
			excludedIpv4Key = append(excludedIpv4Key, ipv4Key)
		}
		var min, max core.Ipv4Key
		copy(min[:], net.ParseIP(pool.Min).To4()[0:4])
		copy(max[:], net.ParseIP(pool.Max).To4()[0:4])
		o.pools = append(o.pools, CreateIpv4Pool(netIp, min, max, excludedIpv4Key))
	}

	o.nextServerIp = net.ParseIP(o.params.NextServerIp)
	if o.nextServerIp == nil {
		o.stats.invalidInitJson++
		return fmt.Errorf("Invalid NextServerIp %s", o.params.NextServerIp)
	}

	// Hold a pointer to the pool in which the server belongs too.
	for _, pool := range o.pools {
		if pool.InSubnet(o.Client.Ipv4) {
			o.serverPool = pool
			break
		}
	}

	o.computeOptions()
	return nil
}

// computeOptions computes the options for each type of packet that the server sends ahead of time.
func (o *PluginDhcpSrvClient) computeOptions() {
	/**********************************************************************
								Offer options
	**********************************************************************/
	offerOptMap := make(map[layers.DHCPOpt][]byte)

	mustNotOfferOpt := make(map[layers.DHCPOpt]bool)     // Map of options that MUST NOT be part of DHCPOFFER
	mustNotOfferOpt[layers.DHCPOptRequestIP] = true      // Requested Ip
	mustNotOfferOpt[layers.DHCPOptParamsRequest] = true  // Parameters Request List
	mustNotOfferOpt[layers.DHCPOptClientID] = true       // Client Identifier
	mustNotOfferOpt[layers.DHCPOptMaxMessageSize] = true // Maximum Message Size

	// Let's add the JSON provided options if allowed
	if (o.params.Options != nil) && (o.params.Options.Offer != nil) {
		for _, op := range *o.params.Options.Offer {
			option := layers.DHCPOpt(op.Type)
			if _, ok := mustNotOfferOpt[option]; ok {
				o.stats.mustNotOfferOpt++
				continue
			}
			offerOptMap[option] = op.Data
		}
	}

	offerOptMap[layers.DHCPOptMessageType] = []byte{byte(layers.DHCPMsgTypeOffer)}
	offerOptMap[layers.DHCPOptLeaseTime] = []byte{0, 0, 0, 0}
	offerOptMap[layers.DHCPOptT1] = []byte{0, 0, 0, 0}
	offerOptMap[layers.DHCPOptT2] = []byte{0, 0, 0, 0}
	offerOptMap[layers.DHCPOptSubnetMask] = []byte{0, 0, 0, 0}
	offerOptMap[layers.DHCPOptServerID] = o.Client.Ipv4.ToIP()

	for k, v := range offerOptMap {
		o.offerOpt = append(o.offerOpt, layers.NewDHCPOption(k, v))
	}

	// Sort the slice for predictable outcome
	sort.Slice(o.offerOpt[:], func(i, j int) bool {
		return o.offerOpt[i].Type < o.offerOpt[j].Type
	})

	var dhcpOfferLength uint16 = 240 // Fixed Length without option

	for _, option := range o.offerOpt {
		switch option.Type {
		case layers.DHCPOptT1:
			o.offerT1OptOff = dhcpOfferLength + 2 // 2 for type + length
		case layers.DHCPOptT2:
			o.offerT2OptOff = dhcpOfferLength + 2 // 2 for type + length
		case layers.DHCPOptLeaseTime:
			o.offerLeaseOptOff = dhcpOfferLength + 2 // 2 for type + length
		case layers.DHCPOptSubnetMask:
			o.offerSubnetMaskOptOff = dhcpOfferLength + 2 // 2 for type + length
		}

		if option.Type == layers.DHCPOptPad {
			dhcpOfferLength++
		} else {
			dhcpOfferLength += uint16(option.Length) + 2 // 2 for type + length
		}
	}

	/**********************************************************************
								ACK Inform options
	**********************************************************************/
	ackInformOptMap := make(map[layers.DHCPOpt][]byte)

	mustNotAckInformOpt := make(map[layers.DHCPOpt]bool)     // Map of options that MUST NOT be part of DHCPACK
	mustNotAckInformOpt[layers.DHCPOptRequestIP] = true      // Requested Ip
	mustNotAckInformOpt[layers.DHCPOptLeaseTime] = true      // Lease Time
	mustNotAckInformOpt[layers.DHCPOptParamsRequest] = true  // Param Request List
	mustNotAckInformOpt[layers.DHCPOptClientID] = true       // Client Identifier
	mustNotAckInformOpt[layers.DHCPOptT1] = true             // T1
	mustNotAckInformOpt[layers.DHCPOptT1] = true             // T2
	mustNotAckInformOpt[layers.DHCPOptMaxMessageSize] = true // Maximum Message Size

	// Let's add the JSON provided options if allowed
	if (o.params.Options != nil) && (o.params.Options.Ack != nil) {
		for _, op := range *o.params.Options.Ack {
			option := layers.DHCPOpt(op.Type)
			if _, ok := mustNotAckInformOpt[option]; ok {
				o.stats.mustNotAckInformOpt++
				continue
			}
			ackInformOptMap[option] = op.Data
		}
	}

	ackInformOptMap[layers.DHCPOptMessageType] = []byte{byte(layers.DHCPMsgTypeAck)}
	ackInformOptMap[layers.DHCPOptServerID] = o.Client.Ipv4.ToIP()

	for k, v := range ackInformOptMap {
		o.ackInformOpt = append(o.ackInformOpt, layers.NewDHCPOption(k, v))
	}

	// Sort the slice for predictable outcome
	sort.Slice(o.ackInformOpt[:], func(i, j int) bool {
		return o.ackInformOpt[i].Type < o.ackInformOpt[j].Type
	})
	/**********************************************************************
								ACK Request options
	**********************************************************************/
	ackReqOptMap := make(map[layers.DHCPOpt][]byte)

	mustNotAckReqOpt := make(map[layers.DHCPOpt]bool)     // Map of options that MUST NOT be part of DHCPACK
	mustNotAckReqOpt[layers.DHCPOptRequestIP] = true      // Requested Ip
	mustNotAckReqOpt[layers.DHCPOptParamsRequest] = true  // Param Request List
	mustNotAckReqOpt[layers.DHCPOptClientID] = true       // Client Identifier
	mustNotAckReqOpt[layers.DHCPOptMaxMessageSize] = true // Maximum Message Size

	// Let's add the JSON provided options if allowed
	if (o.params.Options != nil) && (o.params.Options.Ack != nil) {
		for _, op := range *o.params.Options.Ack {
			option := layers.DHCPOpt(op.Type)
			if _, ok := mustNotAckReqOpt[option]; ok {
				o.stats.mustNotAckReqOpt++
				continue
			}
			ackReqOptMap[option] = op.Data
		}
	}

	ackReqOptMap[layers.DHCPOptMessageType] = []byte{byte(layers.DHCPMsgTypeAck)}
	ackReqOptMap[layers.DHCPOptLeaseTime] = []byte{0, 0, 0, 0}
	ackReqOptMap[layers.DHCPOptT1] = []byte{0, 0, 0, 0}
	ackReqOptMap[layers.DHCPOptT2] = []byte{0, 0, 0, 0}
	ackReqOptMap[layers.DHCPOptSubnetMask] = []byte{0, 0, 0, 0}
	ackReqOptMap[layers.DHCPOptServerID] = o.Client.Ipv4.ToIP()

	for k, v := range ackReqOptMap {
		o.ackReqOpt = append(o.ackReqOpt, layers.NewDHCPOption(k, v))
	}

	// Sort the slice for predictable outcome
	sort.Slice(o.ackReqOpt[:], func(i, j int) bool {
		return o.ackReqOpt[i].Type < o.ackReqOpt[j].Type
	})

	var dhcpHeaderLength uint16 = 240 // Fixed Length without option

	for _, option := range o.ackReqOpt {
		switch option.Type {
		case layers.DHCPOptT1:
			o.ackReqT1OptOff = dhcpHeaderLength + 2 // 2 for type + length
		case layers.DHCPOptT2:
			o.ackReqT2OptOff = dhcpHeaderLength + 2 // 2 for type + length
		case layers.DHCPOptLeaseTime:
			o.ackReqLeaseOptOff = dhcpHeaderLength + 2 // 2 for type + length
		case layers.DHCPOptSubnetMask:
			o.ackReqSubnetMaskOptOff = dhcpHeaderLength + 2 // 2 for type + length
		}

		if option.Type == layers.DHCPOptPad {
			dhcpHeaderLength++
		} else {
			dhcpHeaderLength += uint16(option.Length) + 2 // 2 for type + length
		}
	}
	/**********************************************************************
								NAK options
	**********************************************************************/
	nakOptMap := make(map[layers.DHCPOpt][]byte)

	mayNakOpt := make(map[layers.DHCPOpt]bool)   // Map of options that MAY be part of DHCPNAK
	mayNakOpt[layers.DHCPOptMessage] = true      // Message
	mayNakOpt[layers.DHCPOptClientID] = true     // Client Identifier
	mayNakOpt[layers.DHCPOptVendorOption] = true // Vendor Option

	// Let's add the JSON provided options if allowed
	if (o.params.Options != nil) && (o.params.Options.Nak != nil) {
		for _, op := range *o.params.Options.Nak {
			option := layers.DHCPOpt(op.Type)
			if _, ok := mayNakOpt[option]; !ok {
				o.stats.mustNotNakOpt++
				continue
			}
			nakOptMap[option] = op.Data
		}
	}

	nakOptMap[layers.DHCPOptMessageType] = []byte{byte(layers.DHCPMsgTypeNak)}
	nakOptMap[layers.DHCPOptServerID] = o.Client.Ipv4.ToIP()

	for k, v := range nakOptMap {
		o.nakOpt = append(o.nakOpt, layers.NewDHCPOption(k, v))
	}

	// Sort the slice for predictable outcome
	sort.Slice(o.nakOpt[:], func(i, j int) bool {
		return o.nakOpt[i].Type < o.nakOpt[j].Type
	})
}

// getClientCtx returns the context of the client in case such context exists.
// In case it doesn't, it will return
func (o *PluginDhcpSrvClient) getClientCtx(chaddr core.MACKey) *DhcpClientCtx {
	dhcpClientCtx, ok := o.clientCtxDb[chaddr]
	if !ok {
		o.stats.pktRxNoClientCtx++
		return nil
	}
	return dhcpClientCtx
}

// selectIpToOffer selects the Ipv4 to offer doing the best effort on the algorithm below
/*When a server receives a DHCPDISCOVER message from a client, the
  server chooses a network address for the requesting client.  If no
  address is available, the server may choose to report the problem to
  the system administrator. If an address is available, the new address
  SHOULD be chosen as follows:

     o The client's current address as recorded in the client's current
       binding, ELSE

     o The client's previous address as recorded in the client's (now
       expired or released) binding, if that address is in the server's
       pool of available addresses and not already allocated, ELSE

     o The address requested in the 'Requested IP Address' option, if that
       address is valid and not already allocated, ELSE

     o A new address allocated from the server's pool of available
       addresses; the address is selected based on the subnet from which
       the message was received (if 'giaddr' is 0) or on the address of
       the relay agent that forwarded the message ('giaddr' when not 0).
*/
func (o *PluginDhcpSrvClient) selectIpToOffer(giaddr core.Ipv4Key,
	reqIp core.Ipv4Key,
	clientMac core.MACKey) (pool *Ipv4Pool, yiaddr core.Ipv4Key, subnet core.Ipv4Key, err error) {

	cDhcpCtx, ok := o.clientCtxDb[clientMac]
	if ok {
		// Client already in database, let's give him his old address.
		// If he wants a new address, he should release.
		pool = cDhcpCtx.pool
		yiaddr = cDhcpCtx.ipv4
		subnet = cDhcpCtx.subnetMask
		return pool, yiaddr, subnet, nil
	}

	broadcast := giaddr.IsZero()

	if broadcast {
		// Need to select from the pool of the server
		pool = o.serverPool
	} else {
		// Need to select from the pool in which giaddr is located.
		for _, poolIter := range o.pools {
			if poolIter.InSubnet(giaddr) {
				pool = poolIter
				break
			}
		}
	}

	if pool == nil {
		// No pool found
		return pool, yiaddr, subnet, fmt.Errorf("No pool found for the answer!")
	} else {
		subnet = pool.GetSubnetMask()
	}

	if !reqIp.IsZero() && pool.Contains(reqIp) {
		// Valid requested Ip, let's see if we can provide
		if pool.GetEntry(reqIp) {
			// Pool gave us the address!
			yiaddr = reqIp
		}
	}
	if yiaddr.IsZero() {
		// Couldn't get an address, let's get the first one!
		ipv4, err := pool.GetFirst()
		if err != nil {
			return pool, yiaddr, subnet, fmt.Errorf("The pool is empty!")
		} else {
			yiaddr = ipv4
		}
	}
	return pool, yiaddr, subnet, nil
}

// selectLeaseToOffer selects the lease to offer to this client
/*The server must also choose an expiration time for the lease, as
  follows:

  o IF the client has not requested a specific lease in the
    DHCPDISCOVER message and the client already has an assigned network
    address, the server returns the lease expiration time previously
    assigned to that address (note that the client must explicitly
    request a specific lease to extend the expiration time on a
    previously assigned address), ELSE

  o IF the client has not requested a specific lease in the
    DHCPDISCOVER message and the client does not have an assigned
    network address, the server assigns a locally configured default
    lease time, ELSE

  o IF the client has requested a specific lease in the DHCPDISCOVER
    message (regardless of whether the client has an assigned network
    address), the server may choose either to return the requested
    lease (if the lease is acceptable to local policy) or select
    another lease.
*/
func (o *PluginDhcpSrvClient) selectLeaseToOffer(reqLease uint32, clientMac core.MACKey) (lease uint32) {

	cDhcpCtx, ok := o.clientCtxDb[clientMac]

	if reqLease == 0 && ok {
		// Hasn't requested a specific lease
		if ok {
			lease = cDhcpCtx.GetRemainingTime()
		} else {
			lease = o.params.DefaultLease
		}
	} else {
		// Requested a specific lease
		if reqLease >= o.params.MinLease && reqLease <= o.params.MaxLease {
			lease = reqLease
		} else {
			lease = o.params.DefaultLease
		}
	}
	return lease
}

// OnRemove is called upon removing the DhcpSrv Emu client.
func (o *PluginDhcpSrvClient) OnRemove(ctx *core.PluginCtx) {
	_ = NewDhcpClientCtxDbRemover(&o.clientCtxDb, o.Tctx.GetTimerCtx())
	o.clientCtxDb = nil
	o.stats.activeClients = 0
}

// OnEvent for events the namespace plugin is registered.
func (o *PluginDhcpSrvClient) OnEvent(msg string, a, b interface{}) {}

// OnClientRemove is called when a client's context needs to be removed.
func (o *PluginDhcpSrvClient) OnClientRemove(ctx *DhcpClientCtx) {
	ctx.OnRemove()
	delete(o.clientCtxDb, ctx.mac)
	o.stats.activeClients--
}

// SendOffer sends a DHCPOFFER to a client whose DHCPDISCOVER we have received.
func (o *PluginDhcpSrvClient) SendOffer(dhcph layers.DHCPv4, yiaddr core.Ipv4Key, subnetMask core.Ipv4Key, lease uint32) {
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          dhcph.Xid,
		Secs:         0,
		Flags:        dhcph.Flags,
		ClientIP:     net.IP{0, 0, 0, 0},
		YourClientIP: yiaddr.ToIP(),
		NextServerIP: o.nextServerIp,
		RelayAgentIP: dhcph.RelayAgentIP,
		ClientHWAddr: dhcph.ClientHWAddr,
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      o.offerOpt,
	}

	/*
		If the 'giaddr' field in a DHCP message from a client is non-zero,
		the server sends any return messages to the 'DHCP server' port on the
		BOOTP relay agent whose address appears in 'giaddr'.

		Implementation Note: ciaddr == 0 is DHCPDISCOVER

		If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
		set, then the server broadcasts DHCPOFFER messages to
		0xffffffff.

		If the broadcast bit is not set and 'giaddr' is zero and 'ciaddr' is zero,
		then the server unicasts DHCPOFFER messages to the client's hardware addres
		and 'yiaddr' address.
	*/

	var giaddr core.Ipv4Key
	var chaddr core.MACKey
	dstPort := DHCPV4_CLIENT_PORT
	copy(giaddr[:], dhcp.RelayAgentIP[0:4])
	copy(chaddr[:], dhcp.ClientHWAddr[0:6])

	l2 := o.Client.GetL2Header(dhcp.Broadcast(), uint16(layers.EthernetTypeIPv4))

	fixDstMac := false

	ipv4 := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      128,
		Id:       0xcc,
		SrcIP:    o.Client.Ipv4.ToIP(),
		DstIP:    net.IPv4(255, 255, 255, 255), // Default to Broadcast
		Protocol: layers.IPProtocolUDP}

	if !giaddr.IsZero() {
		// Send to Relay
		dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptRouter, giaddr[:]))
		ipv4.DstIP = dhcp.RelayAgentIP
		dstPort = DHCPV4_SERVER_PORT
		copy(l2[0:6], []byte{0, 0, 0, 0, 0, 0})
		fixDstMac = true // Should be replaced by default gateway's MAC
	} else if !dhcp.Broadcast() {
		// No Relay, no broadcast
		ipv4.DstIP = dhcp.YourClientIP
		copy(l2[0:6], chaddr[:])
	}

	pkt := core.PacketUtlBuild(
		&ipv4,
		&layers.UDP{SrcPort: DHCPV4_SERVER_PORT, DstPort: layers.UDPPort(dstPort)},
		dhcp,
	)

	// Fix DHCP Options
	t1, t2 := GetT1T2(lease)
	var dhcpOffset uint16 = 20 + 8 // 20 for IPv4, 8 for UDP
	offerLeaseOptOff := dhcpOffset + o.offerLeaseOptOff
	offerT1OptOff := dhcpOffset + o.offerT1OptOff
	offerT2OptOff := dhcpOffset + o.offerT2OptOff
	offerSubnetMaskOptOff := dhcpOffset + o.offerSubnetMaskOptOff
	binary.BigEndian.PutUint32(pkt[offerLeaseOptOff:offerLeaseOptOff+4], lease)
	binary.BigEndian.PutUint32(pkt[offerT1OptOff:offerT1OptOff+4], t1)
	binary.BigEndian.PutUint32(pkt[offerT2OptOff:offerT2OptOff+4], t2)
	copy(pkt[offerSubnetMaskOptOff:offerSubnetMaskOptOff+4], subnetMask[:])

	// Fix Ipv4 length and checksum
	ipv4Header := layers.IPv4Header(pkt[0:20])
	ipv4Header.SetLength(uint16(len(pkt)))
	ipv4Header.UpdateChecksum()

	// Fix UDP Length and Checksum
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(pkt)-20))
	binary.BigEndian.PutUint16(pkt[26:28], 0)
	cs := layers.PktChecksumTcpUdp(pkt[20:], 0, ipv4Header)
	binary.BigEndian.PutUint16(pkt[26:28], cs)

	o.stats.pktTxOffer++
	o.stats.pktTx++

	pktToSend := append(l2, pkt...)

	o.Tctx.Veth.SendBuffer(fixDstMac, o.Client, pktToSend, false)
}

// SendAck sends a DHCPACK to a client whose DHCPREQUEST/INFORM we have received.
func (o *PluginDhcpSrvClient) SendAck(dhcph layers.DHCPv4, yiaddr core.Ipv4Key, inform bool) {

	var options layers.DHCPOptions

	if inform {
		options = o.ackInformOpt
	} else {
		options = o.ackReqOpt
	}

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          dhcph.Xid,
		Secs:         0,
		Flags:        dhcph.Flags,
		ClientIP:     dhcph.ClientIP,
		YourClientIP: yiaddr.ToIP(),
		NextServerIP: o.nextServerIp,
		RelayAgentIP: dhcph.RelayAgentIP,
		ClientHWAddr: dhcph.ClientHWAddr,
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      options,
	}

	/*
		If the 'giaddr' field in a DHCP message from a client is non-zero,
		the server sends any return messages to the 'DHCP server' port on the
		BOOTP relay agent whose address appears in 'giaddr'.

		If the 'giaddr' field is zero and the 'ciaddr' field is nonzero,
		then the server unicasts DHCPACK messages to the address in 'ciaddr'.

		If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
		set, then the server broadcasts DHCPACK messages to
		0xffffffff.

		If the broadcast bit is not set and 'giaddr' is zero and 'ciaddr' is zero,
		then the server unicasts DHCPACK messages to the client's hardware addres
		and 'yiaddr' address.
	*/

	var giaddr, ciaddr core.Ipv4Key
	var chaddr core.MACKey
	dstPort := DHCPV4_CLIENT_PORT
	copy(giaddr[:], dhcp.RelayAgentIP[0:4])
	copy(ciaddr[:], dhcp.ClientIP[0:4])
	copy(chaddr[:], dhcp.ClientHWAddr[0:6])

	l2 := o.Client.GetL2Header(dhcp.Broadcast(), uint16(layers.EthernetTypeIPv4))

	ipv4 := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      128,
		Id:       0xcc,
		SrcIP:    o.Client.Ipv4.ToIP(),
		DstIP:    net.IPv4(255, 255, 255, 255), // Default to Broadcast
		Protocol: layers.IPProtocolUDP}

	fixDstMac := false

	if !giaddr.IsZero() && !inform {
		// Inform messages should always be sent to ciaddr
		// giaddr != 0, Send to Relay
		dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptRouter, giaddr[:]))
		ipv4.DstIP = dhcp.RelayAgentIP
		dstPort = DHCPV4_SERVER_PORT
		copy(l2[0:6], []byte{0, 0, 0, 0, 0, 0})
		fixDstMac = true // Should be replaced by default gateway's MAC
	} else if !ciaddr.IsZero() {
		// ciaddr != 0, Send To Ciaddr
		ipv4.DstIP = dhcp.ClientIP
		copy(l2[0:6], []byte{0, 0, 0, 0, 0, 0})
		fixDstMac = true // Should be replaced by default gateway's MAC
	} else if !dhcp.Broadcast() {
		// giaddr == 0, ciaddr == 0, broadcast off
		ipv4.DstIP = dhcp.YourClientIP
		copy(l2[0:6], chaddr[:])
	}

	pkt := core.PacketUtlBuild(
		&ipv4,
		&layers.UDP{SrcPort: DHCPV4_SERVER_PORT, DstPort: layers.UDPPort(dstPort)},
		dhcp,
	)

	// Fix DHCP Options
	if !inform {
		ctx := o.clientCtxDb[chaddr] // Known that it exists
		t1, t2 := GetT1T2(ctx.lease)
		var dhcpOffset uint16 = 20 + 8 // 20 for IPv4, 8 for UDP
		ackReqLeaseOptOff := dhcpOffset + o.offerLeaseOptOff
		ackReqT1OptOff := dhcpOffset + o.offerT1OptOff
		ackReqT2OptOff := dhcpOffset + o.offerT2OptOff
		ackReqSubnetMaskOptOff := dhcpOffset + o.ackReqSubnetMaskOptOff
		binary.BigEndian.PutUint32(pkt[ackReqLeaseOptOff:ackReqLeaseOptOff+4], ctx.lease)
		binary.BigEndian.PutUint32(pkt[ackReqT1OptOff:ackReqT1OptOff+4], t1)
		binary.BigEndian.PutUint32(pkt[ackReqT2OptOff:ackReqT2OptOff+4], t2)
		copy(pkt[ackReqSubnetMaskOptOff:ackReqSubnetMaskOptOff+4], ctx.subnetMask[:])
	}

	// Fix Ipv4 length and checksum
	ipv4Header := layers.IPv4Header(pkt[0:20])
	ipv4Header.SetLength(uint16(len(pkt)))
	ipv4Header.UpdateChecksum()

	// Fix UDP Length and Checksum
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(pkt)-20))
	binary.BigEndian.PutUint16(pkt[26:28], 0)
	cs := layers.PktChecksumTcpUdp(pkt[20:], 0, ipv4Header)
	binary.BigEndian.PutUint16(pkt[26:28], cs)

	o.stats.pktTxAck++
	o.stats.pktTx++

	pktToSend := append(l2, pkt...)

	o.Tctx.Veth.SendBuffer(fixDstMac, o.Client, pktToSend, false)
}

// SendNak sends a DHCPNAK to a client whose DHCPREQUEST we have received and should respond with NAK.
func (o *PluginDhcpSrvClient) SendNak(dhcph layers.DHCPv4) {

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          dhcph.Xid,
		Secs:         0,
		Flags:        dhcph.Flags,
		ClientIP:     net.IP{0, 0, 0, 0},
		YourClientIP: net.IP{0, 0, 0, 0},
		NextServerIP: net.IP{0, 0, 0, 0},
		RelayAgentIP: dhcph.RelayAgentIP,
		ClientHWAddr: dhcph.ClientHWAddr,
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      o.nakOpt,
	}

	/*
		If the 'giaddr' field in a DHCP message from a client is non-zero,
		the server sends any return messages to the 'DHCP server' port on the
		BOOTP relay agent whose address appears in 'giaddr'.

		In all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK messages to 0xffffffff.
	*/

	var giaddr core.Ipv4Key
	dstPort := DHCPV4_CLIENT_PORT
	copy(giaddr[:], dhcp.RelayAgentIP[0:4])

	l2 := o.Client.GetL2Header(dhcp.Broadcast(), uint16(layers.EthernetTypeIPv4))

	fixDstMac := false

	ipv4 := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      128,
		Id:       0xcc,
		SrcIP:    o.Client.Ipv4.ToIP(),
		DstIP:    net.IPv4(255, 255, 255, 255), // Default to Broadcast
		Protocol: layers.IPProtocolUDP}

	if !giaddr.IsZero() {
		// Send to Relay
		ipv4.DstIP = dhcp.RelayAgentIP
		dstPort = DHCPV4_SERVER_PORT
		copy(l2[0:6], []byte{0, 0, 0, 0, 0, 0})
		fixDstMac = true // Should be replaced by default gateway's MAC
	}

	pkt := core.PacketUtlBuild(
		&ipv4,
		&layers.UDP{SrcPort: DHCPV4_SERVER_PORT, DstPort: layers.UDPPort(dstPort)},
		dhcp,
	)

	// Fix Ipv4 length and checksum
	ipv4Header := layers.IPv4Header(pkt[0:20])
	ipv4Header.SetLength(uint16(len(pkt)))
	ipv4Header.UpdateChecksum()

	// Fix UDP Length and Checksum
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(pkt)-20))
	binary.BigEndian.PutUint16(pkt[26:28], 0)
	cs := layers.PktChecksumTcpUdp(pkt[20:], 0, ipv4Header)
	binary.BigEndian.PutUint16(pkt[26:28], cs)

	o.stats.pktTxNak++
	o.stats.pktTx++

	pktToSend := append(l2, pkt...)

	o.Tctx.Veth.SendBuffer(fixDstMac, o.Client, pktToSend, false)
}

// HandleDiscover handles a DHCPDISCOVER packet when it is received.
func (o *PluginDhcpSrvClient) HandleDiscover(dhcph layers.DHCPv4, chaddr core.MACKey, reqIp core.Ipv4Key, reqLease uint32) {

	o.stats.pktRxDiscover++

	var giaddr core.Ipv4Key
	copy(giaddr[:], dhcph.RelayAgentIP[0:4])

	// This handles existing clients also, the handling is done inside selectIpToOffer,
	// selectLeaseToOffer

	pool, yiaddr, subnetMask, err := o.selectIpToOffer(giaddr, reqIp, chaddr)
	if err != nil {
		o.stats.noIpAvailable++
		return
	}

	lease := o.selectLeaseToOffer(reqLease, chaddr)

	if _, ok := o.clientCtxDb[chaddr]; !ok {
		ctx := CreateDhcpClientCtx(o, chaddr, pool, yiaddr, subnetMask, lease)
		o.clientCtxDb[chaddr] = ctx
		o.stats.activeClients++
	}

	o.SendOffer(dhcph, yiaddr, subnetMask, lease)
}

// HandleRequest handles a DHCPREQUEST packet when it is received.
func (o *PluginDhcpSrvClient) HandleRequest(dhcph layers.DHCPv4, chaddr core.MACKey, serverId core.Ipv4Key, reqIp core.Ipv4Key, reqLease uint32) {

	o.stats.pktRxRequest++

	if !serverId.IsZero() && serverId != o.Client.Ipv4 {
		// Safely ignore.
		return
	}

	dhcpClientCtx := o.getClientCtx(chaddr)
	if dhcpClientCtx == nil {
		// Error already set.
		return
	}
	state := dhcpClientCtx.state
	var ciaddr core.Ipv4Key
	copy(ciaddr[:], dhcph.ClientIP[0:4])

	if !serverId.IsZero() {
		/*
			DHCPREQUEST generated during SELECTING state.
			If the DHCPREQUEST message contains a 'server identifier' option,
			the message is in response to a DHCPOFFER message.

			Client inserts the address of the selected server in 'server identifier',
			'ciaddr' MUST be zero,
			'requested IP address' MUST be filled in with the yiaddr value from the chosen DHCPOFFER.
		*/
		if dhcpClientCtx.ipv4 == reqIp && ciaddr.IsZero() && state == DHCPSelecting {
			o.SendAck(dhcph, dhcpClientCtx.ipv4, false)
			dhcpClientCtx.Bind()
		} else {
			o.stats.pktRxBadDhcpReq++
		}
	} else {
		// The message is a request to verify or extend an existing lease.

		if !reqIp.IsZero() && ciaddr.IsZero() {
			/*
				DHCPREQUEST generated during INIT-REBOOT state:
				'server identifier' MUST NOT be filled in,
				'requested IP address', option MUST be filled in with client's notion of its previously assigned address.
				'ciaddr' MUST be zero.

				Server SHOULD send a DHCPNAK message to the client if the 'requested IP address' is incorrect, or is on the wrong network.
			*/
			if dhcpClientCtx.ipv4 != reqIp {
				// Requested IP address is incorrect.
				o.SendNak(dhcph)
			} else {
				// Verify network.
				var giaddr core.Ipv4Key
				copy(giaddr[:], dhcph.RelayAgentIP[0:4])
				if giaddr.IsZero() {
					// Should be in the same subnet as the server.
					if o.serverPool.InSubnet(reqIp) {
						o.SendAck(dhcph, dhcpClientCtx.ipv4, false)
					} else {
						o.SendNak(dhcph)
					}
				} else {
					if dhcpClientCtx.pool.InSubnet(giaddr) {
						o.SendAck(dhcph, dhcpClientCtx.ipv4, false)
					} else {
						o.SendNak(dhcph)
					}
				}
			}
		}

		if reqIp.IsZero() && ciaddr == dhcpClientCtx.ipv4 {
			/*
				DHCPREQUEST generated during REBINDING/RENEWING state:
				'server identifier' MUST NOT be filled in,
				'requested IP address' option MUST NOT be filled in,
				'ciaddr' MUST be filled in with client's IP address.

				Unicast -> Renewing
				Broadcast -> Rebinding
			*/
			if !(state == DHCPRenewing || state == DHCPRebinding) {
				// Not going to answer, as not in the correct state.
				return
			}
			if reqLease == 0 {
				reqLease = o.params.DefaultLease
			}
			lease := o.selectLeaseToOffer(reqLease, chaddr)
			dhcpClientCtx.lease = lease // Set the new lease
			dhcpClientCtx.Bind()        // Rebind
			o.SendAck(dhcph, dhcpClientCtx.ipv4, false)
		}
	}
}

// HandleDecline handles a DHCPDECLINE packet when it is received.
func (o *PluginDhcpSrvClient) HandleDecline(dhcph layers.DHCPv4, chaddr core.MACKey, serverId core.Ipv4Key, reqIp core.Ipv4Key) {

	o.stats.pktRxDecline++

	if serverId != o.Client.Ipv4 {
		// Safely Ignore, serverId must be provided.
		return
	}

	dhcpClientCtx := o.getClientCtx(chaddr)
	if dhcpClientCtx == nil {
		// Error already set.
		return
	}

	/*
		Client indicates that the address is invalid. We are trusting the client.
		Use this with great care, otherwise you will exhaust the pool and the client
		can use it to exploit a Denial of Service.
	*/
	if reqIp == dhcpClientCtx.ipv4 {
		// Only if this address is what we offered, we agree to negate it.
		o.stats.negatedIp++
		dhcpClientCtx.pool.Negate(reqIp) // Negate Ip
		o.OnClientRemove(dhcpClientCtx)  // Remove the context
	} else {
		o.stats.pktRxBadDhcpDecline++
	}
}

// HandleRelease handles a DHCPRELEASE packet when it is received.
func (o *PluginDhcpSrvClient) HandleRelease(dhcph layers.DHCPv4, chaddr core.MACKey, serverId core.Ipv4Key) {

	o.stats.pktRxRelease++

	if serverId != o.Client.Ipv4 {
		// Safely Ignore, serverId must be provided.
		return
	}

	var ciaddr core.Ipv4Key
	copy(ciaddr[:], dhcph.ClientIP[0:4])

	dhcpClientCtx := o.getClientCtx(chaddr)
	if dhcpClientCtx == nil {
		// Error already set.
		return
	}

	if ciaddr != dhcpClientCtx.ipv4 {
		o.stats.ciaddrMismatch++
		return
	}

	o.OnClientRemove(dhcpClientCtx)
}

// HandleInform handles a DHCPINFORM packet when it is received.
func (o *PluginDhcpSrvClient) HandleInform(dhcph layers.DHCPv4) {
	o.stats.pktRxInform++

	if dhcph.Broadcast() {
		/*
			Note by author:
			This is not very clear in RFC 2131, but DHCP Informs should always be sent to ciaddr.
			The Broadcast flag is meant to work around some clients that cannot accept IP unicast datagrams
			before the TCP/IP software. Only already configured clients sent DHCPINFORM, hence there is no reason
			why a client should used the broadcast flag in this case.
		*/
		o.stats.pktRxBadDhcpInform++
		return
	}

	o.SendAck(dhcph, core.Ipv4Key{0, 0, 0, 0}, true)
}

// Handles an incoming Dhcp Packet to the server.
func (o *PluginDhcpSrvClient) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	var mackey core.MACKey
	copy(mackey[:], p[0:6])

	o.stats.pktRx++
	if mackey.IsBroadcast() {
		o.stats.pktRxBroadcast++
	}

	dhcphlen := ps.L7Len
	if dhcphlen < 240 {
		return core.PARSER_ERR
	}

	var dhcph layers.DHCPv4
	err := dhcph.DecodeFromBytes(p[ps.L7:ps.L7+dhcphlen], gopacket.NilDecodeFeedback)
	if err != nil {
		return core.PARSER_ERR
	}

	if dhcph.Broadcast() {
		o.stats.pktRxDhcpBroadcast++
	}

	var chaddr core.MACKey
	if dhcph.HardwareType == layers.LinkTypeEthernet && len(dhcph.ClientHWAddr) == 6 {
		copy(chaddr[:], dhcph.ClientHWAddr[0:6])
	} else {
		o.stats.pktRxBadChAddr++
		return core.PARSER_ERR
	}

	var dhcpMsgType layers.DHCPMsgType
	var reqIp core.Ipv4Key
	var serverId core.Ipv4Key
	var reqLease uint32

	for _, op := range dhcph.Options {

		switch op.Type {
		case layers.DHCPOptMessageType:
			dhcpMsgType = layers.DHCPMsgType(op.Data[0])

		case layers.DHCPOptRequestIP:
			copy(reqIp[:], op.Data[0:4])

		case layers.DHCPOptServerID:
			copy(serverId[:], op.Data[0:4])

		case layers.DHCPOptLeaseTime:
			reqLease = binary.BigEndian.Uint32(op.Data[0:4])
		default:
		}
	}

	switch dhcpMsgType {
	case layers.DHCPMsgTypeDiscover:
		o.HandleDiscover(dhcph, chaddr, reqIp, reqLease)
	case layers.DHCPMsgTypeRequest:
		o.HandleRequest(dhcph, chaddr, serverId, reqIp, reqLease)
	case layers.DHCPMsgTypeDecline:
		o.HandleDecline(dhcph, chaddr, serverId, reqIp)
	case layers.DHCPMsgTypeRelease:
		o.HandleRelease(dhcph, chaddr, serverId)
	case layers.DHCPMsgTypeInform:
		o.HandleInform(dhcph)
	default:
		o.stats.pktRxBadMsgType++
	}

	return core.PARSER_OK
}

/*======================================================================================================
										Plugin DhcpSrv Ns
======================================================================================================*/
// PluginDhcpSrvNs represents the namespace layer for Dhcp Srv.
type PluginDhcpSrvNs struct {
	core.PluginBase
}

// NewDhcpSrvNs creates a new DhcpSrv namespace plugin
func NewDhcpSrvNs(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginDhcpSrvNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)
	return &o.PluginBase, nil
}

// OnRemove when removing DhcpSrv namespace plugin.
func (o *PluginDhcpSrvNs) OnRemove(ctx *core.PluginCtx) {}

// OnEvent for events the namespace plugin is registered.
func (o *PluginDhcpSrvNs) OnEvent(msg string, a, b interface{}) {}

// SetTruncated to complete the gopacket.DecodeFeedback interface.
func (o *PluginDhcpSrvNs) SetTruncated() {}

// HandleRxMDnsPacket parses an incoming Dhcp packet and decides what to do with it.
func (o *PluginDhcpSrvNs) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	/*
		Note: If the packet is a broadcast, we pass it to the first server.
		If the packet is unicast, pass it a specific DhcpSrv.
	*/

	m := ps.M
	p := m.GetData()
	var mackey core.MACKey
	copy(mackey[:], p[0:6])
	var client *core.CClient

	if mackey.IsBroadcast() {
		client = o.Ns.GetFirstClient()
	} else {
		client = o.Ns.CLookupByMac(&mackey)
	}

	if client == nil {
		return core.PARSER_ERR
	}

	cplg := client.PluginCtx.Get(DHCP_SRV_PLUG)
	if cplg == nil {
		return core.PARSER_ERR
	}
	dhcpSrvCPlug := cplg.Ext.(*PluginDhcpSrvClient)
	return dhcpSrvCPlug.HandleRxDhcpPacket(ps)
}

/*======================================================================================================
												Rx
======================================================================================================*/
// HandleRxDhcpPacket is called by the parser each time a packet for the DhcpSrv is received.
func HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)

	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(DHCP_SRV_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	dhcpSrvPlug := nsplg.Ext.(*PluginDhcpSrvNs)
	return dhcpSrvPlug.HandleRxDhcpPacket(ps)
}

/*
======================================================================================================

	Generate Plugin

======================================================================================================
*/
type PluginDhcpSrvCReg struct{}
type PluginDhcpSrvNsReg struct{}

// NewPlugin creates a new DhcpSrv client plugin.
func (o PluginDhcpSrvCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewDhcpSrvClient(ctx, initJson)
}

// NewPlugin creates a new DhcpSrv namespace plugin.
func (o PluginDhcpSrvNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewDhcpSrvNs(ctx, initJson)
}

/*======================================================================================================
											RPC Methods
======================================================================================================*/

type (
	ApiDhcpSrvClientCntHandler struct{} // Counter RPC Handler per Client
)

// getClientPlugin gets the client plugin given the client parameters (Mac & Tunnel Key)
func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginDhcpSrvClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, DHCP_SRV_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginDhcpSrvClient)

	return pClient, nil
}

// ApiDhcpSrvClientCntHandler gets the counters of the DhcpSrv client.
func (h ApiDhcpSrvClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return c.cdbv.GeneralCounters(err, tctx, params, &p)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(DHCP_SRV_PLUG,
		core.PluginRegisterData{Client: PluginDhcpSrvCReg{},
			Ns:     PluginDhcpSrvNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("dhcpsrv_c_cnt", ApiDhcpSrvClientCntHandler{}, true) // get counters / meta per client

	/* register parser */
	core.ParserRegister(DHCP_SRV_PLUG, HandleRxDhcpPacket)
}

func Register(ctx *core.CThreadCtx) {
	// In order for this plugin to be included in the EMU compilation one must provide this empty register
	// function. In case you remove the function call, then the core will not include EMU.
	ctx.RegisterParserCb(DHCP_SRV_PLUG)
}
