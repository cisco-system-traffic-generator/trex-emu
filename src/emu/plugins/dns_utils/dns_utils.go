/*
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

package dns_utils

import (
	"crypto/sha256"
	"emu/core"
	"emu/plugins/transport"
	"encoding/binary"
	"external/google/gopacket/layers"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
	"unsafe"
)

// Contains Dns Utils shared by mDns and Dns.

const (
	DefaultDnsQueryType  = "A"  // A = host
	DefaultDnsQueryClass = "IN" // IN = Internet
	DefaultAutoPlayRate  = 1    // Default Rate in case of Namespace Auto Play
	DefaultClientStep    = 1    // Default step to increment clients in Auto Play
	DefaultHostnameStep  = 1    // Default step to increment hostname in Auto Play
)

/*======================================================================================================
										Interfaces
======================================================================================================*/

// DnsResponderIF should be implemented by whoever responds Dns Queries, such as Dns Name Servers or
// MDns Clients.
type DnsResponderIF interface {
	// BuildAnswers receives a slice of questions and builds a slice of answers based on those questions.
	BuildAnswers([]layers.DNSQuestion) []layers.DNSResourceRecord
	// Reply replies to a slice of questions by building answers using the BuildAnswer function and then
	// writing them in the provided socket.
	Reply(id uint16, questions []layers.DNSQuestion, socket transport.SocketApi) error
}

// DnsQuerierIF should be implemented by whoever transmits Dns Queries, such as Dns clients or
// MDns Clients.
type DnsQuerierIF interface {
	// Query builds questions based using the BuildQuestions function provided in here
	// and writes the packet on the provided socket.
	Query(queries []DnsQueryParams, socket transport.SocketApi) error
}

// DnsAutoPlayPluginIF should be implemented by whoever is interested in an auto play functionality for Dns Clients.
type DnsAutoPlayPluginIF interface {
	// SendQuery receives a MAC address a name and should send a query (Dns/mDns) from the client with the MAC address to the name.
	// It returns true if we should continue sending queries, or false if we need to stop.
	SendQuery(mac *core.MACKey, name string) bool
}

/*======================================================================================================
										Dns Cache
======================================================================================================*/

// DnsCacheEntry represents an entry in the Dns Cache Table.
type DnsCacheEntry struct {
	dlist core.DList `json:"-"` // Node in the double linked list.
	// Note that the dlist must be kept first because of the unsafe conversion.
	Name            string          `json:"name"`      // Name
	Type            string          `json:"dns_type"`  // DNS Type
	Class           string          `json:"dns_class"` // DNS Class
	TTL             uint32          `json:"ttl"`       // Time to live in seconds
	Answer          string          `json:"answer"`    // IP address or Domain Name
	TimeLeft        uint32          `json:"time_left"` // Time Left for entry
	ticksUponCreate float64         `json:"-"`         // Ticks upon create
	epoch           uint64          `json:"-"`         // Epoch in which the entry was added to the table.
	timer           core.CHTimerObj `json:"-"`         // Timer to decrement TTL
	sha256          string          `json:"-"`         // SHA256 of this entry used to keep in hash table.
}

// convertToDnsCacheEntry dlist to the DnsCacheEntry that contains the dlist.
// Note: For the conversion to work, the dlist must be kept first in the DnsCacheEntry.
func convertToDnsCacheEntry(dlist *core.DList) *DnsCacheEntry {
	return (*DnsCacheEntry)(unsafe.Pointer(dlist))
}

// SHA256 makes an DnsCacheEntry hashable. We need to put into the SHA only the things that make the
// entry unique.
func (o *DnsCacheEntry) SHA256() string {
	if o.sha256 == "" {
		h := sha256.New()
		// Epoch is important, same entry in two different epochs is different.
		h.Write([]byte(fmt.Sprintf("%v-%v-%v-%v-%v", o.Name, o.Type, o.Class, o.Answer, o.epoch)))
		o.sha256 = fmt.Sprintf("%x", h.Sum(nil))
	}
	return o.sha256
}

// DnsCacheTbl is a DNS cache table. They key is the SHA256 hash of each entry without TTL.
type DnsCacheTbl map[string]*DnsCacheEntry

// DnsCache represents the Dns cache which includes the cache table, and a mechanism to add/remove entries (timer-based).
type DnsCache struct {
	timerw     *core.TimerCtx  // Timer wheel
	flushTimer core.CHTimerObj // Timer to flush the cache
	tbl        DnsCacheTbl     // Cache Table.
	head       core.DList      // Head pointer to double linked list.
	activeIter *core.DList     // Double Linked list iterator
	iterReady  bool            // Is iterator ready?
	epoch      uint64          // Cache Epoch, incremented with each flush.
}

// NewDnsCache creates a new DnsCache.
func NewDnsCache(timerw *core.TimerCtx) *DnsCache {
	o := new(DnsCache)
	o.tbl = make(DnsCacheTbl)
	o.timerw = timerw
	o.flushTimer.SetCB(o, nil, true) // Second parameter is set to true, means flush timer.
	o.head.SetSelf()                 // Set pointer to itself.
	return o
}

// OnEvent is called in two cases. Cases can be distinguished by the second parameter.
// Case 1: time to remove entries after a flush. Second parameter is True.
// Case 2: Each entry in the table calls *this* function to remove the entry. The first paremeter, is the entry itself.
func (o *DnsCache) OnEvent(a, b interface{}) {
	flush := b.(bool)
	if flush {
		o.OnFlush()
	} else {
		// remove entry from cache
		entry := a.(*DnsCacheEntry)
		o.RemoveEntry(entry.SHA256())
	}
}

// AddEntry adds a new entry to the cache table.
func (o *DnsCache) AddEntry(name string, dnsType layers.DNSType, class layers.DNSClass, ttl uint32, answer string) {
	entry := DnsCacheEntry{
		Name:            name,
		Type:            dnsType.String(),
		Class:           class.String(),
		TTL:             ttl,
		Answer:          answer,
		epoch:           o.epoch,
		ticksUponCreate: o.timerw.TicksInSec()}
	key := entry.SHA256()
	_, ok := o.tbl[key]
	if ok {
		// Entry already exists as old entry, same epoch. Remove the old one so the dlist remains chronologic.
		o.RemoveEntry(key)
	}
	o.head.AddLast(&entry.dlist)
	// The OnEvent is in table, calls with entry. Second parameter is false, means aging.
	entry.timer.SetCB(o, &entry, false)
	o.timerw.StartTicks(&entry.timer, o.timerw.DurationToTicks(time.Duration(ttl)*time.Second)) // Start timer
	o.tbl[key] = &entry
}

// RemoveEntry removes an entry from the cache table. If the entry is not in the table, nothing to do.
func (o *DnsCache) RemoveEntry(key string) {
	entry, ok := o.tbl[key]
	if !ok {
		// nothing to remove
		return
	}

	// Stop timer
	if entry.timer.IsRunning() {
		o.timerw.Stop(&entry.timer)
	}

	// Remove from Linked List
	if o.activeIter == &entry.dlist {
		// it is going to be removed
		o.activeIter = entry.dlist.Next()
	}
	o.head.RemoveNode(&entry.dlist)

	delete(o.tbl, key)
}

// IterReset resets the iterator. Returns if the iterator is resetted or not.
func (o *DnsCache) IterReset() bool {
	o.activeIter = o.head.Next()
	if o.head.IsEmpty() {
		o.iterReady = false
		return true
	}
	o.iterReady = true
	return false
}

// IterIsStopped indicates if the iterator is not ready.
func (o *DnsCache) IterIsStopped() bool {
	return !o.iterReady
}

// GetNext gets the next @param: count entries in the cache.
func (o *DnsCache) GetNext(count int) ([]*DnsCacheEntry, error) {
	r := make([]*DnsCacheEntry, 0)
	if !o.iterReady {
		return r, fmt.Errorf("Iterator is not ready. Reset the iterator!")
	}

	ticksNow := o.timerw.TicksInSec()
	for i := 0; i < count; i++ {
		if o.activeIter == &o.head {
			o.iterReady = false // require a new reset
			break
		}
		entry := convertToDnsCacheEntry(o.activeIter)
		if entry.epoch == o.epoch {
			// Values from older epochs are irrelevant
			// Update how much time left the entry has
			entry.TimeLeft = entry.TTL - uint32(ticksNow-entry.ticksUponCreate)
			r = append(r, entry)
		}
		o.activeIter = o.activeIter.Next()
	}
	return r, nil
}

// OnFlush is called after a user calls flush in order to flush the table in chunks.
// It is important to flush in chunks so we can scale.
func (o *DnsCache) OnFlush() {
	THRESHOLD := 100
	for i := 0; i < THRESHOLD; i++ {
		if o.head.IsEmpty() {
			// Table is empty
			return
		}
		entry := convertToDnsCacheEntry(o.head.Next())
		if entry.epoch < o.epoch {
			o.RemoveEntry(entry.SHA256())
		} else {
			// Cleaned everything, now we are in the current epoch.
			return
		}
	}
	// If you got here, you still have more to flush.
	o.timerw.Start(&o.flushTimer, 1)
}

// Flush flushes the Dns cache.
func (o *DnsCache) Flush() {
	/* We can't remove the whole table since it won't scale.
	What we do instead is that we increment an epoch, and when iterating we return only entries
	on the current epoch. We remove entries from older epochs using a timer in order to scale.*/
	o.epoch++
	if o.timerw.IsRunning(&o.flushTimer) || o.head.IsEmpty() {
		// Cache is empty or we already are flushing
		return
	} else {
		o.timerw.StartTicks(&o.flushTimer, 1) // Start Timer
	}
}

// AddAnswersToCache is a helping function that adds Dns Answers to the cache.
// At the moment, the only supported types are A, AAAA, PTR.
func AddAnswersToCache(cache *DnsCache, answers []layers.DNSResourceRecord) {
	for i := range answers {
		ans := answers[i]
		if ans.Type == layers.DNSTypeA || ans.Type == layers.DNSTypeAAAA {
			// The only types in which we have an IP in response are A, AAAA
			cache.AddEntry(string(ans.Name), ans.Type, ans.Class, ans.TTL, ans.IP.String())
		} else if ans.Type == layers.DNSTypePTR {
			cache.AddEntry(string(ans.Name), ans.Type, ans.Class, ans.TTL, string(ans.PTR))
		}
	}
}

/*======================================================================================================
										Cache Remover
======================================================================================================*/

// DnsCacheRemover is a special struct which is used by MDns Namespace, DNS client plugins to remove the DNS cache.
// Since the cache table can be enormous, we can't iterate it. Hence it requires a special solution.
type DnsCacheRemover struct {
	cache  *DnsCache       // Pointer to cache to remove
	timerw *core.TimerCtx  // Timer wheel
	timer  core.CHTimerObj // Timer
}

// NewDnsCacheRemover creates a new DnsCacheRemover.
func NewDnsCacheRemover(cache *DnsCache, timerw *core.TimerCtx) *DnsCacheRemover {
	o := new(DnsCacheRemover)
	o.cache = cache
	o.timerw = timerw
	o.timer.SetCB(o, 0, 0)
	o.OnEvent(0, 0)
	return o
}

// OnEvent is called each tick and removes a THRESHOLD entries from the table.
func (o *DnsCacheRemover) OnEvent(a, b interface{}) {
	THRESHOLD := 1000
	i := 0
	for k := range o.cache.tbl {
		if i >= THRESHOLD {
			break
		}
		o.cache.RemoveEntry(k)
		i++
	}
	if len(o.cache.tbl) > 0 {
		// Table is not empty.
		o.timerw.StartTicks(&o.timer, 1)
	}
}

/*======================================================================================================
										DnsPktBuilder
======================================================================================================*/

// DnsQueryParams defines the fields in an DNS query as received in RPC.
type DnsQueryParams struct {
	Name  string `json:"name" validate:"required"` // Name of query
	Type  string `json:"dns_type"`                 // Type of the query
	Class string `json:"dns_class"`                // Class of the query
}

// TxtEntries represents an entry in the TXT response.
type TxtEntries struct {
	Field string `json:"field" validate:"required"` // Field type
	Value string `json:"value" validate:"required"` // Value of the field
}

// BuildQuestions converts the queries (RPC-received) to actual Dns questions.
func BuildQuestions(queries []DnsQueryParams) ([]layers.DNSQuestion, error) {
	var questions []layers.DNSQuestion
	for i := range queries {
		dnsQueryType := queries[i].Type
		if dnsQueryType == "" {
			dnsQueryType = DefaultDnsQueryType
		}
		dnsType, err := layers.StringToDNSType(dnsQueryType)
		if err != nil {
			return nil, err
		}
		dnsQueryClass := queries[i].Class
		if dnsQueryClass == "" {
			dnsQueryClass = DefaultDnsQueryClass
		}
		dnsClass, err := layers.StringToDNSClass(dnsQueryClass)
		if err != nil {
			return nil, err
		}
		question := layers.DNSQuestion{
			Name:  []byte(queries[i].Name),
			Type:  dnsType,
			Class: dnsClass,
		}
		questions = append(questions, question)
	}
	return questions, nil
}

// Expects a txt string and converts it to a slice of byte slices compatible with the layer.
// The separator should be a comma.
// For example os=Ubuntu, hw=UCS
func BuildTxtsFromString(txtString string) (txts [][]byte) {
	txtStrings := strings.Split(txtString, ",")
	for i := range txtStrings {
		// Trim whitespaces and append
		txts = append(txts, []byte(strings.TrimSpace(txtStrings[i])))
	}
	return txts
}

// BuildTxtsFromTxtEntries converts the Txt entries into a slice of byte slices compatible with the layer.
func BuildTxtsFromTxtEntries(txtEntries []TxtEntries) (txts [][]byte) {
	for i := range txtEntries {
		txts = append(txts, []byte(txtEntries[i].Field+"="+txtEntries[i].Value))
	}
	return txts
}

// DnsPktBuilder is a simple wrapper class that builds the L7 Dns Packet.
type DnsPktBuilder struct {
	dnsTemplate layers.DNS // L7 template
	mdns        bool       // Is mDns?
}

// NewDnsPktBuilder creates and returns new DnsPktBuilder.
func NewDnsPktBuilder(mdns bool) *DnsPktBuilder {
	o := new(DnsPktBuilder)
	o.mdns = mdns
	o.dnsTemplate = layers.DNS{
		ID:           0,                           // ID is 0 for mDns and randomly generated for DNS.
		QR:           false,                       // False for Query, True for Response
		OpCode:       layers.DNSOpCodeQuery,       // Standard DNS query, opcode = 0
		AA:           false,                       // Authoritative answer.
		TC:           false,                       // Truncated, not supported
		RD:           false,                       // Recursion desired, not supported
		RA:           false,                       // Recursion available, not supported
		Z:            0,                           // Reserved for future use
		ResponseCode: layers.DNSResponseCodeNoErr, // Response code is set to 0 in queries
		QDCount:      0,                           // Number of queries, will be updated on query, 0 for response
		ANCount:      0,                           // Number of answers, will be updated in respose, 0 for queries
		NSCount:      0,                           // Number of authorities = 0
		ARCount:      0,                           // Number of additional records = 0
	}
	return o
}

// BuildQueryPkt builds and returns a query packet with new questions based on the template packet.
func (o *DnsPktBuilder) BuildQueryPkt(questions []layers.DNSQuestion, simulation bool) []byte {

	if !simulation && !o.mdns {
		// Generate the transaction ID randomly.
		// In MDns the transaction ID must be set to 0.
		o.dnsTemplate.ID = uint16(rand.Uint32())
	}
	o.dnsTemplate.QR = false                                 // Query
	o.dnsTemplate.AA = false                                 // AA is false for Queries
	o.dnsTemplate.ResponseCode = layers.DNSResponseCodeNoErr // Set Response Code
	o.dnsTemplate.QDCount = uint16(len(questions))           // Number of questions
	o.dnsTemplate.ANCount = 0                                // No answers, might be not 0 from previous response
	o.dnsTemplate.Questions = questions                      // Questions
	o.dnsTemplate.Answers = []layers.DNSResourceRecord{}     // Answers

	return core.PacketUtlBuild(&o.dnsTemplate)
}

// BuildResponsePkt builds and returns a response packet with new questions/answers based on the template packet.
func (o *DnsPktBuilder) BuildResponsePkt(transactionId uint16,
	answers []layers.DNSResourceRecord,
	questions []layers.DNSQuestion,
	respCode layers.DNSResponseCode) []byte {

	o.dnsTemplate.ID = transactionId               // Transaction ID
	o.dnsTemplate.QR = true                        // Response
	o.dnsTemplate.AA = true                        // AA is true for Response packets
	o.dnsTemplate.ResponseCode = respCode          // Set Response Code
	o.dnsTemplate.QDCount = uint16(len(questions)) // Number of questions
	o.dnsTemplate.ANCount = uint16(len(answers))   // Number of answers
	o.dnsTemplate.Questions = questions            // Questions
	o.dnsTemplate.Answers = answers                // Answers

	return core.PacketUtlBuild(&o.dnsTemplate)
}

/*======================================================================================================
										AutoPlay
======================================================================================================*/

// ProgramEntry represents a single entry in the program which will override the default query.
type ProgramEntry struct {
	Hostnames []string `json:"hostnames" validate:"required"` // Hostnames to query
	DnsType   string   `json:"type"`                          // Query Type
	DnsClass  string   `json:"class"`                         // Query class
}

// CommonDnsAutoPlayParams represents the params provided to an DNS/mDNS namespace as init Json.
type CommonDnsAutoPlayParams struct {
	Rate             float32 `json:"rate"`                                  // Rate in seconds between two consequent queries in the program
	QueryAmount      uint64  `json:"query_amount"`                          // Amount of queries to send. Defaults to 0, and 0 means infinite
	MinClient        string  `json:"min_client" validate:"required"`        // MAC address representing the first client
	MaxClient        string  `json:"max_client" validate:"required"`        // MAC address representing the last client
	ClientStep       uint16  `json:"client_step"`                           // Client incremental step, Defaults to DefaultClientStep
	HostnameTemplate string  `json:"hostname_template" validate:"required"` // Template hostname, will apply number
	MinHostname      uint16  `json:"min_hostname" validate:"eq=0|required"` // The first number to apply to `hostname_template`
	MaxHostname      uint16  `json:"max_hostname" validate:"eq=0|required"` // The last number to apply to `hostname_template`
	InitHostname     uint16  `json:"init_hostname"`                         // The number we start to apply from
	HostnameStep     uint16  `json:"hostname_step"`                         // Hostname incremental step, defaults to DefaultHostnameStep
	DnsType          string  `json:"type"`                                  // Query Type, Defaults to DefaultDnsQueryType
	DnsClass         string  `json:"class"`                                 // Query class, Defaults to DefaultDnsQueryClass
}

// DnsNsAutoPlay defines a struct that is responsible for automatic queries based on the program defined
// in the namespace's init Json. These queries are sent on a rate that can also be specified in said
// init Json.
type DnsNsAutoPlay struct {
	timerw          *core.TimerCtx          // Timer wheel
	timer           core.CHTimerObj         // Timer object
	plugin          DnsAutoPlayPluginIF     // Plugin Interface that supports SendQuery (Dns or mDns)
	params          CommonDnsAutoPlayParams // Common AutoPlay params
	minClient       uint64                  // Minimal client MAC as an uint64
	maxClient       uint64                  // Maximal client MAC as an uint64
	currentClient   uint64                  // The current MAC as an uint64
	ticks           uint32                  // Number of ticks between two consecutive program entries
	numPktsPerEvent uint32                  // Num packets to send each even
	currentHostname uint16                  // The current hostname
}

// NewMDnsNsAutoPlay creates a new MDnsNsAutoPlay object.
func NewDnsNsAutoPlay(plugin DnsAutoPlayPluginIF, timerw *core.TimerCtx, autoPlayParams CommonDnsAutoPlayParams) *DnsNsAutoPlay {
	o := new(DnsNsAutoPlay)
	o.plugin = plugin
	o.timerw = timerw

	o.params = autoPlayParams
	err := o.processCommonParams()
	if err != nil {
		return nil
	}

	duration := time.Duration(float32(time.Second) / o.params.Rate)
	o.ticks, o.numPktsPerEvent = o.timerw.DurationToTicksBurst(duration) // Calculate ticks
	o.timer.SetCB(o, 0, 0)                                               // Set callback for timer
	o.timerw.StartTicks(&o.timer, o.ticks)                               // Start timer
	return o
}

// processCommonParams processes the params that the user defines in Init Json.
func (o *DnsNsAutoPlay) processCommonParams() error {

	extHwAddr := make([]byte, 8) // Prepend two zero bytes so we can hold the MAC address as an uint64.
	hwAddr, err := net.ParseMAC(o.params.MinClient)
	copy(extHwAddr[2:], hwAddr)
	if err != nil {
		return fmt.Errorf("Couldn't parse MinClient!")
	}
	o.minClient = binary.BigEndian.Uint64(extHwAddr)
	hwAddr, err = net.ParseMAC(o.params.MaxClient)
	if err != nil {
		return fmt.Errorf("Couldn't parse MaxClient!")
	}
	copy(extHwAddr[2:], hwAddr)
	o.maxClient = binary.BigEndian.Uint64(extHwAddr)
	o.currentClient = o.minClient // Start from the minimal client

	if o.params.MinHostname > o.params.MaxHostname {
		// Validate that min <= max
		return fmt.Errorf("MinHostname <= MaxHostname doesn't hold")
	}
	if o.params.InitHostname != 0 && (o.params.InitHostname < o.params.MinHostname || o.params.InitHostname > o.params.MaxHostname) {
		// Validate that min <= init <= max
		return fmt.Errorf("MinHostname <= InitHostname <= MaxHostname doesn't hold")
	}
	if o.params.InitHostname > o.params.MinHostname {
		// Init hostname was defined
		o.currentHostname = o.params.InitHostname
	} else {
		// Start from the minimal hostname
		o.currentHostname = o.params.MinHostname
	}

	return nil
}

// OnRemove is called when we remove the AutoPlay
func (o *DnsNsAutoPlay) OnRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

// domainInc increments the current value according to step in the [min-max] domain
func (o *DnsNsAutoPlay) domainInc(min, max, step, current uint64) uint64 {
	left := max - current // this will never overflow as currValue < maxValue
	if step <= left {
		// simple increment by step, not overflow of domain
		// step is fixed module size of domain
		current += step
	} else {
		// overflow of domain
		// if here then (step > left) therefore step - left - 1 will not overflow
		current = min + (step - left - 1) // restart also consumes 1
	}
	return current
}

// incClient increments the MAC address of the client based on defined step and returns the old address (prior to increment)
func (o *DnsNsAutoPlay) incClient() *core.MACKey {
	b := make([]byte, 8)
	var mac core.MACKey
	binary.BigEndian.PutUint64(b, o.currentClient)
	copy(mac[:], b[2:])
	o.currentClient = o.domainInc(o.minClient, o.maxClient, uint64(o.params.ClientStep), o.currentClient)
	return &mac
}

// incHostname increments the hostname based on the defined step and returns the complete hostname with the old value applied.
func (o *DnsNsAutoPlay) incHostname() (hostname string) {
	hostname = fmt.Sprintf(o.params.HostnameTemplate, o.currentHostname)
	o.currentHostname = uint16(o.domainInc(uint64(o.params.MinHostname), uint64(o.params.MaxHostname), uint64(o.params.HostnameStep), uint64(o.currentHostname)))
	return hostname
}

// OnEvent is called by the timer each time a new query needs to be send.
func (o *DnsNsAutoPlay) OnEvent(a, b interface{}) {

	var restartTimer bool
	for i := 0; i < int(o.numPktsPerEvent); i++ {
		mac := o.incClient()        // Get the next client
		hostname := o.incHostname() // Get the next hostname

		restart := o.plugin.SendQuery(mac, hostname) // Send Query and see if we need to restart timer.
		restartTimer = (restartTimer || restart)
	}

	if restartTimer {
		o.timerw.StartTicks(&o.timer, o.ticks) // Restart timer
	}
}
