/*
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

package mdns

/*
mDNS - Multicast DNS (Domain Name System) - https://en.wikipedia.org/wiki/Multicast_DNS

Implementation based on RFC 6762 - https://tools.ietf.org/html/rfc6762
*/

import (
	"crypto/sha256"
	"emu/core"
	"emu/plugins/transport"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	MDNS_PLUG              = "mdns"             // Plugin name
	Ipv4HostPort           = "224.0.0.251:5353" // Host:Port in case of Ipv4
	Ipv6HostPort           = "[ff02::fb]:5353"  // Host:Port in case of Ipv6
	DefaultMDnsQueryType   = "A"                // A = host
	DefaultMDnsQueryClass  = "IN"               // IN = Internet
	DefaultMDnsResponseTTL = 240                // Default TTL value
)

var Ipv4McastMacAddress core.MACKey = core.MACKey{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB} // L2 multicast MAC for Ipv4
var Ipv6McastMacAddress core.MACKey = core.MACKey{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB} // L2 multicast MAC for Ipv6

// MDnsClientStats defines a number of stats for an mDNS client.
type MDnsClientStats struct {
	invalidInitJson      uint64 // Error while decoding client init Json
	invalidSocket        uint64 // Error while creating socket
	socketWriteError     uint64 // Error while writing on a socket
	pktTxMDnsQuery       uint64 // Num of mDNS queries transmitted
	pktRxMDnsQuery       uint64 // Num of mDNS queries received
	pktTxMDnsResponse    uint64 // Num of mDNS responses transmitted
	ipv6QueryNoPlugin    uint64 // Num of Ipv6 queries that can't be sent because no IPv6
	ipv6ResponseNoPlugin uint64 // Num of Ipv6 queries that can't be answered because no IPv6
	queryAAAANoIpv6      uint64 // Num of AAAA queries that can't be answered because of no IPv6
	queryPTRNoDomainName uint64 // Num of PTR queries that can't be answered because domain name unspecified
	queryTXTNoTxtDefined uint64 // Num of TXT queries that can't be answered because txt unspecified
	unsupportedDnsType   uint64 // Num of queries received with an unsupported type
}

// NewMDnsClientStatsDb creates a new counter database for MDnsClientStats.
func NewMDnsClientStatsDb(o *MDnsClientStats) *core.CCounterDb {
	db := core.NewCCounterDb(MDNS_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidInitJson,
		Name:     "invalidInitJson",
		Help:     "Error while decoding init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidSocket,
		Name:     "invalidSocket",
		Help:     "Error creating socket",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.socketWriteError,
		Name:     "socketWriteError",
		Help:     "Error writing in socket",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxMDnsQuery,
		Name:     "pktTxMDnsQuery",
		Help:     "Num of mDNS queries transmitted",
		Unit:     "pkts",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxMDnsQuery,
		Name:     "pktRxMDnsQuery",
		Help:     "Num of mDNS queries received",
		Unit:     "pkts",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxMDnsResponse,
		Name:     "pktTxMDnsResponse",
		Help:     "Num of mDNS responses transmitted",
		Unit:     "pkts",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.ipv6QueryNoPlugin,
		Name:     "ipv6QueryNoPlugin",
		Help:     "Num of Ipv6 queries that can't be sent because no IPv6",
		Unit:     "query",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.ipv6ResponseNoPlugin,
		Name:     "ipv6ResponseNoPlugin",
		Help:     "Num of Ipv6 queries that can't be answered because no IPv6",
		Unit:     "query",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.queryAAAANoIpv6,
		Name:     "queryAAAANoIpv6",
		Help:     "Num of AAAA queries that can't be answered because of no IPv6",
		Unit:     "query",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.queryPTRNoDomainName,
		Name:     "queryPTRNoDomainName",
		Help:     "Num of PTR queries that can't be answered because domain name unspecified",
		Unit:     "query",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.queryTXTNoTxtDefined,
		Name:     "queryTXTNoTxtDefined",
		Help:     "Num of TXT queries that can't be answered because txt unspecified",
		Unit:     "query",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.unsupportedDnsType,
		Name:     "unsupportedDnsType",
		Help:     "Num of queries received with an unsupported type",
		Unit:     "query",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

// MDnsNsStats defines a number of stats for an mDNS namespace.
type MDnsNsStats struct {
	pktRxErrTooShort       uint64 // Received packet is too short
	pktRxBadDstMac         uint64 // mDns packet received with invalid dst Mac
	pktRxBadDstIp          uint64 // mDns packet received with invalid dst IP
	pktRxBadEthType        uint64 // mDns packet received with invalid ethernet type
	rxPkts                 uint64 // Num of mDNS packets received
	rxQuestions            uint64 // Num of mDNS questions received in namespace
	rxAnswers              uint64 // Num of mDNS answers received in namespace
	rxAuthoritiesUnhandled uint64 // Num of authorities unhandled in Rx packets
	rxAddRecordsUnhandled  uint64 // Num of additional records unhandled in Rx packets
}

// NewMDnsNsStatsDb creates a new counter database for MDnsNsStats.
func NewMDnsNsStatsDb(o *MDnsNsStats) *core.CCounterDb {
	db := core.NewCCounterDb(MDNS_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxErrTooShort,
		Name:     "pktRxErrTooShort",
		Help:     "Rx packet too short",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadDstMac,
		Name:     "pktRxBadDstMac",
		Help:     "mDns packet received with invalid Dst Mac",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadDstIp,
		Name:     "pktRxBadDstIp",
		Help:     "mDns packet received with invalid Dst Ip",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBadEthType,
		Name:     "pktRxBadEthType",
		Help:     "mDns packet received with invalid Ethernet Type",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxPkts,
		Name:     "rxPkts",
		Help:     "Num of mDNS pkts received",
		Unit:     "pkts",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxQuestions,
		Name:     "rxQuestions",
		Help:     "Num of mDNS questions received in namespace",
		Unit:     "query",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxAnswers,
		Name:     "rxAnswers",
		Help:     "Numb of mDNS answers received in namespace",
		Unit:     "reply",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxAuthoritiesUnhandled,
		Name:     "rxAuthoritiesUnhandled",
		Help:     "Num of authorities unhandled in Rx packets",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxAddRecordsUnhandled,
		Name:     "rxAddRecordsUnhandled",
		Help:     "Num of additional records unhandled in Rx packets",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

// mdnsEvents holds a list of events on which the mDNS plugin is interested.
var mdnsEvents = []string{}

// TxtEntries represents an entry in the TXT response.
type TxtEntries struct {
	Field string `json:"field" validate=required` // Field type
	Value string `json:"value" validate=required` // Value of the field
}

// MDnsClientParams represents the entries of the Init Json passed to a new MDns client.
type MDnsClientParams struct {
	Hosts       []string     `json:"hosts"`             // Hosts owned by this client. Note that this can include IP addresses for PTR support.
	DomainName  string       `json:"domain_name"`       // Domain name for the client in case of PTR query.
	Txt         []TxtEntries `json:"txt" validate=dive` // Txt to answer in case the TXT query.
	ResponseTTL uint32       `json:"ttl"`               // TTL for response. Will override the default value if provided.
}

// PluginMDNsClient represents a MDns client.
type PluginMDnsClient struct {
	core.PluginBase                     // Plugin Base embedded struct so we get all the base functionality
	mDnsNsPlugin    *PluginMDnsNs       // Pointer to mDNS namespace plugin
	params          MDnsClientParams    // Init Json params
	socketIpv4      transport.SocketApi // Socket API for IPv4
	socketIpv6      transport.SocketApi // Socket API for IPv6. Might be nil in case there is no IPv6.
	stats           MDnsClientStats     // mDNS client statistics
	cdb             *core.CCounterDb    // Counters database
	cdbv            *core.CCounterDbVec // Counters database vector
	hosts           map[string]bool     // Keep a set of hosts for fast lookup
	dnsTemplate     layers.DNS          // L7 Payload Template for an mDNS query/response
	domainName      []byte              // Domain Name as a byte slice if provided.
	txts            [][]byte            // Txt byte array for TXT queries
}

// NewMDnsClient creates a new MDns client.
func NewMDnsClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginMDnsClient)
	o.InitPluginBase(ctx, o)             // Init base object
	o.RegisterEvents(ctx, mdnsEvents, o) // Register events

	o.params.ResponseTTL = DefaultMDnsResponseTTL // Set Default value prior to unmarshal.
	err := o.Tctx.UnmarshalValidate(initJson, &o.params)
	if err != nil {
		o.stats.invalidInitJson++
		return &o.PluginBase
	}

	o.OnCreate()

	return &o.PluginBase
}

// buildTxt converts the Txt entries into a byte array
func (o *PluginMDnsClient) buildTxts() {
	for i := range o.params.Txt {
		txtEntry := []byte(o.params.Txt[i].Field + "=" + o.params.Txt[i].Value)
		o.txts = append(o.txts, txtEntry)
	}
}

// OnCreate is called upon creating a new mDNS client.
func (o *PluginMDnsClient) OnCreate() {

	// Register hosts on namespace database.
	o.mDnsNsPlugin = o.Ns.PluginCtx.Get(MDNS_PLUG).Ext.(*PluginMDnsNs)
	o.mDnsNsPlugin.RegisterClientHosts(o.params.Hosts, o)

	// stats
	o.cdb = NewMDnsClientStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec(MDNS_PLUG)
	o.cdbv.Add(o.cdb)

	var ioctlMap transport.IoctlMap = make(map[string]interface{})
	// According to RFC 3171 a packet sent to the Local Network Control Block (224.0.0.0/24)
	// should be sent with TTL=255
	ioctlMap["ttl"] = 255

	// create sockets
	transportCtx := transport.GetTransportCtx(o.Client)
	if transportCtx != nil {
		var err error
		o.socketIpv4, err = transportCtx.Dial("udp", Ipv4HostPort, o, ioctlMap, &Ipv4McastMacAddress, 5353)
		if err != nil {
			o.stats.invalidSocket++
			return
		}
		_, err = o.Client.GetSourceIPv6()
		if o.Tctx.Simulation || err == nil {
			// Create Ipv6 socket only if client has Ipv6 address.
			o.socketIpv6, err = transportCtx.Dial("udp", Ipv6HostPort, o, ioctlMap, &Ipv6McastMacAddress, 5353)
			if err != nil {
				o.stats.invalidSocket++
				return
			}
		}
	}

	// create hosts set
	o.hosts = make(map[string]bool)
	for _, host := range o.params.Hosts {
		o.hosts[host] = true
	}

	// create query template - maybe put this in a function
	o.dnsTemplate = layers.DNS{
		ID:           0,                           // Maybe randomly generate this
		QR:           false,                       // False for Query, True for Response
		OpCode:       layers.DNSOpCodeQuery,       // Standard DNS query, opcode = 0
		AA:           false,                       // Authoritative answer, not relevant in query
		TC:           false,                       // Truncated, not supported
		RD:           false,                       // Recursion desired, not supported in mDNS
		RA:           false,                       // Recursion available, not supported in mDNS
		Z:            0,                           // Reserved for future use
		ResponseCode: layers.DNSResponseCodeNoErr, // Response code is set to 0 in queries
		QDCount:      0,                           // Number of queries, will be updated on query, 0 for response
		ANCount:      0,                           // Number of answers, will be updated in respose, 0 for queries
		NSCount:      0,                           // Number of authorities = 0
		ARCount:      0,                           // Number of additional records = 0
	}

	// convert domain name to byte
	if o.params.DomainName != "" {
		o.domainName = []byte(o.params.DomainName)
	}
	o.buildTxts() // Convert Txt entries to []byte
}

// OnEvent callback of the mDNS client in case of events.
func (o *PluginMDnsClient) OnEvent(msg string, a, b interface{}) {}

// OnRemove is called when we remove the mDNS client.
func (o *PluginMDnsClient) OnRemove(ctx *core.PluginCtx) {
	ctx.UnregisterEvents(&o.PluginBase, mdnsEvents)
	// Unregister hosts from namespace database.
	o.mDnsNsPlugin.UnregisterHosts(o.params.Hosts)
}

// OnRxEvent function to complete the ISocketCb interface.
func (o *PluginMDnsClient) OnRxEvent(event transport.SocketEventType) { /* no Rx expected in mDNS */ }

// OnRxData function to complete the ISocketCb interface.
func (o *PluginMDnsClient) OnRxData(d []byte) { /* no Rx expected in mDNS */ }

// OnTxEvent function to complete the ISocketCb interface.
func (o *PluginMDnsClient) OnTxEvent(event transport.SocketEventType) { /* No Tx event expected */ }

// buildQuestions converts the queries (RPC-received) to actual mDNS questions.
func (o *PluginMDnsClient) buildQuestions(queries []DnsQueryParams) ([]layers.DNSQuestion, error) {
	var questions []layers.DNSQuestion
	for i, _ := range queries {
		dnsQueryType := queries[i].Type
		if dnsQueryType == "" {
			dnsQueryType = DefaultMDnsQueryType
		}
		dnsType, err := layers.StringToDNSType(dnsQueryType)
		if err != nil {
			return nil, err
		}
		dnsQueryClass := queries[i].Class
		if dnsQueryClass == "" {
			dnsQueryClass = DefaultMDnsQueryClass
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

// Query sends an IPv4/IPv6 or both mDNS query.
func (o *PluginMDnsClient) Query(queries []DnsQueryParams) error {

	var ipv6Queries, ipv4Queries []DnsQueryParams
	for i := range queries {
		if queries[i].Ipv6 {
			ipv6Queries = append(ipv6Queries, queries[i])
		} else {
			ipv4Queries = append(ipv4Queries, queries[i])
		}
	}

	if !o.Tctx.Simulation {
		// Generate the transaction ID randomly.
		o.dnsTemplate.ID = uint16(rand.Uint32())
	}

	// Convert user queries into DNS questions
	ipv4Questions, err := o.buildQuestions(ipv4Queries)
	if err != nil {
		return err
	}

	if len(ipv4Questions) > 0 {
		// complete the template for v4
		o.dnsTemplate.QR = false                             // Query
		o.dnsTemplate.QDCount = uint16(len(ipv4Questions))   // Number of questions
		o.dnsTemplate.ANCount = 0                            // No answers, might be not 0 from previous response
		o.dnsTemplate.Questions = ipv4Questions              // Questions
		o.dnsTemplate.Answers = []layers.DNSResourceRecord{} // Answers

		dnsQuery := core.PacketUtlBuild(
			&o.dnsTemplate,
		)

		transportErr, _ := o.socketIpv4.Write(dnsQuery)
		if transportErr != transport.SeOK {
			o.stats.socketWriteError++
			return transportErr.Error()
		}
		o.stats.pktTxMDnsQuery++ // successfully send query
	}

	ipv6Questions, err := o.buildQuestions(ipv6Queries)
	if err != nil {
		return err
	}

	if len(ipv6Questions) > 0 && o.socketIpv6 == nil {
		o.stats.ipv6QueryNoPlugin++
		return fmt.Errorf("Ipv6 query but no Ipv6 plugin enabled for client.")
	}

	if len(ipv6Questions) > 0 {
		// complete the template for v6
		o.dnsTemplate.QR = false                             // Query
		o.dnsTemplate.QDCount = uint16(len(ipv6Questions))   // Number of questions
		o.dnsTemplate.ANCount = 0                            // No answers, might be not 0 from previous response
		o.dnsTemplate.Questions = ipv6Questions              // Questions
		o.dnsTemplate.Answers = []layers.DNSResourceRecord{} // Answers

		dnsQuery := core.PacketUtlBuild(
			&o.dnsTemplate,
		)

		transportErr, _ := o.socketIpv6.Write(dnsQuery)
		if transportErr != transport.SeOK {
			o.stats.socketWriteError++
			return transportErr.Error()
		}
		o.stats.pktTxMDnsQuery++ // successfully send query
	}

	return nil
}

// buildAnswers builds answers based on mDNS questions.
func (o *PluginMDnsClient) buildAnswers(questions []layers.DNSQuestion) []layers.DNSResourceRecord {
	var answers []layers.DNSResourceRecord
	for _, q := range questions {
		answer := layers.DNSResourceRecord{
			Name:  []byte(q.Name),
			Type:  q.Type,
			Class: q.Class,
			TTL:   o.params.ResponseTTL,
		}

		switch answer.Type {
		case layers.DNSTypeA:
			answer.IP = o.Client.Ipv4.ToIP()
		case layers.DNSTypeAAAA:
			ipv6, err := o.Client.GetSourceIPv6()
			if err != nil {
				o.stats.queryAAAANoIpv6++
				continue
			}
			answer.IP = ipv6.ToIP()
		case layers.DNSTypePTR:
			if o.domainName == nil {
				o.stats.queryPTRNoDomainName++
				continue
			}
			answer.PTR = o.domainName
		case layers.DNSTypeTXT:
			if o.txts == nil {
				o.stats.queryTXTNoTxtDefined++
				continue
			}
			answer.TXTs = o.txts
		default:
			o.stats.unsupportedDnsType++
			continue // skip the ones we can't answer
		}
		answers = append(answers, answer)
	}
	return answers
}

// Reply sends a mDNS response after a query was received.
func (o *PluginMDnsClient) Reply(transactionID uint16, questions []layers.DNSQuestion, ipv6 bool) error {

	if ipv6 && o.socketIpv6 == nil {
		// Ipv6 query was received however client doesn't have the IPv6 plugin.
		o.stats.ipv6ResponseNoPlugin++
		return fmt.Errorf("Ipv6 query was received but no Ipv6 plugin enabled for client.")
	}

	answers := o.buildAnswers(questions)
	if answers == nil {
		// Nothing we can answer, respective error counters are set in buildAnswers.
		return fmt.Errorf("Couldn't answer any query.")
	}

	// complete the template
	o.dnsTemplate.ID = transactionID                 // Transaction ID
	o.dnsTemplate.QR = true                          // Query
	o.dnsTemplate.QDCount = 0                        // Number of questions, might be not 0 from previous response
	o.dnsTemplate.ANCount = uint16(len(answers))     // No answers,
	o.dnsTemplate.Questions = []layers.DNSQuestion{} // Questions
	o.dnsTemplate.Answers = answers                  // Answers

	dnsResponse := core.PacketUtlBuild(
		&o.dnsTemplate,
	)

	var socket transport.SocketApi
	if ipv6 {
		// if you are here there is Ipv6 enabled.
		socket = o.socketIpv6
	} else {
		socket = o.socketIpv4
	}

	transportErr, _ := socket.Write(dnsResponse)
	if transportErr != transport.SeOK {
		o.stats.socketWriteError++
		return transportErr.Error()
	}
	o.stats.pktTxMDnsResponse++
	return nil
}

// HandleRxMDnsQuestions filters the questions and replies to the ones the client can.
func (o *PluginMDnsClient) HandleRxMDnsQuestions(transactionID uint16, questions []layers.DNSQuestion, ipv6 bool) {
	// filter the questions so we get only this client's questions (cQuestions)
	var cQuestions []layers.DNSQuestion
	for i := range questions {
		q := questions[i]
		if _, ok := o.hosts[string(q.Name)]; ok {
			cQuestions = append(cQuestions, q)
		}
	}
	if len(cQuestions) > 0 {
		o.stats.pktRxMDnsQuery++                 // At least one question was for this client
		o.Reply(transactionID, cQuestions, ipv6) // Reply to the ones we can
	}
}

// AddHosts adds hostname to mDNS client and registers the hosts in the namespace database.
// Returns list of hosts already existing / couldn't be added.
func (o *PluginMDnsClient) AddHosts(hosts []string) []string {
	newHosts := o.mDnsNsPlugin.RegisterClientHosts(hosts, o) // new (non-existing) hosts
	newHostsSet := make(map[string]bool)                     // convert to set for fast lookup
	for _, host := range newHosts {
		newHostsSet[host] = true
	}
	var alreadyExistingHosts []string
	for _, host := range hosts {
		if _, ok := newHostsSet[host]; ok {
			o.hosts[host] = true // new added host
		} else {
			alreadyExistingHosts = append(alreadyExistingHosts, host) // already existing
		}
	}
	return alreadyExistingHosts
}

// RemoveHosts removes hostnames from mDNS clients and un registers them from the namespace database.
// Returns slice of non existing hosts.
func (o *PluginMDnsClient) RemoveHosts(hosts []string) []string {
	var nonExistingHosts []string
	for _, host := range hosts {
		if _, ok := o.hosts[host]; !ok {
			nonExistingHosts = append(nonExistingHosts, host)
		}
		delete(o.hosts, host)
	}
	o.mDnsNsPlugin.UnregisterHosts(hosts)
	return nonExistingHosts
}

// GetHosts returns slice of hostnames an mDNS client owns.
func (o *PluginMDnsClient) GetHosts() []string {
	hosts := make([]string, len(o.hosts))
	i := 0
	for host := range o.hosts {
		hosts[i] = host
		i++
	}
	return hosts
}

/*======================================================================================================
												Ns Cache
======================================================================================================*/

// MDnsCacheEntry represents an entry in the MDns Cache Table.
type MDnsCacheEntry struct {
	Name   string          `json:"name"`      // Name
	Type   string          `json:"dns_type"`  // DNS Type
	Class  string          `json:"dns_class"` // DNS Class
	TTL    uint32          `json:"ttl"`       // Time to live in seconds
	Answer string          `json:"answer"`    // IP address or Domain Name
	timer  core.CHTimerObj `json:"-"`         // Timer to decrement TTL
}

// ToSha256 makes an MDnsCacheEntry hashable. The only thing that changes in an MDnsCacheEntry is the TTL,
// as such it is excluded from the hash.
func (o *MDnsCacheEntry) ToSHA256() string {
	h := sha256.New()
	// TTL can change - The other 4 values must be unique.
	h.Write([]byte(fmt.Sprintf("%v-%v-%v-%v", o.Name, o.Type, o.Class, o.Answer)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// MDnsCacheTbl is a DNS cache table. They key is the SHA256 hash of each entry without TTL.
type MDnsCacheTbl map[string]*MDnsCacheEntry

// MDnsCache reprents the MDns cache which includes the cache table, and a mechanism to add/remove entries (timer-based).
type MDnsCache struct {
	timerw *core.TimerCtx // Timer wheel
	tbl    MDnsCacheTbl   // Cache Table.
	stats  *MDnsNsStats   // mDns namespace stats
}

// Create a new MDnsCache.
func (o *MDnsCache) Create(timerw *core.TimerCtx, stats *MDnsNsStats) {
	o.tbl = make(MDnsCacheTbl)
	o.stats = stats
	o.timerw = timerw
}

// OnEvent is called each second and decreases the TTL by one. Each entry in the table calls *this* function.
// The first paremeter, is the entry itself.
func (o *MDnsCache) OnEvent(a, b interface{}) {
	entry := a.(*MDnsCacheEntry)
	entry.TTL--
	if entry.TTL == 0 {
		o.RemoveEntry(entry.ToSHA256())
	} else {
		o.timerw.StartTicks(&entry.timer, o.timerw.DurationToTicks(1*time.Second))
	}
}

// OnRemove is called when the cache is removed.
func (o *MDnsCache) OnRemove() {
	for k := range o.tbl {
		o.RemoveEntry(k)
	}
}

// AddEntry adds a new entry to the cache table.
func (o *MDnsCache) AddEntry(name string, dnsType layers.DNSType, class layers.DNSClass, ttl uint32, answer string) {
	entry := MDnsCacheEntry{Name: name, Type: dnsType.String(), Class: class.String(), TTL: ttl, Answer: answer}
	entry.timer.SetCB(o, &entry, 0)                                            // The OnEvent is in table, calls with entry.
	o.timerw.StartTicks(&entry.timer, o.timerw.DurationToTicks(1*time.Second)) // Start timer
	o.tbl[entry.ToSHA256()] = &entry
}

// RemoveEntry removes an entry from the cache table. If the entry is not in the table, nothing to do.
func (o *MDnsCache) RemoveEntry(key string) {
	entry, ok := o.tbl[key]
	if !ok {
		// nothing to remove
		return
	}
	if entry.timer.IsRunning() {
		o.timerw.Stop(&entry.timer)
	}
	delete(o.tbl, key)
}

/*======================================================================================================
										Ns mDNS plugin
======================================================================================================*/

//PluginMDnsNs represents the mDNS plugin in namespace level.
type PluginMDnsNs struct {
	core.PluginBase                              // Embed plugin base
	cache           MDnsCache                    // mDns cache
	mapHostClient   map[string]*PluginMDnsClient // Map hosts to client database
	stats           MDnsNsStats                  // mDns namespace statistics
	cdb             *core.CCounterDb             // mDns counters
	cdbv            *core.CCounterDbVec          // mDns counter vector
}

// NewMDnsNs creates a new mDNS namespace plugin.
func NewMDnsNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	o := new(PluginMDnsNs)
	o.InitPluginBase(ctx, o)                             // Init the base plugin
	o.RegisterEvents(ctx, []string{}, o)                 // No events to register in namespace level.
	o.cache.Create(ctx.Tctx.GetTimerCtx(), &o.stats)     // Create cache
	o.mapHostClient = make(map[string]*PluginMDnsClient) // Create hosts -> client database
	o.cdb = NewMDnsNsStatsDb(&o.stats)                   // Create new stats database
	o.cdbv = core.NewCCounterDbVec("mDns")
	o.cdbv.Add(o.cdb)
	return &o.PluginBase
}

// OnRemove when removing mDNS namespace plugin.
func (o *PluginMDnsNs) OnRemove(ctx *core.PluginCtx) {
	o.cache.OnRemove()
}

// OnEvent for events the namespace plugin is registered.
func (o *PluginMDnsNs) OnEvent(msg string, a, b interface{}) {}

// HandleRxMDnsAnswers handles an incoming mDns packet's answers by adding them into the namespace cache.
// The only types added to cache are A, AAAA, PTR. Others are ignored.
func (o *PluginMDnsNs) HandleRxMDnsAnswers(answers []layers.DNSResourceRecord) {
	for i := range answers {
		ans := answers[i]
		if ans.Type == layers.DNSTypeA || ans.Type == layers.DNSTypeAAAA {
			// The only types in which we have an IP in response are A, AAAA
			o.cache.AddEntry(string(ans.Name), ans.Type, ans.Class, ans.TTL, ans.IP.String())
		} else if ans.Type == layers.DNSTypePTR {
			o.cache.AddEntry(string(ans.Name), ans.Type, ans.Class, ans.TTL, string(ans.PTR))
		}
	}
}

// HandleRxMDnsQuestions handles an incoming mDns packet's questions.
func (o *PluginMDnsNs) HandleRxMDnsQuestions(transactionID uint16, questions []layers.DNSQuestion, ipv6 bool) {
	// Collect clients that can answer at least one question by hostname.
	// Then let all these clients answer all the questions they can.
	var relevantClients []*PluginMDnsClient
	for i := range questions {
		q := questions[i]
		c, err := o.GetClientByHost(string(q.Name))
		if err != nil {
			// client not found, we can safely proceed to next question
			continue
		}
		relevantClients = append(relevantClients, c)
	}
	// all the clients in relevantClients can answer at least one question
	for _, c := range relevantClients {
		c.HandleRxMDnsQuestions(transactionID, questions, ipv6)
	}
}

// HandleRxMDnsPacket parses an incoming mDNS packet and decides what to do with it.
func (o *PluginMDnsNs) HandleRxMDnsPacket(ps *core.ParserPacketState) int {

	// parse packet
	// if query -> redirect to client based on hostname registration.
	// if response -> handle response by adding value in cache.

	o.stats.rxPkts++

	m := ps.M

	if m.PktLen() < uint32(ps.L7) {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	p := m.GetData()

	ethHeader := layers.EthernetHeader(p[0:14])

	var dstMac core.MACKey
	copy(dstMac[:], ethHeader.GetDestAddress()[:6])
	var ethType layers.EthernetType
	ethType = layers.EthernetType(ethHeader.GetNextProtocol())

	var ipv6 bool

	if ethType == layers.EthernetTypeIPv6 {
		ipv6 = true
	} else if ethType == layers.EthernetTypeIPv4 {
		ipv6 = false
	} else {
		o.stats.pktRxBadEthType++
		return core.PARSER_ERR
	}

	// for now we support only multicast! (unicast responses are not supported)
	var expDstMac core.MACKey
	if ipv6 {
		expDstMac = Ipv6McastMacAddress
	} else {
		expDstMac = Ipv4McastMacAddress
	}

	if expDstMac != dstMac {
		o.stats.pktRxBadDstMac++
		return core.PARSER_ERR
	}

	// verify IP address
	if ipv6 {
		host, _, _ := net.SplitHostPort(Ipv6HostPort)
		expDstIp := net.IP(net.ParseIP(host))
		ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+40])
		dstIp := net.IP(ipv6.DstIP())
		if !expDstIp.Equal(dstIp) {
			o.stats.pktRxBadDstIp++
			return core.PARSER_ERR
		}
	} else {
		host, _, _ := net.SplitHostPort(Ipv4HostPort)
		expDstIp := net.IP(net.ParseIP(host))
		ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])
		var dstIp core.Ipv4Key
		dstIp.SetUint32(ipv4.GetIPDst())
		if !expDstIp.Equal(dstIp.ToIP()) {
			o.stats.pktRxBadDstIp++
			return core.PARSER_ERR
		}
	}
	var udp layers.UDP
	err := udp.DecodeFromBytes(p[ps.L4:ps.L4+8], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	var dns layers.DNS
	err = dns.DecodeFromBytes(p[ps.L7:ps.L7+ps.L7Len], o)
	if err != nil {
		o.stats.pktRxErrTooShort++
		return core.PARSER_ERR
	}

	if dns.QDCount > 0 {
		o.stats.rxQuestions += uint64(dns.QDCount)
		o.HandleRxMDnsQuestions(dns.ID, dns.Questions, ipv6)
	}
	if dns.ANCount > 0 {
		o.stats.rxAnswers += uint64(dns.ANCount)
		o.HandleRxMDnsAnswers(dns.Answers)
	}
	if dns.NSCount > 0 {
		o.stats.rxAuthoritiesUnhandled += uint64(dns.NSCount)
	}
	if dns.ARCount > 0 {
		o.stats.rxAddRecordsUnhandled += uint64(dns.ARCount)
	}

	return 0
}

// SetTruncated to complete the gopacket.DecodeFeedback interface.
func (o *PluginMDnsNs) SetTruncated() {}

// GetResolved returns the resolved DNS entries.
func (o *PluginMDnsNs) GetResolved() (resolved []*MDnsCacheEntry) {
	for _, entry := range o.cache.tbl {
		resolved = append(resolved, entry)
	}
	return resolved
}

// RegisterHosts registers the hosts of a client. If host is already registered, we ignore.
// Returns hosts successfully registered
func (o *PluginMDnsNs) RegisterClientHosts(hosts []string, c *PluginMDnsClient) []string {
	var newHosts []string
	for _, host := range hosts {
		_, ok := o.mapHostClient[host]
		if !ok {
			newHosts = append(newHosts, host)
			o.mapHostClient[host] = c
		}
	}
	return newHosts
}

// UnregisterHosts removes hosts from the map.
func (o *PluginMDnsNs) UnregisterHosts(hosts []string) {
	for _, host := range hosts {
		delete(o.mapHostClient, host) // deleting a non existing entry is a no op
	}
}

// GetClientByHost returns the client owning the hostname if such one exits. If not, it will return an error.
func (o *PluginMDnsNs) GetClientByHost(host string) (*PluginMDnsClient, error) {
	c, ok := o.mapHostClient[host]
	if !ok {
		return nil, fmt.Errorf("No client found for host %v", host)
	}
	return c, nil
}

/*======================================================================================================
												Rx
======================================================================================================*/
// HandleRxMDnsPacket handles an incoming mDns packet by redirecting to the relevant namespace.
func HandleRxMDnsPacket(ps *core.ParserPacketState) int {
	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(MDNS_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	mdnsPlug := nsplg.Ext.(*PluginMDnsNs)
	return mdnsPlug.HandleRxMDnsPacket(ps)
}

/*======================================================================================================
											Generate Plugin
======================================================================================================*/
type PluginMDnsCReg struct{}
type PluginMDnsNsReg struct{}

// NewPlugin creates a new MDNsClient plugin.
func (o PluginMDnsCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewMDnsClient(ctx, initJson)
}

// NewPlugin creates a new MDnsNs plugin.
func (o PluginMDnsNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewMDnsNs(ctx, initJson)
}

/*======================================================================================================
											RPC Methods
======================================================================================================*/

// DnsQueryParams defines the fields in an DNS query as received in RPC.
type DnsQueryParams struct {
	Name  string `json:"name" validate=required` // Name of query
	Type  string `json:"dns_type"`               // Type of the query
	Class string `json:"dns_class"`              // Class of the query
	Ipv6  bool   `json:"ipv6"`                   // Ipv6 query
}

type (
	ApiMDnsClientCntHandler struct{} // Counter RPC Handler per Client
	ApiMDnsNsCntHandler     struct{} // Counter RPC Handler per Ns
	ApiMDnsQueryHandler     struct{} // Query RPC Handler
	ApiMDnsQueryParams      struct {
		Queries []DnsQueryParams `json:"queries" validate=required,dive`
	}
	ApiMDnsAddRemoveHostsHandler struct{} // Add/Remove hosts handler.
	ApiMDnsAddRemoveHostsParams  struct {
		Op    bool     `json:"op"`    // false for add, true for remove
		Hosts []string `json:"hosts"` // hosts to add/remove
	}
	ApiMDnsGetHostsHandler    struct{} // Get Hosts of a client
	ApiMDnsGetResolvedHandler struct{} // GetEntries RPC Handler
)

// getClientPlugin gets the client plugin given the client parameters (Mac & Tunnel Key)
func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginMDnsClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, MDNS_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginMDnsClient)

	return pClient, nil
}

// getClientPlugin gets the namespace plugin given the namespace parameters (Tunnel Key)
func getNsPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginMDnsNs, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetNsPlugin(params, MDNS_PLUG)

	if err != nil {
		return nil, err
	}

	mDnsNs := plug.Ext.(*PluginMDnsNs)
	return mDnsNs, nil
}

// ApiMDnsClientCntHandler gets the counters of the mDNS Client.
func (h ApiMDnsClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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

// ApiMDnsNsCntHandler gets the counters of the mDNS namespace.
func (h ApiMDnsNsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	nsPlug, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return nsPlug.cdbv.GeneralCounters(err, tctx, params, &p)
}

// ApiMDnsQueryHandler handles the RPC query request.
func (h ApiMDnsQueryHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	var p ApiMDnsQueryParams
	tctx := ctx.(*core.CThreadCtx)
	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err = c.Query(p.Queries)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidParams,
			Message: err.Error(),
		}
	}

	return nil, nil
}

// ApiMDnsAddRemoveHostsHandler handles the RPC add or remove hosts request.
func (h ApiMDnsAddRemoveHostsHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	var p ApiMDnsAddRemoveHostsParams
	tctx := ctx.(*core.CThreadCtx)
	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	if p.Op == false {
		alreadyExistingHosts := c.AddHosts(p.Hosts)
		return alreadyExistingHosts, nil
	} else {
		nonExistingHosts := c.RemoveHosts(p.Hosts)
		return nonExistingHosts, nil
	}
}

// ApiMDnsGetHostsHandler handles the RPC add or remove hosts request.
func (h ApiMDnsGetHostsHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	return c.GetHosts(), nil
}

// ApiMDnsGetEntriesHandler handles the RPC get entries request.
func (h ApiMDnsGetResolvedHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	ns, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	res := ns.GetResolved()
	return res, nil
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(MDNS_PLUG,
		core.PluginRegisterData{Client: PluginMDnsCReg{},
			Ns:     PluginMDnsNsReg{},
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

	core.RegisterCB("mdns_c_cnt", ApiMDnsClientCntHandler{}, true)                    // get counters / meta per client
	core.RegisterCB("mdns_c_add_remove_hosts", ApiMDnsAddRemoveHostsHandler{}, false) // add or remove hosts from client
	core.RegisterCB("mdns_c_get_hosts", ApiMDnsGetHostsHandler{}, false)              // show the hosts of a client
	core.RegisterCB("mdns_c_query", ApiMDnsQueryHandler{}, false)                     // query
	core.RegisterCB("mdns_ns_cnt", ApiMDnsNsCntHandler{}, true)                       // get counters / meta per ns
	core.RegisterCB("mdns_ns_get_resolved", ApiMDnsGetResolvedHandler{}, false)       // get resolved entries

	/* register callback for rx side*/
	core.ParserRegister(MDNS_PLUG, HandleRxMDnsPacket)
}

func Register(ctx *core.CThreadCtx) {
	// In order for this plugin to be included in the EMU compilation one must provide this empty register
	// function. In case you remove the function call, then the core will not include EMU.
	ctx.RegisterParserCb(MDNS_PLUG)
}
