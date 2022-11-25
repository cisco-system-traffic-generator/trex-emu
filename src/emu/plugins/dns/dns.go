/*
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

package dns

import (
	"emu/core"
	utils "emu/plugins/dns_utils"
	"emu/plugins/transport"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"net"

	"github.com/intel-go/fastjson"
)

/*
DNS - Domain Name System - https://en.wikipedia.org/wiki/Domain_Name_System

Implementation based on RFCs 1034,1035 - https://datatracker.ietf.org/doc/html/rfc1035

This is a simplified version of DNS that supports only the following architecture:

    +---------+               +----------+               +--------+
    |         | user queries  |          |    query      |        |
    |  User   |-------------->|          |-------------->|  Name  |
    | Program |               | Resolver |               | Server |
    |         |<--------------|          |<--------------|        |
    |         | user responses|          |   response    |        |
    +---------+               +----------+               +--------+
                                |     A
                cache additions |     | references
                                V     |
                              +----------+
                              |  cache   |
                              +----------+

- User program represents a EMU client through API to console (Python Client)
- The resolver is the client itself (CClient)
	- The resolver can query and holds a cache.
- The name server is another client (CClient) that holds the DNS entries.
	- The name server can reply and it maintains a database of DNS entries
	- The database of the name server is loaded on initialization.

Supported types of queries:
	- A
	- AAAA
	- PTR
	- TXT
*/

const (
	DNS_PLUG              = "dns" // Plugin name
	DnsPort               = "53"  // Dns Port
	DefaultDnsResponseTTL = 240   // Default TTL value
)

type DnsClientStats struct {
	invalidInitJson     uint64 // Error while decoding client init Json
	invalidSocket       uint64 // Error while creating socket
	socketWriteError    uint64 // Error while writing on a socket
	socketCloseError    uint64 // Error while closing a socket
	pktRxDecodeError    uint64 // Num of invalid Dns received packets
	invalidIpInDb       uint64 // Invalid Ip found in Database
	txBytes             uint64 // Number of bytes transmitted
	rxBytes             uint64 // Number of bytes received
	rxQuestions         uint64 // Number of questions received
	rxQuestionsNxDomain uint64 // Number of questions with non existant domains.
	dnsFlowAccept       uint64 // Number of Dns flows accepted
	pktTxDnsQuery       uint64 // Num of Dns queries transmitted
	pktRxDnsQuery       uint64 // Num of Dns queries received
	pktTxDnsResponse    uint64 // Num of Dns responses transmitted
	pktRxDnsResponse    uint64 // Num of Dns responses received
	unsupportedDnsType  uint64 // Num of queries received with an unsupported type

}

// NewDnsClientStatsDb creates a new database of Dns counters.
func NewDnsClientStatsDb(o *DnsClientStats) *core.CCounterDb {
	db := core.NewCCounterDb(DNS_PLUG)

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
		Counter:  &o.socketCloseError,
		Name:     "socketCloseError",
		Help:     "Error closing socket",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxDecodeError,
		Name:     "pktRxDecodeError",
		Help:     "Num of invalid Dns packets received",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidIpInDb,
		Name:     "invalidIpInDb",
		Help:     "Invalid Ip found in Name Server Database.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.txBytes,
		Name:     "txBytes",
		Help:     "Number of bytes transmitted",
		Unit:     "bytes",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxBytes,
		Name:     "rxBytes",
		Help:     "Number of bytes received",
		Unit:     "bytes",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxQuestions,
		Name:     "rxQuestions",
		Help:     "Number of questions received",
		Unit:     "ops",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.rxQuestionsNxDomain,
		Name:     "rxQuestionsNxDomain",
		Help:     "Number of questions received with non existant domains",
		Unit:     "ops",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.dnsFlowAccept,
		Name:     "dnsFlowAccept",
		Help:     "Number of Dns flows accepted. Each request is a new flow.",
		Unit:     "ops",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxDnsQuery,
		Name:     "pktTxDnsQuery",
		Help:     "Num of Dns queries transmitted",
		Unit:     "pkts",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxDnsQuery,
		Name:     "pktRxDnsQuery",
		Help:     "Num of Dns queries received",
		Unit:     "pkts",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxDnsResponse,
		Name:     "pktTxDnsResponse",
		Help:     "Num of Dns responses transmitted",
		Unit:     "pkts",
		DumpZero: true,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxDnsResponse,
		Name:     "pktRxDnsResponse",
		Help:     "Num of Dns responses received",
		Unit:     "pkts",
		DumpZero: true,
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

// DnsNsStats defines a number of stats for an Dns namespace.
type DnsNsStats struct {
	invalidInitJson        uint64 // Error while decoding namespace init Json
	autoPlayClientNotFound uint64 // Auto Play client was not found
	clientNoDns            uint64 // Auto Play client doesn't have Dns plugin
	autoPlayQueries        uint64 // Number of queries sent by Auto Play
	autoPlayBadQuery       uint64 // Number of bad queries created by Auto Play
}

// NewDnsNsStatsDb creates a new counter database for DnsNsStats.
func NewDnsNsStatsDb(o *DnsNsStats) *core.CCounterDb {
	db := core.NewCCounterDb(DNS_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidInitJson,
		Name:     "invalidInitJson",
		Help:     "Error while decoding init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.autoPlayClientNotFound,
		Name:     "autoPlayClientNotFound",
		Help:     "AutoPlay client was not found",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.clientNoDns,
		Name:     "clientNoDns",
		Help:     "AutoPlay client doesn't have Dns plugin",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.autoPlayQueries,
		Name:     "autoPlayQueries",
		Help:     "Number of queries sent by Auto Play",
		Unit:     "query",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.autoPlayBadQuery,
		Name:     "autoPlayBadQuery",
		Help:     "Number of bad queries created by Auto Play",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	return db
}

// dnsEvents holds a list of events on which the Dns plugin is interested.
var dnsEvents = []string{}

/*======================================================================================================
											Dns Client
======================================================================================================*/

// DnsEntry represents a Dns entry in the database of the name server.
type DnsEntry struct {
	DnsType  string `json:"type"`   // Dns Type. Defaults to DefaultDnsQueryType.
	DnsClass string `json:"class"`  // Dns Class. Defaults DefaultDnsQueryClass.
	Answer   string `json:"answer"` // Answer for this Dns Entry.
}

// DnsDatabase represents the database of the name server. Each key is a domain that can be queried.
// Each domain can be mapped to multiple entries.
type DnsDatabase map[string][]DnsEntry

// DnsClientParams holds the Init JSON for a Dns Client/Server.
type DnsClientParams struct {
	DnsServerIP string               `json:"dns_server_ip"` // DnsServerIP is the Dns IP for this resolver.
	NameServer  bool                 `json:"name_server"`   // Is this client a name server? Defaults to False.
	Database    *fastjson.RawMessage `json:"database"`      // Database of the name server.
}

// PluginDnsClient represents a DNS client
type PluginDnsClient struct {
	core.PluginBase                      // Plugin Base embedded struct so we get all the base functionality
	params          DnsClientParams      // Init Json params
	stats           DnsClientStats       // DNS Client Stats
	db              DnsDatabase          // Dns Name Server Database
	dstAddr         string               // Destination Address for Dns Server
	cdb             *core.CCounterDb     // Counters database
	cdbv            *core.CCounterDbVec  // Counters database vector
	socket          transport.SocketApi  // Socket Api (both IPv4 and IPv6)
	cache           *utils.DnsCache      // Dns cache
	dnsPktBuilder   *utils.DnsPktBuilder // Dns Packet Builder
}

// NewDnsClient creates a new Dns client.
func NewDnsClient(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginDnsClient)
	o.InitPluginBase(ctx, o)              // Init base object
	o.RegisterEvents(ctx, dnsEvents, o)   // Register events
	o.cdb = NewDnsClientStatsDb(&o.stats) // Register Stats immediately so we can fail safely.
	o.cdbv = core.NewCCounterDbVec(DNS_PLUG)
	o.cdbv.Add(o.cdb)

	err := o.Tctx.UnmarshalValidate(initJson, &o.params)
	if err != nil {
		o.stats.invalidInitJson++
		return nil, err
	}

	if o.IsNameServer() {
		err = fastjson.Unmarshal(*o.params.Database, &o.db)
		if err != nil {
			o.stats.invalidInitJson++
			return nil, err
		}
	} else {
		dnsServer := net.ParseIP(o.params.DnsServerIP)
		if dnsServer == nil {
			o.stats.invalidInitJson++
			return nil, fmt.Errorf("invalid DNS server IP %s", o.params.DnsServerIP)
		}
		if dnsServer.To4() == nil {
			// Specified Ipv6 Dns server
			_, err = o.Client.GetSourceIPv6()
			if err != nil {
				// Client has no IPv6 address.
				o.stats.invalidInitJson++
				return nil, fmt.Errorf("invalid DNS server IP %s", o.params.DnsServerIP)
			}
		}
		o.dstAddr = net.JoinHostPort(dnsServer.String(), DnsPort)
	}

	err = o.OnCreate()
	if err != nil {
		return nil, err
	}

	return &o.PluginBase, nil
}

// OnCreate is called upon creating a new Dns client.
func (o *PluginDnsClient) OnCreate() (err error) {

	o.dnsPktBuilder = utils.NewDnsPktBuilder(false) // Create a packet builder for Dns

	if !o.IsNameServer() {
		o.cache = utils.NewDnsCache(o.Tctx.GetTimerCtx()) // Create cache
	}

	// Create socket
	transportCtx := transport.GetTransportCtx(o.Client)
	if transportCtx != nil {
		if o.IsNameServer() {
			err = transportCtx.Listen("udp", ":53", o)
			if err != nil {
				o.stats.invalidSocket++
				return fmt.Errorf("could not create listening socket: %w", err)
			}
		} else {
			o.socket, err = transportCtx.Dial("udp", o.dstAddr, o, nil, nil, 0)
			if err != nil {
				o.stats.invalidSocket++
				return fmt.Errorf("could not create dialing socket: %w", err)
			}
		}
	}
	return nil
}

// OnAccept is called when a new flow is received. This completed the IServerSocketCb interface.
func (o *PluginDnsClient) OnAccept(socket transport.SocketApi) transport.ISocketCb {
	if !o.IsNameServer() {
		return nil
	}
	o.stats.dnsFlowAccept++ // New flow for the Name Server.
	o.socket = socket       // Store socket so we can reply.
	return o
}

// OnEvent callback of the Dns client in case of events.
func (o *PluginDnsClient) OnEvent(msg string, a, b interface{}) {}

// OnRemove is called when we remove the Dns client.
func (o *PluginDnsClient) OnRemove(ctx *core.PluginCtx) {
	ctx.UnregisterEvents(&o.PluginBase, dnsEvents)
	if o.IsNameServer() {
		transportCtx := transport.GetTransportCtx(o.Client)
		if transportCtx != nil {
			transportCtx.UnListen("udp", ":53", o)
		}
	} else {
		if o.cache != nil {
			_ = utils.NewDnsCacheRemover(o.cache, ctx.Tctx.GetTimerCtx())
			o.cache = nil // GC can remove the client while the cache is removed.
		}
	}
}

// OnRxEvent function to complete the ISocketCb interface.
func (o *PluginDnsClient) OnRxEvent(event transport.SocketEventType) {}

// OnRxData is called when rx data is received for the client.
func (o *PluginDnsClient) OnRxData(d []byte) {
	formatError := false
	o.stats.rxBytes += uint64(len(d))
	var dns layers.DNS
	err := dns.DecodeFromBytes(d, o)
	if err != nil {
		o.stats.pktRxDecodeError++
		formatError = true
	}

	if o.IsNameServer() {
		if formatError {
			// Reply with format error
			o.Reply(0, []layers.DNSQuestion{}, o.socket)
			return // Done. Can't proceed!
		}
		if dns.QR != false {
			// Response received in name server! Nothing to do.
			o.stats.pktRxDnsResponse++
		} else {
			// Query received in name server!
			o.stats.pktRxDnsQuery++
			if dns.QDCount > 0 {
				o.stats.rxQuestions += uint64(dns.QDCount)
				o.Reply(dns.ID, dns.Questions, o.socket)
			}
		}
	} else {
		if formatError {
			// Nothing to do on client!
			return
		}
		if dns.QR == false {
			// Query received in simple client! Nothing to do.
			o.stats.pktRxDnsQuery++
		} else {
			// Response received in simple client! Cache it.
			o.stats.pktRxDnsResponse++
			if dns.ResponseCode == layers.DNSResponseCodeNoErr && dns.ANCount > 0 {
				utils.AddAnswersToCache(o.cache, dns.Answers)
			}
		}
	}
}

// SetTruncated to complete the gopacket.DecodeFeedback interface.
func (o *PluginDnsClient) SetTruncated() {}

// OnTxEvent function to complete the ISocketCb interface.
func (o *PluginDnsClient) OnTxEvent(event transport.SocketEventType) { /* No Tx event expected */ }

// IsNameServer indicates if a PluginDnsClient is serving as a NameServer?
// This will probably be inlined so no worries of performance overhead.
func (o *PluginDnsClient) IsNameServer() bool { return o.params.NameServer }

// Query queries the Dns Server.
func (o *PluginDnsClient) Query(queries []utils.DnsQueryParams, socket transport.SocketApi) error {
	if o.IsNameServer() {
		return fmt.Errorf("Querying is not permitted for Dns Name Servers!")
	}
	questions, err := utils.BuildQuestions(queries)
	if err != nil {
		return err
	}

	if len(questions) > 0 {
		data := o.dnsPktBuilder.BuildQueryPkt(questions, o.Tctx.Simulation)
		if socket == nil {
			return fmt.Errorf("Invalid Socket in Query!")
		}
		transportErr, _ := o.socket.Write(data)
		if transportErr != transport.SeOK {
			o.stats.socketWriteError++
			return transportErr.Error()
		}
		o.stats.pktTxDnsQuery++              // successfully sent query
		o.stats.txBytes += uint64(len(data)) // number of bytes sent
	}
	return nil
}

// isValidAnswer receives a Query Type and Class, and a DnsEntry of the database. It concludes if this
// entry is a valid answer in terms of Type and Class.
func (o *PluginDnsClient) isValidAnswer(entry DnsEntry, qType layers.DNSType, qClass layers.DNSClass) bool {
	// Dns Types must equal. Dns Class should equal in case it isn't Any.
	return (entry.DnsType == qType.String()) && (entry.DnsClass == qClass.String() || qClass == layers.DNSClassAny)
}

// BuildAnswers builds answers based on Dns questions
func (o *PluginDnsClient) BuildAnswers(questions []layers.DNSQuestion) (answers []layers.DNSResourceRecord) {

	for _, q := range questions {
		domainEntries, ok := o.db[string(q.Name)]
		if !ok {
			o.stats.rxQuestionsNxDomain++
			continue
		}

		foundAnswer := false

		for i := range domainEntries {
			if o.isValidAnswer(domainEntries[i], q.Type, q.Class) {
				foundAnswer = true
				class, _ := layers.StringToDNSClass(domainEntries[i].DnsClass)
				answer := layers.DNSResourceRecord{
					Name:  []byte(q.Name),
					Type:  q.Type,
					Class: class,
					TTL:   DefaultDnsResponseTTL,
				}

				switch answer.Type {
				case layers.DNSTypeA, layers.DNSTypeAAAA:
					ip := net.ParseIP(domainEntries[i].Answer)
					if ip != nil {
						answer.IP = ip
					} else {
						o.stats.invalidIpInDb++
						continue // skip the ones we can't answer
					}
				case layers.DNSTypePTR:
					answer.PTR = []byte(domainEntries[i].Answer)
				case layers.DNSTypeTXT:
					answer.TXTs = utils.BuildTxtsFromString(domainEntries[i].Answer)
				default:
					o.stats.unsupportedDnsType++
					continue // skip the ones we can't answer
				}
				answers = append(answers, answer)
			}
		}
		if !foundAnswer {
			o.stats.rxQuestionsNxDomain++
		}
	}
	return answers
}

// Replies replies to questions in a NameServer.
func (o *PluginDnsClient) Reply(transactionId uint16, questions []layers.DNSQuestion, socket transport.SocketApi) error {

	if !o.IsNameServer() {
		return fmt.Errorf("Only Name Servers can reply!")
	}

	if socket == nil {
		return fmt.Errorf("Invalid Socket in Reply!")
	}

	respCode := layers.DNSResponseCodeNoErr // We start with no problems.

	answers := []layers.DNSResourceRecord{}
	if len(questions) > 0 {
		answers = o.BuildAnswers(questions)
		if len(answers) == 0 {
			respCode = layers.DNSResponseCodeNXDomain
		}
	} else {
		respCode = layers.DNSResponseCodeFormErr
	}

	data := o.dnsPktBuilder.BuildResponsePkt(transactionId, answers, questions, respCode)
	transportErr, _ := socket.Write(data)
	if transportErr != transport.SeOK {
		o.stats.socketWriteError++
		return transportErr.Error()
	}

	o.stats.pktTxDnsResponse++ // Response sent
	o.stats.txBytes += uint64(len(data))

	transportErr = socket.Close() // Close socket after each response, because we don't keep a flow table.
	if transportErr != transport.SeOK {
		o.stats.socketCloseError++
		return transportErr.Error()
	}
	return nil
}

// AddDomainEntries adds entries to the Dns Name Server database.
func (o *PluginDnsClient) AddDomainEntries(domain string, newEntries []DnsEntry) error {
	if !o.IsNameServer() {
		return fmt.Errorf("This operation is permitted for Dns Name Servers only!")
	}
	entries, ok := o.db[domain]
	if ok {
		// This domain already exists.
		// Let's convert the entries into a set for fast lookup.
		// Since the DnsEntry is a trivial structure the autogenerated hash and equals function work.
		entriesSet := make(map[DnsEntry]bool)
		for _, entry := range entries {
			entriesSet[entry] = true
		}
		for _, entry := range newEntries {
			if entriesSet[entry] {
				// Entry already exists.
				continue
			} else {
				entries = append(entries, entry)
				entriesSet[entry] = true // malicious user can provide twice the same entry in newEntries
			}
		}
		o.db[domain] = entries
	} else {
		// The domain doesn't exist.
		o.db[domain] = newEntries
	}
	return nil
}

// RemoveDomainEntries removes entries from the Dns Name Server database.
func (o *PluginDnsClient) RemoveDomainEntries(domain string, entriesToRemove []DnsEntry) error {
	if !o.IsNameServer() {
		return fmt.Errorf("This operation is permitted for Dns Name Servers only!")
	}

	entriesToRemoveSet := make(map[DnsEntry]bool)
	for _, entry := range entriesToRemove {
		entriesToRemoveSet[entry] = true
	}

	var validEntries []DnsEntry
	entries, ok := o.db[domain]
	if ok {
		// Domain exists
		for _, entry := range entries {
			if _, ok := entriesToRemoveSet[entry]; !ok {
				// Entry is not in entries to remove.
				validEntries = append(validEntries, entry)
			}
		}
		if len(validEntries) > 0 {
			o.db[domain] = validEntries
		} else {
			delete(o.db, domain)
		}
	}
	// Domain doesn't exist or entry removed.
	return nil
}

// GetDomainEntries returns the entries of a domain from a Dns Name Server.
func (o *PluginDnsClient) GetDomainEntries(domain string) ([]DnsEntry, error) {
	if !o.IsNameServer() {
		return nil, fmt.Errorf("This operation is permitted for Dns Name Servers only!")
	}
	entries, ok := o.db[domain]
	if !ok {
		return nil, fmt.Errorf("Domain %v not in database!", domain)
	}
	return entries, nil
}

// GetDomains returns the domains from a Dns Name Server.
func (o *PluginDnsClient) GetDomains() ([]string, error) {
	if !o.IsNameServer() {
		return nil, fmt.Errorf("This operation is permitted for Dns Name Servers only!")
	}
	domains := make([]string, 0, len(o.db))
	for domain := range o.db {
		domains = append(domains, domain)
	}
	return domains, nil
}

/*======================================================================================================
										Ns Dns plugin
======================================================================================================*/

// DnsAutoPlayParams represents the auto play params for DNS namespace.
type DnsAutoPlayParams struct {
	utils.CommonDnsAutoPlayParams                               // Embed the base parameters
	Program                       map[string]utils.ProgramEntry `json:"program" validate:"dive"` // Program for specific clients with specific queries
}

// DnsNsParams defines the InitJson params for Dns namespaces.
type DnsNsParams struct {
	AutoPlay       bool                 `json:"auto_play"`        // Should autoplay the program
	AutoPlayParams *fastjson.RawMessage `json:"auto_play_params"` // Params for autoplay
}

type PluginDnsNs struct {
	core.PluginBase                      // Embed plugin base
	params          DnsNsParams          // Namespace Paramaters
	autoPlayParams  DnsAutoPlayParams    // Dns Auto Play Params in case they are provided
	stats           DnsNsStats           // Dns namespace statistics
	cdb             *core.CCounterDb     // Dns counters
	cdbv            *core.CCounterDbVec  // Dns counter vector
	autoPlay        *utils.DnsNsAutoPlay // DNS program autoplay
}

// NewDnsNs creates a new DNS namespace plugin.
func NewDnsNs(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginDnsNs)
	o.InitPluginBase(ctx, o)             // Init the base plugin
	o.RegisterEvents(ctx, []string{}, o) // No events to register in namespace level.
	o.cdb = NewDnsNsStatsDb(&o.stats)    // Create new stats database
	o.cdbv = core.NewCCounterDbVec(DNS_PLUG)
	o.cdbv.Add(o.cdb)

	err := o.Tctx.UnmarshalValidate(initJson, &o.params)
	if err != nil {
		o.stats.invalidInitJson++
		return nil, err
	}
	if o.params.AutoPlay {
		// Set default values prior to unmarshal.
		o.autoPlayParams.Rate = utils.DefaultAutoPlayRate
		o.autoPlayParams.ClientStep = utils.DefaultClientStep
		o.autoPlayParams.HostnameStep = utils.DefaultHostnameStep
		err = o.Tctx.UnmarshalValidate(*o.params.AutoPlayParams, &o.autoPlayParams)
		if err != nil {
			o.stats.invalidInitJson++
			return nil, err
		}
		// Create a new DnsNsAutoPlay which will call SendQuery each time we need to send a query.
		o.autoPlay, err = utils.NewDnsNsAutoPlay(o, o.Tctx.GetTimerCtx(), o.autoPlayParams.CommonDnsAutoPlayParams)
		if err != nil {
			o.stats.invalidInitJson++
			return nil, fmt.Errorf("could not create DNS autoplay, error: %w", err)
		}
	}

	return &o.PluginBase, nil
}

// buildQueries builds the query parameters based on the user specified program.
func (o *PluginDnsNs) buildQueries(hostnames []string, dnsType string, dnsClass string) []utils.DnsQueryParams {
	var dnsQueryParams []utils.DnsQueryParams
	for _, hostname := range hostnames {
		if dnsType == "" {
			dnsType = utils.DefaultDnsQueryType
		}
		if dnsClass == "" {
			dnsClass = utils.DefaultDnsQueryClass
		}
		dnsQueryParams = append(dnsQueryParams, utils.DnsQueryParams{Name: hostname, Type: dnsType, Class: dnsClass})
	}
	return dnsQueryParams
}

// getClientQueries returns the queries that this client will ask. It will look in the program to see if this client
// has defined special queries or return the default query.
func (o *PluginDnsNs) getClientQueries(mac *core.MACKey, hostname string) []utils.DnsQueryParams {
	var hwAddr net.HardwareAddr
	hwAddr = mac[:]
	macString := hwAddr.String()
	program, ok := o.autoPlayParams.Program[macString]
	if ok {
		return o.buildQueries(program.Hostnames, program.DnsType, program.DnsClass)
	} else {
		hostnames := []string{hostname}
		return o.buildQueries(hostnames, o.autoPlayParams.DnsType, o.autoPlayParams.DnsClass)
	}
}

// SendQuery sends an DNS query to domain with the client whose mac is provided.
// Returns if we should continue sending queries.
// In case the client is not found, it will not send a query but indicate that we should continue.
// In case the client is found but has no DNS plugin, it will stop the auto play.
func (o *PluginDnsNs) SendQuery(mac *core.MACKey, domain string) bool {

	client := o.Ns.GetClient(mac)

	if client == nil {
		// No such client ...
		o.stats.autoPlayClientNotFound++
		return true // Restart, next one can be ok
	}

	plug := client.PluginCtx.Get(DNS_PLUG)
	if plug == nil {
		// given client doesn't have Dns
		o.stats.clientNoDns++
		return false // Don't restart timer, stop!
	}

	dnsPlug := plug.Ext.(*PluginDnsClient)

	queries := o.getClientQueries(mac, domain)

	err := dnsPlug.Query(queries, dnsPlug.socket)
	if err != nil {
		// Couldn't query properly
		o.stats.autoPlayBadQuery++
	} else {
		o.stats.autoPlayQueries++ // one more auto play query sent
	}
	// If the query amount is not reached, we can restart the timer.
	infiniteQueries := (o.autoPlayParams.QueryAmount == 0)
	return o.stats.autoPlayQueries < o.autoPlayParams.QueryAmount || infiniteQueries
}

// OnRemove when removing Dns namespace plugin.
func (o *PluginDnsNs) OnRemove(ctx *core.PluginCtx) {
	// Remove AutoPlay first
	if o.autoPlay != nil {
		o.autoPlay.OnRemove()
	}
}

// OnEvent for events the namespace plugin is registered.
func (o *PluginDnsNs) OnEvent(msg string, a, b interface{}) {}

/*
======================================================================================================

	Generate Plugin

======================================================================================================
*/
type PluginDnsCReg struct{}
type PluginDnsNsReg struct{}

// NewPlugin creates a new DnsClient plugin.
func (o PluginDnsCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewDnsClient(ctx, initJson)
}

// NewPlugin creates a new DnsNs plugin.
func (o PluginDnsNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewDnsNs(ctx, initJson)
}

/*======================================================================================================
											RPC Methods
======================================================================================================*/

type (
	ApiDnsClientCntHandler struct{} // Counter RPC Handler per Client
	ApiDnsQueryParams      struct {
		Queries []utils.DnsQueryParams `json:"queries" validate:"required,dive"`
	}
	ApiDnsAddRemoveDomainEntriesHandler struct{} // Add/Remove domain entries handler.
	ApiDnsAddRemoveDomainEntriesParams  struct {
		Op      bool       `json:"op"`      // False for add, True for remove
		Domain  string     `json:"domain"`  // Domain to whom we are trying to add/remove.
		Entries []DnsEntry `json:"entries"` // Domain entries to add/remove to domain
	}
	ApiDnsGetDomainEntriesParams struct {
		Domain string `json:"domain"` // Domain who entries to get
	}
	ApiDnsGetDomainEntriesHandler struct{} // Handler for Get Domain Entries
	ApiDnsGetDomainsHandler       struct{} // Get Domains of a Dns Name Server.
	ApiDnsQueryHandler            struct{} // Query RPC Handler
	ApiDnsCacheIterParams         struct {
		Reset bool   `json:"reset"`
		Count uint16 `json:"count" validate:"required,gte=0,lte=255"`
	} // Params for a client cache iteration
	ApiDnsCacheIterHandler struct{} // Iterate client cache
	ApiDnsCacheIterResults struct {
		Empty   bool                   `json:"empty"`
		Stopped bool                   `json:"stopped"`
		Vec     []*utils.DnsCacheEntry `json:"data"`
	} // Results for a client cache iteration
	ApiDnsCacheFlushHandler struct{} // Flush the Dns cache
	ApiDnsNsCntHandler      struct{} // Counter RPC Handler for Namespace
)

// getClientPlugin gets the client plugin given the client parameters (Mac & Tunnel Key)
func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginDnsClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, DNS_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginDnsClient)

	return pClient, nil
}

// getNsPlugin gets the namespace plugin given the namespace parameters (Tunnel Key)
func getNsPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginDnsNs, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetNsPlugin(params, DNS_PLUG)

	if err != nil {
		return nil, err
	}

	dnsNs := plug.Ext.(*PluginDnsNs)
	return dnsNs, nil
}

// ApiDnsClientCntHandler gets the counters of the Dns Client.
func (h ApiDnsClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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

// ApiDnsAddRemoveDomainEntriesHandler handles the RPC request to add or remove entries from a domain in a Name Server.
func (h ApiDnsAddRemoveDomainEntriesHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	var p ApiDnsAddRemoveDomainEntriesParams
	tctx := ctx.(*core.CThreadCtx)
	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	if p.Op == false {
		err = c.AddDomainEntries(p.Domain, p.Entries)
	} else {
		err = c.RemoveDomainEntries(p.Domain, p.Entries)
	}

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return nil, nil
}

// ApiDnsGetDomainEntriesHandler handles the RPC request to get the entries of a domain in a Name Server.
func (h ApiDnsGetDomainEntriesHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	var p ApiDnsGetDomainEntriesParams
	tctx := ctx.(*core.CThreadCtx)
	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	entries, err := c.GetDomainEntries(p.Domain)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return entries, nil
}

// ApiDnsGetDomainsHandler handles the RPC request to get the domains of a Name Server.
func (h ApiDnsGetDomainsHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	entries, err := c.GetDomains()
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return entries, nil
}

// ApiDnsQueryHandler handles the RPC query request.
func (h ApiDnsQueryHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	var p ApiDnsQueryParams
	tctx := ctx.(*core.CThreadCtx)
	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	err = c.Query(p.Queries, c.socket)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidParams,
			Message: err.Error(),
		}
	}

	return nil, nil
}

// ApiDnsCacheIterHandler handles the client cache iteration.
func (h ApiDnsCacheIterHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p ApiDnsCacheIterParams
	var res ApiDnsCacheIterResults
	tctx := ctx.(*core.CThreadCtx)

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	if c.IsNameServer() {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "This operation is permitted only in non Name Servers.",
		}
	}

	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	if p.Reset {
		res.Empty = c.cache.IterReset()
	}
	if res.Empty {
		return &res, nil
	}

	if c.cache.IterIsStopped() {
		res.Stopped = true
		return &res, nil
	}
	keys, err := c.cache.GetNext(int(p.Count))
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	res.Vec = keys
	return &res, nil
}

// ApiDnsCacheFlushHandler flushes the Dns Cache.
func (h ApiDnsCacheFlushHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	if c.IsNameServer() {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: "This operation is permitted only in non Name Servers.",
		}
	}

	c.cache.Flush()
	return nil, nil
}

// ApiDnsNsCntHandler gets the counters of the DNS namespace.
func (h ApiDnsNsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(DNS_PLUG,
		core.PluginRegisterData{Client: PluginDnsCReg{},
			Ns:     PluginDnsNsReg{},
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

	core.RegisterCB("dns_c_cnt", ApiDnsClientCntHandler{}, true)                                     // get counters / meta per client
	core.RegisterCB("dns_c_add_remove_domain_entries", ApiDnsAddRemoveDomainEntriesHandler{}, false) // add or remove entries from a domain in a name server
	core.RegisterCB("dns_c_get_domain_entries", ApiDnsGetDomainEntriesHandler{}, false)              // get entries of a domain in a name server
	core.RegisterCB("dns_c_get_domains", ApiDnsGetDomainsHandler{}, false)                           // get domains of name server
	core.RegisterCB("dns_c_query", ApiDnsQueryHandler{}, false)                                      // query
	core.RegisterCB("dns_c_cache_iter", ApiDnsCacheIterHandler{}, false)                             // iterate client cache
	core.RegisterCB("dns_c_cache_flush", ApiDnsCacheFlushHandler{}, false)                           // flush the cache
	core.RegisterCB("dns_ns_cnt", ApiDnsNsCntHandler{}, true)                                        // get counters / meta per namespace
}

func Register(ctx *core.CThreadCtx) {
	// In order for this plugin to be included in the EMU compilation one must provide this empty register
	// function. In case you remove the function call, then the core will not include EMU.
}
