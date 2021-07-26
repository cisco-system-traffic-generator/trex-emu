/*
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

package dns

import (
	"emu/core"
	"emu/plugins/transport"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"flag"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

var monitor int

// DnsTestBase represents the base parameters for a Dns test.
type DnsTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	capture      bool
	duration     time.Duration
	clientsToSim int
	query        string
	ipv6         bool
	forceDGW     bool
	ForcedgMac   core.MACKey
	counters     DnsClientStats
	initJSON     [][][]byte
	nsInitJson   [][]byte
	cb           DnsTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

// DnsTestCb represents a callback that will be called in the function.
type DnsTestCb func(tctx *core.CThreadCtx, test *DnsTestBase) int

// VethDnsSim represents an Dns veth for simulation.
type VethDnsSim struct {
	DropAll bool
}

// ProcessTxToRx decides either to drop packets or support a loopback arch.
func (o *VethDnsSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}
	// In case we don't DropAll, we loop back
	return m
}

// Run the tests.
func (o *DnsTestBase) Run(t *testing.T, compare bool) {

	var simVeth VethDnsSim
	simVeth.DropAll = o.dropAll
	var simrx core.VethIFSim
	simrx = &simVeth

	var tctx *core.CThreadCtx
	tctx, _ = createSimulationEnv(&simrx, o)

	if o.cb != nil {
		o.cb(tctx, o)
	}
	m := false
	if monitor > 0 {
		m = true
	}
	tctx.Veth.SetDebug(m, os.Stdout, o.capture)
	tctx.MainLoopSim(o.duration)
	defer tctx.Delete()

	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1})
	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}

	var dnsPlug *PluginDnsClient

	for j := 0; j < o.clientsToSim; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)

		c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, a, b})
		clplg := c.PluginCtx.Get(DNS_PLUG)
		if clplg == nil {
			t.Fatalf(" can't find plugin")
		}
		dnsPlug = clplg.Ext.(*PluginDnsClient)
		dnsPlug.cdbv.Dump()
		tctx.SimRecordAppend(dnsPlug.cdb.MarshalValues(false))
		c.OnRemove()
	}

	if o.nsInitJson != nil {
		// dump namespace counters too
		nsPlug := ns.PluginCtx.Get(DNS_PLUG)
		if nsPlug == nil {
			t.Fatalf(" can't find plugin")
		}
		mDnsNsPlug := nsPlug.Ext.(*PluginDnsNs)
		mDnsNsPlug.cdbv.Dump()
		tctx.SimRecordAppend(mDnsNsPlug.cdb.MarshalValues(false))
	}

	if compare {
		if o.monitor {
			tctx.SimRecordCompare(o.testname, t)
		} else {
			if o.clientsToSim == 1 {
				if o.counters != dnsPlug.stats {
					t.Errorf("Bad counters, want %+v, have %+v.\n", o.counters, dnsPlug.stats)
					t.FailNow()
				}
			}

		}
	}
	ns.OnRemove()
}

// createSimulationEnv creates the simulation event.
func createSimulationEnv(simRx *core.VethIFSim, t *DnsTestBase) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1})
	ns := core.NewNSCtx(tctx, &key)
	ns.PluginCtx.CreatePlugins([]string{DNS_PLUG}, t.nsInitJson)
	nsPlg := ns.PluginCtx.Get(DNS_PLUG)
	if nsPlg == nil {
		panic(" can't find plugin")
	}
	tctx.AddNs(&key, ns)
	num := t.clientsToSim

	for j := 0; j < num; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)
		var dg core.Ipv4Key
		if num == 1 {
			dg = core.Ipv4Key{16, 0, 0, 2}
		} else {
			dg = core.Ipv4Key{16, 1, a, b}
		}
		client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, a, b},
			core.Ipv4Key{16, 0, a, b},
			core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, a, b},
			dg)

		// force the mac so that resolve won't be a problem.
		if t.forceDGW {
			// IPv4
			client.ForceDGW = true
			client.Ipv4ForcedgMac = t.ForcedgMac
			// IPv6
			client.Ipv6ForceDGW = true
			client.Ipv6ForcedgMac = t.ForcedgMac
		}
		err := ns.AddClient(client)
		if err != nil {
			panic("Error adding client to namespace:" + err.Error())
		}
		client.PluginCtx.CreatePlugins([]string{DNS_PLUG, transport.TRANS_PLUG}, t.initJSON[j])
		cPlg := client.PluginCtx.Get(DNS_PLUG)
		if cPlg == nil {
			panic(" can't find plugin")
		}

	}
	tctx.RegisterParserCb(transport.TRANS_PLUG) // The one parsing is actually UDP.
	ns.Dump()

	return tctx, nil
}

// DnsQueryCtxRpc simulates a query RPC.
type DnsQueryCtxRpc struct {
	query string
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
}

// OnEvent generates and sends the query RPC.
func (o *DnsQueryCtxRpc) OnEvent(a, b interface{}) {
	rpc := fmt.Sprintf(`{"jsonrpc": "2.0",
	"method":"dns_c_query",
	"params": {"tun": {"vport":1}, "mac": [0, 0, 1, 0, 0, 0], "queries": %v},
	"id": 3}`, o.query)
	o.tctx.Veth.AppendSimuationRPC([]byte(rpc))
}

// queryCb is called to simulate an RPC query.
func queryCb(tctx *core.CThreadCtx, test *DnsTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(2 * time.Second)
	var dnsQueryCtx DnsQueryCtxRpc
	dnsQueryCtx.query = test.query
	dnsQueryCtx.timer.SetCB(&dnsQueryCtx, test.cbArg1, test.cbArg2)
	dnsQueryCtx.tctx = tctx
	timerw.StartTicks(&dnsQueryCtx.timer, ticks)
	return 0
}

// DnsResponseCtx sends a query packet which triggers a response.
type DnsResponseCtx struct {
	ipv6  bool
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
}

// OnEvent generates a query which will trigger an automatic response.
func (o *DnsResponseCtx) OnEvent(a, b interface{}) {
	name := "trex-tgn.cisco.com"
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if o.ipv6 {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 2, 0, 0, 0},
				DstMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
				EthernetType: layers.EthernetTypeIPv6,
			},
			&layers.IPv6{Version: 6,
				HopLimit:   255,
				SrcIP:      net.IP(net.ParseIP("2001:db8::100")),
				DstIP:      net.IP(net.ParseIP("2001:db8::")),
				NextHeader: layers.IPProtocolUDP},
			&layers.UDP{SrcPort: 65200,
				DstPort:  53,
				Length:   36,
				Checksum: 0xc879},
			&layers.DNS{
				ID:           0xf00d,                      // Some fixed value
				QR:           false,                       // False for Query, True for Response
				OpCode:       layers.DNSOpCodeQuery,       // Standard DNS query, opcode = 0
				AA:           false,                       // Authoritative answer = 0 for query.
				TC:           false,                       // Truncated, not supported
				RD:           false,                       // Recursion desired, not supported
				RA:           false,                       // Recursion available, not supported
				Z:            0,                           // Reserved for future use
				ResponseCode: layers.DNSResponseCodeNoErr, // Response code is set to 0 in queries
				QDCount:      1,                           // Number of queries, will be updated on query, 0 for response
				ANCount:      0,                           // Number of answers, will be updated in respose, 0 for queries
				NSCount:      0,                           // Number of authorities = 0
				ARCount:      0,                           // Number of additional records = 0
				Questions:    []layers.DNSQuestion{layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
			},
		)
	} else {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
				DstMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{Version: 4,
				IHL:      5,
				TTL:      255,
				Id:       0xcc,
				SrcIP:    net.IPv4(16, 0, 100, 1),
				DstIP:    net.IPv4(16, 0, 0, 0),
				Checksum: 0x36e0,
				Protocol: layers.IPProtocolUDP},
			&layers.UDP{SrcPort: 65200,
				DstPort:  53,
				Length:   36,
				Checksum: 0x7ec4},
			&layers.DNS{
				ID:           0x1234,                      // Some fixed value
				QR:           false,                       // False for Query, True for Response
				OpCode:       layers.DNSOpCodeQuery,       // Standard DNS query, opcode = 0
				AA:           false,                       // Authoritative answer = 0 for query.
				TC:           false,                       // Truncated, not supported
				RD:           false,                       // Recursion desired, not supported
				RA:           false,                       // Recursion available, not supported
				Z:            0,                           // Reserved for future use
				ResponseCode: layers.DNSResponseCodeNoErr, // Response code is set to 0 in queries
				QDCount:      1,                           // Number of queries, will be updated on query, 0 for response
				ANCount:      0,                           // Number of answers, will be updated in respose, 0 for queries
				NSCount:      0,                           // Number of authorities = 0
				ARCount:      0,                           // Number of additional records = 0
				Questions:    []layers.DNSQuestion{layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
			},
		)
	}

	m := o.tctx.MPool.Alloc(uint16(128))
	m.SetVPort(1)
	m.Append(buf.Bytes())
	o.tctx.Veth.OnRx(m)
}

// responseCb is called to simulate an query which will trigger the response
func responseCb(tctx *core.CThreadCtx, test *DnsTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(2 * time.Second)
	var dnsResponseCtx DnsResponseCtx
	dnsResponseCtx.ipv6 = test.ipv6
	dnsResponseCtx.timer.SetCB(&dnsResponseCtx, test.cbArg1, test.cbArg2)
	dnsResponseCtx.tctx = tctx
	timerw.StartTicks(&dnsResponseCtx.timer, ticks)
	return 0
}

func TestPluginDns1(t *testing.T) {

	initJson1 := [][]byte{[]byte(`{
		"dns_server_ip": "8.8.8.8",
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	query := `[{"name": "google.com"}]`

	a := &DnsTestBase{
		testname:     "dns1",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		query:        query,
		duration:     10 * time.Second,
		clientsToSim: 1,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginDns2(t *testing.T) {

	initJson1 := [][]byte{[]byte(`{
		"dns_server_ip": "2001:4860:4860::8888",
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	query := `[{"name": "google.com", "dns_type": "AAAA"}]`

	a := &DnsTestBase{
		testname:     "dns2",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		query:        query,
		duration:     10 * time.Second,
		clientsToSim: 1,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginDns3(t *testing.T) {

	// Query + response.

	initJson1 := [][]byte{[]byte(`{
		"name_server": true,
		"database": {
			"trex-tgn.cisco.com": [
				{
					"type": "A",
					"class": "IN",
					"answer": "173.36.109.208"
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DnsTestBase{
		testname:     "dns3",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		cb:           responseCb,
	}
	a.Run(t, true)
}

func TestPluginDns4(t *testing.T) {

	// Query + response + IPv6

	initJson1 := [][]byte{[]byte(`{
		"name_server": true,
		"database": {
			"trex-tgn.cisco.com": [
				{
					"type": "A",
					"class": "IN",
					"answer": "173.36.109.208"
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DnsTestBase{
		testname:     "dns4",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		cb:           responseCb,
		ipv6:         true,
	}
	a.Run(t, true)
}

func getServerInitJson() [][]byte {
	return [][]byte{[]byte(`{
		"name_server": true,
		"database": {
			"trex-tgn.cisco.com": [
				{
					"type": "A",
					"class": "IN",
					"answer": "173.36.109.208"
				}
			],
			"cisco.com": [
				{
					"type": "A",
					"class": "IN",
					"answer": "72.163.4.185"
				},
				{
					"type": "A",
					"class": "IN",
					"answer": "72.163.4.161"
				},
				{
					"type": "AAAA",
					"class": "IN",
					"answer": "2001:420:1101:1::185"
				},
				{
					"type": "TXT",
					"class": "IN",
					"answer": "desc=Best place to work!, location=Israel"
				}
			],
			"8.8.8.8.in-addr.arpa": [
				{
					"type": "PTR",
					"class": "IN",
					"answer": "google.com"
				}
			]
		}
	}`)}
}

func TestPluginDns5(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - Type: A, Class: IN

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.1"
	}`)}
	var initJsonArray = [][][]byte{initJsonClient, getServerInitJson()}

	query := `[{"name": "cisco.com"}]`

	a := &DnsTestBase{
		testname:     "dns5",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func TestPluginDns6(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - Type: AAAA, Class: IN

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.1"
	}`)}
	var initJsonArray = [][][]byte{initJsonClient, getServerInitJson()}

	query := `[{"name": "cisco.com", "dns_type": "AAAA"}]`

	a := &DnsTestBase{
		testname:     "dns6",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func TestPluginDns7(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - Type: TXT, Class: Any

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.1"
	}`)}
	var initJsonArray = [][][]byte{initJsonClient, getServerInitJson()}

	query := `[{"name": "cisco.com", "dns_type": "TXT", "dns_class": "Any"}]`

	a := &DnsTestBase{
		testname:     "dns7",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func TestPluginDns8(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - Two questions, one query.

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.1"
	}`)}
	var initJsonArray = [][][]byte{initJsonClient, getServerInitJson()}

	query := `[{"name": "cisco.com", "dns_type": "AAAA"}, {"name": "trex-tgn.cisco.com"}]`

	a := &DnsTestBase{
		testname:     "dns8",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func TestPluginDns9(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - Type: PTR

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.1"
	}`)}
	var initJsonArray = [][][]byte{initJsonClient, getServerInitJson()}

	query := `[{"name": "8.8.8.8.in-addr.arpa", "dns_type": "PTR", "dns_class": "Any"}]`

	a := &DnsTestBase{
		testname:     "dns9",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func TestPluginDns10(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - Non existing domain

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.1"
	}`)}
	var initJsonArray = [][][]byte{initJsonClient, getServerInitJson()}

	query := `[{"name": "google.com"}]`

	a := &DnsTestBase{
		testname:     "dns10",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func TestPluginDns11(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - Trying to query from DnsNameServer, should give error.

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.1"
	}`)}
	var initJsonArray = [][][]byte{getServerInitJson(), initJsonClient}

	query := `[{"name": "google.com"}]`

	a := &DnsTestBase{
		testname:     "dns11",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func TestPluginDns12(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Test specifics - IPv6 Dns Server, asking for Type A.

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "2001:db8::1"
	}`)}
	var initJsonArray = [][][]byte{initJsonClient, getServerInitJson()}

	query := `[{"name": "cisco.com", "dns_type": "A"}]`

	a := &DnsTestBase{
		testname:     "dns12",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 1},
	}
	a.Run(t, true)
}

func getServerInitJsonAutoPlay() [][]byte {
	return [][]byte{[]byte(`{
		"name_server": true,
		"database": {
			"domain1.com": [
				{
					"type": "A",
					"class": "IN",
					"answer": "1.1.1.1"
				}
			],
			"domain2.com": [
				{
					"type": "A",
					"class": "IN",
					"answer": "2.2.2.2"
				},
				{
					"type": "A",
					"class": "IN",
					"answer": "2.2.2.1"
				},
				{
					"type": "AAAA",
					"class": "IN",
					"answer": "2001:420:1101:1::2"
				},
				{
					"type": "TXT",
					"class": "IN",
					"answer": "desc=domain2, gen=trex"
				}
			],
			"domain3.com": [
				{
					"type": "A",
					"class": "CH",
					"answer": "3.3.3.3"
				}
			]
		}
	}`)}
}

func TestPluginDns13(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Basic Auto Play

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "domain%v.com"
			"min_hostname": 1,
			"max_hostname": 2,
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns13",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}

func TestPluginDns14(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// There is no client with 00:00:01:00:00:04!

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:04",
			"hostname_template": "domain%v.com"
			"min_hostname": 1,
			"max_hostname": 4,
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns14",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 4,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}

func TestPluginDns15(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Step Hostname + Step Client

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:03",
			"client_step": 2,
			"hostname_template": "domain%v.com"
			"min_hostname": 1,
			"max_hostname": 3,
			"hostname_step": 2
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns15",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 4,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}

func TestPluginDns16(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Simple Program

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:03",
			"hostname_template": "domain%v.com",
			"min_hostname": 1,
			"max_hostname": 3,
			"program": {
				"00:00:01:00:00:03": {
					"hostnames": ["domain3.com"],
					"class": "Any"
				}
			}
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns16",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 4,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}

func TestPluginDns17(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Simple Program + default type is AAAA

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "domain%v.com",
			"min_hostname": 1,
			"max_hostname": 2,
			"type": "AAAA",
			"program": {
				"00:00:01:00:00:01": {
					"hostnames": ["domain1.com", "domain2.com"],
					"type": "A"
				}
			}
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns17",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 4,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}

func TestPluginDns18(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Rate

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 3.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "domain%v.com"
			"min_hostname": 1,
			"max_hostname": 2,
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns18",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}

func TestPluginDns19(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Ipv6

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "2001:db8::0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 3.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "domain%v.com"
			"min_hostname": 1,
			"max_hostname": 2,
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns19",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}
func TestPluginDns20(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Query Amount + Rate

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 5.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:03",
			"hostname_template": "domain%v.com"
			"min_hostname": 1,
			"max_hostname": 3,
			"query_amount": 5
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns20",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 4,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}
func TestPluginDns21(t *testing.T) {

	// Test Arch - Two Clients. First one is server, second one is client.
	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	// Simple Program

	initJsonClient := [][]byte{[]byte(`{
		"name_server": false,
		"dns_server_ip": "16.0.0.0"
	}`)}

	var initJsonArray = [][][]byte{getServerInitJsonAutoPlay(), initJsonClient, initJsonClient, initJsonClient}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:01",
			"max_client": "00:00:01:00:00:03",
			"hostname_template": "domain%v.com",
			"min_hostname": 1,
			"max_hostname": 3,
			"program": {
				"00:00:01:00:00:03": {
					"hostnames": ["domain3.com"],
					"class": "Any"
				}
				"00:00:01:00:00:02": {
					"hostnames": ["domain2.com"],
					"type": "TXT"
				}
			}
		}
	}`)}

	a := &DnsTestBase{
		testname:     "dns21",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 4,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 1, 0, 0, 0},
	}
	a.Run(t, true)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
