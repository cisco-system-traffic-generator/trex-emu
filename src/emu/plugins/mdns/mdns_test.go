package mdns

import (
	"emu/core"
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

// MDnsTestBase represents the base parameters for a MDns test.
type MDnsTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	capture      bool
	duration     time.Duration
	clientsToSim int
	query        string
	ipv6         bool
	counters     MDnsClientStats
	initJSON     [][][]byte
	nsInitJson   [][]byte
	cb           MDnsTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

// MDnsTestCb represents a callback that will be called in the function.
type MDnsTestCb func(tctx *core.CThreadCtx, test *MDnsTestBase) int

// VethMDnsSim represents an MDns veth for simulation.
type VethMDnsSim struct {
	DropAll bool
}

// ProcessTxToRx decides either to drop packets or support a loopback arch.
func (o *VethMDnsSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}
	// In case we don't DropAll, we loop back
	return m
}

// Run the tests.
func (o *MDnsTestBase) Run(t *testing.T, compare bool) {

	var simVeth VethMDnsSim
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

	var mDnsPlug *PluginMDnsClient

	for j := 0; j < o.clientsToSim; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)

		c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, a, b})
		clplg := c.PluginCtx.Get(MDNS_PLUG)
		if clplg == nil {
			t.Fatalf(" can't find plugin")
		}
		mDnsPlug = clplg.Ext.(*PluginMDnsClient)
		mDnsPlug.cdbv.Dump()
		tctx.SimRecordAppend(mDnsPlug.cdb.MarshalValues(false))
		c.OnRemove()
	}

	if o.nsInitJson != nil {
		// dump namespace counters too
		nsPlug := ns.PluginCtx.Get(MDNS_PLUG)
		if nsPlug == nil {
			t.Fatalf(" can't find plugin")
		}
		mDnsNsPlug := nsPlug.Ext.(*PluginMDnsNs)
		mDnsNsPlug.cdbv.Dump()
		tctx.SimRecordAppend(mDnsNsPlug.cdb.MarshalValues(false))
	}

	if compare {
		if o.monitor {
			tctx.SimRecordCompare(o.testname, t)
		} else {
			if o.clientsToSim == 1 {
				if o.counters != mDnsPlug.stats {
					t.Errorf("Bad counters, want %+v, have %+v.\n", o.counters, mDnsPlug.stats)
					t.FailNow()
				}
			}

		}
	}
	ns.OnRemove()
}

// createSimulationEnv creates the simulation event.
func createSimulationEnv(simRx *core.VethIFSim, t *MDnsTestBase) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1})
	ns := core.NewNSCtx(tctx, &key)
	ns.PluginCtx.CreatePlugins([]string{MDNS_PLUG}, t.nsInitJson)
	nsPlg := ns.PluginCtx.Get(MDNS_PLUG)
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
		err := ns.AddClient(client)
		if err != nil {
			panic("Error adding client to namespace:" + err.Error())
		}
		client.PluginCtx.CreatePlugins([]string{MDNS_PLUG}, t.initJSON[j])
		cPlg := client.PluginCtx.Get(MDNS_PLUG)
		if cPlg == nil {
			panic(" can't find plugin")
		}

	}
	tctx.RegisterParserCb(MDNS_PLUG)
	ns.Dump()

	return tctx, nil
}

// MDnsQueryCtxRpc simulates a query RPC.
type MDnsQueryCtxRpc struct {
	query string
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
}

// OnEvent generates and sends the query RPC.
func (o *MDnsQueryCtxRpc) OnEvent(a, b interface{}) {
	rpc := fmt.Sprintf(`{"jsonrpc": "2.0",
	"method":"mdns_c_query",
	"params": {"tun": {"vport":1}, "mac": [0, 0, 1, 0, 0, 0], "queries": %v},
	"id": 3}`, o.query)
	o.tctx.Veth.AppendSimuationRPC([]byte(rpc))
}

// queryCb is called to simulate an RPC query.
func queryCb(tctx *core.CThreadCtx, test *MDnsTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(2 * time.Second)
	var mDnsQueryCtx MDnsQueryCtxRpc
	mDnsQueryCtx.query = test.query
	mDnsQueryCtx.timer.SetCB(&mDnsQueryCtx, test.cbArg1, test.cbArg2)
	mDnsQueryCtx.tctx = tctx
	timerw.StartTicks(&mDnsQueryCtx.timer, ticks)
	return 0
}

// MDnsResponseCtx sends a query packet which triggers a response.
type MDnsResponseCtx struct {
	ipv6  bool
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
}

// OnEvent generates a query which will trigger an automatic response.
func (o *MDnsResponseCtx) OnEvent(a, b interface{}) {
	name := "trex.local"
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if o.ipv6 {
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
				DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB},
				EthernetType: layers.EthernetTypeIPv6,
			},
			&layers.IPv6{Version: 6,
				HopLimit:   255,
				SrcIP:      net.IP(net.ParseIP("2001:db8::")),
				DstIP:      net.IP(net.ParseIP("ff02::fb")),
				NextHeader: layers.IPProtocolUDP},
			&layers.UDP{SrcPort: 5353,
				DstPort:  5353,
				Length:   36,
				Checksum: 0x7d6a},
			&layers.DNS{
				ID:           0,                           // Maybe randomly generate this
				QR:           false,                       // False for Query, True for Response
				OpCode:       layers.DNSOpCodeQuery,       // Standard DNS query, opcode = 0
				AA:           false,                       // Authoritative answer, not relevant in query
				TC:           false,                       // Truncated, not supported
				RD:           false,                       // Recursion desired, not supported in mDNS
				RA:           false,                       // Recursion available, not supported in mDNS
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
				DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{Version: 4,
				IHL:      5,
				TTL:      255,
				Id:       0xcc,
				SrcIP:    net.IPv4(16, 0, 0, 0),
				DstIP:    net.IPv4(224, 0, 0, 251),
				Checksum: 0xc9ed,
				Protocol: layers.IPProtocolUDP},
			&layers.UDP{SrcPort: 5353,
				DstPort:  5353,
				Length:   36,
				Checksum: 0xba25},
			&layers.DNS{
				ID:           0,                           // Maybe randomly generate this
				QR:           false,                       // False for Query, True for Response
				OpCode:       layers.DNSOpCodeQuery,       // Standard DNS query, opcode = 0
				AA:           false,                       // Authoritative answer, not relevant in query
				TC:           false,                       // Truncated, not supported
				RD:           false,                       // Recursion desired, not supported in mDNS
				RA:           false,                       // Recursion available, not supported in mDNS
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
func responseCb(tctx *core.CThreadCtx, test *MDnsTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(2 * time.Second)
	var mDnsResponseCtx MDnsResponseCtx
	mDnsResponseCtx.ipv6 = test.ipv6
	mDnsResponseCtx.timer.SetCB(&mDnsResponseCtx, test.cbArg1, test.cbArg2)
	mDnsResponseCtx.tctx = tctx
	timerw.StartTicks(&mDnsResponseCtx.timer, ticks)
	return 0
}

func TestPluginMDns1(t *testing.T) {

	// Simple IPv4 query with no response, one client.

	initJson1 := [][]byte{[]byte(`{}`)}
	var initJsonArray = [][][]byte{initJson1}

	query := `[{"name": "trex.local", "dns_class": "IN", "ipv6": false}]`

	a := &MDnsTestBase{
		testname:     "mdns1",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		query:        query,
		duration:     10 * time.Second,
		clientsToSim: 1,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns2(t *testing.T) {

	// Simple IPv6 query with no response.

	initJson1 := [][]byte{[]byte(`{}`)}
	var initJsonArray = [][][]byte{initJson1}

	query := `[{"name": "trex.local", "dns_class": "IN", "ipv6": true}]`

	a := &MDnsTestBase{
		testname:     "mdns2",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns3(t *testing.T) {

	// Query + response.

	initJson1 := [][]byte{[]byte(`{
		"hosts": ["trex.local", "my_server._tcp.local"]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &MDnsTestBase{
		testname:     "mdns3",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		cb:           responseCb,
	}
	a.Run(t, true)
}

func TestPluginMDns4(t *testing.T) {

	// Query + response - IPv6.

	initJson1 := [][]byte{[]byte(`{
		"hosts": ["trex.local", "my_server._tcp.local"]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &MDnsTestBase{
		testname:     "mdns4",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		ipv6:         true,
		cb:           responseCb,
	}
	a.Run(t, true)
}

func TestPluginMDns5(t *testing.T) {

	initJson1 := [][]byte{[]byte(`{
		"hosts": ["trex.local", "my_server._tcp.local"]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	query := `[{"name": "trex.local", "dns_class": "IN", "ipv6": false}]`

	// Pay attention to this test, we are loopbacked

	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	a := &MDnsTestBase{
		testname:     "mdns5",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns6(t *testing.T) {

	// TXT - HW, md and model number.
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
		"txt": [
			{
				"field": "am",
				"value": "AppleTV3,2"
			},
			{
				"field": "ty",
				"value": "Brother HL-L2340D series"
			},
			{
				"field": "OS",
				"value": "Windows 10",
			}
		]
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS"],
		"txt": [
			{
				"field": "HW",
				"value": "Cisco UCS 220M5"
			},
			{
				"field": "md",
				"value": "ecobee3 lite"
			},
			{
				"field": "model_number",
				"value": "N841AP"
			}
		]
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "UCS", "dns_class": "IN", "dns_type": "TXT", "ipv6": false}]`

	a := &MDnsTestBase{
		testname:     "mdns6",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns7(t *testing.T) {

	// TXT - am, ty, and OS
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
		"txt": [
			{
				"field": "am",
				"value": "AppleTV3,2"
			},
			{
				"field": "ty",
				"value": "Brother HL-L2340D series"
			},
			{
				"field": "OS",
				"value": "Windows 10",
			}
		]
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS"],
		"txt": [
			{
				"field": "HW",
				"value": "Cisco UCS 220M5"
			},
			{
				"field": "md",
				"value": "ecobee3 lite"
			},
			{
				"field": "model_number",
				"value": "N841AP"
			}
		]
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "Brother", "dns_class": "IN", "dns_type": "TXT", "ipv6": false}]`

	a := &MDnsTestBase{
		testname:     "mdns7",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns8(t *testing.T) {

	// PTR - IPv6.
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
		"domain_name": "cisco_il"
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS"],
		"domain_name": "cisco_il"
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "UCS", "dns_class": "IN", "dns_type": "PTR", "ipv6": true}]`

	a := &MDnsTestBase{
		testname:     "mdns8",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns9(t *testing.T) {

	// PTR - IPv4 + TTL
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
		"domain_name": "cisco_il"
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "16.0.0.1.cisco.com", "dns_class": "IN", "dns_type": "PTR", "ipv6": false}]`

	a := &MDnsTestBase{
		testname:     "mdns9",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns10(t *testing.T) {

	// AAAA ipv4
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "UCS", "dns_class": "IN", "dns_type": "AAAA", "ipv6": false}]`

	a := &MDnsTestBase{
		testname:     "mdns10",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns11(t *testing.T) {

	// AAAA ipv6
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "trex-04", "dns_class": "IN", "dns_type": "AAAA", "ipv6": true}]`

	a := &MDnsTestBase{
		testname:     "mdns11",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns12(t *testing.T) {

	// TXT query - No TXT Defined (Check counters)
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "trex-04", "dns_class": "IN", "dns_type": "TXT", "ipv6": false}]`

	a := &MDnsTestBase{
		testname:     "mdns12",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns13(t *testing.T) {

	// PTR query - No Domain Name Defined (Check counters)
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	query := `[{"name": "trex-04", "dns_class": "IN", "dns_type": "PTR", "ipv6": false}]`

	a := &MDnsTestBase{
		testname:     "mdns13",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 2,
		query:        query,
		cb:           queryCb,
	}
	a.Run(t, true)
}

func TestPluginMDns14(t *testing.T) {

	// Auto Play with 2 clients and defaults
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-1"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-0"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:01",
			"client_step": 1,
			"hostname_template": "client-%v"
			"min_hostname": 0,
			"max_hostname": 1,
			"hostname_step": 1
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns14",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 2,
	}
	a.Run(t, true)
}

func TestPluginMDns15(t *testing.T) {

	// Auto Play with 2 clients and defaults
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-1"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-0"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 5.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:01",
			"client_step": 1,
			"hostname_template": "client-%v"
			"min_hostname": 0,
			"max_hostname": 1,
			"hostname_step": 1,
			"type": "AAAA"
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns15",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 2,
	}
	a.Run(t, true)
}

func TestPluginMDns16(t *testing.T) {

	// More clients, different steps, including query with no response for client 5.
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-0"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-1"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	initJson3 := [][]byte{[]byte(`{
		"hosts": ["client-2"],
	}`)}

	initJson4 := [][]byte{[]byte(`{
		"hosts": ["client-3"],
	}`)}

	initJson5 := [][]byte{[]byte(`{
		"hosts": ["client-4"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2, initJson3, initJson4, initJson5}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:05",
			"client_step": 2,
			"hostname_template": "client-%v"
			"min_hostname": 0,
			"max_hostname": 5,
			"hostname_step": 1
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns16",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 5,
	}
	a.Run(t, true)
}

func TestPluginMDns17(t *testing.T) {

	// Missing clients and hostname step
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-0"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-1"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	initJson3 := [][]byte{[]byte(`{
		"hosts": ["client-2"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2, initJson3}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:05",
			"hostname_template": "client-%v"
			"min_hostname": 0,
			"max_hostname": 2,
			"init_hostname": 2,
			"hostname_step": 2
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns17",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
	}
	a.Run(t, true)
}

func TestPluginMDns18(t *testing.T) {

	// Ipv6 autoplay
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-0"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-1"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	initJson3 := [][]byte{[]byte(`{
		"hosts": ["client-2"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2, initJson3}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "client-%v"
			"min_hostname": 0,
			"max_hostname": 2,
			"init_hostname": 1,
			"hostname_step": 1,
			"ipv6": true
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns18",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
	}
	a.Run(t, true)
}

func TestPluginMDns19(t *testing.T) {

	// Program with PTR and Any
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-0"],
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-1"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	initJson3 := [][]byte{[]byte(`{
		"hosts": ["client-2"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2, initJson3}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "client-%v"
			"min_hostname": 0,
			"max_hostname": 2,
			"init_hostname": 1,
			"hostname_step": 1,
			"program": {
				"00:00:01:00:00:00": {
					"hostnames": ["16.0.0.1.cisco.com"],
					"type": "PTR",
					"class": "Any"
				}
			}
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns19",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
	}
	a.Run(t, true)
}

func TestPluginMDns20(t *testing.T) {

	// TXT Ipv6 vs normal IPv4
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-0.local"],
		"txt": [
			{
				"field": "am",
				"value": "AppleTV3,2"
			},
			{
				"field": "ty",
				"value": "Brother HL-L2340D series"
			},
			{
				"field": "OS",
				"value": "Windows 10",
			}
		]
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-1.local"],
		"domain_name": "cisco_il",
		"ttl": 180
	}`)}

	initJson3 := [][]byte{[]byte(`{
		"hosts": ["client-2.local"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2, initJson3}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "client-%v.local"
			"min_hostname": 0,
			"max_hostname": 2,
			"init_hostname": 1,
			"hostname_step": 1,
			"program": {
				"00:00:01:00:00:01": {
					"hostnames": ["AppleTV"],
					"type": "TXT",
					"ipv6": true
				},
				"00:00:01:00:00:00": {
					"hostnames": ["BadHost"]
				}
			}
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns20",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
	}
	a.Run(t, true)
}

func TestPluginMDns21(t *testing.T) {

	// multiple hostnames in program
	initJson1 := [][]byte{[]byte(`{
		"hosts": ["AppleTV", "Brother", "client-0._tcp.local"],
		"txt": [
			{
				"field": "am",
				"value": "AppleTV3,2"
			},
			{
				"field": "ty",
				"value": "Brother HL-L2340D series"
			},
			{
				"field": "OS",
				"value": "Windows 10",
			}
		]
	}`)}

	initJson2 := [][]byte{[]byte(`{
		"hosts": ["UCS", "16.0.0.1.cisco.com", "trex-04", "client-1._tcp.local"],
		"domain_name": "cisco_il",
		"ttl": 180
		"txt": [
			{
				"field": "HW",
				"value": "UCS C-220"
			}
		]
	}`)}

	initJson3 := [][]byte{[]byte(`{
		"hosts": ["client-2._tcp.local"],
	}`)}

	var initJsonArray = [][][]byte{initJson1, initJson2, initJson3}

	// Pay attention to this test, we are loopbacked
	// query (TX) --(loopback)-> query(RX) --(logic) -> response (TX) --(loopback) -> response (RX)

	nsInitJson := [][]byte{[]byte(`{
		"auto_play": true,
		"auto_play_params": {
			"rate": 1.0,
			"min_client": "00:00:01:00:00:00",
			"max_client": "00:00:01:00:00:02",
			"hostname_template": "client-%v._tcp.local"
			"min_hostname": 0,
			"max_hostname": 2,
			"init_hostname": 1,
			"hostname_step": 1,
			"program": {
				"00:00:01:00:00:02": {
					"hostnames": ["Brother", "AppleTV"],
					"type": "TXT",
				},
	
			}
		}
	}`)}

	a := &MDnsTestBase{
		testname:     "mdns21",
		dropAll:      false,
		monitor:      true,
		capture:      true,
		initJSON:     initJsonArray,
		nsInitJson:   nsInitJson,
		duration:     10 * time.Second,
		clientsToSim: 3,
	}
	a.Run(t, true)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
