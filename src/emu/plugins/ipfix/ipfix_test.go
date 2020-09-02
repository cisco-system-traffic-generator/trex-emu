package ipfix

import (
	"emu/core"
	"flag"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

var monitor int

type IPFixTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	clientIpv6   core.Ipv6Key
	counters     IPFixStats
	initJSON     [][]byte
	seed         int64
	cb           IPFixTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

type IPFixTestCb func(tctx *core.CThreadCtx, test *IPFixTestBase) int

type VethIPFixSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func (o *VethIPFixSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	m.FreeMbuf()
	return nil
}

func (o *IPFixTestBase) Run(t *testing.T, compare bool) {

	if o.seed != 0 {
		rand.Seed(o.seed)
	}

	var simVeth VethIPFixSim
	simVeth.DropAll = o.dropAll
	var simrx core.VethIFSim
	simrx = &simVeth
	if o.match > 0 {
		simVeth.match = o.match
	}
	var tctx *core.CThreadCtx
	tctx, _ = createSimulationEnv(&simrx, o)

	if o.cb != nil {
		o.cb(tctx, o)
	}
	m := false
	if monitor > 0 {
		m = true
	}
	simVeth.tctx = tctx
	tctx.Veth.SetDebug(m, o.capture)
	tctx.MainLoopSim(o.duration)
	defer tctx.Delete()

	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1})
	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}

	var ipfixPlug *PluginIPFixClient

	for j := 0; j < o.clientsToSim; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)

		c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, a, b})
		clplg := c.PluginCtx.Get(IPFIX_PLUG)
		if clplg == nil {
			t.Fatalf(" can't find plugin")
		}
		ipfixPlug = clplg.Ext.(*PluginIPFixClient)
		ipfixPlug.cdbv.Dump()
		tctx.SimRecordAppend(ipfixPlug.cdb.MarshalValues(false))
	}

	if compare {
		if o.monitor {
			tctx.SimRecordCompare(o.testname, t)
		} else {
			if o.clientsToSim == 1 {
				if o.counters != ipfixPlug.stats {
					t.Errorf("Bad counters, want %+v, have %+v.\n", o.counters, ipfixPlug.stats)
					t.FailNow()
				}
			}

		}
	}
}

func createSimulationEnv(simRx *core.VethIFSim, t *IPFixTestBase) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1})
	ns := core.NewNSCtx(tctx, &key)
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
			t.clientIpv6,
			dg)
		// force the mac so that resolve won't be a problem.
		// IPv4
		client.ForceDGW = true
		client.Ipv4ForcedgMac = core.MACKey{0, 0, 2, 0, 0, 0}
		// IPv6
		client.Ipv6ForceDGW = true
		client.Ipv6ForcedgMac = core.MACKey{0, 0, 2, 0, 0, 0}
		ns.AddClient(client)
		client.PluginCtx.CreatePlugins([]string{IPFIX_PLUG}, t.initJSON)

		// After adding the plugins, we can try to resolve.
		client.AttemptResolve()

		cPlg := client.PluginCtx.Get(IPFIX_PLUG)
		if cPlg == nil {
			panic(" can't find plugin")
		}
	}
	ns.Dump()

	return tctx, nil
}

type TemplateParams struct {
	autoStart       bool    // should autostart
	rate            float32 // data rate
	recordsNum      int     // number of records
	optionsTemplate bool    // is Options Template
	scopeCount      uint16  // scope count for options templates
}

func getTemplate261Fields() string {
	return `
	{
		"name": "clientIPv4Address",
		"type": 45004,
		"length": 4,
		"enterprise_number": 9,
		"data": [16, 0, 0, 1]
	},
	{
		"name": "serverIPv4Address",
		"type": 45005,
		"length": 4,
		"enterprise_number": 9,
		"data": [24, 0, 0, 1]
	},
	{
		"name": "protocolIdentifier",
		"type": 4,
		"length": 1,
		"data": [17]
	},
	{
		"name": "clientTransportPort",
		"type": 45008,
		"length": 2,
		"enterprise_number": 9,
		"data": [128, 232]
	},
	{
		"name": "serverTransportProtocol",
		"type": 45009,
		"length": 2,
		"enterprise_number": 9,
		"data": [0, 53]
	},
	{
		"name": "applicationId",
		"type": 95,
		"length": 4,
		"data": [3, 0, 0, 53]
	},
	{
		"name": "nbar2HttpHost",
		"type": 45003,
		"length": 7,
		"enterprise_number": 9,
		"data": [115, 115, 115, 46, 101, 100, 117]
	},
	{
		"name": "nbar2HttpHostBlackMagic1",
		"type": 45003,
		"length": 7,
		"enterprise_number": 9,
		"data": [3, 0, 0, 53, 52, 4, 0]
	},
	{
		"name": "nbar2HttpHostBlackMagic2",
		"type": 45003,
		"length": 7,
		"enterprise_number": 9,
		"data": [3, 0, 0, 53, 52, 5, 133]
	},
	{
		"name": "flowStartSysUpTime",
		"type": 22,
		"length": 4,
		"data": [0, 0, 0, 1]
	},
	{
		"name": "flowEndSysUpTime",
		"type": 21,
		"length": 4,
		"data": [0, 0, 0, 10]
	},
	{
		"name": "flowStartMilliseconds",
		"type": 152,
		"length": 8,
		"data": [0, 0, 0, 0, 0, 0, 0, 0]
	},
	{
		"name": "responderPackets",
		"type": 299,
		"length": 8,
		"data": [0, 0, 0, 0, 0, 0, 0, 1]
	},
	{
		"name": "initiatorPackets",
		"type": 298,
		"length": 8,
		"data": [0, 0, 0, 0, 0, 0, 0, 1]
	},
	{
		"name": "serverBytesL3",
		"type": 41105,
		"length": 8,
		"enterprise_number": 9,
		"data": [0, 0, 0, 0, 0, 0, 0, 127]
	},
	{
		"name": "clientBytesL3",
		"type": 41106,
		"length": 8,
		"enterprise_number": 9,
		"data": [0, 0, 0, 0, 0, 0, 0, 127]
	}`
}

// Returns Template 261
func getTemplate261(params *TemplateParams) string {
	return fmt.Sprintf(`
	{
		"name": "261",
		"auto_start": %v,
		"rate_pps": %v,
		"data_records_num": %d,
		"template_id": 261,
		"is_options_template": %v,
		"scope_count": %v,
		"fields": [%s]
	}`, params.autoStart, params.rate, params.recordsNum, params.optionsTemplate, params.scopeCount, getTemplate261Fields())
}

// Returns Template 266
func getTemplate266(params *TemplateParams) string {
	return fmt.Sprintf(`
	{
		"name": "266",
		"auto_start": %v,
		"rate_pps": %v,
		"data_records_num": %d,
		"template_id": 266,
		"is_options_template": %v,
		"scope_count": %v,
		"fields": [
			{
				"name": "clientIPv4Address",
				"type": 45004,
				"length": 4,
				"enterprise_number": 9,
				"data": [16, 0, 0, 1]
			},
			{
				"name": "serverIPv4Address",
				"type": 45005,
				"length": 4,
				"enterprise_number": 9,
				"data": [24, 0, 0, 1]
			},
			{
				"name": "ipVersion"
				"type": 60,
				"length": 1,
				"data": [4]
			},
			{
				"name": "protocolIdentifier",
				"type": 4,
				"length": 1,
				"data": [17]
			},
			{
				"name": "serverTransportProtocol",
				"type": 45009,
				"length": 2,
				"enterprise_number": 9,
				"data": [0, 53]
			},
			{
				"name": "ingressVRFID",
				"type": 234,
				"length": 4,
				"data": [0, 0, 0, 255]
			},
			{
				"name": "biflowDirection",
				"type": 239,
				"length": 1,
				"data": [1]
			},
			{
				"name": "observationPointId",
				"type": 138,
				"length": 8,
				"data": [0, 0, 0, 0, 0, 0, 30, 97]
			},
			{
				"name": "applicationId",
				"type": 95,
				"length": 4,
				"data": [3, 0, 0, 53]
			},
			{
				"name": "flowDirection",
				"type": 61,
				"length": 1,
				"data": [1]
			},
			{
				"name": "flowStartMilliseconds",
				"type": 152,
				"length": 8,
				"data": [0, 0, 0, 0, 0, 0, 0, 0]
			},
			{
				"name": "flowEndMilliseconds",
				"type": 153,
				"length": 8,
				"data": [0, 0, 0, 0, 0, 0, 100, 255]
			},
			{
				"name": "newConnectionDeltaCount",
				"type": 278,
				"length": 4,
				"data": [0, 0, 0, 5]
			},
			{
				"name": "numRespsCountDelta",
				"type": 42060,
				"length": 4,
				"enterprise_number": 9,
				"data": [0, 0, 0, 3]
			},
			{
				"name": "sumServerNwkTime",
				"type": 42087,
				"length": 4,
				"enterprise_number": 9,
				"data": [0, 0, 0, 255]
			},
			{
				"name": "retransPackets",
				"type": 42036,
				"length": 4,
				"enterprise_number": 9,
				"data": [0, 0, 12, 255]
			},
			{
				"name": "sumNwkTime",
				"type": 42081,
				"length": 4,
				"enterprise_number": 9,
				"data": [0, 0, 2, 200]
			},
			{
				"name": "sumServerRespTime",
				"type": 42074,
				"length": 4,
				"enterprise_number": 9,
				"data": [0, 0, 0, 10]
			},
			{
				"name": "responderPackets",
				"type": 299,
				"length": 8,
				"data": [0, 0, 0, 0, 0, 0, 0, 1]
			},
			{
				"name": "initiatorPackets",
				"type": 298,
				"length": 8,
				"data": [0, 0, 0, 0, 0, 0, 0, 1]
			},
			{
				"name": "ARTServerRetransmissionsPackets",
				"type": 42038,
				"length": 4,
				"enterprise_number": 9,
				"data": [0, 0, 0, 5]
			},
			{
				"name": "serverBytesL3",
				"type": 41105,
				"length": 8,
				"enterprise_number": 9,
				"data": [0, 0, 0, 0, 0, 0, 0, 127]
			},
			{
				"name": "clientBytesL3",
				"type": 41106,
				"length": 8,
				"enterprise_number": 9,
				"data": [0, 0, 0, 0, 0, 0, 0, 127]
			}
		]
	}`, params.autoStart, params.rate, params.recordsNum, params.optionsTemplate, params.scopeCount)
}

/* Tests */

func TestPluginIPFixNeg1(t *testing.T) {
	// Both IPv4 and IPv6 specified for collector.
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       2,
		recordsNum: 7,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfixNeg1",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{invalidDst: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg2(t *testing.T) {
	// No IPv4 or IPv6 specified for collector.
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       2,
		recordsNum: 7,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "2001::1:80",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfixNeg2",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{invalidDst: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg3(t *testing.T) {
	// Invalid Json
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       2,
		recordsNum: 1,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48, 0, 0, 0
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfixNeg3",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{badOrNoInitJson: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg4(t *testing.T) {
	// No auto start
	templateParams := TemplateParams{
		autoStart:  false,
		rate:       1,
		recordsNum: 1,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfixNeg4",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg5(t *testing.T) {

	a := &IPFixTestBase{
		testname:     "ipfixNeg5",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(`{}`)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{badOrNoInitJson: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg6(t *testing.T) {
	// Duplicate Name
	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "266",
				"auto_start": true,
				"rate_pps": 2.0,
				"data_records_num": 5,
				"template_id": 266,
				"fields":
				[
					{
						"name": "clientIPv4Address",
						"type": 45004,
						"length": 4,
						"enterprise_number": 9,
						"data": [16, 0, 0, 1]
					}
				]
			},
			{
				"name": "266",
				"auto_start": true,
				"rate_pps": 1.0,
				"data_records_num": 1,
				"template_id": 266,
				"fields": 
				[
					{
						"name": "clientIPv4Address",
						"type": 45004,
						"length": 4,
						"enterprise_number": 9,
						"data": [16, 0, 0, 1]
					}
				]
			}
		]
	}`)

	a := &IPFixTestBase{
		testname:     "ipfixNeg6",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{pktTempSent: 11, pktDataSent: 21, failedCreatingGen: 1, duplicateGenName: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg7(t *testing.T) {
	// Invalid engine name. Packets will still keep running but not modified by the engine.
	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "266",
				"auto_start": true,
				"rate_pps": 2.0,
				"data_records_num": 5,
				"template_id": 266,
				"fields":
				[
					{
						"name": "clientIPv4Address",
						"type": 45004,
						"length": 4,
						"enterprise_number": 9,
						"data": [16, 0, 0, 1]
					}
				],
				"engines": [
					{
						"engine_name": "nonExistant",
						"engine_type": "uint",
						"params": {
							"size": 1,
							"offset": 0,
							"min": 0,
							"max": 5,
							"op": "inc",
							"step": 1
						}
					}
				]
			}
		]
	}`)

	a := &IPFixTestBase{
		testname:     "ipfixNeg7",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{pktTempSent: 11, pktDataSent: 21, invalidEngineName: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg8(t *testing.T) {
	// Duplicate Template ID
	initJson := fmt.Sprintf(`
				{
					"netflow_version": 10,
					"dst": "48.0.0.0:4739",
					"domain_id": 7777,
					"generators": [
						{
							"name": "a",
							"auto_start": true,
							"rate_pps": 2.0,
							"data_records_num": 5,
							"template_id": 266,
							"fields":
							[
								{
									"name": "clientIPv4Address",
									"type": 45004,
									"length": 4,
									"enterprise_number": 9,
									"data": [16, 0, 0, 1]
								}
							]
						},
						{
							"name": "b",
							"auto_start": true,
							"rate_pps": 1.0,
							"data_records_num": 1,
							"template_id": 266,
							"fields": 
							[
								{
									"name": "clientIPv4Address",
									"type": 45004,
									"length": 4,
									"enterprise_number": 9,
									"data": [16, 0, 0, 1]
								}
							]
						}
					]
				}`)

	a := &IPFixTestBase{
		testname:     "ipfixNeg8",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{pktTempSent: 11, pktDataSent: 21, failedCreatingGen: 1, duplicateTemplateID: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg9(t *testing.T) {
	// Field length is different from data provided.
	initJson := fmt.Sprintf(`
				{
					"netflow_version": 10,
					"dst": "48.0.0.0:4739",
					"domain_id": 7777,
					"generators": [
						{
							"name": "a",
							"auto_start": true,
							"rate_pps": 2.0,
							"data_records_num": 5,
							"template_id": 266,
							"fields":
							[
								{
									"name": "clientIPv4Address",
									"type": 45004,
									"length": 3,
									"enterprise_number": 9,
									"data": [16, 0, 0, 1]
								}
							]
						}
					]
				}`)

	a := &IPFixTestBase{
		testname:     "ipfixNeg9",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{failedCreatingGen: 1, dataIncorrectLength: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg10(t *testing.T) {
	// Options template without scope count.
	templateParams := TemplateParams{
		autoStart:       true,
		rate:            2,
		recordsNum:      1,
		optionsTemplate: true,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfixNeg10",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{invalidScopeCount: 1, failedCreatingGen: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg11(t *testing.T) {
	// Invalid Template ID

	initJson := `
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 22,
		"generators": [
			{
				"name": "a",
				"auto_start": true,
				"rate_pps": 2.0,
				"data_records_num": 5,
				"template_id": 255,
				"fields":
				[
					{
						"name": "clientIPv4Address",
						"type": 45004,
						"length": 4,
						"enterprise_number": 9,
						"data": [16, 0, 0, 1]
					}
				]
			}
		]
	}
	`

	a := &IPFixTestBase{
		testname:     "ipfixNeg11",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{invalidTemplateID: 1, failedCreatingGen: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg12(t *testing.T) {
	// Enterprise field with v9

	initJson := `
	{
		"netflow_version": 9,
		"dst": "48.0.0.0:4739",
		"domain_id": 22,
		"generators": [
			{
				"name": "a",
				"auto_start": true,
				"rate_pps": 2.0,
				"data_records_num": 5,
				"template_id": 260,
				"fields":
				[
					{
						"name": "nbar2HttpHost",
						"type": 45003,
						"length": 65535,
						"enterprise_number": 9,
					}
				]
			}
		]
	}
	`

	a := &IPFixTestBase{
		testname:     "ipfixNeg12",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{enterpriseFieldv9: 1, failedCreatingGen: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg13(t *testing.T) {
	// Variable length with data

	initJson := `
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 22,
		"generators": [
			{
				"name": "a",
				"auto_start": true,
				"rate_pps": 2.0,
				"data_records_num": 5,
				"template_id": 260,
				"fields":
				[
					{
						"name": "nbar2HttpHost",
						"type": 45003,
						"length": 65535,
						"enterprise_number": 9,
						"data": [3, 5]
					}
				]
			}
		]
	}
	`

	a := &IPFixTestBase{
		testname:     "ipfixNeg13",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{dataIncorrectLength: 1, failedCreatingGen: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFixNeg14(t *testing.T) {
	// Variable length without engine

	initJson := `
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 22,
		"generators": [
			{
				"name": "a",
				"auto_start": true,
				"rate_pps": 2.0,
				"data_records_num": 5,
				"template_id": 260,
				"fields":
				[
					{
						"name": "nbar2HttpHost",
						"type": 45003,
						"length": 65535,
						"enterprise_number": 9,
						"data": []
					},
					{
						"name": "protocolIdentifier",
						"type": 4,
						"length": 1,
						"data": [17]
					}
				],
				"engines": [
					{
						"engine_name": "protocolIdentifier",
						"engine_type": "uint_list",
						"params": {
							"size": 1,
							"offset": 0,
							"list": [6, 17],
							"op": "inc"
						}
					}
				]
			}
		]
	}
	`

	a := &IPFixTestBase{
		testname:     "ipfixNeg14",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		counters:     IPFixStats{variableLengthNoEngine: 1, failedCreatingGen: 1},
	}
	a.Run(t, true)
}

func TestPluginIPFix1(t *testing.T) {
	// DNS Generator - 7 Records in One Data Packet with 2 Data packets per second
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       2,
		recordsNum: 7,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfix1",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix2(t *testing.T) {
	// DNS - Generator 7 Records in One Data Packet with 2 Data packets per second but IPv6
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       2,
		recordsNum: 7,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "[2001:db8::2]:4739",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfix2",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		clientIpv6: core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	a.Run(t, true)
}

func TestPluginIPFix3(t *testing.T) {
	// Maximum Records allowed by MTU and rate of 1.
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       1,
		recordsNum: 0,
	}
	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfix3",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix4(t *testing.T) {
	// Bigger than possible number of records.
	// This will send only template packets.
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       1,
		recordsNum: 255,
	}
	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [%s]
	}
	`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfix4",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix5(t *testing.T) {
	// V9 with 0.5 data rate and IANA fields only.

	a := &IPFixTestBase{
		testname: "ipfix5",
		dropAll:  false,
		monitor:  true,
		match:    0,
		capture:  true,
		initJSON: [][]byte{[]byte(`
		{
			"netflow_version": 9,
			"dst": "48.0.0.0:4739",
			"domain_id": 7777,
			"generators": [
				{
					"name": "dns",
					"auto_start": true,
					"rate_pps": 0.5,
					"data_records_num": 1,
					"template_id": 261,
					"fields": [
						{
							"name": "protocolIdentifier",
							"type": 4,
							"length": 1,
							"data": [17]
						},
						{
							"name": "applicationId",
							"type": 95,
							"length": 4,
							"data": [3, 0, 0, 53]
						},
						{
							"name": "flowStartSysUpTime",
							"type": 22,
							"length": 4,
							"data": [0, 0, 0, 1]
						},
						{
							"name": "flowEndSysUpTime",
							"type": 21,
							"length": 4,
							"data": [0, 0, 0, 10]
						},
						{
							"name": "flowStartMilliseconds",
							"type": 152,
							"length": 8,
							"data": [0, 0, 0, 0, 0, 0, 0, 0]
						},
						{
							"name": "responderPackets",
							"type": 299,
							"length": 8,
							"data": [0, 0, 0, 0, 0, 0, 0, 1]
						},
						{
							"name": "initiatorPackets",
							"type": 298,
							"length": 8,
							"data": [0, 0, 0, 0, 0, 0, 0, 1]
						}
					]
				}
			]
		}
		`)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix6(t *testing.T) {
	// multiple generators
	template261Params := TemplateParams{
		autoStart:  true,
		rate:       1,
		recordsNum: 1,
	}

	template266Params := TemplateParams{
		autoStart:  true,
		rate:       0.5,
		recordsNum: 1,
	}

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [%s, %s]
	}
	`, getTemplate261(&template261Params), getTemplate266(&template266Params))

	a := &IPFixTestBase{
		testname:     "ipfix6",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix7(t *testing.T) {
	// multiple generators v9 with max MTU
	initJson := `
	{
		"netflow_version": 9,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "261",
				"auto_start": true,
				"rate_pps": 1,
				"data_records_num": 0,
				"template_id": 261,
				"fields": [
					{
						"name": "protocolIdentifier",
						"type": 4,
						"length": 1,
						"data": [17]
					}
				]
			},
			{
				"name": "266"
				"auto_start": true,
				"rate_pps": 2,
				"data_records_num": 0,
				"template_id": 266,
				"fields": [
					{
						"name": "ipVersion",
						"type": 60,
						"length": 1,
						"data": [4]
					}
				]
			}
		]
	}`

	a := &IPFixTestBase{
		testname:     "ipfix7",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix8(t *testing.T) {
	// Engines introduced.
	// clientIPv4Address record values ranges in [16.0.0.1 - 16.0.0.255]
	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "261",
				"auto_start": true,
				"rate_pps": 1,
				"data_records_num": 0,
				"template_id": 261,
				"fields": [%s],
				"engines": [
					{
						"engine_name": "clientIPv4Address",
						"engine_type": "uint",
						"params":
						{
							"size": 1,
							"offset": 3,
							"min": 1,
							"max": 255,
							"op": "inc",
							"step": 1,
						}
					}
				]
			}
		]
	}
	`, getTemplate261Fields())

	a := &IPFixTestBase{
		testname:     "ipfix8",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix9(t *testing.T) {
	// Multiple engines and one generator
	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "261",
				"auto_start": true,
				"rate_pps": 1,
				"data_records_num": 1,
				"template_id": 261,
				"fields": [%s],
				"engines": [
					{
						"engine_name": "clientIPv4Address",
						"engine_type": "uint",
						"params":
						{
							"size": 1,
							"offset": 3,
							"min": 1,
							"max": 255,
							"op": "inc",
							"step": 1,
						}
					},
					{
						"engine_name": "initiatorPackets",
						"engine_type": "uint",
						"params":
						{
							"size": 4,
							"offset": 4,
							"min": 0,
							"max": 2147483647,
							"op": "rand"
						}
					},
					{
						"engine_name": "responderPackets",
						"engine_type": "uint",
						"params":
						{
							"size": 1,
							"offset": 0,
							"min": 2,
							"max": 6,
							"op": "dec",
							"step": 2
						}
					}
				]
			}
		]
	}
	`, getTemplate261Fields())

	a := &IPFixTestBase{
		testname:     "ipfix9",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0xc15c0c15c0,
	}
	a.Run(t, true)
}

func TestPluginIPFix10(t *testing.T) {
	// Multiple engines v9 with IPv6
	// 5/9 UDP, 3/9 UDP, 1/9 - ICMP
	// Selector ID odd or even with 50%.
	// Initiator packets large with uint64 range.
	initJson := `
	{
		"netflow_version": 9,
		"dst": "[2001:db8::2]:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "v9Bes",
				"auto_start": true,
				"rate_pps": 1,
				"data_records_num": 1,
				"template_id": 262,
				"fields": [
					{
						"name": "protocolIdentifier",
						"type": 4,
						"length": 1,
						"data": [17]
					},
					{
						"name": "applicationId",
						"type": 95,
						"length": 4,
						"data": [3, 0, 0, 53]
					},
					{
						"name": "flowStartSysUpTime",
						"type": 22,
						"length": 4,
						"data": [0, 0, 0, 1]
					},
					{
						"name": "flowEndSysUpTime",
						"type": 21,
						"length": 4,
						"data": [0, 0, 0, 10]
					},
					{
						"name": "flowStartMilliseconds",
						"type": 152,
						"length": 8,
						"data": [0, 0, 0, 0, 0, 0, 0, 0]
					},
					{
						"name": "responderPackets",
						"type": 299,
						"length": 8,
						"data": [0, 0, 0, 0, 0, 0, 0, 1]
					},
					{
						"name": "initiatorPackets",
						"type": 298,
						"length": 8,
						"data": [0, 0, 0, 0, 0, 0, 0, 1]
					}
				],
				"engines": [
					{
						"engine_name": "protocolIdentifier",
						"engine_type": "histogram_uint",
						"params":
						{
							"size": 1,
							"offset": 0,
							"entries": [
								{
									"v": 17,
									"prob": 5
								},
								{
									"v": 1,
									"prob": 1,
								},
								{
									"v": 6,
									"prob": 3
								}
							]
						}
					},
					{
						"engine_name": "applicationId",
						"engine_type": "histogram_uint_list",
						"params":
						{
							"size": 1,
							"offset": 3,
							"entries": [
								{
									"list": [0, 2, 4, 6, 8],
									"prob": 1
								},
								{
									"list": [1, 3, 5, 7, 9],
									"prob": 1
								}
							]
						}
					},
					{
						"engine_name": "initiatorPackets",
						"engine_type": "histogram_uint64_range",
						"params":
						{
							"size": 8,
							"offset": 0,
							"entries": [
								{
									"min": 0,
									"max": 4294967295,
									"prob": 1
								},
								{
									"min": 4294967296,
									"max": 8589934591,
									"prob": 1
								}
							]
						}
					}
				]
			}
		]
	}`

	a := &IPFixTestBase{
		testname:     "ipfix10",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		clientIpv6: core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		seed: 0xbe5be5,
	}
	a.Run(t, true)
}

func TestPluginIPFix11(t *testing.T) {
	// Multiple generators with field engine.
	// First Generator has only protocol field, TCP(6) or UDP(17) with prob 0.66 vs ICMP with prob 0.33
	// meaning all three have 1/3 prob.
	// Second Generator has only IP version field, v4 with 75% and v6 with 25%.
	initJson := `
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "261",
				"auto_start": true,
				"rate_pps": 1,
				"data_records_num": 2,
				"template_id": 261,
				"fields": [
					{
						"name": "protocolIdentifier",
						"type": 4,
						"length": 1,
						"data": [17]
					}
				],
				"engines": [
					{
						"engine_name": "protocolIdentifier",
						"engine_type": "histogram_uint_list",
						"params": {
							"size": 1,
							"offset": 0,
							"entries": [
								{
									"list": [17, 6],
									"prob": 2
								},
								{
									"list": [1],
									"prob": 1
								}
							]
						}
					}
				]
			},
			{
				"name": "266"
				"auto_start": true,
				"rate_pps": 0.5,
				"data_records_num": 5,
				"template_id": 266,
				"fields": [
					{
						"name": "ipVersion",
						"type": 60,
						"length": 1,
						"data": [4]
					}
				],
				"engines": [
					{
						"engine_name": "ipVersion",
						"engine_type": "histogram_uint",
						"params": {
							"size": 1,
							"offset": 0,
							"entries": [
								{
									"v": 4,
									"prob": 3,
								},
								{
									"v": 6
									"prob": 1,
								}
							]
						}
					}
				]
			}
		]
	}`

	a := &IPFixTestBase{
		testname:     "ipfix11",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0xdeadbeef,
	}
	a.Run(t, true)
}

type IPFixQueryCtx struct {
	tctx  *core.CThreadCtx
	timer core.CHTimerObj
	cnt   uint16
	match uint8
}

func Cb1(tctx *core.CThreadCtx, test *IPFixTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(5 * time.Second)
	var ipfixCtx IPFixQueryCtx
	ipfixCtx.match = test.match
	ipfixCtx.cnt = 0xabcd
	ipfixCtx.timer.SetCB(&ipfixCtx, test.cbArg1, test.cbArg2)
	ipfixCtx.tctx = tctx
	timerw.StartTicks(&ipfixCtx.timer, ticks)
	return 0
}

func (o *IPFixQueryCtx) OnEvent(a, b interface{}) {
	if o.match == 12 {
		if o.cnt == 0xabcd {
			o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0",
			"method":"ipfix_c_set_gen_state",
			"params": {"tun": {"vport":1}, "mac": [0, 0, 1, 0, 0, 0], "enable": false, "rate": 3, "gen_name": "261"},
			"id": 3}`))
			o.cnt += 1
			timerw := o.tctx.GetTimerCtx()
			ticks := timerw.DurationToTicks(time.Duration(3 * time.Second))
			timerw.StartTicks(&o.timer, ticks)
		} else if o.cnt == 0xabce {
			o.tctx.Veth.AppendSimuationRPC([]byte(`{"jsonrpc": "2.0",
			"method":"ipfix_c_set_gen_state",
			"params": {"tun": {"vport":1}, "mac": [0, 0, 1, 0, 0, 0], "enable": true, "rate": 2, "gen_name": "261"},
			"id": 3}`))
		}
	} else if o.match == 13 {
		rpc := `{"jsonrpc": "2.0",
		"method":"ipfix_c_get_gens_info",
		"params": {"tun": {"vport":1}, "mac": [0, 0, 1, 0, 0, 0], "gen_names": ["261", "266"]},
		"id": 3}`
		if o.cnt == 0xabcd {
			o.tctx.Veth.AppendSimuationRPC([]byte(rpc))
			o.cnt += 1
			timerw := o.tctx.GetTimerCtx()
			ticks := timerw.DurationToTicks(time.Duration(3 * time.Second))
			timerw.StartTicks(&o.timer, ticks)
		} else if o.cnt == 0xabce {
			o.tctx.Veth.AppendSimuationRPC([]byte(rpc))
		}
	}

}

func TestPluginIPFix12(t *testing.T) {
	// Test RPC functions.
	// DNS Generator - 7 Records in One Data Packet with 2 Data packets per second
	// Start with 1 pps for 5 seconds, stop for 3 seconds and continue with 2 pps
	templateParams := TemplateParams{
		autoStart:  true,
		rate:       1,
		recordsNum: 1,
	}

	initJson := fmt.Sprintf(`
		{
			"netflow_version": 10,
			"dst": "48.0.0.0:4739",
			"domain_id": 7777,
			"generators": [%s]
		}
		`, getTemplate261(&templateParams))

	a := &IPFixTestBase{
		testname:     "ipfix12",
		dropAll:      false,
		monitor:      true,
		match:        12,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     15 * time.Second,
		clientsToSim: 1,
		cb:           Cb1,
	}
	a.Run(t, true)

}

func TestPluginIPFix13(t *testing.T) {
	// Test RPC functions.
	// Try with two templates and get their info.
	template261Params := TemplateParams{
		autoStart:  true,
		rate:       1,
		recordsNum: 1,
	}

	template266Params := TemplateParams{
		autoStart:  true,
		rate:       2,
		recordsNum: 2,
	}

	initJson := fmt.Sprintf(`
		{
			"netflow_version": 10,
			"dst": "48.0.0.0:4739",
			"domain_id": 7777,
			"generators": [%s, %s]
		}
		`, getTemplate261(&template261Params), getTemplate266(&template266Params))

	a := &IPFixTestBase{
		testname:     "ipfix13",
		dropAll:      false,
		monitor:      true,
		match:        13,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		cb:           Cb1,
	}
	a.Run(t, true)
}

func TestPluginIPFix14(t *testing.T) {
	// Test RPC functions.
	// Special Test to verify that it resolves the MAC.
	template261Params := TemplateParams{
		autoStart:  true,
		rate:       1,
		recordsNum: 1,
	}

	initJson := fmt.Sprintf(`
		{
			"netflow_version": 10,
			"dst": "48.0.0.0:4739",
			"generators": [%s]
		}
		`, getTemplate261(&template261Params))

	a := &IPFixTestBase{
		testname:     "ipfix14",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix15(t *testing.T) {
	// Big Data Rate to see burts

	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 7777,
		"generators": [
			{
				"name": "261",
				"auto_start": true,
				"rate_pps": 200,
				"data_records_num": 1,
				"template_id": 261,
				"fields": [%s],
				"engines": [
					{
						"engine_name": "clientIPv4Address",
						"engine_type": "uint",
						"params":
						{
							"size": 1,
							"offset": 3,
							"min": 1,
							"max": 255,
							"op": "inc",
							"step": 1,
						}
					}
				]
			}
		]
	}
	`, getTemplate261Fields())

	a := &IPFixTestBase{
		testname:     "ipfix15",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginIPFix16(t *testing.T) {
	// Options Template and Data Template v10

	initJson := fmt.Sprintf(`
		{
			"netflow_version": 10,
			"dst": "48.0.0.0:4739",
			"domain_id": 2358,
			"generators": [
				{
					"name": "261",
					"auto_start": true,
					"rate_pps": 1,
					"data_records_num": 0,
					"template_id": 261,
					"is_options_template": true,
					"scope_count": 7,
					"fields": [%s],
					"engines": [
						{
							"engine_name": "applicationId",
							"engine_type": "uint",
							"params": {
								"size": 2,
								"offset": 2,
								"op": "rand",
								"min": 20,
								"max": 50000
							}
						}
					]
				},
				{
					"name": "bes",
					"auto_start": true,
					"rate_pps": 0.2,
					"data_records_num": 7,
					"template_id": 256,
					"fields": [
						{
							"name": "sumServerRespTime",
							"type": 42074,
							"length": 4,
							"enterprise_number": 9,
							"data": [0, 0, 0, 10]
						},
						{
							"name": "serverTransportProtocol",
							"type": 45009,
							"length": 2,
							"enterprise_number": 9,
							"data": [0, 53]
						}
					],
					"engines": [
						{
							"engine_name": "serverTransportProtocol",
							"engine_type": "histogram_uint_list",
							"params": {
								"size": 1,
								"offset": 1,
								"entries": [
									{
										"list": [53],
										"prob": 5
									},
									{
										"list": [67, 68],
										"prob": 4
									},
									{
										"list": [20, 21],
										"prob": 5
									}
								]
							}
						}
					]
				}
			]
		}
		`, getTemplate261Fields())

	a := &IPFixTestBase{
		testname:     "ipfix16",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0x23581321,
	}
	a.Run(t, true)
}

func TestPluginIPFix17(t *testing.T) {
	// Options Template and Data Template v9
	initJson := `
		{
			"netflow_version": 9,
			"dst": "48.0.0.0:4739",
			"domain_id": 6,
			"generators": [
				{
					"name": "275",
					"auto_start": true,
					"rate_pps": 1,
					"data_records_num": 5,
					"template_id": 275,
					"is_options_template": true,
					"scope_count": 1,
					"fields": [
						{
							"name": "interface",
							"type": 2,
							"length": 2,
							"data": [0, 2]
						},
						{
							"name": "samplingInterval",
							"type": 34,
							"length": 2,
							"data": [0, 100]
						},
						{
							"name": "samplingAlgorithm",
							"type": 35,
							"length": 1,
							"data": [1]
						}
					],
					"engines": [
						{
							"engine_name": "interface",
							"engine_type": "uint",
							"params": {
								"size": 1,
								"offset": 1,
								"min": 1,
								"max": 24,
								"op": "dec",
								"step": 2
							}
						}
					]
				}, 
				{
					"name": "270",
					"auto_start": true,
					"rate_pps": 5,
					"data_records_num": 1,
					"template_id": 270,
					"fields": [
						{
							"name": "icmpType",
							"type": 32,
							"length": 2,
							"data": [1, 1]
						},
						{
							"name": "minPktLength",
							"type": 25,
							"length": 2,
							"data": [5, 255]
						},
						{
							"name": "minTTL",
							"type": 52,
							"length": 1,
							"data": [50]
						}
					],
					"engines": [
						{
							"engine_name": "minTTL",
							"engine_type": "histogram_uint",
							"params": {
								"size": 1,
								"offset": 0,
								"entries": [
									{
										"v": 64,
										"prob": 1
									},
									{
										"v": 128,
										"prob": 2
									},
									{
										"v": 192,
										"prob": 5
									}
								]
							}
						}
					]
				}
			]
		}
		`

	a := &IPFixTestBase{
		testname:     "ipfix17",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0xbdbdbd,
	}
	a.Run(t, true)
}

func getVariableLengthJson(rate float32, data_records_num uint16) string {
	initJson := fmt.Sprintf(`
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 6,
		"generators": [
			{
				"name": "275",
				"auto_start": true,
				"rate_pps": %v,
				"data_records_num": %v,
				"template_id": 275,
				"fields": [
					{
						"name": "protocolIdentifier",
						"type": 4,
						"length": 1,
						"data": [17]
					},
					{
						"name": "nbar2HttpHost",
						"type": 45003,
						"length": 65535,
						"enterprise_number": 9
					},
					{
						"name": "nbar2HttpHost2",
						"type": 45003,
						"length": 65535,
						"enterprise_number": 9
					},
					{
						"name": "flowStartMilliseconds",
						"type": 152,
						"length": 8,
						"data": [0, 0, 0, 0, 0, 0, 0, 0]
					},
					{
						"name": "flowEndMilliseconds",
						"type": 153,
						"length": 8,
						"data": [0, 0, 0, 0, 0, 0, 100, 255]
					},
					{
						"name": "ipVersion",
						"type": 60,
						"length": 1,
						"data": [4]
					}
				],
				"engines": [
					{
						"engine_name": "protocolIdentifier",
						"engine_type": "uint_list",
						"params": {
							"size": 1,
							"offset": 1,
							"list": [1, 6, 17],
							"op": "dec",
						}
					},
					{
						"engine_name": "nbar2HttpHost",
						"engine_type": "histogram_url",
						"params": {
							"size": 60,
							"offset": 0,
							"entries": [
								{
									"schemes": ["https"],
									"hosts": ["www.google.com", "www.facebook.com"],
									"prob": 2,
								},
								{
									"schemes": ["http"],
									"hosts": ["cisco.com"],
									"paths": ["en", "il", "en/careers"],
									"prob": 5
								}
							]
						}
					},
					{
						"engine_name": "nbar2HttpHost2",
						"engine_type": "histogram_url",
						"params": {
							"size": 60,
							"offset": 0,
							"entries": [
								{
									"schemes": ["https"],
									"hosts": ["stackoverflow.com"],
									"random_queries": true,
									"prob": 4,
								}
							]
						}
					},
					{
						"engine_type": "time_start",
						"engine_name": "flowStartMilliseconds",
						"params": {
							"size": 8,
							"offset": 0,
							"time_end_engine_name": "flowEndMilliseconds",
							"time_offset": 1257894000000,
							"ipg_min": 20000,
							"ipg_max": 20000
						}
					},
					{
						"engine_type": "time_end",
						"engine_name": "flowEndMilliseconds",
						"params": {
							"size": 8,
							"offset": 0,
							"time_start_engine_name": "flowStartMilliseconds",
							"duration_min": 5000,
							"duration_max": 10000
						}
					}
				]
			}
		]
	}
	`, rate, data_records_num)
	return initJson
}

func TestPluginIPFix18(t *testing.T) {
	// Variable length with Time engines.
	// The timestamp offset is set fixed simply because this is a simulation
	// and we need the test to pass all the time.
	// Simple version without max records calculated.
	initJson := getVariableLengthJson(20, 3)

	a := &IPFixTestBase{
		testname:     "ipfix18",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0xbe5be5,
	}
	a.Run(t, true)
}

func TestPluginIPFix19(t *testing.T) {
	// Variable length with Time engines.
	// The timestamp offset is set fixed simply because this is a simulation
	// and we need the test to pass all the time.
	// Simple version without max records calculated.
	// Maximum records

	initJson := getVariableLengthJson(1, 0)

	a := &IPFixTestBase{
		testname:     "ipfix19",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0xbe5be5,
	}
	a.Run(t, true)
}

func TestPluginIPFix20(t *testing.T) {
	// Variable length with Time engines.
	// The timestamp offset is set fixed simply because this is a simulation
	// and we need the test to pass all the time.
	// Simple version without max records calculated.
	// Maximum records with misses

	initJson := getVariableLengthJson(1, 255)

	a := &IPFixTestBase{
		testname:     "ipfix20",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0xc15c0be51,
	}
	a.Run(t, true)
}

func TestPluginIPFix21(t *testing.T) {
	// Variable length with Time engines.
	// The timestamp offset is set fixed simply because this is a simulation
	// and we need the test to pass all the time.
	// Simple version without max records calculated.
	// 1 record with bursts

	initJson := getVariableLengthJson(200, 1)

	a := &IPFixTestBase{
		testname:     "ipfix21",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     5 * time.Second,
		clientsToSim: 1,
		seed:         0xc15c0be51,
	}
	a.Run(t, true)
}

func TestPluginIPFix22(t *testing.T) {

	// long variable length fields
	initJson := `
	{
		"netflow_version": 10,
		"dst": "48.0.0.0:4739",
		"domain_id": 6,
		"generators": [
			{
				"name": "275",
				"auto_start": true,
				"rate_pps": 2,
				"data_records_num": 3,
				"template_id": 275,
				"fields": [
					{
						"name": "protocolIdentifier",
						"type": 4,
						"length": 1,
						"data": [17]
					},
					{
						"name": "nbar2HttpHost",
						"type": 45003,
						"length": 65535,
						"enterprise_number": 9
					},
					{
						"name": "ipVersion",
						"type": 60,
						"length": 1,
						"data": [4]
					}
				],
				"engines": [
					{
						"engine_name": "nbar2HttpHost",
						"engine_type": "histogram_url",
						"params": {
							"size": 450,
							"offset": 0,
							"entries": [
								{
									"schemes": ["https"],
									"hosts": ["stackoverflow.com"],
									"random_queries": true,
									"prob": 4,
								}
							]
						}
					}
				]
			}
		]
	}
	`
	a := &IPFixTestBase{
		testname:     "ipfix22",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON:     [][]byte{[]byte(initJson)},
		duration:     10 * time.Second,
		clientsToSim: 1,
		seed:         0xc15c0be51,
	}
	a.Run(t, true)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
