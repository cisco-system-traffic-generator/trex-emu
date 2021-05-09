// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package appsim

import (
	"emu/core"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/intel-go/fastjson"
)

var monitor int
var emu_debug int

type TransimTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           TransimTestCb
	cbArg1       interface{}
	cbArg2       interface{}
	c_json       []byte
	ns_json      []byte
}

type TransimTestCb func(tctx *core.CThreadCtx, test *TransimTestBase) int

func (o *TransimTestBase) Run(t *testing.T) {

	var simVeth VethIgmpSim
	simVeth.DropAll = o.dropAll
	var simrx core.VethIFSim
	simrx = &simVeth
	if o.match > 0 {
		simVeth.match = o.match
	}
	tctx, _ := createSimulationEnv(&simrx, o.clientsToSim, o)
	if o.cb != nil {
		o.cb(tctx, o)
	}
	m := false
	if monitor > 0 {
		m = true
	}
	simVeth.tctx = tctx
	tctx.Veth.SetDebug(m, os.Stdout, o.capture)
	tctx.MainLoopSim(o.duration)
	defer tctx.Delete()
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})

	ns := tctx.GetNs(&key)
	if ns == nil {
		t.Fatalf(" can't find ns")
		return
	}
	c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, 0, 1})
	nsplg := c.PluginCtx.Get(APPSIM_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	cPlug := nsplg.Ext.(*PluginAppsimClient)
	cPlug.cdbv.Dump()
	tctx.GetCounterDbVec().Dump()

	//tctx.SimRecordAppend(igmpPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int, test *TransimTestBase) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)

	tctx.AddNs(&key, ns)

	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 1},
		core.Ipv4Key{16, 0, 0, 1},
		core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 16, 0x00, 0x00, 0x01},
		core.Ipv4Key{16, 0, 0, 2})
	client.ForceDGW = true
	client.Ipv4ForcedgMac = core.MACKey{0, 0, 1, 0, 0, 2}
	client.Ipv6ForceDGW = true
	client.Ipv6ForcedgMac = client.Ipv4ForcedgMac

	ns.AddClient(client)
	ns_json := make([][]byte, 0)
	if test.ns_json != nil {
		ns_json = append(ns_json, test.ns_json)
	}
	ns.PluginCtx.CreatePlugins([]string{APPSIM_PLUG}, ns_json)

	cs_json := make([][]byte, 0)
	if test.c_json != nil {
		cs_json = append(cs_json, test.c_json)
	}

	client.PluginCtx.CreatePlugins([]string{APPSIM_PLUG}, cs_json)
	ns.Dump()
	//tctx.RegisterParserCb("dhcp")

	nsplg := ns.PluginCtx.Get(APPSIM_PLUG)
	if nsplg == nil {
		panic(" can't find plugin")
	}

	return tctx, nil
}

type VethIgmpSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func genMbuf(tctx *core.CThreadCtx, pkt []byte) *core.Mbuf {
	m := tctx.MPool.Alloc(uint16(len(pkt)))
	m.SetVPort(1)
	m.Append(pkt)
	return m
}

func (o *VethIgmpSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	m.FreeMbuf()
	return nil
}

func TestPluginAppsim1(t *testing.T) {
}

// load the json

const input_json3 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "min_bytes": 128,
                    "name": "rx"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_bytes": 249,
                    "name": "rx"
                },
                {
                    "buf_index": 1,
                    "name": "tx"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

func TestPluginAppsim4(t *testing.T) {
	var a fastjson.RawMessage
	a = fastjson.RawMessage(input_json3)

	var out map[string]interface{}
	err1 := IsValidAppSimJson(&a, &out)
	if err1 != nil {
		fmt.Printf(" %v", err1)
	}
}

const input_json5_not_valid string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "tunable_list": [ {"tos":1},{"tos":2,"mss":7}
    ],

    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "min_bytes": 128,
                    "name": "rx"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_bytes": 249,
                    "name": "rx"
                },
                {
                    "buf_index": 1,
                    "name": "tx"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,"tunable_index":0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1,
                "tunable_index":7
                }
    }]
}
`

func TestPluginAppsim5(t *testing.T) {
	var a fastjson.RawMessage
	a = fastjson.RawMessage(input_json5_not_valid)

	var out map[string]interface{}
	err1 := IsValidAppSimJson(&a, &out)
	if err1 == nil {
		t.Errorf(" error json should not be valid \n")
	}
}

type AppL7SimTestBase struct {
	testname     string
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	//cb           TransportTestCb
	amount uint32
	cbArg1 interface{}
	cbArg2 interface{}
	param  transportSimParam
}

// run one flow (client/server) simulation
func (o *AppL7SimTestBase) Run(t *testing.T, compare bool) {
	rand.Seed(0x1234)
	if emu_debug > 0 {
		o.param.emu_debug = true
	}

	sim := newTransportSim(&o.param)

	m := false
	if monitor > 0 {
		m = true
	}

	sim.tctx.Veth.SetDebug(m, os.Stdout, o.capture)
	sim.tctx.MainLoopSim(o.duration)

	defer sim.tctx.Delete()
	sim.tctx.SimRecordCompare(o.testname, t)
}

func TestPluginAppSim10(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-10",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         false,
			program_json: input_json3,
		},
	}
	a.Run(t, false)
}

// TCP-ipv6
func TestPluginAppSim11(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-11",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         true,
			program_json: input_json3,
		},
	}
	a.Run(t, false)
}

// UDP program
const input_json12 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx_msg"
                },
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                },
                {
                    "buf_index": 1,
                    "name": "tx_msg"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

// UDP
func TestPluginAppSim12(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-12",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         false,
			udp:          true,
			program_json: input_json12,
		},
	}
	a.Run(t, false)
}

// UDP-ipv6
func TestPluginAppSim13(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-13",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         true,
			udp:          true,
			program_json: input_json12,
		},
	}
	a.Run(t, false)
}

// test delay command
const input_json14 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "min_bytes": 128,
                    "name": "rx"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_bytes": 249,
                    "name": "rx"
                },
                {
                    "usec": 5000000,
                    "name": "delay"
                },
                {
                    "buf_index": 1,
                    "name": "tx"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

// test delay (5 sec) command in the server
func TestPluginAppSim14(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-14",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         false,
			program_json: input_json14,
		},
	}
	a.Run(t, false)
}

const input_json15 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "min_bytes": 128,
                    "name": "rx"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_bytes": 249,
                    "name": "rx"
                },
                {
                    "min_usec": 5000000,
                    "max_usec": 6000000,
                    "name": "delay_rnd"
                },
                {
                    "buf_index": 1,
                    "name": "tx"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

/*func TestPluginAppSim15(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-15",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         false,
			program_json: input_json15,
		},
	}
	a.Run(t, false)
}*/

const input_json16 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "usec": 5000000,
                    "name": "delay"
                },
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "min_bytes": 128,
                    "name": "rx"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_bytes": 498,
                    "name": "rx"
                },
                {
                    "buf_index": 1,
                    "name": "tx"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

func TestPluginAppSim16(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-16",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         false,
			program_json: input_json16,
		},
	}
	a.Run(t, false)
}

const input_json17 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "min_bytes": 128000,
                    "name": "rx"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_bytes": 249,
                    "name": "rx"
                },
                {
                    "name": "set_var",
                    "id": 0,
                    "val": 1000
                },
                {
                    "buf_index": 1,
                    "name": "tx"
                },
				{
                    "offset": -1,
                    "id": 0,
                    "name": "jmp_nz"
                }

            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

func TestPluginAppSim17(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-17",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     100 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         false,
			program_json: input_json17,
		},
	}
	a.Run(t, false)
}

const input_json18 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
                {
                    "name": "reset"
                }
            ]
        },
        {
            "commands": [
                {
                    "name": "nc"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

func TestPluginAppSim18(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-18",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     100 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			ipv6:         false,
			program_json: input_json18,
		},
	}
	a.Run(t, false)
}

// UDP program
const input_json19 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
				{
					"msec": 100,
					"name": "keepalive"
				},				
                {
                    "buf_index": 0,
                    "name": "tx_msg"
                },
                {
                    "min_pkts": 3,
                    "name": "rx_msg"
                },
				{
                    "buf_index": 0,
                    "name": "tx_msg"
                },
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                }

            ]
        },
        {
            "commands": [
				{
					"msec": 100,
					"name": "keepalive"
				},				
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                },
                {
                    "buf_index": 1,
                    "name": "tx_msg"
                },
				{
                    "min_pkts": 1,
                    "name": "rx_msg"
                },
                {
                    "buf_index": 1,
                    "name": "tx_msg"
                }

            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

func TestPluginAppSim19(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-19",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     100 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			udp:          true,
			ipv6:         false,
			program_json: input_json19,
		},
	}
	a.Run(t, false)
}

const input_json20 string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "tunable_list": [ {"no_delay":1},{"tos":2,"mss":7}
    ],

    "program_list": [
        {
            "commands": [
                {
                    "buf_index": 0,
                    "name": "tx"
                },
                {
                    "min_bytes": 128,
                    "name": "rx"
                }
            ]
        },
        {
            "commands": [
                {
                    "min_bytes": 249,
                    "name": "rx"
                },
                {
                    "buf_index": 1,
                    "name": "tx"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0, "tunable_index":0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

func TestPluginAppSim20(t *testing.T) {
	a := &AppL7SimTestBase{
		testname:     "appsim-20",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     100 * time.Second,
		clientsToSim: 1,
		param: transportSimParam{
			name:         "a",
			udp:          false,
			ipv6:         false,
			program_json: input_json20,
		},
	}
	a.Run(t, false)
}

const simple_udp string = `
{
    "buf_list": [
        "R0VUIC8zMzg0IEhUVFAvMS4xDQpIb3N0OiAyMi4wLjAuMw0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KVXNlci1BZ2VudDogTW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNy4wOyBXaW5kb3dzIE5UIDUuMTsgU1YxOyAuTkVUIENMUiAxLjEuNDMyMjsgLk5FVCBDTFIgMi4wLjUwNzI3KQ0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogZW4tdXMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZSwgY29tcHJlc3MNCg0K",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
				{
					"msec": 10,
					"name": "keepalive"
				},				
                {
                    "buf_index": 0,
                    "name": "tx_msg"
                },
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                }
            ]
        },
        {
            "commands": [
				{
					"msec": 10,
					"name": "keepalive"
				},				
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                },
                {
                    "buf_index": 1,
                    "name": "tx_msg"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

const c_simple_udp_ipv4 string = `{ "data" : { "s-1" : { "cps": 2.0, "t": "c", "tid": 0, "ipv6": false, "stream": false,"dst" :"48.0.0.1:80"}}}`
const c_simple_udp_ipv6 string = `{ "data" : { "s-1" : { "cps": 2.0, "t": "c", "tid": 0, "ipv6": true, "stream": false,"dst" :"[2001:db8::3000:1]:80"}}}`

func TestPluginAppSim30(t *testing.T) {
	a := &TransimTestBase{
		testname:     "appsim-30",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		c_json:       []byte(c_simple_udp_ipv4),
		ns_json:      []byte(simple_udp),
	}
	a.Run(t)
}

func TestPluginAppSim31(t *testing.T) {
	a := &TransimTestBase{
		testname:     "appsim-31",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		c_json:       []byte(c_simple_udp_ipv6),
		ns_json:      []byte(simple_udp),
	}
	a.Run(t)
}

const c_simple_udp_ipv4_limit string = `{ "data" : { "s-1" : { "limit": 2, "cps": 2.0, "t": "c", "tid": 0, "ipv6": false, "stream": false,"dst" :"48.0.0.1:80"}}}`

func TestPluginAppSim32(t *testing.T) {
	a := &TransimTestBase{
		testname:     "appsim-32",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		c_json:       []byte(c_simple_udp_ipv4_limit),
		ns_json:      []byte(simple_udp),
	}
	a.Run(t)
}

const c_ssdp_l7 string = `NOTIFY * HTTP/1.1\r
HOST: 239.255.255.250:1900\r
CACHE-CONTROL: max-age=120\r
lOCATION: http://192.168.1.1:7406/rootDesc.xml\r
SERVER: UPnP/Tomato 1.28.7500 MIPSR2Toastman-RT K26 USB Ext UPnP/1.0 MiniUPnPd/1.6\r
NT: upnp:rootdevice\r
USN: uuid:04645c3d-e6b4-4eea-bd35-5c320c12969f::upnp:rootdevice\r
NTS: ssdp:alive\r
OPT: "http://schemas.upnp.org/upnp/1/0/";\r
01-NLS: 1\r
BOOTID.UPNP.ORG: 1\r
CONFIGID.UPNP.ORG: 1337\r
`

const c_ssdp string = `{ "data" : { "s-1" : { "cps": 1.0, "t": "c", "tid": 0, "ipv6": false, "stream": false,"dst" :"239.255.255.250:1900"}}}`

const simple_ssdp_template string = `
{
    "buf_list": [
        "%v",
        "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IE1pY3Jvc29mdC1JSVMvNi4wDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KQ29udGVudC1MZW5ndGg6IDMyMDAwDQoNCjxodG1sPjxwcmU+KioqKioqKioqKjwvcHJlPjwvaHRtbD4="
    ],
    "program_list": [
        {
            "commands": [
				{
					"msec": 10,
					"name": "keepalive"
				},				
                {
                    "buf_index": 0,
                    "name": "tx_msg"
                },
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                }
            ]
        },
        {
            "commands": [
				{
					"msec": 10,
					"name": "keepalive"
				},				
                {
                    "min_pkts": 1,
                    "name": "rx_msg"
                },
                {
                    "buf_index": 1,
                    "name": "tx_msg"
                }
            ]
        }
    ],

    "templates": [{
        "client_template" :{"program_index": 0,
                "port": 80,
                "cps": 1
              },
        "server_template" : {"assoc": [
                    {
                        "port": 80
                    }
                ],
                "program_index": 1
                }
    }]
}
`

func TestPluginAppSim33(t *testing.T) {

	b := base64.StdEncoding.EncodeToString([]byte(c_ssdp_l7))
	simple_ssdp_p := fmt.Sprintf(simple_ssdp_template, b)

	a := &TransimTestBase{
		testname:     "appsim-33",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		c_json:       []byte(c_ssdp),
		ns_json:      []byte(simple_ssdp_p),
	}
	a.Run(t)
}

const c_ssdp_ipv6 string = `{ "data" : { "s-1" : { "cps": 1.0, "t": "c", "tid": 0, "ipv6": true, "stream": false,"dst" :"[FF02::0C]:1900"}}}`

func TestPluginAppSim34(t *testing.T) {

	b := base64.StdEncoding.EncodeToString([]byte(c_ssdp_l7))
	simple_ssdp_p := fmt.Sprintf(simple_ssdp_template, b)

	a := &TransimTestBase{
		testname:     "appsim-34",
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     10 * time.Second,
		clientsToSim: 1,
		c_json:       []byte(c_ssdp_ipv6),
		ns_json:      []byte(simple_ssdp_p),
	}
	a.Run(t)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
	flag.IntVar(&emu_debug, "emu_debug", 0, "emu_debug")
}
