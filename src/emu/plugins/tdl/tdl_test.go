package tdl

import (
	"emu/core"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

var monitor int

type VethTdlSim struct {
	DropAll bool
	cnt     uint8
	match   uint8
	tctx    *core.CThreadCtx
}

func (o *VethTdlSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	m.FreeMbuf()
	return nil
}

type TdlTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	clientIpv6   core.Ipv6Key
	counters     TdlStats
	initJSON     [][]byte
	seed         int64
	cb           TdlTestCb
	cbArg1       interface{}
	cbArg2       interface{}
}

type TdlTestCb func(tctx *core.CThreadCtx, test *TdlTestBase) int

func createSimulationEnv(simRx *core.VethIFSim, t *TdlTestBase) (*core.CThreadCtx, *core.CClient) {
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
		client.PluginCtx.CreatePlugins([]string{TDL_PLUG}, t.initJSON)

		// After adding the plugins, we can try to resolve.
		client.AttemptResolve()

		cPlg := client.PluginCtx.Get(TDL_PLUG)
		if cPlg == nil {
			panic(" can't find plugin")
		}
	}
	ns.Dump()

	return tctx, nil
}

func (o *TdlTestBase) Run(t *testing.T, compare bool) {

	if o.seed != 0 {
		rand.Seed(o.seed)
	}

	var simVeth VethTdlSim
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

	var tdlPlug *PluginTdlClient

	for j := 0; j < o.clientsToSim; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)

		c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, a, b})
		clplg := c.PluginCtx.Get(TDL_PLUG)
		if clplg == nil {
			t.Fatalf(" can't find plugin")
		}
		tdlPlug = clplg.Ext.(*PluginTdlClient)
		tdlPlug.cdbv.Dump()
		tctx.SimRecordAppend(tdlPlug.cdb.MarshalValues(false))
	}

	if compare {
		if o.monitor {
			tctx.SimRecordCompare(o.testname, t)
		} else {
			if o.clientsToSim == 1 {
				if o.counters != tdlPlug.stats {
					t.Errorf("Bad counters, want %+v, have %+v.\n", o.counters, tdlPlug.stats)
					t.FailNow()
				}
			}

		}
	}
}

func TestTypeDefTunnelStats(t *testing.T) {

	initJson := fmt.Sprintf(`
	{
		"dst": "1.1.1.1:8080",
		"udp_debug": true,
		"rate_pps": 2,
		"header": {
			"magic": 255,
			"fru": 255,
			"src_chassis": 0,
			"src_slot": 0,
			"dst_chassis": 0,
			"dst_slot": 0,
			"bay": 0,
			"state_tracking": 0,
			"flag": 0,
			"domain_hash": 0,
			"len": 0,
			"uuid": 3650,
			"tenant_id": 5,
			"luid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0]
		},
		"meta_data": [
			{
				"name": "tunnel_stats",
				"type": "type_def",
				"data": {
					"luid": [197, 137, 85, 66, 108, 215, 28, 149, 190, 189, 136, 234, 246, 161, 93, 13],
					"entries": [
						{
							"name": "flap_count",
							"type": "uint32"
						},
						{
							"name": "total_rx_bytes",
							"type": "uint64"
						},
						{
							"name": "total_tx_bytes",
							"type": "uint64"
						},
						{
							"name": "total_rx_pkts",
							"type": "uint64"
						},
						{
							"name": "total_tx_pkts",
							"type": "uint64"
						},
						{
							"name": "total_clients",
							"type": "uint32"
						},
						{
							"name": "up_time",
							"type": "uint32"
						},
						{
							"name": "keep_alive_tx",
							"type": "uint64"
						},
						{
							"name": "keep_alive_rx",
							"type": "uint64"
						},
						{
							"name": "keep_alive_windows",
							"type": "uint32"
						},
						{
							"name": "keep_alive_dropped",
							"type": "uint32"
						},
						{
							"name": "total_keep_alive_tx",
							"type": "uint64"
						},
						{
							"name": "total_keep_alive_rx",
							"type": "uint64"
						}
					]
				}
			}
		],
		"object": {
			"name": "GRE",
			"type": "tunnel_stats"
		},
		"init_values": [
			{
				"path": "GRE.flap_count",
				"value": 1
			},
			{
				"path": "GRE.total_rx_bytes",
				"value": 20149920
			},
			{
				"path": "GRE.total_tx_bytes",
				"value": 976521
			},
			{
				"path": "GRE.total_rx_pkts",
				"value": 12345
			},
			{
				"path": "GRE.total_tx_pkts",
				"value": 5678
			},
			{
				"path": "GRE.total_clients",
				"value": 100
			},
			{
				"path": "GRE.up_time",
				"value": 2128515
			},
			{
				"path": "GRE.keep_alive_tx",
				"value": 1401590159015
			},
			{
				"path": "GRE.keep_alive_rx",
				"value": 1204158051
			},
			{
				"path": "GRE.keep_alive_windows",
				"value": 2
			},
			{
				"path": "GRE.keep_alive_dropped",
				"value": 0
			},
			{
				"path": "GRE.total_keep_alive_tx",
				"value": 20104510515
			},
			{
				"path": "GRE.total_keep_alive_rx",
				"value": 1215895915
			}
		]
	}`)

	a := &TdlTestBase{
		testname:     "tdl_tunnel_stats",
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

func TestTypeDefLayerKey(t *testing.T) {

	initJson := fmt.Sprintf(`
	{
		"dst": "1.1.1.1:8080",
		"udp_debug": true,
		"rate_pps": 2,
		"header": {
			"magic": 255,
			"fru": 255,
			"src_chassis": 0,
			"src_slot": 0,
			"dst_chassis": 0,
			"dst_slot": 0,
			"bay": 0,
			"state_tracking": 0,
			"flag": 0,
			"domain_hash": 0,
			"len": 0,
			"uuid": 3650,
			"tenant_id": 5,
			"luid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0]
		},
		"meta_data": [
			{
				"name": "layer_flag",
				"type": "enum_def",
				"data": {
					"luid": [52, 34, 60, 50, 136, 246, 203, 187, 208, 9, 188, 143, 128, 214, 18, 117],
					"entries": [
						{
							"name": "ACTIVE_LAYER",
							"value": 0
						},
						{
							"name": "DELETE_LAYER",
							"value": 1
						}
					]
				}
			},
			{
				"name": "layer_key",
				"type": "type_def",
				"data": {
					"entries": [
						{
							"name": "layer_flag",
							"type": "layer_flag"
						},
						{
							"name": "layer_idx",
							"type": "uint8"
						},
						{
							"name": "sub_layer_idx",
							"type": "uint8"
						}
					]
				}
			}
		],
		"object": {
			"name": "key",
			"type": "layer_key"
		},
		"init_values": [
			{
				"path": "key.layer_flag",
				"value": "DELETE_LAYER"
			},
			{
				"path": "key.layer_idx",
				"value": 5
			},
			{
				"path": "key.sub_layer_idx",
				"value": 128
			}
		],
		"engines": [
			{
				"engine_name": "key.layer_idx",
				"engine_type": "uint",
				"params":
				{
					"size": 1,
					"offset": 0,
					"min": 1,
					"max": 255,
					"op": "inc",
					"step": 1,
				}
			}
		]
	}`)

	a := &TdlTestBase{
		testname:     "tdl_layer_key",
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

func TestTypeDef1(t *testing.T) {

	initJson := fmt.Sprintf(`
	{
		"dst": "1.1.1.1:8080",
		"udp_debug": true,
		"rate_pps": 2,
		"header": {
			"magic": 255,
			"fru": 255,
			"src_chassis": 1,
			"src_slot": 2,
			"dst_chassis": 3,
			"dst_slot": 4,
			"bay": 0,
			"state_tracking": 0,
			"flag": 0,
			"domain_hash": 0,
			"len": 0,
			"uuid": 3650,
			"tenant_id": 5,
			"luid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0]
		},
		"meta_data": [
			{
				"name": "enum1",
				"type": "enum_def",
				"data": {
					"luid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 1],
					"entries": [
						{
							"name": "Cisco",
							"value": 20
						},
						{
							"name": "TRex",
							"value": 25
						},
						{
							"name": "Golang",
							"value": 30
						}
					]
				}
			},
			{
				"name": "flag1",
				"type": "flag_def",
				"data": {
					"luid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 2],
					"entries": ["FLAG0", "FLAG1", "FLAG2", "FLAG3"]
				}
			},
			{
				"name": "type1",
				"type": "type_def",
				"data": {
					"luid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 3],
					"entries": [
						{
							"name": "var1",
							"type": "char"
						},
						{
							"name": "var2",
							"type": "enum1"
						},
						{
							"name": "var3",
							"type": "flag1"
						}
					]
				}
			},
			{
				"name": "type2",
				"type": "type_def",
				"data": {
					"luid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 4],
					"entries": [
						{
							"name": "var1",
							"type": "uint8"
						},
						{
							"name": "var2",
							"type": "type1"
						}
					]
				}
			}
		],
		"object": {
			"name": "rootvar",
			"type": "type2"
		},
		"init_values": [
			{
				"path": "rootvar.var1",
				"value": 20
			},
			{
				"path": "rootvar.var2.var1",
				"value": "B"
			},
			{
				"path": "rootvar.var2.var2",
				"value": "Cisco"
			},
			{
				"path": "rootvar.var2.var3",
				"value": ["FLAG0", "FLAG3"]
			}
		],
		"engines": [
			{
				"engine_name": "rootvar.var2.var2",
				"engine_type": "string_list",
				"params": 
					{
						"size": 6,
						"offset": 0,
						"op": "rand",
						"list": ["TRex", "Cisco", "Golang"]
					}
			}
		]
	}`)

	a := &TdlTestBase{
		testname:     "typeDef1",
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
