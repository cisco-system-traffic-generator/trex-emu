package avcipfix

import (
	"emu/core"
	"flag"
	"fmt"
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
	clientIpv6	 core.Ipv6Key
	initJSON	 [][]byte
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

	var simVeth VethIPFixSim
	simVeth.DropAll = o.dropAll
	var simrx core.VethIFSim
	simrx = &simVeth
	if o.match > 0 {
		simVeth.match = o.match
	}
	tctx, _ := createSimulationEnv(&simrx, o)
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

	for j := 0; j < o.clientsToSim; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)

		c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, a, b})
		clplg := c.PluginCtx.Get(IPFIX_PLUG)
		if clplg == nil {
			t.Fatalf(" can't find plugin")
		}
		ipfixPlug := clplg.Ext.(*PluginIpfixClient)
		ipfixPlug.cdbv.Dump()
		tctx.SimRecordAppend(ipfixPlug.cdb.MarshalValues(false))
	}

	if compare {
		tctx.SimRecordCompare(o.testname, t)
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
		ns.AddClient(client)
		client.PluginCtx.CreatePlugins([]string{IPFIX_PLUG}, t.initJSON)

		cPlg := client.PluginCtx.Get(IPFIX_PLUG)
		if cPlg == nil {
			panic(" can't find plugin")
		}
	}
	ns.Dump()
	tctx.RegisterParserCb(IPFIX_PLUG)

	return tctx, nil
}

type initJsonArgs struct {
	ver, records, dataRate uint8
	isIpv6 bool
	genType string
}

func createInitJSON(a *initJsonArgs) [][]byte{
	ipv6 := "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]"
	if a.isIpv6 {
		ipv6 = "[32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]"
	}

	data := fmt.Sprintf(`
	{
		"netflow_version": %d,
		"dst_mac" :[0, 0, 1, 0, 0, 0],
		"dst_ipv4": [48, 0, 0, 0],
		"dst_ipv6": %s,
		"generators": {
			"gen1": {
				"type": "%s",
				"auto_start": true,
				"rate_pps": %d,
				"data_records": %d,
				"gen_type_data": {
					"client_ip": [15, 0, 0, 1],
					"range_of_clients": 150,
					"dns_servers": 100,
					"nbar_hosts": 100
				}
			}
		}
	}
`, a.ver, ipv6, a.genType, a.dataRate, a.records)
	return [][]byte{[]byte(data)}
}

/* Tests */
func TestPluginAvcIPFix_1(t *testing.T) {
	jsonArgs := &initJsonArgs{
		ver: 10,
		genType: "dns",
		isIpv6: false,
		records: 7,
		dataRate: 2,
	}

	a := &IPFixTestBase{
		testname:     "ipfix1",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON: 	  createInitJSON(jsonArgs),
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginAvcIPFix_2(t *testing.T) {
	jsonArgs := &initJsonArgs{
		ver: 10,
		genType: "dns",
		isIpv6: false,
		records: 7,
		dataRate: 2,
	}

	a := &IPFixTestBase{
		testname:     "ipfix2",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON: 	  createInitJSON(jsonArgs),
		duration:     10 * time.Second,
		clientsToSim: 1,
		clientIpv6:   core.Ipv6Key{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	a.Run(t, true)
}

func TestPluginAvcIPFix_3(t *testing.T) {
	jsonArgs := &initJsonArgs{
		ver: 10,
		genType: "dns",
		isIpv6: false,
		records: 0, // using max records allowed by MTU
		dataRate: 2,
	}

	a := &IPFixTestBase{
		testname:     "ipfix3",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON: 	  createInitJSON(jsonArgs),
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func TestPluginAvcIPFix_4(t *testing.T) {
	jsonArgs := &initJsonArgs{
		ver: 10,
		genType: "dns",
		isIpv6: false,
		records: 255, // using huge records number in order to see drops
		dataRate: 2,
	}

	a := &IPFixTestBase{
		testname:     "ipfix4",
		dropAll:      false,
		monitor:      true,
		match:        0,
		capture:      true,
		initJSON: 	  createInitJSON(jsonArgs),
		duration:     10 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t, true)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}