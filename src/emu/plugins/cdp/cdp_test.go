// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package cdp

import (
	"emu/core"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"
)

var monitor int

type CdpTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           CdpTestCb
	cbArg1       interface{}
	cbArg2       interface{}
	options      []byte
}

type CdpTestCb func(tctx *core.CThreadCtx, test *CdpTestBase) int

func (o *CdpTestBase) Run(t *testing.T) {

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
	nsplg := c.PluginCtx.Get(CDP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	cdpPlug := nsplg.Ext.(*PluginCdpClient)
	cdpPlug.cdbv.Dump()
	tctx.GetCounterDbVec().Dump()

	//tctx.SimRecordAppend(igmpPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int, test *CdpTestBase) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(tctx, &key)

	tctx.AddNs(&key, ns)
	dg := core.Ipv4Key{0, 0, 0, 0}

	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 1},
		core.Ipv4Key{0, 0, 0, 0},
		core.Ipv6Key{},
		dg)
	ns.AddClient(client)
	ns.PluginCtx.CreatePlugins([]string{"cdp"}, [][]byte{})

	var inijson [][]byte
	if test.options == nil {
		inijson = [][]byte{}
	} else {
		inijson = [][]byte{test.options}
	}

	client.PluginCtx.CreatePlugins([]string{"cdp"}, inijson)
	ns.Dump()

	nsplg := ns.PluginCtx.Get(CDP_PLUG)
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

func TestPluginCdp1(t *testing.T) {
	cdp_options, _ := hex.DecodeString("0001000c6d7973776974636800020011000000010101cc0004c0a800fd000300134661737445746865726e6574302f31000400080000002800050114436973636f20496e7465726e6574776f726b204f7065726174696e672053797374656d20536f667477617265200a494f532028746d2920433239353020536f667477617265202843323935302d49364b324c3251342d4d292c2056657273696f6e2031322e3128323229454131342c2052454c4541534520534f4654574152452028666331290a546563686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e636f6d2f74656368737570706f72740a436f707972696768742028632920313938362d3230313020627920636973636f2053797374656d732c20496e632e0a436f6d70696c6564205475652032362d4f63742d31302031303a3335206279206e627572726100060015636973636f2057532d43323935302d31320008002400000c011200000000ffffffff010220ff000000000000000bbe189a40ff00000009000c4d59444f4d41494e000a00060001000b0005010012000500001300050000160011000000010101cc0004c0a800fd")
	l := &CdpInit{Options: &CdpOptionsT{Raw: &cdp_options}}
	jsonData2, _ := json.Marshal(l)

	a := &CdpTestBase{
		testname:     "cdp1",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
		options:      jsonData2,
	}
	a.Run(t)
}

func TestPluginCdp2(t *testing.T) {
	cdp_options, _ := hex.DecodeString("0001000c6d7973776974636800020011000000010101cc0004c0a800fd000300134661737445746865726e6574302f31000400080000002800050114436973636f20496e7465726e6574776f726b204f7065726174696e672053797374656d20536f667477617265200a494f532028746d2920433239353020536f667477617265202843323935302d49364b324c3251342d4d292c2056657273696f6e2031322e3128323229454131342c2052454c4541534520534f4654574152452028666331290a546563686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e636f6d2f74656368737570706f72740a436f707972696768742028632920313938362d3230313020627920636973636f2053797374656d732c20496e632e0a436f6d70696c6564205475652032362d4f63742d31302031303a3335206279206e627572726100060015636973636f2057532d43323935302d31320008002400000c011200000000ffffffff010220ff000000000000000bbe189a40ff00000009000c4d59444f4d41494e000a00060001000b00050100120005000013000500")
	l := &CdpInit{Options: &CdpOptionsT{Raw: &cdp_options}}
	jsonData2, _ := json.Marshal(l)

	a := &CdpTestBase{
		testname:     "cdp2",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
		options:      jsonData2,
	}
	a.Run(t)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
