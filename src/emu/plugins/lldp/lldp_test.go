// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package lldp

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

type LldpTestBase struct {
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           LldpTestCb
	cbArg1       interface{}
	cbArg2       interface{}
	options      []byte
}

type LldpTestCb func(tctx *core.CThreadCtx, test *LldpTestBase) int

func (o *LldpTestBase) Run(t *testing.T) {

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
	nsplg := c.PluginCtx.Get(LLDP_PLUG)
	if nsplg == nil {
		t.Fatalf(" can't find plugin")
	}
	lldpPlug := nsplg.Ext.(*PluginLldpClient)
	lldpPlug.cdbv.Dump()
	tctx.GetCounterDbVec().Dump()

	//tctx.SimRecordAppend(igmpPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int, test *LldpTestBase) (*core.CThreadCtx, *core.CClient) {
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
	ns.PluginCtx.CreatePlugins([]string{"lldp"}, [][]byte{})

	var inijson [][]byte
	if test.options == nil {
		inijson = [][]byte{}
	} else {
		inijson = [][]byte{test.options}
	}

	client.PluginCtx.CreatePlugins([]string{"lldp"}, inijson)
	ns.Dump()
	//tctx.RegisterParserCb("dhcp")

	nsplg := ns.PluginCtx.Get(LLDP_PLUG)
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

func TestPluginLldp1(t *testing.T) {
	a := &LldpTestBase{
		testname:     "lldp1",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run(t)
}

func TestPluginLldp2(t *testing.T) {
	lldp_options := "081753756d6d69743330302d34382d506f72742031303031000a0d53756d6d69743330302d3438000c4c53756d6d69743330302d3438202d2056657273696f6e20372e34652e3120284275696c642035292062792052656c656173655f4d61737465722030352f32372f30352030343a35333a3131000e0400140014100e0706000130f9ada002000003e900fe0700120f02070100fe0900120f01036c000010fe0900120f030100000000fe0600120f0405f2fe060080c20101e8fe070080c202010000fe170080c20301e81076322d303438382d30332d3035303500fe050080c20400"

	hex, _ := hex.DecodeString(lldp_options)
	l := &LldpInit{Options: &LldpOptionsT{Raw: &hex}}
	jsonData2, _ := json.Marshal(l)
	a := &LldpTestBase{
		testname:     "lldp2",
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
