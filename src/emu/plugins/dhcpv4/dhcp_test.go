// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package dhcp

import (
	"emu/core"
	"encoding/binary"
	"encoding/hex"
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

type DhcpTestBase struct {
	t            testing.TB
	testname     string
	dropAll      bool
	monitor      bool
	match        uint8
	capture      bool
	duration     time.Duration
	clientsToSim int
	cb           IgmpTestCb
	cbArg1       interface{}
	cbArg2       interface{}
	options      []byte
}

type IgmpTestCb func(tctx *core.CThreadCtx, test *DhcpTestBase) int

func (o *DhcpTestBase) Run() {
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
		o.t.Fatalf(" can't find ns")
		return
	}
	c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, 0, 1})
	nsplg := c.PluginCtx.Get(DHCP_PLUG)
	if nsplg == nil {
		o.t.Fatalf(" can't find plugin")
	}
	dhcpPlug := nsplg.Ext.(*PluginDhcpClient)
	dhcpPlug.cdbv.Dump()
	tctx.GetCounterDbVec().Dump()

	//tctx.SimRecordAppend(igmpPlug.cdb.MarshalValues(false))
	tctx.SimRecordCompare(o.testname, o.t)

}

func createSimulationEnv(simRx *core.VethIFSim, num int, test *DhcpTestBase) (*core.CThreadCtx, *core.CClient) {
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
	err := ns.AddClient(client)
	if err != nil {
		test.t.Fatal(err)
	}
	emptyJsonObj := []byte("{}")
	err = ns.PluginCtx.CreatePlugins([]string{"dhcp"}, [][]byte{emptyJsonObj})
	if err != nil {
		test.t.Fatal(err)
	}

	var inijson [][]byte
	if test.options == nil {
		inijson = [][]byte{emptyJsonObj}
	} else {
		inijson = [][]byte{test.options}
	}

	err = client.PluginCtx.CreatePlugins([]string{"dhcp"}, inijson)
	if err != nil {
		test.t.Fatal(err)
	}
	ns.Dump()
	tctx.RegisterParserCb("dhcp")

	nsplg := ns.PluginCtx.Get(DHCP_PLUG)
	if nsplg == nil {
		panic(" can't find plugin")
	}
	//nsPlug := nsplg.Ext.(*PluginDhcpNs)

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
	var mr *core.Mbuf
	mr = nil
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}

	off := 14 + 8 + 20 + 8

	if m.PktLen() <= uint32(off) {
		m.FreeMbuf()
		return nil
	}
	p := m.GetData()[off:]

	var dhcph layers.DHCPv4
	err := dhcph.DecodeFromBytes(p, gopacket.NilDecodeFeedback)
	if err != nil {
		m.FreeMbuf()
		return nil
	}

	var dhcpmt layers.DHCPMsgType
	dhcpmt = layers.DHCPMsgTypeUnspecified

	for _, o := range dhcph.Options {
		if o.Type == layers.DHCPOptMessageType {
			dhcpmt = layers.DHCPMsgType(o.Data[0])
		}
	}

	switch o.match {
	case 0:
		if dhcpmt == layers.DHCPMsgTypeDiscover {
			pkt := GenerateOfferPacket(dhcph.Xid, net.IPv4(16, 0, 0, 1), net.IPv4(16, 0, 0, 2), int(layers.DHCPMsgTypeOffer), false)
			mr = genMbuf(o.tctx, pkt)
		} else {
			if dhcpmt == layers.DHCPMsgTypeRequest {
				pkt := GenerateOfferPacket(dhcph.Xid, net.IPv4(16, 0, 0, 1), net.IPv4(16, 0, 0, 2), int(layers.DHCPMsgTypeAck), false)
				mr = genMbuf(o.tctx, pkt)
			}
		}
	case 1:

	case 2:
		if dhcpmt == layers.DHCPMsgTypeDiscover {
			pkt := GenerateOfferPacket(dhcph.Xid, net.IPv4(16, 0, 0, 1), net.IPv4(16, 0, 0, 2), int(layers.DHCPMsgTypeOffer), false)
			mr = genMbuf(o.tctx, pkt)
		}
	case 3:
		if dhcpmt == layers.DHCPMsgTypeDiscover {
			pkt := GenerateOfferPacket(dhcph.Xid, net.IPv4(16, 0, 0, 1), net.IPv4(16, 0, 0, 2), int(layers.DHCPMsgTypeOffer), true)
			mr = genMbuf(o.tctx, pkt)
		}
	}

	m.FreeMbuf()
	return mr
}

func TestPluginDhcp1(t *testing.T) {
	a := &DhcpTestBase{
		t:            t,
		testname:     "dhcp1",
		dropAll:      false,
		monitor:      false,
		match:        0,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run()
}

func TestPluginDhcp3(t *testing.T) {
	a := &DhcpTestBase{
		t:            t,
		testname:     "dhcp3",
		dropAll:      false,
		monitor:      false,
		match:        1,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run()
}

func TestPluginDhcp4(t *testing.T) {
	a := &DhcpTestBase{
		t:            t,
		testname:     "dhcp4",
		dropAll:      false,
		monitor:      false,
		match:        2,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run()
}

func TestPluginDhcp5(t *testing.T) {
	a := &DhcpTestBase{
		t:            t,
		testname:     "dhcp5",
		dropAll:      false,
		monitor:      false,
		match:        3,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
	}
	a.Run()
}

func TestPluginDhcp6(t *testing.T) {
	a := &DhcpTestBase{
		t:            t,
		testname:     "dhcp6",
		dropAll:      false,
		monitor:      false,
		match:        3,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
		options:      []byte(`{"options": {"discoverDhcpClassIdOption": "MSFT 5.0", "requestDhcpClassIdOption":"MSFT 6.0"}} `),
	}
	a.Run()
}

func TestPluginDhcp7(t *testing.T) {
	a := &DhcpTestBase{
		t:            t,
		testname:     "dhcp7",
		dropAll:      false,
		monitor:      false,
		match:        3,
		capture:      true,
		duration:     120 * time.Second,
		clientsToSim: 1,
		options:      []byte(`{"options": {"dis": [[60,8,77,83,70,84,32,53,46,48],[60,8,77,83,70,84,32,53,46,48]], "req":[[60,8,77,83,70,84,32,53,46,48],[60,8,77,83,70,84,32,53,46,48],[60,8,77,83,70,84,32,53,46,48]],"ren":[[60,8,77,83,70,84,32,53,46,48]] }} `),
	}
	a.Run()
}

func getL2() []byte {
	l2 := []byte{0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 2, 0x81, 00, 0x00, 0x01, 0x81, 00, 0x00, 0x02, 0x08, 00}
	return l2
}

func getL2B() []byte {
	l2 := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 1, 0, 0, 2, 0x81, 00, 0x00, 0x01, 0x81, 00, 0x00, 0x02, 0x08, 00}
	return l2
}

func GenerateOfferPacket(xid uint32, src net.IP, dst net.IP, dt int, broadcast bool) []byte {

	dhcpOffer := &layers.DHCPv4{Operation: layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          xid,
		ClientIP:     net.IP{0, 0, 0, 0},
		YourClientIP: dst,
		NextServerIP: src,
		RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr{0, 0, 1, 0, 0, 1},
		ServerName:   make([]byte, 64), File: make([]byte, 128)}
	dhcpOffer.Options = append(dhcpOffer.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(dt)}))
	dhcpOffer.Options = append(dhcpOffer.Options, layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte{255, 255, 255, 0}))
	dhcpOffer.Options = append(dhcpOffer.Options, layers.NewDHCPOption(layers.DHCPOptT1, []byte{0, 0, 0, 8}))
	dhcpOffer.Options = append(dhcpOffer.Options, layers.NewDHCPOption(layers.DHCPOptT2, []byte{0, 0, 0, 10}))
	dhcpOffer.Options = append(dhcpOffer.Options, layers.NewDHCPOption(layers.DHCPOptLeaseTime, []byte{0, 0, 0xe, 0x10}))
	dhcpOffer.Options = append(dhcpOffer.Options, layers.NewDHCPOption(layers.DHCPOptServerID, []byte{0xe, 0, 0xe, 0x10}))

	dr := core.PacketUtlBuild(
		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc,
			SrcIP:    src,
			DstIP:    dst,
			Protocol: layers.IPProtocolUDP},

		&layers.UDP{SrcPort: 67, DstPort: 68},
		dhcpOffer,
	)

	ipv4 := layers.IPv4Header(dr[0:20])
	ipv4.SetLength(uint16(len(dr)))
	ipv4.UpdateChecksum()

	binary.BigEndian.PutUint16(dr[24:26], uint16(len(dr)-20))
	binary.BigEndian.PutUint16(dr[26:28], 0)

	if broadcast {
		offerPktTemplate := append(getL2B(), dr...)
		return offerPktTemplate
	} else {
		offerPktTemplate := append(getL2(), dr...)
		return offerPktTemplate
	}
}

func TestPluginDhcp2(t *testing.T) {
	// generate a offer packet
	return
	tctx := core.NewThreadCtx(0, 4510, false, nil)
	defer tctx.Delete()

	m := tctx.MPool.Alloc(1500)
	m.Append(GenerateOfferPacket(7, net.IPv4(16, 0, 0, 1), net.IPv4(16, 0, 0, 2), int(layers.DHCPMsgTypeOffer), false))
	m.DumpK12(0, os.Stdout)
	m.FreeMbuf()

	m = tctx.MPool.Alloc(1500)
	m.Append(GenerateOfferPacket(7, net.IPv4(16, 0, 0, 1), net.IPv4(16, 0, 0, 2), int(layers.DHCPMsgTypeAck), false))
	m.DumpK12(0, os.Stdout)
	m.FreeMbuf()

	b := GenerateOfferPacket(7, net.IPv4(16, 0, 0, 1), net.IPv4(16, 0, 0, 2), int(layers.DHCPMsgTypeAck), false)
	off := 14 + 8 + 20 + 8
	fmt.Printf(" %s \n", hex.Dump(b[off:]))
	//err := dhcph.DecodeFromBytes(b[off:], gopacket.NilDecodeFeedback)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
