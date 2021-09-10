/*
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

package dhcpsrv

import (
	"emu/core"
	"emu/plugins/transport"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"flag"
	"net"
	"os"
	"testing"
	"time"
)

var monitor int

// A simple type to indicate the case type.
type DhcpClientTestCase byte

const (
	Discover DhcpClientTestCase = iota
	OfferDecline
	DiscoverRequest
	DiscoverRequestRenew
	DiscoverRequestRebind
	Inform
)

func TestIpv4PoolSmall(t *testing.T) {
	cidr := "192.168.0.0/29"
	min := core.Ipv4Key{192, 168, 0, 0}
	max := core.Ipv4Key{192, 168, 0, 7}
	excludedIPv4 := []core.Ipv4Key{core.Ipv4Key{192, 168, 0, 1}}

	_, ipNet, _ := net.ParseCIDR(cidr)
	pool := CreateIpv4Pool(ipNet, min, max, excludedIPv4)

	subnet := core.Ipv4Key{255, 255, 255, 248}
	if pool.GetSubnetMask() != subnet {
		t.Errorf("Invalid subnet mask, want %v and have %v\n", subnet, pool.GetSubnetMask())
		t.FailNow()
	}

	// There should be 5 values 192.168.0.2-6
	for i := 0; i < 5; i++ {
		_, _ = pool.GetFirst()
	}
	// Pool Should be Empty
	if !pool.Empty() {
		t.Errorf("Pool Should be Empty, and is not!")
		t.FailNow()
	}
	ipv4 := core.Ipv4Key{192, 168, 0, 2}
	pool.AddFirst(ipv4)
	if pool.Empty() {
		t.Error("Pool Should not be Empty, and is")
		t.FailNow()
	}
	extractedIp, err := pool.GetFirst()
	if err != nil || extractedIp != ipv4 {
		t.Errorf("Extracted Ip %v != ipv4 %v\n", extractedIp, ipv4)
		t.FailNow()
	}

	// Attempt to add Ip not in subnet
	ok := pool.AddFirst(core.Ipv4Key{10, 0, 0, 1})
	if ok {
		t.Error("Added an Ipv4 that doesn't belong to subnet!")
		t.FailNow()
	}

	// Attempt to add excluded
	ok = pool.AddFirst(core.Ipv4Key{192, 168, 0, 1})
	if ok {
		t.Error("Added an Ipv4 that doesn't belong to subnet or excluded!")
		t.FailNow()
	}

	// Attempt to get taken address
	ok = pool.GetEntry(core.Ipv4Key{192, 168, 0, 3})
	if ok {
		t.Error("Distributed Ipv4 was redistributed!")
		t.FailNow()
	}
}

func TestIpv4PoolMedium(t *testing.T) {
	cidr := "192.168.0.0/24"
	min := core.Ipv4Key{192, 168, 0, 0}
	max := core.Ipv4Key{192, 168, 0, 255}
	excludedIPv4 := []core.Ipv4Key{core.Ipv4Key{192, 168, 0, 1}}

	_, ipNet, _ := net.ParseCIDR(cidr)
	pool := CreateIpv4Pool(ipNet, min, max, excludedIPv4)

	subnet := core.Ipv4Key{255, 255, 255, 0}
	if pool.GetSubnetMask() != subnet {
		t.Errorf("Invalid subnet mask, want %v and have %v\n", subnet, pool.GetSubnetMask())
		t.FailNow()
	}

	if pool.Empty() {
		t.Error("Pool Should not be Empty, and is.")
		t.FailNow()
	}

	requestedIp := core.Ipv4Key{192, 168, 0, 20}
	ok := pool.GetEntry(requestedIp)
	if ok {
		// Requested Ip was provided, let's request it again
		if pool.GetEntry(requestedIp) {
			t.Errorf("Ipv4 %v was provided twice simultaneously!", requestedIp)
			t.FailNow()
		}
	}

	// Request excluded
	requestedIp = core.Ipv4Key{192, 168, 0, 1}
	ok = pool.GetEntry(requestedIp)
	if ok {
		t.Errorf("Excluded Ipv4 %v was provided upon request!", requestedIp)
		t.FailNow()
	}
}

func TestIpv4PoolMediumRange(t *testing.T) {
	cidr := "192.168.0.0/24"
	min := core.Ipv4Key{192, 168, 0, 50}
	max := core.Ipv4Key{192, 168, 0, 100}

	_, ipNet, _ := net.ParseCIDR(cidr)
	pool := CreateIpv4Pool(ipNet, min, max, []core.Ipv4Key{})

	subnet := core.Ipv4Key{255, 255, 255, 0}
	if pool.GetSubnetMask() != subnet {
		t.Errorf("Invalid subnet mask, want %v and have %v\n", subnet, pool.GetSubnetMask())
		t.FailNow()
	}

	if pool.Empty() {
		t.Error("Pool Should not be Empty, and is.")
		t.FailNow()
	}

	if pool.Contains(core.Ipv4Key{192, 168, 0, 49}) {
		t.Error("Pool contains invalid address 192.168.0.49!")
		t.FailNow()
	}

	if pool.Contains(core.Ipv4Key{192, 168, 0, 101}) {
		t.Error("Pool contains invalid address 192.168.0.101!")
		t.FailNow()
	}

	if pool.canAdd(core.Ipv4Key{192, 168, 0, 49}) {
		t.Error("Can Add invalid address 192.168.0.49 to pool!")
		t.FailNow()
	}

	if pool.canAdd(core.Ipv4Key{192, 168, 0, 101}) {
		t.Error("Can Add invalid address 192.168.0.101 to pool!")
		t.FailNow()
	}

	requestedIp := core.Ipv4Key{192, 168, 0, 120}
	ok := pool.GetEntry(requestedIp)
	if ok {
		t.Error("Can Request invalid address 192.168.0.120 from pool!")
		t.FailNow()
	}

	requestedIp = core.Ipv4Key{192, 168, 0, 55}
	ok = pool.GetEntry(requestedIp)
	if ok {
		// Requested Ip was provided, let's request it again
		if pool.GetEntry(requestedIp) {
			t.Errorf("Ipv4 %v was provided twice simultaneously!", requestedIp)
			t.FailNow()
		}
	}

}

func TestIpv4PoolLarge(t *testing.T) {
	cidr := "10.0.0.0/16"
	min := core.Ipv4Key{10, 0, 0, 0}
	max := core.Ipv4Key{10, 0, 255, 255}
	excludedIPv4 := []core.Ipv4Key{core.Ipv4Key{10, 0, 1, 1}}

	_, ipNet, _ := net.ParseCIDR(cidr)
	pool := CreateIpv4Pool(ipNet, min, max, excludedIPv4)

	subnet := core.Ipv4Key{255, 255, 0, 0}
	if pool.GetSubnetMask() != subnet {
		t.Errorf("Invalid subnet mask, want %v and have %v\n", subnet, pool.GetSubnetMask())
		t.FailNow()
	}

	if pool.Empty() {
		t.Error("Pool should not be Empty, and is.")
		t.FailNow()
	}

	requestedIp := core.Ipv4Key{10, 0, 2, 1}
	ok := pool.GetEntry(requestedIp)
	if ok {
		// Requested Ip was provided, let's request it again
		if pool.GetEntry(requestedIp) {
			t.Errorf("Ipv4 %v was provided twice simultaneously!", requestedIp)
			t.FailNow()
		}
	}

	// Request excluded
	requestedIp = core.Ipv4Key{10, 0, 1, 1}
	ok = pool.GetEntry(requestedIp)
	if ok {
		t.Errorf("Excluded Ipv4 %v was provided upon request!", requestedIp)
		t.FailNow()
	}

	// 2^16 - 2  entries in the subnet - 1 entry excluded
	for i := 0; i < 0xFFFF-2; i++ {
		_, _ = pool.GetFirst()
	}
	// Pool Should be Empty
	if !pool.Empty() {
		t.Error("Pool should be Empty, and is not!")
		t.FailNow()
	}

	if pool.AddLast(core.Ipv4Key{10, 1, 0, 1}) {
		t.Errorf("Ipv4 not in subnet was added to the pool!")
		t.FailNow()
	}
}

func TestIpv4PoolLargeRange(t *testing.T) {
	cidr := "10.0.0.0/16"
	min := core.Ipv4Key{10, 0, 0, 0}
	max := core.Ipv4Key{10, 0, 2, 255}
	excludedIPv4 := []core.Ipv4Key{core.Ipv4Key{10, 0, 1, 1}}

	_, ipNet, _ := net.ParseCIDR(cidr)
	pool := CreateIpv4Pool(ipNet, min, max, excludedIPv4)

	subnet := core.Ipv4Key{255, 255, 0, 0}
	if pool.GetSubnetMask() != subnet {
		t.Errorf("Invalid subnet mask, want %v and have %v\n", subnet, pool.GetSubnetMask())
		t.FailNow()
	}

	if pool.Empty() {
		t.Error("Pool should not be Empty, and is.")
		t.FailNow()
	}

	if pool.Contains(core.Ipv4Key{10, 0, 3, 0}) {
		t.Error("Pool contains invalid address 10.0.3.0!")
		t.FailNow()
	}

	if !pool.Contains(core.Ipv4Key{10, 0, 0, 0}) {
		t.Error("Pool doesn't contain valid address 10.0.0.0!")
		t.FailNow()
	}

	if !pool.Contains(core.Ipv4Key{10, 0, 2, 255}) {
		t.Error("Pool doesn't contain valid address 10.0.2.255!")
		t.FailNow()
	}

	if pool.canAdd(core.Ipv4Key{10, 0, 3, 1}) {
		t.Error("Can Add invalid address 10.0.3.1 to pool!")
		t.FailNow()
	}

	requestedIp := core.Ipv4Key{10, 0, 0, 0}
	ok := pool.GetEntry(requestedIp)
	if ok {
		t.Error("Can Request invalid address 10.0.0.0 from pool!")
		t.FailNow()
	}

	// 768 entries in the pool - 1 for networkId, - 1 for excluded
	for i := 0; i < 766; i++ {
		_, _ = pool.GetFirst()
	}
	// Pool Should be Empty
	if !pool.Empty() {
		t.Error("Pool should be Empty, and is not!")
		t.FailNow()
	}

	if pool.AddLast(core.Ipv4Key{10, 1, 0, 1}) {
		t.Errorf("Excluded Ipv4 was added to the pool!")
		t.FailNow()
	}
}

// DhcpSrvBase represents the base parameters for a DhcpSrv test.
type DhcpSrvTestBase struct {
	testname      string
	dropAll       bool
	monitor       bool
	capture       bool
	duration      time.Duration
	clientsToSim  int
	forceDGW      bool
	ForcedgMac    core.MACKey
	counters      DhcpSrvStats
	initJSON      [][][]byte
	testCase      DhcpClientTestCase
	discoverReqIp net.IP
	requestReqIp  net.IP
	declineReqIp  net.IP
	ciaddr        net.IP
	cb            DhcpSrvTestCb
	cbArg1        interface{}
	cbArg2        interface{}
}

// DhcpSrvTestCb represents a callback that will be called in the function.
type DhcpSrvTestCb func(tctx *core.CThreadCtx, test *DhcpSrvTestBase) int

// VethDhcpSrvSim represents an DhcpSrv veth for simulation.
type VethDhcpSrvSim struct {
	DropAll bool
}

// ProcessTxToRx decides either to drop packets or support a loopback arch.
func (o *VethDhcpSrvSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	if o.DropAll {
		m.FreeMbuf()
		return nil
	}
	// In case we don't DropAll, we loop back
	return m
}

// Run the tests.
func (o *DhcpSrvTestBase) Run(t *testing.T, compare bool) {

	var simVeth VethDhcpSrvSim
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

	var dhcpSrvPlug *PluginDhcpSrvClient

	for j := 0; j < o.clientsToSim; j++ {
		a := uint8((j >> 8) & 0xff)
		b := uint8(j & 0xff)

		c := ns.CLookupByMac(&core.MACKey{0, 0, 1, 0, a, b})
		clplg := c.PluginCtx.Get(DHCP_SRV_PLUG)
		if clplg == nil {
			t.Fatalf(" can't find plugin")
		}
		dhcpSrvPlug = clplg.Ext.(*PluginDhcpSrvClient)
		dhcpSrvPlug.cdbv.Dump()
		tctx.SimRecordAppend(dhcpSrvPlug.cdb.MarshalValues(false))
		c.OnRemove()
	}

	if compare {
		if o.monitor {
			tctx.SimRecordCompare(o.testname, t)
		} else {
			if o.clientsToSim == 1 {
				if o.counters != dhcpSrvPlug.stats {
					t.Errorf("Bad counters, want %+v, have %+v.\n", o.counters, dhcpSrvPlug.stats)
					t.FailNow()
				}
			}

		}
	}
	ns.OnRemove()
}

// createSimulationEnv creates the simulation event.
func createSimulationEnv(simRx *core.VethIFSim, t *DhcpSrvTestBase) (*core.CThreadCtx, *core.CClient) {
	tctx := core.NewThreadCtx(0, 4510, true, simRx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1})
	ns := core.NewNSCtx(tctx, &key)
	ns.PluginCtx.CreatePlugins([]string{DHCP_SRV_PLUG}, [][]byte{})
	nsPlg := ns.PluginCtx.Get(DHCP_SRV_PLUG)
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
		}
		err := ns.AddClient(client)
		if err != nil {
			panic("Error adding client to namespace:" + err.Error())
		}
		client.PluginCtx.CreatePlugins([]string{DHCP_SRV_PLUG, transport.TRANS_PLUG}, t.initJSON[j])
		cPlg := client.PluginCtx.Get(DHCP_SRV_PLUG)
		if cPlg == nil {
			panic(" can't find plugin")
		}

	}
	tctx.RegisterParserCb(DHCP_SRV_PLUG) // The one parsing is actually UDP.
	ns.Dump()

	return tctx, nil
}

// DhcpClientState handles the logic that the client must use.
type DhcpClientState struct {
	discoverReqIp net.IP
	requestReqIp  net.IP
	declineReqIp  net.IP
	ciaddr        net.IP
	testCase      DhcpClientTestCase
	discoverSent  bool
	declineSent   bool
	bound         bool
	tctx          *core.CThreadCtx
	timerw        *core.TimerCtx
	timer         core.CHTimerObj
}

func (o *DhcpClientState) getBaseLayers() (*layers.Ethernet, *layers.IPv4, *layers.UDP) {
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
		DstMAC:       net.HardwareAddr{255, 255, 255, 255, 255, 255},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{Version: 4,
		IHL:      5,
		TTL:      128,
		Id:       0xcc,
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255),
		Checksum: 0x38f0,
		Protocol: layers.IPProtocolUDP}

	udp := &layers.UDP{SrcPort: DHCPV4_CLIENT_PORT,
		DstPort:  DHCPV4_SERVER_PORT,
		Checksum: 0x181f}
	return ethernet, ipv4, udp
}

// getDhcpDiscoverPkt creates a DHCPDISCOVER packet.
func (o *DhcpClientState) getDhcpDiscoverPkt(relay, broadcastFlag bool) []byte {

	var options layers.DHCPOptions
	options = append(options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptClientID, []byte{1, 0, 0, 1, 0, 0, 0}))
	if o.discoverReqIp != nil {
		options = append(options, layers.NewDHCPOption(layers.DHCPOptRequestIP, o.discoverReqIp))
	} else {
		options = append(options, layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte{0, 0, 0, 0}))
	}
	options = append(options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'h', 'o', 's', 't', '-', 't', 'r', 'e', 'x'}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{byte(layers.DHCPOptSubnetMask),
		byte(layers.DHCPOptRouter),
		byte(layers.DHCPOptDomainName),
		byte(layers.DHCPOptDNS),
		byte(layers.DHCPOptInterfaceMTU),
		byte(layers.DHCPOptNTPServers)}))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}

	ethernet, ipv4, udp := o.getBaseLayers()

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		HardwareOpts: 0,
		Xid:          0xbadf00d,
		Flags:        0x8000, // Broadcast
		ClientIP:     net.IPv4(0, 0, 0, 0),
		YourClientIP: net.IPv4(0, 0, 0, 0),
		NextServerIP: net.IPv4(0, 0, 0, 0),
		RelayAgentIP: net.IPv4(0, 0, 0, 0),
		ClientHWAddr: net.HardwareAddr{0, 0, 1, 0, 0, 0},
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      options}

	if relay {
		ethernet.SrcMAC = net.HardwareAddr{0, 0, 2, 0, 0, 0} // DG
		ethernet.DstMAC = net.HardwareAddr{0, 0, 1, 0, 0, 0} // DhcpSrv Client
		ipv4.SrcIP = net.IPv4(48, 0, 0, 1)                   // Relay
		ipv4.DstIP = net.IPv4(16, 0, 0, 0)                   // DhcpSrv Client
		udp.SrcPort = layers.UDPPort(DHCPV4_SERVER_PORT)     // Server Port
		dhcp.RelayAgentIP = net.IPv4(48, 0, 0, 1)
		if broadcastFlag {
			ipv4.Checksum = 0xf8ee
			udp.Checksum = 0xa81d
		} else {
			ipv4.Checksum = 0xf8ee // IPv4 checksum
			udp.Checksum = 0x281e  // Udp Checksum
			dhcp.Flags = 0x0000    // Flags to unicast
			if o.discoverReqIp != nil {
				udp.Checksum = 0xf813
			}
		}
	} else if !broadcastFlag {
		dhcp.Flags = 0x0000   // Flag to unicast
		udp.Checksum = 0x981f // Checksum
	}
	gopacket.SerializeLayers(buf, opts, ethernet, ipv4, udp, dhcp)
	return buf.Bytes()
}

// getDhcpDiscoverPkt creates a DHCPINFORM packet.
func (o *DhcpClientState) getDhcpInformPkt(relay, broadcastFlag bool) []byte {

	var options layers.DHCPOptions
	options = append(options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeInform)}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptClientID, []byte{1, 0, 0, 1, 0, 0, 0}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'h', 'o', 's', 't', '-', 't', 'r', 'e', 'x'}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{byte(layers.DHCPOptSubnetMask),
		byte(layers.DHCPOptRouter),
		byte(layers.DHCPOptDomainName),
		byte(layers.DHCPOptDNS),
		byte(layers.DHCPOptInterfaceMTU),
		byte(layers.DHCPOptNTPServers)}))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}

	ethernet, ipv4, udp := o.getBaseLayers()

	ipv4.SrcIP = o.ciaddr

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		HardwareOpts: 0,
		Xid:          0xbadf00d,
		Flags:        0x8000, // Broadcast
		ClientIP:     o.ciaddr,
		YourClientIP: net.IPv4(0, 0, 0, 0),
		NextServerIP: net.IPv4(0, 0, 0, 0),
		RelayAgentIP: net.IPv4(0, 0, 0, 0),
		ClientHWAddr: net.HardwareAddr{0, 0, 1, 0, 0, 0},
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      options}

	if relay {
		ethernet.SrcMAC = net.HardwareAddr{0, 0, 2, 0, 0, 0} // DG
		ethernet.DstMAC = net.HardwareAddr{0, 0, 1, 0, 0, 0} // DhcpSrv Client
		ipv4.SrcIP = net.IPv4(48, 0, 0, 1)                   // Relay
		ipv4.DstIP = net.IPv4(16, 0, 0, 0)                   // DhcpSrv Client
		ipv4.Checksum = 0xf8f4                               // IPv4 checksum
		udp.SrcPort = layers.UDPPort(DHCPV4_SERVER_PORT)     // Server port
		udp.Checksum = 0x22e1                                // Udp Checksum
		dhcp.Flags = 0x0000                                  // Flags to unicast
		dhcp.RelayAgentIP = net.IPv4(48, 0, 0, 1)
	} else if !broadcastFlag {
		dhcp.Flags = 0x0000   // Flag to unicast
		udp.Checksum = 0xa235 // Checksum
		ipv4.Checksum = 0x2879
	} else {
		ipv4.Checksum = 0x28f1
		udp.Checksum = 0x2325
	}
	gopacket.SerializeLayers(buf, opts, ethernet, ipv4, udp, dhcp)
	return buf.Bytes()
}

func (o *DhcpClientState) getDhcpRequestPkt(relay, broadcastFlag bool) []byte {
	var options layers.DHCPOptions
	options = append(options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}))
	if o.requestReqIp != nil {
		options = append(options, layers.NewDHCPOption(layers.DHCPOptRequestIP, o.requestReqIp))
	} else {
		options = append(options, layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte{0, 0, 0, 0}))
	}
	options = append(options, layers.NewDHCPOption(layers.DHCPOptClientID, []byte{1, 0, 0, 1, 0, 0, 0}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'h', 'o', 's', 't', '-', 't', 'r', 'e', 'x'}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptServerID, net.IP{16, 0, 0, 0}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{byte(layers.DHCPOptSubnetMask),
		byte(layers.DHCPOptRouter),
		byte(layers.DHCPOptDomainName),
		byte(layers.DHCPOptDNS),
		byte(layers.DHCPOptInterfaceMTU),
		byte(layers.DHCPOptNTPServers)}))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}

	ethernet, ipv4, udp := o.getBaseLayers()

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		HardwareOpts: 0,
		Xid:          0xbadf00d,
		Flags:        0x8000, // Broadcast
		ClientIP:     o.ciaddr,
		YourClientIP: net.IPv4(0, 0, 0, 0),
		NextServerIP: net.IPv4(0, 0, 0, 0),
		RelayAgentIP: net.IPv4(0, 0, 0, 0),
		ClientHWAddr: net.HardwareAddr{0, 0, 1, 0, 0, 0},
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      options}

	if relay {
		ethernet.SrcMAC = net.HardwareAddr{0, 0, 2, 0, 0, 0} // DG
		ethernet.DstMAC = net.HardwareAddr{0, 0, 1, 0, 0, 0} // DhcpSrv Client
		ipv4.SrcIP = net.IPv4(48, 0, 0, 1)                   // Relay
		ipv4.DstIP = net.IPv4(16, 0, 0, 0)                   // DhcpSrv Client
		udp.SrcPort = layers.UDPPort(DHCPV4_SERVER_PORT)     // Server Port
		dhcp.RelayAgentIP = net.IPv4(48, 0, 0, 1)
		if broadcastFlag {
			udp.Checksum = 0xcd6d
		} else {
			udp.Checksum = 0x456e // Udp Checksum
			dhcp.Flags = 0x0000   // Flags to unicast
		}
		ipv4.Checksum = 0xf8e8 // IPv4 checksum
	} else if !broadcastFlag {
		dhcp.Flags = 0x0000   // Flag to unicast
		udp.Checksum = 0xbd8f // Checksum
		ipv4.Checksum = 0x38ea
	} else {
		ipv4.Checksum = 0x38ea
		udp.Checksum = 0x3d8f
	}
	gopacket.SerializeLayers(buf, opts, ethernet, ipv4, udp, dhcp)
	return buf.Bytes()
}

func (o *DhcpClientState) getDhcpDeclinePkt(relay, broadcastFlag bool) []byte {
	var options layers.DHCPOptions
	options = append(options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDecline)}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptClientID, []byte{1, 0, 0, 1, 0, 0, 0}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptRequestIP, o.declineReqIp))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptServerID, net.IP{16, 0, 0, 0}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'h', 'o', 's', 't', '-', 't', 'r', 'e', 'x'}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{byte(layers.DHCPOptSubnetMask),
		byte(layers.DHCPOptRouter),
		byte(layers.DHCPOptDomainName),
		byte(layers.DHCPOptDNS),
		byte(layers.DHCPOptInterfaceMTU),
		byte(layers.DHCPOptNTPServers)}))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}

	ethernet, ipv4, udp := o.getBaseLayers()

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		HardwareOpts: 0,
		Xid:          0xbadf00d,
		Flags:        0x8000, // Broadcast
		ClientIP:     o.ciaddr,
		YourClientIP: net.IPv4(0, 0, 0, 0),
		NextServerIP: net.IPv4(0, 0, 0, 0),
		RelayAgentIP: net.IPv4(0, 0, 0, 0),
		ClientHWAddr: net.HardwareAddr{0, 0, 1, 0, 0, 0},
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      options}

	if relay {
		ethernet.SrcMAC = net.HardwareAddr{0, 0, 2, 0, 0, 0} // DG
		ethernet.DstMAC = net.HardwareAddr{0, 0, 1, 0, 0, 0} // DhcpSrv Client
		ipv4.SrcIP = net.IPv4(48, 0, 0, 1)                   // Relay
		ipv4.DstIP = net.IPv4(16, 0, 0, 0)                   // DhcpSrv Client
		udp.SrcPort = layers.UDPPort(DHCPV4_SERVER_PORT)     // Server Port
		dhcp.RelayAgentIP = net.IPv4(48, 0, 0, 1)
		dhcp.Flags = 0x0000    // Flags to unicast
		ipv4.Checksum = 0xf8e8 // IPv4 checksum
		udp.Checksum = 0xaf03  // Udp Checksum
	} else {
		ipv4.Checksum = 0x38ea
		udp.Checksum = 0xbf0c
	}
	gopacket.SerializeLayers(buf, opts, ethernet, ipv4, udp, dhcp)
	return buf.Bytes()
}

func (o *DhcpClientState) getRenewRebindPkt(lease uint32, relay bool, rebind bool) []byte {
	leaseByte := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseByte, lease)
	var options layers.DHCPOptions
	options = append(options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptClientID, []byte{1, 0, 0, 1, 0, 0, 0}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'h', 'o', 's', 't', '-', 't', 'r', 'e', 'x'}))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptLeaseTime, leaseByte))
	options = append(options, layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{byte(layers.DHCPOptSubnetMask),
		byte(layers.DHCPOptRouter),
		byte(layers.DHCPOptDomainName),
		byte(layers.DHCPOptDNS),
		byte(layers.DHCPOptInterfaceMTU),
		byte(layers.DHCPOptNTPServers)}))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 1, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{Version: 4,
		IHL:      5,
		TTL:      128,
		Id:       0xcc,
		SrcIP:    net.IPv4(16, 0, 0, 2),
		DstIP:    net.IPv4(16, 0, 0, 0),
		Checksum: 0x18EE,
		Protocol: layers.IPProtocolUDP}

	udp := &layers.UDP{SrcPort: DHCPV4_CLIENT_PORT,
		DstPort:  DHCPV4_SERVER_PORT,
		Checksum: 0x57ec}

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		HardwareOpts: 0,
		Xid:          0xbadf00d,
		Flags:        0x0000,
		ClientIP:     net.IPv4(16, 0, 0, 2),
		YourClientIP: net.IPv4(0, 0, 0, 0),
		NextServerIP: net.IPv4(0, 0, 0, 0),
		RelayAgentIP: net.IPv4(0, 0, 0, 0),
		ClientHWAddr: net.HardwareAddr{0, 0, 1, 0, 0, 0},
		ServerName:   make([]byte, 64),
		File:         make([]byte, 128),
		Options:      options}

	if rebind {
		if relay {
			panic("Not Supported")
		} else {
			ethernet.DstMAC = net.HardwareAddr{255, 255, 255, 255, 255, 255}
			ipv4.DstIP = net.IPv4(255, 255, 255, 255)
			ipv4.Checksum = 0x28ee
			udp.Checksum = 0x67ec
		}

	} else if relay {
		ethernet.SrcMAC = net.HardwareAddr{0, 0, 2, 0, 0, 0} // DG
		ipv4.SrcIP = net.IPv4(48, 0, 0, 10)                  // Client - Not Relay
		dhcp.ClientIP = net.IPv4(48, 0, 0, 10)
		ipv4.Checksum = 0xf8e5
		udp.Checksum = 0x17dc
	}
	gopacket.SerializeLayers(buf, opts, ethernet, ipv4, udp, dhcp)
	return buf.Bytes()
}

// OnEvent will generate client packets.
func (o *DhcpClientState) OnEvent(a, b interface{}) {

	relay := a.(bool)
	broadcastFlag := b.(bool)

	var pkt []byte = nil

	switch o.testCase {
	case Discover:
		pkt = o.getDhcpDiscoverPkt(relay, broadcastFlag)
	case Inform:
		pkt = o.getDhcpInformPkt(relay, broadcastFlag)
	case DiscoverRequest:
		if o.discoverSent {
			pkt = o.getDhcpRequestPkt(relay, broadcastFlag)
		} else {
			o.discoverSent = true
			pkt = o.getDhcpDiscoverPkt(relay, broadcastFlag)
			o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(2*time.Second))
		}
	case OfferDecline:
		if o.declineSent {
			pkt = o.getDhcpDiscoverPkt(relay, broadcastFlag)
		} else if o.discoverSent {
			o.declineSent = true
			pkt = o.getDhcpDeclinePkt(relay, broadcastFlag)
			o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(2*time.Second))
		} else {
			o.discoverSent = true
			pkt = o.getDhcpDiscoverPkt(relay, broadcastFlag)
			o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(2*time.Second))
		}
	case DiscoverRequestRenew:
		if o.bound {
			pkt = o.getRenewRebindPkt(60, relay, false)
		} else if o.discoverSent {
			o.bound = true
			pkt = o.getDhcpRequestPkt(relay, broadcastFlag)
			o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(5*time.Second))
		} else {
			o.discoverSent = true
			pkt = o.getDhcpDiscoverPkt(relay, broadcastFlag)
			o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(1*time.Second))
		}
	case DiscoverRequestRebind:
		if o.bound {
			pkt = o.getRenewRebindPkt(60, relay, true)
		} else if o.discoverSent {
			o.bound = true
			pkt = o.getDhcpRequestPkt(relay, broadcastFlag)
			o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(9*time.Second))
		} else {
			o.discoverSent = true
			pkt = o.getDhcpDiscoverPkt(relay, broadcastFlag)
			o.timerw.StartTicks(&o.timer, o.timerw.DurationToTicks(1*time.Second))
		}
	}
	m := o.tctx.MPool.Alloc(uint16(512))
	m.SetVPort(1)
	m.Append(pkt)
	o.tctx.Veth.OnRx(m)
}

// clientCb is called to simulate the client.
func clientCb(tctx *core.CThreadCtx, test *DhcpSrvTestBase) int {
	timerw := tctx.GetTimerCtx()
	ticks := timerw.DurationToTicks(2 * time.Second)
	var dhcpCState DhcpClientState
	dhcpCState.discoverReqIp = test.discoverReqIp
	dhcpCState.requestReqIp = test.requestReqIp
	dhcpCState.declineReqIp = test.declineReqIp
	dhcpCState.ciaddr = test.ciaddr
	dhcpCState.testCase = test.testCase
	dhcpCState.timer.SetCB(&dhcpCState, test.cbArg1, test.cbArg2)
	dhcpCState.tctx = tctx
	dhcpCState.timerw = timerw
	timerw.StartTicks(&dhcpCState.timer, ticks)
	return 0
}

func TestPluginDhcpSrv1(t *testing.T) {

	// NoRelay + Broadcast flag

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv1",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		testCase:     Discover,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv2(t *testing.T) {

	// NoRelay + Unicast flag

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv2",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		testCase:     Discover,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv3(t *testing.T) {

	// Relay + Unicast flag

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "48.0.0.0",
				"max": "48.0.0.15",
				"prefix": 28,
				"exclude": ["48.0.0.1"]
			}
		]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv3",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		testCase:     Discover,
		cb:           clientCb,
		cbArg1:       true,  // Relay
		cbArg2:       false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv4(t *testing.T) {

	// Relay + Unicast flag + Requested Ip

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "48.0.0.0",
				"max": "48.0.0.15",
				"prefix": 28,
				"exclude": ["48.0.0.1"]
			}
		]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:      "dhcpsrv4",
		dropAll:       true,
		monitor:       true,
		capture:       true,
		forceDGW:      true,
		ForcedgMac:    core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:      initJsonArray,
		duration:      10 * time.Second,
		clientsToSim:  1,
		testCase:      Discover,
		cb:            clientCb,
		cbArg1:        true,                 // Relay
		cbArg2:        false,                // No BroadcastFlag
		discoverReqIp: net.IP{48, 0, 0, 10}, // Be careful with this! If you change it, checksum will change! Works only with Relay in test!
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv5(t *testing.T) {

	// NoRelay + Broadcast flag + New Lease

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 3600
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv5",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		testCase:     Discover,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv6(t *testing.T) {

	// NoRelay + Broadcast flag + New Lease + Options

	// The options of T1, T2 are invalid, will be overridden.

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 60,
		"options": {
			"offer": [
				{
					"type": 58,
					"data": [0, 0, 0, 20]
				},
				{
					"type": 59,
					"data": [0, 0, 0, 30]
				},
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				}
			]
		}

	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv6",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		testCase:     Discover,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv7(t *testing.T) {

	// Simple Inform with broadcast - should fail as informs cant have broadcast flag.

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.15",
				"prefix": 28,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 60,
		"options": {
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 3,
					"data": [16, 0, 0, 1]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}

	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv7",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		ciaddr:       net.IP{16, 0, 0, 5},
		testCase:     Inform,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv8(t *testing.T) {

	// Simple Inform - with Relay

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "48.0.0.0",
				"max": "48.0.0.255",
				"prefix": 24,
				"exclude": ["48.0.0.1"]
			}
		],
		"default_lease": 60,
		"options": {
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 3,
					"data": [48, 0, 0, 1]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}

	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv8",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		ciaddr:       net.IP{48, 0, 0, 77},
		testCase:     Inform,
		cb:           clientCb,
		cbArg1:       true,  // Relay
		cbArg2:       false, // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv9(t *testing.T) {

	// Simple Inform no relay no broadcast

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 60,
		"options": {
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 3,
					"data": [16, 0, 0, 1]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}

	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv9",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		ciaddr:       net.IP{16, 0, 0, 125},
		testCase:     Inform,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv10(t *testing.T) {

	// DORA - No Relay, No BroadcastFlag

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 60,
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv10",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		requestReqIp: net.IP{16, 0, 0, 2},
		testCase:     DiscoverRequest,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv11(t *testing.T) {

	// DORA - No, BroadcastFlag

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 60,
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv11",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		requestReqIp: net.IP{16, 0, 0, 2},
		testCase:     DiscoverRequest,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv12(t *testing.T) {

	// DORA - Relay, No Broadcast Flag

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "48.0.0.0",
				"max": "48.0.0.255",
				"prefix": 24,
				"exclude": ["48.0.0.1"]
			}
		],
		"default_lease": 3600,
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 3,
					"data": [48, 0, 0, 1]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 3,
					"data": [48, 0, 0, 1]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:      "dhcpsrv12",
		dropAll:       true,
		monitor:       true,
		capture:       true,
		forceDGW:      true,
		ForcedgMac:    core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:      initJsonArray,
		duration:      10 * time.Second,
		clientsToSim:  1,
		discoverReqIp: net.IP{48, 0, 0, 10},
		requestReqIp:  net.IP{48, 0, 0, 10},
		testCase:      DiscoverRequest,
		cb:            clientCb,
		cbArg1:        true,  // No Relay
		cbArg2:        false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv13(t *testing.T) {

	// DORA - Relay, Broadcast Flag

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "48.0.0.0",
				"max": "48.0.0.255",
				"prefix": 24,
				"exclude": ["48.0.0.1"]
			}
		],
		"default_lease": 3600,
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 3,
					"data": [48, 0, 0, 1]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 3,
					"data": [48, 0, 0, 1]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv13",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		requestReqIp: net.IP{48, 0, 0, 2}, // If you change the Ip the checksum will fail!
		testCase:     DiscoverRequest,
		cb:           clientCb,
		cbArg1:       true, // No Relay
		cbArg2:       true, // Broadcast Flag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv14(t *testing.T) {

	// Discover -> Offer -> Decline -> Discover -> Offer

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv14",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		declineReqIp: net.IP{16, 0, 0, 2},
		testCase:     OfferDecline,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv15(t *testing.T) {

	// Discover -> Offer -> Decline -> Discover -> Offer
	// Relay

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "48.0.0.0",
				"max": "48.0.0.255",
				"prefix": 24,
				"exclude": ["48.0.0.1"]
			}
		]
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:      "dhcpsrv15",
		dropAll:       true,
		monitor:       true,
		capture:       true,
		forceDGW:      true,
		ForcedgMac:    core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:      initJsonArray,
		duration:      10 * time.Second,
		clientsToSim:  1,
		discoverReqIp: net.IP{48, 0, 0, 10},
		requestReqIp:  net.IP{48, 0, 0, 10},
		declineReqIp:  net.IP{48, 0, 0, 10},
		testCase:      OfferDecline,
		cb:            clientCb,
		cbArg1:        true,  // Relay
		cbArg2:        false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv16(t *testing.T) {

	// DORA + Renew, No relay, Broadcast

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 8,
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv16",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		requestReqIp: net.IP{16, 0, 0, 2},
		testCase:     DiscoverRequestRenew,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv17(t *testing.T) {

	// DORA + Renew, Relay, No Broadcast

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "48.0.0.0",
				"max": "48.0.0.255",
				"prefix": 24,
				"exclude": ["48.0.0.1"]
			}
		],
		"default_lease": 8,
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:      "dhcpsrv17",
		dropAll:       true,
		monitor:       true,
		capture:       true,
		forceDGW:      true,
		ForcedgMac:    core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:      initJsonArray,
		duration:      10 * time.Second,
		clientsToSim:  1,
		discoverReqIp: net.IP{48, 0, 0, 10},
		requestReqIp:  net.IP{48, 0, 0, 10},
		testCase:      DiscoverRequestRenew,
		cb:            clientCb,
		cbArg1:        true,  // Relay
		cbArg2:        false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv19(t *testing.T) {

	// DORA with next server ip

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 70,
		"next_server_ip": "16.0.1.1",
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv19",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     10 * time.Second,
		clientsToSim: 1,
		requestReqIp: net.IP{16, 0, 0, 2},
		testCase:     DiscoverRequest,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       false, // No BroadcastFlag
	}
	a.Run(t, true)
}

func TestPluginDhcpSrv18(t *testing.T) {

	// DORA + Rebind, No relay, Broadcast

	initJson1 := [][]byte{[]byte(`{
		"pools": [
			{
				"min": "16.0.0.0",
				"max": "16.0.0.255",
				"prefix": 24,
				"exclude": ["16.0.0.1"]
			}
		],
		"default_lease": 10,
		"options": {
			"offer": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
			"ack": [
				{
					"type": 6,
					"data": [8, 8, 8, 8]
				},
				{
					"type": 15,
					"data": [99, 105, 115, 99, 111, 46, 99, 111, 109]
				}
			]
		}
	}`)}
	var initJsonArray = [][][]byte{initJson1}

	a := &DhcpSrvTestBase{
		testname:     "dhcpsrv18",
		dropAll:      true,
		monitor:      true,
		capture:      true,
		forceDGW:     true,
		ForcedgMac:   core.MACKey{0, 0, 2, 0, 0, 0},
		initJSON:     initJsonArray,
		duration:     20 * time.Second,
		clientsToSim: 1,
		requestReqIp: net.IP{16, 0, 0, 2},
		testCase:     DiscoverRequestRebind,
		cb:           clientCb,
		cbArg1:       false, // No Relay
		cbArg2:       true,  // BroadcastFlag
	}
	a.Run(t, true)
}

func init() {
	flag.IntVar(&monitor, "monitor", 0, "monitor")
}
