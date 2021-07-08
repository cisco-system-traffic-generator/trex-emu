// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package dhcpv6

/*
RFC 8415  DHCPv6 client

*/

import (
	"bytes"
	"emu/core"
	"encoding/binary"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	DHCPV6_PLUG = "dhcpv6"
	/* state of each client */
	DHCP_STATE_INIT        = 0
	DHCP_STATE_REBOOTING   = 1
	DHCP_STATE_REQUESTING  = 2
	DHCP_STATE_SELECTING   = 3
	DHCP_STATE_REBINDING   = 4
	DHCP_STATE_RENEWING    = 5
	DHCP_STATE_BOUND       = 6
	IPV6_HEADER_SIZE       = 40
	STATUS_Success         = 0
	STATUS_UnspecFail      = 1
	STATUS_NoAddrsAvail    = 2
	STATUS_NoBinding       = 3
	STATUS_NotOnLink       = 4
	STATUS_UseMulticast    = 5
	STATUS_NoPrefixAvail   = 6
	REQ_MAX_RC             = 10 /* Max Request retry attempts */
	DEFAULT_TIMEOUT_T1_SEC = 1800
	DEFAULT_TIMEOUT_T2_SEC = 3600
)

// DhcpOptionsT represents a struct that can be provided in the Init Json in order to add/change the default options
// for different type of Dhcpv6 packets.
type DhcpOptionsT struct {
	Solicit  *[][]byte `json:"sol"`   // A slice of options for Solicit Packets, where each option is a binary slice [Code][Data].
	Request  *[][]byte `json:"req"`   // A slice of options for Request Packets, where each option is a binary slice [Code][Data]
	Release  *[][]byte `json:"rel"`   // A slice of options for Release Packets, where each option is a binary slice [Code][Data]
	Rebind   *[][]byte `json:"reb"`   // A slice of options for Rebind Packets, where each option is a binary slice [Code][Data]
	Renew    *[][]byte `json:"ren"`   // A slice of options for Renew Packets, where each option is a binary slice [Code][Data]
	RemoveOR bool      `json:"rm_or"` // Remove Default Option Request
	RemoveVC bool      `json:"rm_vc"` // Remove Default Vendor Class
}

// DhcpInit represents the Init Json for Dhcpv6 plugin
type DhcpInit struct {
	TimerDiscoverSec uint32        `json:"timerd"`
	TimerOfferSec    uint32        `json:"timero"`
	Options          *DhcpOptionsT `json:"options"`
}

// DhcpStats is a struct that aggregates Dhcpv6 statistics.
type DhcpStats struct {
	pktTxDiscover              uint64
	pktRxOffer                 uint64
	pktTxRequest               uint64
	pktRxAck                   uint64
	pktRxLenErr                uint64
	pktRxParserErr             uint64
	pktRxMissingServerIdOption uint64
	pktRxWrongXid              uint64
	pktRxWrongServerId         uint64
	pktRxWrongServerIP         uint64
	pktRxWrongClientId         uint64
	pktRxNoIANA                uint64
	pktRxWrongIANAId           uint64
	pktRxNoIAAddr              uint64
	pktRxWrongDstIp            uint64

	pktRxSTATUS_UnspecFail    uint64
	pktRxSTATUS_NoAddrsAvail  uint64
	pktRxSTATUS_NoBinding     uint64
	pktRxSTATUS_NotOnLink     uint64
	pktRxSTATUS_UseMulticast  uint64
	pktRxSTATUS_NoPrefixAvail uint64

	pktRxUnhandled uint64
	pktRxNotify    uint64
	pktRxRenew     uint64
	pktRxRebind    uint64
}

func NewDhcpStatsDb(o *DhcpStats) *core.CCounterDb {
	db := core.NewCCounterDb("dhcpv6")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxDiscover,
		Name:     "pktTxDiscover",
		Help:     "Tx discover",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxOffer,
		Name:     "pktRxOffer",
		Help:     "received offer",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxRequest,
		Name:     "pktTxRequest",
		Help:     "tx request",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxAck,
		Name:     "pktRxAck",
		Help:     "reply from the server",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxLenErr,
		Name:     "pktRxLenErr",
		Help:     "rx len error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxParserErr,
		Name:     "pktRxParserErr",
		Help:     "rx parser error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxUnhandled,
		Name:     "pktRxUnhandled",
		Help:     "rx unhandled dhcp packet",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNotify,
		Name:     "pktRxNotify",
		Help:     "Notify with new IPv6 addr",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRenew,
		Name:     "pktRxRenew",
		Help:     "rx renew",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRebind,
		Name:     "pktRxRebind",
		Help:     "rx Rebind",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxMissingServerIdOption,
		Name:     "pktRxMissingServerIdOption",
		Help:     "rx missing server id option",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongXid,
		Name:     "pktRxWrongXid",
		Help:     "rx wrong xid",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongServerId,
		Name:     "pktRxWrongServerId",
		Help:     "rx wrong server id",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongServerIP,
		Name:     "pktRxWrongServerIP",
		Help:     "rx wrong server dest ip",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongClientId,
		Name:     "pktRxWrongClientId",
		Help:     "rx wrong client id sent from the server",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNoIANA,
		Name:     "pktRxNoIANA",
		Help:     "rx no IANA server information",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongIANAId,
		Name:     "pktRxWrongIANAId",
		Help:     "rx no IANA server id",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNoIAAddr,
		Name:     "pktRxNoIAAddr",
		Help:     "rx no IANA new addr",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongDstIp,
		Name:     "pktRxWrongDstIp",
		Help:     "rx wrong destination ip",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSTATUS_UnspecFail,
		Name:     "pktRxSTATUS_UnspecFail",
		Help:     "rx server status error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSTATUS_NoAddrsAvail,
		Name:     "pktRxSTATUS_NoAddrsAvail",
		Help:     "rx server status error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSTATUS_NoBinding,
		Name:     "pktRxSTATUS_NoBinding",
		Help:     "rx server status error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSTATUS_NotOnLink,
		Name:     "pktRxSTATUS_NotOnLink",
		Help:     "rx server status error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSTATUS_UseMulticast,
		Name:     "pktRxSTATUS_UseMulticast",
		Help:     "rx server status error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxSTATUS_NoPrefixAvail,
		Name:     "pktRxSTATUS_NoPrefixAvail",
		Help:     "rx server status error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

type PluginDhcpClientTimer struct {
}

func (o *PluginDhcpClientTimer) OnEvent(a, b interface{}) {
	pi := a.(*PluginDhcpClient)
	pi.onTimerEvent()
}

//PluginDhcpClient information per client
type PluginDhcpClient struct {
	core.PluginBase
	dhcpNsPlug                 *PluginDhcpNs
	timerw                     *core.TimerCtx
	init                       DhcpInit
	cnt                        uint8
	state                      uint8
	ticksStart                 uint64
	timer                      core.CHTimerObj
	stats                      DhcpStats
	cdb                        *core.CCounterDb
	cdbv                       *core.CCounterDbVec
	timerCb                    PluginDhcpClientTimer
	t1                         uint32
	t2                         uint32
	timerDiscoverRetransmitSec uint32
	timerOfferRetransmitSec    uint32
	solicitPktTemplate         []byte // Solicit Packet Template
	requestPktTemplate         []byte // Request Packet Template
	releasePktTemplate         []byte // Request Packet Template
	rebindPktTemplate          []byte // Rebind Packet Template
	renewPktTemplate           []byte // Renew Packet Template
	solicitTimeOffset          uint16 // Time Elapsed Option Offset in Solicit Packet
	requestTimeOffset          uint16 // Time Elapsed Option Offset in Request Packet
	releaseTimeOffset          uint16 // Time Elapsed Option Offset in Release Packet
	rebindTimeOffset           uint16 // Time Elapsed Option Offset in Rebind Packet
	renewTimeOffset            uint16 // Time Elapsed Option Offset in Renew Packet
	cid                        []byte
	sid                        []byte // Server Id Learned
	sidOption                  []byte
	sipv6                      net.IP // Server Ip
	srcIpv6                    net.IP // Local Source Ipv6
	l3Offset                   uint16
	l4Offset                   uint16
	l7Offset                   uint16
	l7TimeOffset               uint16
	xid                        uint32
	iaid                       uint32
	serverOption               []byte
	pktIana                    layers.DHCPv6OptionIANA
}

var dhcpEvents = []string{}

// NewDhcpClient creates a new Dhcpv6 plugin
func NewDhcpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginDhcpClient)

	err := fastjson.Unmarshal(initJson, &o.init)
	if err == nil {
		/* init json was provided */
		if o.init.TimerDiscoverSec > 0 {
			o.timerDiscoverRetransmitSec = o.init.TimerDiscoverSec
		}
		if o.init.TimerOfferSec > 0 {
			o.timerOfferRetransmitSec = o.init.TimerOfferSec
		}
	}

	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, dhcpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(DHCPV6_PLUG)
	o.dhcpNsPlug = nsplg.Ext.(*PluginDhcpNs)
	o.OnCreate()

	return &o.PluginBase
}

// OnCreate is called when a new Dhcpv6 plugin is created.
func (o *PluginDhcpClient) OnCreate() {
	o.timerw = o.Tctx.GetTimerCtx()

	// build local source ipv6
	o.srcIpv6 = make(net.IP, net.IPv6len)
	var l6 core.Ipv6Key
	o.Client.GetIpv6LocalLink(&l6)
	o.cid = make([]byte, 0)
	copy(o.srcIpv6[:], l6[:])

	o.preparePacketTemplate()
	o.timerDiscoverRetransmitSec = 5
	o.timerOfferRetransmitSec = 10
	o.cdb = NewDhcpStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("dhcpv6")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.ticksStart = o.timerw.Ticks
	o.pktIana.IPv6 = make(net.IP, net.IPv6len)
	o.sipv6 = make(net.IP, net.IPv6len)
	o.sid = make([]byte, 0)
	o.SendDiscover()
}

func (o *PluginDhcpClient) resetTransactionTimer() {
	o.ticksStart = o.timerw.Ticks
}

// buildPacket builds a packet by adding the IPv6 and UDP to the L2 bytes and DHCPv6 bytes.
func (o *PluginDhcpClient) buildPacket(l2 []byte, dhcp *layers.DHCPv6) []byte {

	ipv6pkt := core.PacketUtlBuild(

		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       8,
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     1,
			SrcIP:        net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstIP:        net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02},
		},

		&layers.UDP{SrcPort: 546, DstPort: 547},
		dhcp,
	)

	p := append(l2, ipv6pkt...)
	ipoffset := len(l2)

	pktSize := len(p)

	ipv6 := layers.IPv6Header(p[ipoffset : ipoffset+IPV6_HEADER_SIZE])

	// set local ip
	var l6 core.Ipv6Key
	o.Client.GetIpv6LocalLink(&l6)
	copy(ipv6.SrcIP()[:], l6[:])
	copy(p[0:6], []byte{0x33, 0x33, 0, 1, 0, 2})

	rcof := ipoffset + IPV6_HEADER_SIZE
	binary.BigEndian.PutUint16(p[rcof+4:rcof+6], uint16(pktSize-rcof))
	ipv6.SetPyloadLength(uint16(pktSize - rcof))
	ipv6.FixUdpL4Checksum(p[rcof:], 0)

	return p
}

// preparePacketTemplate prepares packet templates for different types of DHCPv6 messages.
func (o *PluginDhcpClient) preparePacketTemplate() {
	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv6))
	o.l3Offset = uint16(len(l2))

	var xid uint32
	var iaid uint32
	if !o.Tctx.Simulation {
		xid = uint32(rand.Intn(0xffffff))
		iaid = uint32(rand.Intn(0xffffffff))
	} else {
		xid = 0x345678
		iaid = 0x12345678
	}
	o.xid = xid
	o.iaid = iaid

	o.l4Offset = o.l3Offset + IPV6_HEADER_SIZE
	o.l7Offset = o.l4Offset + 8

	transactionId := []byte{(byte((xid >> 16) & 0xff)), byte(((xid & 0xff00) >> 8)), byte(xid & 0xff)}

	solicit := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeSolicit, TransactionID: transactionId}
	o.createOptions(solicit, layers.DHCPv6MsgTypeSolicit)
	o.solicitPktTemplate = o.buildPacket(l2, solicit)

	request := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeRequest, TransactionID: transactionId}
	o.createOptions(request, layers.DHCPv6MsgTypeRequest)
	o.requestPktTemplate = o.buildPacket(l2, request)

	renew := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeRenew, TransactionID: transactionId}
	o.createOptions(renew, layers.DHCPv6MsgTypeRenew)
	o.renewPktTemplate = o.buildPacket(l2, renew)

	rebind := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeRebind, TransactionID: transactionId}
	o.createOptions(rebind, layers.DHCPv6MsgTypeRebind)
	o.rebindPktTemplate = o.buildPacket(l2, rebind)

	release := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeRelease, TransactionID: transactionId}
	o.createOptions(release, layers.DHCPv6MsgTypeRelease)
	o.releasePktTemplate = o.buildPacket(l2, release)

}

// createOptions creates the DHCP options for each type of message.
func (o *PluginDhcpClient) createOptions(dhcpv6 *layers.DHCPv6, msgType layers.DHCPv6MsgType) {

	var timeOffset *uint16
	var optionsBinary *[][]byte

	switch msgType {
	case layers.DHCPv6MsgTypeSolicit:
		timeOffset = &o.solicitTimeOffset
		if o.init.Options != nil {
			optionsBinary = o.init.Options.Solicit
		}
	case layers.DHCPv6MsgTypeRequest:
		timeOffset = &o.requestTimeOffset
		if o.init.Options != nil {
			optionsBinary = o.init.Options.Request
		}
	case layers.DHCPv6MsgTypeRenew:
		timeOffset = &o.renewTimeOffset
		if o.init.Options != nil {
			optionsBinary = o.init.Options.Renew
		}
	case layers.DHCPv6MsgTypeRebind:
		timeOffset = &o.rebindTimeOffset
		if o.init.Options != nil {
			optionsBinary = o.init.Options.Rebind
		}
	case layers.DHCPv6MsgTypeRelease:
		timeOffset = &o.releaseTimeOffset
		if o.init.Options != nil {
			optionsBinary = o.init.Options.Release
		}
	}

	clientId := &layers.DHCPv6DUID{Type: layers.DHCPv6DUIDTypeLL, HardwareType: []byte{0, 1}, LinkLayerAddress: o.Client.Mac[:]}
	if len(o.cid) == 0 {
		// Set Client Id so we can compare it, only in case it doesn't exist.
		o.cid = append(o.cid, clientId.Encode()[:]...)
	}

	ianaOpt := []byte{0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}

	binary.BigEndian.PutUint32(ianaOpt[0:4], o.iaid)

	removeOro := o.init.Options != nil && o.init.Options.RemoveOR == true
	removeVendorClass := o.init.Options != nil && o.init.Options.RemoveVC == true

	optionsMap := make(map[layers.DHCPv6Opt][]byte)
	optionsMap[layers.DHCPv6OptClientID] = clientId.Encode()
	if !removeOro {
		optionsMap[layers.DHCPv6OptOro] = []byte{0, 0x11, 0, 0x17, 0, 0x18, 0x00, 0x27}
	}
	if !removeVendorClass {
		optionsMap[layers.DHCPv6OptVendorClass] = []byte{0x00, 0x00, 0x01, 0x37, 0x00, 0x08, 0x4d, 0x53, 0x46, 0x54, 0x20, 0x35, 0x2e, 0x30}
	}
	optionsMap[layers.DHCPv6OptIANA] = ianaOpt
	optionsMap[layers.DHCPv6OptElapsedTime] = []byte{0x00, 0x00}

	if optionsBinary != nil {
		for _, op := range *optionsBinary {
			optionsMap[layers.DHCPv6Opt(binary.BigEndian.Uint16(op[0:2]))] = op[2:]
		}
	}

	for k, v := range optionsMap {
		dhcpv6.Options = append(dhcpv6.Options, layers.NewDHCPv6Option(k, v))
	}

	// Sort the options so we will have deterministic results. Otherwise tests will fail since the order
	// is not defined in the previous map.
	sort.Slice(dhcpv6.Options, func(i, j int) bool {
		return dhcpv6.Options[i].Code < dhcpv6.Options[j].Code
	})

	var optionsOffset uint16 = 4 // Represents the Options Starting Offset in Terms of L7.
	for i := range dhcpv6.Options {
		if dhcpv6.Options[i].Code == layers.DHCPv6OptElapsedTime {
			*timeOffset = optionsOffset + 4 // 2 for Code + 2 for Length
		} else {
			optionsOffset += dhcpv6.Options[i].Length + 4 // 2 for Code + 2 for Length
		}
	}
}

// SendDhcpPacket sends the correct DhcpPacket based on the message type. It updates the elapsed time and
// might append the server option.
func (o *PluginDhcpClient) SendDhcpPacket(msgType layers.DHCPv6MsgType, serverOption bool) {

	var msec uint32
	msec = uint32(o.timerw.Ticks-o.ticksStart) * o.timerw.MinTickMsec()
	length := 0
	timeOffset := o.l7Offset

	switch msgType {
	case layers.DHCPv6MsgTypeSolicit:
		length = len(o.solicitPktTemplate)
		timeOffset += o.solicitTimeOffset
	case layers.DHCPv6MsgTypeRequest:
		length = len(o.requestPktTemplate)
		timeOffset += o.requestTimeOffset
	case layers.DHCPv6MsgTypeRenew:
		length = len(o.renewPktTemplate)
		timeOffset += o.renewTimeOffset
	case layers.DHCPv6MsgTypeRebind:
		length = len(o.rebindPktTemplate)
		timeOffset += o.rebindTimeOffset
	case layers.DHCPv6MsgTypeRelease:
		length = len(o.releasePktTemplate)
		timeOffset += o.releaseTimeOffset
	}

	if serverOption {
		length += len(o.sidOption)
	}

	m := o.Ns.AllocMbuf(uint16(length))

	switch msgType {
	case layers.DHCPv6MsgTypeSolicit:
		m.Append(o.solicitPktTemplate)
	case layers.DHCPv6MsgTypeRequest:
		m.Append(o.requestPktTemplate)
	case layers.DHCPv6MsgTypeRenew:
		m.Append(o.renewPktTemplate)
	case layers.DHCPv6MsgTypeRebind:
		m.Append(o.rebindPktTemplate)
	case layers.DHCPv6MsgTypeRelease:
		m.Append(o.releasePktTemplate)
	}

	if serverOption {
		m.Append(o.sidOption)
	}

	p := m.GetData()

	// Update Time Offset
	binary.BigEndian.PutUint16(p[timeOffset:timeOffset+2], uint16(msec/10))

	// Update IPv6 and UDP length in case we appended the SID option.
	ipv6o := o.l3Offset
	ipv6 := layers.IPv6Header(p[ipv6o : ipv6o+IPV6_HEADER_SIZE])

	if serverOption {
		newlen := ipv6.PayloadLength() + uint16(len(o.sidOption))
		ipv6.SetPyloadLength(newlen)
		binary.BigEndian.PutUint16(p[o.l4Offset+4:o.l4Offset+6], newlen)
	}

	ipv6.FixUdpL4Checksum(p[o.l4Offset:], 0)

	o.Tctx.Veth.Send(m)
}

func (o *PluginDhcpClient) SendDiscover() {
	o.state = DHCP_STATE_INIT
	o.cnt = 0
	o.restartTimer(o.timerDiscoverRetransmitSec)
	o.stats.pktTxDiscover++
	o.SendDhcpPacket(layers.DHCPv6MsgTypeSolicit, false)
}

/*OnEvent support event change of IP  */
func (o *PluginDhcpClient) OnEvent(msg string, a, b interface{}) {}

func (o *PluginDhcpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	o.SendRenewRebind(false, true, 0)
	ctx.UnregisterEvents(&o.PluginBase, dhcpEvents)
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *PluginDhcpClient) SendRenewRebind(rebind bool, release bool, timerSec uint32) {

	o.stats.pktTxRequest++
	o.restartTimer(timerSec)

	if release {
		o.SendDhcpPacket(layers.DHCPv6MsgTypeRelease, true)
		return
	}

	if rebind {
		o.SendDhcpPacket(layers.DHCPv6MsgTypeRebind, true)
	} else {
		o.SendDhcpPacket(layers.DHCPv6MsgTypeRenew, true)
	}
}

func (o *PluginDhcpClient) SendReq() {

	o.restartTimer(o.timerOfferRetransmitSec)
	o.SendDhcpPacket(layers.DHCPv6MsgTypeRequest, true)
	o.stats.pktTxRequest++
}

func XidToUint32(xid []byte) uint32 {
	var res uint32
	if len(xid) != 3 {
		return 0xffffffff
	}
	res = uint32(xid[0])<<16 + uint32(xid[1])<<8 + uint32(xid[2])
	return res
}

func (o *PluginDhcpClient) verifyPkt(dhcph *layers.DHCPv6,
	ipv6 layers.IPv6Header,
	cid []byte,
	sid []byte,
	validIana bool,
) int {

	var verifysid bool
	if o.state != DHCP_STATE_INIT {
		verifysid = true
	}

	if XidToUint32(dhcph.TransactionID) != o.xid {
		o.stats.pktRxWrongXid++
		return -1
	}

	// compare client id

	if !bytes.Equal(o.cid, cid) {
		o.stats.pktRxWrongClientId++
		return -1
	}

	if !validIana {
		o.stats.pktRxNoIANA++
		return -1
		if o.pktIana.IAID != o.iaid {
			o.stats.pktRxWrongIANAId++
			return -1
		}

		if !o.pktIana.OptionValid {
			o.stats.pktRxNoIAAddr++
			return -1
		}
	}

	if verifysid {

		if !bytes.Equal(o.sid, sid) {
			o.stats.pktRxWrongServerId++
			return -1
		}

		if !bytes.Equal(o.sipv6, ipv6.SrcIP()) {
			o.stats.pktRxWrongServerIP++
			return -1
		}

	}

	if !bytes.Equal(ipv6.DstIP(), o.srcIpv6) {
		o.stats.pktRxWrongDstIp++
		return -1
	}

	return 0
}

func (o *PluginDhcpClient) restartTimer(sec uint32) {
	if sec == 0 {
		return
	}
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.timerw.Start(&o.timer, time.Duration(sec)*time.Second)
}

//onTimerEvent on timer event callback
func (o *PluginDhcpClient) onTimerEvent() {
	o.cnt++

	if o.cnt > REQ_MAX_RC {
		// reset to discover
		o.resetTransactionTimer()
		o.SendDiscover()
		return
	}

	switch o.state {
	case DHCP_STATE_INIT:
		o.SendDiscover()
	case DHCP_STATE_REQUESTING:
		o.SendReq()
	case DHCP_STATE_BOUND:
		if o.cnt == 1 {
			o.resetTransactionTimer()
		}
		o.state = DHCP_STATE_RENEWING
		o.stats.pktRxRenew++
		o.SendRenewRebind(false, false, o.t2-o.t1)
	case DHCP_STATE_RENEWING:
		if o.cnt == 1 {
			o.resetTransactionTimer()
		}
		o.state = DHCP_STATE_REBINDING
		o.stats.pktRxRebind++
		o.SendRenewRebind(true, false, o.timerOfferRetransmitSec)
	}
}

func normTime(t uint32, t2 bool) uint32 {
	if t == 0 {
		if t2 {
			return DEFAULT_TIMEOUT_T2_SEC
		}
		return DEFAULT_TIMEOUT_T1_SEC
	}
	return t
}

func (o *PluginDhcpClient) HandleAckNak(dhcpmt layers.DHCPv6MsgType,
	dhcph *layers.DHCPv6,
	ipv6 layers.IPv6Header,
	notify bool,
	status uint16) int {

	if status != STATUS_Success {
		o.SendDiscover()
		return -1
	}

	switch dhcpmt {
	case layers.DHCPv6MsgTypeReply:
		o.stats.pktRxAck++
		o.state = DHCP_STATE_BOUND
		if notify {
			o.stats.pktRxNotify++
			var NewIpv6 core.Ipv6Key
			copy(NewIpv6[:], o.pktIana.IPv6)
			o.Client.UpdateDIPv6(NewIpv6)
		}

		o.t1 = normTime(o.pktIana.T1, false)
		o.t2 = normTime(o.pktIana.T2, true)
		if o.t2 < o.t1 {
			o.t2 = o.t1 + 60
		}
		o.cnt = 0
		o.restartTimer(o.t1)
	}
	return 0
}

// EncodeOption remakes the encode() function of layers.DHCPv6Option.
func EncodeOption(o layers.DHCPv6Option) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], uint16(o.Code))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(o.Data)))
	b = append(b, o.Data[:]...)
	return b
}

func (o *PluginDhcpClient) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/

	ipv6 := layers.IPv6Header(p[ps.L3 : ps.L3+IPV6_HEADER_SIZE])

	dhcphlen := ps.L7Len

	if dhcphlen < 4 {
		o.stats.pktRxLenErr++
		return core.PARSER_ERR
	}

	var dhcph layers.DHCPv6
	err := dhcph.DecodeFromBytes(p[ps.L7:ps.L7+dhcphlen], gopacket.NilDecodeFeedback)
	if err != nil {
		o.stats.pktRxParserErr++
		return core.PARSER_ERR
	}

	var dhcpmt layers.DHCPv6MsgType
	dhcpmt = dhcph.MsgType
	var cid []byte
	var sid []byte
	var validIana bool
	var status uint16

	for _, op := range dhcph.Options {
		switch op.Code {
		case layers.DHCPv6OptClientID:
			cid = op.Data
		case layers.DHCPv6OptServerID:
			sid = op.Data
		case layers.DHCPv6OptIANA:
			o.pktIana.OptionValid = false // invalidate
			if o.pktIana.Decode(op.Data) == nil {
				validIana = true
			}
		case layers.DHCPv6OptStatusCode:
			if len(op.Data) == 2 {
				status = binary.BigEndian.Uint16(op.Data[0:2])
			} else {
				status = STATUS_UnspecFail
			}

		default:
		}
	}

	// update the counters
	if status != 0 {
		switch status {
		case STATUS_UnspecFail:
			o.stats.pktRxSTATUS_UnspecFail++
		case STATUS_NoAddrsAvail:
			o.stats.pktRxSTATUS_NoAddrsAvail++
		case STATUS_NoBinding:
			o.stats.pktRxSTATUS_NoBinding++
		case STATUS_NotOnLink:
			o.stats.pktRxSTATUS_NotOnLink++
		case STATUS_UseMulticast:
			o.stats.pktRxSTATUS_UseMulticast++
		case STATUS_NoPrefixAvail:
			o.stats.pktRxSTATUS_NoPrefixAvail++
		default:
			o.stats.pktRxSTATUS_UnspecFail++
		}
	}

	if o.verifyPkt(&dhcph, ipv6, cid, sid, validIana) != 0 {
		return -1
	}

	switch o.state {
	case DHCP_STATE_INIT:

		if dhcpmt == layers.DHCPv6MsgTypeAdverstise {
			o.stats.pktRxOffer++
			// save server ip and server-id option
			if status != STATUS_Success {
				return -1
			}

			if sid == nil {
				o.stats.pktRxMissingServerIdOption++
				return -1
			}
			o.sid = append(o.sid, sid[:]...)
			o.sidOption = EncodeOption(layers.NewDHCPv6Option(layers.DHCPv6OptServerID, o.sid))
			copy(o.sipv6[:], ipv6.SrcIP())
			o.state = DHCP_STATE_REQUESTING
			o.SendReq()
			return 0
		}

	case DHCP_STATE_REQUESTING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv6, true, status)

	case DHCP_STATE_BOUND:
		o.stats.pktRxUnhandled++

	case DHCP_STATE_RENEWING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv6, true, status)

	case DHCP_STATE_REBINDING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv6, true, status)

	default:
		o.stats.pktRxUnhandled++
	}
	return 0
}

// PluginDhcpNs icmp information per namespace
type PluginDhcpNs struct {
	core.PluginBase
	stats DhcpStats
}

func NewDhcpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginDhcpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase
}

func (o *PluginDhcpNs) OnRemove(ctx *core.PluginCtx) {}

func (o *PluginDhcpNs) OnEvent(msg string, a, b interface{}) {}

func (o *PluginDhcpNs) SetTruncated() {}

func (o *PluginDhcpNs) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/
	/* UDP checksum was verified in the parser */
	var mackey core.MACKey
	copy(mackey[:], p[0:6])

	client := o.Ns.CLookupByMac(&mackey)

	if client == nil {
		return core.PARSER_ERR
	}

	cplg := client.PluginCtx.Get(DHCPV6_PLUG)
	if cplg == nil {
		return core.PARSER_ERR
	}
	dhcpCPlug := cplg.Ext.(*PluginDhcpClient)
	return dhcpCPlug.HandleRxDhcpPacket(ps)
}

// HandleRxDhcpPacket Parser call this function with mbuf from the pool
func HandleRxDhcpv6Packet(ps *core.ParserPacketState) int {

	ns := ps.Tctx.GetNs(ps.Tun)
	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(DHCPV6_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	dhcpPlug := nsplg.Ext.(*PluginDhcpNs)
	return dhcpPlug.HandleRxDhcpPacket(ps)
}

type PluginDhcpCReg struct{}
type PluginDhcpNsReg struct{}

func (o PluginDhcpCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewDhcpClient(ctx, initJson)
}

func (o PluginDhcpNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewDhcpNs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */
type (
	ApiDhcpClientCntHandler struct{}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginDhcpNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, DHCPV6_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginDhcpNs)

	return arpNs, nil
}

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginDhcpClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, DHCPV6_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginDhcpClient)

	return pClient, nil
}

func (h ApiDhcpClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return c.cdbv.GeneralCounters(err, tctx, params, &p)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(DHCPV6_PLUG,
		core.PluginRegisterData{Client: PluginDhcpCReg{},
			Ns:     PluginDhcpNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command like ping etc
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("dhcpv6_client_cnt", ApiDhcpClientCntHandler{}, false) // get counters/meta

	/* register callback for rx side*/
	core.ParserRegister("dhcpv6", HandleRxDhcpv6Packet)
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("dhcpv6")
}
