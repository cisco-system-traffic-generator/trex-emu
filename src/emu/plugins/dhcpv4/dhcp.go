// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package dhcp

/*
RFC 2131 DHCP client

client inijson {
	TimerDiscoverSec uint32 `json:"timerd"`
	TimerOfferSec    uint32 `json:"timero"`
}:

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
	"time"

   	"github.com/intel-go/fastjson"
)

const (
	DHCP_PLUG = "dhcp"
	/* state of each client */
	DHCP_STATE_INIT       = 0
	DHCP_STATE_REBOOTING  = 1
	DHCP_STATE_REQUESTING = 2
	DHCP_STATE_SELECTING  = 3
	DHCP_STATE_REBINDING  = 4
	DHCP_STATE_RENEWING   = 5
	DHCP_STATE_BOUND      = 6
)

type DhcpInit struct {
	TimerDiscoverSec uint32 `json:"timerd"`
	TimerOfferSec    uint32 `json:"timero"`
    DiscoverDhcpClassIdOption string  `json:"discoverDhcpClassIdOption"` 
    RequestDhcpClassIdOption  string  `json:"requestDhcpClassIdOption"`       
}

type DhcpStats struct {
	pktTxDiscover    uint64
	pktRxOffer       uint64
	pktTxRequest     uint64
	pktRxAck         uint64
	pktRxLenErr      uint64
	pktRxParserErr   uint64
	pktRxWrongXid    uint64
	pktRxWrongHwType uint64
	pktRxWrongIP     uint64
	pktRxUnhandle    uint64
	pktRxNotify      uint64
	pktRxRenew       uint64
	pktRxNack        uint64
	pktRxRebind      uint64
	pktRxBroadcast   uint64
}

func NewDhcpStatsDb(o *DhcpStats) *core.CCounterDb {
	db := core.NewCCounterDb("dhcp")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxBroadcast,
		Name:     "pktRxBroadcast",
		Help:     "Rx broadcast L2, should be unicast ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTxDiscover,
		Name:     "pktTxDiscover",
		Help:     "Tx discover ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxOffer,
		Name:     "pktRxOffer",
		Help:     "rx offer ",
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
		Help:     "ack from the server",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})
	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxLenErr,
		Name:     "pktRxLenErr",
		Help:     "len error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxParserErr,
		Name:     "pktRxParserErr",
		Help:     "parser error",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxUnhandle,
		Name:     "pktRxUnhandle",
		Help:     "unhandle dhcp packet",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNotify,
		Name:     "pktRxNotify",
		Help:     "notify with new IPv4 addr",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRenew,
		Name:     "pktRxRenew",
		Help:     "renew",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxNack,
		Name:     "pktRxNack",
		Help:     "nack",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxRebind,
		Name:     "pktRxRebind",
		Help:     "Rx rebind",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongXid,
		Name:     "pktRxWrongXid",
		Help:     "wrong xid ignore",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongHwType,
		Name:     "pktRxWrongHwType",
		Help:     "wrong hw type",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktRxWrongIP,
		Name:     "pktRxWrongIP",
		Help:     "rx with wrong dest ip",
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
	dhcpNsPlug *PluginDhcpNs
	timerw     *core.TimerCtx
	cnt        uint8
	state      uint8

	ipv4                       core.Ipv4Key
	server                     core.Ipv4Key
	serverMac                  core.MACKey
	dg                         core.Ipv4Key
	timer                      core.CHTimerObj
	stats                      DhcpStats
	cdb                        *core.CCounterDb
	cdbv                       *core.CCounterDbVec
	timerCb                    PluginDhcpClientTimer
	timerDiscoverRetransmitSec uint32
	timerOfferRetransmitSec    uint32
	t1                         uint32
	t2                         uint32
	discoverPktTemplate        []byte
    discoverDhcpClassIdOption  string  
	requestPktTemplate         []byte
    requestDhcpClassIdOption   string   
	requestRenewPktTemplate    []byte
	l3Offset                   uint16
	xid                        uint32
}

var dhcpEvents = []string{}

/*NewDhcpClient create plugin */
func NewDhcpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	var init DhcpInit
	err := fastjson.Unmarshal(initJson, &init)


	o := new(PluginDhcpClient)

        if err == nil {
            if  init.DiscoverDhcpClassIdOption != ""  {
                 o.discoverDhcpClassIdOption = init.DiscoverDhcpClassIdOption  
             }
            if  init.RequestDhcpClassIdOption != ""  {
                 o.requestDhcpClassIdOption = init.RequestDhcpClassIdOption   
             }

           
       }

	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, dhcpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(DHCP_PLUG)
	o.dhcpNsPlug = nsplg.Ext.(*PluginDhcpNs)
	o.OnCreate()

	if err == nil {
		/* init json was provided */
		if init.TimerDiscoverSec > 0 {
			o.timerDiscoverRetransmitSec = init.TimerDiscoverSec
		}
		if init.TimerOfferSec > 0 {
			o.timerOfferRetransmitSec = init.TimerOfferSec
		}

       
	}
	return &o.PluginBase
}

func (o *PluginDhcpClient) OnCreate() {
	o.timerw = o.Tctx.GetTimerCtx()
	o.preparePacketTemplate()
	o.timerDiscoverRetransmitSec = 5
	o.timerOfferRetransmitSec = 10
  	o.cdb = NewDhcpStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("dhcp")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.SendDiscover()
}

func (o *PluginDhcpClient) preparePacketTemplate() {
	

	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv4))
	o.l3Offset = uint16(len(l2))

	options := append([]byte{1}, o.Client.Mac[:]...)

	var xid uint32
	if !o.Tctx.Simulation {
		xid = uint32(rand.Intn(0xffffffff))
	} else {
		xid = 0x12345678
	}
	o.xid = xid

	dhcp := &layers.DHCPv4{Operation: layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          xid,
		ClientIP:     net.IP{0, 0, 0, 0},
		YourClientIP: net.IP{0, 0, 0, 0},
		NextServerIP: net.IP{0, 0, 0, 0},
		RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr(o.Client.Mac[:]),
		ServerName:   make([]byte, 64), File: make([]byte, 128)}
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptClientID, options))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte{0, 0, 0, 0}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte{'h', 'o', 's', 't', '-', 't', 'r', 'e', 'x', 's'}))
	dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptParamsRequest,
		[]byte{byte(layers.DHCPOptSubnetMask),
			byte(layers.DHCPOptRouter),
			byte(layers.DHCPOptDomainName),
			byte(layers.DHCPOptDNS),
			byte(layers.DHCPOptInterfaceMTU),
			byte(layers.DHCPOptNTPServers)}))

        if  o.discoverDhcpClassIdOption != "" {
            dhcp.Options = append(dhcp.Options, layers.NewDHCPOption(layers.DHCPOptClassID,  []byte( o.discoverDhcpClassIdOption)))
        }
     
	d := core.PacketUtlBuild(
		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc,
			SrcIP:    net.IPv4(0, 0, 0, 0),
			DstIP:    net.IPv4(255, 255, 255, 255),
			Protocol: layers.IPProtocolUDP},

		&layers.UDP{SrcPort: 68, DstPort: 67},
		dhcp,
	)

	ipv4 := layers.IPv4Header(d[0:20])
	ipv4.SetLength(uint16(len(d)))
	ipv4.UpdateChecksum()

	binary.BigEndian.PutUint16(d[24:26], uint16(len(d)-20))
	binary.BigEndian.PutUint16(d[26:28], 0)
	cs := layers.PktChecksumTcpUdp(d[20:], 0, ipv4)
	binary.BigEndian.PutUint16(d[26:28], cs)

	o.discoverPktTemplate = append(l2, d...)

	dhcpReq := &layers.DHCPv4{Operation: layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          xid,
		ClientIP:     net.IP{0, 0, 0, 0},
		YourClientIP: net.IP{0, 0, 0, 0},
		NextServerIP: net.IP{0, 0, 0, 0},
		RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr(o.Client.Mac[:]),
		ServerName:   make([]byte, 64), File: make([]byte, 128)}
	dhcpReq.Options = append(dhcpReq.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}))
	dhcpReq.Options = append(dhcpReq.Options, layers.NewDHCPOption(layers.DHCPOptClientID, options))
	dhcpReq.Options = append(dhcpReq.Options, layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte{0, 0, 0, 0}))
	dhcpReq.Options = append(dhcpReq.Options, layers.NewDHCPOption(layers.DHCPOptServerID, []byte{0, 0, 0, 0}))
	dhcpReq.Options = append(dhcpReq.Options, layers.NewDHCPOption(layers.DHCPOptParamsRequest,
		[]byte{byte(layers.DHCPOptSubnetMask),
			byte(layers.DHCPOptRouter),
			byte(layers.DHCPOptDomainName),
			byte(layers.DHCPOptDNS),
			byte(layers.DHCPOptInterfaceMTU),
			byte(layers.DHCPOptNTPServers)}))

        if  o.requestDhcpClassIdOption!= "" {
           dhcpReq.Options = append(dhcpReq.Options, layers.NewDHCPOption(layers.DHCPOptClassID,  []byte(o.requestDhcpClassIdOption)))
        }
        
 	dr := core.PacketUtlBuild(
		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc,
			SrcIP:    net.IPv4(0, 0, 0, 0),
			DstIP:    net.IPv4(255, 255, 255, 255),
			Protocol: layers.IPProtocolUDP},

		&layers.UDP{SrcPort: 68, DstPort: 67},
		dhcpReq,
	)

	ipv4 = layers.IPv4Header(dr[0:20])
	ipv4.SetLength(uint16(len(dr)))
	ipv4.UpdateChecksum()

	binary.BigEndian.PutUint16(dr[24:26], uint16(len(dr)-20))
	binary.BigEndian.PutUint16(dr[26:28], 0)
	cs = layers.PktChecksumTcpUdp(d[20:], 0, ipv4)
	binary.BigEndian.PutUint16(d[26:28], cs)

	o.requestPktTemplate = append(l2, dr...)

	dhcpReqRenew := &layers.DHCPv4{Operation: layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          xid,
		ClientIP:     net.IP{0, 0, 0, 0},
		YourClientIP: net.IP{0, 0, 0, 0},
		NextServerIP: net.IP{0, 0, 0, 0},
		RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr(o.Client.Mac[:]),
		ServerName:   make([]byte, 64), File: make([]byte, 128)}
	dhcpReqRenew.Options = append(dhcpReqRenew.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}))
	dhcpReqRenew.Options = append(dhcpReqRenew.Options, layers.NewDHCPOption(layers.DHCPOptClientID, options))

	drn := core.PacketUtlBuild(
		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc,
			SrcIP:    net.IPv4(0, 0, 0, 0),
			DstIP:    net.IPv4(0, 0, 0, 0),
			Protocol: layers.IPProtocolUDP},

		&layers.UDP{SrcPort: 68, DstPort: 67},
		dhcpReqRenew,
	)
	ipv4 = layers.IPv4Header(drn[0:20])
	ipv4.SetLength(uint16(len(drn)))
	ipv4.UpdateChecksum()

	binary.BigEndian.PutUint16(drn[24:26], uint16(len(drn)-20))
	binary.BigEndian.PutUint16(drn[26:28], 0)
	cs = layers.PktChecksumTcpUdp(d[20:], 0, ipv4)
	binary.BigEndian.PutUint16(d[26:28], cs)

	o.requestRenewPktTemplate = append(l2, drn...)

}

func (o *PluginDhcpClient) SendDiscover() {
	o.state = DHCP_STATE_INIT
	o.cnt = 0
	o.restartTimer(o.timerDiscoverRetransmitSec)
	o.stats.pktTxDiscover++
	o.Tctx.Veth.SendBuffer(false, o.Client, o.discoverPktTemplate)
}

/*OnEvent support event change of IP  */
func (o *PluginDhcpClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginDhcpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	o.SendRenewRebind(false, true, 0)
	ctx.UnregisterEvents(&o.PluginBase, dhcpEvents)
	// TBD send release message
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *PluginDhcpClient) SendRenewRebind(rebind bool, release bool, timerSec uint32) {

	pkt := o.requestRenewPktTemplate

	unitcast := true

	if rebind {
		unitcast = false
	}
	//
	off := o.l3Offset + 20 + 8 + 12
	copy(pkt[off:off+4], o.ipv4[:])
	if release {
		pkt[off+230] = 7
	} else {
		pkt[off+230] = 3
	}

	ipo := o.l3Offset
	ipv4 := layers.IPv4Header(pkt[ipo : ipo+20])

	if unitcast {
		copy(pkt[0:6], o.serverMac[:])
		srcIPv4 := o.ipv4
		serverIPv4 := o.server
		ipv4.SetIPDst(serverIPv4.Uint32())
		ipv4.SetIPSrc(srcIPv4.Uint32())
	} else {
		copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		ipv4.SetIPDst(0xffffffff)
		ipv4.SetIPSrc(0)
	}
	ipv4.UpdateChecksum()

	binary.BigEndian.PutUint16(pkt[ipo+26:ipo+28], 0)
	cs := layers.PktChecksumTcpUdp(pkt[ipo+20:], 0, ipv4)
	binary.BigEndian.PutUint16(pkt[ipo+26:ipo+28], cs)

	o.stats.pktTxRequest++

	o.restartTimer(timerSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, pkt)
}

func (o *PluginDhcpClient) SendReq() {
	pkt := o.requestPktTemplate

	// offset for the option
	off := o.l3Offset + 20 + 8 + 254
	copy(pkt[off:off+4], o.ipv4[:])
	copy(pkt[off+6:off+10], o.server[:])
	ipo := o.l3Offset
	ipv4 := layers.IPv4Header(pkt[ipo : ipo+20])

	binary.BigEndian.PutUint16(pkt[ipo+26:ipo+28], 0)
	cs := layers.PktChecksumTcpUdp(pkt[ipo+20:], 0, ipv4)
	binary.BigEndian.PutUint16(pkt[ipo+26:ipo+28], cs)

	o.stats.pktTxRequest++
	o.restartTimer(o.timerOfferRetransmitSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, pkt)
}

func convert(ipv4 net.IP) core.Ipv4Key {
	var key core.Ipv4Key
	if len(ipv4) != 4 {
		return key
	}
	key[0] = ipv4[0]
	key[1] = ipv4[1]
	key[2] = ipv4[2]
	key[3] = ipv4[3]
	return key
}

func (o *PluginDhcpClient) verifyPkt(dhcph *layers.DHCPv4, ipv4 layers.IPv4Header, learn bool, server *core.Ipv4Key) int {
	if dhcph.Xid != o.xid {
		o.stats.pktRxWrongXid++
		return -1
	}

	if dhcph.HardwareType != layers.LinkTypeEthernet {
		o.stats.pktRxWrongHwType++
		return -1
	}

	if dhcph.HardwareLen != 6 {
		o.stats.pktRxWrongHwType++
		return -1
	}

	if len(dhcph.YourClientIP) != 4 {
		o.stats.pktRxWrongIP++
		return -1
	}
	if !learn {
		var key core.Ipv4Key
		key = convert(dhcph.YourClientIP)
		if key.Uint32() != ipv4.GetIPDst() {
			o.stats.pktRxWrongIP++
			return -1
		}
		if o.server.IsZero() {
			o.stats.pktRxWrongIP++
			return -1
		}

		if server == nil {
			o.stats.pktRxWrongIP++
			return -1
		} else {
			if !bytes.Equal(o.server[:], server[:]) {
				o.stats.pktRxWrongIP++
				return -1
			}
		}

	} else {
		var key core.Ipv4Key
		key = convert(dhcph.YourClientIP)
		copy(o.ipv4[:], key[:])
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

func (o *PluginDhcpClient) getT1InSec(p *layers.DHCPOption) uint32 {
	if len(p.Data) != 4 {
		return 1811
	}
	return uint32(p.Data[0])<<24 | uint32(p.Data[1])<<16 | uint32(p.Data[2])<<8 | uint32(p.Data[3])
}

//onTimerEvent on timer event callback
func (o *PluginDhcpClient) onTimerEvent() {
	switch o.state {
	case DHCP_STATE_INIT:
		o.SendDiscover()
	case DHCP_STATE_REQUESTING:
		o.cnt++
		if o.cnt > 5 {
			o.SendDiscover()
		} else {
			o.SendReq()
		}
	case DHCP_STATE_BOUND:
		o.state = DHCP_STATE_RENEWING
		o.stats.pktRxRenew++
		o.SendRenewRebind(false, false, o.t2-o.t1)
	case DHCP_STATE_RENEWING:
		o.state = DHCP_STATE_REBINDING
		o.stats.pktRxRebind++
		o.SendRenewRebind(true, false, o.timerOfferRetransmitSec)
	}

}

func (o *PluginDhcpClient) HandleAckNak(dhcpmt layers.DHCPMsgType,
	dhcph *layers.DHCPv4,
	ipv4 layers.IPv4Header,
	t1 uint32,
	t2 uint32,
	notify bool,
	server *core.Ipv4Key) int {
	switch dhcpmt {
	case layers.DHCPMsgTypeAck:
		o.stats.pktRxAck++
		if o.verifyPkt(dhcph, ipv4, false, server) != 0 {
			return -1
		}
		o.state = DHCP_STATE_BOUND
		if notify {
			o.stats.pktRxNotify++
			ipv4addr := ipv4.GetIPDst()
			if ipv4addr != 0 {
				var ipv4key core.Ipv4Key
				ipv4key.SetUint32(ipv4addr)
				// update ip
				o.Client.UpdateIPv4(ipv4key)
				if !o.dg.IsZero() {
					// update dg
					ipv4key.SetUint32(o.dg.Uint32())
				} else {
					ipv4key.SetUint32(o.server.Uint32())
				}
				o.Client.UpdateDgIPv4(ipv4key)
			}
		}
		o.restartTimer(t1)
		o.t1 = t1
		o.t2 = t2
		if o.t2 < o.t1 {
			o.t2 = o.t1 + 1
		}
	case layers.DHCPMsgTypeNak:
		o.SendDiscover()
	}
	return 0
}

func (o *PluginDhcpClient) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/
	var mackey core.MACKey
	copy(mackey[:], p[0:6])

	if mackey.IsBroadcast() {
		o.stats.pktRxBroadcast++
	}

	ipv4 := layers.IPv4Header(p[ps.L3 : ps.L3+20])

	dhcphlen := ps.L7Len

	if dhcphlen < 240 {
		o.stats.pktRxLenErr++
		return core.PARSER_ERR
	}

	var dhcph layers.DHCPv4
	err := dhcph.DecodeFromBytes(p[ps.L7:ps.L7+dhcphlen], gopacket.NilDecodeFeedback)
	if err != nil {
		o.stats.pktRxParserErr++
		return core.PARSER_ERR
	}

	var dhcpmt layers.DHCPMsgType
	var t1 uint32
	var t2 uint32
	dhcpmt = layers.DHCPMsgTypeUnspecified
	t1 = 1811
	t2 = 3200
	o.dg.SetUint32(0)
	var server *core.Ipv4Key
	server = nil
	var serverOp core.Ipv4Key

	for _, op := range dhcph.Options {
		switch op.Type {
		case layers.DHCPOptServerID:
			if len(op.Data) == 4 {
				if o.state == DHCP_STATE_INIT {
					copy(o.server[:], op.Data[:])
				} else {
					copy(serverOp[:], op.Data[:])
					server = &serverOp
				}
			}

		case layers.DHCPOptMessageType:

			dhcpmt = layers.DHCPMsgType(op.Data[0])
		case layers.DHCPOptRouter:
			if op.Length == 4 {
				copy(o.dg[:], op.Data[:])
			}
		case layers.DHCPOptT1:
			t1 = o.getT1InSec(&op)
		case layers.DHCPOptT2:
			t2 = o.getT1InSec(&op)
		default:
		}
	}

	switch o.state {
	case DHCP_STATE_INIT:

		if dhcpmt == layers.DHCPMsgTypeOffer {
			o.stats.pktRxOffer++
			if o.verifyPkt(&dhcph, ipv4, true, server) != 0 {
				return -1
			}

			copy(o.serverMac[:], p[6:12])
			o.state = DHCP_STATE_REQUESTING
			o.SendReq()
			return 0
		}

	case DHCP_STATE_REQUESTING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv4, t1, t2, true, server)
	case DHCP_STATE_BOUND:
		o.stats.pktRxUnhandle++
	case DHCP_STATE_RENEWING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv4, t1, t2, true, server)

	case DHCP_STATE_REBINDING:
		return o.HandleAckNak(dhcpmt, &dhcph, ipv4, t1, t2, true, server)

	default:
		o.stats.pktRxUnhandle++

	}
	return (0)
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

func (o *PluginDhcpNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginDhcpNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginDhcpNs) SetTruncated() {

}

// try to extract the MAC from the DHCP
func (o *PluginDhcpNs) GetMacFromDhcp(ps *core.ParserPacketState, key *core.MACKey) int {
	m := ps.M
	p := m.GetData()
	dhcphlen := ps.L7Len

	if dhcphlen < 240 {
		return core.PARSER_ERR
	}

	var dhcph layers.DHCPv4
	err := dhcph.DecodeFromBytes(p[ps.L7:ps.L7+dhcphlen], gopacket.NilDecodeFeedback)
	if err != nil {
		return core.PARSER_ERR
	}

	if dhcph.HardwareType != layers.LinkTypeEthernet {
		return core.PARSER_ERR
	}

	if dhcph.HardwareLen != 6 {
		return core.PARSER_ERR
	}

	if len(dhcph.ClientHWAddr) == 6 {
		copy((*key)[:], dhcph.ClientHWAddr[0:6])
		return core.PARSER_OK
	}
	return core.PARSER_ERR
}

func (o *PluginDhcpNs) HandleRxDhcpPacket(ps *core.ParserPacketState) int {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/
	/* UDP checksum was verified in the parser */
	var mackey core.MACKey
	copy(mackey[:], p[0:6])

	if mackey.IsBroadcast() {
		// we should look by the DHCP info
		if o.GetMacFromDhcp(ps, &mackey) == core.PARSER_ERR {
			return core.PARSER_ERR
		}
	}

	client := o.Ns.CLookupByMac(&mackey)

	if client == nil {
		return core.PARSER_ERR
	}

	cplg := client.PluginCtx.Get(DHCP_PLUG)
	if cplg == nil {
		return core.PARSER_ERR
	}
	dhcpCPlug := cplg.Ext.(*PluginDhcpClient)
	return dhcpCPlug.HandleRxDhcpPacket(ps)
}

// HandleRxDhcpPacket Parser call this function with mbuf from the pool
func HandleRxDhcpPacket(ps *core.ParserPacketState) int {
	ns := ps.Tctx.GetNs(ps.Tun)

	if ns == nil {
		return core.PARSER_ERR
	}
	nsplg := ns.PluginCtx.Get(DHCP_PLUG)
	if nsplg == nil {
		return core.PARSER_ERR
	}
	dhcpPlug := nsplg.Ext.(*PluginDhcpNs)
	return dhcpPlug.HandleRxDhcpPacket(ps)
}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

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
	plug, err := tctx.GetNsPlugin(params, DHCP_PLUG)

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

	plug, err := tctx.GetClientPlugin(params, DHCP_PLUG)

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
	core.PluginRegister(DHCP_PLUG,
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

	core.RegisterCB("dhcp_client_cnt", ApiDhcpClientCntHandler{}, false) // get counters/meta

	/* register callback for rx side*/
	core.ParserRegister("dhcp", HandleRxDhcpPacket)
}

func Register(ctx *core.CThreadCtx) {
	ctx.RegisterParserCb("dhcp")
}
