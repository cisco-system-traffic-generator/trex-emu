// Copyright (c) 2021 Eolo S.p.A. and Altran Italia S.p.A. and/or them affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package point2point

import (
	"emu/core"
	"external/google/gopacket"
	"external/google/gopacket/layers"
)

// PluginState describes client status
type PluginState uint8

const (
	// PPPPlugin is the name of this plugin
	PPPPlugin = "ppp"
	// PPPStateInit describes just created client
	PPPStateInit PluginState = 0
	// PPPStatePADI describes sent PADI
	PPPStatePADI PluginState = 1
	// PPPStatePADO describes received PADO
	PPPStatePADO PluginState = 2
	// PPPStatePADR describes sent PADR
	PPPStatePADR PluginState = 3
	// PPPStatePADS describes received PADS
	PPPStatePADS PluginState = 4
	// PPPStateLCPNegotiation describes LCP negotiation
	PPPStateLCPNegotiation PluginState = 5
	// PPPStatePAPSent describes sent PAP
	PPPStatePAPSent PluginState = 6
	// PPPStateIPCPNegotiation describes IPCP negotiation
	PPPStateIPCPNegotiation PluginState = 7
	// PPPStateLinkUp describes PPP link is Up
	PPPStateLinkUp PluginState = 8
	// PPPStatePADTSent describes sent PADT
	PPPStatePADTSent PluginState = 9
	// PPPStatePADTReceived describes received PADT
	PPPStatePADTReceived PluginState = 10
)

// PPPInit describes structure of input json
type PPPInit struct {
	UserID   string `json:"user"`
	Password string `json:"password"`
	Timeout  uint8  `json:"timeout"`
}

// PluginPPPClient information per client
type PluginPPPClient struct {
	core.PluginBase
	pppNsPlug             *PluginPPPNs
	tctx                  core.CThreadCtx
	timer                 core.CHTimerObj
	timerw                *core.TimerCtx // timer wheel
	cnt                   uint8
	state                 PluginState
	userID                string
	password              string
	timeout               uint8
	minTimerRetransmitSec uint32
	medTimerRetransmitSec uint32
	maxTimerRetransmitSec uint32
	serverMac             core.MACKey
	pppoedTags            []layers.PPPoEDTag
	pppSessionID          uint16
	localMagicNumber      []byte
	peerMagicNumber       []byte
	authMethod            layers.PPPType
	lcpSendCounter        uint8
	ipcpSendCounter       uint8
	lcpAckSent            bool
	lcpAckReceived        bool
	maxRecUnitBytes       []byte
	negClientIP           core.Ipv4Key     // this variable is used during IPCP Negotiation
	rcvByNak              bool             // IP negotiated is received by Nak
	clientIP              core.Ipv4Key     // this variable is final IP assigned to client
	timerCb               PluginPPPClientTimer
	vlanTagged            bool
	layerTwoDiscovery     []gopacket.SerializableLayer    // support array during PPPoED
	layerTwoSession       []gopacket.SerializableLayer    // support array during PPPoES
	padtSent              uint8
}