// Copyright (c) 2021 Eolo S.p.A. and Altran Italia S.p.A. and/or them affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package point2point

import (
	"bytes"
	"emu/core"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"github.com/intel-go/fastjson"
	"fmt"
	"time"
	"encoding/binary"
	"math/rand"
)

// GetPPPSessionID is a wrapper to return PPP Session ID to JSONRPC
func (o *PluginPPPClient) GetPPPSessionID() uint16 {
	return o.pppSessionID
}

// GetPPPClientIP is a wrapper to return PPP IP Address to JSONRPC
func (o *PluginPPPClient) GetPPPClientIP() string {
	return o.clientIP.ToIP().String()
}

// GetPPPServerMac is a wrapper to return PPP Server Mac to JSONRPC
func (o *PluginPPPClient) GetPPPServerMac() string {
	return o.serverMac.String()
}

var pppEvents = []string{}

// NewPPPClient create plugin
func NewPPPClient(ctx *core.PluginCtx, initJSON []byte) *core.PluginBase {
	var init PPPInit
	err := fastjson.Unmarshal(initJSON, &init)

	o := new(PluginPPPClient)
	o.InitPluginBase(ctx, o)            /* init base object*/
	o.RegisterEvents(ctx, pppEvents, o) /* register events, only if exits*/
	// TO BE UNDERSTAND!
	nsplg := o.Ns.PluginCtx.GetOrCreate(PPPPlugin)
	o.pppNsPlug = nsplg.Ext.(*PluginPPPNs)
	o.OnCreate()

	// init JSON is provided and correctly parsed
	if err == nil {

		if len(init.UserID) > 0 {
			o.userID = init.UserID
		} else {
			o.userID = "test"
		}

		if len(init.Password) > 0 {
			o.password = init.Password
		} else {
			o.password = "test"
		}

		if init.Timeout > 0 {
			o.timeout = init.Timeout
		} else {
			o.timeout = 3
		}
	}

	return &o.PluginBase
}

// OnCreate is invoked at creation of client
func (o *PluginPPPClient) OnCreate() {

	// allocate local timer wheel
	o.timerw = o.Tctx.GetTimerCtx()

	// create local magic number uint32 and save as []byte
	tmpLocalMagicNumber := rand.Uint32()
	o.localMagicNumber = make([]byte, 4)
	binary.BigEndian.PutUint32(o.localMagicNumber[0:], tmpLocalMagicNumber)

	// Maximum Received Unit
	o.maxRecUnitBytes = make([]byte, 2)
	binary.BigEndian.PutUint16(o.maxRecUnitBytes[0:], uint16(1492))

	o.minTimerRetransmitSec = 1
	o.medTimerRetransmitSec = 3
	o.maxTimerRetransmitSec = 5

	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent

	clientMac := o.Client.GetInfo().Mac

	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv4))
	tmp := gopacket.NewPacket(l2, layers.LayerTypeEthernet, gopacket.Default)

	if dot1qLayer := tmp.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		dot1q, _ := dot1qLayer.(*layers.Dot1Q)
		LogTimeFormatted(fmt.Sprintf(
			">> OnCreate >> VLAN %d created PPPClient at Mac -> %s",
			dot1q.VLANIdentifier, clientMac), INFO)
	} else {
		LogTimeFormatted(fmt.Sprintf(
			">> OnCreate >> VLAN Untagged created PPPClient at Mac -> %s",
			clientMac), INFO)
	}

	if clientMac.IsZero() {
		msg := "Error during PPP Client creation : provided Mac Address is \"Zero\""
		LogTimeFormatted(msg, CRITICAL)
		panic(msg)
	}

	o.state = PPPStateInit
	o.sendPADI()
	o.state = PPPStatePADI
	o.padtSent = 0
}

func (o *PluginPPPClient) restartTimer(sec uint32) {

	if sec == 0 {
		return
	}
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.timerw.Start(&o.timer, time.Duration(sec)*time.Second)
}

// sendPADI sends PADI message
func (o *PluginPPPClient) sendPADI() {
	// get from client layer2
	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv4))
	tmp := gopacket.NewPacket(l2, layers.LayerTypeEthernet, gopacket.Default)

	// PPPoED PADI
	pppoed := &layers.PPPoE{
		Version:   0x1,
		Type:      0x1,
		Code:      layers.PPPoECodePADI,
		SessionID: 0x0000,
		Length:    0x0, // filled in next line of code
		Tags: []layers.PPPoEDTag{{
			Type:   layers.PPPoEDTagTypeServiceName,
			Length: 0x0000,
			Value:  []uint8{},
		}},
	}
	pppoed.Length = pppoed.GetPPPoEDTagsSize()

	// ethernet layer by default include broadcast destination
	ethLayer := tmp.Layer(layers.LayerTypeEthernet)
	ethernet, _ := ethLayer.(*layers.Ethernet)

	var padiLayerTwo []gopacket.SerializableLayer

	// Dot1Q
	// this layer can be optional into functional test
	if dot1qLayer := tmp.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		// for future
		o.vlanTagged = true
		ethernet.EthernetType = layers.EthernetTypeDot1Q

		// Dot1Q layer
		tmpDot1q, _ := dot1qLayer.(*layers.Dot1Q)
		dot1qDiscovery := *tmpDot1q
		dot1qDiscovery.Type = layers.EthernetTypePPPoEDiscovery
		// padi layer2
		padiLayerTwo = append(padiLayerTwo, ethernet, &dot1qDiscovery)
	} else {
		// for future
		o.vlanTagged = false
		// Ethernet layer
		ethernet.EthernetType = layers.EthernetTypePPPoEDiscovery
		// padi layer2
		padiLayerTwo = append(padiLayerTwo, ethernet)
	}

	// build raw PADI with layerTwoDiscovery structure and send it
	tmpPadi := append(padiLayerTwo, pppoed)
	rawPadi := core.PacketUtlBuild(tmpPadi...)
	padi := append(rawPadi)

	o.restartTimer(o.maxTimerRetransmitSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, padi)
}

// isPPPoED analyzes received packet and return true if match on PPPoED code
func (o *PluginPPPClient) isPPPoED(ps *core.ParserPacketState, pppoedCode layers.PPPoECode) bool {
	ans := false

	m := ps.M
	p := m.GetData()

	// variables used to find position into raw packet
	var rawEthType []byte
	var rawPPPoEDCode byte

	// if plugin handles Dot1q
	if o.vlanTagged {
		rawEthType = p[16:18]
		rawPPPoEDCode = p[19]
	} else { // if plugin does NOT handle Dot1q
		rawEthType = p[12:14]
		rawPPPoEDCode = p[15]
	}

	obtainedEthType := layers.EthernetType(binary.BigEndian.Uint16(rawEthType))
	if obtainedEthType == layers.EthernetTypePPPoEDiscovery {
		ans = layers.PPPoECode(rawPPPoEDCode) == pppoedCode
	}

	return ans
}

// sendPADR sends PADR message
func (o *PluginPPPClient) sendPADR() {

	// PPPoED PADR
	pppoed := &layers.PPPoE{
		Version:   0x1,
		Type:      0x1,
		Code:      layers.PPPoECodePADR,
		SessionID: 0x0000,
		Length:    0x0, // filled in next line of code
		Tags:      o.pppoedTags,
	}
	pppoed.Length = pppoed.GetPPPoEDTagsSize()

	// build raw PADR with layerTwoDiscovery structure and send it
	tmpPadr := append(o.layerTwoDiscovery, pppoed)
	rawPadr := core.PacketUtlBuild(tmpPadr...)
	padr := append(rawPadr)

	o.state = PPPStatePADR
	o.restartTimer(o.maxTimerRetransmitSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, padr)
}

// sendPADT sends PADT message
func (o *PluginPPPClient) sendPADT() {

	if o.padtSent >= 2 {
		return
	}

	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv4))
	tmp := gopacket.NewPacket(l2, layers.LayerTypeEthernet, gopacket.Default)

	if dot1qLayer := tmp.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		dot1q, _ := dot1qLayer.(*layers.Dot1Q)
		LogTimeFormatted(fmt.Sprintf(">> sendPADT >> VLAN %d Send PADT Message from Mac -> %s",
			dot1q.VLANIdentifier, o.Client.Mac), INFO)
	} else {
		LogTimeFormatted(fmt.Sprintf(">> sendPADT >> Send PADT Message from Mac -> %s",
			o.Client.Mac), INFO)
	}

	// PPPoED PADR
	padtMsg := "session closed"
	pppoed := &layers.PPPoE{
		Version:   0x1,
		Type:      0x1,
		Code:      layers.PPPoECodePADT,
		SessionID: o.pppSessionID,
		Length:    0x0, // filled in next line of code
		Tags: []layers.PPPoEDTag{{
			Type:   layers.PPPoEDTagTypeGenericError,
			Length: uint16(len(padtMsg)),
			Value:  []uint8(padtMsg),
		}},
	}
	pppoed.Length = pppoed.GetPPPoEDTagsSize()

	// build raw PADT with layerTwoDiscovery structure and send it
	tmpPadt := append(o.layerTwoDiscovery, pppoed)
	rawPadt := core.PacketUtlBuild(tmpPadt...)
	padt := append(rawPadt)

	o.state = PPPStatePADTSent
	o.restartTimer(o.maxTimerRetransmitSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, padt)
	o.padtSent += 1
}

/*OnEvent support event change of IP  */
func (o *PluginPPPClient) OnEvent(msg string, a, b interface{}) {
	clientMac := o.Client.GetInfo().Mac
	LogTimeFormatted(fmt.Sprintf(">> OnEvent >> Created PPP Client at Mac -> %s",
		clientMac), INFO)
}

// OnRemove support events handling on plugin remove
func (o *PluginPPPClient) OnRemove(ctx *core.PluginCtx) {

	clientMac := o.Client.GetInfo().Mac
	LogTimeFormatted(fmt.Sprintf(">> OnRemove >> Destroyed PPP Client at Mac -> %s",
		clientMac), INFO)

	if o.state == PPPStateLinkUp {
		o.sendPADT()
	}

	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, pppEvents)
	// TBD send release message
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}


// HandleRxPPPPacket handled Rx packets at client
func (o *PluginPPPClient) HandleRxPPPPacket(ps *core.ParserPacketState) int {
	switch o.state {
	case PPPStateInit:
		// it's first state and change asap to PADI, impossible to receive pkt in this status
	case PPPStatePADI:
		// after sending PADI, parse incoming pkt as candidate PADO
		if o.isPPPoED(ps, layers.PPPoECodePADO) {
			o.prepareLayerTemplate(ps)
			o.handlePADO(ps)
		}
	case PPPStatePADO:
		// this state is used when received PADO and before send PADR, it's difficult to reveive a second PADO
	case PPPStatePADR:
		// after sending PADR, parse incoming pkt as candidate PADS
		if o.isPPPoED(ps, layers.PPPoECodePADS) {
			o.handlePADS(ps)
		}
	case PPPStatePADS:
		// after received PADS is possible to receive asap PPP LCP Conf Request
		// parse candidate PPP LCP Conf Request
		if o.isLCP(ps, layers.LCPTypeConfigurationRequest) {
			// this method bring to PPPStateLCPNegotiation
			o.handleLCPNegotiation(ps)
		} else if o.isLCP(ps, layers.LCPTypeEchoRequest) {
			o.answerLCPEcho(ps)
		}
	case PPPStateLCPNegotiation:
		// After first LCP message received and during entire LCP Negotiation
		// Parsing candidate PPP LCP Negotiation pkt
		if o.isLCP(ps, layers.LCPTypeConfigurationRequest, layers.LCPTypeConfigurationAck) {
			// based on internal status it's possible to enter in PPPStatePAPSent
			o.handleLCPNegotiation(ps)
		} else if o.isLCP(ps, layers.LCPTypeEchoRequest) {
			o.answerLCPEcho(ps)
		}
	case PPPStatePAPSent:
		// At end of LCP Neg, the PAP pkt is sent
		// Parsing candidate PAP response
		if o.isPPP(ps, layers.PPPTypePAP) {
			// verify PAP Auth and move to PPPStateIPCPNegotiation
			o.handlePAPRes(ps)
		} else if o.isLCP(ps, layers.LCPTypeConfigurationRequest) {
			o.handleLCPNegotiation(ps)
		} else if o.isLCP(ps, layers.LCPTypeEchoRequest) {
			o.answerLCPEcho(ps)
		}
	case PPPStateIPCPNegotiation:
		// PAP was ok and clients enters in this state waiting IPCP Negotiation
		// Parsing PPP IPCP pkts
		if o.isPPP(ps, layers.PPPTypeIPCP) {
			o.handleIPCPNegotiation(ps)
		} else if o.isLCP(ps, layers.LCPTypeEchoRequest) {
			o.answerLCPEcho(ps)
		}
	case PPPStateLinkUp:
		// IPCP Neg is completed and client has assigned an IP address
		// Handling PPP LCP Echo Request/Reply
		// Parsing PPP IPCP pkts
		if o.isPPP(ps, layers.PPPTypeIPCP) {
			LogTimeFormatted(fmt.Sprintf(">> PPPStateLinkUp >> IPCP on Mac %v -> Ack with negotiated IP %v",
				o.Client.Mac, o.negClientIP), INFO)
			o.handleIPCPNegotiation(ps)
		} else if o.isLCP(ps, layers.LCPTypeEchoRequest) {
			o.answerLCPEcho(ps)
		} else if o.isLCP(ps, layers.LCPTypeTerminateRequest) {
			o.answerLCPTerminate(ps)
			o.sendPADT()
			o.state = PPPStatePADTSent
		}
	case PPPStatePADTSent:
		// this state is reachable only via EMU API to drive client disconnect
		// Parse PADT response
		if o.isPPPoED(ps, layers.PPPoECodePADT) {
			// ok conclude
			o.state = PPPStatePADTReceived
			o.OnRemove(o.tctx.PluginCtx)
		}
	case PPPStatePADTReceived:
		// it's impossible to receive other pkt here because client shutdown quickly
	}

	return 0
}

// prepareLayerTemplate processes first received packet (PADO) and prepare layers used many times after
func (o *PluginPPPClient) prepareLayerTemplate(ps *core.ParserPacketState) {

	m := ps.M
	p := m.GetData()

	// save server Mac address
	copy(o.serverMac[:], p[6:12])

	// prepare reusable layers
	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeIPv4))
	tmp := gopacket.NewPacket(l2, layers.LayerTypeEthernet, gopacket.Default)

	// replace into ethernet layer client and server MAC
	ethLayer := tmp.Layer(layers.LayerTypeEthernet)
	ethernet, _ := ethLayer.(*layers.Ethernet)
	ethernet.SrcMAC = o.Client.Mac[:]
	ethernet.DstMAC = o.serverMac[:]

	// Dot1Q
	// this layer can be optional into functional test
	if dot1qLayer := tmp.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		o.vlanTagged = true
		// ethernet layer display Dot1Q
		ethernet.EthernetType = layers.EthernetTypeDot1Q

		// Dot1Q layer
		tmpDot1q, _ := dot1qLayer.(*layers.Dot1Q)
		// PPPoED
		dot1qDiscovery := *tmpDot1q
		dot1qDiscovery.Type = layers.EthernetTypePPPoEDiscovery
		// cloning
		tmp2dot1q := dot1qDiscovery
		// PPPoES
		dot1qSession := tmp2dot1q
		dot1qSession.Type = layers.EthernetTypePPPoESession

		// save layer2 for PPPoED
		o.layerTwoDiscovery = append(o.layerTwoDiscovery, ethernet, &dot1qDiscovery)
		// save layer2 for PPPoES
		o.layerTwoSession = append(o.layerTwoSession, ethernet, &dot1qSession)
		/*  Prepare Dot1Q template layers - END */
	} else {
		o.vlanTagged = false

		// prepare ethernet layer for PPPoED
		// EthernetTypePPPoEDiscovery
		tmpEthDiscovery := &layers.Ethernet{
			SrcMAC:            o.Client.Mac[:],
			DstMAC:            o.serverMac[:],
			EthernetType:      layers.EthernetTypePPPoEDiscovery,
		}
		// EthernetTypePPPoESession
		tmpEthSession := &layers.Ethernet{
			SrcMAC:            o.Client.Mac[:],
			DstMAC:            o.serverMac[:],
			EthernetType:      layers.EthernetTypePPPoESession,
		}
		// save layer2 for PPPoED
		o.layerTwoDiscovery = append(o.layerTwoDiscovery, tmpEthDiscovery)
		// save layer2 for PPPoES
		o.layerTwoSession = append(o.layerTwoSession, tmpEthSession)
	}
}

// isPPP analyzes received packet and return true if match on PPPoES type
func (o *PluginPPPClient) isPPP(ps *core.ParserPacketState, pppCode layers.PPPType) bool {
	ans := false

	m := ps.M
	p := m.GetData()

	// variables used to find position into raw packet
	var rawEthType []byte
	var rawPPPCode []byte

	// if plugin handles Dot1q
	if o.vlanTagged {
		rawEthType = p[16:18]
		rawPPPCode = p[24:26]
	} else { // if plugin does NOT handle Dot1q
		rawEthType = p[12:14]
		rawPPPCode = p[20:22]
	}

	obtainedEthType := layers.EthernetType(binary.BigEndian.Uint16(rawEthType))
	if obtainedEthType == layers.EthernetTypePPPoESession {
		ans = layers.PPPType(binary.BigEndian.Uint16(rawPPPCode)) == pppCode
	}

	return ans
}

// isLCP returns true if current packet is PPP LCP and carry at least one of looked for LCPType
func (o *PluginPPPClient) isLCP(ps *core.ParserPacketState, lcpCode ...layers.LCPType) bool {
	ans := false

	if isLCP := o.isPPP(ps, layers.PPPTypeLCP); isLCP {
		m := ps.M
		p := m.GetData()

		var rawLcpCode byte

		if o.vlanTagged {
			rawLcpCode = p[26]
		} else {
			rawLcpCode = p[22]
		}

		currentLcpCode := layers.LCPType(rawLcpCode)
		// if at least one code match with looked for exit and return True
		for _, singleLcpCode := range lcpCode {
			if tmp := currentLcpCode == singleLcpCode; tmp {
				ans = true
				break
			}
		}
	}

	return ans
}

func (o *PluginPPPClient) handlePADS(ps *core.ParserPacketState) {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/

	var rawSessionID []byte

	if o.vlanTagged {
		rawSessionID = p[20:22]
	} else {
		rawSessionID = p[16:18]
	}

	// assign received SessionID to client
	o.pppSessionID = binary.BigEndian.Uint16(rawSessionID)

	o.state = PPPStatePADS
	// wait 1 second to send LCP Configuration Request
	o.restartTimer(o.minTimerRetransmitSec)
}

func (o *PluginPPPClient) handlePADO(ps *core.ParserPacketState) {

	m := ps.M
	p := m.GetData()
	/* the header is at least 8 bytes*/

	// save server Mac address
	copy(o.serverMac[:], p[6:12])

	tmp := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	// PPPoED
	pppoeLayer := tmp.Layer(layers.LayerTypePPPoE)
	pppoed, _ := pppoeLayer.(*layers.PPPoE)
	// save received PPPoED Tags
	o.pppoedTags = pppoed.Tags

	o.state = PPPStatePADO
	// wait 1 second to send PADR
	o.restartTimer(o.minTimerRetransmitSec)
}

func (o *PluginPPPClient) handleLCPNegotiation(ps *core.ParserPacketState) {
	m := ps.M
	p := m.GetData()

	packet := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)
	lcpLayer := packet.Layer(layers.LayerTypeLCP)
	lcp, _ := lcpLayer.(*layers.LCP)

	switch lcp.Code {
	case layers.LCPTypeConfigurationRequest:
		if len(o.peerMagicNumber) == 0 || o.authMethod == 0x0 {
			for _, option := range lcp.Options {
				if option.Type == layers.LCPOptionTypeMagicNumber {
					o.peerMagicNumber = make([]byte, 4)
					copy(o.peerMagicNumber, option.Value[0:])
				} else if option.Type == layers.LCPOptionTypeAuthenticationProtocol {
					tmp := 	binary.BigEndian.Uint16(option.Value[0:])
					o.authMethod = layers.PPPType(tmp)
				}
			}
		}
		o.sendLCPAck(lcp.Identifier)
		o.lcpAckSent = true
	case layers.LCPTypeConfigurationAck:
		o.lcpAckReceived = true
		o.sendLCPConfReq(false)
	}
	// final check on LCP negotiation status
	o.evaluateLCPNegotiationOver()
}

func (o *PluginPPPClient) evaluateLCPNegotiationOver() {

	if o.lcpAckSent && o.lcpAckReceived {
		// go to next state to send PAP Auth Req
		o.state = PPPStatePAPSent
		o.restartTimer(o.minTimerRetransmitSec)
	} else if !o.lcpAckReceived {
		// if no ack received
		o.sendLCPConfReq(false)
	}
}

func (o *PluginPPPClient) sendLCPConfReq(firstTime bool) {
	if firstTime {
		o.state = PPPStateLCPNegotiation
	}
	o.lcpSendCounter++
	identifier := o.lcpSendCounter
	o.sendLCPMsg(layers.LCPTypeConfigurationRequest, identifier)
}

func (o *PluginPPPClient) sendLCPAck(identifier uint8) {
	o.sendLCPMsg(layers.LCPTypeConfigurationAck, identifier)
}

func (o *PluginPPPClient) answerLCPTerminate(ps *core.ParserPacketState) {
	m := ps.M
	p := m.GetData()

	tmp := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	// LCP
	lcpLayer := tmp.Layer(layers.LayerTypeLCP)
	lcp, _ := lcpLayer.(*layers.LCP)

	LogTimeFormatted(fmt.Sprintf(">> LCP Terminate Request >> Received on Mac %v",
		o.Client.Mac), WARNING)

	// this message does not contains magic number
	// it can contain terminate motivation
	for _, option := range lcp.Options {
		if option.Type == layers.LCPOptionQualityProtocol {
			LogTimeFormatted(fmt.Sprintf(">> answerLCPTerminate >> LCP Terminate Request on Mac %v for Quality-Protocol",
				o.Client.Mac), WARNING)
		}
	}
	o.sendLCPMsg(layers.LCPTypeTerminateAck, lcp.Identifier)
}

func (o *PluginPPPClient) answerLCPEcho(ps *core.ParserPacketState) {
	m := ps.M
	p := m.GetData()

	tmp := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	// LCP
	lcpLayer := tmp.Layer(layers.LayerTypeLCP)
	lcp, _ := lcpLayer.(*layers.LCP)

	// compare LCP Echo Request Magic Number with onboarded one
	if !bytes.Equal(lcp.MagicNumber, o.peerMagicNumber) {
		msg := fmt.Sprintf(
			"PPP Plugin has received an LCP Echo Request from unknown peer (expected, obtained) -> (%v,%v)!",
			o.peerMagicNumber, lcp.MagicNumber)
		LogTimeFormatted(msg, CRITICAL)
		panic(msg)
	}
	o.sendLCPMsg(layers.LCPTypeEchoReply, lcp.Identifier)
}

func (o *PluginPPPClient) sendLCPMsg(lcpCode layers.LCPType, identifier uint8) {
	// PPPoES
	pppoes := &layers.PPPoE{
		Version:   0x1,
		Type:      0x1,
		Code:      layers.PPPoECodeSession,
		SessionID: o.pppSessionID,
		Length:    0x0, // filled in next lines of code
		Tags: []layers.PPPoEDTag{},
	}
	// PPP
	ppp := &layers.PPP{
		PPPType:       layers.PPPTypeLCP,
	}
	// LCP layer
	var lcp *layers.LCP

	switch lcpCode {
	case layers.LCPTypeConfigurationRequest:
		lcp = &layers.LCP{
			Code:       layers.LCPTypeConfigurationRequest,
			Identifier: identifier,
			Length:     0, // filled after
			Options:    []layers.LCPOption{
				{
					Type: layers.LCPOptionTypeMaximumReceiveUnit,
					Length: 0x4,
					Value: o.maxRecUnitBytes,
				},
				{
					Type: layers.LCPOptionTypeMagicNumber,
					Length: 0x6,
					Value: o.localMagicNumber,
				},
			},
		}
	case layers.LCPTypeConfigurationAck:
		authMethod := make([]byte, 2)
		binary.BigEndian.PutUint16(authMethod[0:], uint16(o.authMethod))
		lcp = &layers.LCP{
			Code:       layers.LCPTypeConfigurationAck,
			Identifier: identifier,
			Length:     0, // filled after
			Options:    []layers.LCPOption{
				{
					Type: layers.LCPOptionTypeMaximumReceiveUnit,
					Length: 0x4,
					Value: o.maxRecUnitBytes, // 1492
				},
				{
					Type: layers.LCPOptionTypeMagicNumber,
					Length: 0x6,
					Value: o.peerMagicNumber,
				},
				{
					Type: layers.LCPOptionTypeAuthenticationProtocol,
					Length: 0x4,
					Value: authMethod,
				},
			},
		}
	case layers.LCPTypeEchoReply:
		lcp = &layers.LCP{
			Code:       layers.LCPTypeEchoReply,
			Identifier: identifier,
			Length:     0, // filled after
			Options:    []layers.LCPOption{},
			MagicNumber: o.localMagicNumber,
		}
	case layers.LCPTypeTerminateAck:
		lcp = &layers.LCP{
			Code:       layers.LCPTypeTerminateAck,
			Identifier: identifier,
			Length:     0, // filled after
			Options:    []layers.LCPOption{
				{
					Type: layers.LCPOptionTypeMaximumReceiveUnit,
					Length: 0x4,
					Value: o.maxRecUnitBytes,
				},
				{
					Type: layers.LCPOptionTypeMagicNumber,
					Length: 0x6,
					Value: o.localMagicNumber,
				},
			},
		}
	}
	lcp.Length = lcp.GetLCPSize()
	pppoes.Length = lcp.Length + 2 // added two bytes od PPP layer

	// build raw LCP Msg with layerTwoSession structure and send it
	tmpLcpMsg := append(o.layerTwoSession, pppoes, ppp, lcp)
	rawLcpMsg := core.PacketUtlBuild(tmpLcpMsg...)
	lcpMsg := append(rawLcpMsg)

	o.restartTimer(o.minTimerRetransmitSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, lcpMsg)
}

func (o *PluginPPPClient) sendPAPReq() {
	// PPPoES
	pppoes := &layers.PPPoE{
		Version:   0x1,
		Type:      0x1,
		Code:      layers.PPPoECodeSession,
		SessionID: o.pppSessionID,
		Length:    0x0, // filled in next lines of code
		Tags: []layers.PPPoEDTag{},
	}
	// PPP
	ppp := &layers.PPP{
		PPPType:       layers.PPPTypePAP,
	}
	// PAP
	pap := &layers.PAP{
		Code: layers.PAPTypeAuthRequest,
		Identifier: 1,
		Length: 0, // filled later
	}
	pap.AddPeerIDAndPassword(o.userID, o.password)
	pap.Length = pap.GetPAPSize()
	pppoes.Length = pap.Length + 2 // PPP layer size in byte

	// build raw PAP with layerTwoSession structure and send it
	tmpPap := append(o.layerTwoSession, pppoes, ppp, pap)
	rawPap := core.PacketUtlBuild(tmpPap...)
	papReq := append(rawPap)

	o.restartTimer(o.maxTimerRetransmitSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, papReq)
}

func (o *PluginPPPClient) handlePAPRes(ps *core.ParserPacketState) {
	m := ps.M
	p := m.GetData()

	tmp := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	// PPP
	papLayer := tmp.Layer(layers.LayerTypePAP)
	pap, _ := papLayer.(*layers.PAP)

	if code := pap.Code; code == layers.PAPTypeAuthAck {
		o.state = PPPStateIPCPNegotiation
		o.restartTimer(o.minTimerRetransmitSec)
	} else {
		LogTimeFormatted(fmt.Sprintf(">> PluginPPPClient.handlePAPRes >> Unexpected PAP returned code [%d] on Mac %v",
			code, o.Client.Mac), WARNING)
	}
}

func (o *PluginPPPClient) handleIPCPNegotiation(ps *core.ParserPacketState) {
	m := ps.M
	p := m.GetData()

	tmp := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	// IPCP
	ipcpLayer := tmp.Layer(layers.LayerTypeIPCP)
	ipcp, _ := ipcpLayer.(*layers.IPCP)

	switch ipcp.Code {
	case layers.IPCPTypeConfigurationRequest:
		// the IP address arrives only via Nak
		if !o.rcvByNak {
			// get proposed IP Address as candidate
			copy(o.negClientIP[:], ipcp.GetProposedIPAddress())
		}
		o.sendIPCPAck(ipcp.Identifier)
		o.restartTimer(o.minTimerRetransmitSec)
	case layers.IPCPTypeConfigurationAck:
		// if it's received an Ack with current IP Address
		// IPCP Negotiation is Over
		if bytes.Equal(o.negClientIP[:], ipcp.GetProposedIPAddress()) {
			LogTimeFormatted(fmt.Sprintf("Client on Mac %v has IP %v with PPP Id %04X !",
				o.Client.Mac, o.negClientIP, o.pppSessionID), INFO)
			copy(o.clientIP[:], ipcp.GetProposedIPAddress())
			o.state = PPPStateLinkUp
		} else {
			// get proposed IP Address as candidate
			copy(o.negClientIP[:], ipcp.GetProposedIPAddress())
			o.restartTimer(o.minTimerRetransmitSec)
		}
	case layers.IPCPTypeConfigurationNak:
		copy(o.negClientIP[:], ipcp.GetProposedIPAddress())
		o.rcvByNak = true
		// send ASAP Conf Req with IP into Nak
		o.restartTimer(o.maxTimerRetransmitSec)
		o.sendIPCPConfReq()
	}
}

// SendIPCPMsg is a generic function to send IPCP messages
func (o *PluginPPPClient) sendIPCPMsg(ipcpCode2Send layers.IPCPType, identifier uint8) {
	// PPPoES
	pppoes := &layers.PPPoE{
		Version:   0x1,
		Type:      0x1,
		Code:      layers.PPPoECodeSession,
		SessionID: o.pppSessionID,
		Length:    0x0, // filled in next lines of code
		Tags: []layers.PPPoEDTag{},
	}
	// PPP
	ppp := &layers.PPP{
		PPPType:       layers.PPPTypeIPCP,
	}

	msgIdentifier := uint8(0)
	// IPCP
	switch ipcpCode2Send {
	case layers.IPCPTypeConfigurationRequest:
		o.ipcpSendCounter++
		msgIdentifier = o.ipcpSendCounter
	case layers.IPCPTypeConfigurationAck:
		msgIdentifier = identifier
	}
	ipcp := &layers.IPCP{
		Code: ipcpCode2Send,
		Identifier: msgIdentifier,
		Length: 0x0, // filled in next lines of code
		Options: []layers.IPCPOption{
			{
				Type:   layers.IPCPOptionTypeIPAddress,
				Length: 0x6,
				Value:  o.negClientIP[:],
			},
		},
	}
	ipcp.Length = ipcp.GetIPCPSize()
	pppoes.Length = ipcp.Length + 2 // PPP layer size in byte

	// build raw IPCP Msg with layerTwoSession structure and send it
	tmpIpcpMsg := append(o.layerTwoSession, pppoes, ppp, ipcp)
	rawIpcpMsg := core.PacketUtlBuild(tmpIpcpMsg...)
	ipcpMsg := append(rawIpcpMsg)

	o.restartTimer(o.maxTimerRetransmitSec)
	o.Tctx.Veth.SendBuffer(false, o.Client, ipcpMsg)
}

func (o *PluginPPPClient) sendIPCPConfReq() {
	o.sendIPCPMsg(layers.IPCPTypeConfigurationRequest, 0x0)
}

func (o *PluginPPPClient) sendIPCPAck(identifier uint8) {
	o.sendIPCPMsg(layers.IPCPTypeConfigurationAck, identifier)
}
