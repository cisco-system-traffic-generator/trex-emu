// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// August 2021 Eolo S.p.A. and Altran Italia S.p.A.
// - added PPP LCP layer at lines from 67 to 220
// - added PPP PAP layer at lines from 222 to 325
// - added PPP IPCP layer at lines from 327 to 434

package layers

import (
	"encoding/binary"
	"errors"
	"external/google/gopacket"
)

// PPP is the layer for PPP encapsulation headers.
type PPP struct {
	BaseLayer
	PPPType       PPPType
	HasPPTPHeader bool
}

// PPPEndpoint is a singleton endpoint for PPP.  Since there is no actual
// addressing for the two ends of a PPP connection, we use a singleton value
// named 'point' for each endpoint.
var PPPEndpoint = gopacket.NewEndpoint(EndpointPPP, nil)

// PPPFlow is a singleton flow for PPP.  Since there is no actual addressing for
// the two ends of a PPP connection, we use a singleton value to represent the
// flow for all PPP connections.
var PPPFlow = gopacket.NewFlow(EndpointPPP, nil, nil)

// LayerType returns LayerTypePPP
func (p *PPP) LayerType() gopacket.LayerType { return LayerTypePPP }

// LinkFlow returns PPPFlow.
func (p *PPP) LinkFlow() gopacket.Flow { return PPPFlow }

func decodePPP(data []byte, p gopacket.PacketBuilder) error {
	ppp := &PPP{}
	offset := 0
	if data[0] == 0xff && data[1] == 0x03 {
		offset = 2
		ppp.HasPPTPHeader = true
	}
	if data[offset]&0x1 == 0 {
		if data[offset+1]&0x1 == 0 {
			return errors.New("PPP has invalid type")
		}
		ppp.PPPType = PPPType(binary.BigEndian.Uint16(data[offset : offset+2]))
		ppp.BaseLayer = BaseLayer{data[offset : offset+2], data[offset+2:]}
		//ppp.Contents = data[offset : offset+2]
		//ppp.Payload = data[offset+2:]
	} else {
		ppp.PPPType = PPPType(data[offset])
		ppp.Contents = data[offset : offset+1]
		ppp.Payload = data[offset+1:]
	}
	p.AddLayer(ppp)
	p.SetLinkLayer(ppp)
	return p.NextDecoder(ppp.PPPType)
}

// LCP describes layer for PPP Link Control Protocol
type LCP struct {
	BaseLayer
	Code        LCPType
	Identifier  uint8
	Length      uint16
	Options     []LCPOption
	MagicNumber []byte // applicable only LCP Echo Request/Reply
}

// LCPType describes PPP LCP layer Type
type LCPType uint8

// LayerType returns gopacket.LayerTypeLCP
func (p *LCP) LayerType() gopacket.LayerType {
	return LayerTypeLCP
}

// set of supported PPP LCP Type
const (
	LCPTypeConfigurationRequest LCPType = 0x01
	LCPTypeConfigurationAck     LCPType = 0x02
	LCPTypeTerminateRequest     LCPType = 0x05
	LCPTypeTerminateAck         LCPType = 0x06
	LCPTypeEchoRequest          LCPType = 0x09
	LCPTypeEchoReply            LCPType = 0x0a
)

// LCPOption describes zero or more optional information organized into PPP LCP layer
type LCPOption struct {
	Type   LCPOptionType
	Length uint8
	Value  []uint8
}

// LCPOptionType is an enumeration of LCPOption type values, and acts as a decoder for any
// type it supports. Refeers to rfc1661 for details
type LCPOptionType uint8

// set of supported LCP Option Type
// RFC 1700
const (
	LCPOptionTypeMaximumReceiveUnit     LCPOptionType = 0x01
	LCPOptionTypeAuthenticationProtocol LCPOptionType = 0x03
	LCPOptionQualityProtocol            LCPOptionType = 0x04	// https://www.freesoft.org/CIE/RFC/1661/33.htm
	LCPOptionTypeMagicNumber            LCPOptionType = 0x05
)

// GetLCPSize returns size in byte of LCP layer
func (p *LCP) GetLCPSize() uint16 {
	ans := uint16(0)
	switch p.Code {
	case LCPTypeEchoRequest:
		ans += 4 // only magic number
	case LCPTypeEchoReply:
		ans += 4 // only magic number
	default:
		for _, tag := range p.Options {
			ans += 1                      // tag type size
			ans += 1                      // tag length size
			ans += uint16(len(tag.Value)) // tag value size
		}
	}
	ans += 1 // code
	ans += 1 // identifier
	ans += 2 // length
	return ans
}

func decodeLCP(data []byte, p gopacket.PacketBuilder) error {
	lcp := &LCP{
		Code:        LCPType(data[0]),
		Identifier:  data[1],
		Length:      binary.BigEndian.Uint16(data[2:4]),
		Options:     []LCPOption{},
		MagicNumber: []byte{},
	}
	switch lcp.Code {
	case LCPTypeEchoRequest:
		lcp.MagicNumber = data[4:] // only magic number
	case LCPTypeEchoReply:
		lcp.MagicNumber = data[4:] // only magic number
	default:
		// decode LCPOption
		for byteOpts := lcp.Length - 4; byteOpts > 0; {
			offset := uint8(lcp.Length - byteOpts)
			optionLength := data[offset+1]
			tmpLCPOption := &LCPOption{
				Type:   LCPOptionType(data[offset]),
				Length: optionLength,
				Value:  data[2+offset : optionLength+offset],
			}
			byteOpts -= uint16(optionLength) // option entire length
			lcp.Options = append(lcp.Options, *tmpLCPOption)
		}
	}
	lcp.BaseLayer = BaseLayer{data[:], []uint8{}}
	p.AddLayer(lcp)
	return p.NextDecoder(lcp.Code)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if p.PPPType&0x100 == 0 {
		bytes, err := b.PrependBytes(2)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16(p.PPPType))
	} else {
		bytes, err := b.PrependBytes(1)
		if err != nil {
			return err
		}
		bytes[0] = uint8(p.PPPType)
	}
	if p.HasPPTPHeader {
		bytes, err := b.PrependBytes(2)
		if err != nil {
			return err
		}
		bytes[0] = 0xff
		bytes[1] = 0x03
	}
	return nil
}

// SerializeTo for LCP layer
func (p *LCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(int(p.Length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(p.Code)
	bytes[1] = p.Identifier
	binary.BigEndian.PutUint16(bytes[2:], p.Length)
	switch p.Code {
	case LCPTypeEchoRequest:
		copy(bytes[4:], p.MagicNumber) // only magic number
	case LCPTypeEchoReply:
		copy(bytes[4:], p.MagicNumber) // only magic number
	default:
		offset := uint8(4)
		for _, opt := range p.Options {
			bytes[offset] = uint8(opt.Type)
			bytes[offset+1] = opt.Length
			copy(bytes[offset+2:], opt.Value)
			offset += opt.Length
		}
	}
	return nil
}

// PAP describes layer for Password Authentication Protocol
type PAP struct {
	BaseLayer
	Code       PAPType
	Identifier uint8
	Length     uint16
	Data       []PAPData
}

// PAPType describes PAP message type
type PAPType uint8

// LayerType returns gopacket.LayerTypePAP
func (p *PAP) LayerType() gopacket.LayerType {
	return LayerTypePAP
}

// set of supported PAP message type
const (
	PAPTypeAuthRequest PAPType = 0x01
	PAPTypeAuthAck     PAPType = 0x02
	PAPTypeAuthNak     PAPType = 0x03
)

// PAPData struct holds all possible data carried by PAP: Peer-ID, Password and Message
type PAPData struct {
	Length uint8
	Value  []uint8
}

func (p *PAP) AddPeerIDAndPassword(peerID string, password string) {
	if code := p.Code; code == PAPTypeAuthRequest {
		p.Data = []PAPData{
			{
				Value:  []byte(peerID),
				Length: uint8(len(peerID)),
			},
			{
				Value:  []byte(password),
				Length: uint8(len(password)),
			},
		}
	} else {
		panic("Current PAP message is NOT a Auth Request!")
	}
}

// GetPAPSize returns size in byte of PAP layer
func (p *PAP) GetPAPSize() uint16 {
	ans := uint16(0)
	for _, data := range p.Data {
		ans += 1                   // data length field size
		ans += uint16(data.Length) // tag length size
	}
	ans += 1 // code
	ans += 1 // identifier
	ans += 2 // pap length field size
	return ans
}

func decodePAP(data []byte, p gopacket.PacketBuilder) error {
	pap := &PAP{
		Code:       PAPType(data[0]),
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		Data:       []PAPData{},
	}
	// decode PAPData
	nrDatas := 1
	if pap.Code == PAPTypeAuthRequest {
		nrDatas = 2
	}
	offset := uint8(4)
	for index := 0; index < nrDatas; index++ {
		papDataLength := data[offset]
		tmpPAPData := &PAPData{
			Length: papDataLength,
			Value:  data[1+offset : 1+offset+papDataLength],
		}
		offset += 1 + papDataLength
		pap.Data = append(pap.Data, *tmpPAPData)
	}
	pap.BaseLayer = BaseLayer{data[:], []uint8{}}
	p.AddLayer(pap)
	return p.NextDecoder(pap.Code)
}

// SerializeTo for PAP layer
func (p *PAP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(int(p.Length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(p.Code)
	bytes[1] = p.Identifier
	binary.BigEndian.PutUint16(bytes[2:], p.Length)
	offset := uint8(4)
	for _, data := range p.Data {
		bytes[offset] = data.Length
		copy(bytes[offset+1:], data.Value)
		offset += 1 + data.Length
	}
	return nil
}

// IPCP describes layer for Internet Protocol Control Protocol
type IPCP struct {
	BaseLayer
	Code       IPCPType
	Identifier uint8
	Length     uint16
	Options    []IPCPOption
}

// IPCPType describes PAP message type
type IPCPType uint8

// LayerType returns gopacket.LayerTypeIPCP
func (p *IPCP) LayerType() gopacket.LayerType {
	return LayerTypeIPCP
}

// set of supported IPCP message type
const (
	IPCPTypeConfigurationRequest IPCPType = 0x01
	IPCPTypeConfigurationAck     IPCPType = 0x02
	IPCPTypeConfigurationNak     IPCPType = 0x03
)

// IPCPOption struct holds all possible data carried by PAP: Peer-ID, Password and Message
type IPCPOption struct {
	Type   IPCPOptionType
	Length uint8
	Value  []uint8
}

// IPCPOptionType describes IPCP Option type
type IPCPOptionType uint8

// set of supported IPCP Option type
const (
	IPCPOptionTypeIPAddress IPCPOptionType = 0x03
)

func decodeIPCP(data []byte, p gopacket.PacketBuilder) error {
	ipcp := &IPCP{
		Code:       IPCPType(data[0]),
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
		Options:    []IPCPOption{},
	}
	// decode IPCPOption
	for byteOpts := ipcp.Length - 4; byteOpts > 0; {
		offset := uint8(ipcp.Length - byteOpts)
		optionLength := uint8(data[offset+1])
		tmpIPCPOption := &IPCPOption{
			Type:   IPCPOptionType(data[offset]),
			Length: optionLength,
			Value:  data[2+offset : optionLength+offset],
		}
		byteOpts -= uint16(optionLength) // option entire length
		ipcp.Options = append(ipcp.Options, *tmpIPCPOption)
	}
	ipcp.BaseLayer = BaseLayer{data[:], []uint8{}}
	p.AddLayer(ipcp)
	return p.NextDecoder(ipcp.Code)
}

// SerializeTo for IPCP layer
func (p *IPCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(int(p.Length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(p.Code)
	bytes[1] = p.Identifier
	binary.BigEndian.PutUint16(bytes[2:], p.Length)
	offset := uint8(4)
	for _, opt := range p.Options {
		bytes[offset] = uint8(opt.Type)
		bytes[offset+1] = opt.Length
		copy(bytes[offset+2:], opt.Value)
		offset += opt.Length
	}
	return nil
}

// GetIPCPSize returns size in byte of IPCP layer
func (p *IPCP) GetIPCPSize() uint16 {
	ans := uint16(0)
	for _, data := range p.Options {
		ans += uint16(data.Length) // option length size
	}
	ans += 1 // code
	ans += 1 // identifier
	ans += 2 // ipcp length field size
	return ans
}

// GetProposedIPAddress analyzes Options and returns proposed IP Address as []byte
func (p *IPCP) GetProposedIPAddress() []byte {
	ans := make([]byte, 4)
	if len(p.Options) == 0 {
		panic("Handled IPCP packet does not carry IP Address to be acquired!")
	} else {
		for _, option := range p.Options {
			if code := option.Type; code == IPCPOptionTypeIPAddress {
				copy(ans, option.Value)
			}
		}
	}
	return ans
}
