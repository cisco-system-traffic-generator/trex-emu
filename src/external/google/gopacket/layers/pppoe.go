// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// August 2021 Eolo S.p.A. and Altran Italia S.p.A.
// - added support to PPPoED Tags layer

package layers

import (
	"encoding/binary"
	"external/google/gopacket"
)

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoE struct {
	BaseLayer
	Version   uint8
	Type      uint8
	Code      PPPoECode
	SessionID uint16
	Length    uint16
	Tags      []PPPoEDTag
}

// PPPoEDTag is used to describe Tags into PPPoED layer
type PPPoEDTag struct {
	Type   PPPoEDTagType
	Length uint16
	Value  []uint8
}

// PPPoEDTagType is an enumeration of PPPoEDTag type values, and acts as a decoder for any
// type it supports. Refeers to rfc2516 for details
type PPPoEDTagType uint16

// set of supported PPPoED Tags
const (
	PPPoEDTagTypeEndOfList    PPPoEDTagType = 0x0000
	PPPoEDTagTypeServiceName  PPPoEDTagType = 0x0101
	PPPoEDTagTypeACName       PPPoEDTagType = 0x0102
	PPPoEDTagTypeACCookie     PPPoEDTagType = 0x0104
	PPPoEDTagTypeGenericError PPPoEDTagType = 0x0203
)

// GetPPPoEDTagsSize returns size in byte of PPPoED Tags otherwise go to panic
func (p *PPPoE) GetPPPoEDTagsSize() uint16 {
	if p.Code == PPPoECodeSession {
		panic("Current layer is PPPoE Session then not applicable get PPPoE Discovery Tags!")
	} else {
		ans := uint16(0)
		for _, tag := range p.Tags {
			ans += 2 // tag type size
			ans += 2 // tag length size
			ans += uint16(len(tag.Value)) // tag value size
		}
		return ans
	}
}

// LayerType returns gopacket.LayerTypePPPoE.
func (p *PPPoE) LayerType() gopacket.LayerType {
	return LayerTypePPPoE
}

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516).
func decodePPPoE(data []byte, p gopacket.PacketBuilder) error {
	pppoe := &PPPoE{
		Version:   data[0] >> 4,
		Type:      data[0] & 0x0F,
		Code:      PPPoECode(data[1]),
		SessionID: binary.BigEndian.Uint16(data[2:4]),
		Length:    binary.BigEndian.Uint16(data[4:6]),
		Tags:      []PPPoEDTag{},
	}
	if pppoe.Code != PPPoECodeSession && pppoe.Length > 0 {
		for offset := uint16(0); offset < pppoe.Length; {
			tagLength := binary.BigEndian.Uint16(data[8+offset : 10+offset])
			tmpPPPoEDTag := &PPPoEDTag{
				Type:   PPPoEDTagType(binary.BigEndian.Uint16(data[6+offset : 8+offset])),
				Length: tagLength,
				Value:  data[10+offset : 10+tagLength+offset],
			}
			offset += 2         // tag name
			offset += 2         // tag length
			offset += tagLength // tag value length
			pppoe.Tags = append(pppoe.Tags, *tmpPPPoEDTag)
		}
		pppoe.BaseLayer = BaseLayer{data[:6+pppoe.Length], []uint8{}}
	} else {
		// no PPPoED Tags to be parsed
		pppoe.BaseLayer = BaseLayer{data[:6], data[6 : 6+pppoe.Length]}
	}
	p.AddLayer(pppoe)
	return p.NextDecoder(pppoe.Code)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPPoE) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()
	bufferSize := 0
	if p.Code == PPPoECodeSession { // PPPoES
		bufferSize = 6
		if opts.FixLengths {
			p.Length = uint16(len(payload))
		}
	} else { // PPPoED with PPPoED Tags
		bufferSize = 6 + int(p.Length)
	}
	bytes, err := b.PrependBytes(bufferSize)
	if err != nil {
		return err
	}
	bytes[0] = (p.Version << 4) | p.Type
	bytes[1] = byte(p.Code)
	binary.BigEndian.PutUint16(bytes[2:], p.SessionID)
	binary.BigEndian.PutUint16(bytes[4:], p.Length)
	if p.Code == PPPoECodeSession { // PPPoES
		binary.BigEndian.PutUint16(bytes[4:], p.Length)
	} else { // PPPoED with PPPoED Tags
		offset := uint16(6)
		for _, tag := range p.Tags {
			binary.BigEndian.PutUint16(bytes[offset:], uint16(tag.Type))
			offset += 2 // tag name
			binary.BigEndian.PutUint16(bytes[offset:], tag.Length)
			offset += 2 // tag length
			copy(bytes[offset:], tag.Value)
			offset += tag.Length // tag value length
		}
	}
	return nil
}
