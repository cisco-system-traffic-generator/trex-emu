// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"external/google/gopacket"
)

const (
	IpfixTemplateSetIDVer10        = 2
	IpfixOptionsTemplateSetIDVer10 = 3

	IpfixTemplateSetIDVer9        = 0
	IpfixOptionsTemplateSetIDVer9 = 1

	IpfixHeaderLenVer10 = 16
	IpfixHeaderLenVer9  = 20
)

//IPFixHeader  For in place change
type IPFixHeader []byte

func (o IPFixHeader) GetVer() uint16 {
	return binary.BigEndian.Uint16(o[0:2])
}

func (o IPFixHeader) SetLength(length uint16) {
	binary.BigEndian.PutUint16(o[2:4], length)
}

func (o IPFixHeader) SetCount(count uint16) {
	binary.BigEndian.PutUint16(o[2:4], count)
}

func (o IPFixHeader) SetSysUptime(sysUpTime uint32) {
	binary.BigEndian.PutUint32(o[4:8], sysUpTime)
}

func (o IPFixHeader) SetSourceID(sourceID uint32) {
	binary.BigEndian.PutUint32(o[16:20], sourceID)
}

func (o IPFixHeader) SetTimestamp(ts uint32) {
	ver := o.GetVer()
	off := 4
	if ver == 9 {
		off = 8
	}
	binary.BigEndian.PutUint32(o[off:off+4], ts)
}

func (o IPFixHeader) SetFlowSeq(fs uint32) {
	ver := o.GetVer()
	off := 8
	if ver == 9 {
		off = 12
	}
	binary.BigEndian.PutUint32(o[off:off+4], fs)
}

/* IPFixField */

type IPFixField struct {
	Name             string
	Type             uint16
	Length           uint16
	EnterpriseNumber uint32
	Offset           uint16
}

// Len returns the length of a IPFixField.
func (f *IPFixField) Len() int {
	n := 4

	if f.IsEnterprise() {
		n += 4
	}
	return n
}

func (f *IPFixField) IsEnterprise() bool {
	return (f.Type & 0x8000) == 0x8000
}

func (f *IPFixField) encode(b []byte, opts gopacket.SerializeOptions) error {
	binary.BigEndian.PutUint16(b[0:2], f.Type)
	binary.BigEndian.PutUint16(b[2:4], f.Length)
	if f.IsEnterprise() {
		binary.BigEndian.PutUint32(b[4:8], f.EnterpriseNumber)
	}

	return nil
}

type IPFixFields []IPFixField

type IPFixSetEntry interface {
	// Len returns the length of a IPFixSetEntry in bytes.
	Len() int
	// encodes the IPFixSetEntry data into array of bytes.
	encode(b []byte, opts gopacket.SerializeOptions) error
}

/* IPFixTemplate */

type IPFixTemplate struct {
	ID         uint16
	FieldCount uint16
	Fields     IPFixFields
}

// NewIPFixTemplate create a new IPFixTemplate object given id and fields
func NewIPFixTemplate(id uint16, fields IPFixFields) *IPFixTemplate {
	o := new(IPFixTemplate)
	o.ID = id
	o.FieldCount = uint16(len(fields))
	o.Fields = fields
	return o
}

// Len returns the length of a IPFixTemplate.
func (t *IPFixTemplate) Len() int {
	n := 4
	for j := range t.Fields {
		n += t.Fields[j].Len()
	}
	return n
}

func (t *IPFixTemplate) encode(b []byte, opts gopacket.SerializeOptions) error {
	binary.BigEndian.PutUint16(b[0:2], t.ID)
	binary.BigEndian.PutUint16(b[2:4], t.FieldCount)

	offset := 4
	for _, f := range t.Fields {
		if err := f.encode(b[offset:], opts); err != nil {
			return err
		}
		offset += int(f.Len())
	}

	return nil
}

/* IPFixOptionsTemplatev10 */

type IPFixOptionsTemplatev10 struct {
	/*
			      0                   1                   2                   3
		      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |          Set ID = 3           |          Length               |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |         Template ID = 258     |         Field Count = N + M   |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |     Scope Field Count = N     |0|  Scope 1 Infor. Element id. |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |     Scope 1 Field Length      |0|  Scope 2 Infor. Element id. |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |     Scope 2 Field Length      |             ...               |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |            ...                |1|  Scope N Infor. Element id. |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |     Scope N Field Length      |   Scope N Enterprise Number  ...
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		    ...  Scope N Enterprise Number   |1| Option 1 Infor. Element id. |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |    Option 1 Field Length      |  Option 1 Enterprise Number  ...
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		    ... Option 1 Enterprise Number   |              ...              |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |             ...               |0| Option M Infor. Element id. |
		     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		     |     Option M Field Length     |      Padding (optional)       |
			 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	ID         uint16
	FieldCount uint16
	ScopeCount uint16
	Fields     IPFixFields
}

// NewIPFixOptionsTemplatev10 creates a new NewIPFixOptionsTemplatev10 object given the id, scope count and fields.
func NewIPFixOptionsTemplatev10(id, scopeCount uint16, fields IPFixFields) *IPFixOptionsTemplatev10 {
	o := new(IPFixOptionsTemplatev10)
	o.ID = id
	o.ScopeCount = scopeCount
	o.FieldCount = uint16(len(fields))
	o.Fields = fields
	return o
}

// Len returns the length of a IPFixOptionsTemplatev10.
func (t *IPFixOptionsTemplatev10) Len() int {
	n := 6 // 2 for template ID + 2 for field count + 2 for scope count
	for j := range t.Fields {
		n += t.Fields[j].Len()
	}
	return n
}

// encode encodes the object into a packet.
func (t *IPFixOptionsTemplatev10) encode(b []byte, opts gopacket.SerializeOptions) error {
	binary.BigEndian.PutUint16(b[0:2], t.ID)
	binary.BigEndian.PutUint16(b[2:4], t.FieldCount)
	binary.BigEndian.PutUint16(b[4:6], t.ScopeCount)

	offset := 6
	for _, f := range t.Fields {
		if err := f.encode(b[offset:], opts); err != nil {
			return err
		}
		offset += int(f.Len())
	}
	return nil
}

/* IPFixOptionsTemplatev9 */

type IPFixOptionsTemplatev9 struct {
	/*
	    0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |       FlowSet ID = 1          |          Length               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |         Template ID           |      Option Scope Length      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |        Option Length          |       Scope 1 Field Type      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     Scope 1 Field Length      |               ...             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     Scope N Field Length      |      Option 1 Field Type      |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     Option 1 Field Length     |             ...               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |     Option M Field Length     |           Padding             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	ID                uint16
	OptionScopeLength uint16
	OptionLength      uint16
	Fields            IPFixFields
}

// NewIPFixOptionsTemplatev9 creates a new NewIPFixOptionsTemplatev9 object given the id, optionScopeLength, optionLength and fields.
func NewIPFixOptionsTemplatev9(id, optionScopeLength, optionLength uint16, fields IPFixFields) *IPFixOptionsTemplatev9 {
	o := new(IPFixOptionsTemplatev9)
	o.ID = id
	o.OptionScopeLength = optionScopeLength
	o.OptionLength = optionLength
	o.Fields = fields
	return o
}

// Len returns the length of a IPFixOptionsTemplatev9.
func (t *IPFixOptionsTemplatev9) Len() int {
	n := 6 // 2 for  ID + 2 for OptionScopeLength + 2 for OptionLength
	for j := range t.Fields {
		n += t.Fields[j].Len()
	}
	return n
}

// encode encodes the object to a gopacket
func (t *IPFixOptionsTemplatev9) encode(b []byte, opts gopacket.SerializeOptions) error {
	binary.BigEndian.PutUint16(b[0:2], t.ID)
	binary.BigEndian.PutUint16(b[2:4], t.OptionScopeLength)
	binary.BigEndian.PutUint16(b[4:6], t.OptionLength)

	offset := 6
	for _, f := range t.Fields {
		if err := f.encode(b[offset:], opts); err != nil {
			return err
		}
		offset += int(f.Len())
	}
	return nil
}

/* IPFixRecord */
type IPFixRecord struct {
	Data []byte
}

// Len returns the length of a IPFixRecord.
func (r *IPFixRecord) Len() int {
	return len(r.Data)
}

func (r *IPFixRecord) encode(b []byte, opts gopacket.SerializeOptions) error {
	copy(b, r.Data)

	return nil
}

type IPFixTemplates []IPFixTemplate
type IPFixSetEntries []IPFixSetEntry

/* IPFixSet */

type IPFixSet struct {
	ID         uint16
	Length     uint16
	SetEntries IPFixSetEntries
}

// Len returns the length of a IPFixSet.
func (s *IPFixSet) Len() int {
	n := 4
	for j := range s.SetEntries {
		n += s.SetEntries[j].Len()
	}
	s.Length = uint16(n)
	return n
}

// IsDataSet return true if this set is a data set.
func (s *IPFixSet) IsDataSet() bool {
	return s.ID > 255
}

func (s *IPFixSet) encode(b []byte, opts gopacket.SerializeOptions) error {
	binary.BigEndian.PutUint16(b[0:2], s.ID)
	binary.BigEndian.PutUint16(b[2:4], s.Length)

	offset := 4
	for _, t := range s.SetEntries {
		if err := t.encode(b[offset:], opts); err != nil {
			return err
		}
		offset += int(t.Len())
	}
	return nil
}

// IPFixSets is a slice of IPFixSet
type IPFixSets []IPFixSet

// IPFix //
///////////

// IPFix contains data for a single FNF packet.
type IPFix struct {
	BaseLayer
	Ver       uint16
	Length    uint16
	SysUpTime uint32 // Only in ver 9
	Timestamp uint32
	FlowSeq   uint32
	DomainID  uint32
	SourceID  uint32 // Only in ver 9
	Sets      IPFixSets
}

// Len returns the length of IPFix layer
func (i *IPFix) Len() int {
	n := IpfixHeaderLenVer10
	if i.Ver == 9 {
		n = IpfixHeaderLenVer9
	}

	for j := range i.Sets {
		n += i.Sets[j].Len()
	}

	i.Length = uint16(n)
	return n
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (i *IPFix) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	plen := int(i.Len())

	data, err := b.PrependBytes(plen)
	if err != nil {
		return err
	}

	offset := IpfixHeaderLenVer10
	binary.BigEndian.PutUint16(data[0:2], i.Ver)

	if i.Ver == 10 {
		binary.BigEndian.PutUint16(data[2:4], i.Length)
		binary.BigEndian.PutUint32(data[4:8], i.Timestamp)
		binary.BigEndian.PutUint32(data[8:12], i.FlowSeq)
		binary.BigEndian.PutUint32(data[12:16], i.DomainID)
	}
	if i.Ver == 9 {
		setCount := 0
		for j := range i.Sets {
			setCount += len(i.Sets[j].SetEntries)
		}
		binary.BigEndian.PutUint16(data[2:4], uint16(setCount))
		binary.BigEndian.PutUint32(data[4:8], i.SysUpTime)
		binary.BigEndian.PutUint32(data[8:12], i.Timestamp)
		binary.BigEndian.PutUint32(data[12:16], i.FlowSeq)
		binary.BigEndian.PutUint32(data[16:20], i.SourceID)
		offset += 4
	}

	for _, s := range i.Sets {
		if err := s.encode(data[offset:], opts); err != nil {
			return err
		}
		offset += int(s.Length)
	}
	return nil
}

// LayerType returns gopacket.LayerTypeIPFix
func (i *IPFix) LayerType() gopacket.LayerType { return LayerTypeIPFix }

func decodeIPFix(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("Not Implemented yet")
}
