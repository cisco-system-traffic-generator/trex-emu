package tdl

/**
Cisco's TDL - The Definition Language
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

import (
	engines "emu/plugins/field_engine"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/intel-go/fastjson"
)

// TdlTypeIF is the base interface for a Tdl Type. Each Tdl type must implement this.
type TdlTypeIF interface {

	// Any Tdl type must have an encode function, that converts the type to a byte array.
	// Same as serialization/marshaling.
	Encode([]byte) error

	// Any Tdl type must have a decode function. Decodes a byte slice into a Tdl type.
	// Same as de-serialization/un-marshaling.
	Decode([]byte) error

	// GetLength returns the length of the encoded field.
	GetLength() int

	// Indicate if the type is constructed (type_def) or unconstructed.
	IsConstructedType() bool
}

// UnconstructedTdlTypeIF is an interface that represents unconstructed Tdl types, types that have values
// and are not composition of other types.
type UnconstructedTdlTypeIF interface {
	// Any unconstructed Tdl type is a Tdl type.
	TdlTypeIF

	// SetValue sets the initial value of an unconstructed Tdl type.
	SetValue(*fastjson.RawMessage) error

	// Update updates the value of an unconstructed Tdl type based on an engine parameter.
	Update(engines.FieldEngineIF) error

	// FormatTdlType returns a formatted Tdl Type in order to easily dump.
	FormatTdlType() *TdlFormattedType
}

// ConstructedTdlTypeIF is an interface of constructed types, such as TypeDef. These types
// are a composition of other types (constructed or unconstructed). You cannot set the value
// for these types, it needs to be done for each of its entries.
type ConstructedTdlTypeIF interface {
	// Any constructed Tdl type is a Tdl type.
	TdlTypeIF

	/* Returns a map of unconstructed types by iterating all the fields of the constructed type.
	If one of the fields is itself a constructed type, get its map recursively.

	Let's say we have something like this:

	typedef {
		uint8 var0
		uint16 var1
	} type1

	typedef {
		int var0
		type1 var1
	} type2

	Then the map called on `type2` would look like this:
	"var0" -> int object
	"var1.var0" -> uint8 object
	"var1.var1" -> uint16 object
	*/
	GetUnconstructedTypes() map[string]UnconstructedTdlTypeIF
}

// TdlMetaDataIF is an interface for Tdl Meta Data. Each new type we define it is done
// through meta data.
type TdlMetaDataIF interface {
	// ParseMeta parses and processes the metadata.
	ParseMeta(*fastjson.RawMessage, *TdlStats) error

	// GetType returns the type of the meta data.
	GetType() string

	// Get Locally Unique Identifier (LUID) for Tdl Type. In order to be able to decode
	// all metadata/primitive types we need to keep a map of LUID.
	GetLuid() LUID
}

// TdlFormattedType represents a TdlType value and type formatted and ready for dump.
type TdlFormattedType struct {
	Type  string      // Type name
	Value interface{} // Type value
}

// Set of primitive Tdl types.
var PrimitiveTdlTypes map[string]bool = map[string]bool{"uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"int8": true, "int16": true, "int32": true, "int64": true,
	"float": true, "double": true, "counter64": true, "char": true}

// IsPrimitiveTdlType indicates the type given a string is primitive or not.
func IsPrimitiveTdlType(tdlType string) bool {
	_, ok := PrimitiveTdlTypes[tdlType]
	return ok
}

// CreatePrimitiveTdlType creates a new instance of a Tdl primitive type.
func CreatePrimitiveTdlType(tdlTypeStr string) (tdlType TdlTypeIF) {
	switch tdlTypeStr {
	case "char":
		tdlType = new(TdlChar)
	case "uint8":
		tdlType = new(TdlUint8)
	case "uint16":
		tdlType = new(TdlUint16)
	case "uint32":
		tdlType = new(TdlUint32)
	case "uint64":
		tdlType = new(TdlUint64)
	case "int8":
		tdlType = new(TdlInt8)
	case "int16":
		tdlType = new(TdlInt16)
	case "int32":
		tdlType = new(TdlInt32)
	case "int64":
		tdlType = new(TdlInt64)
	case "float":
		tdlType = new(TdlFloat)
	case "double":
		tdlType = new(TdlDouble)
	case "counter64":
		tdlType = new(TdlCounter64)
	default:
		tdlType = nil
	}
	return tdlType
}

// RegisterPrimitiveLuid registers Luid for primitive types
func RegisterPrimitiveLuid(tdlClient *PluginTdlClient) {
	// TODO: Maybe try to encode this in a normal way. Base64 or something.
	tdlClient.registerLuid([16]byte{14, 193, 31, 234, 124, 231, 138, 9, 10, 207, 59, 137, 1, 79, 119, 226}, "uint8")
	tdlClient.registerLuid([16]byte{35, 81, 247, 56, 80, 126, 132, 51, 8, 39, 222, 128, 133, 79, 111, 184}, "uint16")
	tdlClient.registerLuid([16]byte{88, 98, 99, 242, 233, 130, 82, 146, 40, 64, 28, 95, 237, 148, 57, 220}, "uint32")
	tdlClient.registerLuid([16]byte{204, 80, 178, 183, 94, 100, 241, 157, 142, 97, 71, 57, 29, 208, 136, 244}, "uint64")
	tdlClient.registerLuid([16]byte{26, 251, 199, 204, 150, 180, 222, 232, 86, 69, 102, 138, 105, 17, 43, 203}, "int8")
	tdlClient.registerLuid([16]byte{253, 88, 68, 171, 197, 44, 177, 76, 181, 140, 47, 94, 145, 127, 243, 239}, "int16")
	tdlClient.registerLuid([16]byte{218, 162, 251, 216, 239, 86, 108, 71, 226, 61, 237, 218, 58, 206, 11, 136}, "int32")
	tdlClient.registerLuid([16]byte{159, 26, 10, 70, 86, 130, 96, 209, 23, 165, 66, 221, 92, 31, 151, 47}, "int64")
	tdlClient.registerLuid([16]byte{243, 187, 130, 130, 217, 239, 89, 180, 190, 138, 188, 252, 73, 218, 117, 29}, "float")
	tdlClient.registerLuid([16]byte{97, 179, 234, 197, 156, 205, 53, 207, 53, 35, 80, 225, 124, 89, 41, 31}, "double")
	tdlClient.registerLuid([16]byte{198, 110, 87, 174, 241, 19, 164, 204, 7, 190, 188, 114, 20, 219, 19, 248}, "counter64")
	tdlClient.registerLuid([16]byte{150, 30, 181, 138, 149, 22, 187, 121, 54, 125, 11, 229, 104, 230, 41, 255}, "char")
}

// BaseUpdate provides the base functionality for update. This is common to all the
// primitive types.
func BaseUpdate(tdlType UnconstructedTdlTypeIF, engine engines.FieldEngineIF) error {
	b := make([]byte, tdlType.GetLength())
	tdlType.Encode(b)
	_, err := engine.Update(b[engine.GetOffset() : engine.GetOffset()+engine.GetSize()])
	if err != nil {
		return err
	}
	tdlType.Decode(b)
	return nil
}

// ------------------------------------------------------------------------------------------
// TdlChar
//-------------------------------------------------------------------------------------------

//TdlChar is a primitive Tdl type that represents an extended ASCII character.
type TdlChar byte

// Encode a TdlChar into a byte array.
func (o *TdlChar) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	b[0] = byte(*o)
	return nil
}

// Decode a byte array into a TdlUint8.
func (o *TdlChar) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	*o = TdlChar(b[0])
	return nil
}

// GetLength of an encoded TdlUint8.
func (o *TdlChar) GetLength() int {
	return 1
}

// IsConstructedType or is unconstructed type?
func (o *TdlChar) IsConstructedType() bool {
	return false
}

// SetValue of TdlChar.
func (o *TdlChar) SetValue(values *fastjson.RawMessage) error {
	var newValue string
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	newValueEncoded := []byte(newValue)
	if len(newValueEncoded) > o.GetLength() {
		return fmt.Errorf("Can't set value %v for char.\n", newValue)
	}
	*o = TdlChar(newValueEncoded[0])
	return nil
}

// Update the value of a TdlChar using a field engine.
func (o *TdlChar) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlChar.
func (o *TdlChar) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "char"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlUint8
//-------------------------------------------------------------------------------------------

// TdlUint8 is a primitive Tdl type that represents an unsigned integer of 8 bits.
type TdlUint8 uint8

// Encode a TdlUint8 into a byte array.
func (o *TdlUint8) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	b[0] = uint8(*o)
	return nil
}

// Decode a byte array into a TdlUint8.
func (o *TdlUint8) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlUint8(uint8(b[0]))
	return nil
}

// GetLength of an encoded TdlUint8.
func (o *TdlUint8) GetLength() int {
	return 1
}

// IsConstructedType or is unconstructed type?
func (o *TdlUint8) IsConstructedType() bool {
	return false
}

// SetValue of TdlUint8.
func (o *TdlUint8) SetValue(values *fastjson.RawMessage) error {
	var newValue uint8
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlUint8(newValue)
	return nil
}

// Update the value of a TdlUint8 using a field engine.
func (o *TdlUint8) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlUint8.
func (o *TdlUint8) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "uint8"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlUint16
//-------------------------------------------------------------------------------------------

// TdlUint16 is a primitive Tdl type that represents an unsigned integer of 16 bits.
type TdlUint16 uint16

// Encode a TdlUint16 into a byte array.
func (o *TdlUint16) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint16(b, uint16(*o))
	return nil
}

// Decode a byte array into a TdlUint16.
func (o *TdlUint16) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlUint16(binary.BigEndian.Uint16(b))
	return nil
}

// GetLength of an encoded TdlUint16.
func (o *TdlUint16) GetLength() int {
	return 2
}

// IsConstructedType or is unconstructed type?
func (o *TdlUint16) IsConstructedType() bool {
	return false
}

// SetValue of TdlUint16.
func (o *TdlUint16) SetValue(values *fastjson.RawMessage) error {
	var newValue uint16
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlUint16(newValue)
	return nil
}

// Update the value of a TdlUint16 using a field engine.
func (o *TdlUint16) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlUint16.
func (o *TdlUint16) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "uint16"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlUint32
//-------------------------------------------------------------------------------------------

// TdlUint32 is a primitive Tdl type that represents an unsigned integer of 32 bits.
type TdlUint32 uint32

// Encode a TdlUint32 into a byte array.
func (o *TdlUint32) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint32(b, uint32(*o))
	return nil
}

// Decode a byte array into a TdlUint32.
func (o *TdlUint32) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlUint32(binary.BigEndian.Uint32(b))
	return nil
}

// GetLength of an encoded TdlUint32.
func (o *TdlUint32) GetLength() int {
	return 4
}

// IsConstructedType or is unconstructed type?
func (o *TdlUint32) IsConstructedType() bool {
	return false
}

// SetValue of TdlUint32.
func (o *TdlUint32) SetValue(values *fastjson.RawMessage) error {
	var newValue uint32
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlUint32(newValue)
	return nil
}

// Update the value of a TdlUint32 using a field engine.
func (o *TdlUint32) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlUint32.
func (o *TdlUint32) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "uint32"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlUint64
//-------------------------------------------------------------------------------------------

// TdlUint64 is a primitive Tdl type that represents an unsigned integer of 64 bits.
type TdlUint64 uint64

// Encode a TdlUint64 into a byte array.
func (o *TdlUint64) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint64(b, uint64(*o))
	return nil
}

// Decode a byte array into a TdlUint64.
func (o *TdlUint64) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlUint64(binary.BigEndian.Uint64(b))
	return nil
}

// GetLength of an encoded TdlUint64.
func (o *TdlUint64) GetLength() int {
	return 8
}

// IsConstructedType or is unconstructed type?
func (o *TdlUint64) IsConstructedType() bool {
	return false
}

// SetValue of TdlUint64.
func (o *TdlUint64) SetValue(values *fastjson.RawMessage) error {
	var newValue uint64
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlUint64(newValue)
	return nil
}

// Update the value of a TdlUint64 using a field engine.
func (o *TdlUint64) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlUint64.
func (o *TdlUint64) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "uint64"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlInt8
//-------------------------------------------------------------------------------------------

// TdlInt8 is a primitive Tdl type that represents a signed integer (two's complementary) of 8 bits.
type TdlInt8 int8

// Encode a TdlInt8 into a byte array.
func (o *TdlInt8) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	b[0] = uint8(*o)
	return nil
}

// Decode a byte array into a TdlInt8.
func (o *TdlInt8) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlInt8(uint8(b[0]))
	return nil
}

// GetLength of an encoded TdlInt8.
func (o *TdlInt8) GetLength() int {
	return 1
}

// IsConstructedType or is unconstructed type?
func (o *TdlInt8) IsConstructedType() bool {
	return false
}

// SetValue of TdlInt8.
func (o *TdlInt8) SetValue(values *fastjson.RawMessage) error {
	var newValue int8
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlInt8(newValue)
	return nil
}

// Update the value of a TdlInt8 using a field engine.
func (o *TdlInt8) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlInt8.
func (o *TdlInt8) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "int8"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlInt16
//-------------------------------------------------------------------------------------------

// TdlInt16 is a primitive Tdl type that represents a signed integer (two's complementary) of 16 bits.
type TdlInt16 int16

// Encode a TdlInt16 into a byte array.
func (o *TdlInt16) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint16(b, uint16(*o))
	return nil
}

// Decode a byte array into a TdlInt16.
func (o *TdlInt16) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlInt16(binary.BigEndian.Uint16(b))
	return nil
}

// GetLength of an encoded TdlInt16.
func (o *TdlInt16) GetLength() int {
	return 2
}

// IsConstructedType or is unconstructed type?
func (o *TdlInt16) IsConstructedType() bool {
	return false
}

// SetValue of TdlInt16.
func (o *TdlInt16) SetValue(values *fastjson.RawMessage) error {
	var newValue int16
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlInt16(newValue)
	return nil
}

// Update the value of a TdlInt16 using a field engine.
func (o *TdlInt16) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlInt16.
func (o *TdlInt16) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "int16"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlInt32
//-------------------------------------------------------------------------------------------

// TdlInt32 is a primitive Tdl type that represents a signed integer (two's complementary) of 32 bits.
type TdlInt32 int32

// Encode a TdlInt32 into a byte array.
func (o *TdlInt32) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint32(b, uint32(*o))
	return nil
}

// Decode a byte array into a TdlInt32.
func (o *TdlInt32) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlInt32(binary.BigEndian.Uint32(b))
	return nil
}

// GetLength of an encoded TdlInt32.
func (o *TdlInt32) GetLength() int {
	return 4
}

// IsConstructedType or is unconstructed type?
func (o *TdlInt32) IsConstructedType() bool {
	return false
}

// SetValue of TdlInt32.
func (o *TdlInt32) SetValue(values *fastjson.RawMessage) error {
	var newValue int32
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlInt32(newValue)
	return nil
}

// Update the value of a TdlInt32 using a field engine.
func (o *TdlInt32) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlInt32.
func (o *TdlInt32) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "int32"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlInt64
//-------------------------------------------------------------------------------------------

// TdlInt64 is a primitive Tdl type that represents a signed integer (two's complementary) of 64 bits.
type TdlInt64 int64

// Encode a TdlInt64 into a byte array.
func (o *TdlInt64) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint64(b, uint64(*o))
	return nil
}

// Decode a byte array into a TdlInt64.
func (o *TdlInt64) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlInt64(binary.BigEndian.Uint64(b))
	return nil
}

// GetLength of an encoded TdlInt64.
func (o *TdlInt64) GetLength() int {
	return 8
}

// IsConstructedType or is unconstructed type?
func (o *TdlInt64) IsConstructedType() bool {
	return false
}

// SetValue of TdlInt64.
func (o *TdlInt64) SetValue(values *fastjson.RawMessage) error {
	var newValue int64
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlInt64(newValue)
	return nil
}

// Update the value of a TdlInt64 using a field engine.
func (o *TdlInt64) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlInt64.
func (o *TdlInt64) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "int64"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlFloat
//-------------------------------------------------------------------------------------------

// TdlFloat is a primitive Tdl type that represents a float, according to IEEE-754 with 32 bit precision.
type TdlFloat float32

// Encode a TdlFloat into a byte array.
func (o *TdlFloat) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint32(b, math.Float32bits(float32(*o)))
	return nil
}

// Decode a byte array into a TdlFloat.
func (o *TdlFloat) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlFloat(math.Float32frombits(binary.BigEndian.Uint32(b)))
	return nil
}

// GetLength of an encoded TdlFloat.
func (o *TdlFloat) GetLength() int {
	return 4
}

// IsConstructedType or is unconstructed type?
func (o *TdlFloat) IsConstructedType() bool {
	return false
}

// SetValue of TdlFloat.
func (o *TdlFloat) SetValue(values *fastjson.RawMessage) error {
	var newValue float32
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlFloat(newValue)
	return nil
}

// Update the value of a TdlFloat using a field engine.
func (o *TdlFloat) Update(engine engines.FieldEngineIF) error {
	if int(engine.GetSize()) != o.GetLength() {
		// Assuming this is a float engine, it should be float32.
		return fmt.Errorf("TdlFloat engine should be a float32. Want size = %v, have size %v", o.GetLength(), engine.GetSize())
	}
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlFloat.
func (o *TdlFloat) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "float"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlDouble
//-------------------------------------------------------------------------------------------

// TdlDouble is a primitive Tdl type that represents a double according to IEEE-754 with 64 bit precision.
type TdlDouble float64

// Encode a TdlDouble into a byte array.
func (o *TdlDouble) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint64(b, math.Float64bits(float64(*o)))
	return nil
}

// Decode a byte array into a TdlDouble.
func (o *TdlDouble) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	*o = TdlDouble(math.Float64frombits(binary.BigEndian.Uint64(b)))
	return nil
}

// GetLength of an encoded TdlDouble.
func (o *TdlDouble) GetLength() int {
	return 8
}

// IsConstructedType or is unconstructed type?
func (o *TdlDouble) IsConstructedType() bool {
	return false
}

// SetValue of TdlDouble.
func (o *TdlDouble) SetValue(values *fastjson.RawMessage) error {
	var newValue float64
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlDouble(newValue)
	return nil
}

// Update the value of a TdlDouble using a field engine.
func (o *TdlDouble) Update(engine engines.FieldEngineIF) error {
	if int(engine.GetSize()) != o.GetLength() {
		// Assuming it is a float engine, it should be a float64.
		return fmt.Errorf("TdlDouble engine should be a float64. Want size = %v, have size %v", o.GetLength(), engine.GetSize())
	}
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlDouble.
func (o *TdlDouble) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "double"
	t.Value = *o
	return t
}

// ------------------------------------------------------------------------------------------
// TdlCounter64
//-------------------------------------------------------------------------------------------

// TdlCounter64 represents a Tdl type composed by a counter and a residual. Both are signed
// 64 bit integers. The counter is encoded first at offset=0, the residual at offset=8.
type TdlCounter64 struct {
	Counter  int64 `json:"counter" validate:"required"`  // Counter value, offset = 0
	Residual int64 `json:"residual" validate:"required"` // Residual value, offset = 8
}

// Encode a TdlCounter64 into a byte array.
func (o *TdlCounter64) Encode(b []byte) error {
	// Converting between int64 to uint64 doesn't change the bit sign, only the way it is interpreted.
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	binary.BigEndian.PutUint64(b, uint64(o.Counter))
	binary.BigEndian.PutUint64(b[8:], uint64(o.Residual))
	return nil
}

// Decode a byte array into a TdlCounter64.
func (o *TdlCounter64) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	o.Counter = int64(binary.BigEndian.Uint64(b))
	o.Residual = int64(binary.BigEndian.Uint64(b[8:]))
	return nil
}

// GetLength of an encoded TdlCounter.
func (o *TdlCounter64) GetLength() int {
	return 16
}

// IsConstructedType or is unconstructed type?
func (o *TdlCounter64) IsConstructedType() bool {
	return false
}

// SetValue of TdlCounter64.
func (o *TdlCounter64) SetValue(values *fastjson.RawMessage) error {
	var newValue TdlCounter64
	err := fastjson.Unmarshal(*values, &newValue)
	if err != nil {
		return err
	}
	*o = TdlCounter64(newValue)
	return nil
}

// Update the value of a TdlCounter64 using a field engine.
func (o *TdlCounter64) Update(engine engines.FieldEngineIF) error {
	return BaseUpdate(o, engine)
}

// FormatTdlType formats a TdlCounter64.
func (o *TdlCounter64) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "counter64"
	t.Value = *o
	return t
}

/* ------------------------------------------------------------------------------------------
TdlEnum

				 0                   1                   2                   3
				 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|    Variant     |                      Enum Value ...
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|      ....      |
				+-+-+-+-+-+-+-+-+-
-------------------------------------------------------------------------------------------*/

// TdlEnumEntry represents an entry in a TdlEnumDef. An Enum entry consists of a name and value.
type TdlEnumEntry struct {
	Name  string `json:"name" validate:"required"`  // Name of enum entry
	Value int32  `json:"value" validate:"required"` // Value of enum entry
}

// TdlEnumDef implements a Tdl Enum Definition. A Tdl Enum Definition consists
// of multiple Tdl Enum Entries. The definition is used for metadata purposes.
type TdlEnumDef struct {
	Entries     []TdlEnumEntry   `json:"entries" validate:"required"` // List of Enum entries in the enum
	Luid        LUID             `json:"luid" validate:"required"`    // Luid of the new enum type we are defining
	nameToValue map[string]int32 // Fast Lookup Name To Value
	valueToName map[int32]string // Fast Lookup Value to Name
	metaMgr     *TdlMetaDataMgr  // Back pointer to the Manager.
}

// processEnumDef builds name to value and value to name mappings for fast lookup.
// The build is done once, offline when creating the Tdl Enum definition.
func (o *TdlEnumDef) processEnumDef() error {
	o.nameToValue = make(map[string]int32, len(o.Entries))
	o.valueToName = make(map[int32]string, len(o.Entries))
	for i := range o.Entries {
		enumEntry := o.Entries[i]
		if _, ok := o.nameToValue[enumEntry.Name]; ok {
			return fmt.Errorf("Name %v duplicated in Enum definition.\n", enumEntry.Name)
		}
		o.nameToValue[enumEntry.Name] = enumEntry.Value
		if _, ok := o.valueToName[enumEntry.Value]; ok {
			return fmt.Errorf("Value %v duplicated in Enum definition.\n", enumEntry.Value)
		}
		o.valueToName[enumEntry.Value] = enumEntry.Name
	}
	return nil
}

// ParseMeta parses and processes the meta data defining a new type of Enum.
func (o *TdlEnumDef) ParseMeta(meta *fastjson.RawMessage, stats *TdlStats) error {
	// TODO: Should validate and not only unmarshal.
	err := fastjson.Unmarshal(*meta, o)
	if err != nil {
		stats.invalidEnumDef++
		return err
	}
	err = o.processEnumDef()
	if err != nil {
		stats.invalidEnumDef++
		return err
	}
	return nil
}

// GetType of the metadata definition.
func (o *TdlEnumDef) GetType() string {
	return "enum_def"
}

// GetLUID returns the Luid of an Enum definition.
func (o *TdlEnumDef) GetLuid() LUID {
	return o.Luid
}

// NewTdlEnumDef creates a new TdlEnumDef.
func NewTdlEnumDef(metaMgr *TdlMetaDataMgr) TdlMetaDataIF {
	o := new(TdlEnumDef)
	o.metaMgr = metaMgr
	return o
}

// TdlEnumInstance represents an instance of a Tdl Enum definition.
type TdlEnumInstance struct {
	Variant byte         // Variant
	meta    *TdlEnumDef  // A pointer to the read only meta data. Many instances share this.
	val     TdlEnumEntry // The actual value of this instance.
}

// Encode a TdlEnumDef into a byte array.
func (o *TdlEnumInstance) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to encode is too short.\n")
	}
	b[0] = o.Variant
	binary.BigEndian.PutUint32(b[1:], uint32(o.val.Value))
	return nil
}

// Decode a byte array into a TdlEnumDef.
func (o *TdlEnumInstance) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	o.Variant = b[0]
	o.val.Value = int32(binary.BigEndian.Uint32(b[1:]))
	o.val.Name = o.meta.valueToName[o.val.Value]
	return nil
}

// GetLength of an encoded TdlEnumDef.
func (o *TdlEnumInstance) GetLength() int {
	return 5
}

// IsConstructedType or is unconstructed type?
func (o *TdlEnumInstance) IsConstructedType() bool {
	return false
}

// SetValue of TdlEnumInstance.
func (o *TdlEnumInstance) SetValue(values *fastjson.RawMessage) error {
	// Setting values as strings only.
	var newName string
	err := fastjson.Unmarshal(*values, &newName)
	if err != nil {
		return err
	}
	newValue, ok := o.meta.nameToValue[newName]
	if !ok {
		return fmt.Errorf("Invalid value %v for Tdl Enum instance!", newName)
	}
	o.val.Name = newName
	o.val.Value = newValue
	return nil
}

// Update the value of a TdlEnumInstance using a field engine.
func (o *TdlEnumInstance) Update(engine engines.FieldEngineIF) error {
	// Assume a string list engine or string histogram.
	// This doesn't support padding, assumes padded symbol is empty.
	b := make([]byte, engine.GetSize())
	length, err := engine.Update(b[engine.GetOffset() : engine.GetOffset()+engine.GetSize()])
	if err != nil {
		return err
	}
	newEnumNamePadded := string(b[engine.GetOffset() : int(engine.GetOffset())+length])
	var paddingRune rune
	var newEnumName string
	indexPadded := strings.IndexRune(newEnumNamePadded, paddingRune)
	if indexPadded != -1 {
		newEnumName = newEnumNamePadded[:indexPadded]
	} else {
		newEnumName = newEnumNamePadded
	}

	if _, ok := o.meta.nameToValue[newEnumName]; !ok {
		return fmt.Errorf("Generated string %v not a valid enum entry.", newEnumName)
	}
	o.val.Name = newEnumName
	o.val.Value = o.meta.nameToValue[newEnumName]
	return nil
}

// FormatTdlType formats a TdlEnumInstance.
func (o *TdlEnumInstance) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "enum"
	t.Value = o.val
	return t
}

// NewTdlEnumInstance creates a new Tdl Enum instance.
func NewTdlEnumInstance(meta TdlMetaDataIF) (TdlTypeIF, error) {
	enumMeta, ok := meta.(*TdlEnumDef)
	if !ok {
		return nil, fmt.Errorf("Invalid meta data object provided to Enum instance!")
	}
	o := new(TdlEnumInstance)
	o.meta = enumMeta
	return o, nil
}

/**------------------------------------------------------------------------------------------
TdlFlag
				 0                   1                   2                   3
				 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|    Variant     |                   Jump Variant ...
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|      ....      |                    Bit Array ...
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Note: The bit array is encoded left to right. Its length is the minimal number of bytes
needed to hold all of the flags, where each flag is represented by a bit.
-------------------------------------------------------------------------------------------**/

// TdlFlagDef implements a Tdl Flag Definition. A Tdl Flag definition consists
// of multiple Tdl Flag Entries. The flags have a binary state (set, not set).
type TdlFlagDef struct {
	Entries     []string          `json:"entries" validate:"required"` // Entries in the flag
	Luid        LUID              `json:"luid" validate:"required"`    // Luid of the flag we are defining
	bitArrayLen int               // Length of bit array
	length      int               // Total length of field, including jump if specified.
	nameToValue map[string]uint64 // Map flag name to its value
	metaMgr     *TdlMetaDataMgr   // Back pointer to the Manager.
}

// processFlagDef processes the flag definition, checking for invalid values, duplicate names etc.
// Also maps names to values for fast lookup.
func (o *TdlFlagDef) processFlagDef() error {
	// Anything must be aligned to bytes (8 bits)
	o.bitArrayLen = (len(o.Entries)-1)/8 + 1
	// Assumes jump variant is 0, since jump variant is not supported at the moment.
	o.length = 1 + 4 + o.bitArrayLen // variant 1 byte + jumpVariant 4 bytes + bitArray
	o.nameToValue = make(map[string]uint64)
	for i, flag := range o.Entries {
		if _, ok := o.nameToValue[flag]; ok {
			return fmt.Errorf("Flag %v duplicated in Flag definition.\n", flag)
		}
		o.nameToValue[flag] = uint64(i)
	}
	return nil
}

// ParseMeta parses and processes the meta data defining a new type of Flag.
func (o *TdlFlagDef) ParseMeta(meta *fastjson.RawMessage, stats *TdlStats) error {
	err := fastjson.Unmarshal(*meta, o)
	if err != nil {
		stats.invalidFlagDef++
		return err
	}
	err = o.processFlagDef()
	if err != nil {
		stats.invalidFlagDef++
		return err
	}
	return nil
}

// GetType of the metadata definition.
func (o *TdlFlagDef) GetType() string {
	return "flag_def"
}

// GetLUID returns the Luid of an Flag definition.
func (o *TdlFlagDef) GetLuid() LUID {
	return o.Luid
}

// NewTdlFlagDef creates a new Tdl Flag definition.
func NewTdlFlagDef(meta *TdlMetaDataMgr) TdlMetaDataIF {
	o := new(TdlFlagDef)
	o.metaMgr = meta
	return o
}

// TdlFlagInstance represents an instance of Tdl flag defined in metadata.
// The TdlFlagDef is encoded in a bitmap where set bits are represented by 1.
// The encoding is done left to right.
type TdlFlagInstance struct {
	Variant     byte        // Variant
	JumpVariant int32       // Jump relative to variant. The new position is the maximum between jumpVariant or length of encoded message.
	meta        *TdlFlagDef // Pointer to meta data. Can be shared throughout many instances.
	bitArray    []byte      // Flag holder bit array. If bit is set -> flag is active.
}

// Encode a TdlFlagDef into a byte array.
func (o *TdlFlagInstance) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	b[0] = o.Variant
	binary.BigEndian.PutUint32(b[1:], uint32(o.JumpVariant))
	copied := copy(b[5:], o.bitArray)
	if copied != o.meta.bitArrayLen {
		return fmt.Errorf("Failed copying bitmap to provided byte array.\n")
	}
	return nil
}

// Decode a byte array into a TdlFlagDef.
func (o *TdlFlagInstance) Decode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	o.Variant = b[0]
	o.JumpVariant = int32(binary.BigEndian.Uint32(b[1:]))
	copied := copy(o.bitArray, b[5:5+o.meta.bitArrayLen])
	if copied != o.meta.bitArrayLen {
		return fmt.Errorf("Failed decoding TdlFlagDef.")
	}
	return nil
}

// GetLength of an encoded TdlFlagDef.
func (o *TdlFlagInstance) GetLength() int {
	return o.meta.length
}

// IsConstructedType or is unconstructed type?
func (o *TdlFlagInstance) IsConstructedType() bool {
	return false
}

// SetValue of TdlEnumDef.
func (o *TdlFlagInstance) SetValue(values *fastjson.RawMessage) error {
	// Should always be a list of strings.
	var newFlags []string
	err := fastjson.Unmarshal(*values, &newFlags)
	if err != nil {
		return err
	}

	// validity check
	for _, flag := range newFlags {
		if _, ok := o.meta.nameToValue[flag]; !ok {
			return fmt.Errorf("Trying to set invalid flag %v.", flag)
		}
	}

	// clear the set flags
	o.bitArray = make([]byte, o.meta.bitArrayLen)
	for _, flag := range newFlags {
		o.SetFlag(flag)
	}
	return nil
}

// Update the value of a TdlFlagInstance using a field engine.
func (o *TdlFlagInstance) Update(engine engines.FieldEngineIF) error {
	return fmt.Errorf("Engines for flags are not supported at the moment!!")
}

// GetFlagSet indicates if the flag is set (true) or not (false).
func (o *TdlFlagInstance) GetFlagSet(flag string) bool {
	value := o.meta.nameToValue[flag]
	byteIndex := value / 8                         // Index of the byte in which the flag is found.
	var mask uint8 = 1 << (value % 8)              // Mask of the flag in the corresponding byte, for example for 5 it is 00100000.
	return o.bitArray[int(byteIndex)]&mask == mask // Flag is set if value in the bit array is 1.
}

// SetFlag sets a flag.
func (o *TdlFlagInstance) SetFlag(flag string) {
	value := o.meta.nameToValue[flag]
	byteIndex := value / 8             // Index of the byte in which the flag is found.
	var mask uint8 = 1 << (value % 8)  // Mask of the flag in the corresponding byte, for example for 5 it is 00100000.
	o.bitArray[int(byteIndex)] |= mask // Set flag entry to 1.
}

// UnsetFlag unsets a flag.
func (o *TdlFlagInstance) UnsetFlag(flag string) {
	value := o.meta.nameToValue[flag]
	// Golang doesn't support ~ (unary not), so we xor with 0xFF.
	byteIndex := value / 8                      // Index to the byte in which the flag is found.
	var reverseMask uint8 = 0xFF ^ 1<<(value%8) // ReverseMask of the flag in the corresponding byte, for example for 5 it is 11011111.
	o.bitArray[int(byteIndex)] &= reverseMask   // Set flag entry to 0
}

// FormatTdlType formats a TdlFlagInstance.
func (o *TdlFlagInstance) FormatTdlType() *TdlFormattedType {
	t := new(TdlFormattedType)
	t.Type = "flag"
	var setFlags []string
	for _, entry := range o.meta.Entries {
		if o.GetFlagSet(entry) {
			setFlags = append(setFlags, entry)
		}
	}
	t.Value = setFlags
	return t
}

// NewTdlFlagInstance creates a new Tdl Flag instance.
func NewTdlFlagInstance(meta TdlMetaDataIF) (TdlTypeIF, error) {
	flagMeta, ok := meta.(*TdlFlagDef)
	if !ok {
		return nil, fmt.Errorf("Invalid meta data object provided to Flag instance!")
	}
	o := new(TdlFlagInstance)
	o.meta = flagMeta
	o.bitArray = make([]byte, o.meta.bitArrayLen)
	return o, nil
}

/** ------------------------------------------------------------------------------------------
TdlTypeDef
				 0                   1                   2                   3
				 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|    Variant     |     Flags     |   Jump Variant ...
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|             ....               |      Entry 1...
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				|      Entry 2...
				+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

-------------------------------------------------------------------------------------------**/

//TdlTypeDefEntry represents an entry in a Tdl type definition.
type TdlTypeDefEntry struct {
	Name string `json:"name" validate:"required"` // Name of the entry
	Type string `json:"type" validate:"required"` // Type of the entry
}

// TdlTypeDef defines a new Tdl type definition. Used by metadata only.
type TdlTypeDef struct {
	TypeDefEntries []TdlTypeDefEntry `json:"entries" validate:"required"` // The entries in the new type definition.
	Luid           LUID              `json:"luid" validate:"required"`    // Luid of the new type we are defining.
	metaMgr        *TdlMetaDataMgr   // Back pointer to the Manager.
}

// ParseMeta parses and processes the meta data defining a new type of Type.
func (o *TdlTypeDef) ParseMeta(meta *fastjson.RawMessage, stats *TdlStats) error {
	// TODO: Should validate and not only unmarshal.
	err := fastjson.Unmarshal(*meta, o)
	if err != nil {
		stats.invalidTypeDef++
		return err
	}
	return nil
}

// GetType of the metadata definition.
func (o *TdlTypeDef) GetType() string {
	return "type_def"
}

// GetLUID returns the Luid of an Type definition.
func (o *TdlTypeDef) GetLuid() LUID {
	return o.Luid
}

// NewTdlTypeDef creates a new TdlTypeDef.
func NewTdlTypeDef(meta *TdlMetaDataMgr) TdlMetaDataIF {
	o := new(TdlTypeDef)
	o.metaMgr = meta
	return o

}

// TdlTypeInstance represents an instance of a type definition defined in metadata.
type TdlTypeInstance struct {
	Variant     byte        // Variant
	Flags       byte        // Flags
	JumpVariant int32       // JumpVariant in case of padding
	meta        *TdlTypeDef // Pointer to the Flag definition. Many instances share this.
	entries     []TdlTypeIF // All the subentries
	length      int         // Length of the encoded byte array
}

// Encode a TdlTypeDef into a byte array.
func (o *TdlTypeInstance) Encode(b []byte) error {
	if len(b) < o.GetLength() {
		return fmt.Errorf("Byte Array provided to decode is too short.\n")
	}
	b[0] = o.Variant
	b[1] = o.Flags
	binary.BigEndian.PutUint32(b[2:], uint32(o.JumpVariant))
	startingIndex := 6
	for i := range o.entries {
		entry := o.entries[i]
		entryLength := entry.GetLength()
		err := entry.Encode(b[startingIndex : startingIndex+entryLength])
		if err != nil {
			return err
		}
		startingIndex += entryLength
	}
	return nil
}

// Decode a byte array into a TdlTypeDef.
func (o *TdlTypeInstance) Decode(b []byte) error {
	o.Variant = b[0]
	o.Flags = b[1]
	o.JumpVariant = int32(binary.BigEndian.Uint32(b[2:]))
	startingIndex := 6
	for i := range o.entries {
		entry := o.entries[i]
		entryLength := entry.GetLength()
		err := entry.Decode(b[startingIndex : startingIndex+entryLength])
		if err != nil {
			return err
		}
		startingIndex += entryLength
	}
	return nil
}

// GetLength of an encoded TdlTypeDef.
func (o *TdlTypeInstance) GetLength() int {
	return o.length
}

// IsConstructedType returns True if this is a constructed type.
func (o *TdlTypeInstance) IsConstructedType() bool {
	return true
}

// GetUnconstructedTypes returns a map of unconstructed types belonging to this instance
// where the key is the full path to that Tdl type, and the value is the Tdl type instance.
func (o *TdlTypeInstance) GetUnconstructedTypes() map[string]UnconstructedTdlTypeIF {
	leaves := make(map[string]UnconstructedTdlTypeIF)
	for i, _ := range o.entries {
		entry := o.entries[i]
		name := o.meta.TypeDefEntries[i].Name
		if !entry.IsConstructedType() {
			leaves[name] = o.entries[i].(UnconstructedTdlTypeIF)
		} else {
			constructedEntry, _ := entry.(ConstructedTdlTypeIF)
			subTreeLeaves := constructedEntry.GetUnconstructedTypes()
			for leaf, value := range subTreeLeaves {
				absPath := name + "." + leaf
				leaves[absPath] = value
			}
		}
	}
	return leaves
}

// buildEntries builds the entries of the Type def instance. It is important to create
// new instances for each entry.
func (o *TdlTypeInstance) buildEntries() error {
	var entry TdlTypeIF
	for _, typeDefEntry := range o.meta.TypeDefEntries {
		if IsPrimitiveTdlType(typeDefEntry.Type) {
			// Primitive types have no meta data.
			entry = CreatePrimitiveTdlType(typeDefEntry.Type)
		} else {
			// Not primitive, has meta data.
			metaMgr := o.meta.metaMgr
			meta, ok := metaMgr.metaMap[typeDefEntry.Type]
			if !ok {
				return fmt.Errorf("Type %v not primitive and not defined in metadata.\n", typeDefEntry.Type)
			}
			instanceCtor, err := getTdlInstanceCtor(meta.GetType())
			if err != nil {
				return err
			}
			entry, err = instanceCtor(meta)
			if err != nil {
				return err
			}
		}
		o.entries = append(o.entries, entry)
	}
	return nil
}

// build the new Tdl type instance.
func (o *TdlTypeInstance) build() error {
	err := o.buildEntries()
	if err != nil {
		return err
	}
	o.length = 6 // variant + flags + jumpVariant
	// assuming jumpVariant = 0
	for i := range o.entries {
		o.length += o.entries[i].GetLength()
	}
	return nil
}

// NewTdlTypeInstance creates a new Tdl Type instance.
func NewTdlTypeInstance(meta TdlMetaDataIF) (TdlTypeIF, error) {
	typeDefMeta, ok := meta.(*TdlTypeDef)
	if !ok {
		return nil, fmt.Errorf("Invalid meta data object provided to TypeDef instance.")
	}
	o := new(TdlTypeInstance)
	o.meta = typeDefMeta
	o.build()
	return o, nil
}

/**=====================================================================================
	Tdl Meta Manager
======================================================================================*/
// TdlMetaEntry defines a structure on how to provide the metadata. Each meta data entry must
// provide a name, a type, and the data for that type.
type TdlMetaEntry struct {
	Name string               `json:"name" validate:"required"` // Name of the type
	Type string               `json:"type" validate:"required"` // Type of the type
	Data *fastjson.RawMessage `json:"data" validate:"required"` // MetaData of this type
}

// TdlMetaDataMgr defines a Tdl Meta Data Manager. The manager reads the meta data list
// and creates the types for each entry.
type TdlMetaDataMgr struct {
	metaDataList []TdlMetaEntry           // List of TdlMetaEntry so we can map the types to the ctor.
	tdlClient    *PluginTdlClient         // Back Pointer to Tdl Client
	metaMap      map[string]TdlMetaDataIF // Map names to an meta data instances.
}

// registerLuid registers the Luid of all the meta definitions.
func (o *TdlMetaDataMgr) registerLuid() {
	for metaDef, metaDataObj := range o.metaMap {
		o.tdlClient.registerLuid(metaDataObj.GetLuid(), metaDef)
	}
}

// NewTdlMetaDataMgr creates a Tdl Meta Data Manager object.
func NewTdlMetaDataMgr(tdlPlugin *PluginTdlClient, metaData *fastjson.RawMessage) (*TdlMetaDataMgr, error) {
	o := new(TdlMetaDataMgr)
	o.tdlClient = tdlPlugin
	o.metaMap = make(map[string]TdlMetaDataIF)

	// TODO: We need to validate the data, but UnmarshalValidate doesn't work with
	// lists. You can get the JSON validator using o.tdlClient.Tctx.GetJSONValidator()
	// and make some smarter validation.
	err := fastjson.Unmarshal(*metaData, &o.metaDataList)
	if err != nil {
		o.tdlClient.stats.invalidMetaData++
		return nil, err
	}

	for i := range o.metaDataList {
		ctor, err := getTdlMetaCtor(o.metaDataList[i].Type)
		if err != nil {
			o.tdlClient.stats.unregisteredTdlType++
			return nil, err
		}
		tdlMeta := ctor(o)
		err = tdlMeta.ParseMeta(o.metaDataList[i].Data, &tdlPlugin.stats)
		if err != nil {
			o.tdlClient.stats.failedCreatingTdlType++
			return nil, err
		}
		o.metaMap[o.metaDataList[i].Name] = tdlMeta
	}

	return o, nil
}

/**=====================================================================================
	(Tdl Types -> MetaData Constructor) Maps
======================================================================================*/

// TdlMetaCtor represents a new meta ctor signature for a Tdl type.
type TdlMetaCtor func(*TdlMetaDataMgr) TdlMetaDataIF

// TdlMetaCtorDb is the database that maps each Tdl type to its meta ctor.
type TdlMetaCtorDb struct {
	M map[string]TdlMetaCtor
}

// Instance of the TdlMetaCtor database.
var tdlMetaCtorDb TdlMetaCtorDb

// getTdlMetaCtor gets the meta constructor of the provided Tdl type.
func getTdlMetaCtor(tdlType string) (TdlMetaCtor, error) {
	_, ok := tdlMetaCtorDb.M[tdlType]
	if !ok {
		// This *can't* panic, it is called with user input.
		return nil, fmt.Errorf("Tdl meta type %s is not registered.", tdlType)
	}
	return tdlMetaCtorDb.M[tdlType], nil
}

// tdlMetaRegisters registers the meta constructor of the provided Tdl type.
func tdlMetaRegister(tdlType string, ctor TdlMetaCtor) {
	if tdlMetaCtorDb.M == nil {
		tdlMetaCtorDb.M = make(map[string]TdlMetaCtor)
	}
	_, ok := tdlMetaCtorDb.M[tdlType]
	if ok {
		s := fmt.Sprintf("Can't register the same Tdl type twice, %s ", tdlType)
		// This is okay to panic since the developer registers the Tdl Types, not the user.
		panic(s)
	}
	tdlMetaCtorDb.M[tdlType] = ctor
}

/**=====================================================================================
	(Tdl Types -> Instance Constructor) Maps
======================================================================================*/

// TdlInstanceCtor represents a new instance ctor signature for a Tdl type.
type TdlInstanceCtor func(TdlMetaDataIF) (TdlTypeIF, error)

// TdlInstanceCtorDb is the database that maps each Tdl type to its instance ctor.
type TdlInstanceCtorDb struct {
	M map[string]TdlInstanceCtor
}

// Instance of the TdlInstanceCtor database.
var tdlInstanceCtorDb TdlInstanceCtorDb

// getTdlInstanceCtor gets the instance constructor of the provided Tdl type.
func getTdlInstanceCtor(tdlType string) (TdlInstanceCtor, error) {
	_, ok := tdlInstanceCtorDb.M[tdlType]
	if !ok {
		// This *can't* panic, it is called with user input.
		return nil, fmt.Errorf("Tdl meta type %s is not registered.", tdlType)
	}
	return tdlInstanceCtorDb.M[tdlType], nil
}

// tdlInstanceRegisters registers the instance constructor of the provided Tdl type.
func tdlInstanceRegister(tdlType string, ctor TdlInstanceCtor) {
	if tdlInstanceCtorDb.M == nil {
		tdlInstanceCtorDb.M = make(map[string]TdlInstanceCtor)
	}
	_, ok := tdlInstanceCtorDb.M[tdlType]
	if ok {
		s := fmt.Sprintf("Can't register the same Tdl type twice, %s ", tdlType)
		// This is okay to panic since the developer registers the Tdl Types, not the user.
		panic(s)
	}
	tdlInstanceCtorDb.M[tdlType] = ctor
}

func init() {
	// Register all the Tdl Type Definitions.
	tdlMetaRegister("enum_def", NewTdlEnumDef)
	tdlInstanceRegister("enum_def", NewTdlEnumInstance)
	tdlMetaRegister("flag_def", NewTdlFlagDef)
	tdlInstanceRegister("flag_def", NewTdlFlagInstance)
	tdlMetaRegister("type_def", NewTdlTypeDef)
	tdlInstanceRegister("type_def", NewTdlTypeInstance)
}
