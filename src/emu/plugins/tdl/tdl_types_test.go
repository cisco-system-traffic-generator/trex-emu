package tdl

import (
	"bytes"
	"fmt"
	"math"
	"testing"
)

// compareBytes compares that two byte slices are equal.
// In case they are not, it fails the test.
func compareBytes(t *testing.T, a []byte, b []byte, message string) {
	if bytes.Compare(a, b) == 0 {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}

// assertEquals compares to comparable types. In case they are not equal, it fails the test.
func assertEquals(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}

// TestPrimitiveTypes tests the encoding, decoding, get length of fundamental numeric types.
func TestPrimitiveTypes(t *testing.T) {

	// TdlChar
	var var0 TdlChar = 'B'
	var var0Decoded TdlChar
	var0Encoded := []byte{66}
	b := make([]byte, 1)
	var0.Encode(b)
	var0Decoded.Decode(b)
	compareBytes(t, b, var0Encoded, "")
	assertEquals(t, var0, var0Decoded, "")
	assertEquals(t, var0.GetLength(), 1, "")

	// TdlUint8
	var var1 TdlUint8 = 5
	var var1Decoded TdlUint8
	var1Encoded := []byte{5}
	var1.Encode(b)
	var1Decoded.Decode(b)
	compareBytes(t, b, var1Encoded, "")
	assertEquals(t, var1, var1Decoded, "")
	assertEquals(t, var1.GetLength(), 1, "")

	// TdlUint16
	var var2 TdlUint16 = 443
	var2Encoded := []byte{0x01, 0xBB}
	var var2Decoded TdlUint16
	b = make([]byte, 2)
	var2.Encode(b)
	var2Decoded.Decode(b)
	compareBytes(t, b, var2Encoded, "")
	assertEquals(t, var2, var2Decoded, "")
	assertEquals(t, var2.GetLength(), 2, "")

	// TdlUint32
	var var3 TdlUint32 = 77777
	var var3Decoded TdlUint32
	var3Encoded := []byte{0x00, 0x01, 0x2F, 0xD1}
	b = make([]byte, 4)
	var3.Encode(b)
	var3Decoded.Decode(b)
	compareBytes(t, b, var3Encoded, "")
	assertEquals(t, var3, var3Decoded, "")
	assertEquals(t, var3.GetLength(), 4, "")

	// TdlUint64
	var var4 TdlUint64 = 12345678987654321
	var var4Decoded TdlUint64
	var4Encoded := []byte{0x00, 0x2B, 0xDC, 0x54, 0x62, 0x91, 0xF4, 0xB1}
	b = make([]byte, 8)
	var4.Encode(b)
	var4Decoded.Decode(b)
	compareBytes(t, b, var4Encoded, "")
	assertEquals(t, var4, var4Decoded, "")
	assertEquals(t, var4.GetLength(), 8, "")

	// TdlInt8
	var var5 TdlInt8 = 5
	var var5Decoded TdlInt8
	var5Encoded := []byte{5}
	b = make([]byte, 1)
	var5.Encode(b)
	var5Decoded.Decode(b)
	compareBytes(t, b, var5Encoded, "")
	assertEquals(t, var5, var5Decoded, "")
	assertEquals(t, var5.GetLength(), 1, "")

	var var6 TdlInt8 = -128
	var var6Decoded TdlInt8
	var6Encoded := []byte{128}
	var6.Encode(b)
	var6Decoded.Decode(b)
	compareBytes(t, b, var6Encoded, "")
	assertEquals(t, var6, var6Decoded, "")

	// TdlInt16
	var var7 TdlInt16 = 256
	var var7Decoded TdlInt16
	var7Encoded := []byte{0x01, 00}
	b = make([]byte, 2)
	var7.Encode(b)
	var7Decoded.Decode(b)
	compareBytes(t, b, var7Encoded, "")
	assertEquals(t, var7, var7Decoded, "")
	assertEquals(t, var7.GetLength(), 2, "")

	var var8 TdlInt16 = -2500
	var var8Decoded TdlInt16
	var8Encoded := []byte{0xf6, 0x3c}
	var8.Encode(b)
	var8Decoded.Decode(b)
	compareBytes(t, b, var8Encoded, "")
	assertEquals(t, var8, var8Decoded, "")

	// TdlInt32
	var var9 TdlInt32 = math.MaxInt32
	var var9Decoded TdlInt32
	var9Encoded := []byte{0x7F, 0xFF, 0xFF, 0xFF}
	b = make([]byte, 4)
	var9.Encode(b)
	var9Decoded.Decode(b)
	compareBytes(t, b, var9Encoded, "")
	assertEquals(t, var9, var9Decoded, "")
	assertEquals(t, var9.GetLength(), 4, "")

	var var10 TdlInt32 = -2
	var var10Decoded TdlInt32
	var10Encoded := []byte{0xFF, 0xFF, 0xFF, 0xFE}
	var10.Encode(b)
	var10Decoded.Decode(b)
	compareBytes(t, b, var10Encoded, "")
	assertEquals(t, var10, var10Decoded, "")

	// TdlInt64
	var var11 TdlInt64 = math.MaxInt64 - 0xFF
	var var11Decoded TdlInt64
	var11Encoded := []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}
	b = make([]byte, 8)
	var11.Encode(b)
	var11Decoded.Decode(b)
	compareBytes(t, b, var11Encoded, "")
	assertEquals(t, var11, var11Decoded, "")
	assertEquals(t, var11.GetLength(), 8, "")

	var var12 TdlInt64 = -1
	var var12Decoded TdlInt64
	var12Encoded := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	var12.Encode(b)
	var12Decoded.Decode(b)
	compareBytes(t, b, var12Encoded, "")
	assertEquals(t, var12, var12Decoded, "")

	// TdlFloat
	var var13 TdlFloat = math.Pi
	var var13Decoded TdlFloat
	b = make([]byte, 4)
	var13.Encode(b)
	var13Decoded.Decode(b)
	assertEquals(t, var13, var13Decoded, "")
	assertEquals(t, var13.GetLength(), 4, "")

	// TdlDouble
	var var14 TdlDouble = math.E
	var var14Decoded TdlDouble
	b = make([]byte, 8)
	var14.Encode(b)
	var14Decoded.Decode(b)
	assertEquals(t, var14, var14Decoded, "")
	assertEquals(t, var14.GetLength(), 8, "")
}

// TestCounter64Type tests the encoding, decoding, get length of TdlCounter64.
func TestCounter64Type(t *testing.T) {
	var1 := TdlCounter64{Counter: -1, Residual: 3}
	var var1Decoded TdlCounter64
	var1Encoded := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}
	b := make([]byte, 16)
	var1.Encode(b)
	var1Decoded.Decode(b)
	compareBytes(t, b, var1Encoded, "")
	assertEquals(t, var1, var1Decoded, "")
	assertEquals(t, var1.GetLength(), 16, "")

	var1 = TdlCounter64{Counter: 8, Residual: 3}
	var1Encoded = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}
	var1.Encode(b)
	var1Decoded.Decode(b)
	compareBytes(t, b, var1Encoded, "")
	assertEquals(t, var1, var1Decoded, "")
}

// TestEnum tests the encoding, decoding, get length of TdlEnum.
func TestEnum(t *testing.T) {

	meta := TdlEnumDef{
		Entries: []TdlEnumEntry{
			TdlEnumEntry{Name: "NORTH", Value: 1},
			TdlEnumEntry{Name: "SOUTH", Value: 3},
			TdlEnumEntry{Name: "EAST", Value: 5},
			TdlEnumEntry{Name: "WEST", Value: 7},
		},
	}
	err := meta.processEnumDef()
	if err != nil {
		t.Fatal("Failed processing EnumDef!")
	}

	enum := TdlEnumInstance{
		Variant: 0,
		meta:    &meta,
		val:     TdlEnumEntry{Name: "NORTH", Value: 1}}

	var enumDecoded TdlEnumInstance
	enumDecoded.meta = &meta // meta should bet set
	enumEncoded := []byte{0, 0, 0, 0, 1}
	b := make([]byte, 5)
	enum.Encode(b)
	enumDecoded.Decode(b)
	compareBytes(t, b, enumEncoded, "")
	assertEquals(t, enumDecoded.val.Value, enum.val.Value, "")
	assertEquals(t, enumDecoded.val.Name, enum.val.Name, "")
	assertEquals(t, enumDecoded.Variant, enum.Variant, "")

	enum.val = TdlEnumEntry{Name: "WEST", Value: 7}
	enum.Variant = 0xFF
	enumEncoded = []byte{0xFF, 0, 0, 0, 7}
	enum.Encode(b)
	enumDecoded.Decode(b)
	compareBytes(t, b, enumEncoded, "")
	assertEquals(t, enumDecoded.val.Value, enum.val.Value, "")
	assertEquals(t, enumDecoded.val.Name, enum.val.Name, "")
	assertEquals(t, enumDecoded.Variant, enum.Variant, "")
}

// TestFlag tests the encoding, decoding, get length of TdlFlag
func TestFlag(t *testing.T) {

	meta := TdlFlagDef{
		Entries: []string{
			"ECHO_REPLY", "UNASSIGNED_1", "UNASSIGNED_2", "DST_UNREACHABLE",
			"SRC_QUENCH", "REDIRECT", "ALTERNATE_HOST_ADDRESS", "UNASSIGNED_3",
			"ECHO_REQUEST", "ROUTER_ADVERTISEMENT", "ROUTER_SELECTION",
		},
	}

	err := meta.processFlagDef()
	if err != nil {
		t.Fatal("Failed processing FlagDef!")
	}

	flagInstance, _ := NewTdlFlagInstance(&meta)
	flag := flagInstance.(*TdlFlagInstance)

	assertEquals(t, false, flag.GetFlagSet("ECHO_REQUEST"), "")
	flag.SetFlag("ECHO_REQUEST")
	assertEquals(t, true, flag.GetFlagSet("ECHO_REQUEST"), "")
	flag.UnsetFlag("ECHO_REPLY")
	assertEquals(t, false, flag.GetFlagSet("ECHO_REPLY"), "")
	assertEquals(t, flag.GetLength(), 7, "") // 2 bytes needed for flag + 5 bytes for variant, jumpVariant
	flag.SetFlag("REDIRECT")

	flagEncoded := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01} // bits 5, 8 are set ("REDIRECT", "ECHO_REQUEST") - flags are set left to right
	b := make([]byte, flag.GetLength())
	flag.Encode(b)
	compareBytes(t, b, flagEncoded, "")

	flagDecodedInstance, _ := NewTdlFlagInstance(&meta)
	flagDecoded := flagDecodedInstance.(*TdlFlagInstance)
	flagDecoded.Decode(b)
	assertEquals(t, flagDecoded.GetFlagSet("ECHO_REQUEST"), true, "")
	assertEquals(t, flagDecoded.GetFlagSet("REDIRECT"), true, "")
	assertEquals(t, flagDecoded.GetFlagSet("DST_UNREACHABLE"), false, "")
	compareBytes(t, flag.bitArray, flagDecoded.bitArray, "")

	// check independence
	flagDecoded.SetFlag("ROUTER_SELECTION")
	assertEquals(t, flagDecoded.GetFlagSet("ROUTER_SELECTION"), true, "")
	assertEquals(t, flag.GetFlagSet("ROUTER_SELECTION"), false, "")
}

// TestTypeDef tests the encoding, decoding, get length of TdlTypeDef.
func TestTypeDef(t *testing.T) {
	// Primitive Types only
	var myUint TdlUint8 = 3
	var myInt TdlInt8 = -1

	meta := TdlTypeDef{
		TypeDefEntries: []TdlTypeDefEntry{
			TdlTypeDefEntry{Name: "var0", Type: "uint8"},
			TdlTypeDefEntry{Name: "var1", Type: "int8"},
			TdlTypeDefEntry{Name: "var2", Type: "counter64"},
		},
	}

	myType := TdlTypeInstance{
		Variant:     0,
		Flags:       0,
		JumpVariant: 2,
		meta:        &meta,
	}

	myType.build()
	myType.entries[0] = &myUint
	myType.entries[1] = &myInt
	myType.entries[2] = &TdlCounter64{Counter: 2, Residual: 1}

	expectedLength := 6 + 1 + 1 + 16 // 6 is for variant, flags and jump_variant, the rest is the other types.
	assertEquals(t, expectedLength, myType.GetLength(), "")

	myTypeEncoded := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	b := make([]byte, myType.GetLength())
	myType.Encode(b)
	compareBytes(t, b, myTypeEncoded, "")

	var myTypeDecoded TdlTypeInstance
	myTypeDecoded.meta = &meta
	myTypeDecoded.build()
	myTypeDecoded.Decode(b)

	assertEquals(t, myTypeDecoded.JumpVariant, myType.JumpVariant, "")
	counterDecoded := myTypeDecoded.entries[2].(*TdlCounter64)
	origCounter := (myType.entries[2]).(*TdlCounter64)
	assertEquals(t, counterDecoded.Counter, origCounter.Counter, "")
	assertEquals(t, counterDecoded.Residual, origCounter.Residual, "")

	// ------------------------------

	myEnumMeta := TdlEnumDef{
		Entries: []TdlEnumEntry{
			TdlEnumEntry{Name: "NORTH", Value: 1},
			TdlEnumEntry{Name: "SOUTH", Value: 3},
			TdlEnumEntry{Name: "EAST", Value: 5},
			TdlEnumEntry{Name: "WEST", Value: 7},
		},
	}

	err := myEnumMeta.processEnumDef()
	if err != nil {
		t.Fatal("Failed processing EnumDef!")
	}

	myEnumInstance, _ := NewTdlEnumInstance(&myEnumMeta)
	myEnum := myEnumInstance.(*TdlEnumInstance)
	myEnum.val.Value = 7
	myEnum.val.Name = "WEST"

	myEnumEncoded := make([]byte, myEnum.GetLength())
	myEnum.Encode(myEnumEncoded)

	myFlagMeta := TdlFlagDef{
		Entries: []string{
			"ECHO_REPLY", "UNASSIGNED_1", "UNASSIGNED_2", "DST_UNREACHABLE",
			"SRC_QUENCH", "REDIRECT", "ALTERNATE_HOST_ADDRESS", "UNASSIGNED_3",
			"ECHO_REQUEST", "ROUTER_ADVERTISEMENT", "ROUTER_SELECTION",
		},
	}

	err = myFlagMeta.processFlagDef()
	if err != nil {
		t.Fatal("Failed processing FlagDef!")
	}

	myFlagInstance, _ := NewTdlFlagInstance(&myFlagMeta)
	myFlag := myFlagInstance.(*TdlFlagInstance)

	myFlagEncoded := make([]byte, myFlag.GetLength())
	myFlag.Encode(myFlagEncoded)

	var metaMgr TdlMetaDataMgr
	metaMgr.metaMap = make(map[string]TdlMetaDataIF, 2)
	metaMgr.metaMap["myEnum"] = &myEnumMeta
	metaMgr.metaMap["myFlag"] = &myFlagMeta

	meta = TdlTypeDef{
		TypeDefEntries: []TdlTypeDefEntry{
			TdlTypeDefEntry{Name: "var0", Type: "uint8"},
			TdlTypeDefEntry{Name: "var1", Type: "int8"},
			TdlTypeDefEntry{Name: "var2", Type: "counter64"},
			TdlTypeDefEntry{Name: "var3", Type: "myEnum"},
			TdlTypeDefEntry{Name: "var4", Type: "myFlag"},
		},
	}
	meta.metaMgr = &metaMgr

	myType = TdlTypeInstance{
		Variant:     0,
		Flags:       0,
		JumpVariant: 2,
		meta:        &meta,
	}

	myType.build()
	b = make([]byte, 1)
	myType.entries[0].Encode(b)
	compareBytes(t, b, []byte{0}, "") // new instance
	b = make([]byte, len(myFlagEncoded))
	myType.entries[4].Encode(b)
	compareBytes(t, b, make([]byte, len(myFlagEncoded)), "") // new instance

	entry0 := myType.entries[0].(*TdlUint8)
	*entry0 = myUint
	entry1 := myType.entries[1].(*TdlInt8)
	*entry1 = myInt
	entry2 := myType.entries[2].(*TdlCounter64)
	*entry2 = TdlCounter64{Counter: 2, Residual: 1}
	entry3 := myType.entries[3].(*TdlEnumInstance)
	entry3.val.Value = 7
	entry3.val.Name = "WEST"
	entry4 := myType.entries[4].(*TdlFlagInstance)
	entry4.bitArray = myFlag.bitArray

	expectedLength = 6 + 1 + 1 + 5 + 16 + 7 // 6 is for variant, flags and jump_variant, the rest is the other types.
	assertEquals(t, expectedLength, myType.GetLength(), "")

	myTypeEncoded = append(myTypeEncoded, myEnumEncoded...)
	myTypeEncoded = append(myTypeEncoded, myFlagEncoded...)

	b = make([]byte, myType.GetLength())
	myType.Encode(b)
	compareBytes(t, b, myTypeEncoded, "")

	myTypeDecoded.meta = &meta
	myTypeDecoded.entries = myTypeDecoded.entries[:0] // clean older entries
	myTypeDecoded.build()
	myTypeDecoded.Decode(b)

	assertEquals(t, myTypeDecoded.JumpVariant, myType.JumpVariant, "")
	enumDecoded := myTypeDecoded.entries[3].(*TdlEnumInstance)
	origEnum := (myType.entries[3]).(*TdlEnumInstance)
	assertEquals(t, enumDecoded.Variant, origEnum.Variant, "")
}

// TestTypeDefGolden tests the encoding, decoding, get length of TdlTypeDef.
func TestTypeDefGolden(t *testing.T) {

	// Primitive Types only
	meta := TdlTypeDef{
		TypeDefEntries: []TdlTypeDefEntry{
			TdlTypeDefEntry{Name: "flapCount", Type: "uint32"},
			TdlTypeDefEntry{Name: "totalRxBytes", Type: "uint64"},
			TdlTypeDefEntry{Name: "totalTxBytes", Type: "uint64"},
			TdlTypeDefEntry{Name: "totalRxPkts", Type: "uint64"},
			TdlTypeDefEntry{Name: "totalTxPkts", Type: "uint64"},
			TdlTypeDefEntry{Name: "totalClients", Type: "uint32"},
			TdlTypeDefEntry{Name: "upTime", Type: "uint32"},
			TdlTypeDefEntry{Name: "keepAliveTx", Type: "uint64"},
			TdlTypeDefEntry{Name: "keepAliveRx", Type: "uint64"},
			TdlTypeDefEntry{Name: "keepAliveWindows", Type: "uint32"},
			TdlTypeDefEntry{Name: "keepAliveDropped", Type: "uint32"},
			TdlTypeDefEntry{Name: "totalKeepAliveTx", Type: "uint64"},
			TdlTypeDefEntry{Name: "totalKeepAliveRx", Type: "uint64"},
		},
	}

	tunnelStats := TdlTypeInstance{
		Variant:     0,
		Flags:       0,
		JumpVariant: 2,
		meta:        &meta,
	}

	// no need to set tdl client or meta mgr as it has only primitive types
	tunnelStats.build()

	var flapCount TdlUint32 = 1
	var totalRxBytes TdlUint64 = 20149920
	var totalTxBytes TdlUint64 = 976521
	var totalRxPkts TdlUint64 = 12345
	var totalTxPkts TdlUint64 = 5678
	var totalClients TdlUint32 = 100
	var upTime TdlUint32 = 2128515
	var keepAliveTx TdlUint64 = 1401590159015
	var keepAliveRx TdlUint64 = 1204158051
	var keepAliveWindows TdlUint32 = 2
	var keepAliveDropped TdlUint32 = 0
	var totalKeepAliveTx TdlUint64 = 20104510515
	var totalKeepAliveRx TdlUint64 = 1215895915

	entry0 := tunnelStats.entries[0].(*TdlUint32)
	*entry0 = flapCount
	entry1 := tunnelStats.entries[1].(*TdlUint64)
	*entry1 = totalRxBytes
	entry2 := tunnelStats.entries[2].(*TdlUint64)
	*entry2 = totalTxBytes
	entry3 := tunnelStats.entries[3].(*TdlUint64)
	*entry3 = totalRxPkts
	entry4 := tunnelStats.entries[4].(*TdlUint64)
	*entry4 = totalTxPkts
	entry5 := tunnelStats.entries[5].(*TdlUint32)
	*entry5 = totalClients
	entry6 := tunnelStats.entries[6].(*TdlUint32)
	*entry6 = upTime
	entry7 := tunnelStats.entries[7].(*TdlUint64)
	*entry7 = keepAliveTx
	entry8 := tunnelStats.entries[8].(*TdlUint64)
	*entry8 = keepAliveRx
	entry9 := tunnelStats.entries[9].(*TdlUint32)
	*entry9 = keepAliveWindows
	entry10 := tunnelStats.entries[10].(*TdlUint32)
	*entry10 = keepAliveDropped
	entry11 := tunnelStats.entries[11].(*TdlUint64)
	*entry11 = totalKeepAliveTx
	entry12 := tunnelStats.entries[12].(*TdlUint64)
	*entry12 = totalKeepAliveRx

	tunnelStatsEncoded := []byte{0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 1, 51,
		118, 160, 0, 0, 0, 0, 0, 14, 230, 137, 0, 0, 0, 0, 0, 0,
		48, 57, 0, 0, 0, 0, 0, 0, 22, 46, 0, 0, 0, 100, 0, 32,
		122, 131, 0, 0, 1, 70, 85, 72, 150, 167, 0, 0, 0, 0, 71, 197,
		254, 99, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 174,
		82, 124, 51, 0, 0, 0, 0, 72, 121, 25, 107}

	b := make([]byte, tunnelStats.GetLength())
	tunnelStats.Encode(b)
	compareBytes(t, tunnelStatsEncoded, b, "")

	// Second example ---------------------------------
	layerFlagMeta := TdlEnumDef{
		Entries: []TdlEnumEntry{
			TdlEnumEntry{Name: "ACTIVE_LAYER", Value: 0},
			TdlEnumEntry{Name: "DELETE_LAYER", Value: 1},
		},
	}
	err := layerFlagMeta.processEnumDef()
	if err != nil {
		t.Fatal("Failed processing EnumDef!")
	}

	layerFlag := TdlEnumInstance{
		Variant: 0,
		meta:    &layerFlagMeta,
		val:     TdlEnumEntry{Name: "DELETE_LAYER", Value: 1},
	}

	var layerIdx TdlUint8 = 5
	var subLayerIdx TdlUint8 = 128

	layerKeyMeta := TdlTypeDef{
		TypeDefEntries: []TdlTypeDefEntry{
			TdlTypeDefEntry{Name: "layer_flag", Type: "layer_flag"},
			TdlTypeDefEntry{Name: "layer_idx", Type: "uint8"},
			TdlTypeDefEntry{Name: "sub_layer_idx", Type: "uint8"},
		},
	}

	layerKey := TdlTypeInstance{
		Variant:     0,
		Flags:       0,
		JumpVariant: 0,
		meta:        &layerKeyMeta,
	}

	var metaMgr TdlMetaDataMgr
	metaMgr.metaMap = make(map[string]TdlMetaDataIF, 1)
	metaMgr.metaMap["layer_flag"] = &layerFlagMeta

	layerKeyMeta.metaMgr = &metaMgr
	layerKey.build()

	entryNo0 := layerKey.entries[0].(*TdlEnumInstance)
	*entryNo0 = layerFlag
	entryNo1 := layerKey.entries[1].(*TdlUint8)
	*entryNo1 = layerIdx
	entryNo2 := layerKey.entries[2].(*TdlUint8)
	*entryNo2 = subLayerIdx

	b = make([]byte, layerKey.GetLength())
	layerKey.Encode(b)

	layerFlagEncoded := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 128}

	compareBytes(t, layerFlagEncoded, b, "")
}
