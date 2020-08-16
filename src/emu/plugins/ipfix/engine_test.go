package ipfix

import (
	"bytes"
	"emu/core"
	"encoding/binary"
	"math"
	"math/rand"
	"testing"

	"github.com/intel-go/fastjson"
)

// validateGenereatedUint8
func validateGeneratedUint8(b []byte, expected []uint8, eng FieldEngineIF, t *testing.T) {
	var value uint8
	for i := 0; i < len(expected); i++ {
		eng.Update(b[eng.GetOffset():])
		value = uint8(b[eng.GetOffset()])
		if value != expected[i] {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, expected[i], value)
		}
	}

}

// validateGeneratedUint16
func validateGeneratedUint16(b []byte, expected []uint16, eng FieldEngineIF, t *testing.T) {
	var value uint16
	for i := 0; i < len(expected); i++ {
		eng.Update(b[eng.GetOffset():])
		value = binary.BigEndian.Uint16(b[eng.GetOffset():])
		if value != expected[i] {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, expected[i], value)
		}
	}
}

// validateGeneratedUint32
func validateGeneratedUint32(b []byte, expected []uint32, eng FieldEngineIF, t *testing.T) {
	var value uint32
	for i := 0; i < len(expected); i++ {
		eng.Update(b[eng.GetOffset():])
		value = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if value != expected[i] {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, expected[i], value)
		}
	}
}

// validateGeneratedUint64
func validateGeneratedUint64(b []byte, expected []uint64, eng FieldEngineIF, t *testing.T) {
	var value uint64
	for i := 0; i < len(expected); i++ {
		eng.Update(b[eng.GetOffset():])
		value = binary.BigEndian.Uint64(b[eng.GetOffset():])
		if value != expected[i] {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, expected[i], value)
		}
	}
}

// createEngineManager
func createEngineManager(t *testing.T) *FieldEngineManager {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()
	param := fastjson.RawMessage([]byte(`[]`))
	feMgr := NewEngineManager(tctx, &param)
	if feMgr.counters.invalidJson != 0 || feMgr.counters.failedBuildingEngine != 0 {
		t.Errorf("Error while generating engine manager.\n")
		t.FailNow()
	}
	return feMgr
}

// TestUIntEngineBasic
func TestUIntEngineBasic(t *testing.T) {

	feMgr := createEngineManager(t)

	b := make([]byte, 10)
	params := UIntEngineParams{
		Offset:   2,
		Size:     8,
		Op:       "inc",
		Step:     2,
		MinValue: 50,
		MaxValue: 60,
	}
	eng, err := NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
	}
	offset := eng.GetOffset()
	if offset != params.Offset {
		t.Errorf("GetOffset was incorrect, have %v, want %v.\n", offset, params.Offset)
	}
	size := eng.GetSize()
	if size != params.Size {
		t.Errorf("GetSize was incorrect, have %v, want %v.\n", size, params.Size)
	}
	eng.Update(b[offset:])
	value := binary.BigEndian.Uint64(b[offset:])
	if value != params.MinValue {
		t.Errorf("First Update was incorrect, have %v, want %v.\n", value, params.MinValue)
	}
	eng.Update(b[offset:])
	value = binary.BigEndian.Uint64(b[offset:])
	if value != params.MinValue+params.Step {
		t.Errorf("Second Update was incorrect, have %v, want %v.\n", value, params.MinValue+params.Step)
	}
}

// TestUIntEngineNegative
func TestUIntEngineNegative(t *testing.T) {

	feMgr := createEngineManager(t)

	params := UIntEngineParams{
		Offset:   2,
		Size:     1,
		Op:       "inc",
		Step:     2,
		MinValue: 50,
		MaxValue: 260,
	}
	exp := "Max value 260 cannot be represented with size 1.\n"
	_, err := NewUIntEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 1 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 1)
	}
	params = UIntEngineParams{
		Offset:   2,
		Size:     4,
		Op:       "inc",
		Step:     2,
		MinValue: 50,
		MaxValue: 40,
	}
	exp = "Min value 50 is bigger than max value 40.\n"
	_, err = NewUIntEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.maxSmallerThanMin != 1 {
		t.Errorf("maxSmallerThanMin counter incorrect, have %v, want %v.\n", feMgr.counters.maxSmallerThanMin, 1)
	}
	params = UIntEngineParams{
		Offset:   2,
		Size:     4,
		Op:       "aa",
		Step:     2,
		MinValue: 50,
		MaxValue: 55,
	}
	exp = "Unsupported operation aa.\n"
	_, err = NewUIntEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.badOperation != 1 {
		t.Errorf("badOperation counter incorrect, have %v, want %v.\n", feMgr.counters.badOperation, 1)
	}
	params = UIntEngineParams{
		Offset:   2,
		Size:     3,
		Op:       "dec",
		Step:     2,
		MinValue: 50,
		MaxValue: 55,
	}
	exp = "Invalid size 3. Size should be {1, 2, 4, 8}.\n"
	_, err = NewUIntEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.invalidSize != 1 {
		t.Errorf("invalidSize counter incorrect, have %v, want %v.\n", feMgr.counters.invalidSize, 1)
	}
	params = UIntEngineParams{
		Offset:    2,
		Size:      4,
		Op:        "dec",
		Step:      2,
		MinValue:  3,
		MaxValue:  55,
		InitValue: 1,
	}
	exp = "Init value 1 must be between [3 - 55].\n"
	_, err = NewUIntEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.badInitValue != 1 {
		t.Errorf("badInitValue counter incorrect, have %v, want %v.\n", feMgr.counters.badInitValue, 1)
	}
	params = UIntEngineParams{
		Offset:    2,
		Size:      2,
		Op:        "dec",
		Step:      2,
		MinValue:  65666,
		MaxValue:  65667,
		InitValue: 1,
	}
	exp = "Max value 65667 cannot be represented with size 2.\n"
	_, err = NewUIntEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 2 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 2)
	}
}

// TestUInt16EngineInc
func TestUInt16EngineInc(t *testing.T) {

	feMgr := createEngineManager(t)

	// simple increase with Step 5, restart takes 1 on wrap around
	params := UIntEngineParams{
		Offset:    0,
		Size:      2,
		Op:        "inc",
		Step:      5,
		MinValue:  50,
		MaxValue:  100,
		InitValue: 75,
	}
	eng, err := NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	// Restarting takes 1, so going from 100 to 50 consumes 1 and then 4 are left.
	expected := []uint16{75, 80, 85, 90, 95, 100, 54, 59, 64, 69, 74}
	b := make([]byte, 8)
	validateGeneratedUint16(b, expected, eng, t)

	// simple increment with Step 1
	params = UIntEngineParams{
		Offset:   2,
		Size:     2,
		Op:       "inc",
		Step:     1,
		MinValue: 5,
		MaxValue: 9,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{5, 6, 7, 8, 9, 5, 6}
	validateGeneratedUint16(b, expected, eng, t)

	// generate small domain with wrap around, validate restart takes 1
	params = UIntEngineParams{
		Offset:   4,
		Size:     2,
		Op:       "inc",
		Step:     2,
		MinValue: 3,
		MaxValue: 7,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{3, 5, 7, 4, 6, 3}
	validateGeneratedUint16(b, expected, eng, t)

	// generate with large Step no wrap around
	params = UIntEngineParams{
		Offset:    6,
		Size:      2,
		Op:        "inc",
		Step:      5000,
		MinValue:  0x0100,
		MaxValue:  0xffff,
		InitValue: 10000,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{10000, 15000, 20000, 25000, 30000, 35000, 40000}
	validateGeneratedUint16(b, expected, eng, t)

	// validate bytes slice in the end
	expectedBytes := []byte{0x00, 0x4a, 0x00, 0x06, 0x00, 0x03, 0x9c, 0x40} // [74, 6, 3, 40000]
	if !bytes.Equal(expectedBytes, b) {
		t.Errorf("Byte slice not as expected, have %v, want %v.\n", b, expectedBytes)
	}
}

// TestUInt16EngineDec
func TestUInt16EngineDec(t *testing.T) {

	feMgr := createEngineManager(t)

	// simple decrease with init value
	params := UIntEngineParams{
		Offset:    0,
		Size:      2,
		Op:        "dec",
		Step:      1,
		MinValue:  0,
		MaxValue:  5,
		InitValue: 3,
	}
	b := make([]byte, 8)
	var value uint16
	eng, err := NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.")
		t.FailNow()
	}
	expected := []uint16{3, 2, 1, 0, 5, 4}
	validateGeneratedUint16(b, expected, eng, t)

	// decrease of all the domain
	params = UIntEngineParams{
		Offset:    2,
		Size:      2,
		Op:        "dec",
		Step:      1,
		MinValue:  0,
		MaxValue:  0xffff,
		InitValue: 0xffff,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 0xffff; i++ {
		eng.Update(b[params.Offset:])
	}
	value = binary.BigEndian.Uint16(b[params.Offset:])
	if value != 1 {
		t.Errorf("Incorrect update,  want %v, have %v.\n", 1, value)
	}

	// decrease with wrap around
	params = UIntEngineParams{
		Offset:   4,
		Size:     2,
		Op:       "dec",
		Step:     2,
		MinValue: 0,
		MaxValue: 0xffff,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{0, 0xffff - 1, 0xffff - 3}
	validateGeneratedUint16(b, expected, eng, t)

	// decrease on minimal domain [3]
	params = UIntEngineParams{
		Offset:   6,
		Size:     2,
		Op:       "dec",
		Step:     2,
		MinValue: 3,
		MaxValue: 3,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{3, 3, 3}
	validateGeneratedUint16(b, expected, eng, t)

	// validate bytes slice in the end
	expectedBytes := []byte{0x00, 0x04, 0x00, 0x01, 0xff, 0xff - 3, 0x00, 0x03}
	if !bytes.Equal(expectedBytes, b) {
		t.Errorf("Byte slice not as expected, have %v, want %v.\n", b, expectedBytes)
	}
}

// TestUInt16EngineRand
func TestUInt16EngineRand(t *testing.T) {

	feMgr := createEngineManager(t)

	// random generation on a small domain, simple validation using Go's wonderful feature.
	params := UIntEngineParams{
		Offset:    0,
		Size:      2,
		Op:        "rand",
		MinValue:  0,
		MaxValue:  5,
		InitValue: 3,
	}
	b := make([]byte, 8)
	var value uint16
	eng, err := NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1000; i++ {
		eng.Update(b[params.Offset:])
		value = binary.BigEndian.Uint16(b[params.Offset:])
		if value < 0 || value > 5 {
			t.Errorf("Incorrect update, want in [%v-%v], have %v.\n", 0, 5, value)
		}
	}

	// Generate 1000 times and expect only 7.
	params = UIntEngineParams{
		Offset:   2,
		Size:     2,
		Op:       "rand",
		MinValue: 7,
		MaxValue: 7,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1000; i++ {
		eng.Update(b[params.Offset:])
		value = binary.BigEndian.Uint16(b[params.Offset:])
		if value != 7 {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, 7, value)
		}
	}

	iterNumber := 1 << 16
	// Generate in the domain of [1-2] iterNumber times and expect half half.
	params = UIntEngineParams{
		Offset:   4,
		Size:     2,
		Op:       "rand",
		MinValue: 1,
		MaxValue: 2,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	ones, twos := 0, 0
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[params.Offset:])
		value = binary.BigEndian.Uint16(b[params.Offset:])
		if value == 1 {
			ones++
		} else if value == 2 {
			twos++
		} else {
			t.Errorf("Generated value %v not in domain, [%v - %v].\n", value, params.MinValue, params.MaxValue)
		}
	}
	if ones+twos != iterNumber {
		t.Errorf("Expected %v generated numbers, generated only %v.\n", iterNumber, ones+twos)
		t.FailNow()
	}
	expectedGen := iterNumber >> 1
	expectedLowerBound := float64(expectedGen) * 0.99
	expectedHigherBound := float64(expectedGen) * 1.01
	if float64(ones) < expectedLowerBound || float64(ones) > expectedHigherBound {
		t.Errorf("Generated number of 1s incorrect, have %v, expected [%v - %v].\n", ones, expectedLowerBound, expectedHigherBound)
	}

	// Same idea as before, bigger domain
	params = UIntEngineParams{
		Offset:   6,
		Size:     2,
		Op:       "rand",
		MinValue: 0,
		MaxValue: 7,
	}
	var generatedHistogram [8]int
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[params.Offset:])
		value = binary.BigEndian.Uint16(b[params.Offset:])
		generatedHistogram[value]++
	}
	expectedGen = iterNumber >> 3
	// increase the allowed error since we are generating less of the same.
	expectedLowerBound = float64(expectedGen) * 0.90
	expectedHigherBound = float64(expectedGen) * 1.1
	for i := 0; i < len(generatedHistogram); i++ {
		if float64(generatedHistogram[i]) < expectedLowerBound || float64(generatedHistogram[i]) > expectedHigherBound {
			t.Errorf("Generated number of %vs incorrect, have %v, expected [%v - %v].\n", i, generatedHistogram[i], expectedLowerBound, expectedHigherBound)
		}
	}
}

// TestUInt32EngineInc
func TestUInt32Engine(t *testing.T) {

	feMgr := createEngineManager(t)

	// simple increase for uint32
	params := UIntEngineParams{
		Offset:   0,
		Size:     4,
		Op:       "inc",
		MinValue: 0xffff,
		MaxValue: 0xffff + 10,
		Step:     2,
	}
	b := make([]byte, 16)
	eng, err := NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected := []uint32{0xffff, 0xffff + 2, 0xffff + 4, 0xffff + 6, 0xffff + 8, 0xffff + 10, 0xffff + 1, 0xffff + 3}
	validateGeneratedUint32(b, expected, eng, t)

	// decrease with wrap around
	params = UIntEngineParams{
		Offset:    4,
		Size:      4,
		Op:        "dec",
		MinValue:  100,
		MaxValue:  0xffffffff,
		Step:      1,
		InitValue: 101,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected = []uint32{101, 100, 0xffffffff, 0xffffffff - 1}
	validateGeneratedUint32(b, expected, eng, t)

	// random on a domain of uint32
	params = UIntEngineParams{
		Offset:   8,
		Size:     4,
		Op:       "rand",
		MinValue: 1 << 16,
		MaxValue: 1<<16 + 31,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	var value uint32
	zeroOffset := uint32(params.MinValue)
	iterNumber := 1 << 20
	var generatedHistogram [32]int
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		value = binary.BigEndian.Uint32(b[eng.GetOffset():])
		generatedHistogram[value-zeroOffset]++
	}
	expectedGen := iterNumber >> 5
	expectedLowerBound := float64(expectedGen) * 0.95
	expectedHigherBound := float64(expectedGen) * 1.05
	for i := 0; i < len(generatedHistogram); i++ {
		if float64(generatedHistogram[i]) < expectedLowerBound || float64(generatedHistogram[i]) > expectedHigherBound {
			t.Errorf("Generated number of %vs incorrect, have %v, expected [%v - %v].\n", i, generatedHistogram[i], expectedLowerBound, expectedHigherBound)
		}
	}

	// complicated test, non uniform updates.
	params = UIntEngineParams{
		Offset:   12,
		Size:     4,
		Op:       "inc",
		MinValue: 0xffff,
		MaxValue: 0xffffffff,
		Step:     1 << 16,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	var expValue uint32
	var genValue uint32
	eng.Update(b[eng.GetOffset():])
	for i := 17; i <= 33; i++ {
		expValue = uint32(1<<i) - 1
		if i == 33 {
			expValue = 1<<17 - 2
		}
		for j := 0; j < 1<<((i-17)%16); j++ {
			eng.Update(b[eng.GetOffset():])
		}
		genValue = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if genValue != expValue {
			t.Errorf("Failed on iteration %v, want %v, have %v.\n", i-16, expValue, genValue)
		}
	}
}

// TestUInt64Engine
func TestUInt64Engine(t *testing.T) {

	feMgr := createEngineManager(t)

	// simple rand test for uint64
	params := UIntEngineParams{
		Offset:   0,
		Size:     8,
		Op:       "rand",
		MinValue: 0,
		MaxValue: 15,
	}
	b := make([]byte, 24)
	eng, err := NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	var value uint64
	iterNumber := 1 << 16
	var generatedHistogram [16]int
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		value = binary.BigEndian.Uint64(b[eng.GetOffset():])
		generatedHistogram[value]++
	}
	expectedGen := iterNumber >> 4
	expectedLowerBound := float64(expectedGen) * 0.90
	expectedHigherBound := float64(expectedGen) * 1.1
	for i := 0; i < len(generatedHistogram); i++ {
		if float64(generatedHistogram[i]) < expectedLowerBound || float64(generatedHistogram[i]) > expectedHigherBound {
			t.Errorf("Generated number of %vs incorrect, have %v, expected [%v - %v].\n", i, generatedHistogram[i], expectedLowerBound, expectedHigherBound)
		}
	}

	// increase to cause overflow with Step
	params = UIntEngineParams{
		Offset:    8,
		Size:      8,
		Op:        "inc",
		MinValue:  0,
		MaxValue:  math.MaxUint64,
		InitValue: math.MaxUint64 - 2,
		Step:      2,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected := []uint64{math.MaxUint64 - 2, math.MaxUint64, 1, 3, 5, 7}
	validateGeneratedUint64(b, expected, eng, t)

	// decrease to cause overflow
	params = UIntEngineParams{
		Offset:    16,
		Size:      8,
		Op:        "dec",
		MinValue:  0,
		MaxValue:  math.MaxUint64,
		InitValue: 1,
		Step:      1,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected = []uint64{1, 0, math.MaxUint64, math.MaxUint64 - 1}
	validateGeneratedUint64(b, expected, eng, t)
}

// TestUInt8Engine
func TestUInt8Engine(t *testing.T) {

	feMgr := createEngineManager(t)

	// complete domain increment with wrap around
	params := UIntEngineParams{
		Offset:   0,
		Size:     1,
		Op:       "inc",
		MinValue: 0,
		MaxValue: 0xff,
		Step:     1,
	}
	b := make([]byte, 8)
	eng, err := NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	var expected []uint8
	for i := 0; i <= 256; i++ {
		expected = append(expected, uint8(i%256))
	}
	// expected = [0, 1, 2, 3, ... 255, 0]
	validateGeneratedUint8(b, expected, eng, t)

	// decrement with wrap around
	params = UIntEngineParams{
		Offset:    1,
		Size:      1,
		Op:        "dec",
		MinValue:  0,
		MaxValue:  0xff,
		Step:      1,
		InitValue: 5,
	}
	expected = []uint8{5, 4, 3, 2, 1, 0, 255, 254, 253, 252, 251, 250}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	validateGeneratedUint8(b, expected, eng, t)

	// increment with Step
	params = UIntEngineParams{
		Offset:   2,
		Size:     1,
		Op:       "inc",
		MinValue: 0,
		MaxValue: 0xff,
		Step:     5,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected = expected[:0]
	for i := 0; i <= 500; i += 5 {
		expected = append(expected, uint8(i%256))
	}
	// expected = [0, 5, 10, ..., 255, 4, 9 ..., 244 ]
	validateGeneratedUint8(b, expected, eng, t)

	// decrement with Step and wrap around
	params = UIntEngineParams{
		Offset:    3,
		Size:      1,
		Op:        "dec",
		MinValue:  0,
		MaxValue:  0xff,
		Step:      5,
		InitValue: 0xff,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected = expected[:0]
	for i := 0xff; i >= 0; i -= 5 {
		expected = append(expected, uint8(i))
	}
	expected = append(expected, 251)
	// expected = [255, 250, 245, ..., 0, 251]
	validateGeneratedUint8(b, expected, eng, t)

	// validate bytes slice in the end
	expectedBytes := []byte{0x00, 0xfa, 0xf4, 0xfb}
	if !bytes.Equal(expectedBytes, b[0:4]) {
		t.Errorf("Byte slice not as expected, have %v, want %v.\n", b[0:4], expectedBytes)
	}

	// rand 0xff
	params = UIntEngineParams{
		Offset:   4,
		Size:     1,
		Op:       "rand",
		MinValue: 0xff,
		MaxValue: 0xff,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	var value uint8
	for i := 0; i < 0xff; i++ {
		eng.Update(b[eng.GetOffset():])
		value = uint8(b[eng.GetOffset()])
		if value != 0xff {
			t.Errorf("Error generating random value, have %v, want %v.\n", value, 0xff)
		}
	}

	// random on all the domain
	params = UIntEngineParams{
		Offset:   5,
		Size:     1,
		Op:       "rand",
		MinValue: 0x0,
		MaxValue: 0xff,
	}
	eng, err = NewUIntEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	iterNumber := 1 << 20
	var generatedHistogram [256]int
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[params.Offset:])
		value = uint8(b[eng.GetOffset()])
		generatedHistogram[value]++
	}
	expectedGen := iterNumber >> 8
	// increase the allowed error since we are generating less of the same.
	expectedLowerBound := float64(expectedGen) * 0.90
	expectedHigherBound := float64(expectedGen) * 1.1
	for i := 0; i < len(generatedHistogram); i++ {
		if float64(generatedHistogram[i]) < expectedLowerBound || float64(generatedHistogram[i]) > expectedHigherBound {
			t.Errorf("Generated number of %vs incorrect, have %v, expected [%v - %v].\n", i, generatedHistogram[i], expectedLowerBound, expectedHigherBound)
		}
	}
}

// TestHistogramUInt32Engine
func TestHistogramUInt32Engine(t *testing.T) {

	feMgr := createEngineManager(t)

	// simple binary non uniform
	entries := []HistogramEntry{&HistogramUInt32Entry{V: 1, Prob: 1}, &HistogramUInt32Entry{V: 10, Prob: 3}}
	params := HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 0,
			Size:   4,
		},
		entries,
	}
	b := make([]byte, 16)
	var v uint32
	generated := make([]int, len(entries))
	iterNumber := 1 << 20
	eng, err := NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if v == 1 {
			generated[0]++
		} else if v == 10 {
			generated[1]++
		} else {
			t.Errorf("Generated number not in range of any entry %v.\n", v)
		}
	}
	verifyBinGenerator(iterNumber>>2, generated[0], 2, t)

	// complete randomization, check that it wont crash
	numEntries := 1000
	entries = entries[:0]
	for i := 0; i < numEntries; i++ {
		entry := HistogramUInt32Entry{V: rand.Uint32(), Prob: uint32(rand.Intn(1 << 10))}
		entries = append(entries, &entry)
	}
	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 4,
			Size:   4,
		},
		entries,
	}
	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1<<10; i++ {
		eng.Update(b[eng.GetOffset():])
	}

	// 4 uniform entries
	entries = []HistogramEntry{&HistogramUInt32Entry{V: 0, Prob: 2}, &HistogramUInt32Entry{V: 1, Prob: 2}, &HistogramUInt32Entry{V: 2, Prob: 2}, &HistogramUInt32Entry{V: 3, Prob: 2}}
	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 8,
			Size:   4,
		},
		entries,
	}
	generated = make([]int, len(entries))
	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v = binary.BigEndian.Uint32(b[eng.GetOffset():])
		generated[v]++
	}
	verifyBinGenerator(iterNumber>>2, generated[0], 2, t)
	verifyBinGenerator(iterNumber>>2, generated[1], 2, t)
	verifyBinGenerator(iterNumber>>2, generated[2], 2, t)

	// 1 entry
	entries = []HistogramEntry{&HistogramUInt32Entry{V: 0, Prob: 1000}}
	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 12,
			Size:   4,
		},
		entries,
	}
	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1<<10; i++ {
		eng.Update(b[eng.GetOffset():])
		v = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if v != 0 {
			t.Errorf("Generated wrong value, want %v have %v.\n", 0, v)
		}
	}
}

// TestHistogramUInt32RangeEngine
func TestHistogramUInt32RangeEngine(t *testing.T) {

	feMgr := createEngineManager(t)

	// generate number between 0-100 with 0.5 prob and 101-200 with 0.5 prob
	entries := []HistogramEntry{&HistogramUInt32RangeEntry{Min: 0, Max: 100, Prob: 1}, &HistogramUInt32RangeEntry{Min: 101, Max: 200, Prob: 1}}
	params := HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 0,
			Size:   4,
		},
		entries,
	}
	b := make([]byte, 16)
	var v uint32
	generated := make([]int, len(entries))
	iterNumber := 1 << 20
	eng, err := NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		eng.Update(b)
		v = binary.BigEndian.Uint32(b)
		if v <= 100 && v >= 0 {
			generated[0]++
		} else if v >= 101 && v <= 200 {
			generated[1]++
		} else {
			t.Errorf("Generated number not in range of any entry %v.\n", v)
		}
	}
	verifyBinGenerator(1<<19, generated[0], 1, t)

	// generate number between 0-1000 with prob 0.5 and between 500-1500 with prob 0.5
	// this means that numbers 0-50 with prob 0.25, 50-100 with prob 0.5 and 100-150 with prob 0.25
	entries = []HistogramEntry{&HistogramUInt32RangeEntry{Min: 0, Max: 1000, Prob: 1}, &HistogramUInt32RangeEntry{Min: 500, Max: 1500, Prob: 1}}
	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 4,
			Size:   4,
		},
		entries,
	}
	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated = make([]int, 3)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if v < 500 && v >= 0 {
			generated[0]++
		} else if v >= 500 && v < 1000 {
			generated[1]++
		} else if v >= 1000 && v <= 1500 {
			generated[2]++
		} else {
			t.Errorf("Generated number not in range of any entry %v.\n", v)
		}
	}
	verifyBinGenerator(1<<18, generated[0], 1, t)
	verifyBinGenerator(1<<19, generated[1], 1, t)

	// generate with 3 ranges
	entries = []HistogramEntry{&HistogramUInt32RangeEntry{Min: 0, Max: 1000, Prob: 1}, &HistogramUInt32RangeEntry{Min: 2000, Max: 3000, Prob: 1},
		&HistogramUInt32RangeEntry{Min: 4000, Max: 5000, Prob: 1}}
	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 8,
			Size:   4,
		},
		entries,
	}
	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated = make([]int, len(entries))
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if v <= 1000 && v >= 0 {
			generated[0]++
		} else if v >= 2000 && v <= 3000 {
			generated[1]++
		} else if v >= 4000 && v <= 5000 {
			generated[2]++
		} else {
			t.Errorf("Generated number not in range of any entry %v.\n", v)
		}
	}
	verifyBinGenerator(iterNumber/3, generated[0], 1, t)
	verifyBinGenerator(iterNumber/3, generated[1], 1, t)

	// generate with different probabilites
	entries = []HistogramEntry{&HistogramUInt32RangeEntry{Min: 0, Max: 1000, Prob: 1}, &HistogramUInt32RangeEntry{Min: 2000, Max: 3000, Prob: 7}}
	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 12,
			Size:   4,
		},
		entries,
	}
	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated = make([]int, len(entries))
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if v <= 1000 && v >= 0 {
			generated[0]++
		} else if v >= 2000 && v <= 3000 {
			generated[1]++
		} else {
			t.Errorf("Generated number not in range of any entry %v.\n", v)
		}
	}
	verifyBinGenerator(iterNumber>>3, generated[0], 1, t)
}

// TestHistogramUInt32ListEngine
func TestHistogramUInt32ListEngine(t *testing.T) {

	feMgr := createEngineManager(t)

	// even digit vs odd digit uniform
	entries := []HistogramEntry{&HistogramUInt32ListEntry{List: []uint32{1, 3, 5, 7, 9}, Prob: 1}, &HistogramUInt32ListEntry{List: []uint32{0, 2, 4, 6, 8}, Prob: 1}}
	params := HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 0,
			Size:   4,
		},
		entries,
	}
	b := make([]byte, 8)
	var v uint32
	iterNumber := 1 << 20
	eng, err := NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	evens := 0
	for i := 0; i < iterNumber; i++ {
		eng.Update(b)
		v = binary.BigEndian.Uint32(b)
		if v >= 10 {
			t.Errorf("Generated number not in range of any entry %v.\n", v)
		} else {
			if v%2 == 0 {
				evens++
			}
		}
	}
	verifyBinGenerator(iterNumber>>1, evens, 1, t)

	// 1/4 evens and 3/4 odds
	entries = []HistogramEntry{&HistogramUInt32ListEntry{List: []uint32{1, 3, 5, 7, 9}, Prob: 3}, &HistogramUInt32ListEntry{List: []uint32{0, 2, 4, 6, 8}, Prob: 1}}
	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 4,
			Size:   4,
		},
		entries,
	}
	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	evens = 0
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if v >= 10 {
			t.Errorf("Generated number not in range of any entry %v.\n", v)
		} else {
			if v%2 == 0 {
				evens++
			}
		}
	}
	verifyBinGenerator(iterNumber>>2, evens, 1, t)
}

// TestUIntListEngineNegative
func TestUIntListEngineNegative(t *testing.T) {

	feMgr := createEngineManager(t)

	// size too small
	params := UIntListEngineParams{
		Offset: 2,
		Size:   1,
		Op:     "inc",
		Step:   2,
		List:   []uint64{5, 3, 260},
	}
	exp := "List value 260 cannot be represented with size 1.\n"
	_, err := NewUIntListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 1 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 1)
	}

	// invalid size
	params = UIntListEngineParams{
		Offset: 2,
		Size:   3,
		Op:     "inc",
		Step:   2,
		List:   []uint64{5, 3, 260},
	}
	exp = "Invalid size 3. Size should be {1, 2, 4, 8}.\n"
	_, err = NewUIntListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.invalidSize != 1 {
		t.Errorf("invalidSize counter incorrect, have %v, want %v.\n", feMgr.counters.invalidSize, 1)
	}

	// bad operation
	params = UIntListEngineParams{
		Offset: 2,
		Size:   2,
		Op:     "bes",
		Step:   2,
		List:   []uint64{5, 3, 260},
	}
	exp = "Unsupported operation bes.\n"
	_, err = NewUIntListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.badOperation != 1 {
		t.Errorf("badOperation counter incorrect, have %v, want %v.\n", feMgr.counters.badOperation, 1)
	}

	// bad init index
	params = UIntListEngineParams{
		Offset:    2,
		Size:      2,
		Op:        "rand",
		Step:      2,
		List:      []uint64{5, 3, 260},
		InitIndex: 4,
	}
	exp = "Init index 4 must be between [0 - 3].\n"
	_, err = NewUIntListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.badInitValue != 1 {
		t.Errorf("badInitValue counter incorrect, have %v, want %v.\n", feMgr.counters.badInitValue, 1)
	}

	// size too small
	params = UIntListEngineParams{
		Offset:    2,
		Size:      2,
		Op:        "rand",
		Step:      2,
		List:      []uint64{5, 0xFFFF + 1, 260},
		InitIndex: 4,
	}
	exp = "List value 65536 cannot be represented with size 2.\n"
	_, err = NewUIntListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 2 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 2)
	}

	// empty list
	params = UIntListEngineParams{
		Offset:    2,
		Size:      2,
		Op:        "rand",
		Step:      2,
		List:      []uint64{},
		InitIndex: 0,
	}
	exp = "Engine list can't be empty.\n"
	_, err = NewUIntListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.emptyList != 1 {
		t.Errorf("emptyList counter incorrect, have %v, want %v.\n", feMgr.counters.emptyList, 1)
	}
}

// TestUIntListEngine
func TestUIntListEngine(t *testing.T) {

	feMgr := createEngineManager(t)

	// simple increase
	params := UIntListEngineParams{
		Offset:    0,
		Size:      2,
		Op:        "inc",
		Step:      1,
		List:      []uint64{50, 60, 63},
		InitIndex: 1,
	}
	eng, err := NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected := []uint16{60, 63, 50, 60, 63, 50, 60}
	b := make([]byte, 20)
	validateGeneratedUint16(b, expected, eng, t)

	// increase with step
	params = UIntListEngineParams{
		Offset: 2,
		Size:   1,
		Op:     "inc",
		Step:   2,
		List:   []uint64{5, 9, 8, 7, 3},
	}
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	exp := []uint8{5, 8, 3, 9, 7, 5, 8, 3, 9, 7, 5}
	validateGeneratedUint8(b, exp, eng, t)

	// increase with step larger than domain, step = 7%4 = 3
	params = UIntListEngineParams{
		Offset: 3,
		Size:   1,
		Op:     "inc",
		Step:   7,
		List:   []uint64{5, 9, 4, 20},
	}
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	exp = []uint8{5, 20, 4, 9, 5, 20, 4, 9, 5, 20, 4}
	validateGeneratedUint8(b, exp, eng, t)

	// decrement with bigger size
	params = UIntListEngineParams{
		Offset:    4,
		Size:      2,
		Op:        "dec",
		Step:      1,
		List:      []uint64{5, 9, 4, 20, 40, 250, 1},
		InitIndex: 4,
	}
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{40, 20, 4, 9, 5, 1, 250, 40, 20, 4, 9, 5, 1}
	validateGeneratedUint16(b, expected, eng, t)

	// decrement with step
	params = UIntListEngineParams{
		Offset:    6,
		Size:      2,
		Op:        "dec",
		Step:      5,
		List:      []uint64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096},
		InitIndex: 3,
	}
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{8, 2048, 64, 2, 512, 16, 4096, 128, 4, 1024, 32, 1, 256, 8}
	validateGeneratedUint16(b, expected, eng, t)

	// decrement with step
	params = UIntListEngineParams{
		Offset:    8,
		Size:      8,
		Op:        "inc",
		Step:      1,
		List:      []uint64{0xFFFFFFFF + 1, 0x100000000, 0xFF, 0xFFFF, 0xFFFFF},
		InitIndex: 0,
	}
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	exp64 := []uint64{0xFFFFFFFF + 1, 0x100000000, 0xFF, 0xFFFF, 0xFFFFF, 0xFFFFFFFF + 1}
	validateGeneratedUint64(b, exp64, eng, t)

	// decrement with step
	params = UIntListEngineParams{
		Offset:    16,
		Size:      4,
		Op:        "dec",
		Step:      2,
		List:      []uint64{0xFFFFFFFF, 0xFFFF + 1, 0xFF, 0xFFFF, 0xFFFFF},
		InitIndex: 4,
	}
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	exp32 := []uint32{0xFFFFF, 0xFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF + 1, 0xFFFFF}
	validateGeneratedUint32(b, exp32, eng, t)

	// validate bytes slice in the end
	expectedBytes := []byte{0x00, 60, 5, 4, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0x0F, 0xFF, 0xFF}
	if !bytes.Equal(expectedBytes, b) {
		t.Errorf("Byte slice not as expected, have %v, want %v.\n", b, expectedBytes)
	}
}

//TestUIntListEngineRand
func TestUIntListEngineRand(t *testing.T) {
	feMgr := createEngineManager(t)

	params := UIntListEngineParams{
		Offset:    0,
		Size:      2,
		Op:        "rand",
		List:      []uint64{1, 1, 1},
		InitIndex: 2,
	}
	b := make([]byte, 8)
	var value uint16
	eng, err := NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1000; i++ {
		eng.Update(b[eng.GetOffset():])
		value = binary.BigEndian.Uint16(b[eng.GetOffset():])
		if value != 1 {
			t.Errorf("Incorrect update, want 1, have %v.\n", value)
		}
	}

	params = UIntListEngineParams{
		Offset:    2,
		Size:      4,
		Op:        "rand",
		List:      []uint64{1, 2, 3},
		InitIndex: 2,
	}
	var value32 uint32
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1000; i++ {
		eng.Update(b[eng.GetOffset():])
		value32 = binary.BigEndian.Uint32(b[eng.GetOffset():])
		if value32 != 1 && value32 != 2 && value32 != 3 {
			t.Errorf("Incorrect update, want {1, 2, 3}, have %v.\n", value)
		}
	}

	params = UIntListEngineParams{
		Offset: 6,
		Size:   2,
		Op:     "rand",
		List:   []uint64{20, 30, 25},
	}
	var twenties, thirties, twentyfives int
	eng, err = NewUIntListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 30000; i++ {
		eng.Update(b[eng.GetOffset():])
		value = binary.BigEndian.Uint16(b[eng.GetOffset():])
		switch value {
		case 20:
			twenties++
		case 30:
			thirties++
		case 25:
			twentyfives++
		default:
			t.Errorf("Incorrect update, want {20, 25, 30}, have %v.\n", value)
		}
	}
	if twenties < 9000 || twenties > 11000 {
		t.Errorf("Expected number of 20's not in domain [9000-11000], have %v\n", twenties)
	}
	if thirties < 9000 || thirties > 11000 {
		t.Errorf("Expected number of 30's not in domain [9000-11000], have %v\n", thirties)
	}
}

// validates the generated byte string is the same as the expected byte string.
func validateGeneratedString(b []byte, expected [][]byte, eng *StringListEngine, t *testing.T) {
	for i := 0; i < len(expected); i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		if !bytes.Equal(expected[i], b[eng.GetOffset():eng.GetOffset()+eng.GetSize()]) {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, expected[i], b[eng.GetOffset():eng.GetOffset()+eng.GetSize()])
		}
	}
}

// TestStringListNegative
func TestStringListNegative(t *testing.T) {

	feMgr := createEngineManager(t)

	// too long string
	params := StringListEngineParams{
		Offset:       0,
		Size:         10,
		Op:           "inc",
		Step:         2,
		List:         []string{"abc", "aaaaaaaaaaa", "bes"},
		InitIndex:    0,
		PaddingValue: 1,
	}
	exp := "String aaaaaaaaaaa cannot be represented with size 10.\n"
	_, err := NewStringListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 1 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 1)
	}

	// bad init value
	params = StringListEngineParams{
		Offset:       0,
		Size:         10,
		Op:           "inc",
		Step:         2,
		List:         []string{"abc", "בס", "bes"},
		InitIndex:    3,
		PaddingValue: 1,
	}
	exp = "Init index 3 must be between [0 - 3].\n"
	_, err = NewStringListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.badInitValue != 1 {
		t.Errorf("badInitValue counter incorrect, have %v, want %v.\n", feMgr.counters.badInitValue, 1)
	}

	// bad operation
	params = StringListEngineParams{
		Offset:    0,
		Size:      10,
		Op:        "a",
		Step:      2,
		List:      []string{"abc", "בס", "bes"},
		InitIndex: 1,
	}
	exp = "Unsupported operation a.\n"
	_, err = NewStringListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.badOperation != 1 {
		t.Errorf("badOperation counter incorrect, have %v, want %v.\n", feMgr.counters.badOperation, 1)
	}

	// too short
	params = StringListEngineParams{
		Offset:    0,
		Size:      3,
		Op:        "rand",
		Step:      2,
		List:      []string{"abc", "בס", "bes"},
		InitIndex: 1,
	}
	exp = "String בס cannot be represented with size 3.\n"
	_, err = NewStringListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 2 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 2)
	}

	// empty list
	params = StringListEngineParams{
		Offset:    0,
		Size:      3,
		Op:        "rand",
		Step:      2,
		List:      []string{},
		InitIndex: 1,
	}
	exp = "Engine list can't be empty.\n"
	_, err = NewStringListEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.emptyList != 1 {
		t.Errorf("emptyList counter incorrect, have %v, want %v.\n", feMgr.counters.emptyList, 1)
	}
}

// TestStringList
func TestStringList(t *testing.T) {

	feMgr := createEngineManager(t)
	b := make([]byte, 50)

	// simple increase
	params := StringListEngineParams{
		Offset:       0,
		Size:         4,
		Op:           "inc",
		Step:         1,
		List:         []string{"icmp", "tcp", "udp"},
		InitIndex:    1,
		PaddingValue: 0,
	}
	eng, err := NewStringListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	icmpBytes := []byte("icmp")
	tcpBytes := []byte("tcp")
	tcpBytes = append(tcpBytes, 0)
	udpBytes := []byte("udp")
	udpBytes = append(udpBytes, 0)
	expected := [][]byte{tcpBytes, udpBytes, icmpBytes, tcpBytes, udpBytes}
	validateGeneratedString(b, expected, eng, t)

	// emojis and stuff with padding and dec with step
	params = StringListEngineParams{
		Offset:       4,
		Size:         6,
		Op:           "dec",
		Step:         2,
		List:         []string{"bes", "😁", "בס"},
		InitIndex:    1,
		PaddingValue: 1,
	}
	eng, err = NewStringListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	besBytes := []byte("bes")
	besBytes = append(besBytes, []byte{1, 1, 1}...)
	emojiBytes := []byte("😁")
	emojiBytes = append(emojiBytes, []byte{1, 1}...)
	hebrewBytes := []byte("בס")
	hebrewBytes = append(hebrewBytes, []byte{1, 1}...)
	expected = [][]byte{emojiBytes, hebrewBytes, besBytes, emojiBytes, hebrewBytes}
	validateGeneratedString(b, expected, eng, t)

	// longer strings
	params = StringListEngineParams{
		Offset: 10,
		Size:   40,
		Op:     "inc",
		Step:   7,
		List:   []string{"TRex - Realistic traffic generator", "Cisco - Computer Networking", "AVC - Application Visibility and Control", "TRex EMU server is written in Golang"},
	}
	eng, err = NewStringListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	trex := []byte("TRex - Realistic traffic generator")
	trex = append(trex, []byte{0, 0, 0, 0, 0, 0}...)
	cisco := []byte("Cisco - Computer Networking")
	cisco = append(cisco, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...)
	avc := []byte("AVC - Application Visibility and Control")
	emu := []byte("TRex EMU server is written in Golang")
	emu = append(emu, []byte{0, 0, 0, 0}...)
	expected = [][]byte{trex, emu, avc, cisco, trex}
	validateGeneratedString(b, expected, eng, t)
}

// TestStringListRand
func TestStringListRand(t *testing.T) {

	feMgr := createEngineManager(t)
	b := make([]byte, 4)

	// short answers
	params := StringListEngineParams{
		Offset:       0,
		Size:         4,
		Op:           "rand",
		Step:         1,
		List:         []string{"y", "n", "yes", "no"},
		InitIndex:    1,
		PaddingValue: 0,
	}
	eng, err := NewStringListEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	y := []byte("y")
	y = append(y, []byte{0, 0, 0}...)
	n := []byte("n")
	n = append(n, []byte{0, 0, 0}...)
	yes := []byte("yes")
	yes = append(yes, []byte{0}...)
	no := []byte("no")
	no = append(no, []byte{0, 0}...)
	var histogram [4]int
	expected := [4][]byte{y, n, yes, no}
	for i := 0; i < 20000; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		expectedValue := false
		for i := range expected {
			if bytes.Equal(b[eng.GetOffset():eng.GetOffset()+eng.GetSize()], expected[i]) {
				histogram[i]++
				expectedValue = true
			}
		}
		if !expectedValue {
			t.Errorf("Unexpected value generated %v.\n", b[eng.GetOffset():eng.GetOffset()+eng.GetSize()])
			t.FailNow()
		}
	}
	for i := 0; i < len(histogram); i++ {
		if histogram[i] < 4500 || histogram[i] > 5500 {
			t.Errorf("String generated %v times, want in domain [4500-5500].\n", histogram[i])
		}
	}
}

// TestTimeEngineNegative
func TestTimeEngineNegative(t *testing.T) {

	feMgr := createEngineManager(t)

	// invalid size
	params := TimeStartEngineParams{
		Offset:            0,
		Size:              2,
		InterPacketGapMin: 500,
		InterPacketGapMax: 1000,
		TimeEndEngineName: "end",
		UptimeOffset:      20,
	}
	exp := "Size for this engine must be 4 or 8. Invalid size 2.\n"
	_, err := NewTimeStartEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.invalidSize != 1 {
		t.Errorf("invalidSize counter incorrect, have %v, want %v.\n", feMgr.counters.invalidSize, 1)
	}

	// invalid size
	paramsEnd := TimeEndEngineParams{
		Offset:              0,
		Size:                2,
		DurationMin:         500,
		DurationMax:         1000,
		TimeStartEngineName: "start",
	}
	exp = "Size for this engine must be 4 or 8. Invalid size 2.\n"
	_, err = NewTimeEndEngine(&paramsEnd, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.invalidSize != 2 {
		t.Errorf("invalidSize counter incorrect, have %v, want %v.\n", feMgr.counters.invalidSize, 2)
	}

	// max smaller than min
	params = TimeStartEngineParams{
		Offset:            0,
		Size:              8,
		InterPacketGapMin: 500,
		InterPacketGapMax: 250,
		TimeEndEngineName: "end",
		UptimeOffset:      20,
	}
	exp = "InterPacketGap min 500 is greater than InterPacketGap max 250.\n"
	_, err = NewTimeStartEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.maxSmallerThanMin != 1 {
		t.Errorf("maxSmallerThanMin counter incorrect, have %v, want %v.\n", feMgr.counters.maxSmallerThanMin, 1)
	}

	// max smaller than min
	paramsEnd = TimeEndEngineParams{
		Offset:              0,
		Size:                8,
		DurationMin:         500,
		DurationMax:         250,
		TimeStartEngineName: "start",
	}
	exp = "Duration min 500 is greater than Duration max 250.\n"
	_, err = NewTimeEndEngine(&paramsEnd, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.maxSmallerThanMin != 2 {
		t.Errorf("maxSmallerThanMin counter incorrect, have %v, want %v.\n", feMgr.counters.maxSmallerThanMin, 2)
	}

	// size too small
	params = TimeStartEngineParams{
		Offset:            0,
		Size:              4,
		InterPacketGapMin: 500,
		InterPacketGapMax: 0xFFFFFFFF + 1,
		TimeEndEngineName: "end",
		UptimeOffset:      20,
	}
	exp = "Size too small, can't represent max value or uptime offset with 4 bytes.\n"
	_, err = NewTimeStartEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 1 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 1)
	}

	// size too small
	params = TimeStartEngineParams{
		Offset:            0,
		Size:              4,
		InterPacketGapMin: 500,
		InterPacketGapMax: 550,
		TimeEndEngineName: "end",
		UptimeOffset:      0xF00000000,
	}
	exp = "Size too small, can't represent max value or uptime offset with 4 bytes.\n"
	_, err = NewTimeStartEngine(&params, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 2 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 2)
	}

	// size too small
	paramsEnd = TimeEndEngineParams{
		Offset:              0,
		Size:                4,
		DurationMin:         500,
		DurationMax:         0xFFFFFFFF + 1,
		TimeStartEngineName: "start",
	}
	exp = "Size too small, can't represent max value 4294967296  with 4 bytes.\n"
	_, err = NewTimeEndEngine(&paramsEnd, feMgr)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	if feMgr.counters.sizeTooSmall != 3 {
		t.Errorf("sizeTooSmall counter incorrect, have %v, want %v.\n", feMgr.counters.sizeTooSmall, 3)
	}
}

// TestTimeEngine
func TestTimeEngine(t *testing.T) {
	feMgr := createEngineManager(t)
	b := make([]byte, 8)

	paramsStart := TimeStartEngineParams{
		Offset:            0,
		Size:              4,
		InterPacketGapMin: 10000,
		InterPacketGapMax: 15000,
		TimeEndEngineName: "end",
		UptimeOffset:      2500,
	}
	startEng, err := NewTimeStartEngine(&paramsStart, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}

	paramsEnd := TimeEndEngineParams{
		Offset:              4,
		Size:                4,
		DurationMin:         500,
		DurationMax:         1000,
		TimeStartEngineName: "start",
	}
	endEng, err := NewTimeEndEngine(&paramsEnd, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}

	feMgr.engines[paramsStart.TimeEndEngineName] = endEng
	feMgr.engines[paramsEnd.TimeStartEngineName] = startEng

	end := uint32(paramsStart.UptimeOffset) - uint32(paramsStart.InterPacketGapMin)
	for i := 0; i < 1000; i++ {
		startEng.Update(b[startEng.GetOffset() : startEng.GetOffset()+startEng.GetSize()])
		start := binary.BigEndian.Uint32(b[startEng.GetOffset():])
		minStart := end + uint32(paramsStart.InterPacketGapMin)
		maxStart := end + uint32(paramsStart.InterPacketGapMax)
		if start < minStart || start > maxStart {
			t.Errorf("Bad Update no %v. Expected Flow Start in [%v-%v], got %v.\n", i, minStart, maxStart, start)
			t.FailNow()
		}

		endEng.Update(b[endEng.GetOffset() : endEng.GetOffset()+endEng.GetSize()])
		end = binary.BigEndian.Uint32(b[endEng.GetOffset():])
		minEnd := start + uint32(paramsEnd.DurationMin)
		maxEnd := start + uint32(paramsEnd.DurationMax)
		if end < minEnd || end > maxEnd {
			t.Errorf("Bad Update no %v. Expected Flow End in [%v-%v], got %v.\n", i, minEnd, minEnd, end)
			t.FailNow()
		}
	}

	feMgr = createEngineManager(t)
	b = make([]byte, 16)

	paramsStart = TimeStartEngineParams{
		Offset:            0,
		Size:              8,
		InterPacketGapMin: 100000,
		InterPacketGapMax: 100000,
		TimeEndEngineName: "end",
		UptimeOffset:      25000,
	}
	startEng, err = NewTimeStartEngine(&paramsStart, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}

	paramsEnd = TimeEndEngineParams{
		Offset:              8,
		Size:                8,
		DurationMin:         30000,
		DurationMax:         30000,
		TimeStartEngineName: "start",
	}
	endEng, err = NewTimeEndEngine(&paramsEnd, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}

	feMgr.engines[paramsStart.TimeEndEngineName] = endEng
	feMgr.engines[paramsEnd.TimeStartEngineName] = startEng

	startExp := paramsStart.UptimeOffset
	endExp := paramsStart.UptimeOffset + paramsEnd.DurationMin
	for i := 0; i < 1000; i++ {
		startEng.Update(b[startEng.GetOffset() : startEng.GetOffset()+startEng.GetSize()])
		start := binary.BigEndian.Uint64(b[startEng.GetOffset():])
		if start != startExp {
			t.Errorf("Bad Update no %v. Expected Flow Start %v, got %v.\n", i, startExp, start)
			t.FailNow()
		}

		endEng.Update(b[endEng.GetOffset() : endEng.GetOffset()+endEng.GetSize()])
		end := binary.BigEndian.Uint64(b[endEng.GetOffset():])
		if end != endExp {
			t.Errorf("Bad Update no %v. Expected Flow End %v, got %v.\n", i, endExp, end)
			t.FailNow()
		}
		difference := paramsStart.InterPacketGapMax + paramsEnd.DurationMax
		startExp = startExp + difference
		endExp = endExp + difference
	}
}

// TestHistogramURL
func TestHistogramURL(t *testing.T) {
	feMgr := createEngineManager(t)

	entries := []HistogramEntry{
		// only scheme + host
		&HistogramURLEntry{
			Schemes: []string{"https"},
			Hosts:   []string{"google.com"},
			Prob:    6},
		&HistogramURLEntry{
			Schemes: []string{"https"},
			Hosts:   []string{"facebook.com"},
			Prob:    6},
		// multiple schemes + host + multiple paths
		&HistogramURLEntry{
			Schemes: []string{"http", "https"},
			Hosts:   []string{"ynet.co.il"},
			Paths:   []string{"home", "news/sports"},
			Prob:    6,
		},
	}
	/* possible options
	https://google.com - prob: 6/18
	https://facebook.com - prob: 6/18
	http://ynet.co.il - prob: 1/18
	http://ynet.co.il/home - prob: 1/18
	http://ynet.co.il/news/sports - prob: 1/18
	https://ynet.co.il - prob: 1/18
	https://ynet.co.il/home - prob: 1/18
	https://ynet.co.il/news/sports - prob: 1/18
	*/
	params := HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 0,
			Size:   40,
		},
		entries,
	}
	b := make([]byte, 128)
	generated := make(map[string]int, 8)
	iterNumber := 180000
	eng, err := NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		length, _ := eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		gen := string(b[:length])
		generated[gen]++
	}
	expected := make(map[string]int, 8)
	expected["https://google.com"] = 60000
	expected["https://facebook.com"] = 60000
	expected["http://ynet.co.il"] = 10000
	expected["http://ynet.co.il/home"] = 10000
	expected["http://ynet.co.il/news/sports"] = 10000
	expected["https://ynet.co.il"] = 10000
	expected["https://ynet.co.il/home"] = 10000
	expected["https://ynet.co.il/news/sports"] = 10000

	for url := range generated {
		min := int(float32(expected[url]) * 0.9)
		max := int(float32(expected[url]) * 1.1)
		if generated[url] < min || generated[url] > max {
			t.Errorf("Bad amount generated for url %v, expected in [%v-%v], got %v.\n", url, min, max, generated[url])
			t.FailNow()
		}
	}

	entries = []HistogramEntry{
		// scheme + host + path + query
		&HistogramURLEntry{
			Schemes: []string{"https"},
			Hosts:   []string{"www.google.com"},
			Paths:   []string{"doodles", "search", "images"},
			Queries: []string{"username=bes", "x=1&y=2"},
			Prob:    24},
		// scheme + host + query
		&HistogramURLEntry{
			Schemes: []string{"ftp"},
			Hosts:   []string{"ftp.adobe.com"},
			Queries: []string{"product=acrobat"},
			Prob:    12},
	}
	/* possible options
	https://www.google.com - prob: 1/18
	https://www.google.com/doodles - prob: 1/18
	https://www.google.com/search - prob: 1/18
	https://www.google.com/images - prob: 1/18
	https://www.google.com?username=bes - prob: 1/18
	https://www.google.com/doodles?username=bes - prob: 1/18
	https://www.google.com/images?username=bes - prob: 1/18
	https://www.google.com/search?username=bes - prob: 1/18
	https://www.google.com?x=1&y=2 - prob: 1/18
	https://www.google.com/doodles?x=1&y=2 - prob: 1/18
	https://www.google.com/images?x=1&y=2 - prob: 1/18
	https://www.google.com/search?x=1&y=2 - prob: 1/18
	ftp://ftp.adobe.com?product=acrobat - prob 3/18
	ftp://ftp.adobe.com - prob 3/18
	*/

	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 40,
			Size:   60,
		},
		entries,
	}

	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated = make(map[string]int, 14)
	for i := 0; i < iterNumber; i++ {
		length, _ := eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		gen := string(b[eng.GetOffset() : int(eng.GetOffset())+length])
		generated[gen]++
	}

	expected = make(map[string]int, 14)
	expected["https://www.google.com"] = 10000
	expected["https://www.google.com/doodles"] = 10000
	expected["https://www.google.com/search"] = 10000
	expected["https://www.google.com/images"] = 10000
	expected["https://www.google.com?username=bes"] = 10000
	expected["https://www.google.com/doodles?username=bes"] = 10000
	expected["https://www.google.com/images?username=bes"] = 10000
	expected["https://www.google.com/search?username=bes"] = 10000
	expected["https://www.google.com?x=1&y=2"] = 10000
	expected["https://www.google.com/doodles?x=1&y=2"] = 10000
	expected["https://www.google.com/images?x=1&y=2"] = 10000
	expected["https://www.google.com/search?x=1&y=2"] = 10000
	expected["ftp://ftp.adobe.com?product=acrobat"] = 30000
	expected["ftp://ftp.adobe.com"] = 30000

	for url := range generated {
		min := int(float32(expected[url]) * 0.9)
		max := int(float32(expected[url]) * 1.1)
		if generated[url] < min || generated[url] > max {
			t.Errorf("Bad amount generated for url %v, expected in [%v-%v], got %v.\n", url, min, max, generated[url])
			t.FailNow()
		}
	}

	entries = []HistogramEntry{
		&HistogramURLEntry{
			Schemes:     []string{"https"},
			Hosts:       []string{"google.com"},
			RandomQuery: true,
			Prob:        1},
	}

	params = HistogramEngineParams{
		HistogramEngineCommonParams{
			Offset: 100,
			Size:   22, // allow only one letter random queries
		},
		entries,
	}

	generated = make(map[string]int, 63)

	eng, err = NewHistogramEngine(&params, feMgr)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		length, _ := eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		gen := string(b[eng.GetOffset() : int(eng.GetOffset())+length])
		generated[gen]++
	}

	// Half are empty queries and the other half are uniformly distributed letters and numbers.
	emptyQuery := "https://google.com?q="
	emptyQueryCounter := iterNumber >> 1
	allTheRestCounter := (iterNumber >> 1) / 62

	for url := range generated {
		min, max := 0, 0
		if url == emptyQuery {
			min = int(float32(emptyQueryCounter) * 0.9)
			max = int(float32(emptyQueryCounter) * 1.1)
		} else {
			min = int(float32(allTheRestCounter) * 0.9)
			max = int(float32(allTheRestCounter) * 1.1)
		}

		if generated[url] < min || generated[url] > max {
			t.Errorf("Bad amount generated for url %v, expected in [%v-%v], got %v.\n", url, min, max, generated[url])
			t.FailNow()
		}
	}

}
