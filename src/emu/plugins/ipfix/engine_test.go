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
func validateGeneratedUint8(b []byte, expected []uint8, eng *UIntEngine, t *testing.T) {
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
func validateGeneratedUint16(b []byte, expected []uint16, eng *UIntEngine, t *testing.T) {
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
func validateGeneratedUint32(b []byte, expected []uint32, eng *UIntEngine, t *testing.T) {
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
func validateGeneratedUint64(b []byte, expected []uint64, eng *UIntEngine, t *testing.T) {
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
	iterNumber := 1 << 15
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
	verifyBinGenerator(1<<13, generated[0], 2, t)

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
