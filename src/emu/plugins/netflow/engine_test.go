package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"unicode/utf8"
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

// TestUIntEngineBasic
func TestUIntEngineBasic(t *testing.T) {
	b := make([]byte, 10)
	params := UIntEngineParams{
		offset:   2,
		size:     8,
		op:       "inc",
		step:     2,
		minValue: 50,
		maxValue: 60,
	}
	eng, err := NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
	}
	offset := eng.GetOffset()
	if offset != params.offset {
		t.Errorf("GetOffset was incorrect, have %v, want %v.\n", offset, params.offset)
	}
	size := eng.GetSize()
	if size != params.size {
		t.Errorf("GetSize was incorrect, have %v, want %v.\n", size, params.size)
	}
	eng.Update(b[offset:])
	value := binary.BigEndian.Uint64(b[offset:])
	if value != params.minValue {
		t.Errorf("First Update was incorrect, have %v, want %v.\n", value, params.minValue)
	}
	eng.Update(b[offset:])
	value = binary.BigEndian.Uint64(b[offset:])
	if value != params.minValue+params.step {
		t.Errorf("Second Update was incorrect, have %v, want %v.\n", value, params.minValue+params.step)
	}
}

// TestUIntEngineNegative
func TestUIntEngineNegative(t *testing.T) {
	params := UIntEngineParams{
		offset:   2,
		size:     1,
		op:       "inc",
		step:     2,
		minValue: 50,
		maxValue: 260,
	}
	exp := "Max value 260 cannot be represented with size 1.\n"
	_, err := NewUIntEngine(&params)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	params = UIntEngineParams{
		offset:   2,
		size:     4,
		op:       "inc",
		step:     2,
		minValue: 50,
		maxValue: 40,
	}
	exp = "Min value 50 is bigger than max value 40.\n"
	_, err = NewUIntEngine(&params)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	params = UIntEngineParams{
		offset:   2,
		size:     4,
		op:       "aa",
		step:     2,
		minValue: 50,
		maxValue: 55,
	}
	exp = "Unsupported operation aa.\n"
	_, err = NewUIntEngine(&params)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	params = UIntEngineParams{
		offset:   2,
		size:     3,
		op:       "dec",
		step:     2,
		minValue: 50,
		maxValue: 55,
	}
	exp = "Invalid size 3. Size should be {1, 2, 4, 8}.\n"
	_, err = NewUIntEngine(&params)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	params = UIntEngineParams{
		offset:    2,
		size:      4,
		op:        "dec",
		step:      2,
		minValue:  3,
		maxValue:  55,
		initValue: 1,
	}
	exp = "Init value 1 must be between [3 - 55].\n"
	_, err = NewUIntEngine(&params)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	params = UIntEngineParams{
		offset:    2,
		size:      2,
		op:        "dec",
		step:      2,
		minValue:  65666,
		maxValue:  65667,
		initValue: 1,
	}
	exp = "Max value 65667 cannot be represented with size 2.\n"
	_, err = NewUIntEngine(&params)
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
}

// TestUInt16EngineInc
func TestUInt16EngineInc(t *testing.T) {
	// simple increase with step 5, restart takes 1 on wrap around
	params := UIntEngineParams{
		offset:    0,
		size:      2,
		op:        "inc",
		step:      5,
		minValue:  50,
		maxValue:  100,
		initValue: 75,
	}
	eng, err := NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	// Restarting takes 1, so going from 100 to 50 consumes 1 and then 4 are left.
	expected := []uint16{75, 80, 85, 90, 95, 100, 54, 59, 64, 69, 74}
	b := make([]byte, 8)
	validateGeneratedUint16(b, expected, eng, t)

	// simple increment with step 1
	params = UIntEngineParams{
		offset:   2,
		size:     2,
		op:       "inc",
		step:     1,
		minValue: 5,
		maxValue: 9,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{5, 6, 7, 8, 9, 5, 6}
	validateGeneratedUint16(b, expected, eng, t)

	// generate small domain with wrap around, validate restart takes 1
	params = UIntEngineParams{
		offset:   4,
		size:     2,
		op:       "inc",
		step:     2,
		minValue: 3,
		maxValue: 7,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{3, 5, 7, 4, 6, 3}
	validateGeneratedUint16(b, expected, eng, t)

	// generate with large step no wrap around
	params = UIntEngineParams{
		offset:    6,
		size:      2,
		op:        "inc",
		step:      5000,
		minValue:  0x0100,
		maxValue:  0xffff,
		initValue: 10000,
	}
	eng, err = NewUIntEngine(&params)
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
	// simple decrease with init value
	params := UIntEngineParams{
		offset:    0,
		size:      2,
		op:        "dec",
		step:      1,
		minValue:  0,
		maxValue:  5,
		initValue: 3,
	}
	b := make([]byte, 8)
	var value uint16
	eng, err := NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.")
		t.FailNow()
	}
	expected := []uint16{3, 2, 1, 0, 5, 4}
	validateGeneratedUint16(b, expected, eng, t)

	// decrease of all the domain
	params = UIntEngineParams{
		offset:    2,
		size:      2,
		op:        "dec",
		step:      1,
		minValue:  0,
		maxValue:  0xffff,
		initValue: 0xffff,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 0xffff; i++ {
		eng.Update(b[params.offset:])
	}
	value = binary.BigEndian.Uint16(b[params.offset:])
	if value != 1 {
		t.Errorf("Incorrect update,  want %v, have %v.\n", 1, value)
	}

	// decrease with wrap around
	params = UIntEngineParams{
		offset:   4,
		size:     2,
		op:       "dec",
		step:     2,
		minValue: 0,
		maxValue: 0xffff,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	expected = []uint16{0, 0xffff - 1, 0xffff - 3}
	validateGeneratedUint16(b, expected, eng, t)

	// decrease on minimal domain [3]
	params = UIntEngineParams{
		offset:   6,
		size:     2,
		op:       "dec",
		step:     2,
		minValue: 3,
		maxValue: 3,
	}
	eng, err = NewUIntEngine(&params)
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
	// random generation on a small domain, simple validation using Go's wonderful feature.
	params := UIntEngineParams{
		offset:    0,
		size:      2,
		op:        "rand",
		minValue:  0,
		maxValue:  5,
		initValue: 3,
	}
	b := make([]byte, 8)
	var value uint16
	eng, err := NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	// Since this is a Go Test, go will provide the same random generation all the time.
	// Hence we can put the expected after we saw it once.
	expected := []uint16{3, 2, 1, 5, 1, 5, 2, 2, 4, 2}
	for i := 0; i < len(expected); i++ {
		eng.Update(b[params.offset:])
		value = binary.BigEndian.Uint16(b[params.offset:])
		if value != expected[i] {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, expected[i], value)
		}
	}

	// Generate 1000 times and expect only 7.
	params = UIntEngineParams{
		offset:   2,
		size:     2,
		op:       "rand",
		minValue: 7,
		maxValue: 7,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1000; i++ {
		eng.Update(b[params.offset:])
		value = binary.BigEndian.Uint16(b[params.offset:])
		if value != 7 {
			t.Errorf("Incorrect update no %v, want %v, have %v.\n", i, expected[i], value)
		}
	}

	iterNumber := 1 << 16
	// Generate in the domain of [1-2] iterNumber times and expect half half.
	params = UIntEngineParams{
		offset:   4,
		size:     2,
		op:       "rand",
		minValue: 1,
		maxValue: 2,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	ones, twos := 0, 0
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[params.offset:])
		value = binary.BigEndian.Uint16(b[params.offset:])
		if value == 1 {
			ones++
		} else if value == 2 {
			twos++
		} else {
			t.Errorf("Generated value %v not in domain, [%v - %v].\n", value, params.minValue, params.maxValue)
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
		offset:   6,
		size:     2,
		op:       "rand",
		minValue: 0,
		maxValue: 7,
	}
	var generatedHistogram [8]int
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[params.offset:])
		value = binary.BigEndian.Uint16(b[params.offset:])
		generatedHistogram[value]++
	}
	expectedGen = iterNumber >> 3
	// increase the allowed error since we are generating less of the same.
	expectedLowerBound = float64(expectedGen) * 0.95
	expectedHigherBound = float64(expectedGen) * 1.05
	for i := 0; i < len(generatedHistogram); i++ {
		if float64(generatedHistogram[i]) < expectedLowerBound || float64(generatedHistogram[i]) > expectedHigherBound {
			t.Errorf("Generated number of %vs incorrect, have %v, expected [%v - %v].\n", i, generatedHistogram[i], expectedLowerBound, expectedHigherBound)
		}
	}
}

// TestUInt32EngineInc
func TestUInt32Engine(t *testing.T) {
	// simple increase for uint32
	params := UIntEngineParams{
		offset:   0,
		size:     4,
		op:       "inc",
		minValue: 0xffff,
		maxValue: 0xffff + 10,
		step:     2,
	}
	b := make([]byte, 16)
	eng, err := NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected := []uint32{0xffff, 0xffff + 2, 0xffff + 4, 0xffff + 6, 0xffff + 8, 0xffff + 10, 0xffff + 1, 0xffff + 3}
	validateGeneratedUint32(b, expected, eng, t)

	// decrease with wrap around
	params = UIntEngineParams{
		offset:    4,
		size:      4,
		op:        "dec",
		minValue:  100,
		maxValue:  0xffffffff,
		step:      1,
		initValue: 101,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected = []uint32{101, 100, 0xffffffff, 0xffffffff - 1}
	validateGeneratedUint32(b, expected, eng, t)

	// random on a domain of uint32
	params = UIntEngineParams{
		offset:   8,
		size:     4,
		op:       "rand",
		minValue: 1 << 16,
		maxValue: 1<<16 + 31,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	var value uint32
	zeroOffset := uint32(params.minValue)
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
		offset:   12,
		size:     4,
		op:       "inc",
		minValue: 0xffff,
		maxValue: 0xffffffff,
		step:     1 << 16,
	}
	eng, err = NewUIntEngine(&params)
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
	// simple rand test for uint64
	params := UIntEngineParams{
		offset:   0,
		size:     8,
		op:       "rand",
		minValue: 0,
		maxValue: 15,
	}
	b := make([]byte, 24)
	eng, err := NewUIntEngine(&params)
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
	expectedLowerBound := float64(expectedGen) * 0.97
	expectedHigherBound := float64(expectedGen) * 1.03
	for i := 0; i < len(generatedHistogram); i++ {
		if float64(generatedHistogram[i]) < expectedLowerBound || float64(generatedHistogram[i]) > expectedHigherBound {
			t.Errorf("Generated number of %vs incorrect, have %v, expected [%v - %v].\n", i, generatedHistogram[i], expectedLowerBound, expectedHigherBound)
		}
	}

	// increase to cause overflow with step
	params = UIntEngineParams{
		offset:    8,
		size:      8,
		op:        "inc",
		minValue:  0,
		maxValue:  math.MaxUint64,
		initValue: math.MaxUint64 - 2,
		step:      2,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected := []uint64{math.MaxUint64 - 2, math.MaxUint64, 1, 3, 5, 7}
	validateGeneratedUint64(b, expected, eng, t)

	// decrease to cause overflow
	params = UIntEngineParams{
		offset:    16,
		size:      8,
		op:        "dec",
		minValue:  0,
		maxValue:  math.MaxUint64,
		initValue: 1,
		step:      1,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	expected = []uint64{1, 0, math.MaxUint64, math.MaxUint64 - 1}
	validateGeneratedUint64(b, expected, eng, t)
}

// TestUInt8Engine
func TestUInt8Engine(t *testing.T) {

	// complete domain increment with wrap around
	params := UIntEngineParams{
		offset:   0,
		size:     1,
		op:       "inc",
		minValue: 0,
		maxValue: 0xff,
		step:     1,
	}
	b := make([]byte, 8)
	eng, err := NewUIntEngine(&params)
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
		offset:    1,
		size:      1,
		op:        "dec",
		minValue:  0,
		maxValue:  0xff,
		step:      1,
		initValue: 5,
	}
	expected = []uint8{5, 4, 3, 2, 1, 0, 255, 254, 253, 252, 251, 250}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	validateGeneratedUint8(b, expected, eng, t)

	// increment with step
	params = UIntEngineParams{
		offset:   2,
		size:     1,
		op:       "inc",
		minValue: 0,
		maxValue: 0xff,
		step:     5,
	}
	eng, err = NewUIntEngine(&params)
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

	// decrement with step and wrap around
	params = UIntEngineParams{
		offset:    3,
		size:      1,
		op:        "dec",
		minValue:  0,
		maxValue:  0xff,
		step:      5,
		initValue: 0xff,
	}
	eng, err = NewUIntEngine(&params)
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
		offset:   4,
		size:     1,
		op:       "rand",
		minValue: 0xff,
		maxValue: 0xff,
	}
	eng, err = NewUIntEngine(&params)
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
		offset:   5,
		size:     1,
		op:       "rand",
		minValue: 0x0,
		maxValue: 0xff,
	}
	eng, err = NewUIntEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	iterNumber := 1 << 20
	var generatedHistogram [256]int
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[params.offset:])
		value = uint8(b[eng.GetOffset()])
		generatedHistogram[value]++
	}
	expectedGen := iterNumber >> 8
	// increase the allowed error since we are generating less of the same.
	expectedLowerBound := float64(expectedGen) * 0.95
	expectedHigherBound := float64(expectedGen) * 1.05
	for i := 0; i < len(generatedHistogram); i++ {
		if float64(generatedHistogram[i]) < expectedLowerBound || float64(generatedHistogram[i]) > expectedHigherBound {
			t.Errorf("Generated number of %vs incorrect, have %v, expected [%v - %v].\n", i, generatedHistogram[i], expectedLowerBound, expectedHigherBound)
		}
	}
}

// TestHistogramUInt32Engine
func TestHistogramUInt32Engine(t *testing.T) {

	// simple binary non uniform
	entries := []HistogramEntry{&HistogramUInt32Entry{v: 1, prob: 1}, &HistogramUInt32Entry{v: 10, prob: 3}}
	params := HistogramEngineParams{
		offset:  0,
		size:    4,
		entries: entries,
	}
	b := make([]byte, 16)
	var v uint32
	generated := make([]int, len(entries))
	iterNumber := 1 << 15
	eng, err := NewHistogramEngine(&params)
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
	verifyBinGenerator(1<<13, generated[0], 1, t)

	// complete randomization, check that it wont crash
	numEntries := 1000
	entries = entries[:0]
	for i := 0; i < numEntries; i++ {
		entry := HistogramUInt32Entry{v: rand.Uint32(), prob: uint32(rand.Intn(1 << 10))}
		entries = append(entries, &entry)
	}
	params = HistogramEngineParams{
		offset:  4,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	for i := 0; i < 1<<10; i++ {
		eng.Update(b[eng.GetOffset():])
	}

	// 4 uniform entries
	entries = []HistogramEntry{&HistogramUInt32Entry{v: 0, prob: 2}, &HistogramUInt32Entry{v: 1, prob: 2}, &HistogramUInt32Entry{v: 2, prob: 2}, &HistogramUInt32Entry{v: 3, prob: 2}}
	params = HistogramEngineParams{
		offset:  8,
		size:    4,
		entries: entries,
	}
	generated = make([]int, len(entries))
	eng, err = NewHistogramEngine(&params)
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
	entries = []HistogramEntry{&HistogramUInt32Entry{v: 0, prob: 1000}}
	params = HistogramEngineParams{
		offset:  12,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
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

	// generate number between 0-100 with 0.5 prob and 101-200 with 0.5 prob
	entries := []HistogramEntry{&HistogramUInt32RangeEntry{min: 0, max: 100, prob: 1}, &HistogramUInt32RangeEntry{min: 101, max: 200, prob: 1}}
	params := HistogramEngineParams{
		offset:  0,
		size:    4,
		entries: entries,
	}
	b := make([]byte, 16)
	var v uint32
	generated := make([]int, len(entries))
	iterNumber := 1 << 20
	eng, err := NewHistogramEngine(&params)
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
	entries = []HistogramEntry{&HistogramUInt32RangeEntry{min: 0, max: 1000, prob: 1}, &HistogramUInt32RangeEntry{min: 500, max: 1500, prob: 1}}
	params = HistogramEngineParams{
		offset:  4,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
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
	entries = []HistogramEntry{&HistogramUInt32RangeEntry{min: 0, max: 1000, prob: 1}, &HistogramUInt32RangeEntry{min: 2000, max: 3000, prob: 1},
		&HistogramUInt32RangeEntry{min: 4000, max: 5000, prob: 1}}
	params = HistogramEngineParams{
		offset:  8,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
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
	entries = []HistogramEntry{&HistogramUInt32RangeEntry{min: 0, max: 1000, prob: 1}, &HistogramUInt32RangeEntry{min: 2000, max: 3000, prob: 7}}
	params = HistogramEngineParams{
		offset:  12,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
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

	// even digit vs odd digit uniform
	entries := []HistogramEntry{&HistogramUInt32ListEntry{list: []uint32{1, 3, 5, 7, 9}, prob: 1}, &HistogramUInt32ListEntry{list: []uint32{0, 2, 4, 6, 8}, prob: 1}}
	params := HistogramEngineParams{
		offset:  0,
		size:    4,
		entries: entries,
	}
	b := make([]byte, 8)
	var v uint32
	iterNumber := 1 << 20
	eng, err := NewHistogramEngine(&params)
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
	entries = []HistogramEntry{&HistogramUInt32ListEntry{list: []uint32{1, 3, 5, 7, 9}, prob: 3}, &HistogramUInt32ListEntry{list: []uint32{0, 2, 4, 6, 8}, prob: 1}}
	params = HistogramEngineParams{
		offset:  4,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
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

// TestHistogramRuneEngine
func TestHistogramRuneEngine(t *testing.T) {

	b := make([]byte, 8)
	iterNumber := 60000
	var v rune
	var size int
	// simple ASCII runes
	entries := []HistogramEntry{&HistogramRuneEntry{r: 'a', prob: 1}, &HistogramRuneEntry{r: 'b', prob: 2}, &HistogramRuneEntry{r: 'c', prob: 3}}
	params := HistogramEngineParams{
		offset:  0,
		size:    1,
		entries: entries,
	}
	eng, err := NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated := make([]int, len(entries))
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		v, size = utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		generated[v-'a']++
	}
	verifyBinGenerator(10000, generated[0], 2, t)
	verifyBinGenerator(20000, generated[1], 2, t)
	verifyBinGenerator(30000, generated[2], 2, t)

	// hebrew runes, need 2 bytes
	iterNumber = 150000
	entries = entries[:0]
	letters := []rune{'ב', 'ס', 'ד', 'ו', 'ל', 'מ', 'ה'}
	probSlice := []uint32{1, 2, 3, 4, 2, 1, 2}
	for i := 0; i < len(probSlice); i++ {
		entries = append(entries, &HistogramRuneEntry{r: letters[i], prob: probSlice[i]})
	}
	params = HistogramEngineParams{
		offset:  1,
		size:    2,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	received := make(map[rune]int)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		v, size = utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		received[v]++
	}
	for i, letter := range letters {
		verifyBinGenerator(10000*int(probSlice[i]), received[letter], 2, t)
	}

	// utf8 emojis need 4 bytes
	iterNumber = 100000
	entries = entries[:0]
	letters = []rune{'🤩', '😁', '🤬', '😱'}
	probSlice = []uint32{2, 5, 1, 2}
	for i := 0; i < len(probSlice); i++ {
		entries = append(entries, &HistogramRuneEntry{r: letters[i], prob: probSlice[i]})
	}
	params = HistogramEngineParams{
		offset:  3,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	received = make(map[rune]int)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		v, size = utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		received[v]++
	}
	for i, letter := range letters {
		verifyBinGenerator(10000*int(probSlice[i]), received[letter], 2, t)
	}
}

// TestHistogramRuneRangeEngine
func TestHistogramRuneRangeEngine(t *testing.T) {
	b := make([]byte, 8)
	iterNumber := 40000
	var v rune
	var size int

	// simple ASCII rune ranges
	entries := []HistogramEntry{&HistogramRuneRangeEntry{min: 'a', max: 'e', prob: 1}, &HistogramRuneRangeEntry{min: 'f', max: 'z', prob: 3}}
	params := HistogramEngineParams{
		offset:  0,
		size:    1,
		entries: entries,
	}
	eng, err := NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated := make([]int, 26)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		v, size = utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		generated[v-'a']++
	}
	aToE := generated[0] + generated[1] + generated[2] + generated[3] + generated[4]
	verifyBinGenerator(10000, aToE, 1, t)

	// mixed range - a = 1/6, d=1/6, b = 2/6, c = 2/6
	iterNumber = 60000
	entries = []HistogramEntry{&HistogramRuneRangeEntry{min: 'a', max: 'c', prob: 1}, &HistogramRuneRangeEntry{min: 'b', max: 'd', prob: 1}}
	params = HistogramEngineParams{
		offset:  1,
		size:    1,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated = make([]int, 4)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		v, size = utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		generated[v-'a']++
	}
	verifyBinGenerator(10000, generated[0], 2, t)
	verifyBinGenerator(20000, generated[1], 2, t)
	verifyBinGenerator(20000, generated[2], 2, t)
	verifyBinGenerator(10000, generated[3], 2, t)

	// hebrew range
	iterNumber = 1 << 16
	entries = []HistogramEntry{&HistogramRuneRangeEntry{min: 'א', max: 'ג', prob: 1}, &HistogramRuneRangeEntry{min: 'ד', max: 'ו', prob: 1}}
	params = HistogramEngineParams{
		offset:  2,
		size:    2,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated = make([]int, 6)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		v, size = utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		generated[v-'א']++
	}
	alefToGimel := generated[0] + generated[1] + generated[2]
	verifyBinGenerator(iterNumber>>1, alefToGimel, 1, t)

	// bad range
	entries = []HistogramEntry{&HistogramRuneRangeEntry{min: 'z', max: 'a', prob: 1}}
	params = HistogramEngineParams{
		offset:  4,
		size:    1,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	exp := fmt.Sprintf("Max %v is smaller than min %v in HistogramRuneRangeEntry.\n", 'a', 'z')
	err = eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
}

//TestHistogramRuneListEngine
func TestHistogramRuneListEngine(t *testing.T) {

	b := make([]byte, 8)
	iterNumber := 50000
	var v rune
	var size int
	// emojis
	goodEmojis := []rune{'😀', '😁', '😍', '😇'}
	badEmojis := []rune{'😡', '👹', '🤮'}
	entries := []HistogramEntry{&HistogramRuneListEntry{list: goodEmojis, prob: 3}, &HistogramRuneListEntry{list: badEmojis, prob: 2}}
	params := HistogramEngineParams{
		offset:  0,
		size:    4,
		entries: entries,
	}
	eng, err := NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	generated := make(map[rune]int)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		v, size = utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		generated[v]++
	}
	goodEmojisGenerated := 0
	for _, emoji := range goodEmojis {
		goodEmojisGenerated += generated[emoji]
	}
	badEmojisGenerated := 0
	for _, emoji := range badEmojis {
		badEmojisGenerated += generated[emoji]
	}
	// verify good and bad proportions
	verifyBinGenerator(30000, goodEmojisGenerated, 1, t)
	verifyBinGenerator(20000, badEmojisGenerated, 1, t)

	// verify uniform distributions inside good and inside bad
	// these can be small so give them more error space
	verifyBinGenerator(30000/4, generated['😀'], 3, t)
	verifyBinGenerator(20000/3, generated['😡'], 3, t)

	// empty list - negative test
	var emptyList []rune
	entries = []HistogramEntry{&HistogramRuneListEntry{list: emptyList, prob: 3}}
	params = HistogramEngineParams{
		offset:  4,
		size:    4,
		entries: entries,
	}
	eng, err = NewHistogramEngine(&params)
	if err != nil {
		t.Errorf("Error while generating new engine.\n %v.\n", err.Error())
		t.FailNow()
	}
	exp := "Empty list in HistogramRuneListEntry.\n"
	err = eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
	if err.Error() != exp {
		t.Errorf("Didnt't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
}
