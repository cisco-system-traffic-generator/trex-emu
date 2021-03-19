package field_engine

import (
	"math"
	"math/rand"
	"testing"
)

// verifyBinGenerator verifies that the bin generator test results are as expected.
func verifyBinGenerator(expected, received int, errPerc float64, t *testing.T) {
	errFloat := errPerc / 100
	lowBound := int((1 - errFloat) * float64(expected))
	highBound := int((1 + errFloat) * float64(expected))
	if received < lowBound || received > highBound {
		t.Errorf("Error in binary generation, have %v, expected in [%v - %v] domain.\n", received, lowBound, highBound)
	}
}

// coincident - This function checks two vectors are coincident (one is a positive scalar multiple of the other)
// up to some small error allowed. A dot B = |A| |B| cos (t) where t is the angle between the two vectors.
// Returns true if the vectors are coincident else false.
func coincident(a, b []uint32, errPerc float64) bool {
	var ab, aa, bb uint64
	for i := 0; i < len(a); i++ {
		ab += uint64(a[i] * b[i])
		aa += uint64(a[i] * a[i])
		bb += uint64(b[i] * b[i])
	}
	abab := ab * ab
	aabb := aa * bb
	errFloat := errPerc / 100
	if !(abab > uint64((1-errFloat)*float64(aabb))) {
		return false
	}
	return true
}

// verifyDistribution verifies that the distribution is proportional to the expected distribution (a),
// and that it is scaled as it should (b), hence proving the correctness.
// To verify (a) we can check that the expected and received slices (vectors) are coincident.
// To verify (b) we can check that the sum of received is equal to iterNumber.
func verifyDistribution(expected, received []uint32, iterNumber uint32, errPerc float64, t *testing.T) {
	coincident := coincident(expected, received, errPerc)
	if !coincident {
		t.Errorf("Received is not coincident to expected\n.")
	}
	var sumHistogram uint32
	for i := 0; i < len(received); i++ {
		sumHistogram += received[i]
	}
	if sumHistogram != iterNumber {
		t.Errorf("Didn't generate correctly, generated %v, want %v.\n", sumHistogram, iterNumber)
	}
}

// TestNonUniRandGenNegative
func TestNonUniRandGenNegative(t *testing.T) {
	distributions := []uint32{0, 0}
	exp := "This array contains only 0.\n"
	_, err := NewNonUniformRandGen(distributions)
	if err.Error() != exp {
		t.Errorf("Didn't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
	distributions = []uint32{math.MaxUint32, math.MaxUint32}
	exp = "The distributions sum to more than MaxUint32 (1), can't scale them.\n"
	_, err = NewNonUniformRandGen(distributions)
	if err.Error() != exp {
		t.Errorf("Didn't raise correct error, have %v, want %v.\n", err.Error(), exp)
	}
}

// TestBinaryDistribution
func TestBinaryDistribution(t *testing.T) {

	// generate only 1
	binGen := NewBinDistribution(0, 1, 0)
	var res int
	iterNumber := 1 << 15
	for i := 0; i < iterNumber; i++ {
		res += binGen.Generate()
	}
	verifyBinGenerator(iterNumber, res, 2, t)

	// generate only 0
	res = 0
	binGen = NewBinDistribution(0, 1, math.MaxUint32)
	for i := 0; i < iterNumber; i++ {
		res += binGen.Generate()
	}
	verifyBinGenerator(0, res, 2, t)

	// generate 50-50
	res = 0
	binGen = NewBinDistribution(0, 1, math.MaxUint32>>1)
	for i := 0; i < iterNumber; i++ {
		res += binGen.Generate()
	}
	verifyBinGenerator(iterNumber>>1, res, 2, t)

	// generate 25-75
	res = 0
	binGen = NewBinDistribution(0, 1, math.MaxUint32>>2)
	for i := 0; i < iterNumber*4; i++ {
		res += binGen.Generate()
	}
	verifyBinGenerator(3*iterNumber, res, 2, t)

	// generate other than 0 - 1, 30/70
	fives := 0
	sevens := 0
	expectedFives := int(0.3 * float64(iterNumber))
	binGen = NewBinDistribution(5, 7, floatToUInt(0.3))
	for i := 0; i < iterNumber; i++ {
		res = binGen.Generate()
		if res == 5 {
			fives++
		} else if res == 7 {
			sevens++
		} else {
			t.Errorf("Generated invalid value %v, should generate only %v or %v.\n", res, 5, 7)
		}
	}
	verifyBinGenerator(expectedFives, fives, 2, t)
	verifyBinGenerator(iterNumber-expectedFives, sevens, 2, t)
}

// TestNonUniRandGenBin
func TestNonUniRandGenBin(t *testing.T) {

	// simple binary 33% generator
	dist := []uint32{1, 2}
	iterNumber := 1 << 20
	var res int
	gen, err := NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}

	for i := 0; i < iterNumber; i++ {
		res += gen.Generate()
	}
	verifyBinGenerator(2*iterNumber/3, res, 1, t)

	// trivial case
	dist = []uint32{0, 5}
	res = 0
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}

	for i := 0; i < iterNumber; i++ {
		res += gen.Generate()
	}
	verifyBinGenerator(iterNumber, res, 1, t)

	// opposite trivial case
	dist = []uint32{2, 0}
	res = 0
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}

	for i := 0; i < iterNumber; i++ {
		res += gen.Generate()
	}
	verifyBinGenerator(iterNumber, iterNumber-res, 1, t)

	// 50 - 50
	dist = []uint32{1, 1}
	res = 0
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		res += gen.Generate()
	}
	verifyBinGenerator(iterNumber>>1, res, 1, t)

	// 50 - 50 with maxUint32 >> 1
	dist = []uint32{math.MaxUint32 >> 1, math.MaxUint32 >> 1}
	res = 0
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	for i := 0; i < iterNumber; i++ {
		res += gen.Generate()
	}
	verifyBinGenerator(iterNumber>>1, res, 1, t)
}

// TestNonUniRandGen
func TestNonUniRandGen(t *testing.T) {

	//simple uniform
	dist := []uint32{1, 1, 1, 1}
	var iterNumber uint32
	iterNumber = 1 << 10
	var histogram []uint32
	gen, err := NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	histogram = make([]uint32, len(dist))
	for i := 0; i < int(iterNumber); i++ {
		histogram[gen.Generate()]++
	}
	verifyDistribution(dist, histogram, iterNumber, 1, t)

	// simple non uniform
	dist = []uint32{1, 5, 3}
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	histogram = make([]uint32, len(dist))
	for i := 0; i < int(iterNumber); i++ {
		histogram[gen.Generate()]++
	}
	verifyDistribution(dist, histogram, iterNumber, 1, t)

	// big proportions
	iterNumber = 1 << 15
	dist = []uint32{1, 10000, 5000}
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	histogram = make([]uint32, len(dist))
	for i := 0; i < int(iterNumber); i++ {
		histogram[gen.Generate()]++
	}
	verifyDistribution(dist, histogram, iterNumber, 1, t)

	// a bit longer
	dist = []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	histogram = make([]uint32, len(dist))
	for i := 0; i < int(iterNumber); i++ {
		histogram[gen.Generate()]++
	}
	verifyDistribution(dist, histogram, iterNumber, 1, t)

	// with 0
	dist = []uint32{0, 1, 1}
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	histogram = make([]uint32, len(dist))
	for i := 0; i < int(iterNumber); i++ {
		histogram[gen.Generate()]++
	}
	verifyDistribution(dist, histogram, iterNumber, 1, t)

	// very very long with complete randomization
	dist = []uint32{0}
	distLength := 1 << 15
	for i := 0; i < distLength; i++ {
		dist = append(dist, uint32(rand.Intn(1<<17)))
	}
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	histogram = make([]uint32, len(dist))
	for i := 0; i < int(iterNumber); i++ {
		histogram[gen.Generate()]++
	}
	verifyDistribution(dist, histogram, iterNumber, 1, t)

	// only 1
	dist = []uint32{2}
	gen, err = NewNonUniformRandGen(dist)
	if err != nil {
		t.Errorf("Failed building generator with input %v.\n %v\n", dist, err.Error())
		t.FailNow()
	}
	histogram = make([]uint32, len(dist))
	for i := 0; i < int(iterNumber); i++ {
		histogram[gen.Generate()]++
	}
	if histogram[0] != iterNumber {
		t.Errorf("Failed generating with only one distribution, want %v, have %v.\n", iterNumber, histogram[0])
	}
}
