package ipfix

import (
	"fmt"
	"math"
	"math/rand"
)

/* Fast generation of non-uniform random numbers.
Idea taken from https://oroboro.com/non-uniform-random-numbers/
For efficiency and accuracy, we’re going to implement the non-uniform generator
using 32-bit fixed point math, with all bits to the right of the decimal point
( aka 0.32 fixed point). Each integer will correspond to a number the range from [0-1).
*/

// GeneratorIF is an interface for all common generators.
// A non uniform random generator, a binary generator or a simple uniform generator can
// implement this interface as long as they generate integers.
type GeneratorIF interface {
	// Generate function that all the types that want to implement this interface must
	// provide. Our types are quite simple and return an integer.
	Generate() int
}

// floatToUInt converts a float [0, 1) to a uint32
func floatToUInt(val float64) uint32 {
	return uint32(val * math.MaxUint32)
}

// UIntToFloat converts a uint32 to a float in [0,1)
func UIntToFloat(val uint32) float64 {
	return float64(val) / math.MaxUint32
}

// BinDistribution represents a binary distribution. Generate *a* with probability = prob
// and generate *b* with probability = (1-prob)
// Pay attention that we work with uint32 instead of float.
type BinDistribution struct {
	a    int    // the first element to generate
	b    int    // the second element to generate
	prob uint32 // the probability of generating a, generating b has probability (1-prob)
}

// NewBinDistribution creates a new binary distribution.
func NewBinDistribution(a, b int, prob uint32) *BinDistribution {
	o := new(BinDistribution)
	o.a = a
	o.b = b
	o.prob = prob
	return o
}

// String implements the Stringer interface for pretty print.
func (o *BinDistribution) String() string {
	return fmt.Sprintf("{a = %v, b = %v, prob = %v}", o.a, o.b, o.prob)
}

// Generate is the interface implementation that makes BinDistribution an implementation of
// the generator interface. Generates *a* or *b* according to the probability.
func (o *BinDistribution) Generate() int {
	randValue := rand.Uint32()
	if randValue <= o.prob {
		return o.a
	} else {
		return o.b
	}
}

// NonUniformRandGen is a non uniform random generator that generates on O(1) time and space.
// It receives as input a distribution slice, for example [0.05, 0.10, 0.10, 0.20, 0.55]
// When you call the generate function of the NonUniformRandGen it will return the index
// of the generated (with that distribution) of the distribution.
// Following the previous example, it will generate 0 with 0.05 probability, 1 with 0.10 probability,
// so on, and 4 with 0.55 probability.
type NonUniformRandGen struct {
	distributions    []uint32           // a slice of distributions/probabilities. The sum of the elements in the slice = math.MaxUint32.
	binDistributions []*BinDistribution // a slice of binary distributions that can be created from the input distributions
	numNonZeroDist   uint32             // the number of non zero distributions
}

// NewNonUnformRandGen creates a new non uniform random generator.
func NewNonUniformRandGen(distributions []uint32) (*NonUniformRandGen, error) {
	o := new(NonUniformRandGen)
	// calculate the number of non zero probabilites
	for _, dist := range distributions {
		if dist != 0 {
			o.numNonZeroDist++
		}
	}
	if o.numNonZeroDist == 0 {
		// degenerate array = all 0
		return nil, fmt.Errorf("This array contains only 0.\n")
	}
	o.distributions = make([]uint32, len(distributions))
	copy(o.distributions, distributions)
	err := o.normalize()
	if err != nil {
		return nil, err
	}
	err = o.decompose()
	if err != nil {
		return nil, err
	}
	return o, nil
}

/* -----------------------------------------------------------------------------------------------
										Scale
----------------------------------------------------------------------------------------------- */
// Scales the distributions to a domain of [0-MaxUint32]
func (o *NonUniformRandGen) scale() error {
	var sum uint32
	for _, dist := range o.distributions {
		if sum+dist < sum {
			return fmt.Errorf("The distributions sum to more than MaxUint32 (1), can't scale them.\n")
		}
		sum += dist
	}
	for i, dist := range o.distributions {
		var relative float64
		relative = float64(dist) / float64(sum)
		o.distributions[i] = floatToUInt(relative)
	}
	return nil
}

/* -----------------------------------------------------------------------------------------------
										Distribute Leftover
----------------------------------------------------------------------------------------------- */
// tryDistributingLeftoverToMax distributes the leftover to the max distribution.
// If the leftover is smaller than 0.1% of the max distribution it will distribute,
// and return true, else it returns false.
func (o *NonUniformRandGen) tryDistributingLeftoverToMax() (ok bool, leftover uint32) {
	var sum uint32
	var max uint32
	var maxId int
	for i, dist := range o.distributions {
		sum += dist
		if dist > max {
			max = dist
			maxId = i
		}
	}
	allowedError := max / 1000      // 0.1% of max won't be noticed.
	leftover = math.MaxUint32 - sum // what is left to scale to 1.
	if leftover <= allowedError {
		o.distributions[maxId] += leftover
		return true, leftover
	}
	return false, leftover
}

// distributeLeftoverRelatively distributes the leftover in a relative way.
// Meaning the bigger values will get bigger leftover, making sure that
// the distribution is kept intact.
func (o *NonUniformRandGen) distributeLeftoverRelatively(leftover uint32) {
	for i, dist := range o.distributions {
		leftoverPerDist := leftover * uint32(UIntToFloat(dist))
		o.distributions[i] += leftoverPerDist
	}
}

// distributeOnes distributes leftover as ones to every distribution.
// At this point the leftover should be less than the number of distributions
// hence this doesn't change the distribution as much.
// If you however provide a very long slice of distributions (i.e 5Gig) we are in trouble.
func (o *NonUniformRandGen) distributeLeftoverAsOnes(leftover uint32) error {
	if leftover > uint32(len(o.distributions)) {
		return fmt.Errorf("Leftover bigger than number of distributions, should distribute relatively first.\n")
	}
	var i uint32
	for ; i < leftover; i++ {
		o.distributions[i]++
	}
	return nil
}

// distributeLeftover distributes the leftover to MaxUint32.
// It tries to distribute the leftover in such a way that it will
// keep the distribution intact.
func (o *NonUniformRandGen) distributeLeftover() (err error) {
	if ok, leftover := o.tryDistributingLeftoverToMax(); !ok {
		o.distributeLeftoverRelatively(leftover)
		if ok, leftover = o.tryDistributingLeftoverToMax(); !ok {
			err = o.distributeLeftoverAsOnes(leftover)
		}
	}
	return err
}

/* -----------------------------------------------------------------------------------------------
										Normalize
----------------------------------------------------------------------------------------------- */
// normalize the distribution slice to a domain of [0, MaxUint32]
func (o *NonUniformRandGen) normalize() error {
	// Normalize the probabilities to sum to 1, or in other words math.MaxUint32.
	if o.numNonZeroDist == 1 {
		// trivial case, only 1 probability
		for i, dist := range o.distributions {
			if dist != 0 {
				o.distributions[i] = math.MaxUint32
				break
			}
		}
	} else {
		// interesting case
		err := o.scale()
		if err != nil {
			return err
		}

		err = o.distributeLeftover()
		if err != nil {
			return err
		}
	}

	// validate
	var sum uint64
	for _, dist := range o.distributions {
		sum += uint64(dist)
	}
	if sum != math.MaxUint32 {
		return fmt.Errorf("Normalization was not successful, sum of distributions is %v.\n", sum)
	}
	return nil
}

/* -----------------------------------------------------------------------------------------------
										Decompose
----------------------------------------------------------------------------------------------- */
// findNewBinDistIndexes finds the indeces for the next two elements that will create
// a binary distribution. The small index must hold o.distributions[small] <= threshold
// while the big index must hold o.distribution[big] + o.distribution[small] >= threshhold.
// In case there are no such indeces, the function returns an error.
func (o *NonUniformRandGen) findNewBinDistIndexes(threshold uint32) (small, big int, err error) {
	// iterate to find the small index
	for i, dist := range o.distributions {
		// try to find a distribution lower than the threshold which is non zero
		if dist <= threshold && dist != 0 {
			small = i
			break
		}
	}

	for i, dist := range o.distributions {
		// big and small can't be the same
		if i != small && dist+o.distributions[small] >= threshold {
			big = i
			break
		}
	}

	if small == 0 && big == 0 {
		err = fmt.Errorf("All the distributions are 0, %v.\n", o.distributions)
	}

	return small, big, err

}

// We've selected 2 symbols, at indeces small and big such that distributions[small] <= threashold
// and big >= (threashold - distribution[small]).
// This function will create a new binary distribution, and make
// the appropriate adjustments to the input distributions.
func (o *NonUniformRandGen) computeNewBinDist(small, big int, numNonZero, threshold uint32) error {
	if small == big {
		return fmt.Errorf("While decomposing the indices are the same.\n")
	} else {
		o.binDistributions = append(o.binDistributions, NewBinDistribution(small, big, o.distributions[small]*(numNonZero-1)))
		o.distributions[big] -= (threshold - o.distributions[small])
	}
	o.distributions[small] = 0
	return nil
}

// decompose a non uniform distribution to binary non uniform distributions
// every non uniform distribution of n (non zero) distributions can be
// decomposed to (n-1) non uniform binary distributions.
func (o *NonUniformRandGen) decompose() error {
	if len(o.distributions) == 1 {
		// handle the special case of just 1 distribution
		o.binDistributions = append(o.binDistributions, NewBinDistribution(0, 0, 0))
	} else if len(o.distributions) == 2 {
		// in this case the general algorithm also fails
		o.binDistributions = append(o.binDistributions, NewBinDistribution(0, 1, o.distributions[0]))
	} else {
		if o.numNonZeroDist < 2 {
			// in case we have [0, 1] then we need to create 1 binary distribution, not 0.
			o.numNonZeroDist = 2
		}
		// the number of binary distributions will be numNonZeroDist - 1
		threshold := math.MaxUint32 / (o.numNonZeroDist - 1)
		for {
			small, big, err := o.findNewBinDistIndexes(threshold)
			if err != nil {
				// probably couldn't find more indeces
				break
			}
			err = o.computeNewBinDist(small, big, o.numNonZeroDist, threshold)
			if len(o.binDistributions) == int(o.numNonZeroDist-1) {
				// there might be small errors while decomposing, hence we 0.
				for i := range o.distributions {
					o.distributions[i] = 0
				}
			}
			if err != nil {
				return err
			}
		}
		// at this point we should have all the (numNonZeroDist - 1) binary distributions
		if len(o.binDistributions) != int(o.numNonZeroDist-1) {
			return fmt.Errorf("After decomposing, the number of binary distributions is incorrect.\n")
		}
	}
	return nil
}

// Generate implements the interface Generator and provives an O(1) time and space
// complexity generator for non uniform distributions.
func (o *NonUniformRandGen) Generate() int {
	// Uniformly choose the binary distribution, all of them have the same probability.
	binDist := o.binDistributions[rand.Intn(len(o.binDistributions))]
	// Generate from that binary distribution.
	return binDist.Generate()

}
