package netflow

import (
	"bytes"
	"emu/core"
	"encoding/binary"
	"testing"
	"unicode/utf8"

	"github.com/intel-go/fastjson"
)

// TestUIntEngineManagerBasic
func TestEngineManagerBasic(t *testing.T) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()
	par := fastjson.RawMessage([]byte(`[
					{
					"engine_type": "uint",
					"engine_name": "bes",
					"params":
						{
							"size": 2,
							"offset": 0,
							"min": 0,
							"max": 5,
							"op": "inc",
						}
		 			}
		 		]`))
	feMgr := NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 1 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 1, len(feMgr.engines))
		t.FailNow()
	}
	eng, ok := feMgr.engines["bes"]
	if !ok {
		t.Errorf("Engine map doesn't contain the required engine name %v.\n", "bes")
		t.FailNow()
	}
	b := make([]byte, 2)
	expected := []uint16{0, 1, 2, 3, 4, 5, 0, 1, 2}
	for i := 0; i < len(expected); i++ {
		eng.Update(b[eng.GetOffset():])
		value := binary.BigEndian.Uint16(b[eng.GetOffset():])
		if value != expected[i] {
			t.Errorf("Error generating value, want %v, have %v.\n", expected[i], value)
		}
	}
	expectedBytes := []byte{0x00, 0x02}
	if !bytes.Equal(expectedBytes, b) {
		t.Errorf("Buffer not as expected, want %v, have %v.\n", expectedBytes, b)
	}
}

// TestUIntEngineManagerMultipleUInt
func TestEngineManagerMultipleUInt(t *testing.T) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()
	par := fastjson.RawMessage([]byte(`[
					{
						"engine_type": "uint",
						"engine_name": "Increase",
						"params":
							{
								"size": 1,
								"offset": 0,
								"min": 0,
								"max": 50,
								"op": "inc",
								"step": 20,
								"init": 5,
							}
					},
					{
						"engine_type": "uint",
						"engine_name": "Decrease",
						"params":
							{
								"size": 2,
								"offset": 2,
								"min": 200,
								"max": 2000,
								"op": "dec",
								"step": 200,
							}
					},
					{
						"engine_type": "uint",
						"engine_name": "Random",
						"params":
							{
								"size": 4,
								"offset": 4,
								"min": 1000,
								"max": 2000,
								"op": "rand"
							}

					}
		 		]`))
	feMgr := NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 3 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 3, len(feMgr.engines))
		t.FailNow()
	}
	names := []string{"Increase", "Decrease", "Random"}
	var engines []FieldEngineIF
	for _, name := range names {
		eng, ok := feMgr.engines[name]
		if !ok {
			t.Errorf("Engine map doesn't contain the required engine name %v.\n", name)
			t.FailNow()
		}
		engines = append(engines, eng)
	}
	b := make([]byte, 8)

	expectedInc := []uint8{5, 25, 45, 14, 34, 3, 23}
	var receivedInc []uint8
	expectedDec := []uint16{200, 1801, 1601, 1401, 1201, 1001, 801}
	var receivedDec []uint16
	var receivedRand []uint32
	for i := 0; i < len(expectedInc); i++ {
		for j := 0; j < len(engines); j++ {
			eng := engines[j]
			eng.Update(b[eng.GetOffset():])
			if j == 0 {
				receivedInc = append(receivedInc, uint8(b[eng.GetOffset()]))
			} else if j == 1 {
				receivedDec = append(receivedDec, binary.BigEndian.Uint16(b[eng.GetOffset():]))
			} else if j == 2 {
				receivedRand = append(receivedRand, binary.BigEndian.Uint32(b[eng.GetOffset():]))
			}
		}
	}
	// validate each one
	for i := 0; i < len(expectedInc); i++ {
		if expectedInc[i] != receivedInc[i] {
			t.Errorf("Increase didn't generate as expected, want %v, have %v.\n", expectedInc[i], receivedInc[i])
		}
		if expectedDec[i] != receivedDec[i] {
			t.Errorf("Decrease didn't generate as expected, want %v, have %v.\n", expectedDec[i], receivedDec[i])
		}
		if receivedRand[i] < 1000 || receivedRand[i] > 2000 {
			t.Errorf("Random didn't generate as expected, want in [%v-%v], have %v.\n", 1000, 2000, receivedRand[i])
		}
	}
	// validate no overlap in first 4 bytes
	expectedBytes := []byte{0x17, 0x00, 0x03, 0x21} // [23, 0, 801]
	if !bytes.Equal(expectedBytes, b[0:4]) {
		t.Errorf("Buffer not as expected, want %v, have %v.\n", expectedBytes, b[0:4])
	}
}

//TestEngineManagerNegativeUint
func TestEngineManagerNegativeUint(t *testing.T) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()

	// bad operation
	par := fastjson.RawMessage([]byte(`[
					{
					"engine_type": "uint",
					"engine_name": "Emu",
					"params":
						{
					 		"size": 2,
					 		"offset": 0,
							"min": 0,
							"max": 5,
							"op": "aa",
						}
		 			}
				 ]`))
	feMgr := NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.badOperation != 1 {
		t.Errorf("Bad counter badOperation, want %v, have %v.\n", 1, feMgr.counters.badOperation)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// invalid json
	par = fastjson.RawMessage([]byte(`[
			{
			"engine_type": "uint,
			"engine_name": "Emu",
			"params":
				{
					"size": 2,
					"offset": 0,
					"min": 0,
					"max": 5,
					"op": "aa",
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.invalidJson != 1 {
		t.Errorf("Bad counter invalidJson, want %v, have %v.\n", 1, feMgr.counters.invalidJson)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// another invalid json
	par = fastjson.RawMessage([]byte(`[
			{
			"engine_type": "uint",
			"engine_name": 1,
			"params":
				{
					"size": 2,
					"offset": 0,
					"min": 0,
					"max": 5,
					"op": "aa",
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.invalidJson != 1 {
		t.Errorf("Bad counter invalidJson, want %v, have %v.\n", 1, feMgr.counters.invalidJson)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// invalidSize and bad operation
	par = fastjson.RawMessage([]byte(`[
			{
			"engine_type": "uint",
			"engine_name": "Emu",
			"params":
				{
					"size": 5,
					"offset": 0,
					"min": 0,
					"max": 5,
					"op": "aa",
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.invalidSize != 1 && feMgr.counters.badOperation != 1 {
		t.Errorf("Bad counters invalidSize, badOperation, want %v, have %v and %v respectively.\n", 1, feMgr.counters.invalidSize, feMgr.counters.badOperation)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// min biger than max
	par = fastjson.RawMessage([]byte(`[
			{
			"engine_type": "uint",
			"engine_name": "Emu",
			"params":
				{
					"size": 4,
					"offset": 0,
					"min": 25,
					"max": 5,
					"op": "inc",
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.maxSmallerThanMin != 1 {
		t.Errorf("Bad counter maxSmallerThanMin want %v, have %v.\n", 1, feMgr.counters.maxSmallerThanMin)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// size too small
	par = fastjson.RawMessage([]byte(`[
			{
			"engine_type": "uint",
			"engine_name": "Emu",
			"params":
				{
					"size": 2,
					"offset": 0,
					"min": 25,
					"max": 70000,
					"op": "inc",
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.sizeTooSmall != 1 {
		t.Errorf("Bad counter sizeTooSmall want %v, have %v.\n", 1, feMgr.counters.sizeTooSmall)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// bad engine type
	par = fastjson.RawMessage([]byte(`[
			{
			"engine_type": "uint32",
			"engine_name": "Emu",
			"params":
				{
					"size": 2,
					"offset": 0,
					"min": 25,
					"max": 70000,
					"op": "inc",
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.badEngineType != 1 {
		t.Errorf("Bad counter badEngineType want %v, have %v.\n", 1, feMgr.counters.badEngineType)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}
}

//TestEngineManagerHistogramUIntBasic
func TestEngineManagerHistogramUIntBasic(t *testing.T) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()
	b := make([]byte, 12)

	// uint32 entry
	par := fastjson.RawMessage([]byte(`[
					{
						"engine_type": "histogram_uint32",
						"engine_name": "Emu",
						"params":
						{
							"size": 4,
							"offset": 0,
							"entries":
							[
								{
									"v": 0,
									"prob": 1
								},
								{
									"v": 1,
									"prob": 1
								}
							]
						},
		 			}
				 ]`))
	feMgr := NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 1 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 1, len(feMgr.engines))
		t.FailNow()
	}
	eng, ok := feMgr.engines["Emu"]
	if !ok {
		t.Errorf("Engine map doesn't contain the required engine name %v.\n", "Emu")
		t.FailNow()
	}

	var sum uint32
	iterNumber := 1 << 20
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		value := binary.BigEndian.Uint32(b[eng.GetOffset():])
		if !(value == 0 || value == 1) {
			t.Errorf("Generated bad value, expected 0 or 1, got %v.\n", value)
		}
		sum += value
	}
	verifyBinGenerator(iterNumber>>1, int(sum), 1, t)

	// uint32 range
	par = fastjson.RawMessage([]byte(`[
		{
			"engine_type": "histogram_uint32_range",
			"engine_name": "Emu",
			"params":
			{
				"size": 4,
				"offset": 4,
				"entries":
				[
					{
						"min": 0,
						"max": 5,
						"prob": 1
					},
					{
						"min": 6,
						"max": 49,
						"prob": 3
					}
				]
			},
		 }
	 ]`))

	feMgr = NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 1 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 1, len(feMgr.engines))
		t.FailNow()
	}
	eng, ok = feMgr.engines["Emu"]
	if !ok {
		t.Errorf("Engine map doesn't contain the required engine name %v.\n", "Emu")
		t.FailNow()
	}
	receivedHistogram := make([]int, 50)
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		value := binary.BigEndian.Uint32(b[eng.GetOffset():])
		receivedHistogram[value]++
	}
	expectedFirst := (iterNumber >> 2) / 6
	expectedSecond := ((iterNumber >> 2) * 3) / 44
	sumOfFirst := 0
	for i := 0; i < len(receivedHistogram); i++ {
		if i < 6 {
			// small numbers bigs error
			verifyBinGenerator(expectedFirst, receivedHistogram[i], 5, t)
			sumOfFirst += receivedHistogram[i]
		} else {
			verifyBinGenerator(expectedSecond, receivedHistogram[i], 5, t)
		}
	}
	verifyBinGenerator(iterNumber>>2, sumOfFirst, 2, t)

	// uint32 list
	par = fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint32_list",
				"engine_name": "Emu",
				"params":
				{
					"size": 4,
					"offset": 8,
					"entries":
					[
						{
							"list": [1, 3, 5, 7, 9],
							"prob": 3
						},
						{
							"list": [0, 2, 4, 6, 8],
							"prob": 1
						}
					]
				},
			 }
		 ]`))

	feMgr = NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 1 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 1, len(feMgr.engines))
		t.FailNow()
	}
	eng, ok = feMgr.engines["Emu"]
	if !ok {
		t.Errorf("Engine map doesn't contain the required engine name %v.\n", "Emu")
		t.FailNow()
	}
	odd := 0
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		value := binary.BigEndian.Uint32(b[eng.GetOffset():])
		if value%2 == 0 {
			odd++
		}
	}
	verifyBinGenerator(iterNumber>>2, odd, 1, t)
}

// TestEngineManagerHistogramRuneBasic
func TestEngineManagerHistogramRuneBasic(t *testing.T) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()
	b := make([]byte, 12)

	// rune entry, a and b
	par := fastjson.RawMessage([]byte(`[
					{
						"engine_type": "histogram_rune",
						"engine_name": "TRex",
						"params":
						{
							"size": 1,
							"offset": 0,
							"entries":
							[
								{
									"v": 97,
									"prob": 1
								},
								{
									"v": 98,
									"prob": 1
								}
							]
						},
		 			}
				 ]`))
	feMgr := NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 1 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 1, len(feMgr.engines))
		t.FailNow()
	}
	eng, ok := feMgr.engines["TRex"]
	if !ok {
		t.Errorf("Engine map doesn't contain the required engine name %v.\n", "TRex")
		t.FailNow()
	}

	iterNumber := 1 << 15
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v, size := utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		if !(v == 'a' || v == 'b') {
			t.Errorf("Bad rune generated, wanted a or b, got %#U", v)
		}
	}

	// rune range
	par = fastjson.RawMessage([]byte(`[
					{
						"engine_type": "histogram_rune_range",
						"engine_name": "Bes",
						"params":
						{
							"size": 1,
							"offset": 1,
							"entries":
							[
								{
									"min": 97,
									"max": 99,
									"prob": 2
								},
								{
									"min": 101,
									"max": 103,
									"prob": 1
								}
							]
						},
		 			}
				 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 1 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 1, len(feMgr.engines))
		t.FailNow()
	}
	eng, ok = feMgr.engines["Bes"]
	if !ok {
		t.Errorf("Engine map doesn't contain the required engine name %v.\n", "Bes")
		t.FailNow()
	}
	var firstEntry, secondEntry int
	iterNumber = 300000
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v, size := utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		if v == 'a' || v == 'b' || v == 'c' {
			firstEntry++
		} else if v == 'e' || v == 'f' || v == 'g' {
			secondEntry++
		} else {
			t.Errorf("Bad rune generated, wanted [a, b, c, e, f, g], got %#U", v)

		}
	}
	verifyBinGenerator(200000, firstEntry, 2, t)
	verifyBinGenerator(100000, secondEntry, 2, t)

	// rune list
	par = fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_rune_list",
				"engine_name": "TRex",
				"params":
				{
					"size": 1,
					"offset": 2,
					"entries":
					[
						{
							"list": [97, 98],
							"prob": 1
						},
						{
							"list": [99, 100],
							"prob": 1
						}
					]
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 1 {
		t.Errorf("Engine map is of wrong size, want %v, have %v.\n", 1, len(feMgr.engines))
		t.FailNow()
	}
	eng, ok = feMgr.engines["TRex"]
	if !ok {
		t.Errorf("Engine map doesn't contain the required engine name %v.\n", "TRex")
		t.FailNow()
	}
	firstEntry, secondEntry = 0, 0
	iterNumber = 1 << 15
	for i := 0; i < iterNumber; i++ {
		eng.Update(b[eng.GetOffset():])
		v, size := utf8.DecodeRune(b[eng.GetOffset():])
		if size != int(eng.GetSize()) {
			t.Errorf("Error decoding rune, incorrect size. Want %v, have %v.\n", eng.GetSize(), size)
		}
		if v == 'a' || v == 'b' {
			firstEntry++
		} else if v == 'c' || v == 'd' {
			secondEntry++
		} else {
			t.Errorf("Bad rune generated, wanted [a, b, c, e, f, g], got %#U", v)
		}
	}
	verifyBinGenerator(iterNumber>>1, firstEntry, 2, t)
}

// TestEngineManagerHistogramNegative
func TestEngineManagerHistogramNegative(t *testing.T) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()

	// degenerate array
	par := fastjson.RawMessage([]byte(`[
					{
						"engine_type": "histogram_uint32",
						"engine_name": "TRex",
						"params":
						{
							"size": 4,
							"offset": 0,
							"entries":
							[
								{
									"v": 0,
									"prob": 0,
								},
								{
									"v": 1,
									"prob": 0
								}
							]
						}
		 			}
				 ]`))
	feMgr := NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.generatorCreationError != 1 {
		t.Errorf("Bad counter generatorCreationError, want %v, have %v.\n", 1, feMgr.counters.generatorCreationError)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// probabilities too big that won't scale.
	par = fastjson.RawMessage([]byte(`[
					{
						"engine_type": "histogram_uint32",
						"engine_name": "TRex",
						"params":
						{
							"size": 4,
							"offset": 0,
							"entries":
							[
								{
									"v": 0,
									"prob": 2947483645 
								},
								{
									"v": 1,
									"prob": 2947483645
								}
							]
						}
		 			}
				 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.generatorCreationError != 1 {
		t.Errorf("Bad counter generatorCreationError, want %v, have %v.\n", 1, feMgr.counters.generatorCreationError)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// empty list
	par = fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint32_list",
				"engine_name": "TRex",
				"params":
				{
					"size": 4,
					"offset": 4,
					"entries":
					[
						{
							"list": [],
							"prob": 1
						},
						{
							"list": [1],
							"prob": 1
						}
					]
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.emptyList != 1 {
		t.Errorf("Bad counter emptyList, want %v, have %v.\n", 1, feMgr.counters.emptyList)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// empty rune list
	par = fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_rune_list",
				"engine_name": "TRex",
				"params":
				{
					"size": 4,
					"offset": 8,
					"entries":
					[
						{
							"list": [97, 98],
							"prob": 1
						},
						{
							"list": [],
							"prob": 1
						}
					]
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.emptyList != 1 {
		t.Errorf("Bad counter emptyList, want %v, have %v.\n", 1, feMgr.counters.emptyList)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// max > min
	par = fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint32_range",
				"engine_name": "TRex",
				"params":
				{
					"size": 4,
					"offset": 10,
					"entries":
					[
						{
							"min": 5,
							"max": 3,
							"prob": 1
						},
						{
							"max": 5,
							"min": 3,
							"prob": 1
						}
					]
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.maxSmallerThanMin != 1 {
		t.Errorf("Bad counter maxSmallerThanMin, want %v, have %v.\n", 1, feMgr.counters.maxSmallerThanMin)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}

	// max > min rune
	par = fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_rune_range",
				"engine_name": "TRex",
				"params":
				{
					"size": 4,
					"offset": 10,
					"entries":
					[
						{
							"min": 97,
							"max": 99,
							"prob": 1
						},
						{
							"max": 103,
							"min": 105,
							"prob": 1
						}
					]
				}
			 }
		 ]`))
	feMgr = NewEngineManager(tctx, &par)
	if feMgr.counters.failedBuildingEngine != 1 && feMgr.counters.maxSmallerThanMin != 1 {
		t.Errorf("Bad counter maxSmallerThanMin, want %v, have %v.\n", 1, feMgr.counters.maxSmallerThanMin)
	}
	if len(feMgr.engines) != 0 {
		t.Errorf("Engine map is not empty inspite of errors\n")
	}
}

// TestEngineManagerMixed
func TestEngineManagerMixed(t *testing.T) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()
	b := make([]byte, 16)

	// multiple deterministic types
	par := fastjson.RawMessage([]byte(`[
					{
						"engine_type": "uint",
						"engine_name": "uint8",
						"params":
						{
							"size": 1,
							"offset": 0,
							"min": 1,
							"max": 5,
							"init": 3,
							"step": 2,
							"op": "inc"
						}
					 },
					 {
						 "engine_type": "uint",
						 "engine_name": "uint16",
						 "params":
						 {
							"size": 2,
							"offset": 1,
							"min": 10000,
							"max": 50000,
							"step": 5000,
							"init": 20000,
							"op": "dec"
						 }
					 },
					 {
						 "engine_type": "histogram_uint32",
						 "engine_name": "histogram_uint32",
						 "params":
						 {
							 "size": 4,
							 "offset": 3,
							 "entries":
							 [
								{
									"v": 7,
									"prob": 3
								}
							 ]
						 }
					 },
					 {
						 "engine_type": "histogram_uint32_range",
						 "engine_name": "histogram_uint32_range",
						 "params":
						 {
							 "size": 4,
							 "offset": 7,
							 "entries":
							 [
								{
									"min": 255,
									"max": 255,
									"prob": 5
								}
							 ]
						 }
					 },
					 {
						 "engine_type": "histogram_uint32_list",
						 "engine_name": "histogram_uint32_list",
						 "params":
						 {
							 "size": 4,
							 "offset": 11,
							 "entries":
							 [
								 {
									 "list": [65535],
									 "prob": 1
								 }
							 ]
						 }
					 }
				 ]`))
	feMgr := NewEngineManager(tctx, &par)
	if len(feMgr.engines) != 5 {
		t.Errorf("Engine map not build succesfully, want %v engines, have %v engines.\n", 5, len(feMgr.engines))
	}
	for _, eng := range feMgr.engines {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
	}
	expectedBytes := []byte{0x03, 0x4E, 0x20, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00}
	if !bytes.Equal(expectedBytes, b) {
		t.Errorf("Bytes are not equal, want %v, have %v.\n", expectedBytes, b)
	}
	for _, eng := range feMgr.engines {
		eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
	}
	expectedBytes = []byte{0x05, 0x3A, 0x98, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00}
}
