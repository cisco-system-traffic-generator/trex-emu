package netflow

import (
	"emu/core"
	"encoding/hex"
	"math/rand"
	"sort"
	"testing"

	"github.com/intel-go/fastjson"
)

type EngineManagerTestBase struct {
	testname     string              // the name of the test which will be used for generated file
	monitor      bool                // boolean if we are monitoring the data or not
	bufferSize   int                 // buffer size to create in bytes
	iterNumber   int                 // number of iterations for the engine
	engineNumber int                 // number of engines
	inputJson    fastjson.RawMessage // inputJson for engine
	counters     FieldEngineCounters // counters to compare to
	seed         int64               // seed for deterministic generation
}

func (o *EngineManagerTestBase) Run(t *testing.T, compare bool) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()

	if o.seed != 0 {
		rand.Seed(o.seed)
	}

	feMgr := NewEngineManager(tctx, &o.inputJson)
	if len(feMgr.engines) != o.engineNumber {
		o.monitor = false

	}

	b := make([]byte, o.bufferSize)

	var engineNames []string

	/*
		The code must be deterministic in order to compare to the generated json.
		In order to get deterministic pseudo random generation (PRG) we set the seed.
		But this is not enough, the map of engines must be iterated each time in the
		same order!!.
		This is why we collect the keys of the map (engine names), we sort them and then
		iterate the map in this specific order every time.
	*/
	for engine_name := range feMgr.engines {
		engineNames = append(engineNames, engine_name)
	}
	sort.Strings(engineNames)

	for i := 0; i < o.iterNumber; i++ {
		for _, eng_name := range engineNames {
			eng := feMgr.engines[eng_name]
			eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])

		}
		if o.monitor {
			tctx.SimRecordAppend(hex.Dump(b))
		}
	}
	tctx.SimRecordAppend(feMgr.cdb.MarshalValues(true))
	if compare {
		if o.monitor {
			tctx.SimRecordCompare(o.testname, t)
		} else {
			if o.counters != *feMgr.counters {
				t.Errorf("Bad counters, want %+v, have %+v.\n", o.counters, feMgr.counters)
				t.FailNow()
			}
		}
	}
}

func TestEngineManagerNeg1(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg1",
		monitor:      false,
		bufferSize:   2,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
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
		 ]`)),
		counters: FieldEngineCounters{badOperation: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg2(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg2",
		monitor:      false,
		bufferSize:   2,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
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
		 ]`)),
		counters: FieldEngineCounters{invalidJson: 1},
	}
	a.Run(t, true)
}

func TestEngineManager6Neg3(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg3",
		monitor:      false,
		bufferSize:   2,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
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
		 ]`)),
		counters: FieldEngineCounters{badOperation: 1, invalidSize: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg4(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg4",
		monitor:      false,
		bufferSize:   2,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
			"engine_type": "uint",
			"engine_name": "Emu",
			"params":
				{
					"size": 2,
					"offset": 0,
					"min": 70000,
					"max": 69999,
					"op": "inc",
				}
			 }
		 ]`)),
		counters: FieldEngineCounters{sizeTooSmall: 1, maxSmallerThanMin: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg5(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg5",
		monitor:      false,
		bufferSize:   2,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
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
		 ]`)),
		counters: FieldEngineCounters{badEngineType: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg6(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg6",
		monitor:      false,
		bufferSize:   4,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint",
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
		 ]`)),
		counters: FieldEngineCounters{generatorCreationError: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg7(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg7",
		monitor:      false,
		bufferSize:   4,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint",
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
		 ]`)),
		counters: FieldEngineCounters{generatorCreationError: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg8(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg8",
		monitor:      false,
		bufferSize:   4,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint_list",
				"engine_name": "TRex",
				"params":
				{
					"size": 4,
					"offset": 0,
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
		 ]`)),
		counters: FieldEngineCounters{emptyList: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg9(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg9",
		monitor:      false,
		bufferSize:   4,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint_range",
				"engine_name": "TRex",
				"params":
				{
					"size": 4,
					"offset": 0,
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
		 ]`)),
		counters: FieldEngineCounters{maxSmallerThanMin: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg10(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg10",
		monitor:      false,
		bufferSize:   4,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint64_range",
				"engine_name": "TRex",
				"params":
				{
					"size": 4,
					"offset": 0,
					"entries":
					[
						{
							"min": 2222222222222,
							"max": 2222222222221,
							"prob": 1
						},
						{
							"max": 26565232146,
							"min": 3256565622,
							"prob": 1
						}
					]
				}
			 }
		 ]`)),
		counters: FieldEngineCounters{failedBuildingEngine: 1, invalidSize: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg11(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg11",
		monitor:      false,
		bufferSize:   2,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint_range",
				"engine_name": "TRex",
				"params":
				{
					"size": 2,
					"offset": 0,
					"entries":
					[
						{
							"min": 50000,
							"max": 70000,
							"prob": 1
						},
						{
							"max": 15,
							"min": 65525,
							"prob": 1
						}
					]
				}
			 }
		 ]`)),
		counters: FieldEngineCounters{invalidSize: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManagerNeg12(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "feNeg12",
		monitor:      false,
		bufferSize:   2,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint_list",
				"engine_name": "TRex",
				"params":
				{
					"size": 1,
					"offset": 0,
					"entries":
					[
						{
							"list": [5],
							"prob": 1
						},
						{
							"list": [256],
							"prob": 1
						}
					]
				}
			 }
		 ]`)),
		counters: FieldEngineCounters{invalidSize: 1, failedBuildingEngine: 1},
	}
	a.Run(t, true)
}

func TestEngineManager1(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "fe1",
		monitor:      true,
		bufferSize:   1,
		iterNumber:   100,
		engineNumber: 1,
		inputJson: fastjson.RawMessage([]byte(`[
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
					 }
					]`)),
	}
	a.Run(t, true)
}

func TestEngineManager2(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "fe2",
		monitor:      true,
		bufferSize:   15,
		iterNumber:   100,
		engineNumber: 5,
		inputJson: fastjson.RawMessage([]byte(`[
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
				 "engine_type": "histogram_uint",
				 "engine_name": "histogram_uint",
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
				 "engine_type": "histogram_uint_range",
				 "engine_name": "histogram_uint_range",
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
				 "engine_type": "histogram_uint_list",
				 "engine_name": "histogram_uint_list",
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
		 ]`)),
	}
	a.Run(t, true)
}

func TestEngineManager3(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "fe3",
		monitor:      true,
		bufferSize:   8,
		iterNumber:   100,
		engineNumber: 3,
		seed:         0xbe5be5,
		inputJson: fastjson.RawMessage([]byte(`[
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
		 ]`)),
	}
	a.Run(t, true)
}

func TestEngineManager4(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "fe4",
		monitor:      true,
		bufferSize:   18,
		iterNumber:   200,
		engineNumber: 7,
		seed:         0xc15c0,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "uint",
				"engine_name": "IncreaseUint8",
				"params":
					{
						"size": 1,
						"offset": 0,
						"min": 0,
						"max": 255,
						"op": "inc",
						"step": 15,
						"init": 5,
					}
			},
			{
				"engine_type": "uint",
				"engine_name": "DecreaseUint16",
				"params":
					{
						"size": 2,
						"offset": 1,
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
						"offset": 3,
						"min": 1000,
						"max": 2000,
						"op": "rand"
					}
			},
			{
				"engine_type": "uint",
				"engine_name": "IncUint64",
				"params":
					{
						"size": 8,
						"offset": 7,
						"min": 10000000000,
						"max": 20000000000,
						"op": "inc"
					}
			},
			{
				"engine_type": "histogram_uint",
				"engine_name": "histogram_uint",
				"params": 
					{
						"size": 1,
						"offset": 15,
						"entries":
							[
								{
									"v": 7,
									"prob": 15
								},
								{
									"v": 77,
									"prob": 1
								}
							]
					}
			},
			{
				"engine_type": "histogram_uint_range",
				"engine_name": "histogram_uint_range",
				"params": 
					{
						"size": 1,
						"offset": 16,
						"entries":
							[
								{
									"min": 128,
									"max": 191,
									"prob": 3
								},
								{
									"min": 192,
									"max": 223,
									"prob": 2
								},
								{
									"min": 224,
									"max": 239,
									"prob": 1
								}
							]
					}
			},
			{
				"engine_type": "histogram_uint_list",
				"engine_name": "histogram_uint_list",
				"params":
					{
						"size": 1,
						"offset": 17,
						"entries":
							[
								{
									"list": [1, 2, 3],
									"prob": 1
								},
								{
									"list": [4, 5, 6],
									"prob": 1
								}
							]
					}
			}
		 ]`)),
	}
	a.Run(t, true)
}

func TestEngineManager5(t *testing.T) {
	a := &EngineManagerTestBase{
		testname:     "fe5",
		monitor:      true,
		bufferSize:   22,
		iterNumber:   200,
		engineNumber: 5,
		seed:         0xdeadbeef,
		inputJson: fastjson.RawMessage([]byte(`[
			{
				"engine_type": "histogram_uint",
				"engine_name": "histogram_uint",
				"params": 
					{
						"size": 2,
						"offset": 0,
						"entries":
							[
								{
									"v": 1,
									"prob": 2
								},
								{
									"v": 3,
									"prob": 4
								}
							]
					}
			},
			{
				"engine_type": "histogram_uint_range",
				"engine_name": "histogram_uint_range",
				"params": 
					{
						"size": 2,
						"offset": 2,
						"entries":
							[
								{
									"min": 5,
									"max": 6,
									"prob": 7
								},
								{
									"min": 8,
									"max": 9,
									"prob": 10
								},
								{
									"min": 11,
									"max": 12,
									"prob": 13
								}
							]
					}
			},
			{
				"engine_type": "histogram_uint_list",
				"engine_name": "histogram_uint_list",
				"params":
					{
						"size": 2,
						"offset": 4,
						"entries":
							[
								{
									"list": [128, 192, 224],
									"prob": 2
								},
								{
									"list": [224, 240, 248],
									"prob": 3
								}
							]
					}
			},
			{
				"engine_type": "histogram_uint64",
				"engine_name": "histogram_uint64",
				"params":
					{
						"size": 8,
						"offset": 6,
						"entries":
							[
								{
									"v": 1,
									"prob": 2
								},
								{
									"v": 0,
									"prob": 2
								}
							]
					}
			},
			{
				"engine_type": "histogram_uint64_list",
				"engine_name": "histogram_uint64_list",
				"params":
					{
						"size": 8,
						"offset": 14,
						"entries":
							[
								{
									"list": [128, 192, 224, 240, 248, 254],
									"prob": 6
								},
								{
									"list": [255],
									"prob": 1
								}
							]
					}
			}
		 ]`)),
	}
	a.Run(t, true)
}
