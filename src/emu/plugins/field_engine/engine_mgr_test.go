package field_engine

import (
	"emu/core"
	"encoding/hex"
	"math/rand"
	"regexp"
	"sort"
	"testing"

	"github.com/intel-go/fastjson"
)

type EngineManagerTestBase struct {
	t            testing.TB
	expCreateErr string
	testname     string              // the name of the test which will be used for generated file
	monitor      bool                // boolean if we are monitoring the data or not
	bufferSize   int                 // buffer size to create in bytes
	iterNumber   int                 // number of iterations for the engine
	engineNumber int                 // number of engines
	inputJson    fastjson.RawMessage // inputJson for engine
	counters     FieldEngineCounters // counters to compare to
	seed         int64               // seed for deterministic generation
}

func expErrCheck(t testing.TB, expErrStr string, err error) {
	if err == nil {
		if expErrStr == "" {
			return
		}
		t.Fatalf("Did not get expected error: %s", expErrStr)
	}
	if expErrStr == "" {
		t.Fatalf("Got unexpected error: %v", err)
	}
	expErrRe := regexp.MustCompile(expErrStr)
	if !expErrRe.MatchString(err.Error()) {
		t.Fatalf("Expected error '%s', got: '%v'", expErrStr, err)
	}
}

func (o *EngineManagerTestBase) Run(compare bool) {
	var simrx core.VethIFSim
	tctx := core.NewThreadCtx(0, 4510, true, &simrx)
	defer tctx.Delete()

	if o.seed != 0 {
		rand.Seed(o.seed)
	}

	feMgr, err := NewEngineManager(tctx, &o.inputJson)
	expErrCheck(o.t, o.expCreateErr, err)
	if err != nil {
		return
	}
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
			tctx.SimRecordCompare(o.testname, o.t)
		} else {
			if o.counters != *feMgr.counters {
				o.t.Fatalf("Bad counters, want %+v, have %+v.", o.counters, feMgr.counters)
			}
		}
	}
}

func TestEngineManagerNeg1(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Unsupported operation aa",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg2(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "invalid character",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager6Neg3(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Invalid size 5",
		inputJson: []byte(`[
			{
			"engine_type": "uint",
			"engine_name": "Emu",
			"params":
				{
					"size": 5,
					"offset": 0,
					"min": 0,
					"max": 5,
					"op": "inc",
				}
			 }
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg4(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Max value 69999 cannot be represented with size 2",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg5(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "field engine uint32 is not registered",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg6(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Random distribution array contains only 0",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg7(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "The distributions sum to more than MaxUint32",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg8(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Entry .+ contains an empty list",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg9(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Min 5 bigger than max 3",
		testname:     "feNeg9",
		monitor:      false,
		bufferSize:   4,
		iterNumber:   0,
		engineNumber: 1,
		inputJson: []byte(`[
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
		 ]`),
		counters: FieldEngineCounters{maxSmallerThanMin: 1, failedBuildingEngine: 1},
	}
	a.Run(true)
}

func TestEngineManagerNeg10(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Invalid size 4 with this type of engine",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg11(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Max 70000 can't be represented with 2 bytes",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg12(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "List value 256 can't be represented with 1 bytes",
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg13(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "List value 256 cannot be represented with size 1",
		inputJson: []byte(`[
			{
				"engine_type": "uint_list",
				"engine_name": "TRex",
				"params":
				{
					"size": 1,
					"offset": 0,
					"list": [50, 20, 30, 256],
					"step": 2,
					"init_index": 6,
					"op": "a"
				}
			 }
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg14(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Schemes list can't be empty",
		inputJson: []byte(`[
			{
				"engine_type": "histogram_url",
				"engine_name": "URL",
				"params":
				{
					"size": 20,
					"offset": 0,
					"entries": [
						{
							"schemes": [],
							"hosts": ["google.com"],
							"prob": 2
						}
					]
				}
			 }
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg15(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Hosts list can't be empty",
		inputJson: []byte(`[
			{
				"engine_type": "histogram_url",
				"engine_name": "URL",
				"params":
				{
					"size": 20,
					"offset": 0,
					"entries": [
						{
							"schemes": ["http"],
							"hosts": [],
							"prob": 2
						}
					]
				}
			 }
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg16(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Size 10 is not enough to encode the longest URL",
		inputJson: []byte(`[
			{
				"engine_type": "histogram_url",
				"engine_name": "URL",
				"params":
				{
					"size": 10,
					"offset": 0,
					"entries": [
						{
							"schemes": ["http"],
							"hosts": ["mylongdomain.com"],
							"prob": 2
						}
					]
				}
			 }
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg17(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Can't have a list of queries and random queries set together",
		inputJson: []byte(`[
			{
				"engine_type": "histogram_url",
				"engine_name": "URL",
				"params":
				{
					"size": 20,
					"offset": 0,
					"entries": [
						{
							"schemes": ["http"],
							"hosts": ["trex-tgn.cisco.com"],
							"queries": ["fail=True"],
							"random_queries": true,
							"prob": 2
						}
					]
				}
			 }
		 ]`),
	}
	a.Run(true)
}

func TestEngineManagerNeg18(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		expCreateErr: "Field validation for 'Size' failed",
		inputJson: []byte(`[
			{
				"engine_type": "float",
				"engine_name": "float32",
				"params":
				{
					"size": 2,
					"offset": 0,
					"min": -10,
					"max": 10
				}
			 }
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager1(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe1",
		monitor:      true,
		bufferSize:   1,
		iterNumber:   100,
		engineNumber: 1,
		inputJson: []byte(`[
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
					]`),
	}
	a.Run(true)
}

func TestEngineManager2(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe2",
		monitor:      true,
		bufferSize:   15,
		iterNumber:   100,
		engineNumber: 5,
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager3(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe3",
		monitor:      true,
		bufferSize:   8,
		iterNumber:   100,
		engineNumber: 3,
		seed:         0xbe5be5,
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager4(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe4",
		monitor:      true,
		bufferSize:   18,
		iterNumber:   200,
		engineNumber: 7,
		seed:         0xc15c0,
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager5(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe5",
		monitor:      true,
		bufferSize:   22,
		iterNumber:   200,
		engineNumber: 5,
		seed:         0xdeadbeef,
		inputJson: []byte(`[
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
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager6(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe6",
		monitor:      true,
		bufferSize:   16,
		iterNumber:   200,
		engineNumber: 4,
		seed:         0xc15c0c15c0be5be,
		inputJson: []byte(`[
			{
				"engine_type": "uint_list",
				"engine_name": "uint_list_inc",
				"params": 
					{
						"size": 4,
						"offset": 0,
						"op": "inc",
						"list": [70000, 6214125, 5, 2]
					}
			},
			{
				"engine_type": "uint_list",
				"engine_name": "uint_list_dec",
				"params":
					{
						"size": 2,
						"offset": 4,
						"op": "dec",
						"list": [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096],
						"step": 2,
						"init_index": 4
					}
			},
			{
				"engine_type": "uint_list",
				"engine_name": "uint_list_random",
				"params":
					{
						"size": 1,
						"offset": 6,
						"list": [3, 7, 15, 31, 127, 255],
						"op": "rand"
					}
			},
			{
				"engine_type": "uint_list",
				"engine_name": "uint_list_64",
				"params":
					{
						"size": 8,
						"offset": 8,
						"list": [128, 192, 224, 240, 248, 254],
						"op": "inc",
						"step": 5,
						"init_index": 3
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager7(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe7",
		monitor:      true,
		bufferSize:   120,
		iterNumber:   200,
		engineNumber: 4,
		seed:         0xc15c0c15c0be5be,
		inputJson: []byte(`[
			{
				"engine_type": "string_list",
				"engine_name": "string_list_inc",
				"params": 
					{
						"size": 20,
						"offset": 0,
						"op": "inc",
						"list": ["TRex", "Cisco", "AVC", "EMU", "Golang", "🤩"]
					}
			},
			{
				"engine_type": "string_list",
				"engine_name": "string_list_dec",
				"params":
					{
						"size": 5,
						"offset": 20,
						"op": "dec",
						"list": ["icmp", "tcp", "udp", "rtp", "tls", "dns", "dhcp", "ipfix"],
						"step": 3,
						"init_index": 4,
						"padding_value": 255
					}
			},
			{
				"engine_type": "string_list",
				"engine_name": "string_list_random",
				"params":
					{
						"size": 75,
						"offset": 25,
						"list": ["https://cisco.com", "https://trex-tgn.cisco.com", "https://github.com/cisco-system-traffic-generator", "https://groups.google.com/g/trex-tgn"],
						"op": "rand"
					}
			},
			{
				"engine_type": "string_list",
				"engine_name": "string_list_inc2",
				"params":
					{
						"size": 20,
						"offset": 100,
						"list": ["ciscociscobesbes"],
						"op": "inc",
						"step": 5,
						"init_index": 0,
						"padding": 255,
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager8(t *testing.T) {
	/* There is a hack in this test. Since the simulating environment
	runs the engines in a lexicographic order to provide deterministic
	running behavior, in order to make sure time_start engines are run
	before time_end engines, we make sure their names are smaller (lexicographically)
	than time_end engines*/
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe8",
		monitor:      true,
		bufferSize:   24,
		iterNumber:   200,
		engineNumber: 4,
		seed:         0xbe51be51,
		inputJson: []byte(`[
			{
				"engine_type": "time_start",
				"engine_name": "a",
				"params": 
					{
						"size": 4,
						"offset": 0,
						"time_end_engine_name": "b",
						"ipg_min": 2000,
						"ipg_max": 5000
					}
			},
			{
				"engine_type": "time_end",
				"engine_name": "b",
				"params":
					{
						"size": 4,
						"offset": 4,
						"time_start_engine_name": "a",
						"duration_min": 10,
						"duration_max": 100
					}
			},
			{
				"engine_type": "time_start",
				"engine_name": "c",
				"params":
					{
						"size": 8,
						"offset": 8,
						"time_end_engine_name": "d",
						"time_offset": 9000000000,
						"ipg_min": 1000000,
						"ipg_max": 5000000
					}
			},
			{
				"engine_type": "time_end",
				"engine_name": "d",
				"params":
					{
						"size": 8,
						"offset": 16,
						"time_start_engine_name": "c",
						"duration_min": 90000,
						"duration_max": 100000
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager9(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe9",
		monitor:      true,
		bufferSize:   60,
		iterNumber:   500,
		engineNumber: 1,
		seed:         0x12344321,
		inputJson: []byte(`[
			{
				"engine_type": "histogram_url",
				"engine_name": "URL",
				"params": 
					{
						"size": 60,
						"offset": 0,
						"entries": [
							{
								"schemes": ["https"],
								"hosts": ["www.google.com", "www.facebook.com"]
								"prob": 2,
							},
							{
								"schemes": ["http"],
								"hosts": ["cisco.com"]
								"paths": ["en", "il", "en/careers"]
								"prob": 5
							},
							{
								"schemes": ["ftp"],
								"hosts": ["downloads.cisco.com"],
								"queries": ["image=asr1k"]
								"prob": 3
							},
							{
								"schemes": ["https", "http"]
								"hosts": ["www.trex-tgn.cisco.com"]
								"paths": ["trex", "trex/doc", "trex/release", "trex/reports"]
								"prob": 10
							},
							{
								"schemes": ["https"],
								"hosts": ["stackoverflow.com"],
								"random_queries": true,
								"prob": 4,
							},
							{
								"schemes": ["http"],
								"hosts": ["sceasr-b20:8080", "sceasr-b20:8181"],
								"paths": ["jenkins", "trex", "trex/doc"],
								"random_queries": true,
								"prob": 6
							}
						]
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager10(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe10",
		monitor:      true,
		bufferSize:   12,
		iterNumber:   21,
		engineNumber: 1,
		seed:         0xc15c0be5,
		inputJson: []byte(`[
			{
				"engine_type": "histogram_string",
				"engine_name": "Strings",
				"params": 
					{
						"size": 10,
						"offset": 2,
						"should_pad": true,
						"entries": [
							{
								"str": "TRex",
								"prob": 2,
							},
							{
								"str": "CiscoTRex"
								"prob": 5,
								"padding_value": 36
							}
						]
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager11(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe11",
		monitor:      true,
		bufferSize:   10,
		iterNumber:   21,
		engineNumber: 1,
		seed:         0xdeadbeef,
		inputJson: []byte(`[
			{
				"engine_type": "histogram_string",
				"engine_name": "Strings",
				"params": 
					{
						"size": 10,
						"offset": 0,
						"should_pad": false,
						"entries": [
							{
								"str": "טירקס",
								"prob": 2,
							},
							{
								"str": "Cisco"
								"prob": 5,
								"padding_value": 36
							}
						]
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager12(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe12",
		monitor:      true,
		bufferSize:   8,
		iterNumber:   100,
		engineNumber: 1,
		seed:         0xc15c0be5,
		inputJson: []byte(`[
					{
						"engine_type": "int",
						"engine_name": "int64",
						"params":
						{
							"size": 4,
							"offset": 4,
							"min": -128,
							"max": 127,
							"op": "rand"
						}
					 }
					]`),
	}
	a.Run(true)
}

func TestEngineManager13(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe13",
		monitor:      true,
		bufferSize:   4,
		iterNumber:   100,
		engineNumber: 3,
		seed:         0xc15c0c15c0be5be,
		inputJson: []byte(`[
			{
				"engine_type": "int_list",
				"engine_name": "int_list_inc",
				"params": 
					{
						"size": 1,
						"offset": 0,
						"op": "inc",
						"list": [-128, -1, 0, 1, 127]
					}
			},
			{
				"engine_type": "int_list",
				"engine_name": "int_list_dec",
				"params":
					{
						"size": 1,
						"offset": 1,
						"op": "dec",
						"list": [-7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7],
						"step": 2,
						"init_index": 4
					}
			},
			{
				"engine_type": "int_list",
				"engine_name": "int_list_random",
				"params":
					{
						"size": 2,
						"offset": 2,
						"list": [3, 7, 15, 31, 127, 255, -32768, 32767, -1],
						"op": "rand"
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager14(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe14",
		monitor:      true,
		bufferSize:   30,
		iterNumber:   200,
		engineNumber: 6,
		seed:         0xdeadbeef,
		inputJson: []byte(`[
			{
				"engine_type": "histogram_int",
				"engine_name": "histogram_int",
				"params":
					{
						"size": 2,
						"offset": 0,
						"entries":
							[
								{
									"v": -1,
									"prob": 2
								},
								{
									"v": 1,
									"prob": 4
								}
							]
					}
			},
			{
				"engine_type": "histogram_int_range",
				"engine_name": "histogram_int_range",
				"params": 
					{
						"size": 2,
						"offset": 2,
						"entries":
							[
								{
									"min": -32768,
									"max": -32765,
									"prob": 7
								},
								{
									"min": -3,
									"max": 3,
									"prob": 10
								},
								{
									"min": 32764,
									"max": 32767,
									"prob": 13
								}
							]
					}
			},
			{
				"engine_type": "histogram_int_list",
				"engine_name": "histogram_int_list",
				"params":
					{
						"size": 2,
						"offset": 4,
						"entries":
							[
								{
									"list": [-5, -4, -3],
									"prob": 2
								},
								{
									"list": [3, 4, 5],
									"prob": 3
								}
							]
					}
			},
			{
				"engine_type": "histogram_int64",
				"engine_name": "histogram_int64",
				"params":
					{
						"size": 8,
						"offset": 6,
						"entries":
							[
								{
									"v": -1,
									"prob": 1
								},
								{
									"v": 1,
									"prob": 1
								}
							]
					}
			},
			{
				"engine_type": "histogram_int64_range",
				"engine_name": "histogram_int64_range",
				"params":
					{
						"size": 8,
						"offset": 14,
						"entries":
							[
								{
									"min": -100102401491,
									"max": 0,
									"prob": 1
								},
								{
									"min": 1,
									"max": 104910491049214,
									"prob": 1
								}
							]
					}
			},
			{
				"engine_type": "histogram_int64_list",
				"engine_name": "histogram_int64_list",
				"params":
					{
						"size": 8,
						"offset": 22,
						"entries":
							[
								{
									"list": [-128, -64, -32],
									"prob": 2
								},
								{
									"list": [32, 64, 128],
									"prob": 3
								}
							]
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager15(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe15",
		monitor:      true,
		bufferSize:   12,
		iterNumber:   100,
		engineNumber: 2,
		seed:         0xbe5be5,
		inputJson: []byte(`[
			{
				"engine_type": "float",
				"engine_name": "float64",
				"params":
					{
						"size": 8,
						"offset": 0,
						"min": -10,
						"max": 10,
					}
			},
			{
				"engine_type": "float",
				"engine_name": "float32",
				"params":
					{
						"size": 4,
						"offset": 8,
						"min": 200,
						"max": 2000,
					}
			}
		 ]`),
	}
	a.Run(true)
}

func TestEngineManager16(t *testing.T) {
	a := &EngineManagerTestBase{
		t:            t,
		testname:     "fe16",
		monitor:      true,
		bufferSize:   16,
		iterNumber:   100,
		engineNumber: 3,
		seed:         0xc15c0c15c0be5be,
		inputJson: []byte(`[
			{
				"engine_type": "float_list",
				"engine_name": "float_inc",
				"params": 
					{
						"size": 4,
						"offset": 0,
						"op": "inc",
						"list": [3.14, 2.71, 1.62, 1.44]
					}
			},
			{
				"engine_type": "float_list",
				"engine_name": "float_list_dec",
				"params":
					{
						"size": 4,
						"offset": 4,
						"op": "dec",
						"list": [-4.5, -2.4, -1.1, 0, 1.2, 3.33333],
						"step": 2,
						"init_index": 4
					}
			},
			{
				"engine_type": "float_list",
				"engine_name": "float_list_random",
				"params":
					{
						"size": 8,
						"offset": 8,
						"list": [0.000001, 1.0009, 3.333, 3.14582],
						"op": "rand"
					}
			}
		 ]`),
	}
	a.Run(true)
}
