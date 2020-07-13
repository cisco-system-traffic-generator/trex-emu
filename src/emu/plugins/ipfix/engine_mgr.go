// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package ipfix

import (
	"emu/core"
	"external/osamingo/jsonrpc"
	"fmt"

	"github.com/intel-go/fastjson"
)

/*---------------------------------------------------------------------------------
									Counters
---------------------------------------------------------------------------------*/
// FieldEngineCounters are common counters of all the field engine
// objects and the engine manager.
type FieldEngineCounters struct {
	bufferTooShort         uint64 // buffer too short in update
	maxSmallerThanMin      uint64 // max smaller than min
	badOperation           uint64 // bad operation for uint engine
	invalidSize            uint64 // invalid size for uint engine
	badInitValue           uint64 // bad init value for uint engine
	sizeTooSmall           uint64 // size too small to represent max value for uint engine
	invalidJson            uint64 // invalid json upon creation
	failedBuildingEngine   uint64 // got error while building engine
	generatorCreationError uint64 // error creating the non uniform random generator
	invalidHistogramEntry  uint64 // invalid histogram entry, might be empty list or max < min
	badCopyToBuffer        uint64 // copying to buffer failed
	emptyList              uint64 // empty list in histogram entry
	badEngineType          uint64 // bad engine type provided by the user
}

//Creates a database of engine counters
func NewFECountersDb(o *FieldEngineCounters) *core.CCounterDb {
	db := core.NewCCounterDb("field_engine")
	db.Add(&core.CCounterRec{
		Counter:  &o.bufferTooShort,
		Name:     "bufferTooShort",
		Help:     "Buffer supplied to Update was too short.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.maxSmallerThanMin,
		Name:     "maxSmallerThanMin",
		Help:     "Provided max < min.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.badOperation,
		Name:     "badOperation",
		Help:     "Bad Operation for UInt engine. Provice {inc, dec, rand}",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.invalidSize,
		Name:     "invalidSize",
		Help:     "Invalid size for UInt engine.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.badInitValue,
		Name:     "badInitValue",
		Help:     "Bad init value for UInt engine. Init must be in [min-max]",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.sizeTooSmall,
		Name:     "sizeTooSmall",
		Help:     "Size is too small to represent max value.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.invalidJson,
		Name:     "invalidJson",
		Help:     "JSON unmarshal failed.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.failedBuildingEngine,
		Name:     "failedBuildingEngine",
		Help:     "Failed building at least one of the engines.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.generatorCreationError,
		Name:     "generatorCreationError",
		Help:     "Couldn't create non uniform random generator. Check your distribution.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.invalidHistogramEntry,
		Name:     "invalidHistogramEntry",
		Help:     "Invalid histogram entry. Can't generate value.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.badCopyToBuffer,
		Name:     "badCopyToBuffer",
		Help:     "Unsuccessful copy to buffer.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.emptyList,
		Name:     "emptyList",
		Help:     "Empty list in histogram entry. Should provide at least one element.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})
	db.Add(&core.CCounterRec{
		Counter:  &o.badEngineType,
		Name:     "badEngineType",
		Help:     "Engine type is not registered in the engines type database.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

/*---------------------------------------------------------------------------------
							Engine Manager
---------------------------------------------------------------------------------*/

// FieldEngineRequest represents a request for a field engine. Each request must
// provide the engine name, the engine type and parameters for that specific type
// of engine. Based on the type a special handler builds the engine with the params.
type FieldEngineRequest struct {
	EngineName string               `json:"engine_name"` // name of the engine
	EngineType string               `json:"engine_type"` // type of the engine
	Params     *fastjson.RawMessage `json:"params"`      // params for the engine of EngineType
}

// FieldEngineManager is a Manager that will create the Field Engine objects
// and a map containing all of them, based on the json received by the user,
// through RPC. Each engine is handled by a request, which specifies the
// type of the engine and it's name.  The manager is provided a pointer to all the engines
// and contains the database of counters for all the engines.
type FieldEngineManager struct {
	requests []FieldEngineRequest     // A slice of field engine requests.
	engines  map[string]FieldEngineIF // A map of engines, maps field engine name to field engine object.
	counters *FieldEngineCounters     // Field Engine General Counters
	cdb      *core.CCounterDb         // Counter Database for Field Engine Counters
	cdbv     *core.CCounterDbVec      // Database Vector
	tctx     *core.CThreadCtx         // thread context
}

// NewEngineManager creates and returns a new engine manager. The manager will always be non nil,
// but before trying to use it's engines make sure to verify the counters don't contain errors.
func NewEngineManager(ctx interface{}, data *fastjson.RawMessage) *FieldEngineManager {
	o := new(FieldEngineManager)
	o.tctx = ctx.(*core.CThreadCtx)
	o.engines = make(map[string]FieldEngineIF)
	o.counters = new(FieldEngineCounters)
	o.cdb = NewFECountersDb(o.counters)
	o.cdbv = core.NewCCounterDbVec("field_engine_counters")

	// unmarshal the requests
	err := fastjson.Unmarshal(*data, &o.requests)
	if err != nil {
		o.counters.invalidJson++
		return o
	}

	// create a field engine for each request
	for _, request := range o.requests {
		cb, err := getFieldEngineCB(request.EngineType)
		if err != nil {
			o.counters.badEngineType++
			// clean the map by making a new one.
			o.engines = make(map[string]FieldEngineIF)
			return o
		}
		eng, err := cb(request.Params, o)
		if err != nil {
			o.counters.failedBuildingEngine++
			// clean the map by making a new one.
			o.engines = make(map[string]FieldEngineIF)
			return o
		}
		o.engines[request.EngineName] = eng
	}
	return o
}

// GetFEManagerCounters returns the Field Engine Manager counters.
// The params decides things like the verbosity, filtering or whether to dump zero errors.
func (o *FieldEngineManager) GetFEManagerCounters(params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p core.ApiCntParams
	return o.cdbv.GeneralCounters(nil, o.tctx, params, &p)
}

/*---------------------------------------------------------------------------------
							Engine Callback Database
---------------------------------------------------------------------------------*/
// Callback Database for each Field Engine.
// The engines register in this database with a callback which is used upon creation.

// FieldEngineCB is the callback function signature.
type FieldEngineCB func(params *fastjson.RawMessage, mgr *FieldEngineManager) (FieldEngineIF, error)

// FieldEngineDB is the database that maps each field engine (by type) to its callback function.
type FieldEngineDB struct {
	M map[string]FieldEngineCB
}

var fieldEngineDB FieldEngineDB

// getFieldEngineCB returns the CB of a field engine given its typ.e
func getFieldEngineCB(fe string) (FieldEngineCB, error) {
	_, ok := fieldEngineDB.M[fe]
	if !ok {
		// This *can't* panic, it is called with user input.
		return nil, fmt.Errorf("Field engine %s is not registered.", fe)
	}
	return fieldEngineDB.M[fe], nil
}

// fieldEngineRegister registers a field engine and its callback to the database.
func fieldEngineRegister(fe string, cb FieldEngineCB) {
	if fieldEngineDB.M == nil {
		fieldEngineDB.M = make(map[string]FieldEngineCB)
	}
	_, ok := fieldEngineDB.M[fe]
	if ok {
		s := fmt.Sprintf("Can't register the same field engine twice, %s ", fe)
		// This is okay to panic since the developer registers the FE, not the user.
		panic(s)
	}
	fieldEngineDB.M[fe] = cb
}
