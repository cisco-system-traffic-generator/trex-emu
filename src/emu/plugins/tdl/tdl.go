package tdl

/**
Cisco's TDL - The Definition Language
Copyright (c) 2021 Cisco Systems and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
that can be found in the LICENSE file in the root of the source
tree.
*/

import (
	"emu/core"
	engines "emu/plugins/field_engine"
	"emu/plugins/transport"
	"encoding/binary"
	"external/osamingo/jsonrpc"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	TDL_PLUG       = "tdl"
	DefaultRatePps = 1
)

// LUID is a locally unique identifier as defined by TDL. It is 128 bits long, and
// each type (primitives or composed) has a unique LUID.
type LUID [16]byte // Locally unique identifier - 128 bit

// TdlStats defines a number of stats for Tdl. This stats can be error or information counters.
type TdlStats struct {
	invalidDst                uint64 // Invalid destination address
	badOrNoInitJson           uint64 // Bad or no init Json
	invalidMetaData           uint64 // Invalid metadata
	unregisteredTdlType       uint64 // Unregistered Tdl type
	failedCreatingTdlType     uint64 // Failed creating Tdl type from metadata definition
	failedBuildingTdlType     uint64 // Failed building Tdl type instance
	failedBuildingMetaDataMgr uint64 // Failed building metadata manager
	failedBuildingEngineMgr   uint64 // Failed building engine manager
	invalidInitValues         uint64 // Invalid initial values
	invalidEnumDef            uint64 // Invalid Enum definition
	invalidFlagDef            uint64 // Invalid Flag definition
	invalidTypeDef            uint64 // Invalid Type definition
	invalidObjType            uint64 // Invalid Object type
	invalidSocket             uint64 // Error while creating socket
	socketWriteError          uint64 // Error happened writing in the socket.
	payloadUpdateErr          uint64 // Error happened while updating the payload
	duplicateLuid             uint64 // Duplicate Luid upon registration
	pktsTx                    uint64 // Number of transmitted packets.
}

// NewTdlStatsDb creates a TdlStats database.
func NewTdlStatsDb(o *TdlStats) *core.CCounterDb {
	db := core.NewCCounterDb(TDL_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidDst,
		Name:     "invalidDst",
		Help:     "Invalid destination address",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.badOrNoInitJson,
		Name:     "badOrNoInitJson",
		Help:     "Invalid init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidMetaData,
		Name:     "invalidMetaData",
		Help:     "Invalid meta data definition in init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.unregisteredTdlType,
		Name:     "unregisteredTdlType",
		Help:     "Tdl type not registered/supported",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedCreatingTdlType,
		Name:     "failedCreatingTdlType",
		Help:     "Failed creating Tdl type from meta definition",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedBuildingTdlType,
		Name:     "failedBuildingTdlType",
		Help:     "Failed building Tdl type instance",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedBuildingMetaDataMgr,
		Name:     "failedBuildingMetaDataMgr",
		Help:     "Failed building metadata manager",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedBuildingEngineMgr,
		Name:     "failedBuildingEngineMgr",
		Help:     "Failed building engine manager",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidInitValues,
		Name:     "invalidInitValues",
		Help:     "Invalid initial values",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidEnumDef,
		Name:     "invalidEnumDef",
		Help:     "Invalid Enum definition",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidFlagDef,
		Name:     "invalidFlagDef",
		Help:     "Invalid Flag definition",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidTypeDef,
		Name:     "invalidTypeDef",
		Help:     "Invalid Type definition",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidObjType,
		Name:     "invalidObjType",
		Help:     "The object type is invalid",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.socketWriteError,
		Name:     "socketWriteError",
		Help:     "Error happened writing in socket",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.payloadUpdateErr,
		Name:     "payloadUpdateErr",
		Help:     "Error happened while updating payload",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.duplicateLuid,
		Name:     "duplicateLuid",
		Help:     "Duplicate LUID upon registration",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktsTx,
		Name:     "pktsTx",
		Help:     "Number of packets transmitted",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

// TDLHeader represents the header of a TDL packet.
type TdlHeader struct {
	Magic         byte  `json:"magic"`                    // Magic byte
	Fru           byte  `json:"fru"`                      // Fru
	SrcChassis    byte  `json:"src_chassis"`              // Source chassis
	SrcSlot       byte  `json:"src_slot"`                 // Source slot
	DstChassis    byte  `json:"dst_chassis"`              // Destination chassis
	DstSlot       byte  `json:"dst_slot"`                 // Destination slot
	Bay           byte  `json:"bay"`                      // Bay
	StateTracking byte  `json:"state_tracking"`           // State tracking
	Flag          byte  `json:"flag"`                     // Flag
	DomainHash    int32 `json:"domain_hash"`              // Domain Hash
	Len           int32 `json:"len"`                      // Length : FIXME: What length, L7, payload only?
	Uuid          int64 `json:"uuid" validate:"required"` // UUID: FIXME: What uuid?
	TenantId      int16 `json:"tenant_id"`                // Tenant Id
	Luid          LUID  `json:"luid" validate:"required"` // LUID of the type following the header.
}

// Encode a TdlHeader into a byte array.
func (o *TdlHeader) Encode() []byte {
	b := make([]byte, 27)
	b[0] = o.Magic
	b[1] = o.Fru
	b[2] = o.SrcChassis
	b[3] = o.SrcSlot
	b[4] = o.DstChassis
	b[5] = o.DstSlot
	b[6] = o.Bay
	b[7] = o.StateTracking
	b[8] = o.Flag
	binary.BigEndian.PutUint32(b[9:], uint32(o.DomainHash))
	binary.BigEndian.PutUint32(b[13:], uint32(o.Len))
	binary.BigEndian.PutUint64(b[17:], uint64(o.Uuid))
	binary.BigEndian.PutUint16(b[25:], uint16(o.TenantId))
	b = append(b, o.Luid[:]...)
	return b
}

// TdlObject represents the main Tdl object. This is the object that will be encoded in the packet.
type TdlObject struct {
	Name string `json:"name" validate:"required"` // Name of the object
	Type string `json:"type" validate:"required"` // Type of the object
}

// UnconstructedTdlType represents a initialization for an unconstructed Tdl type. It consists of the absolute
// path of the type and its initial value.
type UnconstructedTdlType struct {
	AbsPath string               `json:"path" validate:"required"`  // Absolute path of the type. For example: var0.var1.var2
	Value   *fastjson.RawMessage `json:"value" validate:"required"` // Value to set for the type.
}

// TdlClientParams defines a structure that parses the init Json params of the Tdl client.
type TdlClientParams struct {
	Dst        string                 `json:"dst" validate:"required"`         // Destination address. Combination of Host:Port
	Rate       float32                `json:"rate_pps"`                        // Rate of Tx in PPS. Default=1.
	UdpDebug   bool                   `json:"udp_debug"`                       // Should we run UDP because we are debugging?
	Header     TdlHeader              `json:"header" validate:"required"`      // Tdl header options
	Meta       *fastjson.RawMessage   `json:"meta_data" validate:"required"`   // Tdl meta data Json to pass to the metadata manager.
	Object     TdlObject              `json:"object" validate:"required"`      // Tdl object data
	InitValues []UnconstructedTdlType `json:"init_values" validate:"required"` // List of initialization values for unconstructed types.
	Engines    *fastjson.RawMessage   `json:"engines"`                         // Engine Json to pass to the engine manager.
}

// PluginTdlClient represents a Tdl Client.
type PluginTdlClient struct {
	core.PluginBase                                      // Plugin Base embedded struct so we get all the base functionality
	simulation         bool                              // Flag indication of a simulation
	formattedJson      map[string]interface{}            // Formatted Json to dump in case of simulation
	isIpv6             bool                              // Flag indication of IPv6 traffic
	dstAddress         string                            // Destination address. Combination of Host:Port
	udpDebug           bool                              // Should we run UDP because we are debugging?
	transportCtx       *transport.TransportCtx           // Transport Layer Context
	socket             transport.SocketApi               // Socket API
	dgMacResolved      bool                              // Is the default gateway MAC address resolved?
	stats              TdlStats                          // Tdl statistics
	cdb                *core.CCounterDb                  // Counters database
	cdbv               *core.CCounterDbVec               // Counters database vector
	metaDataMgr        *TdlMetaDataMgr                   // Tdl meta data manager
	unconstructedTypes map[string]UnconstructedTdlTypeIF // Absolute path to interface of an unconstructed Tdl type
	header             TdlHeader                         // Tdl Header as defined by client
	objInstance        TdlTypeIF                         // Object instance
	encodedHeader      []byte                            // Tdl header encoded, doesn't change
	payload            []byte                            // L7 - Tdl payload
	pktTicks           uint32                            // Ticks between two subsequent packets
	pktsPerInterval    uint32                            // Number of packets to send each interval
	timerw             *core.TimerCtx                    // Timer Wheel
	pktTimer           core.CHTimerObj                   // Timer to send packets
	timerCb            TdlTimerCallback                  // Timer callback object
	engineMgr          *engines.FieldEngineManager       // Engine Manager
	engineMap          map[string]engines.FieldEngineIF  // Map of engines name -> engine
	luidTypeMap        map[LUID]string                   // Map of Luid to type
}

// TdlTimerCallback is an empty struct used as a callback for the timer that sends the packets.
// Because of the need to create a specific type of OnEvent for events in the Client struct, we need
// this struct for its OnEvent implementation
type TdlTimerCallback struct{}

// OnEvent is called each time a packet needs to be send.
func (o *TdlTimerCallback) OnEvent(a, b interface{}) {
	// @param:a should be a pointer to the client plugin
	tdlPlug := a.(*PluginTdlClient)
	err := tdlPlug.updatePayload()
	if err != nil {
		tdlPlug.stats.payloadUpdateErr++
	}
	if tdlPlug.simulation {
		tdlPlug.formattedJson = UpdateJson(tdlPlug.unconstructedTypes, tdlPlug.formattedJson)
		tdlPlug.DumpFormattedJson()
	}
	tdlPlug.sendPacket()
	tdlPlug.timerw.StartTicks(&tdlPlug.pktTimer, tdlPlug.pktTicks)
}

// tdlEvents holds a list of events on which the Tdl plugin is interested.
var tdlEvents = []string{core.MSG_DG_MAC_RESOLVED}

// NewTdlClient creates a new Tdl client.
func NewTdlClient(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {

	o := new(PluginTdlClient)
	o.InitPluginBase(ctx, o)            // Init base object
	o.RegisterEvents(ctx, tdlEvents, o) // Register events
	o.OnCreate()

	params := TdlClientParams{Rate: DefaultRatePps}
	err := o.Tctx.UnmarshalValidate(initJson, &params)

	if err != nil {
		o.stats.badOrNoInitJson++
		return nil, err
	}

	// Init Json was provided and successfully decoded into params.
	var host string
	if host, _, err = net.SplitHostPort(params.Dst); err != nil {
		o.stats.invalidDst++
		return nil, err
	}
	o.isIpv6 = strings.Contains(host, ":")
	o.dstAddress = params.Dst
	o.udpDebug = params.UdpDebug
	o.header = params.Header
	o.encodedHeader = o.header.Encode()               // Encode header already since it won't change.
	o.payload = append(o.payload, o.encodedHeader...) // payload starts with the header
	o.pktTicks, o.pktsPerInterval = o.timerw.DurationToTicksBurst(time.Duration(float32(time.Second) / params.Rate))
	o.transportCtx = transport.GetTransportCtx(o.Client)

	// Create Metadata Manager
	o.metaDataMgr, err = NewTdlMetaDataMgr(o, params.Meta)
	if err != nil {
		o.stats.failedBuildingMetaDataMgr++
		return nil, err
	}
	RegisterPrimitiveLuid(o)     // Register primitive types
	o.metaDataMgr.registerLuid() // Register meta data types

	// Build the main object instance
	err = o.buildObjectInstance(params.Object)
	if err != nil {
		o.stats.failedBuildingTdlType++
		return nil, err
	}

	// build the map
	o.buildUnconstructedTypesMap(params.Object)

	// Create Engine Manager
	if params.Engines != nil {
		o.engineMgr, err = engines.NewEngineManager(o.Tctx, params.Engines)
		if err != nil {
			o.stats.failedBuildingEngineMgr++
			return nil, fmt.Errorf("could not create engine manager: %w", err)
		}
		o.engineMap = o.engineMgr.GetEngineMap()
	}

	// Validate engine names are valid unconstructed types.
	for engineName := range o.engineMap {
		if _, ok := o.unconstructedTypes[engineName]; !ok {
			o.stats.failedBuildingEngineMgr++
			return nil, fmt.Errorf("Got engine for unexisting field %s", engineName)
		}
	}

	// Set initial values for unconstructed types.
	err = o.setInitialValues(params.InitValues)
	if err != nil {
		o.stats.invalidInitValues++
		return nil, err
	}

	if o.simulation {
		o.formattedJson = BuildJson(o.unconstructedTypes)
	}

	return &o.PluginBase, nil
}

// OnCreate is called upon creating a new Tdl client.
func (o *PluginTdlClient) OnCreate() {
	// Create counter database and vector.
	o.simulation = o.Tctx.Simulation
	o.cdb = NewTdlStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec(TDL_PLUG)
	o.cdbv.Add(o.cdb)
	o.unconstructedTypes = make(map[string]UnconstructedTdlTypeIF)

	o.timerw = o.Tctx.GetTimerCtx()
	o.pktTimer.SetCB(&o.timerCb, o, 0)
}

// OnRemove is called when we remove the Tdl client.
func (o *PluginTdlClient) OnRemove(ctx *core.PluginCtx) {
	if o.pktTimer.IsRunning() {
		o.timerw.Stop(&o.pktTimer)
	}
	ctx.UnregisterEvents(&o.PluginBase, tdlEvents)
	if o.socket != nil {
		o.socket.Close()
	}
}

// OnEvent callback of the Tdl client in case of events.
func (o *PluginTdlClient) OnEvent(msg string, a, b interface{}) {
	switch msg {
	case core.MSG_DG_MAC_RESOLVED:
		bitMask, ok := a.(uint8)
		if !ok {
			// failed at type assertion
			return
		}
		if o.dgMacResolved {
			// already resolved, nothing to do
			// shouldn't call OnResolve twice
			return
		}
		resolvedIPv4 := (bitMask & core.RESOLVED_IPV4_DG_MAC) == core.RESOLVED_IPV4_DG_MAC
		resolvedIPv6 := (bitMask & core.RESOLVED_IPV6_DG_MAC) == core.RESOLVED_IPV6_DG_MAC
		if (o.isIpv6 && resolvedIPv6) || (!o.isIpv6 && resolvedIPv4) {
			o.OnResolve()
		}
	}
}

// OnResolve is called when the default gateway Mac address is resolved.
func (o *PluginTdlClient) OnResolve() {
	o.dgMacResolved = true
	if o.transportCtx != nil {
		var err error
		l4Protocol := "tcp"
		if o.udpDebug {
			l4Protocol = "udp"
		}
		o.socket, err = o.transportCtx.Dial(l4Protocol, o.dstAddress, o, nil, nil, 0)
		if err != nil {
			o.stats.invalidSocket++
			return
		}
		if o.socket.GetCap()&transport.SocketCapConnection == 0 {
			// socket isn't connection oriented, we can start ticks
			o.timerw.StartTicks(&o.pktTimer, o.pktTicks)
		}
	}
}

// OnRxEvent function to complete the ISocketCb interface.
func (o *PluginTdlClient) OnRxEvent(event transport.SocketEventType) {

	if o.udpDebug {
		// In UDP we don't expect any event. Maybe we should panic!
		return
	}

	if (event & transport.SocketEventConnected) > 0 {
		// connection established, we can start timer
		o.timerw.StartTicks(&o.pktTimer, o.pktTicks)
	}

	if event&transport.SocketRemoteDisconnect > 0 {
		// remote disconnected before connection
		if o.pktTimer.IsRunning() {
			o.timerw.Stop(&o.pktTimer)
		}
		o.socket.Close()
	}

	if (event & transport.SocketClosed) > 0 {
		err := o.socket.GetLastError()
		if err != transport.SeOK {
			fmt.Printf("==> ERROR   %v \n", err.String())
		}
		o.socket = nil
	}

}

// OnRxData function to complete the ISocketCb interface.
func (o *PluginTdlClient) OnRxData(d []byte) {
	if !o.udpDebug {
		// TCP
		// TODO: Do something with the received data.
	}
	// UDP Debug, not Rx data expected
}

// OnTxEvent function
func (o *PluginTdlClient) OnTxEvent(event transport.SocketEventType) {
	// Depends if we are running TCP or UDP (debug)
	// TODO: Need to implement in case of TCP
}

// registerLuid registers a type and its Luid on its Luid map.
func (o *PluginTdlClient) registerLuid(luid LUID, typeName string) {
	if o.luidTypeMap == nil {
		o.luidTypeMap = make(map[LUID]string)
	}
	if _, ok := o.luidTypeMap[luid]; ok {
		o.stats.duplicateLuid++
		return
	}
	o.luidTypeMap[luid] = typeName
}

/*
	buildObjectInstance builds the object we are trying to send.

1. If the object is a primitive type then we have a trivial case.
2. Otherwise, the object is defined in metadata and shall be build using the instance constructor.
*/
func (o *PluginTdlClient) buildObjectInstance(obj TdlObject) error {
	if IsPrimitiveTdlType(obj.Type) {
		// primitive type
		o.objInstance = CreatePrimitiveTdlType(obj.Type)
	} else {
		// not primitive
		// Or it can be an array of predefined meta : FIXME - This is not supported yet.
		meta, ok := o.metaDataMgr.metaMap[obj.Type]
		if !ok {
			o.stats.invalidObjType++
			return fmt.Errorf("Object type %v is not primitive and not present in meta", obj.Type)
		}
		ctor, err := getTdlInstanceCtor(meta.GetType())
		if err != nil {
			o.stats.invalidObjType++
			return err
		}
		o.objInstance, err = ctor(meta)
		if err != nil {
			// This error is the one the caller increments
			return err
		}
	}
	return nil
}

// buildUnconstructedTypesMap builds the unconstructed types map.
func (o *PluginTdlClient) buildUnconstructedTypesMap(obj TdlObject) {
	if o.objInstance == nil {
		return
	}
	if !o.objInstance.IsConstructedType() {
		o.unconstructedTypes[obj.Name] = o.objInstance.(UnconstructedTdlTypeIF)
	} else {
		constructedObj := o.objInstance.(ConstructedTdlTypeIF)
		unconstructedTypes := constructedObj.GetUnconstructedTypes()
		for unconstructedType, value := range unconstructedTypes {
			o.unconstructedTypes[obj.Name+"."+unconstructedType] = value
		}
	}
}

// setInitialValues for all the unconstructed Tdl types.
func (o *PluginTdlClient) setInitialValues(initValues []UnconstructedTdlType) error {
	for i, _ := range initValues {
		absPath := initValues[i].AbsPath
		value := initValues[i].Value
		variable, ok := o.unconstructedTypes[absPath]
		if !ok {
			return fmt.Errorf("There is no such variable %v", absPath)
		}
		err := variable.SetValue(value)
		if err != nil {
			return err
		}
	}
	return nil
}

// updatePayload updates the L7 payload.
func (o *PluginTdlClient) updatePayload() error {
	o.payload = o.payload[:len(o.encodedHeader)] // remove old encoded object

	// Update all the unconstructed types
	for name, engine := range o.engineMap {
		unconstructedTdlType := o.unconstructedTypes[name]
		unconstructedTdlType.Update(engine)
	}

	// Then encode the new object
	encodedObj := make([]byte, o.objInstance.GetLength())
	err := o.objInstance.Encode(encodedObj)
	if err != nil {
		return err
	}
	o.payload = append(o.payload, encodedObj...)
	return nil
}

// sendPackets sends a TdlPacket
func (o *PluginTdlClient) sendPacket() {
	socketErr, _ := o.socket.Write(o.payload)
	if socketErr != transport.SeOK {
		o.stats.socketWriteError++
	} else {
		o.stats.pktsTx++
	}
}

// DumpTree dumps the json tree.
func (o *PluginTdlClient) DumpFormattedJson() {
	// FIXME: This is a hack to deep copy the map, since if we append it to
	// the sim record it will be appended by reference and when it is dumped
	// the values are not actual. Must find a better way to do this.
	copyMap := make(map[string]interface{})
	buf, _ := fastjson.Marshal(o.formattedJson)
	fastjson.Unmarshal(buf, &copyMap)
	o.Tctx.SimRecordAppend(copyMap)
}

/*
======================================================================================================

	Generate Plugin

======================================================================================================
*/
type PluginTdlCReg struct{}
type PluginTdlNsReg struct{}

func (o PluginTdlCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	return NewTdlClient(ctx, initJson)
}

func (o PluginTdlNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	// No Ns plugin for now.
	return nil, nil
}

/*
======================================================================================================

	RPC Methods

======================================================================================================
*/
type (
	ApiTdlClientCntHandler struct{}
)

// getClientPlugin gets the client plugin given the client parameters (Mac & Tunnel Key)
func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginTdlClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, TDL_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginTdlClient)

	return pClient, nil
}

// ApiTdlClientCntHandler gets the counters of the Tdl Client.
func (h ApiTdlClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return c.cdbv.GeneralCounters(err, tctx, params, &p)
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(TDL_PLUG,
		core.PluginRegisterData{Client: PluginTdlCReg{},
			Ns:     PluginTdlNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("tdl_c_cnt", ApiTdlClientCntHandler{}, false) // get counters / meta
}

func Register(ctx *core.CThreadCtx) {
	// In order for this plugin to be included in the EMU compilation one must provide this empty register
	// function. In case you remove the function call, then the core will not include EMU.
}
