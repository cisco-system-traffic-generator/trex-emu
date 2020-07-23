// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package ipfix

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	IPFIX_PLUG               = "ipfix" // IPFix Plugin name
	DefaultIPFixVersion      = 10      // Default Netflow Version
	DefaultIPFixSrcPort      = 30334   // Default Source Port
	DefaultIPFixDstPort      = 4739    // Default Destination Port
	DefaultIPFixTemplateRate = 1       // Template PPS
	DefaultIPFixDataRate     = 3       // Data PPS
)

// Simulation states true if simulation mode is on, using a global variable due to multiple access.
var Simulation bool

// IPFixField represent a IPFixField field which is a TLV (Type-Length-Value(data)) structure.
// This is used to parse the incoming JSON.
type IPFixField struct {
	Name             string `json:"name" validate:"required"`   // Name of this field
	Type             uint16 `json:"type" validate:"required"`   // Type of this field
	Length           uint16 `json:"length" validate:"required"` // Length of this field
	EnterpriseNumber uint32 `json:"enterprise_number"`          // Enterprise Number
	Data             []byte `json:"data" validate:"required"`   // Starting Data
}

// isVariableLength indicates if this field is variable length.
func (o *IPFixField) isVariableLength() bool {
	return o.Length == 0xFFFF
}

// getIPFixField returns a IPFixField is implemented in the layers package of Golang.
func (o *IPFixField) getIPFixField() layers.IPFixField {
	if o.isEnterprise() {
		return layers.IPFixField{Type: o.Type, Length: o.Length, Name: o.Name, EnterpriseNumber: o.EnterpriseNumber}
	}
	return layers.IPFixField{Type: o.Type, Length: o.Length, Name: o.Name}
}

// isEnterprise indicates if the IPFix Field is a IANA field (globally accepted) or an enterprise field.
func (o *IPFixField) isEnterprise() bool {
	if o.Type&0x8000 == 0 {
		// Enterprise Bit is 0.
		return false
	}
	// Enterprise bit is 1.
	return true
}

// IPFixGenParams represents the paramaters of an IPFix Generator and is used to parse the incoming JSON.
type IPFixGenParams struct {
	Name            string               `json:"name" validate:"required"`        // Name of the Generator
	AutoStart       bool                 `json:"auto_start"`                      // Start exporting this generator when plugin is loaded.
	DataRate        float32              `json:"rate_pps"`                        // Rate of data records in pps.
	RecordsNum      uint32               `json:"data_records_num"`                // Number of records in each data packet
	TemplateID      uint16               `json:"template_id" validate:"required"` // Template ID
	OptionsTemplate bool                 `json:"is_options_template"`             // Is Options Template or Data Template
	ScopeCount      uint16               `json:"scope_count"`                     // Scope Count for Option Templates, the number of fields that are scoped.
	Fields          []*IPFixField        `json:"fields" validate:"required"`      // Template Fields of this generator.
	Engines         *fastjson.RawMessage `json:"engines"`                         // Field Engines for the templates
}

// IPFixGen represents a fixed collection of fields which can change over time depending on the engines
// they are supplied. The generator generates Template and Data packets alike, given a rate for each one.
type IPFixGen struct {
	name                string              // Name of this generator.
	enabled             bool                // Is generator exporting at the moment.
	templateRate        float32             // Template rate in PPS.
	dataRate            float32             // Data rate in PPS.
	templateID          uint16              // Template ID.
	recordsNum          uint32              // Number of records in a packet as received from the user.
	recordsNumToSent    uint32              // Number of records to send in a packet.
	optionsTemplate     bool                // Is Options Template or Data Template
	scopeCount          uint16              // Scope Count for Option Templates, the number of fields that are scoped.
	dataTicks           uint32              // Ticks between 2 consequent Data Set packets.
	dataPktsPerInterval uint32              // How many data packets to send each interval
	templateTicks       uint32              // Ticks between 2 consequent Template Set packets.
	dataBuffer          []byte              // Data Buffer containing the field values.
	templatePkt         []byte              // A complete Template Packet.
	dataPkt             []byte              // A complete Data Packet from L2 to IPFix Data Sets (L7)
	fields              []*IPFixField       // IPFixFields as parsed from the JSON.
	templateFields      layers.IPFixFields  // IPFixFields in layers.
	fieldNames          map[string]bool     // Set of field names.
	engineMgr           *FieldEngineManager // Field Engine Manager
	dataTimer           core.CHTimerObj     // Timer for Data Set packets.
	templateTimer       core.CHTimerObj     // Timer for Template Set packets
	timerw              *core.TimerCtx      // Timer Wheel
	ipfixPlug           *PluginIPFixClient  // Pointer to the IPFixClient that owns this generator.
}

// NewIPFixGen creates a new IPFix generator (exporting process) based on the parameters received in the
// init JSON.
func NewIPFixGen(ipfix *PluginIPFixClient, initJson *fastjson.RawMessage) (*IPFixGen, bool) {

	init := IPFixGenParams{DataRate: DefaultIPFixDataRate, AutoStart: true}
	err := ipfix.Tctx.UnmarshalValidate(*initJson, &init)

	if err != nil {
		ipfix.stats.invalidJson++
		return nil, false
	}

	// validate fields aswell, not only outside Json.
	validator := ipfix.Tctx.GetJSONValidator()
	for i := range init.Fields {
		err = validator.Struct(init.Fields[i])
		if err != nil {
			ipfix.stats.invalidJson++
			return nil, false
		}
	}

	if _, ok := ipfix.generatorsMap[init.Name]; ok {
		ipfix.stats.duplicateGenName++
		return nil, false
	}

	if _, ok := ipfix.templateIDSet[init.TemplateID]; ok {
		ipfix.stats.duplicateTemplateID++
		return nil, false
	}

	if init.TemplateID <= 0xFF {
		ipfix.stats.invalidTemplateID++
		return nil, false
	}

	if init.OptionsTemplate && (init.ScopeCount == 0) {
		ipfix.stats.invalidScopeCount++
		return nil, false
	}

	o := new(IPFixGen)
	o.ipfixPlug = ipfix
	o.OnCreate()

	o.name = init.Name
	o.enabled = init.AutoStart
	o.templateID = init.TemplateID
	o.dataRate = init.DataRate
	o.recordsNum = init.RecordsNum
	o.optionsTemplate = init.OptionsTemplate
	o.scopeCount = init.ScopeCount
	o.fields = init.Fields
	// Create Engine Manager
	if init.Engines != nil {
		o.engineMgr = NewEngineManager(o.ipfixPlug.Tctx, init.Engines)
		if !o.engineMgr.WasCreatedSuccessfully() {
			o.ipfixPlug.stats.failedBuildingEngineMgr++
			return nil, false
		}
	}

	o.fieldNames = make(map[string]bool, len(o.fields))
	// Build Template Fields and Data Buffer.
	for i := range o.fields {
		if o.ipfixPlug.ver == 0x09 && o.fields[i].isEnterprise() {
			o.ipfixPlug.stats.enterpriseFieldv9++
			return nil, false
		}
		o.templateFields = append(o.templateFields, o.fields[i].getIPFixField())
		if len(o.fields[i].Data) != int(o.fields[i].Length) {
			ipfix.stats.dataIncorrectLength++
			return nil, false
		}
		o.fieldNames[o.fields[i].Name] = true // add each field to the field names
		o.dataBuffer = append(o.dataBuffer, o.fields[i].Data...)
	}

	// verify each engine name is a correct field
	if o.engineMgr != nil {
		for engineName, _ := range o.engineMgr.engines {
			if _, ok := o.fieldNames[engineName]; !ok {
				o.ipfixPlug.stats.invalidEngineName++
			}
		}
	}

	// Calculate Ticks for Timer.
	o.templateTicks = o.timerw.DurationToTicks(time.Duration(float32(time.Second) / o.templateRate))
	o.dataTicks, o.dataPktsPerInterval = o.timerw.DurationToTicksBurst(time.Duration(float32(time.Second) / o.dataRate))

	ok := o.prepareTemplatePkt()
	if !ok {
		return nil, false
	}
	// Preparing the data packet is not needed as SendPkt prepares it by itself. This packet changes every iteration.

	maxRecords := o.calcMaxRecords()

	if o.recordsNum == 0 || o.recordsNum > maxRecords {
		// number of records wasn't supplied or it is bigger then what the MTU allows.
		o.recordsNumToSent = maxRecords
	} else {
		o.recordsNumToSent = o.recordsNum
	}

	// Attempt to send the first packets inorder.
	o.sendTemplatePkt() // template packet
	o.sendDataPkt()     // data packet

	return o, true
}

// OnCreate initializes fields of the IPFixGen.
func (o *IPFixGen) OnCreate() {
	o.templateRate = DefaultIPFixTemplateRate
	o.timerw = o.ipfixPlug.timerw
	// Set Timer callbacks to this object's OnEvent(). However we need to differ between
	// the timers and hence the difference in the second parameter.
	o.templateTimer.SetCB(o, true, 0)
	o.dataTimer.SetCB(o, false, 0)
}

// OnRemove is called upon removing an IPFix Generator.
func (o *IPFixGen) OnRemove() {
	if o.templateTimer.IsRunning() {
		o.timerw.Stop(&o.templateTimer)
	}
	if o.dataTimer.IsRunning() {
		o.timerw.Stop(&o.dataTimer)
	}
}

// OnEvent sends a new packet every time it is called. It can be a template packet or a data packet.
func (o *IPFixGen) OnEvent(a, b interface{}) {
	var isTemplate bool
	switch v := a.(type) {
	case bool:
		isTemplate = v
	default:
		return
	}
	if isTemplate {
		o.sendTemplatePkt()
	} else {
		o.sendDataPkt()
	}

}

// calcMaxRecords calculate the maximum number of records we can send without overflowing the MTU.
// In case of variable length, each time the len of the flow changes, we need to calculate the maximum
// num of records again.
func (o *IPFixGen) calcMaxRecords() uint32 {
	recordLength := len(o.dataBuffer)                                  // length of 1 record.
	basePktLen := len(o.ipfixPlug.basePkt) - int(o.ipfixPlug.l3Offset) // length of packet L3-L4
	ipfixHeaderLen := layers.IpfixHeaderLenVer10
	if o.ipfixPlug.ver == 9 {
		ipfixHeaderLen = layers.IpfixHeaderLenVer9
	}

	allowed := o.ipfixPlug.Client.MTU - uint16(basePktLen+ipfixHeaderLen+4) // set header length is 4
	return uint32(allowed / uint16(recordLength))
}

/*======================================================================================================
										Send packet
======================================================================================================*/
// sendTemplatePkt sends a Template packet
func (o *IPFixGen) sendTemplatePkt() {
	o.ipfixPlug.trySettingDstMac()
	canSent := o.enabled && o.ipfixPlug.dstMacResolved
	if canSent {
		ipfixVer := o.ipfixPlug.ver
		pkt := o.templatePkt
		o.fixPkt(pkt)
		o.sendPkt(pkt)
		o.ipfixPlug.stats.pktTempSent++
		if ipfixVer == 9 {
			o.ipfixPlug.flowSeqNum++
		}
	}
	o.timerw.StartTicks(&o.templateTimer, o.templateTicks)
}

// sendDataPkt sends a burst of data packets (burst can be of size 1)
func (o *IPFixGen) sendDataPkt() {
	o.ipfixPlug.trySettingDstMac()
	canSent := o.enabled && o.ipfixPlug.dstMacResolved
	if canSent {
		ipfixVer := o.ipfixPlug.ver
		// Only Data Packets can have bursts.
		var mtuMissedRecords uint32
		if o.recordsNum > o.recordsNumToSent {
			mtuMissedRecords = o.recordsNum - o.recordsNumToSent
			o.ipfixPlug.stats.recordsMtuMissErr += uint64(mtuMissedRecords * o.dataPktsPerInterval)
		}
		o.ipfixPlug.stats.pktDataSent += uint64(o.dataPktsPerInterval)
		for i := 0; i < int(o.dataPktsPerInterval); i++ {
			o.prepareDataPkt()
			pkt := o.dataPkt
			o.fixPkt(pkt)
			o.sendPkt(pkt)
			// updating the flow sequence number must be inside the loop because fixPkt uses the value.
			if ipfixVer == 9 {
				o.ipfixPlug.flowSeqNum++
			} else if ipfixVer == 10 {
				o.ipfixPlug.flowSeqNum += o.recordsNumToSent
			}
		}
	}
	o.timerw.StartTicks(&o.dataTimer, o.dataTicks)
}

// fixPkt makes the differential fixes in each packet, like FlowSeq, Timestamp, Checksums, Length, etc.
func (o *IPFixGen) fixPkt(pkt []byte) {
	l3Offset := o.ipfixPlug.l3Offset
	l4Offset := o.ipfixPlug.l4Offset
	ipfixOffset := o.ipfixPlug.ipfixOffset
	ipfixVer := o.ipfixPlug.ver
	ipFixHeader := layers.IPFixHeader(pkt[ipfixOffset:])

	if ipfixVer == 10 {
		ipFixHeader.SetLength(uint16(len(pkt[ipfixOffset:])))
	}

	if ipfixVer == 9 {
		ipFixHeader.SetCount(uint16(o.recordsNumToSent))
		if !Simulation {
			ipFixHeader.SetSysUptime(o.ipfixPlug.sysUpTime)
		} else {
			ipFixHeader.SetSysUptime(0)
		}
	}
	ipFixHeader.SetFlowSeq(o.ipfixPlug.flowSeqNum)
	if !Simulation {
		ipFixHeader.SetTimestamp(uint32(o.ipfixPlug.unixTimeNow))
	}

	// L3 & L4 length & checksum fix
	binary.BigEndian.PutUint16(pkt[l4Offset+4:l4Offset+6], uint16(len(pkt[l4Offset:])))
	l3Len := uint16(len(pkt[l3Offset:]))
	isIpv6 := o.ipfixPlug.isIpv6

	if !isIpv6 {
		// IPv4 Packet
		ipv4 := layers.IPv4Header(pkt[l3Offset : l3Offset+20])
		ipv4.SetLength(l3Len)
		ipv4.UpdateChecksum()
		binary.BigEndian.PutUint16(pkt[l4Offset+6:l4Offset+8], 0)
	} else {
		// IPv6 Packet
		ipv6 := layers.IPv6Header(pkt[l3Offset : l3Offset+40])
		ipv6.SetPyloadLength(uint16(len(pkt[l4Offset:])))
		ipv6.FixUdpL4Checksum(pkt[l4Offset:], 0)
	}
}

// sendPkt sends an actual packet.
func (o *IPFixGen) sendPkt(pkt []byte) {
	m := o.ipfixPlug.Ns.AllocMbuf(uint16(len(pkt)))
	m.Append(pkt)
	o.ipfixPlug.Tctx.Veth.Send(m)
}

/*======================================================================================================
										Template Packets
======================================================================================================*/
// calcOptionLengthv9 calculates Option Scope Length and Option Length for Options Template v9 packets.
func (o *IPFixGen) calcOptionLengthv9() (optionScopeLength, optionLength uint16) {
	// Each field owns 4 bytes, 2 for Type and 2 for Length
	optionScopeLength = 4 * o.scopeCount
	optionLength = 4 * (uint16(len(o.templateFields)) - o.scopeCount)
	return optionScopeLength, optionLength
}

// getOptionsTemplateSets returns the Options-Template sets for sending Options-Template Set packets.
// This is the Sets part of TemplateSets L7.
func (o *IPFixGen) getOptionsTemplateSets() layers.IPFixSets {

	var optionsTemplateEntry layers.IPFixSetEntry
	var setID uint16

	if o.ipfixPlug.ver == 9 {
		setID = uint16(layers.IpfixOptionsTemplateSetIDVer9)
		optionScopeLength, optionLength := o.calcOptionLengthv9()
		optionsTemplateEntry = layers.NewIPFixOptionsTemplatev9(o.templateID, optionScopeLength, optionLength, o.templateFields)

	} else if o.ipfixPlug.ver == 10 {
		setID = uint16(layers.IpfixOptionsTemplateSetIDVer10)
		optionsTemplateEntry = layers.NewIPFixOptionsTemplatev10(o.templateID, o.scopeCount, o.templateFields)
	}
	return layers.IPFixSets{
		layers.IPFixSet{
			ID: setID,
			SetEntries: layers.IPFixSetEntries{
				layers.IPFixSetEntry(optionsTemplateEntry),
			},
		},
	}
}

// getDataTemplateSets returns the Data-Template sets for sending Data-Template Set packets.
// This is the Sets part of TemplateSets L7.
func (o *IPFixGen) getDataTemplateSets() layers.IPFixSets {

	templateEntry := layers.NewIPFixTemplate(o.templateID, o.templateFields)
	setID := uint16(layers.IpfixTemplateSetIDVer10)
	if o.ipfixPlug.ver == 9 {
		setID = layers.IpfixTemplateSetIDVer9
	}

	return layers.IPFixSets{
		layers.IPFixSet{
			ID: setID,
			SetEntries: layers.IPFixSetEntries{
				layers.IPFixSetEntry(templateEntry),
			},
		},
	}
}

// prepareTemplatePkt create the Template packet which is send by default each second to the collector.
// This packet teaches the controller how to read the data packets. Template packets can be Data-Templates
// or Option Templates.
func (o *IPFixGen) prepareTemplatePkt() bool {
	ipfixPlug := o.ipfixPlug
	var sets layers.IPFixSets
	if o.optionsTemplate {
		sets = o.getOptionsTemplateSets()
	} else {
		sets = o.getDataTemplateSets()
	}
	ipFixHeader := core.PacketUtlBuild(
		&layers.IPFix{
			Ver:       ipfixPlug.ver,
			SysUpTime: ipfixPlug.sysUpTime,
			SourceID:  ipfixPlug.domainID,
			FlowSeq:   ipfixPlug.flowSeqNum,
			DomainID:  ipfixPlug.domainID,
			Sets:      sets,
		},
	)
	o.templatePkt = append(ipfixPlug.basePkt, ipFixHeader...)

	templatePktLenNoL2 := len(o.templatePkt) - int(o.ipfixPlug.l3Offset) // length of packet L3-L7

	if templatePktLenNoL2 > int(o.ipfixPlug.Client.MTU) {
		o.ipfixPlug.stats.templatePktLongerThanMTU++
		return false
	}
	return true
}

/*======================================================================================================
										Data Packets
======================================================================================================*/
// updateDataBuffer updates the data buffer by running the different engines provided to the generator.
// It runs the engines *in order* with the order the fields were provided. If you provide the engines
// in the same order as the fields, they will run in order.
// The offset provided is relative to the beginning of the field.
func (o *IPFixGen) updateDataBuffer() {
	if o.engineMgr == nil {
		// Nothing to do
		return
	}
	currentOffset := 0
	for _, field := range o.fields {
		if eng, ok := o.engineMgr.engines[field.Name]; ok {
			b := o.dataBuffer[currentOffset:]
			eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
		}
		currentOffset += int(field.Length)
	}
}

// getDataSets creates the Sets for the Data outgoing packet.
func (o *IPFixGen) getDataSets() layers.IPFixSets {
	setEntries := make(layers.IPFixSetEntries, o.recordsNumToSent)
	for i := uint32(0); i < o.recordsNumToSent; i++ {
		o.updateDataBuffer()
		data := make([]byte, len(o.dataBuffer))
		copiedBytes := copy(data, o.dataBuffer)
		if copiedBytes != len(o.dataBuffer) {
			o.ipfixPlug.stats.badCopy++
		}
		setEntries[i] = layers.IPFixSetEntry(&layers.IPFixRecord{
			Data: data,
		})
	}
	return layers.IPFixSets{
		layers.IPFixSet{
			ID:         o.templateID,
			SetEntries: setEntries,
		},
	}
}

// getDataSets prepares the Data packet by generating the IPFix L7 Data and attaching the newly created
// L7 to the base packet created the IPFix Client Plugin.
func (o *IPFixGen) prepareDataPkt() {
	if o.dataPkt != nil {
		// Clear the Data Packet as we are about to create a new one.
		o.dataPkt = o.dataPkt[:0]
	}
	ipfixPlug := o.ipfixPlug
	sets := o.getDataSets()
	ipFixHeader := core.PacketUtlBuild(
		&layers.IPFix{
			Ver:       ipfixPlug.ver,
			SysUpTime: ipfixPlug.sysUpTime,
			SourceID:  ipfixPlug.domainID,
			FlowSeq:   ipfixPlug.flowSeqNum,
			DomainID:  ipfixPlug.domainID,
			Sets:      sets,
		},
	)

	o.dataPkt = append(ipfixPlug.basePkt, ipFixHeader...)
}

/*======================================================================================================
										RPC API for IPFixGen
======================================================================================================*/
// SetDataRate sets a new data rate through RPC.
func (o *IPFixGen) SetDataRate(rate float32) {
	o.dataRate = rate
	duration := time.Duration(float32(time.Second) / o.dataRate)
	o.dataTicks, o.dataPktsPerInterval = o.timerw.DurationToTicksBurst(duration)
	// Restart the timer.
	if o.dataTimer.IsRunning() {
		o.timerw.Stop(&o.dataTimer)
	}
	o.timerw.StartTicks(&o.dataTimer, o.dataTicks)
}

// GetInfo gets the generator information through RPC.
func (o *IPFixGen) GetInfo() *GenInfo {
	var i GenInfo

	i.Enabled = o.enabled
	i.RecordsNum = o.recordsNum
	i.RecordsNumSend = o.recordsNumToSent
	i.TemplateRate = o.templateRate
	i.DataRate = o.dataRate
	i.TemplateID = o.templateID
	i.FieldsNum = len(o.fields)
	if o.engineMgr != nil {
		i.EnginesNum = len(o.engineMgr.engines)
	} else {
		i.EnginesNum = 0
	}

	return &i
}

/*======================================================================================================
											IPFix Stats
======================================================================================================*/
// IPFixStats
type IPFixStats struct {
	pktTempSent              uint64 // How many Template packets sent.
	pktDataSent              uint64 // How many Data packets sent.
	templatePktLongerThanMTU uint64 // Template Packet Length is longer than MTU, hence we can't send Template packets or any packets for that matter.
	recordsMtuMissErr        uint64 // How many Data records dropped cause the record num is too big for MTU
	dataIncorrectLength      uint64 // Data entry of field is not the same as the length provided in the same field.
	invalidJson              uint64 // Json could not be unmarshalled or validated correctly.
	invalidParams            uint64 // Invalid init JSON params provided.
	failedCreatingGen        uint64 // Failed creating a generator with the generator's provided JSON.
	badCopy                  uint64 // Copying elements didn't complete succesfully.
	enterpriseFieldv9        uint64 // Enterprise Fields are not supported for V9.
	badOrNoInitJson          uint64 // Init Json was either not provided or invalid.
	unsuccessfulMacResolve   uint64 // Tried to resolve MAC of DG and failed.
	duplicateGenName         uint64 // Generator with the same name already registered.
	duplicateTemplateID      uint64 // Two generators with the same template ID.
	invalidTemplateID        uint64 // Invalid Template ID, smaller than 255.
	failedBuildingEngineMgr  uint64 // Failed Building Engine Manager with the provided JSON.
	invalidEngineName        uint64 // Invalid Engine Name. Engine name must be a field name.
	invalidScopeCount        uint64 // Invalid Scope Count, in case of Options Template user must specify a scope count > 0.
}

// NewIPFixStatsDb creates a IPFixStats database.
func NewIPFixStatsDb(o *IPFixStats) *core.CCounterDb {
	db := core.NewCCounterDb(IPFIX_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTempSent,
		Name:     "pktTempSent",
		Help:     "Template packets sent.",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktDataSent,
		Name:     "pktDataSent",
		Help:     "Data packets sent.",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.templatePktLongerThanMTU,
		Name:     "templatePktLongerThanMTU",
		Help:     "Template packet of a generator is longer than MTU.",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.recordsMtuMissErr,
		Name:     "recordsMtuMissErr",
		Help:     "Record left out because of low MTU value.",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.dataIncorrectLength,
		Name:     "dataIncorrectLength",
		Help:     "Data entry of field is not the same as the length provided in the same field.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidJson,
		Name:     "invalidJson",
		Help:     "Json could not be unmarshalled or validated correctly.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedCreatingGen,
		Name:     "failedCreatingGen",
		Help:     "Failed creating a new generator from the given JSON.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.badCopy,
		Name:     "badCopy",
		Help:     "Unsuccesful copy.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidParams,
		Name:     "invalidParams",
		Help:     "Invalid Init JSON Params provided.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.enterpriseFieldv9,
		Name:     "enterpriseFieldv9",
		Help:     "Enterpise field specified for Netflow v9 is not supported..",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.badOrNoInitJson,
		Name:     "badOrNoInitJson",
		Help:     "Init Json was either not provided or invalid.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.unsuccessfulMacResolve,
		Name:     "unsuccessfulMacResolve",
		Help:     "Tried to resolve MAC address of Default Gateway and failed.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.duplicateGenName,
		Name:     "duplicateGenName",
		Help:     "Generator with the same name already registered.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.duplicateTemplateID,
		Name:     "duplicateTemplateID",
		Help:     "Another generator has the same template ID. Can't have 2 generators with the same template ID.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidTemplateID,
		Name:     "invalidTemplateID",
		Help:     "Invalid template ID, template ID must be bigger than 255.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedBuildingEngineMgr,
		Name:     "failedBuildingEngineMgr",
		Help:     "Failed building engine manager with the provided JSON.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidEngineName,
		Name:     "invalidEngineName",
		Help:     "Invalid engine name. Engine name must be a field name.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidScopeCount,
		Name:     "invalidScopeCount",
		Help:     "Invalid scope count, in case of Options Template, scope count must be scecified and > 0.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

/*======================================================================================================
											IPFix Client
======================================================================================================*/

// IPFixClientParams defines the json structure for Ipfix plugin.
type IPFixClientParams struct {
	Ver        uint16                 `json:"netflow_version"`                // NetFlow version 9 or 10
	Ipv4       core.Ipv4Key           `json:"dst_ipv4"`                       // Collector IPv4 address
	Ipv6       core.Ipv6Key           `json:"dst_ipv6"`                       // Collector IPv6 address
	Mac        core.MACKey            `json:"dst_mac"`                        // Collector MAC address
	DstPort    uint16                 `json:"dst_port"`                       // Dst UDP port, Collector port
	SrcPort    uint16                 `json:"src_port"`                       // Source UDP port, Exporter port
	DomainID   uint32                 `json:"domain_id"`                      // Observation Domain ID
	Generators []*fastjson.RawMessage `json:"generators" validate:"required"` // Ipfix Generators (Template or Data)
}

// IPFixTimerCallback is an empty struct used as a callback for the timer which resolves the UnixTime.
// Because of the need to create a specific type of OnEvent for events in the Client struct, we need
// this struct for its OnEvent implementation
type IPFixTimerCallback struct{}

// PluginIPFixClient represents an IPFix client, someone that owns one or multiple exporting processes.
// Each IPFixGen is an exporting process.
type PluginIPFixClient struct {
	core.PluginBase                      // Plugin Base
	ver             uint16               // NetFlow version 9 or 10
	dstIpv4         core.Ipv4Key         // Collector IPv4 address
	dstIpv6         core.Ipv6Key         // Collector IPv6 address
	dstMac          core.MACKey          // Forced Collector MAC, not using DG Mac.
	dstPort         uint16               // Destination UDP port, Collector port
	srcPort         uint16               // Source UDP port, Exporter port
	sysStartTime    time.Time            // Start time of the system in order to calculate uptime.
	sysUpTime       uint32               // System Up Time (Only in Ver 9) in resolution of milliseconds.
	unixTimeNow     int64                // Unix Time Now for Unix Time in Header, should be on resolution of seconds.
	domainID        uint32               // Observation Domain ID
	flowSeqNum      uint32               // Flow sequence number must be common for all IPFix Gen.
	isIpv6          bool                 // True if dstIPv6 supplied
	dstMacResolved  bool                 // True if the destination MAC address is resolved.
	basePkt         []byte               // Base Pkt L2-L4
	l3Offset        uint16               // Offset to L3
	l4Offset        uint16               // Offset to L4
	ipfixOffset     uint16               // IPFix Offset
	timerw          *core.TimerCtx       // Timer Wheel
	timer           core.CHTimerObj      // Timer Object for calculating Unix time every tick
	timerCb         IPFixTimerCallback   // Timer Callback object
	stats           IPFixStats           // IPFix statistics
	cdb             *core.CCounterDb     // Counters Database
	cdbv            *core.CCounterDbVec  // Counters Database Vector
	generators      []*IPFixGen          // List of Generators
	generatorsMap   map[string]*IPFixGen // Generator Map for fast lookup with generator name.
	templateIDSet   map[uint16]bool      // Set of Template IDs.
}

var ipfixEvents = []string{}

// NewIPFixClient creates an IPFix client plugin. An IPFix client can own multiple generators
// (exporting processes).
func NewIPFixClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginIPFixClient)
	o.InitPluginBase(ctx, o)              /* init base object*/
	o.RegisterEvents(ctx, ipfixEvents, o) /* register events, only if they exist*/
	o.OnCreate()

	// Parse the Init JSON.
	init := IPFixClientParams{Ver: DefaultIPFixVersion, DstPort: DefaultIPFixDstPort, SrcPort: DefaultIPFixSrcPort,
		DomainID: o.domainID}
	err := o.Tctx.UnmarshalValidate(initJson, &init)

	if err != nil {
		o.stats.badOrNoInitJson++
		return &o.PluginBase
	}

	// Init Json was provided and successfuly unmarshalled.
	if (!init.Ipv4.IsZero() && !init.Ipv6.IsZero()) || (init.Ipv4.IsZero() && init.Ipv6.IsZero()) {
		o.stats.invalidParams++
		return &o.PluginBase
	}
	o.ver = init.Ver
	o.dstMac = init.Mac
	o.dstIpv4 = init.Ipv4
	if !init.Ipv6.IsZero() {
		o.dstIpv6 = init.Ipv6
		o.isIpv6 = true
	}
	o.dstPort = init.DstPort
	o.srcPort = init.SrcPort
	o.domainID = init.DomainID
	if len(init.Generators) > 0 {
		o.prepareBasePacket()
		o.generatorsMap = make(map[string]*IPFixGen, len(init.Generators))
		o.templateIDSet = make(map[uint16]bool, len(init.Generators))
		for i := range init.Generators {
			gen, ok := NewIPFixGen(o, init.Generators[i])
			if ok {
				o.generators = append(o.generators, gen)
				o.generatorsMap[gen.name] = gen
				o.templateIDSet[gen.templateID] = true
			} else {
				o.stats.failedCreatingGen++
			}
		}
	}

	return &o.PluginBase
}

// OnCreate is called upon creating a new IPFix client.
func (o *PluginIPFixClient) OnCreate() {

	// Domain ID will be randomly picked in case it is not provided.
	// Flow sequence number common to all generators is randomized.
	if !Simulation {
		o.domainID = rand.Uint32()
		o.flowSeqNum = rand.Uint32()
	} else {
		o.domainID = 0x87654321
		o.flowSeqNum = 0x12345678
	}
	// Timers
	o.timerw = o.Tctx.GetTimerCtx()
	o.sysStartTime = time.Now()
	o.unixTimeNow = o.sysStartTime.Unix()
	o.timer.SetCB(&o.timerCb, o, 0)
	// Every one tick update the time in order to have a good time difference.
	o.timerw.StartTicks(&o.timer, 1)
	// Create counters database and vector.
	o.cdb = NewIPFixStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec(IPFIX_PLUG)
	o.cdbv.Add(o.cdb)
}

// OnRemove is called when we are trying to remove this IPFix client.
func (o *PluginIPFixClient) OnRemove(ctx *core.PluginCtx) {
	ctx.UnregisterEvents(&o.PluginBase, ipfixEvents)
	// Stop Our Timer
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	// Remove Generators
	for _, gen := range o.generators {
		gen.OnRemove()
	}
}

// OnEvent callback of the IPFix client plugin.
func (o *PluginIPFixClient) OnEvent(msg string, a, b interface{}) {
}

// OnEvent callback of the IPFixTimerCallback
func (o *IPFixTimerCallback) OnEvent(a, b interface{}) {
	// a should be a pointer to the client plugin
	ipfixPlug := a.(*PluginIPFixClient)
	// Get the time now.
	timeNow := time.Now()
	// Calculate the uptime
	ipfixPlug.sysUpTime = uint32(timeNow.Sub(ipfixPlug.sysStartTime).Milliseconds())
	// Calculate the unix time
	ipfixPlug.unixTimeNow = timeNow.Unix()
	// Restart call
	ipfixPlug.timerw.StartTicks(&ipfixPlug.timer, 1)

}

// resolvedDstMac tries to resolve the destination MAC of the default gateway
// depending on IPv4 or IPv6 destination.
func (o *PluginIPFixClient) resolveDstMac() (mac core.MACKey, ok bool) {
	if !o.isIpv6 {
		mac, ok = o.Client.ResolveIPv4DGMac()
	} else {
		mac, ok = o.Client.ResolveIPv6DGMac()
	}
	return mac, ok
}

// trySettingDstMac tries resolving the dst mac and setting it in the base packet, or increments an error counter.
func (o *PluginIPFixClient) trySettingDstMac() {
	if !o.dstMacResolved {
		dstMac, ok := o.resolveDstMac()
		if ok {
			o.dstMacResolved = true
			layers.EthernetHeader(o.basePkt).SetDestAddress(dstMac[:])
		} else {
			o.stats.unsuccessfulMacResolve++
		}
	}

}

// prepareBasePacket prepares L2, L3, L4 of the IPfix packets.
// L7 is added later depending on the type of packet we want to send.
func (o *PluginIPFixClient) prepareBasePacket() {

	var l2Type layers.EthernetType
	if o.isIpv6 {
		l2Type = layers.EthernetTypeIPv6
	} else {
		l2Type = layers.EthernetTypeIPv4
	}

	// L2
	pkt := o.Client.GetL2Header(false, uint16(l2Type))
	layers.EthernetHeader(pkt).SetSrcAddress(o.Client.Mac[:])
	if !o.dstMac.IsZero() {
		// Forced MAC
		layers.EthernetHeader(pkt).SetDestAddress(o.dstMac[:])
		o.dstMacResolved = true
	} else {
		// Default Gateway MAC
		var dstMac core.MACKey
		dstMac, o.dstMacResolved = o.resolveDstMac()
		if o.dstMacResolved {
			layers.EthernetHeader(pkt).SetDestAddress(dstMac[:])
		} else {
			o.stats.unsuccessfulMacResolve++
		}
	}

	o.l3Offset = uint16(len(pkt))

	// L3
	var ipHeader []byte
	if !o.isIpv6 {
		ipHeader = core.PacketUtlBuild(
			&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc,
				SrcIP:    net.IP(o.Client.Ipv4[:]),
				DstIP:    net.IP(o.dstIpv4[:]),
				Protocol: layers.IPProtocolUDP})
	} else {
		ipHeader = core.PacketUtlBuild(
			&layers.IPv6{
				Version:      6,
				TrafficClass: 0,
				FlowLabel:    0,
				NextHeader:   layers.IPProtocolUDP,
				HopLimit:     255,
				SrcIP:        net.IP(o.Client.Ipv6[:]),
				DstIP:        net.IP(o.dstIpv6[:]),
			})
	}

	pkt = append(pkt, ipHeader...)
	o.l4Offset = uint16(len(pkt))

	// L4
	udpHeader := core.PacketUtlBuild(
		&layers.UDP{SrcPort: layers.UDPPort(o.srcPort),
			DstPort: layers.UDPPort(o.dstPort)})

	o.basePkt = append(pkt, udpHeader...)
	o.ipfixOffset = uint16(len(o.basePkt))
}

/*======================================================================================================
											Generate Plugin
======================================================================================================*/
type PluginIPFixCReg struct{}
type PluginIPFixNsReg struct{}

func (o PluginIPFixCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	Simulation = ctx.Tctx.Simulation // init simulation mode
	return NewIPFixClient(ctx, initJson)
}

func (o PluginIPFixNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	// No Ns plugin for now.
	return nil
}

/*======================================================================================================
											RPC Methods
======================================================================================================*/
type GenInfo struct {
	Enabled        bool    `json:"enabled"`              // Is generator enabled
	TemplateRate   float32 `json:"template_rate_pps"`    // Template Rate of Generator in PPs
	DataRate       float32 `json:"data_rate_pps"`        // Data Rate of Generator in PPS
	RecordsNum     uint32  `json:"data_records_num"`     // Number of records in packets as specified by user
	RecordsNumSend uint32  `json:"data_records_num_send` // Number of records in packets sent.
	TemplateID     uint16  `json:"template_id"`          // Template ID
	FieldsNum      int     `json:"fields_num"`           // Number of fields in each record
	EnginesNum     int     `json:"engines_num"`          // Numner of engines this generator has.
}

type (
	ApiIpfixClientCntHandler struct{}

	ApiIpfixClientSetGenStateHandler struct{}
	ApiIpfixClientSetGenStateParams  struct {
		GenName string  `json:"gen_name"`
		Enable  *bool   `json:"enable"`
		Rate    float32 `json:"rate"`
	}

	ApiIpfixClientGetGensInfoHandler struct{}
	ApiIpfixClientGetGensInfoParams  struct {
		GenNames []string `json:"gen_names"`
	}
	ApiIpfixClientGetGensInfoResult struct {
		GensInfos map[string]GenInfo `json:"generators_info"`
	}
)

// getClientPlugin gets the client plugin given the client parameters (Mac & Tunnel Key)
func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginIPFixClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, IPFIX_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginIPFixClient)

	return pClient, nil
}

// ApiIpfixClientCntHandler gets the counters of the IPFix Client.
func (h ApiIpfixClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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

// ApiIpfixClientSetGenStateHandler can set a generator to running or not and change its data rate.
func (h ApiIpfixClientSetGenStateHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiIpfixClientSetGenStateParams

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	tctx := ctx.(*core.CThreadCtx)
	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	gen, ok := c.generatorsMap[p.GenName]
	if !ok {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: fmt.Sprintf("Generator %s was not found.", p.GenName),
		}
	}

	if p.Enable != nil {
		gen.enabled = *p.Enable
	}
	if p.Rate > 0 {
		gen.SetDataRate(p.Rate)
	}

	return nil, nil
}

// ApiIpfixClientGetGensInfoHandler gets generator information.
func (h ApiIpfixClientGetGensInfoHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiIpfixClientGetGensInfoParams
	var res ApiIpfixClientGetGensInfoResult

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	tctx := ctx.(*core.CThreadCtx)
	err = tctx.UnmarshalValidate(*params, &p)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	res.GensInfos = make(map[string]GenInfo, len(p.GenNames))
	for _, genName := range p.GenNames {
		gen, ok := c.generatorsMap[genName]
		if !ok {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: fmt.Sprintf("Generator %s was not found.", genName),
			}
		}
		res.GensInfos[genName] = *gen.GetInfo()
	}

	return res, nil
}

func init() {

	/* register of plugins callbacks for ns,c level  */
	core.PluginRegister(IPFIX_PLUG,
		core.PluginRegisterData{Client: PluginIPFixCReg{},
			Ns:     PluginIPFixNsReg{},
			Thread: nil}) /* no need for thread context for now */

	/* The format of the RPC commands xxx_yy_zz_aa

	  xxx - the plugin name

	  yy  - ns - namespace
			c  - client
			t   -thread

	  zz  - cmd  command like ping etc
			set  set configuration
			get  get configuration/counters

	  aa - misc
	*/

	core.RegisterCB("ipfix_c_cnt", ApiIpfixClientCntHandler{}, false) // get counters / meta
	core.RegisterCB("ipfix_c_set_gen_state", ApiIpfixClientSetGenStateHandler{}, false)
	core.RegisterCB("ipfix_c_get_gens_info", ApiIpfixClientGetGensInfoHandler{}, false)
}
