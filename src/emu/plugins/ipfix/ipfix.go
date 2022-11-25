// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package ipfix

/*
NetFlow/IPFix is a feature that was introduced on Cisco routers around 1996 that provides the ability to collect IP network traffic as it enters or exits an interface.
By analyzing the data provided by NetFlow, a network administrator can determine things such as the source and destination of traffic, class of service, and the causes of congestion.
A typical flow monitoring setup (using NetFlow) consists of three main components:

* Flow exporter: aggregates packets into flows and exports flow records towards one or more flow collectors.
* Flow collector: responsible for reception, storage and pre-processing of flow data received from a flow exporter.
* Analysis application: analyzes received flow data in the context of intrusion detection or traffic profiling, for example.

TRex EMU emulates the aforementioned flow exporter for https://tools.ietf.org/html/rfc3954 Netflow v9, RFC 3954 and https://tools.ietf.org/html/rfc7011 Netflow v10 (IPFix), RFC 7011.
*/

import (
	"emu/core"
	engines "emu/plugins/field_engine"
	"emu/plugins/transport"
	"encoding/binary"
	"errors"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	IPFIX_PLUG               = "ipfix" // IPFix Plugin name
	DefaultIPFixVersion      = 10      // Default Netflow Version
	DefaultIPFixTemplateRate = 1       // Template PPS
	DefaultIPFixDataRate     = 3       // Data PPS
)

// Simulation states true if simulation mode is on, using a global variable due to multiple access.
var Simulation bool

// Package level init flag
var Init bool

// IPFixField represent a IPFixField field which is a TLV (Type-Length-Value(data)) structure.
// This is used to parse the incoming JSON.
type IPFixField struct {
	Name             string `json:"name" validate:"required"`   // Name of this field
	Type             uint16 `json:"type" validate:"required"`   // Type of this field
	Length           uint16 `json:"length" validate:"required"` // Length of this field
	EnterpriseNumber uint32 `json:"enterprise_number"`          // Enterprise Number
	Data             []byte `json:"data"`                       // Starting Data
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
	TemplateRate    float32              `json:"template_rate_pps"`               // Rate of template records in pps.
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
	name                   string                           // Name of this generator.
	enabled                bool                             // Is generator exporting at the moment.
	paused                 bool                             // Temporarily pause generator to avoid blocking
	templateRate           float32                          // Template rate in PPS.
	dataRate               float32                          // Data rate in PPS.
	templateID             uint16                           // Template ID.
	recordsNum             uint32                           // Number of records in a packet as received from the user.
	recordsNumToSent       uint32                           // Number of records to send in a packet.
	variableLengthFields   bool                             // Has variable length fields?
	optionsTemplate        bool                             // Is Options Template or Data Template
	scopeCount             uint16                           // Scope Count for Option Templates, the number of fields that are scoped.
	availableRecordPayload int                              // Available bytes for record payloads.
	maxPacketSize          int                              // Maximum packet size
	dataTicks              uint32                           // Ticks between 2 consequent Data Set packets.
	dataPktsPerInterval    uint32                           // How many data packets to send each interval
	templateTicks          uint32                           // Ticks between 2 consequent Template Set packets.
	dataBuffer             []byte                           // Data Buffer containing the field values.
	templatePayload        []byte                           // A L7 payload for template packets.
	dataPayload            []byte                           // A L7 payload for data packets.
	fields                 []*IPFixField                    // IPFixFields as parsed from the JSON.
	templateFields         layers.IPFixFields               // IPFixFields in layers.
	fieldNames             map[string]bool                  // Set of field names.
	engineMgr              *engines.FieldEngineManager      // Field Engine Manager
	engineMap              map[string]engines.FieldEngineIF // Map of engine name to field engine interface
	dataTimer              core.CHTimerObj                  // Timer for Data Set packets.
	templateTimer          core.CHTimerObj                  // Timer for Template Set packets
	timerw                 *core.TimerCtx                   // Timer Wheel
	ipfixPlug              *PluginIPFixClient               // Pointer to the IPFixClient that owns this generator.
}

// NewIPFixGen creates a new IPFix generator (exporting process) based on the parameters received in the
// init JSON.
func NewIPFixGen(ipfix *PluginIPFixClient, initJson *fastjson.RawMessage) (*IPFixGen, error) {

	init := IPFixGenParams{TemplateRate: DefaultIPFixTemplateRate, DataRate: DefaultIPFixDataRate, AutoStart: true}
	err := ipfix.Tctx.UnmarshalValidate(*initJson, &init)
	if err != nil {
		ipfix.stats.invalidJson++
		return nil, err
	}

	// validate fields as well, not only outside Json.
	validator := ipfix.Tctx.GetJSONValidator()
	for i := range init.Fields {
		err = validator.Struct(init.Fields[i])
		if err != nil {
			ipfix.stats.invalidJson++
			return nil, err
		}
	}

	if _, ok := ipfix.generatorsMap[init.Name]; ok {
		ipfix.stats.duplicateGenName++
		return nil, fmt.Errorf("duplicate generator name %s", init.Name)
	}

	if _, ok := ipfix.templateIDSet[init.TemplateID]; ok {
		ipfix.stats.duplicateTemplateID++
		return nil, fmt.Errorf("duplicate template ID %d", init.TemplateID)
	}

	if init.TemplateID <= 0xFF {
		ipfix.stats.invalidTemplateID++
		return nil, fmt.Errorf("invalid template ID %d", init.TemplateID)
	}

	if init.OptionsTemplate && (init.ScopeCount == 0) {
		ipfix.stats.invalidScopeCount++
		return nil, fmt.Errorf("invalid scope count %d", init.ScopeCount)
	}

	o := new(IPFixGen)
	o.ipfixPlug = ipfix
	o.OnCreate()

	o.name = init.Name
	o.enabled = init.AutoStart
	o.templateID = init.TemplateID
	o.templateRate = init.TemplateRate
	o.dataRate = init.DataRate
	o.recordsNum = init.RecordsNum
	o.optionsTemplate = init.OptionsTemplate
	o.scopeCount = init.ScopeCount
	o.fields = init.Fields

	// Create Engine Manager
	if init.Engines != nil {
		o.engineMgr, err = engines.NewEngineManager(o.ipfixPlug.Tctx, init.Engines)
		if err != nil {
			o.ipfixPlug.stats.failedBuildingEngineMgr++
			return nil, fmt.Errorf("could not create engine manager: %w", err)
		}
		o.engineMap = o.engineMgr.GetEngineMap()
	}

	o.fieldNames = make(map[string]bool, len(o.fields))
	// Build Template Fields and Data Buffer.
	for _, field := range o.fields {
		if o.ipfixPlug.ver == 9 && field.isEnterprise() {
			o.ipfixPlug.stats.enterpriseFieldv9++
			return nil, fmt.Errorf("NetFlow version 9 does not support enterprise field %s", field.Name)
		}
		if o.ipfixPlug.ver == 9 && field.isVariableLength() {
			o.ipfixPlug.stats.variableLengthFieldv9++
			return nil, fmt.Errorf("NetFlow version 9 does not support var len field %s", field.Name)
		}
		o.templateFields = append(o.templateFields, field.getIPFixField())
		if !field.isVariableLength() && (len(field.Data) != int(field.Length)) {
			ipfix.stats.dataIncorrectLength++
			return nil, fmt.Errorf("Field %s data size differs from declared field length %d", field.Name, field.Length)
		}
		o.fieldNames[field.Name] = true // add each field to the field names
		if !field.isVariableLength() {
			// don't add variable length fields to the data buffer, they don't have a data buffer.
			o.dataBuffer = append(o.dataBuffer, field.Data...)
		} else {
			o.variableLengthFields = true
			// variable length field, verify that no data.
			if len(field.Data) != 0 {
				ipfix.stats.dataIncorrectLength++
				return nil, fmt.Errorf("variable length field %s has data", field.Name)
			}
			// also we must have an engine for variable length fields
			if o.engineMgr == nil {
				ipfix.stats.variableLengthNoEngine++
				return nil, fmt.Errorf("No engine for var len field %s", field.Name)
			} else {
				if _, ok := o.engineMap[field.Name]; !ok {
					ipfix.stats.variableLengthNoEngine++
					return nil, fmt.Errorf("No engine for var len field %s", field.Name)
				}
			}
		}
	}

	// verify each engine name is a correct field
	if o.engineMgr != nil {
		for engineName := range o.engineMap {
			if _, ok := o.fieldNames[engineName]; !ok {
				o.ipfixPlug.stats.invalidEngineName++
				return nil, fmt.Errorf("Got engine for unexisting field %s", engineName)
			}
		}
	}

	// Calculate Ticks for Timer.
	o.templateTicks = o.timerw.DurationToTicks(time.Duration(float32(time.Second) / o.templateRate))
	o.dataTicks, o.dataPktsPerInterval = o.timerw.DurationToTicksBurst(time.Duration(float32(time.Second) / o.dataRate))

	if o.ipfixPlug.dgMacResolved {
		// If resolved before the generators were created, we call on resolve explicitly.
		if ok := o.OnResolve(); !ok {
			return nil, fmt.Errorf("could not resolve DG")
		}
	}

	return o, nil
}

func (o *IPFixGen) Pause(pause bool) {
	o.paused = pause

	if pause {
		rate := o.dataRate
		o.SetDataRate(0)
		o.dataRate = rate

		rate = o.templateRate
		o.SetTemplateRate(0)
		o.templateRate = rate
	} else {
		o.SetDataRate(o.dataRate)
		o.SetTemplateRate(o.templateRate)
	}
}

// OnCreate initializes fields of the IPFixGen.
func (o *IPFixGen) OnCreate() {
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
	if o.ipfixPlug.enabled == false {
		return
	}

	if o.ipfixPlug.maxTime > 0 {
		enabledDuration := time.Since(o.ipfixPlug.enabledTime)
		if enabledDuration >= o.ipfixPlug.maxTime {
			o.ipfixPlug.Enable(false)
			return
		}
	}

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

func (o *IPFixGen) getMaxPacketSize() int {
	maxPacketSize := o.ipfixPlug.exporter.GetMaxSize()

	// IPFIX packet length field is uint16
	if maxPacketSize > math.MaxUint16 {
		maxPacketSize = math.MaxUint16
	}

	return maxPacketSize
}

// OnResolve is called when the client successfully resolves the mac address of the default gateway
// and we can create a socket.
func (o *IPFixGen) OnResolve() bool {
	o.maxPacketSize = o.getMaxPacketSize()

	o.calcAvailableRecordPayload()
	var maxRecords uint32

	if !o.variableLengthFields {
		// in case we are working with fixed size records we know ahead of time how many records we can send.
		maxRecords = o.calcMaxRecords()
	} else {
		// Upper bound on the maximum number of records
		maxRecords = o.calcMaxRecordsVarLength()
	}

	if o.recordsNum == 0 || o.recordsNum > maxRecords {
		// number of records wasn't supplied or it is bigger then what the MTU allows.
		o.recordsNumToSent = maxRecords
	} else {
		o.recordsNumToSent = o.recordsNum
	}

	ok := o.prepareTemplatePayload()
	if !ok {
		return false
	}
	// Preparing the data payload is not needed as SendPkt prepares it by itself. This packet changes every iteration.

	return true
}

// calcAvailableRecordPayload calculates the amount of bytes available for record payloads.
func (o *IPFixGen) calcAvailableRecordPayload() {
	ipfixHeaderLen := layers.IpfixHeaderLenVer10
	if o.ipfixPlug.ver == 9 {
		ipfixHeaderLen = layers.IpfixHeaderLenVer9
	}
	o.availableRecordPayload = o.maxPacketSize - (ipfixHeaderLen + 4) // set header length is 4
}

// calcShortestRecord calculates the length of the shortest possible record in case of variable length.
func (o *IPFixGen) calcShortestRecord() (length int) {
	if !o.variableLengthFields {
		length = len(o.dataBuffer)
	} else {
		length = len(o.dataBuffer)
		for i := range o.fields {
			if o.fields[i].isVariableLength() {
				length += 1 // one for each variable length
			}
		}
	}
	return length
}

// calcLongestRecord calculates the length of the longest possible record in case of variable length.
func (o *IPFixGen) calcLongestRecord() (length int) {
	if !o.variableLengthFields {
		length = len(o.dataBuffer)
	} else {
		length = len(o.dataBuffer)
		for i := range o.fields {
			if o.fields[i].isVariableLength() {
				eng := o.engineMap[o.fields[i].Name]
				length += int(eng.GetSize()) // Size is the upper limit.
			}
		}
	}
	return length
}

// calcMaxRecords calculate the maximum number of records we can send without overflowing the MTU.
// This function should be called only on generators that don't contain variable length fields.
func (o *IPFixGen) calcMaxRecords() uint32 {
	recordLength := len(o.dataBuffer) // length of 1 record.
	return uint32(o.availableRecordPayload / recordLength)
}

// calcMaxRecordsVarLength calculates the maximum number of records we can send in case of variable length.
// This is an upper bound and not exactly the number we can send.
func (o *IPFixGen) calcMaxRecordsVarLength() uint32 {
	return uint32(o.availableRecordPayload / o.calcShortestRecord())
}

/*
======================================================================================================

	Send packet

======================================================================================================
*/
func (o *IPFixGen) sendTemplatePktInt() {
	ipfixVer := o.ipfixPlug.ver
	payload := o.templatePayload
	o.fixPayload(payload)

	_, err := o.ipfixPlug.exporter.Write(payload, 1, 0)
	if err != nil {
		o.ipfixPlug.stats.exporterWriteError++
	} else {
		o.ipfixPlug.stats.pktTempSent++
		o.ipfixPlug.stats.recordsTempSent++
		if ipfixVer == 9 {
			o.ipfixPlug.flowSeqNum++
		}
	}
}

func (o *IPFixGen) isReachedMaxTempRecordsToSend() bool {
	var isReachedMaxTempRecordsToSend bool

	if o.ipfixPlug.stats.maxTempRecordsToSend > 0 {
		isReachedMaxTempRecordsToSend = o.ipfixPlug.stats.recordsTempSent >= o.ipfixPlug.stats.maxTempRecordsToSend
	}

	return isReachedMaxTempRecordsToSend
}

// sendTemplatePkt sends a Template packet
func (o *IPFixGen) sendTemplatePkt() {
	if o.isReachedMaxTempRecordsToSend() {
		// Max tx template records reached - stop sending template records.
		return
	}

	isSend := o.enabled && !o.paused
	if isSend {
		o.sendTemplatePktInt()
	}

	if o.paused {
		o.ipfixPlug.stats.genPausedSkipWrite++
	} else {
		o.timerw.StartTicks(&o.templateTimer, o.templateTicks)
	}
}

func (o *IPFixGen) isReachedMaxDataRecordsToSend() bool {
	var isReachedMaxDataRecordsToSend bool

	if o.ipfixPlug.stats.maxDataRecordsToSend > 0 {
		isReachedMaxDataRecordsToSend = o.ipfixPlug.stats.recordsDataSent >= o.ipfixPlug.stats.maxDataRecordsToSend
	}

	return isReachedMaxDataRecordsToSend
}

func (o *IPFixGen) sendDataPktInt() {
	ipfixVer := o.ipfixPlug.ver
	records := o.prepareDataPayload()
	payload := o.dataPayload
	o.fixPayload(payload)

	_, err := o.ipfixPlug.exporter.Write(payload, 0, records)
	if err != nil {
		o.ipfixPlug.stats.exporterWriteError++
	} else {
		o.ipfixPlug.stats.pktDataSent++
		o.ipfixPlug.stats.recordsDataSent += uint64(records)

		// updating the flow sequence number must be inside the loop because fixPayload uses the value.
		if ipfixVer == 9 {
			o.ipfixPlug.flowSeqNum++
		} else if ipfixVer == 10 {
			o.ipfixPlug.flowSeqNum += records
		}
		if o.recordsNum > records && !o.isReachedMaxDataRecordsToSend() {
			mtuMissedRecords := o.recordsNum - records
			o.ipfixPlug.stats.recordsMtuMissErr += uint64(mtuMissedRecords)
		}
	}
}

// sendDataPkt sends a burst of data packets (burst can be of size 1)
func (o *IPFixGen) sendDataPkt() {
	var restartTimer = true

	if o.enabled {
		// Only Data Packets can have bursts.
		for i := 0; i < int(o.dataPktsPerInterval); i++ {
			if o.paused {
				o.ipfixPlug.stats.genPausedSkipWrite++
				restartTimer = false
				break
			}

			if o.isReachedMaxDataRecordsToSend() {
				// Max tx data records reached - no need to restart data timer.
				restartTimer = false
				break
			}

			o.sendDataPktInt()
		}
	}

	if restartTimer {
		o.timerw.StartTicks(&o.dataTimer, o.dataTicks)
	}
}

// fixPayload makes the differential fixes in each packet, like FlowSeq, Timestamp, Length, etc.
func (o *IPFixGen) fixPayload(pkt []byte) {
	ipfixVer := o.ipfixPlug.ver
	ipFixHeader := layers.IPFixHeader(pkt)

	if ipfixVer == 10 {
		ipFixHeader.SetLength(uint16(len(pkt)))
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
		ipFixHeader.SetTimestamp(uint32(o.ipfixPlug.unixUtcTimeNow))
	}
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

// prepareTemplatePayload create the Template packet which is send by default each second to the collector.
// This packet teaches the controller how to read the data packets. Template packets can be Data-Templates
// or Option Templates.
func (o *IPFixGen) prepareTemplatePayload() bool {
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
	if len(ipFixHeader) > o.maxPacketSize {
		o.ipfixPlug.stats.templatePktLongerThanMTU++
		return false
	}

	o.templatePayload = ipFixHeader
	return true
}

/*======================================================================================================
										Data Packets
======================================================================================================*/
// encodeVarLengthData encodes the payload of a variable length (information element, ie) field when
// length represents the length of this information element
func (o *IPFixGen) encodeVarLengthData(length int, ie []byte) (data []byte) {
	/*
		In most cases, the length of the Information Element will be less
		than 255 octets.  The following length-encoding mechanism optimizes
		the overhead of carrying the Information Element length in this more
		common case.  The length is carried in the octet before the
		Information Element, as shown in Figure R.

		 0                    1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		| Length (< 255)|          Information Element                  |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                      ... continuing as needed                 |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			Figure R: Variable-Length Information Element (IE)
						(Length < 255 Octets)

		The length may also be encoded into 3 octets before the Information
		Element, allowing the length of the Information Element to be greater
		than or equal to 255 octets.  In this case, the first octet of the
		Length field MUST be 255, and the length is carried in the second and
		third octets, as shown in Figure S.

		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|      255      |      Length (0 to 65535)      |       IE      |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                      ... continuing as needed                 |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			Figure S: Variable-Length Information Element (IE)
					(Length 0 to 65535 Octets)

		The octets carrying the length (either the first or the first
		three octets) MUST NOT be included in the length of the Information
		Element.
	*/
	if length < 0xFF {
		data = append(data, uint8(length))
	} else {
		data = append(data, 0xFF)
		lengthBuffer := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuffer, uint16(length))
		data = append(data, lengthBuffer...)
	}
	data = append(data, ie[:length]...)
	return data
}

// getDataRecords updates the data buffer by running the different engines provided to the generator.
// Also it runs the variable length engines on variable length fields which are not part of the data buffer.
// Returns the Data Record buffer as it should be put in the payload.
// It runs the engines *in order* with the order the fields were provided. If you provide the engines
// in the same order as the fields, they will run in order.
// The offset provided is relative to the beginning of the field.
func (o *IPFixGen) getDataRecord() (data []byte) {
	if o.engineMgr == nil {
		// Nothing to do, no engines and no variable length fields.
		// Pre calculated data buffer is enough.
		return o.dataBuffer
	}
	currentOffset := 0
	for _, field := range o.fields {
		if eng, ok := o.engineMap[field.Name]; ok {
			// field has engine
			if field.isVariableLength() {
				// variable length fields are not part of the data buffer
				buffer := make([]byte, eng.GetSize())
				length, _ := eng.Update(buffer)
				data = append(data, o.encodeVarLengthData(length, buffer)...)
			} else {
				b := o.dataBuffer[currentOffset:]
				eng.Update(b[eng.GetOffset() : eng.GetOffset()+eng.GetSize()])
			}
		}
		if !field.isVariableLength() {
			data = append(data, o.dataBuffer[currentOffset:currentOffset+int(field.Length)]...)
			currentOffset += int(field.Length)
		}
	}
	return data
}

// getDataSets creates the Sets for the Data outgoing packet.
func (o *IPFixGen) getDataSets() (layers.IPFixSets, uint32) {
	var setEntries layers.IPFixSetEntries
	availablePayload := o.availableRecordPayload
	longestRecord := o.calcLongestRecord()

	recordsNumToSend := o.recordsNumToSent
	if o.ipfixPlug.stats.maxDataRecordsToSend > 0 {
		recordsNumToSend = uint32(math.Min(float64(o.recordsNumToSent),
			float64(o.ipfixPlug.stats.maxDataRecordsToSend-o.ipfixPlug.stats.recordsDataSent)))
	}

	for i := uint32(0); i < recordsNumToSend; i++ {
		if availablePayload < longestRecord {
			// in case we don't have variable length fields this shouldn't happen
			break
		} else {
			data := o.getDataRecord()
			availablePayload -= len(data)
			setEntries = append(setEntries, layers.IPFixSetEntry(&layers.IPFixRecord{Data: data}))
		}
	}
	return layers.IPFixSets{
		layers.IPFixSet{
			ID:         o.templateID,
			SetEntries: setEntries,
		},
	}, uint32(len(setEntries))
}

// prepareDataPayload prepares the Data packet by generating the IPFix L7 Data and attaching the newly created
// L7 to the base packet created the IPFix Client Plugin.
// Returns the number of records it added to the data set.
func (o *IPFixGen) prepareDataPayload() (records uint32) {
	if o.dataPayload != nil {
		// Clear the Data Payload as we are about to create a new one.
		o.dataPayload = o.dataPayload[:0]
	}
	ipfixPlug := o.ipfixPlug
	sets, records := o.getDataSets()
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

	o.dataPayload = ipFixHeader
	return records
}

/*======================================================================================================
										RPC API for IPFixGen
======================================================================================================*/

func (o *IPFixGen) Enable(enable bool) {
	o.enabled = enable
}

// SetDataRate sets a new data rate through RPC.
func (o *IPFixGen) SetDataRate(rate float32) {
	o.dataRate = rate

	if o.paused {
		return
	}

	duration := time.Duration(float32(time.Second) / o.dataRate)
	o.dataTicks, o.dataPktsPerInterval = o.timerw.DurationToTicksBurst(duration)

	// Restart the timer.
	if o.dataTimer.IsRunning() {
		o.timerw.Stop(&o.dataTimer)
		o.timerw.StartTicks(&o.dataTimer, o.dataTicks)
	}
}

// SetTemplateRate sets a new template rate through RPC.
func (o *IPFixGen) SetTemplateRate(rate float32) {
	o.templateRate = rate

	if o.paused {
		return
	}

	o.templateTicks = o.timerw.DurationToTicks(time.Duration(float32(time.Second) / o.templateRate))

	// Restart the timer.
	if o.templateTimer.IsRunning() {
		o.timerw.Stop(&o.templateTimer)
		o.timerw.StartTicks(&o.templateTimer, o.templateTicks)
	}
}

// GetInfo gets the generator information through RPC.
func (o *IPFixGen) GetInfo() *GenInfo {
	var i GenInfo

	i.Enabled = o.enabled
	i.OptionsTemplate = o.optionsTemplate
	i.ScopeCount = o.scopeCount
	i.RecordsNum = o.recordsNum
	i.RecordsNumSend = o.recordsNumToSent
	i.TemplateRate = o.templateRate
	i.DataRate = o.dataRate
	i.TemplateID = o.templateID
	i.FieldsNum = len(o.fields)
	if o.engineMgr != nil {
		i.EnginesNum = len(o.engineMap)
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
	pktTempSent                           uint64 // How many Template packets sent.
	pktDataSent                           uint64 // How many Data packets sent.
	recordsTempSent                       uint64 // Number of template records sent.
	recordsDataSent                       uint64 // Number of data records sent.
	maxTempRecordsToSend                  uint64 // Maximum number of temp records to send by the client (0 - no limit)
	maxDataRecordsToSend                  uint64 // Maximum number of data records to send by the client (0 - no limit)
	templatePktLongerThanMTU              uint64 // Template Packet Length is longer than MTU, hence we can't send Template packets or any packets for that matter.
	recordsMtuMissErr                     uint64 // How many Data records dropped cause the record num is too big for MTU
	dataIncorrectLength                   uint64 // Data entry of field is not the same as the length provided in the same field.
	failedCreatingExporter                uint64 // Failed creating a new exporter
	failedCreatingExporterWrongKernelMode uint64 // Failed creating a new exporter since kernel mode is wrong
	exporterWriteError                    uint64 // Error writing to exporter
	genPausedSkipWrite                    uint64 // Num of write skips when generator is paused to avoid exporter blocking
	invalidJson                           uint64 // Json could not be unmarshalled or validated correctly.
	invalidDst                            uint64 // Invalid Dst provided.
	failedCreatingGen                     uint64 // Failed creating a generator with the generator's provided JSON.
	enterpriseFieldv9                     uint64 // Enterprise Fields are not supported for V9.
	variableLengthFieldv9                 uint64 // Variable length Fields are not supported for V9.
	variableLengthNoEngine                uint64 // Variable length field without engine provided.
	badOrNoInitJson                       uint64 // Init Json was either not provided or invalid.
	duplicateGenName                      uint64 // Generator with the same name already registered.
	duplicateTemplateID                   uint64 // Two generators with the same template ID.
	invalidTemplateID                     uint64 // Invalid Template ID, smaller than 255.
	failedBuildingEngineMgr               uint64 // Failed Building Engine Manager with the provided JSON.
	invalidEngineName                     uint64 // Invalid Engine Name. Engine name must be a field name.
	invalidScopeCount                     uint64 // Invalid Scope Count, in case of Options Template user must specify a scope count > 0.
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
		Counter:  &o.recordsTempSent,
		Name:     "recordsTempSent",
		Help:     "Template records sent.",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.recordsDataSent,
		Name:     "recordsDataSent",
		Help:     "Data records sent.",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.maxTempRecordsToSend,
		Name:     "maxTempRecordsToSend",
		Help:     "Max num of temp records to send (0 - no limit).",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.maxDataRecordsToSend,
		Name:     "maxDataRecordsToSend",
		Help:     "Max num of data records to send (0 - no limit).",
		Unit:     "records",
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
		Help:     "Field data of invalid length.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedCreatingExporter,
		Name:     "failedCreatingExporter",
		Help:     "Failure creating a new exporter based on init JSON.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.failedCreatingExporterWrongKernelMode,
		Name:     "failedCreatingExporterWrongKernelMode",
		Help:     "Failure creating a new exporter since kernel mode is wrong.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.exporterWriteError,
		Name:     "exporterWriteError",
		Help:     "Error writing to exporter.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.genPausedSkipWrite,
		Name:     "genPausedSkipWrite",
		Help:     "Num of write skips when generator is paused to avoid exporter blocking.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidJson,
		Name:     "invalidJson",
		Help:     "JSON could not be unmarshalled or validated correctly.",
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
		Counter:  &o.invalidDst,
		Name:     "invalidDst",
		Help:     "Invalid destination provided.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.enterpriseFieldv9,
		Name:     "enterpriseFieldv9",
		Help:     "Enterpise fields not supported in Netflow v9.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.variableLengthFieldv9,
		Name:     "variableLengthFieldv9",
		Help:     "Variable length fields not supported in Netflow v9.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.variableLengthNoEngine,
		Name:     "variableLengthNoEngine",
		Help:     "Variable length field without engine provided.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.badOrNoInitJson,
		Name:     "badOrNoInitJson",
		Help:     "Init JSON was either not provided or invalid.",
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
		Help:     "Duplicate template ID. Can't have 2 generators with the same template ID.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidTemplateID,
		Name:     "invalidTemplateID",
		Help:     "Invalid template ID. Template ID must be bigger than 255.",
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
		Help:     "Invalid scope count. Options template have scope counts > 0.",
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
	Ver            uint16                 `json:"netflow_version"`                // NetFlow version 9 or 10
	Dst            string                 `json:"dst" validate:"required"`        // Destination Address. Combination of Host:Port.
	DomainID       uint32                 `json:"domain_id"`                      // Observation Domain ID
	MaxDataRecords uint64                 `json:"max_data_records"`               // Max number of data records to send (0 - no limit)
	MaxTempRecords uint64                 `json:"max_template_records"`           // Max number of template records to send (0 - no limit)
	MaxTime        Duration               `json:"max_time"`                       // Max time to export records (0 - no limit)
	AutoStart      bool                   `json:"auto_start"`                     // Start exporting this client when plugin is loaded (default: true)
	ExporterParams *fastjson.RawMessage   `json:"exporter_params"`                // Exporter parameters
	Generators     []*fastjson.RawMessage `json:"generators" validate:"required"` // Ipfix Generators (Template or Data)
}

// IPFixTimerCallback is an empty struct used as a callback for the timer which resolves the UnixTime.
// Because of the need to create a specific type of OnEvent for events in the Client struct, we need
// this struct for its OnEvent implementation
type IPFixTimerCallback struct{}

// PluginIPFixClient represents an IPFix client, someone that owns one or multiple exporting processes.
// Each IPFixGen is an exporting process.
type PluginIPFixClient struct {
	core.PluginBase                               // Plugin Base
	ver             uint16                        // NetFlow version 9 or 10
	dstUrl          url.URL                       // Destination URL.
	isIpv6          bool                          // Is destination address IPv6 or IPv4 address
	sysStartTime    time.Time                     // Start time of the system in order to calculate uptime.
	sysUpTime       uint32                        // System Up Time (Only in Ver 9) in resolution of milliseconds.
	unixUtcTimeNow  int64                         // Unix Time Now for Unix Time in Header, should be on resolution of seconds.
	domainID        uint32                        // Observation Domain ID
	autoStart       bool                          // Start exporting this client when plugin is loaded (default: true)
	maxTime         time.Duration                 // Maximum time to export
	enabledTime     time.Time                     // Time when client was enabled
	flowSeqNum      uint32                        // Flow sequence number must be common for all IPFix Gen.
	dgMacResolved   bool                          // Is the default gateway MAC address resolved?
	timerw          *core.TimerCtx                // Timer Wheel
	timer           core.CHTimerObj               // Timer Object for calculating Unix time every tick
	timerCb         IPFixTimerCallback            // Timer Callback object
	stats           IPFixStats                    // IPFix statistics
	cdb             *core.CCounterDb              // Counters Database
	cdbv            *core.CCounterDbVec           // Counters Database Vector
	generators      []*IPFixGen                   // List of Generators
	generatorsMap   map[string]*IPFixGen          // Generator Map for fast lookup with generator name.
	templateIDSet   map[uint16]bool               // Set of Template IDs.
	exporter        Exporter                      // Factory class to create and store exporters based on the given dst URL
	init            bool                          // Is client initialization succeeded
	enabled         bool                          // Flows generations is enabled for the client
	IpfixNsPlugin   *IpfixNsPlugin                // Reference to the namespace IPFIX plugin if exists
	autoTriggered   bool                          // Client was auto triggered by the namespace plugin
	trgDeviceInfo   *DevicesAutoTriggerDeviceInfo // Auto triggered device info
}

var ipfixEvents = []string{core.MSG_DG_MAC_RESOLVED}

func isSupportedUrlScheme(scheme string) bool {
	switch scheme {
	case "emu-udp", "udp", "file", "http", "https":
		return true
	default:
	}

	return false
}

func parseDstField(dstField string) (*url.URL, bool, error) {
	var err error
	var dstUrl *url.URL
	var isHostPort = false
	var isUrl = false
	var isIpv6 = false

	// Replace template strings with valid escape characters.
	dstField = strings.Replace(dstField, dstUrlTenantIdTemplateStr, dstUrlTenantIdEscapeChar, 1)
	dstField = strings.Replace(dstField, dstUrlSiteIdTemplateStr, dstUrlSiteIdEscapeChar, 1)
	dstField = strings.Replace(dstField, dstUrlDeviceIdTemplateStr, dstUrlDeviceIdEscapeChar, 1)

	if dstUrl, err = url.Parse(dstField); err == nil {
		// dstField is a valid URL with a scheme
		isUrl = true
	}

	if !isUrl {
		if _, _, err = net.SplitHostPort(dstField); err == nil {
			//dstField is a valid host or host:port
			isHostPort = true
			dstUrl = new(url.URL)
			// Default URL scheme is emu-udp (udp based on emu's udp transport layer)
			dstUrl.Scheme = "emu-udp"
			dstUrl.Host = dstField
		}
	}

	if !isHostPort && !isUrl {
		return nil, false, errors.New("Invalid dst URL or HostPort field in init JSON")
	}

	if !isSupportedUrlScheme(dstUrl.Scheme) {
		return nil, false, fmt.Errorf("Invalid dst URL scheme '%s' in init JSON (should be emu-udp, udp, file, http or https)", dstUrl.Scheme)
	}

	host, _, _ := net.SplitHostPort(dstUrl.Host)
	isIpv6 = strings.Contains(host, ":")

	return dstUrl, isIpv6, nil
}

// Get total generators rate of non-option templates data flows
func (o *PluginIPFixClient) getTotalGenDataRatePps() float32 {
	var totalGenDataRatePps float32

	for _, gen := range o.generators {
		if !gen.optionsTemplate {
			totalGenDataRatePps += gen.dataRate
		}
	}

	return totalGenDataRatePps
}

func (o *PluginIPFixClient) updateGenDataRate() {
	if !o.autoTriggered {
		return
	}

	var ratePerDevicePps float32
	var totalGenDataRatePps float32
	var normRatePerDevicePps float32

	dat := o.IpfixNsPlugin.devicesAutoTrigger
	ratePerDevicePps = dat.GetRatePerDevicePps()
	totalGenDataRatePps = o.getTotalGenDataRatePps()
	if ratePerDevicePps > 0 && totalGenDataRatePps > 0 {
		normRatePerDevicePps = ratePerDevicePps / totalGenDataRatePps
	}

	for _, gen := range o.generators {
		if !gen.optionsTemplate {
			gen.SetDataRate(normRatePerDevicePps * gen.dataRate)
		}
	}

	log.Info("Updated generators data rate as follows: ")
	log.Info(" - Rate per device (PPS) - ", ratePerDevicePps)
	log.Info(" - Total generators data rate (PPS) - ", totalGenDataRatePps)
	log.Info(" - Normalization data rate factor - ", normRatePerDevicePps)
}

// NewIPFixClient creates an IPFix client plugin. An IPFix client can own multiple generators
// (exporting processes).
func NewIPFixClient(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	o := new(PluginIPFixClient)
	o.InitPluginBase(ctx, o) // Init base object
	o.OnCreate()

	// Get NS plugin object, if exist
	nsPlugin := o.Ns.PluginCtx.Get(IPFIX_PLUG)
	if nsPlugin != nil {
		o.IpfixNsPlugin = nsPlugin.Ext.(*IpfixNsPlugin)
		dat := o.IpfixNsPlugin.devicesAutoTrigger
		if dat != nil {
			if di, err := dat.GetTriggeredDeviceInfo(ctx.Client); err == nil {
				o.trgDeviceInfo = di
				o.autoTriggered = true
			}
		}
	}

	// Parse the Init JSON.
	init := IPFixClientParams{Ver: DefaultIPFixVersion, DomainID: o.domainID, AutoStart: true}
	err := o.Tctx.UnmarshalValidate(initJson, &init)
	if err != nil {
		o.stats.badOrNoInitJson++
		return nil, err
	}

	// Init Json was provided and successfully unmarshalled.

	// Parse dst URL field
	dstUrl, isIpv6, err := parseDstField(init.Dst)
	if err != nil {
		o.stats.invalidDst++
		return nil, err
	}

	o.ver = init.Ver
	o.dstUrl = *dstUrl
	o.isIpv6 = isIpv6
	o.domainID = init.DomainID
	o.autoStart = init.AutoStart
	o.maxTime = init.MaxTime.Duration

	o.stats.maxDataRecordsToSend = init.MaxDataRecords
	o.stats.maxTempRecordsToSend = init.MaxTempRecords

	// Create a corresponding new exporter based on dst url
	o.exporter, err = CreateExporter(o, &o.dstUrl, init.ExporterParams)
	if err != nil {
		o.stats.failedCreatingExporter++
		if err == ErrExporterWrongKernelMode {
			o.stats.failedCreatingExporterWrongKernelMode++
		}
		return nil, err
	}

	o.cdbv.AddVec(o.exporter.GetCountersDbVec())

	if len(init.Generators) > 0 {
		o.generatorsMap = make(map[string]*IPFixGen, len(init.Generators))
		o.templateIDSet = make(map[uint16]bool, len(init.Generators))
		for i := range init.Generators {
			gen, err := NewIPFixGen(o, init.Generators[i])
			if err != nil {
				o.stats.failedCreatingGen++
				return nil, err
			}
			o.generators = append(o.generators, gen)
			o.generatorsMap[gen.name] = gen
			o.templateIDSet[gen.templateID] = true
		}

		o.updateGenDataRate()
	}

	if o.exporter.GetKernelMode() {
		o.RegisterEvents(ctx, []string{}, o)
		o.OnResolve()
	} else {
		o.RegisterEvents(ctx, ipfixEvents, o)
	}

	o.init = true

	return &o.PluginBase, nil
}

func (o *PluginIPFixClient) Pause(pause bool) {
	for _, gen := range o.generators {
		gen.Pause(pause)
	}
}

func (o *PluginIPFixClient) Enable(enable bool) {
	if o.enabled == false && enable == true {
		o.enabledTime = currentTime()
		o.enabled = enable

		if o.exporter != nil {
			o.exporter.Enable(enable)
		}

		for _, gen := range o.generators {
			gen.sendTemplatePkt()
			gen.sendDataPkt()
		}
	} else if o.enabled == true && enable == false {
		if o.exporter != nil {
			o.exporter.Enable(enable)
		}

		o.enabled = enable
		return
	}
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
	o.sysStartTime = currentTime()
	o.unixUtcTimeNow = o.sysStartTime.UTC().Unix()
	o.timer.SetCB(&o.timerCb, o, 0)
	// Every one tick update the time in order to have a good time difference.
	o.timerw.StartTicks(&o.timer, 1)
	// Create counters database and vector.
	o.cdb = NewIPFixStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec(IPFIX_PLUG)
	o.cdbv.Add(o.cdb)
}

// OnResolve is called when the default gateway mac address is resolved. Here we can start the dial.
func (o *PluginIPFixClient) OnResolve() {
	o.dgMacResolved = true
	var err error

	if o.exporter == nil {
		o.exporter, err = CreateExporter(o, &o.dstUrl, nil)
		if err != nil {
			o.stats.failedCreatingExporter++
			return
		}
	}

	for i := range o.generators {
		// Created generators can now proceed.
		o.generators[i].OnResolve()
	}

	if o.autoStart {
		o.Enable(true)
	}
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

	if o.exporter != nil {
		o.exporter.Close()
		o.exporter = nil
	}
}

// OnEvent callback of the IPFix client plugin.
func (o *PluginIPFixClient) OnEvent(msg string, a, b interface{}) {
	if o.init == false {
		/* Client initialization failed */
		return
	}

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

// OnEvent callback of the IPFixTimerCallback
func (o *IPFixTimerCallback) OnEvent(a, b interface{}) {
	// a should be a pointer to the client plugin
	ipfixPlug := a.(*PluginIPFixClient)
	// Get the time now.
	timeNow := currentTime()
	// Calculate the uptime
	ipfixPlug.sysUpTime = uint32(timeNow.Sub(ipfixPlug.sysStartTime).Milliseconds())
	// Calculate the unix time
	ipfixPlug.unixUtcTimeNow = timeNow.UTC().Unix()
	// Restart call
	ipfixPlug.timerw.StartTicks(&ipfixPlug.timer, 1)
}

// OnRxEvent function to complete the ISocketCb interface.
func (o *PluginIPFixClient) OnRxEvent(event transport.SocketEventType) {
	// no rx expected in IPFix
}

// OnRxData function to complete the ISocketCb interface.
func (o *PluginIPFixClient) OnRxData(d []byte) {
	// no rx expected in IPFix
}

// OnTxEvent function
func (o *PluginIPFixClient) OnTxEvent(event transport.SocketEventType) {
	// No Tx Events expected.
}

/*======================================================================================================
										    Ipfix NS
======================================================================================================*/

// IpfixNsParams defines the InitJson params for IPFIX namespaces
type IpfixNsParams struct {
	DevicesAutoTrigger *fastjson.RawMessage `json:"devices_auto_trigger"`
}

type IpfixNsStats struct {
	invalidInitJson                  uint64
	failedToCreateDevicesAutoTrigger uint64
}

// IpfixNsPlugin represents the IPFIX plugin in namespace level
type IpfixNsPlugin struct {
	core.PluginBase                        // Embedded plugin base
	params             IpfixNsParams       // Namespace init JSON paramaters
	stats              IpfixNsStats        // Namespace statistics
	cdb                *core.CCounterDb    // IPFix counters DB
	cdbv               *core.CCounterDbVec // IPFix counters DB vector
	devicesAutoTrigger *DevicesAutoTrigger
}

// NewIpfixNsStatsDb creates a new counter database for IpfixNsStats.
func NewIpfixNsStatsDb(p *IpfixNsStats) *core.CCounterDb {
	db := core.NewCCounterDb(IPFIX_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &p.invalidInitJson,
		Name:     "invalidInitJson",
		Help:     "Error while decoding init Json",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &p.failedToCreateDevicesAutoTrigger,
		Name:     "failedToCreateDevicesAutoTrigger",
		Help:     "Failed to create devices auto trigger",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

// NewIpfixNs creates a new IPFIX namespace plugin.
func NewIpfixNs(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	// NS level IPFIX plugin is supported only in kernel mode
	kernelMode := ctx.Tctx.GetKernelMode()
	if !kernelMode {
		return nil, fmt.Errorf("Creating NS level IPFIX plugin failed - not kernel mode")
	}

	p := new(IpfixNsPlugin)
	p.InitPluginBase(ctx, p)             // Init the base plugin
	p.RegisterEvents(ctx, []string{}, p) // No events to register in namespace level
	p.cdb = NewIpfixNsStatsDb(&p.stats)  // Create new stats database
	p.cdbv = core.NewCCounterDbVec(IPFIX_PLUG)
	p.cdbv.Add(p.cdb)

	err := p.Tctx.UnmarshalValidate(initJson, &p.params)
	if err != nil {
		p.stats.invalidInitJson++
		return nil, err
	}

	p.devicesAutoTrigger, err = NewDevicesAutoTrigger(p, p.params.DevicesAutoTrigger)
	if err != nil {
		p.stats.failedToCreateDevicesAutoTrigger++
		return nil, err
	}

	p.cdbv.AddVec(p.devicesAutoTrigger.GetCountersDbVec())

	log.Info("New IPFIX namespace plugin was created with init json: ")
	log.Info(string(*p.params.DevicesAutoTrigger))

	return &p.PluginBase, nil
}

// OnRemove when removing IPFIX namespace plugin
func (o *IpfixNsPlugin) OnRemove(ctx *core.PluginCtx) {
	if o.devicesAutoTrigger != nil {
		o.devicesAutoTrigger.Delete()
		o.devicesAutoTrigger = nil
	}
}

// OnEvent for events the namespace plugin is registered.
func (o *IpfixNsPlugin) OnEvent(msg string, a, b interface{}) {}

/*
======================================================================================================

	Generate Plugin

======================================================================================================
*/
type PluginIPFixCReg struct{}
type PluginIPFixNsReg struct{}

// Init IPFIX plugin module once when the first ns or client plugin is configured
func initIpfixPlugin(ctx *core.PluginCtx) {
	if Init {
		return
	}

	Simulation = ctx.Tctx.Simulation
	configureLogger(ctx.Tctx.GetVerbose())

	Init = true
}

func (o PluginIPFixCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	initIpfixPlugin(ctx)
	return NewIPFixClient(ctx, initJson)
}

func (o PluginIPFixNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) (*core.PluginBase, error) {
	initIpfixPlugin(ctx)
	return NewIpfixNs(ctx, initJson)
}

/*
======================================================================================================

	RPC Methods

======================================================================================================
*/
type GenInfo struct {
	Enabled         bool    `json:"enabled"`               // Is generator enabled
	OptionsTemplate bool    `json:"options_template"`      // Is options template or regular template
	ScopeCount      uint16  `json:"scope_count"`           // Scope count in case of options template
	TemplateRate    float32 `json:"template_rate_pps"`     // Template Rate of Generator in PPs
	DataRate        float32 `json:"data_rate_pps"`         // Data Rate of Generator in PPS
	RecordsNum      uint32  `json:"data_records_num"`      // Number of records in packets as specified by user
	RecordsNumSend  uint32  `json:"data_records_num_send"` // Number of records in packets sent.
	TemplateID      uint16  `json:"template_id"`           // Template ID
	FieldsNum       int     `json:"fields_num"`            // Number of fields in each record
	EnginesNum      int     `json:"engines_num"`           // Number of engines this generator has.
}

type (
	ApiIpfixClientCntHandler struct{}

	ApiIpfixClientSetStateHandler struct{}
	ApiIpfixClientSetStateParams  struct {
		Enable *bool `json:"enable"`
	}

	ApiIpfixClientGetGensInfoHandler struct{}
	ApiIpfixClientGetGensInfoResult  struct {
		GensInfos map[string]GenInfo `json:"generators_info"`
	}

	ApiIpfixClientSetGenStateHandler struct{}
	ApiIpfixClientSetGenStateParams  struct {
		GenName      string  `json:"gen_name"`
		Enable       *bool   `json:"enable"`
		Rate         float32 `json:"rate"`
		TemplateRate float32 `json:"template_rate"`
	}

	ApiIpfixClientGetExpInfoHandler struct{}

	ApiIpfixNsCntHandler struct{} // Counter RPC Handler per Ns
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

// getNsPlugin gets the namespace plugin given the namespace parameters (Tunnel Key)
func getNsPlugin(ctx interface{}, params *fastjson.RawMessage) (*IpfixNsPlugin, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetNsPlugin(params, IPFIX_PLUG)

	if err != nil {
		return nil, err
	}

	mIpfixNs := plug.Ext.(*IpfixNsPlugin)
	return mIpfixNs, nil
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

func (h ApiIpfixClientSetStateHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p ApiIpfixClientSetStateParams

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

	if p.Enable != nil {
		c.Enable(*p.Enable)
	}

	return nil, nil
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
		gen.Enable(*p.Enable)
	}
	if p.Rate > 0 {
		gen.SetDataRate(p.Rate)
	}
	if p.TemplateRate > 0 {
		gen.SetTemplateRate(p.TemplateRate)
	}

	return nil, nil
}

// ApiIpfixClientGetGensInfoHandler gets generator information.
func (h ApiIpfixClientGetGensInfoHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var res ApiIpfixClientGetGensInfoResult

	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	res.GensInfos = make(map[string]GenInfo, len(c.generatorsMap))
	for genName, gen := range c.generatorsMap {
		res.GensInfos[genName] = *gen.GetInfo()
	}

	return res, nil
}

func (h ApiIpfixClientGetExpInfoHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	c, err := getClientPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	res := c.exporter.GetInfoJson()

	return res, nil
}

// ApiIpfixNsCntHandler gets the counters of the Ipfix namespace.
func (h ApiIpfixNsCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {
	var p core.ApiCntParams
	tctx := ctx.(*core.CThreadCtx)
	nsPlug, err := getNsPlugin(ctx, params)
	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}
	return nsPlug.cdbv.GeneralCounters(err, tctx, params, &p)
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

	core.RegisterCB("ipfix_c_cnt", ApiIpfixClientCntHandler{}, false) // get counters / meta per client
	core.RegisterCB("ipfix_c_set_state", ApiIpfixClientSetStateHandler{}, false)
	core.RegisterCB("ipfix_c_get_gens_info", ApiIpfixClientGetGensInfoHandler{}, false)
	core.RegisterCB("ipfix_c_set_gen_state", ApiIpfixClientSetGenStateHandler{}, false)
	core.RegisterCB("ipfix_c_get_exp_info", ApiIpfixClientGetExpInfoHandler{}, false)

	core.RegisterCB("ipfix_ns_cnt", ApiIpfixNsCntHandler{}, true) // get counters / meta per ns
}

func Register(ctx *core.CThreadCtx) {
	// In order for this plugin to be included in the EMU compilation one must provide this empty register
	// function. In case you remove the function call, then the core will not include EMU.
}
