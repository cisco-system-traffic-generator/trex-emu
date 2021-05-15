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
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"math/rand"
	"net"
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
	templateRate           float32                          // Template rate in PPS.
	dataRate               float32                          // Data rate in PPS.
	templateID             uint16                           // Template ID.
	recordsNum             uint32                           // Number of records in a packet as received from the user.
	recordsNumToSent       uint32                           // Number of records to send in a packet.
	variableLengthFields   bool                             // Has variable length fields?
	optionsTemplate        bool                             // Is Options Template or Data Template
	scopeCount             uint16                           // Scope Count for Option Templates, the number of fields that are scoped.
	availableRecordPayload uint16                           // Available bytes for record payloads.
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
func NewIPFixGen(ipfix *PluginIPFixClient, initJson *fastjson.RawMessage) (*IPFixGen, bool) {

	init := IPFixGenParams{TemplateRate: DefaultIPFixTemplateRate, DataRate: DefaultIPFixDataRate, AutoStart: true}
	err := ipfix.Tctx.UnmarshalValidate(*initJson, &init)

	if err != nil {
		ipfix.stats.invalidJson++
		return nil, false
	}

	// validate fields as well, not only outside Json.
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
	o.templateRate = init.TemplateRate
	o.dataRate = init.DataRate
	o.recordsNum = init.RecordsNum
	o.optionsTemplate = init.OptionsTemplate
	o.scopeCount = init.ScopeCount
	o.fields = init.Fields
	// Create Engine Manager
	if init.Engines != nil {
		o.engineMgr = engines.NewEngineManager(o.ipfixPlug.Tctx, init.Engines)
		if !o.engineMgr.WasCreatedSuccessfully() {
			o.ipfixPlug.stats.failedBuildingEngineMgr++
			return nil, false
		}
		o.engineMap = o.engineMgr.GetEngineMap()
	}

	o.fieldNames = make(map[string]bool, len(o.fields))
	// Build Template Fields and Data Buffer.
	for i := range o.fields {
		if o.ipfixPlug.ver == 0x09 && o.fields[i].isEnterprise() {
			o.ipfixPlug.stats.enterpriseFieldv9++
			return nil, false
		}
		if o.ipfixPlug.ver == 9 && o.fields[i].isVariableLength() {
			o.ipfixPlug.stats.variableLengthFieldv9++
			return nil, false
		}
		o.templateFields = append(o.templateFields, o.fields[i].getIPFixField())
		if !o.fields[i].isVariableLength() && (len(o.fields[i].Data) != int(o.fields[i].Length)) {
			ipfix.stats.dataIncorrectLength++
			return nil, false
		}
		o.fieldNames[o.fields[i].Name] = true // add each field to the field names
		if !o.fields[i].isVariableLength() {
			// don't add variable length fields to the data buffer, they don't have a data buffer.
			o.dataBuffer = append(o.dataBuffer, o.fields[i].Data...)
		} else {
			o.variableLengthFields = true
			// variable length field, verify that no data.
			if len(o.fields[i].Data) != 0 {
				ipfix.stats.dataIncorrectLength++
				return nil, false
			}
			// also we must have an engine for variable length fields
			if o.engineMgr == nil {
				ipfix.stats.variableLengthNoEngine++
				return nil, false
			} else {
				if _, ok := o.engineMap[o.fields[i].Name]; !ok {
					ipfix.stats.variableLengthNoEngine++
					return nil, false
				}
			}
		}
	}

	// verify each engine name is a correct field
	if o.engineMgr != nil {
		for engineName, _ := range o.engineMap {
			if _, ok := o.fieldNames[engineName]; !ok {
				o.ipfixPlug.stats.invalidEngineName++
			}
		}
	}

	// Calculate Ticks for Timer.
	o.templateTicks = o.timerw.DurationToTicks(time.Duration(float32(time.Second) / o.templateRate))
	o.dataTicks, o.dataPktsPerInterval = o.timerw.DurationToTicksBurst(time.Duration(float32(time.Second) / o.dataRate))

	if o.ipfixPlug.dgMacResolved {
		// If resolved before the generators were created, we call on resolve explicitly.
		if ok := o.OnResolve(); !ok {
			return nil, false
		}

	}

	return o, true
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

// OnResolve is called when the client successfully resolves the mac address of the default gateway
// and we can create a socket.
func (o *IPFixGen) OnResolve() bool {
	ok := o.prepareTemplatePayload()
	if !ok {
		return false
	}
	// Preparing the data payload is not needed as SendPkt prepares it by itself. This packet changes every iteration.

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

	// Attempt to send the first packets in order.
	o.sendTemplatePkt() // template packet
	o.sendDataPkt()     // data packet
	return true
}

// calcAvailableRecordPayload calculates the amount of bytes available for record payloads.
func (o *IPFixGen) calcAvailableRecordPayload() {
	ipfixHeaderLen := layers.IpfixHeaderLenVer10
	if o.ipfixPlug.ver == 9 {
		ipfixHeaderLen = layers.IpfixHeaderLenVer9
	}
	o.availableRecordPayload = o.ipfixPlug.availableL7MTU - uint16(ipfixHeaderLen+4) // set header length is 4
}

// calcShortestRecord calculates the length of the shortest possible record in case of variable length.
func (o *IPFixGen) calcShortestRecord() (length uint16) {
	if !o.variableLengthFields {
		length = uint16(len(o.dataBuffer))
	} else {
		length = uint16(len(o.dataBuffer))
		for i, _ := range o.fields {
			if o.fields[i].isVariableLength() {
				length += 1 // one for each variable length
			}
		}
	}
	return length
}

// calcLongestRecord calculates the length of the longest possible record in case of variable length.
func (o *IPFixGen) calcLongestRecord() (length uint16) {
	if !o.variableLengthFields {
		length = uint16(len(o.dataBuffer))
	} else {
		length = uint16(len(o.dataBuffer))
		for i, _ := range o.fields {
			if o.fields[i].isVariableLength() {
				eng := o.engineMap[o.fields[i].Name]
				length += eng.GetSize() // Size is the upper limit.
			}
		}
	}
	return length
}

// calcMaxRecords calculate the maximum number of records we can send without overflowing the MTU.
// This function should be called only on generators that don't contain variable length fields.
func (o *IPFixGen) calcMaxRecords() uint32 {
	recordLength := len(o.dataBuffer) // length of 1 record.
	return uint32(o.availableRecordPayload / uint16(recordLength))
}

// calcMaxRecordsVarLength calculates the maximum number of records we can send in case of variable length.
// This is an upper bound and not exactly the number we can send.
func (o *IPFixGen) calcMaxRecordsVarLength() uint32 {
	return uint32(o.availableRecordPayload / o.calcShortestRecord())
}

/*======================================================================================================
										Send packet
======================================================================================================*/

// sendTemplatePkt sends a Template packet
func (o *IPFixGen) sendTemplatePkt() {
	if o.enabled {
		ipfixVer := o.ipfixPlug.ver
		payload := o.templatePayload
		o.fixPayload(payload)
		err, _ := o.ipfixPlug.socket.Write(payload)
		if err != transport.SeOK {
			o.ipfixPlug.stats.socketWriteError++
		} else {
			o.ipfixPlug.stats.pktTempSent++
			if ipfixVer == 9 {
				o.ipfixPlug.flowSeqNum++
			}
		}
	}
	o.timerw.StartTicks(&o.templateTimer, o.templateTicks)
}

// sendDataPkt sends a burst of data packets (burst can be of size 1)
func (o *IPFixGen) sendDataPkt() {
	if o.enabled {
		ipfixVer := o.ipfixPlug.ver
		// Only Data Packets can have bursts.
		for i := 0; i < int(o.dataPktsPerInterval); i++ {
			records := o.prepareDataPayload()
			payload := o.dataPayload
			o.fixPayload(payload)
			err, _ := o.ipfixPlug.socket.Write(payload)
			if err != transport.SeOK {
				o.ipfixPlug.stats.socketWriteError++
			} else {
				o.ipfixPlug.stats.pktDataSent++
				// updating the flow sequence number must be inside the loop because fixPayload uses the value.
				if ipfixVer == 9 {
					o.ipfixPlug.flowSeqNum++
				} else if ipfixVer == 10 {
					o.ipfixPlug.flowSeqNum += records
				}
				if o.recordsNum > records {
					mtuMissedRecords := o.recordsNum - records
					o.ipfixPlug.stats.recordsMtuMissErr += uint64(mtuMissedRecords)
				}
			}
		}
	}
	o.timerw.StartTicks(&o.dataTimer, o.dataTicks)
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
		ipFixHeader.SetTimestamp(uint32(o.ipfixPlug.unixTimeNow))
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
	if len(ipFixHeader) > int(o.ipfixPlug.availableL7MTU) {
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
	for i := uint32(0); i < o.recordsNumToSent; i++ {
		if availablePayload < longestRecord {
			// in case we don't have variable length fields this shouldn't happen
			break
		} else {
			data := o.getDataRecord()
			availablePayload -= uint16(len(data))
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

// SetTemplateRate sets a new template rate through RPC.
func (o *IPFixGen) SetTemplateRate(rate float32) {
	o.templateRate = rate
	o.templateTicks = o.timerw.DurationToTicks(time.Duration(float32(time.Second) / o.templateRate))
	// Restart the timer.
	if o.templateTimer.IsRunning() {
		o.timerw.Stop(&o.templateTimer)
	}
	o.timerw.StartTicks(&o.templateTimer, o.templateTicks)
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
	pktTempSent              uint64 // How many Template packets sent.
	pktDataSent              uint64 // How many Data packets sent.
	templatePktLongerThanMTU uint64 // Template Packet Length is longer than MTU, hence we can't send Template packets or any packets for that matter.
	recordsMtuMissErr        uint64 // How many Data records dropped cause the record num is too big for MTU
	dataIncorrectLength      uint64 // Data entry of field is not the same as the length provided in the same field.
	invalidSocket            uint64 // Error while creating socket
	socketWriteError         uint64 // Error while writing on a socket.
	invalidJson              uint64 // Json could not be unmarshalled or validated correctly.
	invalidDst               uint64 // Invalid Dst provided.
	failedCreatingGen        uint64 // Failed creating a generator with the generator's provided JSON.
	enterpriseFieldv9        uint64 // Enterprise Fields are not supported for V9.
	variableLengthFieldv9    uint64 // Variable length Fields are not supported for V9.
	variableLengthNoEngine   uint64 // Variable length field without engine provided.
	badOrNoInitJson          uint64 // Init Json was either not provided or invalid.
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
		Help:     "Field data of invalid length.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.invalidSocket,
		Name:     "invalidSocket",
		Help:     "Error creating socket.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.socketWriteError,
		Name:     "socketWriteError",
		Help:     "Error writing in socket.",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

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
	Ver        uint16                 `json:"netflow_version"`                // NetFlow version 9 or 10
	Dst        string                 `json:"dst" validate:"required"`        // Destination Address. Combination of Host:Port.
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
	core.PluginBase                         // Plugin Base
	ver             uint16                  // NetFlow version 9 or 10
	dstAddress      string                  // Destination Address. Combination of Host:Port.
	isIpv6          bool                    // Is destination address IPv6 or IPv4 address
	sysStartTime    time.Time               // Start time of the system in order to calculate uptime.
	sysUpTime       uint32                  // System Up Time (Only in Ver 9) in resolution of milliseconds.
	unixTimeNow     int64                   // Unix Time Now for Unix Time in Header, should be on resolution of seconds.
	domainID        uint32                  // Observation Domain ID
	flowSeqNum      uint32                  // Flow sequence number must be common for all IPFix Gen.
	transportCtx    *transport.TransportCtx // Transport Layer Context
	socket          transport.SocketApi     // Socket API
	dgMacResolved   bool                    // Is the default gateway MAC address resolved?
	availableL7MTU  uint16                  // Available L7 MTU
	timerw          *core.TimerCtx          // Timer Wheel
	timer           core.CHTimerObj         // Timer Object for calculating Unix time every tick
	timerCb         IPFixTimerCallback      // Timer Callback object
	stats           IPFixStats              // IPFix statistics
	cdb             *core.CCounterDb        // Counters Database
	cdbv            *core.CCounterDbVec     // Counters Database Vector
	generators      []*IPFixGen             // List of Generators
	generatorsMap   map[string]*IPFixGen    // Generator Map for fast lookup with generator name.
	templateIDSet   map[uint16]bool         // Set of Template IDs.
}

var ipfixEvents = []string{core.MSG_DG_MAC_RESOLVED}

// NewIPFixClient creates an IPFix client plugin. An IPFix client can own multiple generators
// (exporting processes).
func NewIPFixClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginIPFixClient)
	o.InitPluginBase(ctx, o)              // Init base object
	o.RegisterEvents(ctx, ipfixEvents, o) // Register events, only if they exist
	o.OnCreate()

	// Parse the Init JSON.
	init := IPFixClientParams{Ver: DefaultIPFixVersion, DomainID: o.domainID}
	err := o.Tctx.UnmarshalValidate(initJson, &init)

	if err != nil {
		o.stats.badOrNoInitJson++
		return &o.PluginBase
	}

	// Init Json was provided and successfully unmarshalled.
	var host string
	if host, _, err = net.SplitHostPort(init.Dst); err != nil {
		o.stats.invalidDst++
		return &o.PluginBase
	}
	o.isIpv6 = strings.Contains(host, ":")

	o.ver = init.Ver
	o.dstAddress = init.Dst
	o.domainID = init.DomainID

	o.transportCtx = transport.GetTransportCtx(o.Client)

	if len(init.Generators) > 0 {
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

// OnResolve is called when the default gateway mac address is resolved. Here we can start the dial.
func (o *PluginIPFixClient) OnResolve() {
	o.dgMacResolved = true
	if o.transportCtx != nil {
		var err error
		o.socket, err = o.transportCtx.Dial("udp", o.dstAddress, o, nil, nil, 0)
		if err != nil {
			o.stats.invalidSocket++
			return
		}
		o.availableL7MTU = o.socket.GetL7MTU()

		for i, _ := range o.generators {
			// Created generators can now proceed.
			o.generators[i].OnResolve()
		}
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
	if o.socket != nil {
		o.socket.Close()
	}
}

// OnEvent callback of the IPFix client plugin.
func (o *PluginIPFixClient) OnEvent(msg string, a, b interface{}) {
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
	timeNow := time.Now()
	// Calculate the uptime
	ipfixPlug.sysUpTime = uint32(timeNow.Sub(ipfixPlug.sysStartTime).Milliseconds())
	// Calculate the unix time
	ipfixPlug.unixTimeNow = timeNow.Unix()
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

	ApiIpfixClientSetGenStateHandler struct{}
	ApiIpfixClientSetGenStateParams  struct {
		GenName      string  `json:"gen_name"`
		Enable       *bool   `json:"enable"`
		Rate         float32 `json:"rate"`
		TemplateRate float32 `json:"template_rate"`
	}

	ApiIpfixClientGetGensInfoHandler struct{}
	ApiIpfixClientGetGensInfoResult  struct {
		GensInfos map[string]GenInfo `json:"generators_info"`
	}
	ApiIpfixClientGetGenNamesHandler struct{}
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

func Register(ctx *core.CThreadCtx) {
	// In order for this plugin to be included in the EMU compilation one must provide this empty register
	// function. In case you remove the function call, then the core will not include EMU.
}
