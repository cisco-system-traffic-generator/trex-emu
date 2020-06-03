// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

/* 
References:
https://www.iana.org/assignments/ipfix/ipfix.xhtml
https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide/5_AVC_Metric_Def.html
https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide/avc_app_exported_fields.html
*/

package avcipfix

import (
	"fmt"
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"time"
	"math/rand"
	"strings"
)

const (
	FIXED_VAR_LEN = 7  // TODO: move to length variables and remove this
	CISCO_PEN = 9
)

// GetRandInt return a random value in range [0,n). In simulation returns n / 2 for deterministic results .
func GetRandInt(n int) int {
	if Simulation {
		return n >> 1
	}
	return rand.Intn(n)
}

type DataReportGenIf interface {
	// getReport will generate each time a new data report for netflow record.
	getReport() []byte
}

// BaseTemplateInfo is holding information for known templates
type BaseTemplateInfo struct {
	templateID 		uint16
	fields 			layers.IPFixFields				// Saving fields order
	fieldsMap		map[string]*layers.IPFixField	// For fast field access by name
}

func NewBaseTemplateInfo (templateID uint16, fields layers.IPFixFields) *BaseTemplateInfo {
	o := new(BaseTemplateInfo)
	o.templateID = templateID
	o.fields = fields
	o.fieldsMap = make(map[string]*layers.IPFixField, len(fields))
	offset := uint16(0) 
	for _, f := range fields {
		o.fieldsMap[f.Name] = &f
		f.Offset = offset
		offset += f.Length
	}
	return o
}

func (o BaseTemplateInfo) updateField(report []byte, fieldName string, val []byte) {
	field := o.fieldsMap[fieldName]
	off := field.Offset
	l := field.Length
	copy(report[off : off + l], val)
}

type DNSDataGenInit struct {
	ClientStartIP	core.Ipv4Key	`json:"client_ip"`
	ClientsRange	uint32	 		`json:"range_of_clients"`
	ServerStartIP	core.Ipv4Key    `json:"server_ip"`
	ServersRange	uint32			`json:"range_of_servers"`
	NbarHosts		uint32	 		`json:"nbar_hosts"`
}

type IpfixDNSDataGen struct {
	report 	   []byte
	clients    []IpfixDNSClient
	nbarHosts  []string
}

func NewIpfixDnsDataGen(init *DNSDataGenInit) *IpfixDNSDataGen {
	o := new(IpfixDNSDataGen)
	/* Default values */
	clientsNum := uint32(10)
	clientStartIP := core.Ipv4Key{16, 0, 0, 1}
	serversNum := uint32(15)
	serverStartIP := core.Ipv4Key{48, 0, 0, 1}
	nbarHostsNum := uint32(15)

	if init != nil {
		if init.ClientsRange > 0 {
			clientsNum = init.ClientsRange
		}
		if !init.ClientStartIP.IsZero() {
			clientStartIP = init.ClientStartIP
		}
		if init.NbarHosts > 0 {
			nbarHostsNum = init.NbarHosts
		}
		if !init.ServerStartIP.IsZero() {
			serverStartIP = init.ServerStartIP
		}
		if init.ServersRange > 0 {
			serversNum = init.ServersRange
		}
	}

	o.randNbars(nbarHostsNum)
	ipNum := serverStartIP.Uint32()

	dnsServers := make([]core.Ipv4Key, serversNum)
	for i := range(dnsServers) {
		dnsServers[i].SetUint32(ipNum)
		ipNum++
	}

	ipNum = clientStartIP.Uint32()
	o.clients = make([]IpfixDNSClient, clientsNum)
	for i := range(o.clients) {
		c := &o.clients[i]
		c.ip.SetUint32(ipNum)
		ipNum++
		c.srcPort = uint16(GetRandInt(62000) + 2000)
		c.dnsServer = dnsServers[GetRandInt(len(dnsServers))]
	}

	o.initReport()

	return o
}

func (o *IpfixDNSDataGen) getRandClient() *IpfixDNSClient {
	return &o.clients[GetRandInt(len(o.clients))]
}

func (o *IpfixDNSDataGen) getReport() []byte {
	client := o.getRandClient()

	nbarHost := o.nbarHosts[GetRandInt(len(o.nbarHosts))]
	var srcPort [2]byte
	binary.BigEndian.PutUint16(srcPort[:], client.srcPort) 
	flowStartBytes := make([]byte, 8)
	if !Simulation {
		binary.BigEndian.PutUint64(flowStartBytes, uint64(time.Now().Unix()))
	}

	db := templateMap["dns"]
	db.updateField(o.report, "clientIPv4Address", client.ip[:])
	db.updateField(o.report, "serverIPv4Address", client.dnsServer[:])
	db.updateField(o.report, "clientTransportPort", srcPort[:])
	db.updateField(o.report, "nbar2HttpHost", []byte(nbarHost))
	db.updateField(o.report, "flowStartMilliseconds", flowStartBytes)

	client.srcPort++

	// TODO move back to old format with length variable
	// res = append(res, o.ip[:]...)		  						     // clientIPv4Address
	// res = append(res, o.dnsServer[:]...)  							 // serverIPv4Address
	// res = append(res, 0x11)                    	 	 		 		 // protocolIdentifier
	// res = append(res, o.srcPort[:]...)					             // clientTransportPort
	// res = append(res, 0x0, 0x35)                                	 	 // serverTransportPort
	// res = append(res, 0x03, 0x00, 0x00, 0x35)						 // applicationId
	// res = append(res, uint8(len(nbarHost)) + 7)
	// res = append(res, 0x3, 0x0, 0x0, 0x35, 0x34, 0x1)
	// res = append(res, []byte(nbarHost)...)						     // nbar2HttpHost, domain
	// res = append(res, 0x0, 0x8)										 // Null Terminator
	// res = append(res, 0x3, 0x0, 0x0, 0x35, 0x34, 0x4, 0x0, 0x1, 0x8) // nbar2HttpHost, black magic
	// res = append(res, 0x3, 0x0, 0x0, 0x35, 0x34, 0x5, 0x85, 0x80)	 // nbar2HttpHost, black magic
	// res = append(res, 0x0, 0x0, 0x0, 0x1) 							 // flowStartSysUpTime
	// res = append(res, 0x0, 0x0, 0x0, 0xb) 							 // flowEndSysUpTime
	// res = append(res, flowStartBytes...) 							 // flowStartMilliseconds
	// res = append(res, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1) 		 // responderPackets
	// res = append(res, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1) 		 // initiatorPackets
	// res = append(res, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7f) 		 // serverBytesL3
	// res = append(res, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4) 		 // clientBytesL3
	return o.report
}

func (o *IpfixDNSDataGen) initReport() {
	c := o.getRandClient()
	nbarHost := o.nbarHosts[GetRandInt(len(o.nbarHosts))]
	var srcPort [2]byte
	binary.BigEndian.PutUint16(srcPort[:], c.srcPort)

	o.report = append(o.report, c.ip[:]...)		  						    // clientIPv4Address
	o.report = append(o.report, c.dnsServer[:]...)  						// serverIPv4Address
	o.report = append(o.report, 0x11)                    	 	 		 	// protocolIdentifier
	o.report = append(o.report, srcPort[:]...)					       		// clientTransportPort
	o.report = append(o.report, 0x0, 0x35)                                	// serverTransportPort
	o.report = append(o.report, 0x03, 0x00, 0x00, 0x35)						// applicationId
	o.report = append(o.report, []byte(nbarHost)...)						// nbar2HttpHost, domain
	o.report = append(o.report, 0x3, 0x0, 0x0, 0x35, 0x34, 0x4, 0x0) 		// nbar2HttpHost, black magic1
	o.report = append(o.report, 0x3, 0x0, 0x0, 0x35, 0x34, 0x5, 0x85)	 	// nbar2HttpHost, black magic2
	o.report = append(o.report, 0x0, 0x0, 0x0, 0x1) 						// flowStartSysUpTime
	o.report = append(o.report, 0x0, 0x0, 0x0, 0xb) 						// flowEndSysUpTime
	o.report = append(o.report, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0) 	// flowStartMilliseconds
	o.report = append(o.report, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1) 	// responderPackets
	o.report = append(o.report, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1) 	// initiatorPackets
	o.report = append(o.report, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7f) 	// serverBytesL3
	o.report = append(o.report, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4) 	// clientBytesL3
}

func (o *IpfixDNSDataGen) randNbars(n uint32) {
	o.nbarHosts = make([]string, n)
	endings := [...]string{".com", ".org", ".net", ".edu", ".gov", ".co.il", ".ru"}
	digitsAndLowCase := "abcdefghijklmnopqrstuvwxyz0123456789"

	for i := uint32(0); i < n; i++ {
		rndEnding := endings[GetRandInt(len(endings))]

		var b strings.Builder
		b.Grow(int(FIXED_VAR_LEN))
		domainLen := FIXED_VAR_LEN - len(rndEnding)

		for i := 0; i < domainLen; i++ {
			rndChar := digitsAndLowCase[GetRandInt(len(digitsAndLowCase))] 
			fmt.Fprintf(&b, "%c", rndChar)
		}
		fmt.Fprintf(&b, "%s", rndEnding)
		o.nbarHosts[i] = b.String()
	}
}

type IpfixDNSClient struct {
	ip     		core.Ipv4Key
	dnsServer	core.Ipv4Key
	srcPort		uint16
}

var templateMap = make(map[string]*BaseTemplateInfo, 5)

func init() {
	/* known fields */
	clientIPv4Address 		 := layers.IPFixField{Type: 0xafcc, Length: 4, Name: "clientIPv4Address", EnterpriseNumber: CISCO_PEN}
	serverIPv4Address 		 := layers.IPFixField{Type: 0xafcd, Length: 4, Name: "serverIPv4Address", EnterpriseNumber: CISCO_PEN}
	protocolIdentifier 		 := layers.IPFixField{Type: 0x0004, Length: 1, Name: "protocolIdentifier"}
	clientTransportPort 	 := layers.IPFixField{Type: 0xafd0, Length: 2, Name: "clientTransportPort", EnterpriseNumber: CISCO_PEN}
	serverTransportPort 	 := layers.IPFixField{Type: 0xafd1, Length: 2, Name: "serverTransportPort", EnterpriseNumber: CISCO_PEN}
	applicationID 			 := layers.IPFixField{Type: 0x005f, Length: 4, Name: "applicationId"}
	nbar2HttpHost 			 := layers.IPFixField{Type: 0xafcb, Length: FIXED_VAR_LEN, Name: "nbar2HttpHost", EnterpriseNumber: CISCO_PEN}
	nbar2HttpHostBlackMagic1 := layers.IPFixField{Type: 0xafcb, Length: FIXED_VAR_LEN, Name: "nbar2HttpHostBlackMagic1", EnterpriseNumber: CISCO_PEN}
	nbar2HttpHostBlackMagic2 := layers.IPFixField{Type: 0xafcb, Length: FIXED_VAR_LEN, Name: "nbar2HttpHostBlackMagic2", EnterpriseNumber: CISCO_PEN}
	flowStartSysUpTime 		 := layers.IPFixField{Type: 0x0016, Length: 4, Name: "flowStartSysUpTime"}
	flowEndSysUpTime 		 := layers.IPFixField{Type: 0x0015, Length: 4, Name: "flowEndSysUpTime"}
	flowStartMilliseconds 	 := layers.IPFixField{Type: 0x0098, Length: 8, Name: "flowStartMilliseconds"}
	responderPackets 		 := layers.IPFixField{Type: 0x012b, Length: 8, Name: "responderPackets"}
	initiatorPackets 		 := layers.IPFixField{Type: 0x012a, Length: 8, Name: "initiatorPackets"}
	serverBytesL3 			 := layers.IPFixField{Type: 0xa091, Length: 8, Name: "serverBytesL3", EnterpriseNumber: CISCO_PEN}
	clientBytesL3 			 := layers.IPFixField{Type: 0xa092, Length: 8, Name: "clientBytesL3", EnterpriseNumber: CISCO_PEN}
	sourceIPv6Address 		 := layers.IPFixField{Type: 0x001b, Length: 16, Name: "sourceIPv6Address"}
	destinationIPv6Address	 := layers.IPFixField{Type: 0x001c, Length: 16, Name: "destinationIPv6Address"}
	ipVersion				 := layers.IPFixField{Type: 0x003c, Length: 1, Name: "ipVersion"}
	sourceTransportPort		 := layers.IPFixField{Type: 0x0007, Length: 2, Name: "sourceTransportPort"}
	destinationTransportPort := layers.IPFixField{Type: 0x000b, Length: 2, Name: "destinationTransportPort"}
	ingressVRFID			 := layers.IPFixField{Type: 0x00ea, Length: 4, Name: "ingressVRFID"}
	biflowDirection			 := layers.IPFixField{Type: 0x00ef, Length: 1, Name: "biflowDirection"}
	observationPointID		 := layers.IPFixField{Type: 0x008a, Length: 8, Name: "observationPointId"}
	flowDirection			 := layers.IPFixField{Type: 0x003d, Length: 1, Name: "flowDirection"}
	octetDeltaCount			 := layers.IPFixField{Type: 0x0001, Length: 8, Name: "octetDeltaCount"}
	packetDeltaCount		 := layers.IPFixField{Type: 0x0002, Length: 8, Name: "packetDeltaCount"}
	flowEndMilliseconds		 := layers.IPFixField{Type: 0x0099, Length: 8, Name: "flowEndMilliseconds"}
	sourceIPv4Address		 := layers.IPFixField{Type: 0x0008, Length: 4, Name: "sourceIPv4Address"}
	destinationIPv4Address	 := layers.IPFixField{Type: 0x000c, Length: 4, Name: "destinationIPv4Address"}
	transportRtpSsrc	     := layers.IPFixField{Type: 0x909e, Length: 4, Name: "transportRtpSsrc", EnterpriseNumber: CISCO_PEN}
	newConnectionDeltaCount  := layers.IPFixField{Type: 0x0116, Length: 4, Name: "newConnectionDeltaCount", EnterpriseNumber: CISCO_PEN}
	numRespsCountDelta		 := layers.IPFixField{Type: 0xa44c, Length: 4, Name: "numRespsCountDelta", EnterpriseNumber: CISCO_PEN}
	sumServerNwkTime		 := layers.IPFixField{Type: 0xa467, Length: 4, Name: "sumServerNwkTime", EnterpriseNumber: CISCO_PEN}
	retransPackets			 := layers.IPFixField{Type: 0xa434, Length: 4, Name: "retransPackets", EnterpriseNumber: CISCO_PEN}
	sumNwkTime				 := layers.IPFixField{Type: 0xa461, Length: 4, Name: "sumNwkTime", EnterpriseNumber: CISCO_PEN}
	sumServerRespTime		 := layers.IPFixField{Type: 0xa45a, Length: 4, Name: "sumServerRespTime", EnterpriseNumber: CISCO_PEN}
	clientIPv6Address		 := layers.IPFixField{Type: 0xafce, Length: 16, Name: "clientIPv6Address", EnterpriseNumber: CISCO_PEN}
	serverIPv6Address		 := layers.IPFixField{Type: 0xafcf, Length: 16, Name: "serverIPv6Address", EnterpriseNumber: CISCO_PEN}
	collectTransportPacketsLostCounter := layers.IPFixField{Type: 0x909b, Length: 4, Name: "collectTransportPacketsLostCounter", EnterpriseNumber: CISCO_PEN}
	ARTServerRetransmissionsPackets	   := layers.IPFixField{Type: 0xa436, Length: 4, Name: "ARTServerRetransmissionsPackets", EnterpriseNumber: CISCO_PEN}
	collectTransportRtpPayloadType	   := layers.IPFixField{Type: 0x90b1, Length: 1, Name: "collectTransportRtpPayloadType", EnterpriseNumber: CISCO_PEN}

	/* known templates */
	templateMap["dns"] = NewBaseTemplateInfo(
		261,
		layers.IPFixFields {
			clientIPv4Address,
			serverIPv4Address,
			protocolIdentifier,
			clientTransportPort,
			serverTransportPort,
			applicationID,
			nbar2HttpHost,
			nbar2HttpHostBlackMagic1,
			nbar2HttpHostBlackMagic2,
			flowStartSysUpTime,
			flowEndSysUpTime,
			flowStartMilliseconds,
			responderPackets,
			initiatorPackets,
			serverBytesL3,
			clientBytesL3,
		},
	)

	templateMap["266"] = NewBaseTemplateInfo(
		266,
		layers.IPFixFields {
			clientIPv4Address,
			serverIPv4Address,
			ipVersion,
			protocolIdentifier,
			serverTransportPort,
			ingressVRFID,
			biflowDirection,
			observationPointID,
			applicationID,
			flowDirection,
			flowStartMilliseconds,
			flowEndMilliseconds,
			newConnectionDeltaCount,
			numRespsCountDelta,
			sumServerNwkTime,
			retransPackets,
			sumNwkTime,
			sumServerRespTime,
			responderPackets,
			initiatorPackets,
			ARTServerRetransmissionsPackets,
			serverBytesL3,
			clientBytesL3,
		},
	)

	templateMap["267"] = NewBaseTemplateInfo(
		267,
		layers.IPFixFields {
			clientIPv6Address,
			serverIPv6Address,
			ipVersion,
			protocolIdentifier,
			serverTransportPort,
			ingressVRFID,
			biflowDirection,
			observationPointID,
			applicationID,
			flowDirection,
			flowStartMilliseconds,
			flowEndMilliseconds,
			newConnectionDeltaCount,
			numRespsCountDelta,
			sumServerNwkTime,
			retransPackets,
			sumNwkTime,
			sumServerRespTime,
			responderPackets,
			initiatorPackets,
			ARTServerRetransmissionsPackets,
			serverBytesL3,
			clientBytesL3,
		},
	)

	templateMap["268"] = NewBaseTemplateInfo(
		268,
		layers.IPFixFields {
			sourceIPv4Address,
			destinationIPv4Address,
			ipVersion,
			protocolIdentifier,
			sourceTransportPort,
			destinationTransportPort,
			transportRtpSsrc,
			collectTransportRtpPayloadType,
			ingressVRFID,
			biflowDirection,
			observationPointID,
			applicationID,
			flowDirection,
			collectTransportPacketsLostCounter,
			octetDeltaCount,
			packetDeltaCount,
			flowStartMilliseconds,
			flowEndMilliseconds,
			layers.IPFixField{Type: 0x90e5, Length: 8, EnterpriseNumber: CISCO_PEN},
		},
	)

	templateMap["269"] = NewBaseTemplateInfo(
		269,
		layers.IPFixFields {
			sourceIPv6Address,
			destinationIPv6Address,
			ipVersion,			
			protocolIdentifier,
			sourceTransportPort,
			destinationTransportPort,
			transportRtpSsrc,
			collectTransportRtpPayloadType,
			ingressVRFID,
			biflowDirection,
			observationPointID,
			applicationID,
			flowDirection,
			collectTransportPacketsLostCounter,
			octetDeltaCount,
			packetDeltaCount,
			flowStartMilliseconds,
			flowEndMilliseconds,
			layers.IPFixField{Type: 0x90e5, Length: 8, EnterpriseNumber: CISCO_PEN},
		},
	)

	// TODO: move back to length variable when ready
	// templateMap["dns"] = NewBaseTemplateInfo(
	// 	261,
	// 	layers.IPFixFields {
	// 		layers.IPFixField{Type: 0xafcc, Length: 4, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0xafcd, Length: 4, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0x0004, Length: 1},
	// 		layers.IPFixField{Type: 0xafd0, Length: 2, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0xafd1, Length: 2, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0x005f, Length: 4},
	// 		layers.IPFixField{Type: 0xafcb, Length: 0xffff, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0xafcb, Length: 0xffff, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0xafcb, Length: 0xffff, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0x0016, Length: 4},
	// 		layers.IPFixField{Type: 0x0015, Length: 4},
	// 		layers.IPFixField{Type: 0x0098, Length: 8},
	// 		layers.IPFixField{Type: 0x012b, Length: 8},
	// 		layers.IPFixField{Type: 0x012a, Length: 8},
	// 		layers.IPFixField{Type: 0xa091, Length: 8, EnterpriseNumber: CISCO_PEN},
	// 		layers.IPFixField{Type: 0xa092, Length: 8, EnterpriseNumber: CISCO_PEN},
	// 	},
	// )
}
