// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package avcipfix

import (
	"emu/core"
	"encoding/binary"
	"encoding/json"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	IPFIX_PLUG   = "avcnet"
	MAC_RES_TIME = 500 // for mac resolving in milliseconds
)

// Simulation states true if simulation mode is on, using a globale variable due to many accesses
var Simulation bool

type IpfixGenInit struct {
	AutoStart bool   `json:"auto_start"`   // Start exporting this gen when plugin is loaded.
	Type      string `json:"type"`         // Type of generator, i.e "dns".
	DataRate  uint32 `json:"rate_pps"`     // Rate of data records in pps.
	Records   uint32 `json:"data_records"` // Number of records in each data packet

	DataGen DataReportGenIf `json:"-"`
	RawData json.RawMessage `json:"gen_type_data"`
}

// UnmarshalJSON is used for unmarshaling different generators types.
func (o *IpfixGenInit) UnmarshalJSON(b []byte) error {
	type init IpfixGenInit // avoid infinite loop
	err := json.Unmarshal(b, (*init)(o))
	if err != nil {
		return err
	}

	switch o.Type {
	case "dns":
		var dnsInit DNSDataGenInit
		err = json.Unmarshal(o.RawData, &dnsInit)
		if err != nil {
			return err
		}
		dnsDataGen := NewIpfixDnsDataGen(&dnsInit)
		o.DataGen = dnsDataGen
	default:
		return &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidParams,
			Message: "Unknown ipfix generator type: " + o.Type,
		}
	}

	return nil
}

type IpfixGen struct {
	isRunning     bool
	genType       string
	templateRate  float32
	dataRateMs    float32
	records       uint32
	flowSeqNum    uint32
	dataTimer     core.CHTimerObj
	templateTimer core.CHTimerObj
	dataGen       DataReportGenIf

	templatePkt []byte
	dataPkt     []byte

	ipfixPlug *PluginIpfixClient
}

func NewIpfixGen(ipfix *PluginIpfixClient, init *IpfixGenInit) *IpfixGen {

	o := new(IpfixGen)
	o.ipfixPlug = ipfix
	o.OnCreate()

	if init != nil {
		/* init json was provided */
		if init.AutoStart {
			o.isRunning = init.AutoStart
		}
		if init.Type != "" {
			o.genType = init.Type
		}
		if init.Records != 0 {
			o.records = init.Records
		}
		if init.DataRate != 0 {
			o.SetDataRate(init.DataRate)
		}
		if init.DataGen != nil {
			o.dataGen = init.DataGen
		}
	}

	if o.records == 0 {
		// number of records wasn't supplied, use max value according to MTU
		o.calcMaxRecords()
	}
	o.prepareTemplatePkt()
	o.prepareDataPkt()

	o.templateTimer.SetCB(o, true, 0)
	o.dataTimer.SetCB(o, false, 0)
	o.ipfixPlug.restartTimer(&o.templateTimer, uint64(o.templateRate), time.Millisecond)
	o.ipfixPlug.restartTimer(&o.dataTimer, uint64(o.dataRateMs), time.Millisecond)

	return o
}

// SetDataRate change data rate pkts, rate in pps.
func (o *IpfixGen) SetDataRate(rate uint32) {
	o.dataRateMs = 1000.0 / float32(rate)
}

func (o *IpfixGen) OnCreate() {
	// defaults
	o.isRunning = false
	o.genType = "dns"
	o.templateRate = 1000.0
	o.SetDataRate(3)
	o.records = 0
	if !Simulation {
		o.flowSeqNum = rand.Uint32()
	} else {
		o.flowSeqNum = 0x12345678
	}
}

func (o *IpfixGen) prepareTemplatePkt() {
	ipfixPlug := o.ipfixPlug
	sets := o.getTemplateSets()
	ipFixHeader := core.PacketUtlBuild(
		&layers.IPFix{
			Ver:       ipfixPlug.ver,
			SysUpTime: ipfixPlug.sysUpTime,
			SourceID:  ipfixPlug.domainID,
			FlowSeq:   o.flowSeqNum,
			DomainID:  ipfixPlug.domainID,
			Sets:      sets,
		},
	)
	o.templatePkt = append(ipfixPlug.basePkt, ipFixHeader...)
}

func (o *IpfixGen) prepareDataPkt() {
	ipfixPlug := o.ipfixPlug
	sets := o.getDataSets()
	ipFixHeader := core.PacketUtlBuild(
		&layers.IPFix{
			Ver:       ipfixPlug.ver,
			SysUpTime: ipfixPlug.sysUpTime,
			SourceID:  ipfixPlug.domainID,
			FlowSeq:   o.flowSeqNum,
			DomainID:  ipfixPlug.domainID,
			Sets:      sets,
		},
	)

	o.dataPkt = append(ipfixPlug.basePkt, ipFixHeader...)
}

func (o *IpfixGen) GetInfo() *GenInfo {
	var i GenInfo

	i.GenType = o.genType
	i.IsRunning = o.isRunning
	i.Records = o.records
	i.TemplateRate = uint32(1000 / o.templateRate)
	i.DataRate = uint32(1000 / o.dataRateMs)
	i.FlowSeqNum = fmt.Sprintf("0x%x", o.flowSeqNum)

	return &i
}

// OnEvent send ipfix template or data to collector when timer expired.
func (o *IpfixGen) OnEvent(a, b interface{}) {
	var isTemplate bool
	switch v := a.(type) {
	case bool:
		isTemplate = v
	default:
		// panic("Wrong parameter to OnEvent, expecting 'a' as bool type")
		return
	}

	ipfixPlug := o.ipfixPlug
	canSend := o.isRunning && ipfixPlug.isMacResolved

	if canSend {
		var pkt []byte
		if isTemplate {
			pkt = o.templatePkt
		} else {
			pkt = o.dataPkt
		}

		l3Offset := ipfixPlug.l3Offset
		l4Offset := ipfixPlug.l4Offset
		ipfixOffset := ipfixPlug.ipfixOffset
		ipfixVer := ipfixPlug.ver
		ipFixHeader := layers.IPFixHeader(pkt[ipfixOffset:])

		if ipfixVer == 10 {
			ipFixHeader.SetLength(uint16(len(pkt[ipfixOffset:])))
		}

		if ipfixVer == 9 {
			ipFixHeader.SetCount(uint16(o.records))
			sysUpTime := uint32(time.Now().Unix()) - ipfixPlug.sysUpTime
			ipFixHeader.SetSysUptime(sysUpTime)
		}

		ipFixHeader.SetFlowSeq(o.flowSeqNum)
		if !Simulation {
			ipFixHeader.SetTimestamp(uint32(time.Now().Unix()))
		}

		// L3 & L4 length & checksum fix
		binary.BigEndian.PutUint16(pkt[l4Offset+4:l4Offset+6], uint16(len(pkt[l4Offset:])))
		l3Len := uint16(len(pkt[l3Offset:]))
		isIpv6 := ipfixPlug.isIpv6

		if !isIpv6 {
			ipv4 := layers.IPv4Header(pkt[l3Offset : l3Offset+20])
			ipv4.SetLength(l3Len)
			ipv4.UpdateChecksum()
			binary.BigEndian.PutUint16(pkt[l4Offset+6:l4Offset+8], 0)
		} else {
			ipv6 := layers.IPv6Header(pkt[l3Offset : l3Offset+40])
			ipv6.SetPyloadLength(uint16(len(pkt[l4Offset:])))
			ipv6.FixUdpL4Checksum(pkt[l4Offset:], 0)
		}

		if l3Len <= o.ipfixPlug.Client.MTU {
			m := ipfixPlug.Ns.AllocMbuf(uint16(len(pkt)))
			m.Append(pkt)
			ipfixPlug.Tctx.Veth.Send(m)
			if ipfixVer == 9 {
				o.flowSeqNum++
			}

			if isTemplate {
				ipfixPlug.stats.pktTempSent++
			} else {
				ipfixPlug.stats.pktDataSent++
				if ipfixVer == 10 {
					o.flowSeqNum += o.records
				}
			}
		} else {
			o.ipfixPlug.stats.pktMtuMissErr++
		}
	}

	if isTemplate {
		ipfixPlug.restartTimer(&o.templateTimer, uint64(o.templateRate), time.Millisecond)
	} else {
		ipfixPlug.restartTimer(&o.dataTimer, uint64(o.dataRateMs), time.Millisecond)
	}
}

func (o *IpfixGen) getTemplateSets() layers.IPFixSets {
	t := templateMap[o.genType]
	templateEntry := layers.NewIPFixTemplate(t.templateID, t.fields)

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

func (o *IpfixGen) getDataSets() layers.IPFixSets {
	setEntries := make(layers.IPFixSetEntries, o.records)
	for i := uint32(0); i < o.records; i++ {
		setEntries[i] = layers.IPFixSetEntry(&layers.IPFixRecord{
			Data: o.dataGen.getReport(),
		})
	}

	templateInfo := templateMap[o.genType]
	return layers.IPFixSets{
		layers.IPFixSet{
			ID:         templateInfo.templateID,
			SetEntries: setEntries,
		},
	}
}

func (o *IpfixGen) calcMaxRecords() {
	report := o.dataGen.getReport()
	ipHeaderLen := 20
	if o.ipfixPlug.isIpv6 {
		ipHeaderLen = 40
	}
	ipfixHeaderLen := layers.IpfixHeaderLenVer10
	if o.ipfixPlug.ver == 9 {
		ipfixHeaderLen = layers.IpfixHeaderLenVer9
	}

	allowed := o.ipfixPlug.Client.MTU - uint16(ipHeaderLen+8+ipfixHeaderLen+4)
	o.records = uint32(allowed / uint16(len(report)))
}

// IpfixGenInitMap maps between generator names to their init object
type IpfixGenInitMap map[string]*IpfixGenInit

type IpfixStats struct {
	pktTempSent        uint64
	pktDataSent        uint64
	pktMtuMissErr      uint64
	CollectorMacNotRes uint64
}

func NewIpfixStatsDb(o *IpfixStats) *core.CCounterDb {
	db := core.NewCCounterDb(IPFIX_PLUG)

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTempSent,
		Name:     "pktTempSent",
		Help:     "Template packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktDataSent,
		Name:     "pktDataSent",
		Help:     "Data packets",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	db.Add(&core.CCounterRec{
		Counter:  &o.pktMtuMissErr,
		Name:     "pktMtuMissErr",
		Help:     "Packet dropped due to low mtu value",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScERROR})

	db.Add(&core.CCounterRec{
		Counter:  &o.CollectorMacNotRes,
		Name:     "CollectorMacNotRes",
		Help:     "Number of tries to resolve collector mac",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScERROR})

	return db
}

// IpfixClientInit defines the json structure for Ipfix plugin.
type IpfixClientInit struct {
	Ver        uint16          `json:"netflow_version"` // Net flow version 9 or 10
	Ipv4       core.Ipv4Key    `json:"dst_ipv4"`        // Collector IPv4 address
	Ipv6       core.Ipv6Key    `json:"dst_ipv6"`        // Collector Ipv6 address
	Mac        core.MACKey     `json:"dst_mac"`         // Collector Mac address
	DstPort    uint16          `json:"dst_port"`        // Collector port
	SrcPort    uint16          `json:"src_port"`        // Our port
	Generators IpfixGenInitMap `json:"generators"`      // Ipfix Generators (Template or Data)
}

// IpfixGenMap mapped generator name to the wanted generator
type IpfixGenMap map[string]*IpfixGen

// PluginIpfixClient defines Ipfix information for sending templates & data packets to a collector.
type PluginIpfixClient struct {
	core.PluginBase

	ver           uint16       // Netflow version 9 or 10
	dstIpv4       core.Ipv4Key // Collector IPv4 address
	dstIpv6       core.Ipv6Key // Collector Ipv6 address (if exists)
	dstMac        core.MACKey  // Forced Collector Mac, not using dg resolved mac
	dstPort       uint16       // Collector port
	srcPort       uint16       // Our port
	sysUpTime     uint32       // System Up Time (Only in Ver 9)
	domainID      uint32       // Random domain ID
	isMacResolved bool
	isIpv6        bool        // True if "dst_ipv6" supplied
	generators    IpfixGenMap // Generators map (templates and data) keys as generator's name.

	timerw       *core.TimerCtx
	resolveCb    IpfixClientResolveTimer // In case mac isn't resolve, stop sending packets and wait for resolving.
	resolveTimer core.CHTimerObj
	stats        IpfixStats
	cdb          *core.CCounterDb
	cdbv         *core.CCounterDbVec

	basePkt     []byte
	l3Offset    uint16
	l4Offset    uint16
	ipfixOffset uint16
}

var ipfixEvents = []string{}

func (o *PluginIpfixClient) restartTimer(timer *core.CHTimerObj, t uint64, units time.Duration) {
	if t == 0 {
		return
	}
	if timer.IsRunning() {
		o.timerw.Stop(timer)
	}
	o.timerw.Start(timer, time.Duration(t)*units)
}

func (o *PluginIpfixClient) tryResolveMac() {
	o.stats.CollectorMacNotRes++
	_, ok := o.Client.ResolveIPv4DGMac()
	o.isMacResolved = ok
	if ok {
		o.prepareBasePacket()
	} else {
		o.restartTimer(&o.resolveTimer, MAC_RES_TIME, time.Millisecond)
	}
}

func (o *PluginIpfixClient) prepareBasePacket() {

	isIpv6 := o.isIpv6
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
		o.isMacResolved = true
	} else {
		dstMac, ok := o.Client.ResolveIPv4DGMac()
		o.isMacResolved = ok
		if ok {
			layers.EthernetHeader(pkt).SetDestAddress(dstMac[:])
		} else {
			o.restartTimer(&o.resolveTimer, MAC_RES_TIME, time.Millisecond)
			return
		}
	}

	o.l3Offset = uint16(len(pkt))

	// L3
	var ipHeader []byte
	if !isIpv6 {
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

func (o *PluginIpfixClient) OnEvent(msg string, a, b interface{}) {
}

// NewIpfixClient create  Ipfix plugin for a client.
func NewIpfixClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	var init IpfixClientInit
	err := fastjson.Unmarshal(initJson, &init)

	o := new(PluginIpfixClient)
	o.InitPluginBase(ctx, o)              /* init base object*/
	o.RegisterEvents(ctx, ipfixEvents, o) /* register events, only if exits*/
	o.OnCreate()

	if err == nil {
		/* init json was provided */
		if init.Ver > 0 {
			o.ver = init.Ver
		}
		if !init.Mac.IsZero() {
			o.dstMac = init.Mac
		}
		if !init.Ipv4.IsZero() {
			o.dstIpv4 = init.Ipv4
		}
		if !init.Ipv6.IsZero() {
			o.dstIpv6 = init.Ipv6
			o.isIpv6 = true
		}
		if init.DstPort != 0 {
			o.dstPort = init.DstPort
		}
		if init.SrcPort != 0 {
			o.srcPort = init.SrcPort
		}
		if len(init.Generators) > 0 {
			o.prepareBasePacket()
			o.generators = make(IpfixGenMap, len(init.Generators))
			for name, genInit := range init.Generators {
				o.generators[name] = NewIpfixGen(o, genInit)
			}
		}
	}

	return &o.PluginBase
}

func (o *PluginIpfixClient) OnCreate() {
	/* Default values */
	o.ver = 10
	o.timerw = o.Tctx.GetTimerCtx()
	o.dstIpv4 = core.Ipv4Key{1, 1, 1, 4}
	o.dstPort = 4739
	o.srcPort = 30334
	o.sysUpTime = uint32(time.Now().Unix())
	if !Simulation {
		o.domainID = rand.Uint32()
	} else {
		o.domainID = 0x87654321
	}
	o.cdb = NewIpfixStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec(IPFIX_PLUG)
	o.cdbv.Add(o.cdb)
	o.resolveTimer.SetCB(&o.resolveCb, o, 0)
}

func (o *PluginIpfixClient) OnRemove(ctx *core.PluginCtx) {
	ctx.UnregisterEvents(&o.PluginBase, ipfixEvents)
	for _, gen := range o.generators {
		if gen.templateTimer.IsRunning() {
			o.timerw.Stop(&gen.templateTimer)
		}
		if gen.dataTimer.IsRunning() {
			o.timerw.Stop(&gen.dataTimer)
		}
	}
}

type IpfixClientResolveTimer struct {
}

func (o *IpfixClientResolveTimer) OnEvent(a, b interface{}) {
	p := a.(*PluginIpfixClient)
	p.tryResolveMac()
}

type PluginIPFixCReg struct{}
type PluginIPFixNsReg struct{}

func (o PluginIPFixCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	Simulation = ctx.Tctx.Simulation // init simulation mode
	return NewIpfixClient(ctx, initJson)
}

func (o PluginIPFixNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	// No Ns plugin for now.
	return nil
}

/* RPC Methods */

type GenInfo struct {
	GenType      string `json:"type"`
	IsRunning    bool   `json:"is_running"`
	TemplateRate uint32 `json:"template_rate_pps"`
	DataRate     uint32 `json:"data_rate_pps"`
	Records      uint32 `json:"data_records"`
	FlowSeqNum   string `json:"flow_sequence"`
}

type (
	ApiIpfixClientCntHandler struct{}

	ApiIpfixClientSetGenStateHandler struct{}
	ApiIpfixClientSetGenStateParams  struct {
		GenName string `json:"gen_name"`
		Running *bool  `json:"running"`
		Rate    uint32 `json:"rate"`
	}

	ApiIpfixClientGetGensInfoHandler struct{}
	ApiIpfixClientGetGensInfoParams  struct {
		GenNames []string `json:"gen_names"`
	}
	ApiIpfixClientGetGensInfoResult struct {
		GensInfos map[string]GenInfo `json:"gens_infos"`
	}
)

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginIpfixClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, IPFIX_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginIpfixClient)

	return pClient, nil
}

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

	gen, ok := c.generators[p.GenName]
	if !ok {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: fmt.Sprintf("generator '%s' was not found", p.GenName),
		}
	}

	if p.Running != nil {
		gen.isRunning = *p.Running
	}
	if p.Rate > 0 {
		gen.SetDataRate(p.Rate)
	}

	return nil, nil
}

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
		gen, ok := c.generators[genName]
		if !ok {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.ErrorCodeInvalidRequest,
				Message: fmt.Sprintf("generator '%s' was not found", genName),
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

	core.RegisterCB("avcnet_c_cnt", ApiIpfixClientCntHandler{}, false) // get counters / meta
	core.RegisterCB("avcnet_c_set_gen_state", ApiIpfixClientSetGenStateHandler{}, false)
	core.RegisterCB("avcnet_c_get_gens_info", ApiIpfixClientGetGensInfoHandler{}, false)

}
