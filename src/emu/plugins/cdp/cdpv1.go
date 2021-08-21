// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package cdp

/*
cdp protocol.

broadcast cisco CDP packet every tick. The CDP TLV information can be tuned by the inijson

*/

import (
	"emu/core"
	"encoding/binary"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	CDP_PLUG = "cdp"
	/* state of each client */
)

var cdpDefaultDestMAC core.MACKey = core.MACKey{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc} // L2 multicast MAC for CDP

type CdpOptionsT struct {
	Raw *[]byte `json:"raw"` // raw options to add
}

type CdpInit struct {
	TimerSec uint32       `json:"timer"`
	Ver      uint8        `json:"ver"` // 1, or 2
	Options  *CdpOptionsT `json:"options"`
	BadCs    uint16       `json:"cs"` // for generating bad cs
}

type CdpStats struct {
	pktTx uint64
}

func NewCdpStatsDb(o *CdpStats) *core.CCounterDb {
	db := core.NewCCounterDb("cdp")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTx,
		Name:     "pktTx",
		Help:     "broadcast packet ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

type PluginCdpClientTimer struct {
}

func (o *PluginCdpClientTimer) OnEvent(a, b interface{}) {
	pi := a.(*PluginCdpClient)
	pi.onTimerEvent()
}

//PluginCdpClient information per client
type PluginCdpClient struct {
	core.PluginBase
	cdpNsPlug   *PluginCdpNs
	timerw      *core.TimerCtx
	init        CdpInit
	timer       core.CHTimerObj
	stats       CdpStats
	cdb         *core.CCounterDb
	cdbv        *core.CCounterDbVec
	timerCb     PluginCdpClientTimer
	timerSec    uint32
	l3Offset    uint16
	pktTemplate []byte
}

var cdpEvents = []string{}

/*NewCdpClient create plugin */
func NewCdpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginCdpClient)
	fastjson.Unmarshal(initJson, &o.init)

	o.InitPluginBase(ctx, o)            /* init base object*/
	o.RegisterEvents(ctx, cdpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(CDP_PLUG)
	o.cdpNsPlug = nsplg.Ext.(*PluginCdpNs)
	o.OnCreate()

	return &o.PluginBase
}

func (o *PluginCdpClient) OnCreate() {
	o.timerw = o.Tctx.GetTimerCtx()
	o.preparePacketTemplate()
	o.timerSec = 30
	if o.init.TimerSec > 0 {
		o.timerSec = o.init.TimerSec
	}

	o.cdb = NewCdpStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("cdp")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.SendCdp()
}

func (o *PluginCdpClient) preparePacketTemplate() {

	l2 := o.Client.GetL2Header(true, 0)
	copy(l2[0:6], cdpDefaultDestMAC[:])

	o.l3Offset = uint16(len(l2))

	llc := &layers.LLC{
		DSAP:    0xaa,
		SSAP:    0xaa,
		Control: 0x3,
	}

	snap := &layers.SNAP{
		OrganizationalCode: []byte{0, 0, 0xc},
		Type:               layers.EthernetTypeCiscoDiscovery,
	}

	ver := uint8(2)
	if o.init.Ver > 0 {
		ver = o.init.Ver
	}
	cdph := &layers.CiscoDiscovery{
		Version: ver,
		TTL:     180,
	}
	// example
	//cdph.Values = append(cdph.Values, layers.NewCdpVal(layers.CDPTLVDevID, []byte(`myswitch`)))

	d := core.PacketUtlBuild(
		llc,
		snap,
		cdph,
	)

	if (o.init.Options != nil) && (o.init.Options.Raw != nil) {
		d = append(d, *(o.init.Options.Raw)...)
	}
	// fix checksum
	cs := layers.CdpChecksum(d[8:], 0)
	if o.init.BadCs > 0 {
		binary.BigEndian.PutUint16(d[10:12], o.init.BadCs)
	} else {
		binary.BigEndian.PutUint16(d[10:12], cs)
	}
	// fix 802.3 length
	a := len(l2) - 2
	binary.BigEndian.PutUint16(l2[a:a+2], uint16(len(d)))

	o.pktTemplate = append(l2, d...)
}

func (o *PluginCdpClient) SendCdp() {
	o.restartTimer(o.timerSec)
	o.stats.pktTx++
	o.Tctx.Veth.SendBuffer(false, o.Client, o.pktTemplate, false)
}

/*OnEvent support event change of IP  */
func (o *PluginCdpClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginCdpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, cdpEvents)
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *PluginCdpClient) restartTimer(sec uint32) {
	if sec == 0 {
		return
	}
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.timerw.Start(&o.timer, time.Duration(sec)*time.Second)
}

//onTimerEvent on timer event callback
func (o *PluginCdpClient) onTimerEvent() {
	o.SendCdp()
}

// PluginCdpNs icmp information per namespace
type PluginCdpNs struct {
	core.PluginBase
	stats CdpStats
}

func NewCdpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginCdpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase
}

func (o *PluginCdpNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginCdpNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginCdpNs) SetTruncated() {

}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginCdpCReg struct{}
type PluginCdpNsReg struct{}

func (o PluginCdpCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewCdpClient(ctx, initJson)
}

func (o PluginCdpNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewCdpNs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */
type (
	ApiCdpClientCntHandler struct{}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginCdpNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, CDP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginCdpNs)

	return arpNs, nil
}

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginCdpClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, CDP_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginCdpClient)

	return pClient, nil
}

func (h ApiCdpClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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
	core.PluginRegister(CDP_PLUG,
		core.PluginRegisterData{Client: PluginCdpCReg{},
			Ns:     PluginCdpNsReg{},
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

	core.RegisterCB("cdp_client_cnt", ApiCdpClientCntHandler{}, false) // get counters/meta

}

func Register(ctx *core.CThreadCtx) {
	//pass
}
