// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package lldp

/*
lldp client send every 30 sec information from initJson

*/

import (
	"emu/core"
	"external/google/gopacket/layers"
	"external/osamingo/jsonrpc"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	LLDP_PLUG = "lldp"
	/* state of each client */
)

var lldpDefaultDestMAC = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}

type LldpOptionsT struct {
	Raw           *[]byte `json:"raw"`            // raw options to add
	RemoveDefault bool    `json:"remove_default"` // remove the default 		ChassisID/PortID/TTL
}

type LldpInit struct {
	TimerSec uint32        `json:"timer"`
	Options  *LldpOptionsT `json:"options"`
}

type LldpStats struct {
	pktTx uint64
}

func NewLldpStatsDb(o *LldpStats) *core.CCounterDb {
	db := core.NewCCounterDb("lldp")

	db.Add(&core.CCounterRec{
		Counter:  &o.pktTx,
		Name:     "pktTx",
		Help:     "broadcast lldp packet ",
		Unit:     "pkts",
		DumpZero: false,
		Info:     core.ScINFO})

	return db
}

type PluginLldpClientTimer struct {
}

func (o *PluginLldpClientTimer) OnEvent(a, b interface{}) {
	pi := a.(*PluginLldpClient)
	pi.onTimerEvent()
}

//PluginLldpClient information per client
type PluginLldpClient struct {
	core.PluginBase
	lldpNsPlug  *PluginLldpNs
	timerw      *core.TimerCtx
	init        LldpInit
	timer       core.CHTimerObj
	stats       LldpStats
	cdb         *core.CCounterDb
	cdbv        *core.CCounterDbVec
	timerCb     PluginLldpClientTimer
	timerSec    uint32
	l3Offset    uint16
	pktTemplate []byte
}

var lldpEvents = []string{}

/*NewLldpClient create plugin */
func NewLldpClient(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginLldpClient)
	fastjson.Unmarshal(initJson, &o.init)

	o.InitPluginBase(ctx, o)             /* init base object*/
	o.RegisterEvents(ctx, lldpEvents, o) /* register events, only if exits*/
	nsplg := o.Ns.PluginCtx.GetOrCreate(LLDP_PLUG)
	o.lldpNsPlug = nsplg.Ext.(*PluginLldpNs)
	o.OnCreate()

	return &o.PluginBase
}

func (o *PluginLldpClient) OnCreate() {
	o.timerw = o.Tctx.GetTimerCtx()
	o.preparePacketTemplate()
	o.timerSec = 30
	if o.init.TimerSec > 0 {
		o.timerSec = o.init.TimerSec
	}

	o.cdb = NewLldpStatsDb(&o.stats)
	o.cdbv = core.NewCCounterDbVec("lldp")
	o.cdbv.Add(o.cdb)
	o.timer.SetCB(&o.timerCb, o, 0) // set the callback to OnEvent
	o.SendLldp()
}

func (o *PluginLldpClient) preparePacketTemplate() {

	l2 := o.Client.GetL2Header(true, uint16(layers.EthernetTypeLinkLayerDiscovery))
	copy(l2[0:6], lldpDefaultDestMAC[:])
	o.l3Offset = uint16(len(l2))

	lldp := &layers.LinkLayerDiscovery{
		ChassisID: layers.LLDPChassisID{layers.LLDPChassisIDSubTypeMACAddr, l2[6:12]},
		PortID:    layers.LLDPPortID{layers.LLDPPortIDSubtypeIfaceName, []byte("1/1")},
		TTL:       120,
	}

	d := core.PacketUtlBuild(
		lldp,
	)
	if (o.init.Options != nil) && (o.init.Options.RemoveDefault) {
		d = []byte{0, 0}
	}

	if (o.init.Options != nil) && (o.init.Options.Raw != nil) {
		d = d[:len(d)-2]
		d = append(d, *(o.init.Options.Raw)...)
		d = append(d, []byte{0, 0}...)
	}

	o.pktTemplate = append(l2, d...)
}

func (o *PluginLldpClient) SendLldp() {
	o.restartTimer(o.timerSec)
	o.stats.pktTx++
	o.Tctx.Veth.SendBuffer(false, o.Client, o.pktTemplate)
}

/*OnEvent support event change of IP  */
func (o *PluginLldpClient) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginLldpClient) OnRemove(ctx *core.PluginCtx) {
	/* force removing the link to the client */
	ctx.UnregisterEvents(&o.PluginBase, lldpEvents)
	// TBD send release message
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *PluginLldpClient) restartTimer(sec uint32) {
	if sec == 0 {
		return
	}
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
	o.timerw.Start(&o.timer, time.Duration(sec)*time.Second)
}

//onTimerEvent on timer event callback
func (o *PluginLldpClient) onTimerEvent() {
	o.SendLldp()
}

// PluginLldpNs icmp information per namespace
type PluginLldpNs struct {
	core.PluginBase
	stats LldpStats
}

func NewLldpNs(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {

	o := new(PluginLldpNs)
	o.InitPluginBase(ctx, o)
	o.RegisterEvents(ctx, []string{}, o)

	return &o.PluginBase
}

func (o *PluginLldpNs) OnRemove(ctx *core.PluginCtx) {
}

func (o *PluginLldpNs) OnEvent(msg string, a, b interface{}) {

}

func (o *PluginLldpNs) SetTruncated() {

}

// Tx side client get an event and decide to act !
// let's see how it works and add some tests

type PluginLldpCReg struct{}
type PluginLldpNsReg struct{}

func (o PluginLldpCReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewLldpClient(ctx, initJson)
}

func (o PluginLldpNsReg) NewPlugin(ctx *core.PluginCtx, initJson []byte) *core.PluginBase {
	return NewLldpNs(ctx, initJson)
}

/*******************************************/
/*  RPC commands */
type (
	ApiLldpClientCntHandler struct{}
)

func getNs(ctx interface{}, params *fastjson.RawMessage) (*PluginLldpNs, *jsonrpc.Error) {
	tctx := ctx.(*core.CThreadCtx)
	plug, err := tctx.GetNsPlugin(params, LLDP_PLUG)

	if err != nil {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: err.Error(),
		}
	}

	arpNs := plug.Ext.(*PluginLldpNs)

	return arpNs, nil
}

func getClientPlugin(ctx interface{}, params *fastjson.RawMessage) (*PluginLldpClient, error) {
	tctx := ctx.(*core.CThreadCtx)

	plug, err := tctx.GetClientPlugin(params, LLDP_PLUG)

	if err != nil {
		return nil, err
	}

	pClient := plug.Ext.(*PluginLldpClient)

	return pClient, nil
}

func (h ApiLldpClientCntHandler) ServeJSONRPC(ctx interface{}, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

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
	core.PluginRegister(LLDP_PLUG,
		core.PluginRegisterData{Client: PluginLldpCReg{},
			Ns:     PluginLldpNsReg{},
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

	core.RegisterCB("lldp_client_cnt", ApiLldpClientCntHandler{}, false) // get counters/meta

}

func Register(ctx *core.CThreadCtx) {
	//pass
}
