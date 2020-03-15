// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package core

import (
	"fmt"
	"runtime"
	"strings"
)

type IPluginIf interface {
	OnEvent(msg string, a, b interface{})
	OnRemove(o *PluginCtx) // call before delete
}

/* PluginBase plugin base that should be included in any plugin

type PluginArp struct {
	PluginBase
	arpEnable bool
}


*/
type PluginBase struct {
	Client *CClient
	Ns     *CNSCtx
	Tctx   *CThreadCtx
	I      IPluginIf
	Ext    interface{} // extention
}

func (o *PluginBase) InitPluginBase(ctx *PluginCtx, ext interface{}) {
	o.Tctx = ctx.Tctx
	o.Ns = ctx.Ns
	o.Client = ctx.Client
	o.Ext = ext
}

func (o *PluginBase) RegisterEvents(ctx *PluginCtx, events []string, i IPluginIf) {
	o.I = i
	ctx.RegisterEvents(o, events)
}

type IPluginRegister interface {
	NewPlugin(c *PluginCtx, initJson []byte) *PluginBase // call to create a new plugin
}

type PluginRegisterData struct {
	Client IPluginRegister
	Ns     IPluginRegister
	Thread IPluginRegister
}

type pluginRegister struct {
	M map[string]PluginRegisterData
}

type MapPlugins map[string]*PluginBase
type MapEventBus map[string][]*PluginBase // string is the msg name

func (o MapEventBus) Add(msg string, vo *PluginBase) {

	v := o[msg]
	for _, obj := range v {
		if obj == vo {
			return
		}
	}
	v = append(v, vo)
	o[msg] = v
}

func (o MapEventBus) Remove(msg string, vo *PluginBase) {
	v, ok := o[msg]
	if !ok {
		return
	}
	index := -1
	for i, obj := range v {
		if obj == vo {
			index = i
		}
	}
	if index != -1 {
		v[index] = v[len(v)-1]
		v = v[:len(v)-1]
	}
	o[msg] = v
}

// BroadcastMsg In case vo is provided the msg will be filtered (not provided) to this plugin
// used in case we want to filter message to the same object the publish them
func (o MapEventBus) BroadcastMsg(vo *PluginBase, msg string, a, b interface{}) {
	v, ok := o[msg]
	if !ok {
		return
	}
	for _, obj := range v {
		if obj != vo {
			obj.I.OnEvent(msg, a, b)
		}
	}
}

type PluginLevelType uint8

const (
	PLUGIN_LEVEL_CLIENT = 16
	PLUGIN_LEVEL_NS     = 17
	PLUGIN_LEVEL_THREAD = 18
)

/* PluginCtx manage plugins */
type PluginCtx struct {
	Client     *CClient
	Ns         *CNSCtx
	Tctx       *CThreadCtx
	T          PluginLevelType
	mapPlugins MapPlugins
	eventBus   MapEventBus // event bus
}

func NewPluginCtx(client *CClient,
	ns *CNSCtx,
	tctx *CThreadCtx,
	t PluginLevelType) *PluginCtx {
	o := new(PluginCtx)
	o.Client = client
	o.Ns = ns
	o.Tctx = tctx
	o.T = t
	o.mapPlugins = make(MapPlugins)
	o.eventBus = make(MapEventBus)
	return o
}

// CreatePlugins create plugins with default init value, called when a new object client/ns/thread is created
func (o *PluginCtx) CreatePlugins(plugins []string, initJson [][]byte) error {
	/* nothing to do */
	if len(plugins) == 0 {
		return nil
	}

	var errstrings []string
	initlen := len(initJson)
	for i, pl := range plugins {
		var initobj []byte
		initobj = nil
		if i < initlen {
			initobj = initJson[i]
		}
		l := o.addPlugin(pl, initobj)
		if l != nil {
			errstrings = append(errstrings, l.Error())
		}
	}
	if len(errstrings) == 0 {
		return nil
	}
	return fmt.Errorf(strings.Join(errstrings, "\n"))
}

func (o *PluginCtx) OnRemove() {

	/* free all clients plugins */
	for k := range o.mapPlugins {
		o.RemovePlugins(k)
	}

	/* clean the event bus */
	for k := range o.eventBus {
		delete(o.eventBus, k)
	}
}

func (o *PluginCtx) getRegLevel(v *PluginRegisterData) IPluginRegister {
	var p IPluginRegister

	if o.T == PLUGIN_LEVEL_CLIENT {
		p = v.Client
	} else if o.T == PLUGIN_LEVEL_NS {
		p = v.Ns
	} else {
		p = v.Thread
	}
	return p
}

// addPlugin add one plugin to PluginCtx
func (o *PluginCtx) addPlugin(pl string, initJson []byte) error {

	v, ok := pluginregister.M[pl]
	if !ok {
		return fmt.Errorf("plugins-add %s does not exits ", pl)
	}
	p := o.getRegLevel(&v)

	nobj := p.NewPlugin(o, initJson)

	_, ok = o.mapPlugins[pl]
	if ok {
		s := fmt.Sprintf(" plugin %s already exits ", pl)
		panic(s)
	}

	o.mapPlugins[pl] = nobj
	return nil
}

// RemovePlugins remove plugin
func (o *PluginCtx) RemovePlugins(pl string) error {
	_, ok := pluginregister.M[pl]
	if !ok {
		return fmt.Errorf("plugins-remove %s does not exits ", pl)
	}
	obj, ok1 := o.mapPlugins[pl]
	if !ok1 {
		return fmt.Errorf("plugins-remove %s does not exits ", pl)
	}
	obj.I.OnRemove(o)
	return nil
}

//GetOrCreate if it wasn't created by RPC with default json, try to create a default with nil JSON data
//
func (o *PluginCtx) GetOrCreate(pl string) *PluginBase {
	obj, ok := o.mapPlugins[pl]
	if !ok {
		o.addPlugin(pl, nil)
		obj = o.Get(pl)
	}

	if obj == nil {
		panic("GetOrCreate return nil ")
	}
	return obj
}

// Get return the dynamic pointer to a plugin
func (o *PluginCtx) Get(pl string) *PluginBase {

	obj, ok := o.mapPlugins[pl]
	if !ok {
		return nil
	} else {
		return obj
	}
}

// BroadcastMsg send the event for all the plugins registers , skip this plugin provided in this (if not nil)
func (o *PluginCtx) BroadcastMsg(ov *PluginBase, msg string, a, b interface{}) {
	o.eventBus.BroadcastMsg(ov, msg, a, b)
}

/*RegisterEvents  register events, should be called in create callback */
func (o *PluginCtx) RegisterEvents(ov *PluginBase, events []string) {
	for _, obj := range events {
		o.eventBus.Add(obj, ov)
	}
}

/*UnregisterEvents  unregister events, should be called OnRemove */
func (o *PluginCtx) UnregisterEvents(ov *PluginBase, events []string) {
	for _, obj := range events {
		o.eventBus.Remove(obj, ov)
	}
}

///////////////////////////////////////////////////

/* read only map, init */
var pluginregister pluginRegister

// PluginRegister register per plugin 3 level information
func PluginRegister(pi string, pr PluginRegisterData) {
	_, ok := pluginregister.M[pi]
	if ok {
		s := fmt.Sprintf(" can't register the same plugin twice %s ", pi)
		panic(s)
	}
	fmt.Sprintf(" register plugin %s ", pi)
	pluginregister.M[pi] = pr
}

func init() {
	if runtime.NumGoroutine() != 1 {
		panic(" NumGoroutine() should be 1 on init time, require lock  ")
	}
	pluginregister.M = make(map[string]PluginRegisterData)
}
