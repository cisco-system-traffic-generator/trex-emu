// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package core

import (
	"time"
)

/* timer context there is one per thread ctx
   tick is 10msec. two levels
*/

/* ticks */
const (
	eTIMER_TICK                = 10 * time.Millisecond
	eTIMER_TICK_SIM            = 100 * time.Millisecond
	eTIMERW_SECOND_LEVEL_BURST = 32
)

type TimerCtx struct {
	Timer        *time.Timer   // the timer
	TickDuration time.Duration // the duration of the tick
	timerw       *CNATimerWheel
	Ticks        uint64
	Cdb          *CCounterDb
}

// NewTimerCtx create a context
func NewTimerCtx(simulation bool) *TimerCtx {
	o := new(TimerCtx)
	var timerw *CNATimerWheel
	var rc RCtw
	if simulation {
		o.TickDuration = eTIMER_TICK_SIM
		o.Timer = time.NewTimer(o.TickDuration)
		timerw, rc = NewTimerW(128, 16)

	} else {
		o.TickDuration = eTIMER_TICK
		o.Timer = time.NewTimer(o.TickDuration)
		timerw, rc = NewTimerW(1024, 16)

	}
	if rc != RC_HTW_OK {
		panic("can't init timew")
	}
	o.timerw = timerw
	o.Cdb = NewCCounterDb("timerw")
	o.Cdb.Add(&CCounterRec{
		Counter:  &o.timerw.totalEvents,
		Name:     "activeTimer",
		Help:     "active timers",
		Unit:     "timers",
		DumpZero: false,
		Info:     ScINFO})
	o.Cdb.Add(&CCounterRec{
		Counter:  &o.Ticks,
		Name:     "ticks",
		Help:     "ticks",
		Unit:     "ops",
		DumpZero: false,
		Info:     ScINFO})

	return o
}

func (o *TimerCtx) ActiveTimers() uint64 {
	return o.timerw.ActiveTimers()
}

func (o *TimerCtx) IsRunning(tmr *CHTimerObj) bool {
	return tmr.IsRunning()
}

// Stop the timer, make sure it is not running
func (o *TimerCtx) Stop(tmr *CHTimerObj) {
	o.timerw.Stop(tmr)
}

//MinTickMsec() return how long take a one tick in msec by default it is 10
func (o *TimerCtx) MinTickMsec() uint32 {
	return uint32(o.TickDuration / time.Millisecond)
}

func (o *TimerCtx) TicksInSec() float64 {
	return float64(time.Duration(o.Ticks)*o.TickDuration) / 1e9
}

// DurationToTicks convert to ticks for better performance
func (o *TimerCtx) DurationToTicks(duration time.Duration) uint32 {
	ticks := uint32(duration / o.TickDuration)
	return ticks
}

// StartTicks start the timer using ticks instead of time
func (o *TimerCtx) StartTicks(tmr *CHTimerObj, ticks uint32) {
	o.timerw.Start(tmr, ticks)
}

// Start timer by duration
func (o *TimerCtx) Start(tmr *CHTimerObj, duration time.Duration) {
	ticks := o.DurationToTicks(duration)
	o.timerw.Start(tmr, ticks)
}

// HandleTicks should be called only by main loop
func (o *TimerCtx) HandleTicks() {
	o.Ticks++
	o.timerw.OnTick(eTIMERW_SECOND_LEVEL_BURST)
	o.Timer.Reset(o.TickDuration)
}
