// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package core

import (
	"math"
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

/*
Calculate the number of ticks and the burstSize in a duration of time.
There might be need to send just one packet (no burst) if the duration is long enough,
or to send a burst of packets every 1 tick.
Params:
duration: Duration between two consecutive calls, DeltaTime.

Returns:
ticks: How many ticks in this durations
burstSize : How many packets to send on each tick size.
*/
func (o *TimerCtx) DurationToTicksBurst(duration time.Duration) (ticks, burstSize uint32) {
	if duration >= o.TickDuration {
		/* The duration is more then the granularity, so no need to sends burts of packets.
		   However there might be cases like duration = 15 msec, but the granularity is 10 msec,
		   in these cases we make the duration smaller, so we might actually finish faster. */
		return o.DurationToTicks(duration), 1
	}
	if duration == 0 {
		panic("Shouldn't call with duration 0")
	}
	/* The duration is smaller then the minimal tick granularity, so need to do bursts each 1 ticks.
	   In cases like 3 msec but the granularity is 10 msec, we would send 9 packets, so it can take longer.
	   In cases like 6 msec but the granulatiry is 10 msec, we would sent 12 packets so it can overflow */
	return 1, uint32(math.Round(float64(o.TickDuration) / float64(duration)))

}
