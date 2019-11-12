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
	eTIMERW_SECOND_LEVEL_BURST = 32
)

type TimerCtx struct {
	Timer        *time.Timer   // the timer
	TickDuration time.Duration // the duration of the tick
	timerw       *CNATimerWheel
	Ticks        uint64
}

// NewTimerCtx create a context
func NewTimerCtx() *TimerCtx {
	o := new(TimerCtx)
	o.TickDuration = eTIMER_TICK
	o.Timer = time.NewTimer(o.TickDuration)
	timerw, rc := NewTimerW(1024, 16)
	if rc != RC_HTW_OK {
		panic("can't init timew")
	}
	o.timerw = timerw
	return o
}

func (o *TimerCtx) IsRunning(tmr *CHTimerObj) bool {
	return tmr.IsRunning()
}

// Stop the timer, make sure it is not running
func (o *TimerCtx) Stop(tmr *CHTimerObj) {
	o.timerw.Stop(tmr)
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
