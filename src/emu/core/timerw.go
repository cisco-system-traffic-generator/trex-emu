package core

/* CNATimerWheel

This class was ported from TRex c++ server

It has two levels of tw

Example:

* 2x1024 buckets
* 2 levels
* Level 1 div = 16 .
* Each tick is configured to 1msec

it would give:

level 0: 1msec - 1sec 	(res = 1msec)
level 1: 1sec -- 67sec    (res=64msec)



tw.Create(1024,16)


tm.Start(event,ticks)
tm.Stop(event)
tm.OnTick() // should be called every 1msec


*/

import (
	"unsafe"
)

const (
	RC_HTW_OK                  = 0
	RC_HTW_ERR_NO_RESOURCES    = -1
	RC_HTW_ERR_TIMER_IS_ON     = -2
	RC_HTW_ERR_NO_LOG2         = -3
	RC_HTW_ERR_MAX_WHEELS      = -4
	RC_HTW_ERR_NOT_ENOUGH_BITS = -5
)

type RCtw int

//convert errn to string
func (o RCtw) String() string {

	switch o {
	case RC_HTW_OK:
		return "RC_HTW_OK"
	case RC_HTW_ERR_NO_RESOURCES:
		return "RC_HTW_ERR_NO_RESOURCES"
	case RC_HTW_ERR_TIMER_IS_ON:
		return "RC_HTW_ERR_TIMER_IS_ON"
	case RC_HTW_ERR_NO_LOG2:
		return "RC_HTW_ERR_NO_LOG2"
	case RC_HTW_ERR_MAX_WHEELS:
		return "RC_HTW_ERR_MAX_WHEELS"
	case RC_HTW_ERR_NOT_ENOUGH_BITS:
		return "RC_HTW_ERR_NOT_ENOUGH_BITS"
	default:
		return "Unknown RC_HTW_ERR"

	}
}

type cHTimerWheelLink struct {
	next *cHTimerWheelLink
	prev *cHTimerWheelLink
}

func (o *cHTimerWheelLink) reset() {
	o.next = nil
	o.prev = nil
}

func (o *cHTimerWheelLink) setSelf() {
	o.next = o
	o.prev = o
}

func (o *cHTimerWheelLink) isSelf() bool {
	if o.next == o {
		return (true)
	}
	return (false)
}

func (o *cHTimerWheelLink) append(obj *cHTimerWheelLink) {
	obj.next = o
	obj.prev = o.prev
	o.prev.next = obj
	o.prev = obj
}

func (o *cHTimerWheelLink) detach() {
	if o.next == nil {
		panic(" next can't zero ")
	}
	next := o.next
	next.prev = o.prev
	o.prev.next = next
	o.next = nil
	o.prev = nil
}

type cHTimerBucket struct {
	cHTimerWheelLink
	count uint32
}

func (o *cHTimerBucket) resetCount() {
	o.count = 0
}

func (o *cHTimerBucket) append(obj *cHTimerWheelLink) {
	o.cHTimerWheelLink.append(obj)
	o.count++
}

func (o *cHTimerBucket) decCount() {
	if o.count == 0 {
		panic(" counter can't be zero ")
	}
	o.count--
}

// To do replace with Event
// CHTimerOnEvent callback interface
type CHTimerOnEvent interface {
	OnEvent(a, b interface{})
}

// CHTimerObj timer object to allocate
type CHTimerObj struct {
	cHTimerWheelLink
	root      *cHTimerBucket
	ticksLeft uint32
	wheel     uint8
	typeFlags uint8
	cb        CHTimerOnEvent // callback interface
	cbA       interface{}    // callback A args
	cbB       interface{}    // callback B args
}

func (o *CHTimerObj) SetCB(cb CHTimerOnEvent, a interface{}, b interface{}) {
	o.cb = cb
	o.cbA = a
	o.cbB = b
}

func (o *CHTimerObj) call() {
	o.cb.OnEvent(o.cbA, o.cbB)
}

func (o *CHTimerObj) reset() {
	o.cHTimerWheelLink.reset()
}

func (o *CHTimerObj) IsRunning() bool {
	if o.next != nil {
		return (true)
	}
	return (false)
}

func (o *CHTimerObj) detach() {
	o.root.decCount()
	o.root = nil
	o.cHTimerWheelLink.detach()
}

const (
	hNA_TIMER_LEVELS      = 2
	hNA_MAX_LEVEL1_EVENTS = 64 /* small bursts */
)

type naHtwStateNum uint8

type cHTimerOneWheel struct {
	buckets      []cHTimerBucket
	activeBucket *cHTimerBucket
	bucketIndex  uint32
	ticks        uint32
	wheelSize    uint32
	wheelMask    uint32
	tickDone     bool
}

func utlIslog2(num uint32) bool {
	var mask uint32
	mask = 1
	for i := 0; i < 31; i++ {
		if mask == num {
			return (true)
		}
		if mask > num {
			return (false)
		}
		mask = mask << 1
	}
	return (false)
}

func utllog2Shift(num uint32) uint32 {
	var mask uint32
	mask = 1

	for i := 0; i < 31; i++ {
		if mask == num {
			return (uint32(i))
		}
		if mask > num {
			return 0
		}
		mask = mask << 1
	}
	return 0xffffffff
}

// create a new single TW with number of buckets
func newTWOne(size uint32) (*cHTimerOneWheel, RCtw) {

	var o *cHTimerOneWheel

	o = new(cHTimerOneWheel)

	r := o.initTWOne(size)

	return o, r
}

// place holder
func delTWOne(o *cHTimerOneWheel) RCtw {
	return RC_HTW_OK
}

// create a new single TW with number of buckets
func (o *cHTimerOneWheel) initTWOne(size uint32) RCtw {

	if !utlIslog2(size) {
		return RC_HTW_ERR_NO_LOG2
	}
	o.wheelMask = size - 1
	o.wheelSize = size
	o.buckets = make([]cHTimerBucket, size)
	o.activeBucket = &o.buckets[0]
	for i := 0; i < int(size); i++ {
		obj := &o.buckets[i]
		obj.setSelf()
		obj.resetCount()
	}
	return RC_HTW_OK
}

func convPtr(o *cHTimerWheelLink) *CHTimerObj {
	return (*CHTimerObj)(unsafe.Pointer(o))
}

func (o *cHTimerOneWheel) detachAll() uint32 {

	var totalEvents uint32
	for i := 0; i < int(o.wheelSize); i++ {
		b := &o.buckets[i]

		for !b.isSelf() {
			first := convPtr(b.next)
			first.detach()
			totalEvents++
			first.call()
		}
	}
	return totalEvents
}

func (o *cHTimerOneWheel) start(tmr *CHTimerObj, ticks uint32) RCtw {
	if tmr.IsRunning() {
		return RC_HTW_ERR_TIMER_IS_ON
	}
	o.append(tmr, uint32(ticks))
	return RC_HTW_OK
}

func (o *cHTimerOneWheel) stop(tmr *CHTimerObj) {
	if tmr.IsRunning() {
		tmr.detach()
	}
}

func (o *cHTimerOneWheel) nextTick() bool {
	o.ticks++
	o.bucketIndex++

	if o.tickDone {
		o.tickDone = false
	}
	if o.bucketIndex == o.wheelSize {
		o.bucketIndex = 0
		o.tickDone = true
	}
	o.activeBucket = &o.buckets[o.bucketIndex]
	return (o.tickDone)
}

func (o *cHTimerOneWheel) popEvent() *CHTimerObj {

	if o.activeBucket.isSelf() {
		return nil
	}

	first := convPtr(o.activeBucket.next)
	first.detach()
	return (first)
}

func (o *cHTimerOneWheel) append(tmr *CHTimerObj, ticks uint32) {

	var cursor uint32
	var cur *cHTimerBucket
	cursor = ((o.bucketIndex + ticks) & o.wheelMask)
	cur = &o.buckets[cursor]

	tmr.root = cur /* set root */
	cur.append(&tmr.cHTimerWheelLink)
}

func (o *cHTimerOneWheel) getActiveBucketTotalEvents() uint32 {
	return o.activeBucket.count
}

// CNATimerWheel struct
type CNATimerWheel struct {
	ticks            [hNA_TIMER_LEVELS]uint32
	wheelSize        uint32
	wheelMask        uint32
	wheelShift       uint32
	wheelLevel1Shift uint32
	wheelLevel1Err   uint32
	totalEvents      uint64
	timerw           [hNA_TIMER_LEVELS]cHTimerOneWheel
	state            naHtwStateNum
	cntDiv           uint16 /*div of time for level1 */
	cntState         uint16 /* the state of level1 for cnt mode */
	cntPerIte        uint32
}

// InitTW init the timer
func (o *CNATimerWheel) InitTW(size uint32, level1Div uint32) RCtw {

	for i := 0; i < hNA_TIMER_LEVELS; i++ {
		res := o.timerw[i].initTWOne(size)
		if res != RC_HTW_OK {
			return res
		}
		o.ticks[i] = 0
	}

	if !utlIslog2(level1Div) {
		return RC_HTW_ERR_NO_LOG2
	}

	o.wheelShift = utllog2Shift(size)
	o.wheelMask = size - 1
	o.wheelSize = size
	o.wheelLevel1Shift = o.wheelShift - utllog2Shift(level1Div)
	o.wheelLevel1Err = ((1 << (o.wheelLevel1Shift)) - 1)
	o.cntDiv = 1 << o.wheelLevel1Shift
	return RC_HTW_OK
}

// NewTimerW create a new TW with number of buckets and div
func NewTimerW(size uint32, level1Div uint32) (*CNATimerWheel, RCtw) {

	var o *CNATimerWheel

	o = new(CNATimerWheel)

	r := o.InitTW(size, level1Div)

	return o, r
}

/* onTickLevel0 handle the tick of the first level */
func (o *CNATimerWheel) onTickLevel0() {
	tm := &o.timerw[0]

	for {
		event := tm.popEvent()
		if event == nil {
			break
		}
		o.totalEvents--
		event.call()
	}

	tm.nextTick()
	o.ticks[0]++
}

func (o *CNATimerWheel) onTickLevelInc(level uint8) {

	o.cntState++
	tm := &o.timerw[level]
	if o.cntState == o.cntDiv {
		tm.nextTick()
		o.ticks[level]++
		o.cntState = 0
	}
}

func max(a, b uint32) uint32 {
	if a < b {
		return b
	}
	return a
}

func (o *CNATimerWheel) restart(tmr *CHTimerObj, ticks uint32) {

	nticks := (ticks + o.wheelLevel1Err) >> o.wheelLevel1Shift

	if nticks < o.wheelSize {
		if nticks < 2 {
			nticks = 2
		}
		tmr.ticksLeft = 0
		tmr.wheel = 1
		o.timerw[1].start(tmr, nticks-1)
	} else {
		tmr.ticksLeft = ticks - ((o.wheelSize - 1) << o.wheelLevel1Shift)
		tmr.wheel = 1
		o.timerw[1].start(tmr, o.wheelSize-1)
	}
}

// OnTickLevel call by global tick
func (o *CNATimerWheel) onTickLevel(level uint8, minEvents uint32, left *uint32) uint16 {
	tm := &o.timerw[level]
	var cnt uint32
	cnt = 0
	oldState := o.cntState

	*left = tm.getActiveBucketTotalEvents()

	if *left == 0 {
		o.onTickLevelInc(level)
		return (oldState)
	}

	if o.cntState == 0 {
		steps := (*left + uint32(o.cntDiv) - 1) / uint32(o.cntDiv)
		o.cntPerIte = max(steps, minEvents)
	}

	for {
		event := tm.popEvent()
		if event == nil {
			break
		}
		if event.ticksLeft == 0 {
			o.totalEvents--
			event.call()
		} else {
			o.restart(event, event.ticksLeft)
		}
		cnt++
		if cnt == o.cntPerIte {
			o.onTickLevelInc(level)
			*left -= cnt
			return (oldState)
		}
	}

	*left = tm.getActiveBucketTotalEvents()
	o.onTickLevelInc(level)
	return (oldState)
}

// OnTick return if there is a residue
func (o *CNATimerWheel) OnTick(minEvents uint32) {
	var left uint32
	left = 0
	o.onTickLevel0()
	o.onTickLevel(1, minEvents, &left)
}

// Stop schedule a timer event
func (o *CNATimerWheel) Stop(tmr *CHTimerObj) {
	if tmr.IsRunning() {
		o.timerw[tmr.wheel].stop(tmr)
		o.totalEvents--
	}
}

// Start schedule a timer event
func (o *CNATimerWheel) Start(tmr *CHTimerObj, ticks uint32) {
	o.totalEvents++
	if ticks < o.wheelSize {
		tmr.ticksLeft = 0
		tmr.wheel = 0
		o.timerw[0].start(tmr, ticks)
	}
	o.restart(tmr, ticks)
}
