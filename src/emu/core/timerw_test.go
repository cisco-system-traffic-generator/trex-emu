package core

import (
	"fmt"
	"testing"
)

/*var i, numEvent uint32

numEvent = 1
var events = make([]myEventTest, numEvent)

for i = 0; i < numEvent; i++ {
	var e *myEventTest
	e = &events[i]
	e.id = i + 1
	e.dTick = 1200 + i
	e.tTick = e.dTick
	e.timerw = &timerw
	e.SetCB(&events[i], nil, nil)
	timerw.start(&e.CHTimerObj, e.dTick)
}

for i = 0; i < 1300; i++ {
	var left uint32
	fmt.Printf("-[tick %d] \n", i)
	timerw.onTickLevel0()
	timerw.OnTickLevel(1, 16, &left)
}*/

type myTest1Stats struct {
	ticks     uint32
	firstTick uint32
}
type myEventTest struct {
	CHTimerObj
	id     uint32
	dTick  uint32
	tTick  uint32
	timerw *CNATimerWheel
	stats  *myTest1Stats
}

func (o *myEventTest) OnEvent(a, b interface{}) {
	//fmt.Printf(" [event %d] \n", o.id)
	o.timerw.Start(&o.CHTimerObj, 2)
	o.stats.ticks++
	if o.stats.firstTick == 0 {
		o.stats.firstTick = o.timerw.ticks[0]
	}
}

func TestTimerw1(t *testing.T) {
	var timerw *CNATimerWheel
	var rc RCtw
	timerw, rc = NewTimerW(1024, 16)
	if rc != RC_HTW_OK {
		panic("can't init timew")
	}
	var i, numEvent, maxTicks uint32
	numEvent = 2
	maxTicks = 100

	var events = make([]myEventTest, numEvent)
	var globalStats myTest1Stats

	for i = 0; i < numEvent; i++ {
		var e *myEventTest
		e = &events[i]
		e.id = i + 1
		e.dTick = 10 + i
		e.tTick = e.dTick
		e.timerw = timerw
		e.stats = &globalStats
		e.SetCB(&events[i], nil, nil)
		timerw.Start(&e.CHTimerObj, e.dTick)
	}

	for i = 0; i < maxTicks; i++ {
		//fmt.Printf("-[tick %d] \n", i)
		timerw.OnTick(16)
	}

	expectedTicks := (maxTicks - 10) * numEvent / 2
	fmt.Println(globalStats)

	if globalStats.ticks != expectedTicks {
		t.Fatalf(" expected ticks %d is not %d ", globalStats.ticks, expectedTicks)
	}
}

func TestTimerw2(t *testing.T) {
	var timerw *CNATimerWheel
	var rc RCtw
	timerw, rc = NewTimerW(1024, 16)
	if rc != RC_HTW_OK {
		panic("can't init timew")
	}
	var i, numEvent, maxTicks uint32
	numEvent = 1
	maxTicks = 2000

	var events = make([]myEventTest, numEvent)
	var globalStats myTest1Stats

	for i = 0; i < numEvent; i++ {
		var e *myEventTest
		e = &events[i]
		e.id = i + 1
		e.dTick = 1200 + i
		e.tTick = e.dTick
		e.timerw = timerw
		e.stats = &globalStats
		e.SetCB(&events[i], nil, nil)
		timerw.Start(&e.CHTimerObj, e.dTick)
	}

	for i = 0; i < maxTicks; i++ {
		timerw.OnTick(16)
	}

	fmt.Println(globalStats)

	var expectedTicks uint32
	expectedTicks = 424
	if globalStats.firstTick != 1153 {
		t.Fatalf(" First ticks error ")
	}
	if globalStats.ticks != expectedTicks {
		t.Fatalf(" expected ticks %d is not %d ", globalStats.ticks, expectedTicks)
	}
}
