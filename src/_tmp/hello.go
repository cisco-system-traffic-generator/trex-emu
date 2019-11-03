package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"external/google/gopacket/pcapgo"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/go-ffmt/ffmt"
)

const s string = "constant"

func testSwitch() {

	i := 7

	switch i {
	case 1:
		fmt.Println("1")
	case 2:
		fmt.Println("2")
	case 3:
		fmt.Println("3")
	default:
		fmt.Println("default")
	}
}

func testLoops() {

	i := 1
	fmt.Println("start")
	for i <= 3 {
		fmt.Println(i)
		i++
	}
	fmt.Println("end")

	for j := 7; j <= 9; j++ {
		fmt.Print(j)
	}

	for {
		fmt.Println("\nbreak")
		break
	}

	fmt.Println("start 5 loop")
	for n := 0; n <= 5; n++ {
		if n%2 == 0 {
			continue
		}
		fmt.Println(n)
	}
	fmt.Println("end")

}

func test() {
	const n = 500000
	const i uint32 = 17

	fmt.Println("hello world 1 " + "hey")
	fmt.Println("1+1 =", 1+1, "12", 14)
	fmt.Println(true && false)
	fmt.Println(false && false)
	fmt.Println(!true)
	fmt.Println(s, i, n)
}

func testNumbers() {
	//var a uint8
	//var b float64
	//a = 12
	//b = 12.34

	var c [10]uint32
	fmt.Println(c)
	fmt.Println(len(c))

	for i := 1; i < 10; i++ {
		c[i] = uint32(i)
	}

	for i := 1; i < 10; i++ {
		fmt.Println(i, c[i])
	}
}

func testVectors() {
	s := make([]string, 0)
	s = append(s, "a")
	s = append(s, "b")
	s = append(s, "c")
	fmt.Println(cap(s))
	fmt.Println(s)

	for i := 0; i < len(s); i++ {
		fmt.Println(s[i])
	}

	s1 := s[0:2]
	s2 := make([]string, 0)
	if cap(s2) < len(s) {
		s3 := make([]string, len(s))
		copy(s3, s)
		fmt.Println("s3")
		fmt.Println(s3)
		s2 = s3
	}

	fmt.Println(s1)
	copy(s2, s)
	s = append(s, "d")
	fmt.Println(s2)
	fmt.Println(s)
}

// mapTest is an example for a test
// input :
// output:
func mapTest() {
	m := make(map[string]string)
	m["k1"] = "k1"
	m["k2"] = "k2"
	fmt.Println(m)

	s := m["k1"]
	fmt.Println(s)

	var valid bool
	s, valid = m["k6"]

	if valid {
		fmt.Println(valid)
		fmt.Println(len(s))
	}
}

func mapTest2() {

	var a uint32
	var b bool
	b = true
	a = 0xFFFF1122
	a ^= 0x11110000

	var c float64
	c = 12.1234
	e := [5]int{1, 2, 3, 4, 5}
	var d = make([]int, 0)
	d = append(d, 1)
	d = append(d, 2)
	d = append(d, 3)
	fmt.Printf(" this is an example %v %d 0x%x %2.4f \n", b, a, a, c)
	s := fmt.Sprintf(" this is an example %v %d 0x%x %2.4f \n", b, a, a, c)
	fmt.Print(s)

	fmt.Printf(" array %v %v \n", d, e)
}

func mapTes4() {
	n := map[string]int{"foo": 1, "bar": 2}
	fmt.Println(n)
}

func mapTes3(size int, debug bool) {
	m := make(map[string]int)

	for i := 0; i < size; i++ {
		key := fmt.Sprintf("key%d", i)
		if debug {
			fmt.Printf(" adding %v:%v \n", key, i)
		}
		m[key] = i
	}

	for i := 0; i < size; i++ {
		key := fmt.Sprintf("key%d", i)

		var v int
		var f bool

		v, f = m[key]
		if !f {
			fmt.Println("ERROR 1")
		} else {
			if v != i {
				fmt.Println("ERROR 2")
			}
		}
	}
	fmt.Println(len(m))
}

func rangeTest() {

	d := []int{1, 2, 3, 5, 6}
	for i, num := range d {
		fmt.Println(i, num)
	}

	m := map[string]int{"a": 1, "b": 2}

	for k, v := range m {
		fmt.Println(k, v)
	}

}

func calcAB(a, b int) (int, int, int) {

	return a + b, a - b, a * b
}

func testCalc() {
	var a, b, c int
	a, b, c = calcAB(10, 20)
	fmt.Println(a, b, c)
}

func test1(a int) int {
	return a + 7
}

func testClosure() {
	var f, f1 func(a int) int
	f = func(a int) int {

		return a + 7
	}
	f1 = test1

	fmt.Println(f(19), f1(19))
}

func zeroval(val *int) {
	*val = 12
}

func testPointers() {
	var a int
	zeroval(&a)
	fmt.Println(a, &a)
}

type myInt uint32

// CPersonIf is somthing
type CPersonIf interface {
	Dump() string
}

// CPersonBase object represent a
// person
type CPersonBase struct {
	name     string
	age      int
	_Private int
}

// CPersonBaseCreate create an object
func CPersonBaseCreate() *CPersonBase {
	obj := new(CPersonBase)
	obj.name = "a"
	obj.age = 12
	return obj
}

// Delete CPersonBase delete an CPersonBase
func (o *CPersonBase) Delete() {
	o.age = 0
}

func (o *CPersonBase) getName() string {
	return o.name
}

// Dump the name of the object
func (o *CPersonBase) Dump() string {
	fmt.Println("base", o.name)
	return ""
}

// CPersonAna Ana
type CPersonAna struct {
	CPersonBase
	dogName string
}

// Dump the name of the object
func (o *CPersonAna) Dump() string {
	fmt.Println("ana", o.name, o.dogName)
	return ""
}

func dumpObj(_if CPersonIf) {
	_if.Dump()
}

func testClass() {
	a := new(CPersonBase)
	//{name:"Bob",age:12}
	a.name = "bob"
	a.age = 12
	a._Private = 14
	dumpObj(a)

	b := new(CPersonAna)
	//{name:"Bob",age:12}
	b.name = "bob1"
	b.age = 12
	b._Private = 14
	fmt.Println(b.getName())
	b.dogName = "Boki"

	dumpObj(b)

	//fmt.Println(a)
}

func testClass2() {
	obj := CPersonBaseCreate()
	fmt.Println(obj)

	obj.Dump()
	obj.Delete()

	//fmt.Println(a)
}

func typeDef() {
	var a myInt
	a = 12
	fmt.Println(a)
}

func funcError(a int) (int, error) {
	if a == 0 {
		return -1, fmt.Errorf("this is an error %d ", 12)
	}
	return 0, nil
}

func testErr() {
	var b int
	var err, err1 error

	fmt.Println(reflect.TypeOf(b))

	fmt.Printf("%T", b)
	fmt.Printf(" type: %d %d \n", reflect.TypeOf(b).Kind(), reflect.Int)

	//if reflect.TypeOf(b).Kind() == Int {
	//fmt.Println(" working")
	//}

	_, err = funcError(0)
	if err != nil {
		fmt.Println("ERROR", err)
	}
	b, err1 = funcError(0)
	if err1 != nil {
		fmt.Println(b)
	}
}

func strSplit() {

	a := "a , 12, abf, 12,15"
	l := strings.Split(a, ",")
	for i, o := range l {
		l[i] = strings.TrimSpace(o)
	}

	for _, o := range l {
		fmt.Printf("'%s'\n", o)
	}
}

func testRegEx() {
	// very nice package
	// link https://golang.org/pkg/regexp/syntax/
	r, _ := regexp.Compile(`^p([a-z]+)ch\s+(\d+)\s+(\d+)\s+(\w+)`)
	fmt.Printf("%#v\n", r.FindStringSubmatch("peach 12 13 abc  "))

	//match, _ := regexp.MatchString(`^p([a-z]+)ch\d+`, "peach 12 13 abc  ")
	//fmt.Println(match)
	//r, _ := regexp.Compile("p([a-z]+)ch")
	//fmt.Println(r.MatchString("peach"))
}

func highResTick() {

	var now time.Time
	var d time.Duration

	for i := 0; i < 10; i++ {
		now = time.Now()
		d = time.Now().Sub(now)
		fmt.Println(now.Unix(), now.UnixNano(), d)
	}
	fmt.Println("---")
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 10; i++ {
		now = time.Now()
		fmt.Println(now.Unix(), now.UnixNano())
	}
}

func testRand() {
	fmt.Print(rand.Intn(100), ",", rand.Intn(100), "\n")
}

func testChan2(c chan uint32) {
	for i := 0; i < 1000; i++ {
		select {
		case c <- uint32(i):
		default:
		}
	}
}

func chanTest() {
	msgQue := make(chan uint32, 100)
	var sum uint64
	sum = 0

	go testChan2(msgQue)

	time.Sleep(1 * time.Second)
	for i := 0; i < 100; i++ {
		msg := <-msgQue
		sum += uint64(msg)
	}
	fmt.Println(sum)
}

func timerTest() {
	timer1 := time.NewTimer(2 * time.Second)
	timer2 := time.NewTimer(1 * time.Second)
	//timer3 := time.NewTimer(10 * time.Second)

	for {
		select {
		case <-timer1.C:
			fmt.Println("1")
			//timer1 = time.NewTimer(2 * time.Second)
		case <-timer2.C:
			fmt.Println("2")
		default:
			break
		}
	}
}

type cOnEvent interface {
	onEvent(a, b interface{})
}

type cAMsgTimerEvent struct {
	obj *cA
}

func newTimerEvent(o *cA, a, b interface{}) cOnEvent {

	msg := new(cAMsgTimerEvent)
	msg.obj = o
	return msg
}

func (o *cAMsgTimerEvent) onEvent(a, b interface{}) {
	o.obj.onTimerEvent(a, b)
}

type cA struct {
	name string
	age  int
}

func (o *cA) onEvent(a, b interface{}) {
	fmt.Printf("A: onEvent %T %#v %T %v n:%s\n", a, a, b, b, o.name)
}

func (o *cA) onTimerEvent(a, b interface{}) {
	fmt.Printf("A TimeEvent: onEvent %T %#v %T %v n:%s\n", a, a, b, b, o.name)
}

type cB struct {
	name string
	age  int
}

func (o *cB) onEvent(a, b interface{}) {
	fmt.Printf("B: onEvent %T %#v %T %v \n", a, a, b, b)
}

type onEventCb func(o interface{}, a, b interface{})

func callEvent(event cOnEvent) {
	fmt.Println(unsafe.Sizeof(event))
	event.onEvent(2, "b")
}

func testCallbacks() {
	a := new(cA)
	b := new(cB)
	a.name = "string"
	fmt.Println(unsafe.Sizeof(*a))

	//make(map[string]string){"a":"b","b":"c"}
	a.onEvent(1, "a")
	//a.OnEvent(1,)
	b.onEvent(1, "a")

	callEvent(a)
	callEvent(b)

	cb := a.onEvent
	fmt.Printf(" callback %T \n", cb)
	cb(2, 2)
	//var cb1 onEventCb
	//cb1 = (*cA).onEvent
	//cb1(a, 3, 3)
	callEvent(newTimerEvent(a, 17, 17))
}

type Parent struct {
	Name string
}

func (p *Parent) Yell() {
	fmt.Println("Parent's yelling")
}

type Child struct {
	Parent // put at top
	Name   string
}

func (p *Child) Yell() {
	p.Parent.Yell()
	fmt.Println("Child yelling")
}

// 1. timer wheel, JSON-RPC per user, client/multi-/packet/save to pcap
// 2. tests
// 3. pkgs
// 4. events t

const (
	RC_HTW_OK                  = 0
	RC_HTW_ERR_NO_RESOURCES    = -1
	RC_HTW_ERR_TIMER_IS_ON     = -2
	RC_HTW_ERR_NO_LOG2         = -3
	RC_HTW_ERR_MAX_WHEELS      = -4
	RC_HTW_ERR_NOT_ENOUGH_BITS = -5
)

type RCtw int

// errors type for timer-wheel
type CHTimerWheelErrorStr int

//convert errn to string
func (o CHTimerWheelErrorStr) String() string {

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

//convert errn to Help string
func (o CHTimerWheelErrorStr) StringHelp() string {

	switch o {
	case RC_HTW_OK:
		return "ok"
	case RC_HTW_ERR_NO_RESOURCES:
		return "not enough memory"
	case RC_HTW_ERR_TIMER_IS_ON:
		return "timer is already on, you should stop before start"
	case RC_HTW_ERR_NO_LOG2:
		return "number of buckets should be log2"
	case RC_HTW_ERR_MAX_WHEELS:
		return "maximum number of wheels is limited to 4"
	case RC_HTW_ERR_NOT_ENOUGH_BITS:
		return "(log2(buckets) * number of wheels)  should be less than 32, try to reduce the number of wheels"
	default:
		return "unknown error "
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

// HTWticks ticks for tw
type HTWticks uint32

// CHTimerOnEvent callback interface
type CHTimerOnEvent interface {
	onEvent(a, b interface{})
}

// CHTimerObj timer object to allocate
type CHTimerObj struct {
	cHTimerWheelLink
	root      *cHTimerBucket
	ticksLeft HTWticks
	wheel     uint8
	typeFlags uint8
	Parent    interface{}    // parent object
	CB        CHTimerOnEvent // callback interface
}

func (o *CHTimerObj) reset() {
	o.cHTimerWheelLink.reset()
}

func (o *CHTimerObj) isRunning() bool {
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

/* CNATimerWheel

This class was ported from TRex c++ server

it has two levels of tw and a few use-cases

* 1024 buckets
* 2 levels
* level 1 div = 16 .
* each tick is configured to  20usec

it would give:

level 0: 20usec -- 20.48 msec res=20usec
level 1: 20msec -- 1.3sec     res=1.3msec

level 1 could be disabled and in all cases the evets are processed in spread mode (there won't be a burst)


use-case 0 - two levels
=========

two levels, spread level #2

level_0
level_1


tw.Create(1024,16)
tw.set_level1_cnt_div(); // calculate the spread factor



On tick - process the two levels
---

tw.on_tick_level0((void *)&m_timer,cb);     << no spread
tw.on_tick_level_count(1,(void *)&m_timer,cb,32,left);   << spread


tw.Delete();


use-case 2 - one level *NOT* spread (simulation is using this mode)
=========

each tick is 50msec

create one level

tw.Create(1024,1)

and then we only should call level0 tick

tw.on_tick_level0((void *)&m_timer,cb);

tw.Delete()



use-case 3 - one level  *spread*
=========


tw.Create(1024,1)
tw.set_level1_cnt_div(50); // manual split of the first level , split the tick to 50 so if we have tick of 1msec every 20usec



one tick
--------
tw.on_tick_level_count(0,(void *)&m_timer,cb,16,left);   << spread



tw.Delete()


*/
const (
	hNA_TIMER_LEVELS      = 2
	hNA_MAX_LEVEL1_EVENTS = 64 /* small bursts */
)

type naHtwStateNum uint8

type cHTimerOneWheel struct {
	buckets      []cHTimerBucket
	activeBucket *cHTimerBucket
	bucketIndex  uint32
	ticks        HTWticks
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

	if !utlIslog2(size) {
		return nil, RC_HTW_ERR_NO_LOG2
	}

	var o *cHTimerOneWheel
	o = new(cHTimerOneWheel)

	o.wheelMask = size - 1
	o.wheelSize = size
	o.buckets = make([]cHTimerBucket, size)

	o.activeBucket = &o.buckets[0]
	for i := 0; i < int(size); i++ {
		obj := &o.buckets[i]
		obj.setSelf()
		obj.resetCount()
	}
	return o, RC_HTW_OK
}

// place holder
func delTWOne(o *cHTimerOneWheel) RCtw {
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
			/* TBD need to fix this */
			//cb(userdata,first);
		}
	}
	return totalEvents
}

func (o *cHTimerOneWheel) stop(tmr *CHTimerObj) {
	if tmr.isRunning() {
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
	cursor = ((o.bucketIndex + uint32(o.ticks)) & o.wheelMask)
	cur = &o.buckets[cursor]

	tmr.root = cur /* set root */
	cur.append(&tmr.cHTimerWheelLink)
}

// CNATimerWheel
type CNATimerWheel struct {
	ticks            [hNA_TIMER_LEVELS]HTWticks
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

/*
// create a new TW with number of buckets
func NewTW(size uint32, level1Div uint8) (*CNATimerWheel, RCtw) {

	var o *CNATimerWheel

	o = new(CNATimerWheel)

	for i := 0; i < hNA_TIMER_LEVELS; i++ {
		res := o.timerw[i].Create(size)
		if res != RC_HTW_OK {
			return nil, res
		}
		o.ticks[i] = 0
	}

	if !utlIslog2(level1Div) {
		return nil, RC_HTW_ERR_NO_LOG2
	}

	o.wheelShift = utllog2Shift(wheel_size)
	o.wheelMask = size - 1
	o.wheelSize = wheel_size
	//m_wheel_level1_shift = m_wheel_shift - utl_log2_shift((uint32_t)level1_div);
	//m_wheel_level1_err  = ((1<<(m_wheel_level1_shift))-1);
	//assert(m_wheel_shift>utl_log2_shift((uint32_t)level1_div));

	//return(RC_HTW_OK);
}
*/
func castingPointers() {
	var p *cHTimerBucket
	p = new(cHTimerBucket)
	p.setSelf()
	p.resetCount()
	fmt.Printf("pointers manipolation %p %T %v \n", p, p, p)
	var v *cHTimerBucket
	v = (*cHTimerBucket)(unsafe.Pointer(p.next))
	fmt.Printf("pointers manipolation %p %T %v \n", v, v, v)
}

type mt struct {
	String string
	Int    int
	Slice  []int
	Map    map[string]interface{}
}

func exampleFfmt() {
	m := mt{
		"hello world",
		100,
		[]int{1, 2, 3, 4, 5, 6},
		map[string]interface{}{
			"A":  123,
			"BB": 456,
		},
	}

	fmt.Println(m) // fmt the default formatting.
	/*
		{hello world 100 [1 2 3 4 5 6] map[BB:456 A:123]}
	*/

	ffmt.Puts(m) // More friendly formatting.
	/*
		{
		String: "hello world"
		Int:    100
		Slice:  [
		1 2 3
		4 5 6
		]
		Map: {
		"A":  123
		"BB": 456
		}
		}
	*/

	ffmt.Print(m) // Same "Puts" but String unadded '"'.
	/*
		{
		String: hello world
		Int:    100
		Slice:  [
		1 2 3
		4 5 6
		]
		Map: {
		A:  123
		BB: 456
		}
		}
	*/

	ffmt.P(m) // Format data and types.
	/*
		main.mt{
		String: string("hello world")
		Int:    int(100)
		Slice:  []int[
		int(1) int(2) int(3)
		int(4) int(5) int(6)
		]
		Map: map[string]interface {}{
		string("A"):  int(123)
		string("BB"): int(456)
		}
		}
	*/

	ffmt.Pjson(m) // Format it in json style.
	/*
		{
		"Int": 100
		,"Map": {
		"A":  123
		,"BB": 456
		}
		,"Slice": [
		1,2,3
		,4,5,6
		]
		,"String": "hello world"
		}
	*/
}

/*func triggerJSONRPC() {
	mr := jsonrpc.NewMethodRepository()

	if err := mr.RegisterMethod("Main.Echo", EchoHandler{}, EchoParams{}, EchoResult{}); err != nil {
		log.Fatalln(err)
	}

	if err := mr.RegisterMethod("Main.Positional", PositionalHandler{}, PositionalParams{}, PositionalResult{}); err != nil {
		log.Fatalln(err)
	}

	http.Handle("/jrpc", mr)
	http.HandleFunc("/jrpc/debug", mr.ServeDebug)

	if err := http.ListenAndServe(":8080", http.DefaultServeMux); err != nil {
		log.Fatalln(err)
	}
}*/

func Test3() {

	b := []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x70}

	b1 := b[0:4]
	fmt.Println(hex.Dump(b1))
	x1 := binary.BigEndian.Uint32(b[0:])
	x2 := binary.BigEndian.Uint32(b[4:])

	var out bytes.Buffer
	r, err := zlib.NewReader(bytes.NewReader(b))
	fmt.Println(err)
	io.Copy(&out, r)

	fmt.Println(hex.Dump(out.Bytes()))

	//x2 := binary.BigEndian.Uint32(b[4:7])
	fmt.Printf(" 0x%x 0x%x \n", x1, x2)
	return
}

func main() {
	//castingPointers()
	//testCallbacks()
	//timerTest()
	//chanTest()
	//testRand()
	//panic("this is an error")
	//highResTick()
	//testRegEx()
	//strSplit()
	//testErr()
	//testClass()
	//testPointers()
	//testClosure()
	//testCalc()
	//calcAB(a, b int)
	//rangeTest()
	//mapTes3(100, false)
	//mapTest2()
	//mapTest()
	//testVectors()
	//testNumbers()
	//testSwitch()
	//fmt.Println(time.Now().Weekday())
	//fmt.Println(time.Now())
	//test()
	//testLoops()
}

func testpcapWrite() {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17}
	ts := time.Unix(0, 0)
	f, _ := os.Create("/tmp/example.pcap")
	w := pcapgo.NewWriterNanos(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     ts,
		Length:        len(data),
		CaptureLength: len(data),
	}, data)
	f.Close()
}

func write_to_pcap(pcap_name string, o []byte) {
	ts := time.Unix(0, 0)
	f, _ := os.Create("/tmp/" + pcap_name + ".pcap")
	w := pcapgo.NewWriterNanos(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     ts,
		Length:        len(o),
		CaptureLength: len(o),
	}, o)
	f.Close()

}

func testpcapWrite2() {
	//data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	//ip.SerializeTo(buf, opts)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{142, 122, 18, 195, 169, 113},
			DstMAC:       net.HardwareAddr{58, 86, 107, 105, 89, 94},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc, SrcIP: net.IPv4(16, 0, 0, 1), DstIP: net.IPv4(48, 0, 0, 1), Length: 44,
			Protocol: layers.IPProtocolTCP},
		&layers.TCP{SrcPort: 0x1111, DstPort: 0x2222, Seq: 0x11223344, Ack: 0x77889900},
		gopacket.Payload([]byte{1, 2, 3, 4}))

	data := buf.Bytes()
	fmt.Println(buf.Layers())

	ts := time.Unix(0, 0)
	f, _ := os.Create("/tmp/example.pcap")
	w := pcapgo.NewWriterNanos(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     ts,
		Length:        len(data),
		CaptureLength: len(data),
	}, data)
	f.Close()
}

func testSlice() {
	s := []byte{2, 3, 5, 7, 11, 13}
	printSlice(s)

	// Slice the slice to give it zero length.
	s = s[:0]
	printSlice(s)

	// Extend its length.
	s = s[:4]
	printSlice(s)

	// Drop its first two values.
	s = s[2:]
	printSlice(s)
}

func testPkt2() {

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	//ip.SerializeTo(buf, opts)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{142, 122, 18, 195, 169, 113},
			DstMAC:       net.HardwareAddr{58, 86, 107, 105, 89, 94},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc, SrcIP: net.IPv4(16, 0, 0, 1), DstIP: net.IPv4(48, 0, 0, 1), Length: 44,
			Protocol: layers.IPProtocolTCP},
		&layers.TCP{SrcPort: 0x1111, DstPort: 0x2222, Seq: 0x11223344, Ack: 0x77889900},
		gopacket.Payload([]byte{1, 2, 3, 4}))

	data := buf.Bytes()
	write_to_pcap("d1", data)
	ipv4 := layers.IPv4Header(data[14 : 14+20])
	ipv4.SetIPDst(0x20000010)
	ipv4.SetIPSrc(0x40000010)
	ipv4.SetTOS(0x10)
	fmt.Printf(" %x %x %x \n", ipv4.GetIPDst(), ipv4.GetIPSrc(), ipv4.GetTOS())
	ipv4.UpdateChecksum()
	write_to_pcap("d2", data)
}

func printSlice(s []byte) {
	fmt.Printf("len=%d cap=%d %+v\n", len(s), cap(s), s)
}

func testpcapWrite3() {
	fmt.Printf("hey this is an example \n")
}
