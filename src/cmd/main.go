package main

import (
	"emu/rpc"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
	"unsafe"
)

const RTE_PKTMBUF_HEADROOM = 64
const MBUF_INVALID_PORT = 0xffff
const IND_ATTACHED_MBUF = 0x2

type DList struct {
	next *DList
	prev *DList
}

func (o *DList) IsEmpty() bool {
	return o.IsSelf()
}

func (o *DList) SetSelf() {
	o.next = o
	o.prev = o
}

func (o *DList) IsSelf() bool {
	if (o.next == o) && (o.prev == o) {
		return (true)
	}
	return (false)
}

func (o *DList) Append(obj *DList) {
	obj.next = o
	obj.prev = o.prev
	o.prev.next = obj
	o.prev = obj
}
func (o *DList) AppendTail(obj *DList) {
	o.prev.Append(obj)
}

func (o *DList) Next() *DList {
	return o.next
}

func (o *DList) Prev() *DList {
	return o.prev
}

func (o *DList) DetachHead() *DList {
	if (o.next == nil) || (o.IsEmpty()) {
		panic(" next can't zero or empty ")
	}
	next := o.next
	o.next = next.next
	next.next.prev = o
	next.SetSelf()
	return (next)
}

func (o *DList) DetachTail() *DList {
	if (o.prev == nil) || (o.IsEmpty()) {
		panic(" next can't zero or empty ")
	}
	prev := o.prev
	o.prev = prev.prev
	prev.prev.next = o
	prev.SetSelf()
	return (prev)
}

type MyObjectTest struct {
	val   uint32
	dlist DList
}

func covert(dlist *DList) *MyObjectTest {
	var s MyObjectTest
	return (*MyObjectTest)(unsafe.Pointer(uintptr(unsafe.Pointer(dlist)) - unsafe.Offsetof(s.dlist)))
}

func testdList() {
	var first *MyObjectTest

	for i := 0; i < 10; i++ {
		o := new(MyObjectTest)
		o.val = uint32(i)
		if i == 0 {
			o.dlist.SetSelf()
			first = o
		} else {
			first.dlist.Append(&o.dlist)
		}
	}

	n := first
	for {
		fmt.Println(n.val)
		n = covert(n.dlist.Next())
		if n == first {
			break
		}
	}

	first.dlist.DetachTail()

	fmt.Println("--")
	n = first
	for {
		fmt.Println(n.val)
		n = covert(n.dlist.Next())
		if n == first {
			break
		}
	}

	for j := 0; j < 9; j++ {
		fmt.Printf(" detach -- %d \n", 1)
		if !first.dlist.IsEmpty() {
			first.dlist.DetachTail()
		}

		n = first
		for {
			fmt.Println(n.val)
			n = covert(n.dlist.Next())
			if n == first {
				break
			}
		}

	}
}

type MbufPoll struct {
	pools []MbufPollSize
}

var pool_sizes = [...]uint16{128, 256, 512, 1024, 2048, 4096, 9 * 1024}

func (o *MbufPoll) GetMaxPacketSize() uint16 {
	return (9 * 1024)
}

func (o *MbufPoll) Init(maxCacheSize uint32) {

	o.pools = make([]MbufPollSize, len(pool_sizes))
	for i, s := range pool_sizes {
		o.pools[i].Init(maxCacheSize, s)
	}
}

func (o *MbufPoll) Alloc(size uint16) *Mbuf {
	for i, ps := range pool_sizes {
		if size <= ps {
			return o.pools[i].NewMbuf()
		}
	}
	s := fmt.Sprintf(" MbufPoll.Alloc size is too big %d ", size)
	panic(s)
}

func (o *MbufPoll) GetStats() *MbufPollStats {
	var stats MbufPollStats

	for i, _ := range pool_sizes {
		stats.Add(&o.pools[i].stats)
	}
	return &stats
}

func (o *MbufPoll) DumpStats() {
	fmt.Println(" size  | stats ")
	fmt.Println(" ----------------------")
	for i, s := range pool_sizes {
		p := &o.pools[i].stats
		fmt.Printf(" %-04d  | %3.0f%%  %+v  \n", s, p.HitRate(), *p)
	}

}

type MbufPollStats struct {
	CntAlloc      uint64
	CntFree       uint64
	CntCacheAlloc uint64
	CntCacheFree  uint64
}

func (o *MbufPollStats) HitRate() float32 {
	if o.CntCacheFree == 0 {
		return 0.0
	}
	return float32(o.CntCacheAlloc) * 100.0 / float32(o.CntCacheFree)
}

// Add o = o + obj
func (o *MbufPollStats) Add(obj *MbufPollStats) {
	o.CntAlloc += obj.CntAlloc
	o.CntFree += obj.CntFree
	o.CntCacheAlloc += obj.CntCacheAlloc
	o.CntCacheFree += obj.CntCacheFree
}

type MbufPollSize struct {
	mlist        DList
	cacheSize    uint32 /*	the active cache size */
	maxCacheSize uint32 /*	the maximum cache size */
	mbufSize     uint16 /* buffer size without the RTE_PKTMBUF_HEADROOM */

	stats MbufPollStats
}

// Init the pool
func (o *MbufPollSize) Init(maxCacheSize uint32, mbufSize uint16) {
	o.mlist.SetSelf()
	o.maxCacheSize = maxCacheSize
	o.mbufSize = mbufSize
}

func (o *MbufPollSize) getHead() *Mbuf {
	h := o.mlist.DetachTail()
	o.cacheSize -= 1
	return (toMbuf(h))
}

// NewMbuf alloc new mbuf with the right size
func (o *MbufPollSize) NewMbuf() *Mbuf {

	// ignore the size of the packet
	var m *Mbuf
	if o.cacheSize > 0 {
		o.stats.CntCacheAlloc++
		m = o.getHead()
		m.resetMbuf()
		return (m)
	}

	// allocate new mbuf
	m = new(Mbuf)
	m.bufLen = uint16(o.mbufSize) + RTE_PKTMBUF_HEADROOM
	m.data = make([]byte, m.bufLen)
	m.pool = o
	m.resetMbuf()
	o.stats.CntAlloc++
	return (m)
}

// FreeMbuf free mbuf to cache
func (o *MbufPollSize) FreeMbuf(obj *Mbuf) {

	if o.cacheSize < o.maxCacheSize {
		o.mlist.Append(&obj.dlist)
		o.cacheSize++
		o.stats.CntCacheFree++
	} else {
		o.stats.CntFree++
	}
}

func toMbuf(dlist *DList) *Mbuf {
	return (*Mbuf)(unsafe.Pointer(dlist))
}

type Mbuf struct {
	dlist     DList // point to the next mbuf
	pool      *MbufPollSize
	pktLen    uint32
	refcnt    uint16
	olFlags   uint16
	dataLen   uint16
	dataOff   uint16
	bufLen    uint16
	nbSegs    uint16
	port      uint16
	timestamp uint64
	data      []byte
}

func (o *Mbuf) GetRefCnt() uint16 {
	return o.refcnt
}

func (o *Mbuf) SetRefCnt(n uint16) {
	o.refcnt = n
}

func (o *Mbuf) UpdateRefCnt(update int16) {
	o.refcnt = o.refcnt + uint16(update)
}

func (o *Mbuf) resetMbuf() {

	o.dlist.SetSelf()
	o.dataLen = 0
	o.pktLen = 0
	o.nbSegs = 1
	o.dataOff = RTE_PKTMBUF_HEADROOM
	o.port = MBUF_INVALID_PORT
	o.olFlags = 0
	o.refcnt = 1
	o.timestamp = 0
}

func (o *Mbuf) IsDirect() bool {
	if o.olFlags&(IND_ATTACHED_MBUF) == 0 {
		return true
	} else {
		return false
	}
}

func (o *Mbuf) PktLen() uint32 {
	return o.pktLen
}

func (o *Mbuf) DataLen() uint16 {
	return o.dataLen
}

func (o *Mbuf) LastSeg() *Mbuf {
	return toMbuf(o.dlist.Prev())
}

func (o *Mbuf) Tailroom() uint16 {
	return (o.bufLen - o.dataOff - o.dataLen)
}

func (o *Mbuf) Headroom() uint16 {
	return o.dataOff
}

func (o *Mbuf) Prepend(d []byte) {
	var size uint16
	size = uint16(len(d))
	if size > o.dataOff {
		s := fmt.Sprintf(" prepend %d bytes to mbuf remain size %d", size, o.dataOff)
		panic(s)
	}
	o.dataOff -= size
	o.dataLen += size
	o.pktLen += uint32(size)
	copy(o.data[o.dataOff:], d)
}

//GetData return the byte stream of current object
func (o *Mbuf) GetData() []byte {
	return o.data[o.dataOff:(o.dataOff + o.dataLen)]
}

//Append len bytes to an mbuf.
func (o *Mbuf) Append(d []byte) {
	last := o.LastSeg()
	off := last.dataOff + last.dataLen
	n := last.bufLen - off
	var size uint16
	size = uint16(len(d))
	if size > n {
		s := fmt.Sprintf(" append %d to mbuf remain size %d", size, n)
		panic(s)
	}

	copy(last.data[off:], d)
	o.pktLen += uint32(size)
	last.dataLen += size
}

// Trim - Remove len bytes of data at the end of the mbuf.
func (o *Mbuf) Trim(dlen uint16) {
	last := o.LastSeg()
	if dlen > last.dataLen {
		s := fmt.Sprintf(" trim %d bigger than packet len %d", dlen, last.dataLen)
		panic(s)
	}
	last.dataLen -= dlen
	o.pktLen -= uint32(dlen)
}

func (o *Mbuf) IsContiguous() bool {
	if o.nbSegs == 1 {
		return true
	} else {
		return false
	}
}

// Adj Remove len bytes at the beginning of an mbuf.
func (o *Mbuf) Adj(dlen uint16) int {

	if dlen > o.dataLen {
		return -1
	}
	o.dataLen -= dlen
	o.dataOff += dlen
	o.pktLen -= uint32(dlen)
	return 0
}

// Attach new mbuf
func (o *Mbuf) AppendMbuf(m *Mbuf) {
	o.dlist.Append(&m.dlist)
	o.pktLen += uint32(m.dataLen)
	o.nbSegs += 1
}

func (o *Mbuf) DetachHead() *Mbuf {
	m := toMbuf(o.dlist.DetachHead())
	o.pktLen -= uint32(m.dataLen)
	o.nbSegs -= 1
	return m
}

func (o *Mbuf) DetachTail() *Mbuf {
	m := toMbuf(o.dlist.DetachTail())
	o.pktLen -= uint32(m.dataLen)
	o.nbSegs -= 1
	return m
}

// Next return next mbuf. should be compared to head node
func (o *Mbuf) Next() *Mbuf {
	return toMbuf(o.dlist.Next())
}

func (o *Mbuf) freeMbufSeg() {
	if o.refcnt != 1 {
		s := fmt.Sprintf(" refcnt should be 1")
		panic(s)
	}
	// give the mbuf back
	o.pool.FreeMbuf(o)
}

//FreeMbuf to original pool
func (o *Mbuf) FreeMbuf() {

	var next *Mbuf
	m := o
	for {
		next = m.Next()
		m.freeMbufSeg()
		if next == o {
			break
		}
		m = next
	}
	o = nil
}

// SanityCheck verify that mbuf is OK, panic if not
func (o *Mbuf) SanityCheck(header bool) {
	if o.pool == nil {
		panic(" pool is nil ")
	}

	if o.refcnt != 1 {
		panic(" refcnt is not supported ")
	}

	if !header {
		return
	}

	if uint32(o.dataLen) > o.pktLen {
		panic(" bad data_len ")
	}
	segs := o.nbSegs
	pktLen := o.pktLen
	m := o

	for {
		if m.dataOff > m.bufLen {
			panic(" data offset too big in mbuf segment ")
		}
		if m.dataOff+m.dataLen > m.bufLen {
			panic(" data length too big in mbuf segment ")
		}
		segs -= 1
		pktLen -= uint32(m.dataLen)
		m = m.Next()
		if m == o {
			break
		}
	}
	if segs > 0 {
		panic(" bad nb_segs ")
	}
	if pktLen > 0 {
		panic(" bad pkt_len")
	}
}

// Dump dump as hex
func (o *Mbuf) Dump() {

	var next *Mbuf
	first := true
	cnt := 0
	m := o
	for {
		next = m.Next()
		fmt.Printf(" %d: ", cnt)
		if first {
			fmt.Printf(" pktlen : %d, ", m.pktLen)
			fmt.Printf(" segs   : %d, ", m.nbSegs)
			fmt.Printf(" ports  : %d, ", m.port)
		}
		fmt.Printf(" buflen  : %d ", m.bufLen)
		fmt.Printf(" dataLen : %d ", m.dataLen)
		if o.dataLen > 0 {
			fmt.Printf("\n%s\n", hex.Dump(m.GetData()))
		} else {
			fmt.Printf("\n Empty\n")
		}
		if next == o {
			break
		}
		first = false
		m = next
		cnt += 1
	}
}

/*

func (o *mbuf_mempool) getTail() *mbuf {
	h := o.dlist.DetachTail()
	o.size = o.size - 1
	return (toMbuf(h))
}

func (o *mbuf_mempool) New(size uint16) *mbuf {
	// ignore the size of the packet
	var m *mbuf
	if o.size > 0 {
		return (o.getTail())
	}

	m = NewMbuf()
	m.pool = o
	return (m)
}

func (o *mbuf_mempool) Free(m *mbuf) {
	if o.size < 1024 {
		o.dlist.Append(&m.dlist)
		o.size += 1
	}
}
*/
type pkt []byte

func newPktSize(size uint16) pkt {
	var mbuf pkt
	mbuf = make(pkt, size)
	return mbuf
}

func freePkt() {

}

var que []pkt

var mque []*Mbuf

func test1() {
	size := 5000000
	start := time.Now().UnixNano()
	que = make([]pkt, 0)
	for i := 0; i < size; i++ {
		mbuf := newPktSize(128 /*+ uint16(rand.Intn(1400)*/)
		mbuf[0] = byte(i & 0xff)
		que = append(que, mbuf)
		//fmt.Printf("%d \n%s\n", len(mbuf), hex.Dump(mbuf))
	}
	d := time.Now().UnixNano() - start
	fmt.Printf(" nsec %d %d \n", d, d/int64(size))
}

/*
func test2() {
	var pool mbuf_mempool
	pool.dlist.SetSelf()

	size := 5000000
	cnt := 0
	start := time.Now().UnixNano()

	for i := 0; i < size; i++ {
		if cnt == 1000 {
			if len(mque) != 1000 {
				panic("error")
			}
			for _, m := range mque {
				pool.Free(m)
			}
			mque = mque[:0]
			cnt = 0
		}
		if cnt < 1000 {
			m := pool.New(128)
			mque = append(mque, m)
			cnt++
		}
	}
	d := time.Now().UnixNano() - start
	fmt.Printf(" nsec %d %d \n", d, d/int64(size))
}
*/

func testStats() {
	var a MbufPollStats
	var b MbufPollStats
	b.CntAlloc = 12
	b.CntCacheFree = 17
	a.Add(&b)
	a.Add(&b)
	//fmt.Printf("%+v", a)
	//fmt.Println(a)
}

func getBufIndex(size uint16) []byte {
	buf := make([]byte, size)
	for i, _ := range buf {
		buf[i] = byte(i)
	}
	return buf
}

func testMpool1() {

	var pool MbufPoll
	pool.Init(1024)

	fmt.Println(pool.GetMaxPacketSize())
	fmt.Printf("%+v \n", *pool.GetStats())
	pool.DumpStats()

	for i := 0; i < 10; i++ {
		m := pool.Alloc(128)
		//m.Dump()
		m.Append(getBufIndex(100))
		//m.Append([]byte{1, 2, 3, 4, 5})
		//m.Dump()
		m1 := pool.Alloc(256)
		m1.Append(getBufIndex(200))
		m.AppendMbuf(m1)
		m.SanityCheck(true)
		//m.Dump()
		m2 := pool.Alloc(1025)
		m2.Append(getBufIndex(300))
		m.AppendMbuf(m2)
		m.SanityCheck(true)
		//m.Dump()

		//_ = m.DetachTail()
		//m.Dump()

		m.FreeMbuf()
	}
	pool.DumpStats()
	fmt.Printf("%+v \n", *pool.GetStats())

	//m1 := pool.Alloc(128)
	//m.AppendMbuf(m1)

	//m.Dump()
}

func testMpool2() {

	var pool MbufPoll
	pool.Init(1024)
	mque = make([]*Mbuf, 0)

	size := 5000000
	cnt := 0
	start := time.Now().UnixNano()

	for i := 0; i < size; i++ {
		if cnt == 10 {
			if len(mque) != 10 {
				panic("error")
			}
			for _, m := range mque {
				m.FreeMbuf()
			}
			mque = mque[:0]
			cnt = 0
		}
		if cnt < 10 {
			m := pool.Alloc(uint16(rand.Intn(2000)))
			mque = append(mque, m)
			cnt++
		}
	}
	d := time.Now().UnixNano() - start
	fmt.Printf(" nsec %d %d \n", d, d/int64(size))
	pool.DumpStats()

}

func main() {
	testMpool2()
	//testStats()
	return
	var data *[]byte
	d := make([]byte, 10)
	data = &d
	fmt.Println(*data)
	(*data)[0] = 1
	fmt.Println(*data)

	//b := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	//fmt.Println(b)
	//fmt.Println(b[0:1])

	//test2()
	return
	testdList()
	return
	test1()
	fmt.Println(len(que))
	return
	rand.Seed(time.Now().UnixNano())
	rpc.RcpCtx.Create(4510)
	rpc.RcpCtx.StartRxThread()

	for {
		select {
		case req := <-rpc.RcpCtx.GetC():
			rpc.RcpCtx.HandleReqToChan(req)
		}
	}

	rpc.RcpCtx.Delete()
	return
}
