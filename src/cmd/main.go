package main

import (
	"emu/rpc"
	"fmt"
	"math/rand"
	"time"
	"unsafe"
)

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

type MbufPollSize struct {
	mlist     DList
	cacheSize uint32
	size      uint32
}

const RTE_PKTMBUF_HEADROOM = 64
const MBUF_INVALID_PORT = 0xffff
const EXT_ATTACHED_MBUF = 0x1
const IND_ATTACHED_MBUF = 0x2

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

func (o *Mbuf) SetRefCnt(new uint16) {
	o.refcnt = new
}

func (o *Mbuf) UpdateRefCnt(update int16) {
	o.refcnt = o.refcnt + uint16(update)
}

func (o *Mbuf) resetMbuf(bufLen uint16) {
	o.dataLen = 0
	o.bufLen = 0
	o.pktLen = 0
	o.nbSegs = 1
	o.port = MBUF_INVALID_PORT
	o.olFlags = 0
	o.refcnt = 1
	o.timestamp = 0
}

func (o *Mbuf) IsDirect() bool {
	if o.olFlags&(IND_ATTACHED_MBUF|EXT_ATTACHED_MBUF) == 0 {
		return true
	} else {
		return false
	}
}

func (o *Mbuf) IsClone() bool {

	if o.olFlags&(IND_ATTACHED_MBUF) == 0 {
		return true
	} else {
		return false
	}
}

func (o *Mbuf) HasExtBuf() bool {

	if o.olFlags&(EXT_ATTACHED_MBUF) == 0 {
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

func (o *Mbuf) Attach(m *Mbuf) {
}

func (o *Mbuf) beforeFreeMbuf() {

}

func (o *Mbuf) freeMbufSeg() {

}

//FreeMbuf to original pool
func (o *Mbuf) FreeMbuf() {

	var next *Mbuf
	m := o

	for {
		next = toMbuf(o.dlist.Next())
		m.freeMbufSeg()
		m = next
		if m == o {
			break
		}
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

//var mque []*mbuf

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

func main() {
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
