// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"emu/core"
	"fmt"
)

const (
	SB_DROPCALL = 0x80
)

/*
  the queue is an indirect to dynamic of mbuf-2048. only pointers is allocated ahead of time.
  head and tail to the index:offset of the buffer

	index (ref)

  h:128 0 -> mbuf [2048]
  t     1 -> mbuf [2048]
    2


*/
type queuePtr struct {
	index     uint32
	offset    uint16
	indexSize uint32
}

func (o *queuePtr) init(indexSize uint32) {
	o.indexSize = indexSize
}

func (o *queuePtr) initBase(p *queuePtr) {
	o.indexSize = p.indexSize
}

func (o *queuePtr) reset() {
	o.index = 0
	o.offset = 0
}

func (o *queuePtr) getMaxAbsOffset() uint32 {
	return o.indexSize * core.MBUF_RX_POOL_SIZE
}

func (o *queuePtr) getAbsOffset() uint32 {
	return o.index*core.MBUF_RX_POOL_SIZE + uint32(o.offset)
}

func (o *queuePtr) setByAbsOffset(offset uint32) {
	o.index = offset / uint32(core.MBUF_RX_POOL_SIZE)
	o.offset = uint16(offset - o.index*uint32(core.MBUF_RX_POOL_SIZE))

}

func (o *queuePtr) getPtr(p *queuePtr, offset uint32) {
	off := o.getAbsOffset() + offset
	if off >= o.getMaxAbsOffset() {
		off -= o.getMaxAbsOffset()
	}
	p.setByAbsOffset(off)
}

// get relative offset in the same block or from zero
func (o *queuePtr) getRelativeOffset(p *queuePtr) uint16 {
	if o.index == p.index {
		if o.offset > p.offset {
			panic(" getRelativeOffset(p *queuePtr) ")
		}
		return p.offset - o.offset
	}
	return p.offset
}

func (o *queuePtr) getFree() uint16 {
	return core.MBUF_RX_POOL_SIZE - uint16(o.offset)
}

func (o *queuePtr) incIndex() {
	o.index++
	if o.index == o.indexSize {
		o.index = 0
	}
}

func (o *queuePtr) IncFree(off uint16, freeIndex *bool, index *uint32) {
	*freeIndex = false
	o.offset += off
	if o.offset == core.MBUF_RX_POOL_SIZE {
		*freeIndex = true
		*index = o.index
		o.incIndex()
		o.offset = 0
	}
}

func (o *queuePtr) Inc(off uint16, size uint32) {
	var freeIndex bool
	var index uint32
	o.IncFree(off, &freeIndex, &index)
}

type txSocketQueue struct {
	tctx     *core.CThreadCtx
	pool     *core.MbufPollSize
	ref      []*core.Mbuf
	refSize  uint32 // the number of pointers
	refCap   uint32 // number of pointer allocated
	head     queuePtr
	tail     queuePtr
	sb_cc    uint32 /* actual chars in buffer */
	sb_hiwat uint32 /* max actual char count */
	sb_flags uint32 /* flags, see below */
	s        *TcpSocket
}

func newTxSocket(tctx *core.CThreadCtx,
	qsize uint32) *txSocketQueue {
	o := new(txSocketQueue)
	o.init(tctx, qsize)
	return o
}

func (o *txSocketQueue) init(tctx *core.CThreadCtx,
	qsize uint32,
) {
	o.tctx = tctx
	o.pool = tctx.MPool.GetPoolBySize(core.MBUF_RX_POOL_SIZE)
	if qsize == 0 {
		qsize = 64 * 1024 // default
	}
	o.sb_hiwat = qsize
	// add spare pointer for simplification of the queue.
	// there won't be a cases that head and tail will contend on the same memory
	o.refSize = (qsize+core.MBUF_RX_POOL_SIZE-1)/uint32(core.MBUF_RX_POOL_SIZE) + 2
	o.ref = make([]*core.Mbuf, o.refSize) // pointer to buffers
	o.head.init(o.refSize)
	o.tail.init(o.refSize)
}

// return how many bytes are free
func (o *txSocketQueue) getFreeSize() uint32 {
	return o.sb_hiwat - o.getSize()
}

// capacity in bytes
func (o *txSocketQueue) getCap() uint32 {
	return o.refCap * core.MBUF_RX_POOL_SIZE
}

// return how many bytes are in the queue
func (o *txSocketQueue) getInternalSize() uint32 {
	var ho, to uint32
	ho = o.head.getAbsOffset()
	to = o.tail.getAbsOffset()
	if ho >= to {
		return ho - to
	} else {
		return ho + o.head.getMaxAbsOffset() - to
	}
}

// get used size
func (o *txSocketQueue) getSize() uint32 {
	return o.sb_cc
}

func (o *txSocketQueue) isFull() bool {
	if o.getSize() == o.sb_hiwat {
		return true
	}
	return false
}

func (o *txSocketQueue) isEmpty() bool {
	if o.getSize() == 0 {
		return true
	}
	return false
}

// add buffer to the head of the queue, it is overflow return the number of bytes copied
//
func (o *txSocketQueue) writeHead(buf []byte) int {
	var blen uint32
	if o.isFull() {
		return 0
	}
	blen = uint32(len(buf))
	if blen > o.getFreeSize() {
		blen = o.getFreeSize()
	}
	o.writeHeadInternal(buf[:blen])
	o.sb_cc += blen
	return (int(blen))
}

func (o *txSocketQueue) writeHeadInternal(buf []byte) {
	var s uint32
	var l uint32
	l = uint32(len(buf))
	for {
		s += o.copyToHead(buf[s:])
		if s == l {
			break
		}
	}
}

func minSpace(free uint16, req uint32) uint16 {
	if uint32(free) >= req {
		// read all the size from current chunk
		return uint16(req)
	} else {
		// copy all
		return free
	}
}

func (o *txSocketQueue) getOrAllocIndex(head *queuePtr) *core.Mbuf {
	i := o.head.index
	if head.offset == 0 {
		if o.ref[i] == nil {
			o.refCap++
			o.ref[i] = o.pool.NewMbuf()
		}
		return o.ref[i]
	}
	if o.ref[i] == nil {
		panic(" txSocketQueue can't return be a nil pointer ")
	}
	return o.ref[i]
}

func (o *txSocketQueue) getIndex(p *queuePtr) *core.Mbuf {
	i := p.index
	if o.ref[i] == nil {
		panic(" txSocketQueue getIndex can't return be a nil pointer ")
	}
	return o.ref[i]
}

func (o *txSocketQueue) freeIndex(index uint32) {
	if o.ref[index] == nil {
		panic(" txSocketQueue can't return a nil pointer ")
	}
	o.refCap--
	o.pool.FreeMbuf(o.ref[index])
	o.ref[index] = nil
}

// copy part of the buffer (from the start) to specific block at index i
// allocate it if it does not exits
func (o *txSocketQueue) copyToHead(buf []byte) uint32 {
	m := o.getOrAllocIndex(&o.head)
	free := o.head.getFree()
	z := uint16(minSpace(free, uint32(len(buf))))
	m.Append(buf[:z])
	o.head.Inc(z, o.refSize)
	return uint32(z)
}

func (o *txSocketQueue) dropTail(size uint32) {
	if size > o.getSize() {
		panic(" can't drop tail with size bigger than the size")
	}
	for {
		size -= o.dropTailBlock(size)
		if size == 0 {
			break
		}
	}
}

func (o *txSocketQueue) dropTailBlock(size uint32) uint32 {
	m := o.getIndex(&o.tail)
	free := o.tail.getFree() // in case of tail if full
	z := uint16(minSpace(free, size))
	m.Adj(z)
	var freeIndex bool
	var index uint32
	o.tail.IncFree(z, &freeIndex, &index)
	if freeIndex == true {
		o.freeIndex(index)
	}

	return uint32(z)
}

// return how much was copied
func (o *txSocketQueue) copyFromTail(p *queuePtr, size uint32, tobuf []byte, boffset uint32) uint32 {
	m := o.getIndex(p)
	free := p.getFree()
	z := uint16(minSpace(free, size))
	of := o.tail.getRelativeOffset(p)
	copy(tobuf[boffset:boffset+uint32(z)], m.GetData()[of:of+z])
	p.Inc(z, o.refSize)
	return uint32(z)
}

// Read from tail offset (0 is from tail) of the queue number of bytes and copy it to tobuf
func (o *txSocketQueue) readOffset(offset uint32, size uint32, tobuf []byte) int {
	if size == 0 {
		return 0
	}
	if offset+size > o.getSize() {
		panic("txSocketQueue offset+bytes >= o.getSize() ")
	}
	var p queuePtr
	p.initBase(&o.tail)
	var boff, d uint32
	o.tail.getPtr(&p, offset)
	for {
		d = o.copyFromTail(&p, size, tobuf, boff)
		boff += d
		size -= d
		if size == 0 {
			break
		}
	}
	return (0)
}

// Get the space free to add
func (o *txSocketQueue) getSbspace() uint32 {
	return (o.sb_hiwat - o.sb_cc)
}

// drop all
func (o *txSocketQueue) sbdrop_all() {
	if o.sb_cc > 0 {
		o.sbdrop(o.sb_cc)
	}
}

// free resource
func (o *txSocketQueue) onRemove() {
	o.sbdrop_all()
	for _, obj := range o.ref {
		if obj != nil {
			o.pool.FreeMbuf(obj)
		}
	}
	o.head.reset()
	o.tail.reset()
	o.refCap = 0
}

func (o *txSocketQueue) sanityCheck() {

	if o.getSize() != o.getInternalSize() {
		fmt.Printf(" sanity check %v \n,", o)
		panic(" sanityCheck() ")
	}
}

// drop from tail len bytes and call, always from interrupt
func (o *txSocketQueue) sbdrop(len uint32) {
	if len == 0 {
		return
	}
	o.dropTail(len)
	o.sb_cc -= len
	o.sb_flags |= SB_DROPCALL
	if o.sb_cc == 0 {
		if o.head != o.tail {
			panic(" sbdrop ")
		}
		if o.head.offset > 0 {
			o.freeIndex(o.head.index)
		}
		o.head.reset()
		o.tail.reset()
	}
	if o.s != nil {
		if o.sb_cc < (o.sb_hiwat >> 1) {
			if o.s.drainUserQueue() {
				if o.sb_cc < (o.sb_hiwat >> 1) {
					o.s.cbmask |= SocketTxMore
				}
				if o.sb_cc == 0 {
					o.s.checkCloseDefer()
					o.s.cbmask |= SocketTxEmpty
				}
			}
		}
	}
}

func (o *txSocketQueue) String() string {
	var s string
	s += fmt.Sprintf("Size     : %d \n", o.sb_hiwat)
	s += fmt.Sprintf("Occupied : %d:%d \n", o.getSize(), o.getInternalSize())
	s += fmt.Sprintf("Free : %d \n", o.getFreeSize())
	s += fmt.Sprintf("Head : %d:%d \n", o.head.index, o.head.offset)
	s += fmt.Sprintf("Tail : %d:%d \n", o.tail.index, o.tail.offset)
	s += fmt.Sprintf("vector : [")
	for i, obj := range o.ref {
		if obj != nil {
			s += fmt.Sprintf("%d,", i)
		}
	}
	s += fmt.Sprintf("] \n")
	/*tobuf := make([]byte, o.getSize())
	o.readOffset(0, o.getSize(), tobuf)
	s += fmt.Sprintf(" %v \n", tobuf)*/
	return s
}

type rxSocketQueue struct {
	sb_cc    uint32 /* actual chars in buffer */
	sb_hiwat uint32 /* max actual char count */
	sb_flags uint16 /* flags, see below */
}

func (o *rxSocketQueue) sbspace() uint32 {
	return o.sb_hiwat
}

type socketData struct {
	so_options uint16
	so_error   SocketErr
	so_state   int
	so_rcv     rxSocketQueue
	so_snd     txSocketQueue
}
