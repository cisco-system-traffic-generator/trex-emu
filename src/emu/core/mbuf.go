package core

import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

/*mbuf

A simplified version of DPDK/BSD mbuf library

see
https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html

1. It uses pool of memory for each packet size and cache the mbuf
2. The performance is about ~x20 relative to simple allocation (~20nsec vs 900nsec)
3. The memory is normal allocated memory from heap/GC
3. It does not support attach/detach for multicast  (simplification)
4. Single threaded -- each thread should have its own local pool


	var pool MbufPoll
	pool.Init(1024) 			# cache up to 1024 active packets per pool for -> ~9MB
	pool.DumpStats()			# dump statistic
	m := pool.Alloc(128)		#
	m.Dump()					# Dump the mbuf
	m.Append([]byte{1,2,3})     #append data
	m.FreeMbuf()   				#free the memory to cache. It is not mandatory to free it

*/

const lRTE_PKTMBUF_HEADROOM = 64
const lMBUF_INVALID_PORT = 0xffff
const lIND_ATTACHED_MBUF = 0x2

//MAX_PACKET_SIZE the maximum packet size
const MAX_PACKET_SIZE uint16 = 9 * 1024

// MbufPoll cache of mbufs per packet size
type MbufPoll struct {
	pools []MbufPollSize
}

var poolSizes = [...]uint16{128, 256, 512, 1024, 2048, 4096, MAX_PACKET_SIZE}

//GetMaxPacketSize return the maximum
func (o *MbufPoll) GetMaxPacketSize() uint16 {
	return (MAX_PACKET_SIZE)
}

// Init init all the pools (per size).
// maxCacheSize - how many packets to cache
func (o *MbufPoll) Init(maxCacheSize uint32) {

	o.pools = make([]MbufPollSize, len(poolSizes))
	for i, s := range poolSizes {
		o.pools[i].Init(maxCacheSize, s)
	}
}

// Alloc new mbuf from the right pool
func (o *MbufPoll) Alloc(size uint16) *Mbuf {
	for i, ps := range poolSizes {
		if size <= ps {
			return o.pools[i].NewMbuf()
		}
	}
	s := fmt.Sprintf(" MbufPoll.Alloc size is too big %d ", size)
	panic(s)
}

// GetStats return accumulated statistics for all pools
func (o *MbufPoll) GetStats() *MbufPollStats {
	var stats MbufPollStats

	for i := range poolSizes {
		stats.Add(&o.pools[i].stats)
	}
	return &stats
}

// DumpStats dump statistics
func (o *MbufPoll) DumpStats() {
	fmt.Println(" size  | stats ")
	fmt.Println(" ----------------------")
	for i, s := range poolSizes {
		p := &o.pools[i].stats
		fmt.Printf(" %-04d  | %3.0f%%  %+v  \n", s, p.HitRate(), *p)
	}

}

// MbufPollStats per pool statistic
type MbufPollStats struct {
	CntAlloc      uint64
	CntFree       uint64
	CntCacheAlloc uint64
	CntCacheFree  uint64
}

//HitRate return the hit rate in precent
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

// MbufPollSize pool per size
type MbufPollSize struct {
	mlist        DList
	cacheSize    uint32 /*	the active cache size */
	maxCacheSize uint32 /*	the maximum cache size */
	mbufSize     uint16 /* buffer size without the lRTE_PKTMBUF_HEADROOM */

	stats MbufPollStats
}

// Init the pool
func (o *MbufPollSize) Init(maxCacheSize uint32, mbufSize uint16) {
	o.mlist.SetSelf()
	o.maxCacheSize = maxCacheSize
	o.mbufSize = mbufSize
}

func (o *MbufPollSize) getHead() *Mbuf {
	h := o.mlist.RemoveLast()
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
	m.bufLen = uint16(o.mbufSize) + lRTE_PKTMBUF_HEADROOM
	m.data = make([]byte, m.bufLen)
	m.pool = o
	m.resetMbuf()
	o.stats.CntAlloc++
	return (m)
}

// FreeMbuf free mbuf to cache
func (o *MbufPollSize) FreeMbuf(obj *Mbuf) {

	if o.cacheSize < o.maxCacheSize {
		o.mlist.AddLast(&obj.dlist)
		o.cacheSize++
		o.stats.CntCacheFree++
	} else {
		o.stats.CntFree++
	}
}

func toMbuf(dlist *DList) *Mbuf {
	return (*Mbuf)(unsafe.Pointer(dlist))
}

// Mbuf represent a chunk of packet
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

func (o *Mbuf) getRefCnt() uint16 {
	return o.refcnt
}

func (o *Mbuf) setRefCnt(n uint16) {
	o.refcnt = n
}

func (o *Mbuf) updateRefCnt(update int16) {
	o.refcnt = o.refcnt + uint16(update)
}

func (o *Mbuf) resetMbuf() {

	o.dlist.SetSelf()
	o.dataLen = 0
	o.pktLen = 0
	o.nbSegs = 1
	o.dataOff = lRTE_PKTMBUF_HEADROOM
	o.port = lMBUF_INVALID_PORT
	o.olFlags = 0
	o.refcnt = 1
	o.timestamp = 0
}

func (o *Mbuf) isDirect() bool {
	if o.olFlags&(lIND_ATTACHED_MBUF) == 0 {
		return true
	} else {
		return false
	}
}

func (o *Mbuf) SetVPort(vport uint16) {
	o.port = vport
}

// PktLen return the packet len. Valid only for the header mbuf
func (o *Mbuf) PktLen() uint32 {
	return o.pktLen
}

// DataLen return the amount of data valid for this mbuf
func (o *Mbuf) DataLen() uint16 {
	return o.dataLen
}

// LastSeg return the last mbuf
func (o *Mbuf) LastSeg() *Mbuf {
	return toMbuf(o.dlist.Prev())
}

// Tailroom return the amount of bytes left in the tail - per mbuf
func (o *Mbuf) Tailroom() uint16 {
	return (o.bufLen - o.dataOff - o.dataLen)
}

// Headroom return the amount of bytes left in the head - per mbuf
func (o *Mbuf) Headroom() uint16 {
	return o.dataOff
}

// Prepend - prepend buffer. panic in case there is no enough room. check before with Headroom()
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

//Append  Append buffer to an mbuf - panic in case there is no room. check left space with Tailroom()
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

// IsContiguous - valid for header mbuf, return  true in case it has only one mbuf in chain
func (o *Mbuf) IsContiguous() bool {
	if o.nbSegs == 1 {
		return true
	} else {
		return false
	}
}

// Adj - Remove len bytes at the beginning of an mbuf.
func (o *Mbuf) Adj(dlen uint16) int {

	if dlen > o.dataLen {
		return -1
	}
	o.dataLen -= dlen
	o.dataOff += dlen
	o.pktLen -= uint32(dlen)
	return 0
}

// AppendMbuf add mbuf to be last in chain
func (o *Mbuf) AppendMbuf(m *Mbuf) {
	o.dlist.AddLast(&m.dlist)
	o.pktLen += uint32(m.dataLen)
	o.nbSegs++
}

// DetachLast remove the first mbuf and return it
func (o *Mbuf) DetachLast() *Mbuf {
	m := toMbuf(o.dlist.RemoveLast())
	o.pktLen -= uint32(m.dataLen)
	o.nbSegs--
	return m
}

// DetachFirst remove the last mbuf and return it
func (o *Mbuf) DetachFirst() *Mbuf {
	m := toMbuf(o.dlist.RemoveFirst())
	o.pktLen -= uint32(m.dataLen)
	o.nbSegs--
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

//FreeMbuf to original pool, the mbuf can't be used after this function
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

// Dump debug dump as buffer
func (o *Mbuf) String() string {
	var next *Mbuf
	first := true
	cnt := 0
	s := ""
	m := o
	for {
		next = m.Next()
		s += fmt.Sprintf(" %d: ", cnt)
		if first {
			s += fmt.Sprintf(" pktlen : %d, ", m.pktLen)
			s += fmt.Sprintf(" segs   : %d, ", m.nbSegs)
			s += fmt.Sprintf(" ports  : %d, ", m.port)
		}
		s += fmt.Sprintf(" buflen  : %d ", m.bufLen)
		s += fmt.Sprintf(" dataLen : %d ", m.dataLen)
		if o.dataLen > 0 {
			s += fmt.Sprintf("\n%s\n", hex.Dump(m.GetData()))
		} else {
			s += fmt.Sprintf("\n Empty\n")
		}
		if next == o {
			break
		}
		first = false
		m = next
		cnt++
	}
	return s
}

// Dump - dump
func (o *Mbuf) Dump() {
	fmt.Println(o)
}

func (o *Mbuf) GetContiguous(pool *MbufPoll) *Mbuf {

	if o.IsContiguous() {
		panic(" this mbuf is already Contiguous ")
	}
	var next *Mbuf
	m := o
	tom := pool.Alloc(uint16(o.PktLen()))
	for {
		next = m.Next()
		tom.Append(m.GetData()[:])
		if next == o {
			break
		}
		m = next
	}

	return tom
}
