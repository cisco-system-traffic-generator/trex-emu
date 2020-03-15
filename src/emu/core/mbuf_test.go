// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package core

import (
	"fmt"
	"testing"
	"time"
	"unsafe"
)

type MyObjectTest struct {
	val   uint32
	dlist DList
}

func covert(dlist *DList) *MyObjectTest {
	var s MyObjectTest
	return (*MyObjectTest)(unsafe.Pointer(uintptr(unsafe.Pointer(dlist)) - unsafe.Offsetof(s.dlist)))
}

func TestDlist1(t *testing.T) {
	var first *MyObjectTest
	for i := 0; i < 10; i++ {
		o := new(MyObjectTest)
		o.val = uint32(i)
		if i == 0 {
			o.dlist.SetSelf()
			first = o
		} else {
			first.dlist.AddLast(&o.dlist)
		}
	}

	var it DListIter

	fmt.Println("--")
	for it.Init(&first.dlist); it.IsCont(); it.Next() {
		fmt.Println(covert(it.Val()).val)
	}

}

func getBufIndex(size uint16) []byte {
	buf := make([]byte, size)
	for i, _ := range buf {
		buf[i] = byte(i)
	}
	return buf
}

func TestMbuf1(t *testing.T) {
	var pool MbufPoll
	pool.Init(1024)

	fmt.Println(pool.GetMaxPacketSize())
	fmt.Printf("%+v \n", *pool.GetStats())
	pool.DumpStats()

	for i := 0; i < 10; i++ {
		m := pool.Alloc(128)
		m.Append(getBufIndex(100))
		m1 := pool.Alloc(256)
		m1.Append(getBufIndex(200))
		m.AppendMbuf(m1)
		m.SanityCheck(true)
		m2 := pool.Alloc(1025)
		m2.Append(getBufIndex(300))
		m.AppendMbuf(m2)
		m.SanityCheck(true)
		if m.PktLen() != 600 {
			t.Fatalf(" pkt size should be 600 ")
		}
		m.FreeMbuf()
	}
	pool.DumpStats()
	fmt.Printf("%+v \n", *pool.GetStats())
	fmt.Println(pool.GetStats().HitRate())
	if pool.GetStats().HitRate() < 90 {
		t.Fatalf(" expected hitrate is 90 ")
	}
}

func TestMbuf2(t *testing.T) {
	var mque []*Mbuf

	var pool MbufPoll
	pool.Init(1024)
	mque = make([]*Mbuf, 0)
	size := 500000
	cnt := 0
	start := time.Now().UnixNano()
	cacheSize := 2

	for i := 0; i < size; i++ {
		if cnt == cacheSize {
			if len(mque) != cacheSize {
				panic("error")
			}
			for _, m := range mque {
				m.FreeMbuf()
			}
			mque = mque[:0]
			cnt = 0
		}
		if cnt < cacheSize {
			m := pool.Alloc(128)
			mque = append(mque, m)
			cnt++
		}
	}
	d := time.Now().UnixNano() - start
	nsec := d / int64(size) / 2
	fmt.Printf(" nsec %d %d \n", d, nsec)
	if pool.GetStats().HitRate() < 99 {
		t.Fatalf(" expected hitrate is 99 ")
	}

	if nsec > 100 {
		t.Fatalf(" alloc/free should be faster than %d nsec", nsec)
	}
	pool.DumpStats()
}

func TestMbuf3(t *testing.T) {

	var pool MbufPoll
	pool.Init(1024)
	m1 := pool.Alloc(128)
	m1.Append([]byte{1, 2, 3, 4, 5, 6})
	m2 := pool.Alloc(128)
	m2.Append([]byte{10, 11, 12, 13, 14, 15})
	m1.AppendMbuf(m2)
	if m1.IsContiguous() {
		t.Fatalf(" m1 should not be Contiguous")
	}
	m1.Dump()
	m3 := m1.GetContiguous(&pool)
	m3.Dump()
	m1.FreeMbuf()
	m3.FreeMbuf()
	pool.DumpStats()
}
