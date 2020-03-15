// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package core

import (
	"fmt"
	"testing"
)

func TestCnt1(t *testing.T) {
	var cnt uint64
	var cnt1 float64
	cnt = 17
	cnt1 = 18.1

	c1 := &CCounterRec{
		Counter:  &cnt,
		Name:     "A",
		Help:     "an example",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO}
	c2 := &CCounterRec{
		Counter:  &cnt1,
		Name:     "B",
		Help:     "an example",
		Unit:     "pkts",
		DumpZero: false,
		Info:     ScINFO}
	fmt.Println("val:" + string(c1.MarshalValue()))
	fmt.Println("meta:" + string(c1.MarshalMetaAndVal()))
	db := NewCCounterDb("my db")
	db.Add(c1)
	db.Add(c2)
	db.Dump()
	cnt = 18
	cnt1 = 19.31

	fmt.Println()
	fmt.Printf(string(db.MarshalMeta()))
	fmt.Println()
	//fmt.Printf(string(db.MarshalValues()))
	//fmt.Println()
}
