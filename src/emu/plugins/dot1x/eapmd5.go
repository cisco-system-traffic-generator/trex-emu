// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package dot1x

import (
	"crypto/md5"
)

type EapMd5Handler struct {
	b []byte
	r []byte
}

func (o *EapMd5Handler) GetName() string {
	return ("eap-md5")
}

func (o *EapMd5Handler) BuildResp(d *Dot1xMethodData) (bool, bool, []byte) {
	passwd := d.plug.cfg.Password
	if passwd != nil {
		if d.eap.Length > 4 && d.eap.TypeData != nil {

			if len(d.eap.TypeData) > 0 {
				if (d.eap.TypeData[0] == 16) && (d.eap.TypeData[0] <= (uint8(len(d.eap.TypeData)) - 1)) {
					o.b = o.b[:0] //[id,password,challeng]
					o.b = append(o.b, d.eap.Id)
					o.b = append(o.b, []byte(*passwd)...)
					o.b = append(o.b, d.eap.TypeData[1:17]...) // the first 16 bytes
					r := md5.Sum(o.b)
					o.r = o.r[:0]
					o.r = append(o.r, uint8(len(r)))
					o.r = append(o.r, r[:]...)
					return true, true, o.r
				}
			}
		}
		d.plug.stats.pktMethodWrongLen++
	} else {
		d.plug.stats.pktMethodNoPassword++
	}
	return false, false, []byte{}
}

func (o *EapMd5Handler) Success(d *Dot1xMethodData) bool {
	return true
}

func (o *EapMd5Handler) OnRemove() {

}

func NewEapMd5() Dot1xMethodIF {
	p := new(EapMd5Handler)
	p.b = make([]byte, 0)
	p.r = make([]byte, 0)
	return p
}
