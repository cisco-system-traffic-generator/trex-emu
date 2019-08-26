package main

import (
	"fmt"
	"unsafe"
)

type dummy struct{}

func (o *dummy) a() {
	fmt.Println("a")
}

func (o *dummy) b() {
	fmt.Println("b")
}

type dummy2 struct {
	dummy
}

func (o *dummy2) b() {
	fmt.Println("b2")
}

func main() {
	var a dummy
	var a2 dummy2
	a.a()
	a.b()
	a2.a()
	a2.b()

	fmt.Printf("hello %d %d %d\n", 17, unsafe.Sizeof(a2), unsafe.Sizeof(a))
}
