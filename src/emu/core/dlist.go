package core

/*DList ...
Doubly-linked list implementation that embedded inside an object to eliminate the need to allocate memory twice

Should be init by o.SetSelf()

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
			first.dlist.AddLast(&o.dlist)
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

}

*/
// DList embedded inside a diffrent struct
type DList struct {
	next *DList
	prev *DList
}

//IsEmpty return if empty
func (o *DList) IsEmpty() bool {
	return o.IsSelf()
}

// SetSelf init the object by pointing to self
func (o *DList) SetSelf() {
	o.next = o
	o.prev = o
}

//IsSelf return true if the object point to itself
func (o *DList) IsSelf() bool {
	if (o.next == o) && (o.prev == o) {
		return (true)
	}
	return (false)
}

// AddLast Appends the specified element to the end of this list.
func (o *DList) AddLast(obj *DList) {
	obj.next = o
	obj.prev = o.prev
	o.prev.next = obj
	o.prev = obj
}

// AddFirst Inserts the specified element at the beginning of this list.
func (o *DList) AddFirst(obj *DList) {
	o.next.AddLast(obj)
}

// Next return next pointer
func (o *DList) Next() *DList {
	return o.next
}

// Prev return next pointer
func (o *DList) Prev() *DList {
	return o.prev
}

// RemoveFirst Removes and returns the first element from this dlist.
func (o *DList) RemoveFirst() *DList {
	if (o.next == nil) || (o.IsEmpty()) {
		panic(" next can't zero or empty ")
	}
	next := o.next
	o.next = next.next
	next.next.prev = o
	next.SetSelf()
	return (next)
}

// RemoveLast Removes and returns the last element from this dlist.
func (o *DList) RemoveLast() *DList {
	if (o.prev == nil) || (o.IsEmpty()) {
		panic(" next can't zero or empty ")
	}
	prev := o.prev
	o.prev = prev.prev
	prev.prev.next = o
	prev.SetSelf()
	return (prev)
}
