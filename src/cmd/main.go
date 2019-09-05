package main

import (
	"context"
	"fmt"
	"log"
	"time"

	ffmt "github.com/go-ffmt/ffmt"
	"github.com/intel-go/fastjson"
	"github.com/osamingo/jsonrpc"
	zmq "github.com/pebbe/zmq4"
)

type (
	EchoHandler struct{}
	EchoParams  struct {
		Name string `json:"name"`
	}
	EchoResult struct {
		Message string `json:"message"`
	}

	PositionalHandler struct{}
	PositionalParams  []int
	PositionalResult  struct {
		Message []int `json:"message"`
	}
)

func (h EchoHandler) ServeJSONRPC(c context.Context, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p EchoParams
	if err := jsonrpc.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	return EchoResult{
		Message: "Hello, " + p.Name,
	}, nil
}

func (h PositionalHandler) ServeJSONRPC(c context.Context, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	var p PositionalParams
	if err := jsonrpc.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	return PositionalResult{
		Message: p,
	}, nil
}

func testJSONRPC() {

	mr := jsonrpc.NewMethodRepository()

	if err := mr.RegisterMethod("Main.Echo", EchoHandler{}, EchoParams{}, EchoResult{}); err != nil {
		log.Fatalln(err)
	}

	if err := mr.RegisterMethod("Main.Positional", PositionalHandler{}, PositionalParams{}, PositionalResult{}); err != nil {
		log.Fatalln(err)
	}

	//go createZMQ()

	/*if err := http.ListenAndServe(":8080", http.DefaultServeMux); err != nil {
		log.Fatalln(err)
	}*/
}

type CZmqJsonRPC2 struct {
	ctx        *zmq.Context
	socket     *zmq.Socket
	serverPort uint16
	mr         *jsonrpc.MethodRepository
}

// Create create a zmq server in port
func (o *CZmqJsonRPC2) Create(serverPort uint16) {
	context, err := zmq.NewContext()
	socket, err := context.NewSocket(zmq.REP)
	if err != nil {
		panic(err)
	}

	if socket == nil {
		panic(" zmq client is nil")
	}

	o.ctx = context
	o.socket = socket
	o.serverPort = serverPort
	bindStr := fmt.Sprintf("tcp://*:%d", o.serverPort)
	socket.Bind(bindStr)
}

// Delete  this is an help
func (o *CZmqJsonRPC2) Delete() {
	o.socket.Close()
}

func ParseRequest(req []byte) ([]*jsonrpc.Request, bool, *jsonrpc.Error) {

	if len(req) == 0 {
		return nil, false, jsonrpc.ErrInvalidRequest()
	}

	f := req[0]
	var rs []*jsonrpc.Request

	if f != '[' {
		var singleReq *jsonrpc.Request
		err := fastjson.Unmarshal(req, &singleReq)
		if err != nil {
			return nil, false, jsonrpc.ErrParse()
		}
		return append(rs, singleReq), false, nil
	}

	err := fastjson.Unmarshal(req, &rs)

	if err != nil {
		return nil, false, jsonrpc.ErrParse()
	}

	return rs, true, nil
}

// GetResponse help 
func GetResponse(resp []*jsonrpc.Response, batch bool) ([]byte, error) {
	if batch || len(resp) > 1 {
		return fastjson.Marshal(resp)
	} else if len(resp) == 1 {
		return fastjson.Marshal(resp[0])
	}
	return nil,nil 
}

// HandleReq input buffer return buffer
func (o *CZmqJsonRPC2) HandleReq(req []byte) []byte {

	rs, batch, err := ParseRequest(req)
	if err != nil {
		b,_ := GetResponse([]*jsonrpc.Response{
			{
				Version: jsonrpc.Version,
				Error:   err,
			},
		}, false)
		return b
	}

	resp := make([]*jsonrpc.Response, len(rs))
	for i := range rs {
		resp[i] = o.mr.InvokeMethod(nil, rs[i])
	}

	b,_ := GetResponse(resp,batch)
	return b
}

// HandleReqRes this is an help
func (o *CZmqJsonRPC2) HandleReqRes() {
	msg, _ := o.socket.RecvBytes(0)
	res := o.HandleReq(msg)
	o.socket.SendBytes(res, 0)
}

func testZmqJSonRPC() {
	fmt.Println(" start server ")

	var jsonrpc CZmqJsonRPC2

	jsonrpc.Create(5555)
	for {
		jsonrpc.HandleReqRes()
	}

	jsonrpc.Delete()
}

func createZMQ(mr *jsonrpc.MethodRepository) {
	context, err := zmq.NewContext()
	socket, err := context.NewSocket(zmq.REP)
	defer socket.Close()

	if err != nil {
		panic(err)
	}
	if socket == nil {
		panic(" zmq client is nil")
	}

	socket.Bind("tcp://*:5555")

	for {
		msg, _ := socket.Recv(0)

		// send reply back to client
		//reply := fmt.Sprintf("World")
		socket.Send(msg, 0)
	}

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

type myRequest struct {
	Version string               `json:"jsonrpc"`
	Method  string               `json:"method"`
	Params  *fastjson.RawMessage `json:"params"`
	ID      *fastjson.RawMessage `json:"id"`
}

func testFastJsonParser() {
	var req myRequest
	jsonReq := []byte(`{"jsonrpc": "2.0", "method": "Main.Echo", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}`)
	err := fastjson.Unmarshal(jsonReq, &req)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	fmt.Println(string(jsonReq))
	fmt.Printf(" %+v \n", req)
}

func testFastJsonParser3() {
	//var req []myRequest
	/*jsonReq := []byte(`[{"jsonrpc": "2.0", "method": "Main.Echo", "params": {"subtrahend": 23, "minuend": 42}, "id": 3},
	{"jsonrpc": "2.0", "method": "Main.Echo", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}]`)*/

	jsonReq := []byte(`{"jsonrpc": "2.0", "method": "Main.Echo", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}`)
	rs, batch, err := ParseRequest(jsonReq)

	fmt.Printf(" %+v %+v %+v %s \n", rs, batch, err, rs[0].Method)

	ffmt.Pjson(rs)
	/*err := fastjson.Unmarshal(jsonReq, &req)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	fmt.Println(string(jsonReq))
	fmt.Printf(" %+v \n", req)*/
}

func testFastJsonParser4() {

	var req myRequest
	jsonReq := []byte(`{"jsonrpc": "2.0", "method": "Main.Echo", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}`)
	err := fastjson.Unmarshal(jsonReq, &req)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	fmt.Println(string(jsonReq))
	fmt.Printf(" %+v \n", req)
	ffmt.Pjson(req)

	b, err := fastjson.MarshalIndent(req, "", "")

	fmt.Printf(" back to the results %s \n", string(b))
}

func testFastJsonParser5() {

	resp := []*jsonrpc.Response{
		{
		Version: jsonrpc.Version,
		Error: jsonrpc.ErrParse(),
		},
	}

	b, err := GetResponse(resp, false) 
	fmt.Println(string(b))
	fmt.Println(err)
}



func testFastJsonParser2() {
	var jsonBlob = []byte(`[
	{"Name": "Platypus", "Order": "Monotremata"},
	{"Name": "Quoll",    "Order": "Dasyuromorphia"}
	]`)
	type Animal struct {
		Name  string
		Order string
	}
	var animals []Animal
	err := fastjson.Unmarshal(jsonBlob, &animals)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Printf("%+v", animals)
	// Output:
	// [{Name:Platypus Order:Monotremata} {Name:Quoll Order:Dasyuromorphia}]
}

func main() {
	testFastJsonParser5() 
	//	testFastJsonParser()
	return
	//exampleFfmt()
	//return
	fmt.Printf(" Starting a server \n")
	fmt.Printf("start to sleep \n")
	for {
		time.Sleep(1 * time.Second)
	}
}
