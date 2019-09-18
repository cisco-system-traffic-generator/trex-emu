package main

import (
	"bytes"
	"context"
	"emu/core"
	"fmt"
	"io"
	"log"
	"math/rand"
	"time"

	"external/osamingo/jsonrpc"
	zmq "external/pebbe/zmq4"

	"encoding/binary"
	"encoding/hex"

	"compress/zlib"

	ffmt "github.com/go-ffmt/ffmt"
	"github.com/intel-go/fastjson"
)

type CZmqJsonRPC2 struct {
	ctx        *zmq.Context
	socket     *zmq.Socket
	serverPort uint16
	mr         *jsonrpc.MethodRepository
}

var RcpCtx CZmqJsonRPC2

type (
	ApiSyncHandler struct{}
	ApiSyncParams  struct {
		Name  string `json:"name"`
		Major uint8  `json:"major"`
		Minor uint8  `json:"minor"`
	}

	ApiGetVersionHandler struct{}
	ApiGetVersionParams  struct{}
	ApiGetVersionResult  struct {
		Version   string `json:"version"`
		Builddate string `json:"build_date"`
		Buildtime string `json:"build_time"`
		Buildby   string `json:"built_by"`
		Mode      string `json:"mode"`
	}

	ApiPingHandler struct{}
	ApiPingParams  struct{}
	ApiPingResult  struct {
		Timestamp float64 `json:"ts"`
	}
)

func (h ApiPingHandler) ServeJSONRPC(c context.Context, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	return ApiPingResult{
		Timestamp: float64(time.Now().Second()),
	}, nil
}

func (h ApiGetVersionHandler) ServeJSONRPC(c context.Context, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	return ApiGetVersionResult{
		Version:   "v0.1",
		Builddate: "05.05.2019",
		Buildtime: "16:00",
		Buildby:   "hhaim",
		Mode:      "emulation",
	}, nil
}

const EMU_MAJOR_VER uint8 = 0
const EMU_MINOR_VER uint8 = 1
const EMU_NAME = "EMU"

var apiHandler string

func (h ApiSyncHandler) ServeJSONRPC(c context.Context, params *fastjson.RawMessage) (interface{}, *jsonrpc.Error) {

	api := RcpCtx.mr.GetAPI()
	if len(api) == 0 {
		// generate handler
		api = core.RandSeq(10)
		apiHandler = api
		fmt.Println(" API" + apiHandler)
		RcpCtx.mr.SetAPI(api)
	}
	var p ApiSyncParams
	if err := jsonrpc.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	// agreed
	valid := false
	if (p.Major == EMU_MAJOR_VER) && (p.Minor <= EMU_MINOR_VER) && (p.Name == "EMU") {
		valid = true
	}

	if valid {
		return jsonrpc.ApiSyncResult{
			Api: apiHandler,
		}, nil
	} else {
		msg := fmt.Sprintf("Server API %s:(%d:%d) does not match the client API %s:(%d:%d) ",
			EMU_NAME, EMU_MAJOR_VER, EMU_MINOR_VER,
			p.Name, p.Major, p.Minor)
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.ErrorCodeInvalidRequest,
			Message: msg,
		}
	}
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

	mr := jsonrpc.NewMethodRepository()
	o.mr = mr
	o.mr.Verbose = true

	if err := mr.RegisterMethod("api_sync_v2", ApiSyncHandler{}, true); err != nil {
		log.Fatalln(err)
	}

	if err := mr.RegisterMethod("get_version", ApiGetVersionHandler{}, false); err != nil {
		log.Fatalln(err)
	}

	if err := mr.RegisterMethod("ping", ApiPingHandler{}, true); err != nil {
		log.Fatalln(err)
	}

}

// Delete  this is an help
func (o *CZmqJsonRPC2) Delete() {
	o.socket.Close()
}

// HandleReq input buffer return buffer
func (o *CZmqJsonRPC2) HandleReq(req []byte) []byte {
	return (o.mr.ServeBytesCompress(req))
}

// HandleReqRes this is an help
func (o *CZmqJsonRPC2) HandleReqRes() {
	msg, _ := o.socket.RecvBytes(0)
	res := o.HandleReq(msg)
	o.socket.SendBytes(res, 0)
}

func testZMQJSONRPC() {
	fmt.Println(" start server ")

	RcpCtx.Create(4510)
	for {
		RcpCtx.HandleReqRes()
	}

	RcpCtx.Delete()
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

func Test3() {

	b := []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x70}

	b1 := b[0:4]
	fmt.Println(hex.Dump(b1))
	x1 := binary.BigEndian.Uint32(b[0:])
	x2 := binary.BigEndian.Uint32(b[4:])

	var out bytes.Buffer
	r, err := zlib.NewReader(bytes.NewReader(b))
	fmt.Println(err)
	io.Copy(&out, r)

	fmt.Println(hex.Dump(out.Bytes()))

	//x2 := binary.BigEndian.Uint32(b[4:7])
	fmt.Printf(" 0x%x 0x%x \n", x1, x2)
	return
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

/*func testMarshal() {
	id := fastjson.RawMessage([]byte(`{"a":"b","api_h": "xDtMBRVXwr"}`))
	var p map[string]*fastjson.RawMessage
	if err := fastjson.Unmarshal(&id, &p); err != nil {
		fmt.Println(err)
		return
	}
	if val, ok := p["api_h"]; ok {
		//string(*val)
		var str string

		fmt.Printf("%s", "hey")
	}

}*/

func main() {
	rand.Seed(time.Now().UnixNano())
	//testMarshal2()

	testZMQJSONRPC()

	//testFastJsonParser5()
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
