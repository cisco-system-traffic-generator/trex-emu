package main

import (
	"fmt"
	"time"

	zmq "github.com/pebbe/zmq4"
)

func createZMQ() {
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
		//fmt.Println("Received ", string(msg))

		// send reply back to client
		//reply := fmt.Sprintf("World")
		socket.Send(msg, 0)
	}

}

func main() {
	fmt.Printf(" Starting a server \n")
	go createZMQ()
	fmt.Printf("start to sleep \n")
	for {
		time.Sleep(1 * time.Second)
	}
}
