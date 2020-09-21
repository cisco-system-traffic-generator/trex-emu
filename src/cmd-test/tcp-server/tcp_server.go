package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

var port = "0.0.0.0:9001"

func echo(conn net.Conn) {
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes(byte('\n'))
		if err == nil {
			conn.Write(line)
		} else {
			break
		}
	}
	conn.Close()
}

func main() {
	l, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("ERROR", err)
			continue
		}
		go echo(conn)
	}
}
