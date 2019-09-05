package jsonrpc

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"compress/zlib"
)

const ZMQ_MAGIC uint32 = 0xabe85cea

func isCompress(msg []byte) bool {
	if len(msg) < 8 {
		return false
	}
	magic := binary.BigEndian.Uint32(msg[0:])
	if magic == ZMQ_MAGIC {
		return true
	}
	return false
}

func uncompressBuff(msg []byte) []byte {
	if len(msg) < 8 {
		return msg
	}
	magic := binary.BigEndian.Uint32(msg[0:])
	//size := binary.BigEndian.Uint32(msg[4:])
	if magic != ZMQ_MAGIC {
		return msg
	}
	var out bytes.Buffer
	r, err := zlib.NewReader(bytes.NewReader(msg[8:]))

	if err != nil {
		/* magic but does not have zlib  headers
		need to logs this
		*/
		fmt.Println(err)
		return msg
	}

	io.Copy(&out, r)
	return out.Bytes()
}

func compressBuff(msg []byte) []byte {
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	r := bytes.NewReader(msg)

	/* write the header*/
	binary.Write(w, binary.BigEndian, ZMQ_MAGIC)
	var size uint32
	size = uint32(len(msg))
	binary.Write(w, binary.BigEndian, size)

	/* write the rest zlib*/
	cw := zlib.NewWriter(w)
	io.Copy(cw, r)
	cw.Close()
	w.Flush()
	return out.Bytes()
}
