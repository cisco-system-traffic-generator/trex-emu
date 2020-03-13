package core

/* message  format

uint32 - message header

  MAGIC
  uint16 0xBEEF -- MAGIC FEEB - compress
  uint16 number of packets

each packet is like this

uint8 0xAA -- MAGIC
uint8 vport
uint16 pkt_size

*/

import (
	"encoding/binary"
	zmq "external/pebbe/zmq4"
	"fmt"
)

const (
	ZMQ_PACKET_HEADER_MAGIC = 0xBEEF
	ZMQ_TX_PKT_BUTST_SIZE   = 64
	ZMQ_TX_MAX_BUFFER_SIZE  = 32 * 1024
)

type VethIFZmq struct {
	rxCtx    *zmq.Context
	txCtx    *zmq.Context
	rxSocket *zmq.Socket
	txSocket *zmq.Socket
	rxPort   uint16 // in respect to EMU. rx->emu
	txPort   uint16 // in respect to EMU. emu->tx

	cn         chan []byte
	vec        []*Mbuf
	txVecSize  uint32
	stats      VethStats
	tctx       *CThreadCtx
	K12Monitor bool /* to standard output*/
	cdb        *CCounterDb
	buf        []byte
}

func (o *VethIFZmq) CreateSocket(server string, port uint16) (*zmq.Context, *zmq.Socket) {
	context, err := zmq.NewContext()
	if err != nil || context == nil {
		panic(err)
	}

	socket, err := context.NewSocket(zmq.PAIR)
	if err != nil || socket == nil {
		panic(err)
	}

	str := fmt.Sprintf("tcp://%s:%d", server, port)
	err = socket.Connect(str)
	if err != nil {
		panic(err)
	}
	return context, socket

}

func (o *VethIFZmq) Create(ctx *CThreadCtx, port uint16, server string) {

	o.rxCtx, o.rxSocket = o.CreateSocket(server, port)
	o.txCtx, o.txSocket = o.CreateSocket(server, port+1)

	o.rxPort = port
	o.txPort = port + 1
	o.buf = make([]byte, 32*1024)

	o.cn = make(chan []byte)

	o.vec = make([]*Mbuf, 0)
	o.txVecSize = 0
	o.tctx = ctx
	o.cdb = NewVethStatsDb(&o.stats)
}

func (o *VethIFZmq) StartRxThread() {
	go o.rxThread()
}

func (o *VethIFZmq) rxThread() {

	for {
		msg, err := o.rxSocket.RecvBytes(0)
		if err != nil {
			panic(err)
		}
		o.cn <- msg
	}
}

func (o *VethIFZmq) GetC() chan []byte {
	return o.cn
}

func (o *VethIFZmq) FlushTx() {
	if len(o.vec) == 0 {
		return
	}
	o.buf = o.buf[:0]
	var header uint32
	var pkth [4]byte
	o.stats.TxBatch++
	header = (uint32(0xBEEF) << 16) + uint32(len(o.vec))
	binary.BigEndian.PutUint32(pkth[:], header)
	o.buf = append(o.buf, pkth[:]...) // message header

	for _, m := range o.vec {
		if !m.IsContiguous() {
			panic(" mbuf should be contiguous  ")
		}
		if o.K12Monitor {
			m.DumpK12(o.tctx.GetTickSimInSec())
		}
		var pktHeader uint32
		pktHeader = (uint32(0xAA) << 24) + uint32((m.VPort()&0xff))<<16 + uint32(m.pktLen&0xffff)
		binary.BigEndian.PutUint32(pkth[:], pktHeader)
		o.buf = append(o.buf, pkth[:]...)     // packet header
		o.buf = append(o.buf, m.GetData()...) // packet itself
		m.FreeMbuf()
	}
	o.vec = o.vec[:0]
	o.txVecSize = 0
	o.txSocket.SendBytes(o.buf, 0)
}

func (o *VethIFZmq) Send(m *Mbuf) {

	pktlen := m.PktLen()
	o.stats.TxPkts++
	o.stats.TxBytes += uint64(pktlen)

	if o.txVecSize+pktlen >= ZMQ_TX_MAX_BUFFER_SIZE {
		o.FlushTx()
	}

	if !m.IsContiguous() {
		m1 := m.GetContiguous(&o.tctx.MPool)
		m.FreeMbuf()
		o.vec = append(o.vec, m1)
	} else {
		o.vec = append(o.vec, m)
	}
	o.txVecSize += pktlen
	if len(o.vec) == ZMQ_TX_PKT_BUTST_SIZE {
		o.FlushTx()
	}
}

// SendBuffer get a buffer as input, should allocate mbuf and call send
func (o *VethIFZmq) SendBuffer(unicast bool, c *CClient, b []byte) {
	var vport uint16
	vport = c.Ns.GetVport()
	m := o.tctx.MPool.Alloc(uint16(len(b)))
	m.SetVPort(vport)
	m.Append(b)
	if unicast {
		if c.DGW == nil {
			m.FreeMbuf()
			o.stats.TxDropNotResolve++
			return
		}
		if !c.DGW.IpdgResolved {
			m.FreeMbuf()
			o.stats.TxDropNotResolve++
			return
		}
		p := m.GetData()
		copy(p[6:12], c.Mac[:])
		copy(p[0:6], c.DGW.IpdgMac[:])
	}
	o.Send(m)
}

// get the packet
func (o *VethIFZmq) OnRx(m *Mbuf) {
	o.stats.RxPkts++
	o.stats.RxBytes += uint64(m.PktLen())
	if o.K12Monitor {
		fmt.Printf("\n ->RX<- \n")
		m.DumpK12(o.tctx.GetTickSimInSec())
	}
	o.tctx.HandleRxPacket(m)
}

/* get the veth stats */
func (o *VethIFZmq) GetStats() *VethStats {
	return &o.stats
}

func (o *VethIFZmq) SimulatorCleanup() {

	for _, m := range o.vec {
		m.FreeMbuf()
	}
	o.vec = nil
	o.rxSocket.Close()
	o.txSocket.Close()
	o.rxCtx.Term()
	o.txCtx.Term()

}

func (o *VethIFZmq) SetDebug(monitor bool, capture bool) {
	o.K12Monitor = monitor
}

func (o *VethIFZmq) GetCdb() *CCounterDb {
	return o.cdb
}

func (o *VethIFZmq) SimulatorCheckRxQueue() {

}

func (o *VethIFZmq) OnRxStream(stream []byte) {
	o.stats.RxBatch++
	blen := uint32(len(stream))
	if blen < 4 {
		o.stats.RxParseErr++
		return
	}
	header := binary.BigEndian.Uint32(stream[0:4])
	if ((header & 0xffff0000) >> 16) != ZMQ_PACKET_HEADER_MAGIC {
		o.stats.RxParseErr++
		return
	}
	pkts := int(header & 0xffff)
	var of uint16
	of = 4
	var vport uint8
	var pktLen uint16
	var m *Mbuf
	for i := 0; i < pkts; i++ {
		if blen < uint32(of+4) {
			o.stats.RxParseErr++
			return
		}

		header = binary.BigEndian.Uint32(stream[of : of+4])
		if (header & 0xff000000) != 0xAA000000 {
			o.stats.RxParseErr++
			return
		}

		vport = uint8((header & 0x00ff0000) >> 16)
		pktLen = uint16((header & 0x0000ffff))
		if blen < uint32(of+4+pktLen) {
			o.stats.RxParseErr++
			return
		}

		m = o.tctx.MPool.Alloc(pktLen)
		m.SetVPort(uint16(vport))
		m.Append(stream[of+4 : of+4+pktLen])
		o.OnRx(m)
		of = of + 4 + pktLen
	}
}

func (o *VethIFZmq) AppendSimuationRPC(request []byte) {
	panic("AppendSimuationRPC should not be called ")
}
