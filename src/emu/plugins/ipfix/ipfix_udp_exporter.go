package ipfix

import (
	"emu/core"
	"errors"
	"fmt"
	"net"
	"sync"
)

type UdpExporterCounters struct {
	writes                   uint64
	writesFailed             uint64
	txBytes                  uint64
	writeChanEvLowWatermark  uint64
	writeChanEvHighWatermark uint64
}

type UdpExporter struct {
	conn       net.Conn
	init       bool
	writeChan  *core.NonBlockingChan
	wg         sync.WaitGroup
	client     *PluginIPFixClient
	counters   UdpExporterCounters
	countersDb *core.CCounterDb
}

type UdpExporterInfoJson struct {
	ExporterType string `json:"exporter_type"`
}

const (
	udpExporterType                 = "udp"
	udpExporterCountersDbName       = "IPFIX udp exporter"
	udpExporterChanCapacity         = 200
	udpExporterChanLowWatermarkThr  = 40
	udpExporterChanHighWatermarkThr = 160
)

func NewUdpExporter(client *PluginIPFixClient, hostport string) (*UdpExporter, error) {
	if client == nil {
		return nil, errors.New("Client param is nil")
	}

	var err error

	p := new(UdpExporter)

	kernelMode := client.Tctx.GetKernelMode()
	if kernelMode != p.GetKernelMode() {
		return nil, ErrExporterWrongKernelMode
	}

	p.client = client

	p.newUdpExporterCountersDb()

	p.writeChan, err = core.NewNonBlockingChan(
		udpExporterChanCapacity,
		udpExporterChanLowWatermarkThr,
		udpExporterChanHighWatermarkThr,
		client.Tctx.GetTimerCtx())
	if err != nil {
		return nil, errors.New("Failed to create non-blocking channel")
	}

	p.writeChan.RegisterObserver(p)

	conn, err := net.Dial("udp", hostport)
	if err != nil {
		return nil, errors.New("Failed to create UDP socket")
	}
	p.conn = conn

	p.wg.Add(1)
	go p.writerThread()
	p.init = true

	log.Info("\nIPFIX UDP exporter created with the following parameters: ",
		"\n\thostport - ", hostport)

	return p, nil
}

func (p *UdpExporter) newUdpExporterCountersDb() {
	p.countersDb = core.NewCCounterDb(udpExporterCountersDbName)

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writes,
		Name:     "writes",
		Help:     "Num of writes",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writesFailed,
		Name:     "writesFailed",
		Help:     "Num of failed writes",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txBytes,
		Name:     "txBytes",
		Help:     "Num of bytes transmitted",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writeChanEvLowWatermark,
		Name:     "writeChanEvLowWatermark",
		Help:     "Num of write channel low watermark events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writeChanEvHighWatermark,
		Name:     "writeChanEvHighWatermark",
		Help:     "Num of write channel high watermark events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
}

func (p *UdpExporter) Notify(event core.NonBlockingChanEvent) {
	switch event {
	case core.EvLowWatermark:
		p.counters.writeChanEvLowWatermark++
		p.client.Pause(false)
	case core.EvHighWatermark:
		p.counters.writeChanEvHighWatermark++
		p.client.Pause(true)
	default:
	}
}

func (p *UdpExporter) write(b []byte) (int, error) {
	n, err := p.conn.Write(b)
	if err != nil {
		return 0, fmt.Errorf("Failed to write to socket - %s", err)
	}

	return n, err
}

func (p *UdpExporter) writerThread() {
	defer p.wg.Done()
	for {
		obj, err, more := p.writeChan.Read(true)
		if err != nil || !more {
			return
		}

		b := obj.(*[]byte)
		_, err = p.write(*b)
		if err == nil {
			p.counters.txBytes += uint64(len(*b))
		} else {
			p.counters.writesFailed++
		}
	}
}

func (p *UdpExporter) Write(b []byte, tempRecordsNum uint32, dataRecordsNum uint32) (int, error) {
	if p.init == false {
		return 0, errors.New("Failed to write - udp exporter object is uninitialized")
	}

	p.counters.writes++

	err := p.writeChan.Write(&b, false)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (p *UdpExporter) Close() error {
	if p.init == false {
		return nil
	}

	p.writeChan.Close()
	p.wg.Wait()

	err := p.conn.Close()
	if err != nil {
		return fmt.Errorf("Failed to close socket - %s", err)
	}

	p.init = false

	return nil
}

func (p *UdpExporter) GetMaxSize() int {
	if p.init == false {
		return 0
	}

	return 1500
}

func (p *UdpExporter) GetType() string {
	return udpExporterType
}

func (p *UdpExporter) GetCountersDbVec() *core.CCounterDbVec {
	db := core.NewCCounterDbVec(udpExporterCountersDbName)
	db.Add(p.countersDb)
	return db
}

func (p *UdpExporter) GetKernelMode() bool {
	return true
}

func (p *UdpExporter) GetInfoJson() interface{} {
	var res UdpExporterInfoJson

	res.ExporterType = p.GetType()

	return &res
}
