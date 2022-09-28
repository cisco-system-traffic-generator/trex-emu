package ipfix

import (
	"emu/core"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

type UdpExporterCounters struct {
	apiWrites                uint64
	apiWritesFailed          uint64
	txWrites                 uint64
	txWritesFailed           uint64
	txBytes                  uint64
	txPackets                uint64
	txTempRecords            uint64
	txDataRecords            uint64
	writeChanEvLowWatermark  uint64
	writeChanEvHighWatermark uint64
	writeChanLen             uint64
	writeChanPeakLen         uint64
}

type UdpExporter struct {
	conn       net.Conn
	init       bool
	enabled    bool
	writeChan  *core.NonBlockingChan
	wg         sync.WaitGroup
	client     *PluginIPFixClient
	counters   UdpExporterCounters
	countersDb *core.CCounterDb
}

type UdpExporterInfoJson struct {
	ExporterType string `json:"exporter_type"`
	Enabled      string `json:"enabled"`
}

const (
	udpExporterType                 = "udp"
	udpExporterCountersDbName       = "IPFIX udp exporter"
	udpExporterChanCapacity         = 2000
	udpExporterChanLowWatermarkThr  = 400
	udpExporterChanHighWatermarkThr = 1600
)

type udpExporterWriteInfo struct {
	buffer         []byte
	tempRecordsNum uint32
	dataRecordsNum uint32
}

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
	p.enabled = true
	p.init = true

	log.Info("\nIPFIX UDP exporter created with the following parameters: ",
		"\n\thostport - ", hostport)

	return p, nil
}

func (p *UdpExporter) newUdpExporterCountersDb() {
	p.countersDb = core.NewCCounterDb(udpExporterCountersDbName)

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.apiWrites,
		Name:     "apiWrites",
		Help:     "Num of API calls to write",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.apiWritesFailed,
		Name:     "apiWritesFailed",
		Help:     "Num of failed API calls to write",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txWrites,
		Name:     "txWrites",
		Help:     "Num of socket writes",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txWritesFailed,
		Name:     "txWritesFailed",
		Help:     "Num of failed socket writes",
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
		Counter:  &p.counters.txPackets,
		Name:     "txPackets",
		Help:     "Num of packets transmitted",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txTempRecords,
		Name:     "txTempRecords",
		Help:     "Num of template records transmitted",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txDataRecords,
		Name:     "txDataRecords",
		Help:     "Num of data records transmitted",
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

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writeChanLen,
		Name:     "writeChanLen",
		Help:     "Write channel current length",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.writeChanPeakLen,
		Name:     "writeChanPeakLen",
		Help:     "Write channel peak length",
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
	if p.enabled == false {
		return 0, nil
	}

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

		if p.enabled == false {
			break
		}

		p.counters.writeChanLen = uint64(p.writeChan.GetLen())
		p.counters.txWrites++

		writeInfo := obj.(*udpExporterWriteInfo)
		_, err = p.write(*&writeInfo.buffer)
		if err == nil {
			p.counters.txBytes += uint64(len(*&writeInfo.buffer))
			p.counters.txPackets++
			p.counters.txTempRecords += uint64(writeInfo.tempRecordsNum)
			p.counters.txDataRecords += uint64(writeInfo.dataRecordsNum)
		} else {
			p.counters.txWritesFailed++
		}
	}
}

func (p *UdpExporter) Write(b []byte, tempRecordsNum uint32, dataRecordsNum uint32) (int, error) {
	if p.init == false {
		return 0, errors.New("Failed to write - udp exporter object is uninitialized")
	}

	if p.enabled == false {
		return 0, nil
	}

	p.counters.apiWrites++

	var writeInfo *udpExporterWriteInfo
	writeInfo = new(udpExporterWriteInfo)
	writeInfo.buffer = b
	writeInfo.tempRecordsNum = tempRecordsNum
	writeInfo.dataRecordsNum = dataRecordsNum

	err := p.writeChan.Write(writeInfo, false)
	if err != nil {
		p.counters.apiWritesFailed++
		return 0, err
	}

	p.counters.writeChanLen = uint64(p.writeChan.GetLen())
	p.counters.writeChanPeakLen = uint64(p.writeChan.GetPeakLen())

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

func (p *UdpExporter) Enable(enable bool) error {
	p.enabled = enable
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
	res.Enabled = strconv.FormatBool(p.enabled)

	return &res
}
