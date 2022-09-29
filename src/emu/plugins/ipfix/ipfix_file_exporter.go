package ipfix

import (
	"bufio"
	"emu/core"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FileExporterParams struct {
	Name        string   `json:"name"`
	Dir         string   `json:"dir"`
	MaxSize     int      `json:"max_size"`
	MaxInterval Duration `json:"max_interval"`
	MaxFiles    int      `json:"max_files"`
	Compress    bool     `json:"compress"`
}

type FileExporterStats struct {
	apiWrites               uint64
	apiWritesFailed         uint64
	apiRotates              uint64
	apiRotatesFailed        uint64
	txWrites                uint64
	txWritesFailed          uint64
	txBytes                 uint64
	txTempRecords           uint64
	txDataRecords           uint64
	cmdWrite                uint64
	cmdRotate               uint64
	cmdChanEvLowWatermark   uint64
	cmdChanEvHighWatermark  uint64
	cmdChanLen              uint64
	cmdChanPeakLen          uint64
	fileRotates             uint64
	fileRotatesFailed       uint64
	maxIntervalTimerExpired uint64
	maxFilesExceeded        uint64
	maxSizeExceeded         uint64
	evFileCreated           uint64
	evFileRemoved           uint64
}

type FileExporterEventId int

const (
	EvFileCreated FileExporterEventId = iota
	EvFileRemoved
)

func (s FileExporterEventId) String() string {
	switch s {
	case EvFileCreated:
		return "EvFileCreated"
	case EvFileRemoved:
		return "EvFileRemoved"
	}
	return "unknown"
}

type FileExporterEvent struct {
	id             FileExporterEventId
	filePath       string
	fileSize       int
	tempRecordsNum uint32
	dataRecordsNum uint32
}

func (s FileExporterEvent) String() string {
	str := fmt.Sprintf("FileExporterEvent: \n"+
		"  id = %s \n"+
		"  filePath = %s \n"+
		"  fileSize = %d \n"+
		"  tempRecordsNum = %d \n"+
		"  dataRecordsNum = %d \n",
		s.id, s.filePath, s.fileSize, s.tempRecordsNum, s.dataRecordsNum)
	return str
}

type FileExporterObserver interface {
	notify(event FileExporterEvent)
}

type FileExporter struct {
	name               string
	namePrefix         string
	nameExt            string
	maxSize            int
	maxInterval        time.Duration
	compress           bool
	dir                string
	maxFiles           int
	enabled            bool
	init               bool
	file               *os.File
	fileWriter         *bufio.Writer
	creationTime       time.Time
	index              uint64 // Running index for created files
	fileSize           int    // Size of current file
	tempRecordsNum     uint32 // Number of template records in current file
	dataRecordsNum     uint32 // Number of data records in current file
	observerList       []*FileExporterObserver
	fileFormatRegexStr string
	fileFormatRegex    *regexp.Regexp
	cmdChan            *core.NonBlockingChan
	done               chan bool
	wg                 sync.WaitGroup
	client             *PluginIPFixClient
	counters           FileExporterStats
	countersDb         *core.CCounterDb
	timerCtx           *core.TimerCtx
	maxIntervalTimer   *time.Timer
}

type FileExporterInfoJson struct {
	ExporterType string `json:"exporter_type"`
	Enabled      string `json:"enabled"`
}

const (
	fileExporterType                 = "file"
	fileExporterCountersDbName       = "IPFIX file exporter"
	rotatedFileTimeFormat            = "20060102150405" /* yyyyMMddHHmmss */
	compressSuffix                   = ".gz"
	fileFormatRegexStr               = `\d+\.(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})-(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).`
	fileExporterChanCapacity         = 10000
	fileExporterChanLowWatermarkThr  = 2000
	fileExporterChanHighWatermarkThr = 8000
)

type fileExporterCmdId int

const (
	cmdWrite fileExporterCmdId = iota
	cmdRotate
)

func (s fileExporterCmdId) String() string {
	switch s {
	case cmdWrite:
		return "cmdWrite"
	case cmdRotate:
		return "cmdRotate"
	}
	return "unknown"
}

type fileExporterCmd struct {
	id                  fileExporterCmdId
	writeBuffer         []byte
	writeTempRecordsNum uint32
	writeDataRecordsNum uint32
}

func NewFileExporter(client *PluginIPFixClient, params *FileExporterParams) (*FileExporter, error) {
	if params.Name == "" {
		return nil, errors.New("Failed to create file exporter - name parameter is mandatory")
	}

	if params.Dir == "" {
		return nil, errors.New("Failed to create file exporter - dir parameter is mandatory")
	}

	var err error

	p := new(FileExporter)

	kernelMode := client.Tctx.GetKernelMode()
	if kernelMode != p.GetKernelMode() {
		return nil, ErrExporterWrongKernelMode
	}

	p.newFileExporterCountersDb()

	p.name = params.Name
	p.maxSize = params.MaxSize
	p.maxInterval = params.MaxInterval.Duration
	p.compress = params.Compress
	p.maxFiles = params.MaxFiles
	p.dir = params.Dir
	p.client = client

	// If MaxSize is not provided assume no size limit
	if params.MaxSize == 0 {
		p.maxSize = math.MaxInt
	}

	p.namePrefix, p.nameExt = prefixAndExt(p.name)
	p.fileFormatRegexStr = fileFormatRegexStr
	p.fileFormatRegex = regexp.MustCompile(p.fileFormatRegexStr)
	p.timerCtx = client.Tctx.GetTimerCtx()
	p.done = make(chan bool)

	p.newMaxIntervalTimer()

	p.cmdChan, err = core.NewNonBlockingChan(
		fileExporterChanCapacity,
		fileExporterChanLowWatermarkThr,
		fileExporterChanHighWatermarkThr,
		p.timerCtx)
	if err != nil {
		return nil, errors.New("Failed to create non-blocking channel")
	}

	p.cmdChan.RegisterObserver(p)

	p.wg.Add(1)
	go p.cmdThread()
	p.enabled = true
	p.init = true

	log.Info("\nIPFIX FILE exporter created with the following parameters: ",
		"\n\tname -", p.name, " (prefix -", p.namePrefix, ", ext -", p.nameExt, ")",
		"\n\tdir -", p.dir,
		"\n\tmaxSize -", p.maxSize,
		"\n\tmaxInterval -", p.maxInterval,
		"\n\tcompress -", p.compress,
		"\n\tmaxFiles -", p.maxFiles)

	return p, nil
}

func (p *FileExporter) newFileExporterCountersDb() {
	p.countersDb = core.NewCCounterDb(fileExporterCountersDbName)

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
		Counter:  &p.counters.apiRotates,
		Name:     "apiRotates",
		Help:     "Num of API calls to rotate",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.apiRotatesFailed,
		Name:     "apiRotatesFailed",
		Help:     "Num of failed API calls to rotate",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txWrites,
		Name:     "txWrites",
		Help:     "Num of files writes",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txWritesFailed,
		Name:     "txWritesFailed",
		Help:     "Num of failed files writes failed",
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
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.cmdWrite,
		Name:     "cmdWrite",
		Help:     "Num of command channel write events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.cmdRotate,
		Name:     "cmdRotate",
		Help:     "Num of command channel rotate events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.cmdChanEvLowWatermark,
		Name:     "cmdChanEvLowWatermark",
		Help:     "Num of command chan low watermark events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.cmdChanEvHighWatermark,
		Name:     "cmdChanEvHighWatermark",
		Help:     "Num of command chan high watermark events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.cmdChanLen,
		Name:     "cmdChanLen",
		Help:     "Command channel current length",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.cmdChanPeakLen,
		Name:     "cmdChanPeakLen",
		Help:     "Command channel peak length",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.fileRotates,
		Name:     "fileRotates",
		Help:     "Num of file rotates",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.fileRotatesFailed,
		Name:     "fileRotatesFailed",
		Help:     "Num of failed file rotates",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.maxIntervalTimerExpired,
		Name:     "maxIntervalTimerExpired",
		Help:     "Num of max interval timer expired",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.maxFilesExceeded,
		Name:     "maxFilesExceeded",
		Help:     "Num of max files exceeded",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.maxSizeExceeded,
		Name:     "maxSizeExceeded",
		Help:     "Num of max size exceeded",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.evFileCreated,
		Name:     "evFileCreated",
		Help:     "Num of file created event notifications",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.evFileRemoved,
		Name:     "evFileRemoved",
		Help:     "Num of file removed event notifications",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
}

func (p *FileExporter) GetName() string {
	return p.name
}

func (p *FileExporter) GetDir() string {
	return p.dir
}

func (p *FileExporter) GetMaxSize() int {
	return p.maxSize
}

func (p *FileExporter) GetMaxInterval() time.Duration {
	return p.maxInterval
}

func (p *FileExporter) GetCompress() bool {
	return p.compress
}

func (p *FileExporter) GetMaxFiles() int {
	return p.maxFiles
}

func (p *FileExporter) GetType() string {
	return fileExporterType
}

func (p *FileExporter) GetCountersDbVec() *core.CCounterDbVec {
	db := core.NewCCounterDbVec(fileExporterCountersDbName)
	db.Add(p.countersDb)
	return db
}

func (p *FileExporter) GetKernelMode() bool {
	return true
}

func (p *FileExporter) GetInfoJson() interface{} {
	var res FileExporterInfoJson

	res.ExporterType = p.GetType()
	res.Enabled = strconv.FormatBool(p.enabled)

	return &res
}

func (p *FileExporter) Write(b []byte, tempRecordsNum uint32, dataRecordsNum uint32) (int, error) {
	if p.init == false {
		return 0, errors.New("Failed to write - file exporter object is uninitialized")
	}

	if p.enabled == false {
		return 0, nil
	}

	p.counters.apiWrites++

	var cmd *fileExporterCmd
	cmd = new(fileExporterCmd)
	cmd.id = cmdWrite
	cmd.writeBuffer = b
	cmd.writeTempRecordsNum = tempRecordsNum
	cmd.writeDataRecordsNum = dataRecordsNum

	err := p.cmdChan.Write(cmd, false)
	if err != nil {
		p.counters.apiWritesFailed++
		return 0, err
	}

	p.counters.cmdChanLen = uint64(p.cmdChan.GetLen())
	p.counters.cmdChanPeakLen = uint64(p.cmdChan.GetPeakLen())

	return len(b), nil
}

func (p *FileExporter) Close() error {
	if p.init == false {
		return nil
	}

	return p.close()
}

func (p *FileExporter) Enable(enable bool) error {
	p.enabled = enable
	return nil
}

func (p *FileExporter) Rotate() error {
	if p.init == false {
		return nil
	}

	if p.enabled == false {
		return nil
	}

	p.counters.apiRotates++

	var cmd *fileExporterCmd
	cmd = new(fileExporterCmd)
	cmd.id = cmdRotate

	err := p.cmdChan.Write(cmd, false)
	if err != nil {
		p.counters.apiRotatesFailed++
		return err
	}

	return err
}

func (p *FileExporter) RegisterObserver(o FileExporterObserver) {
	if p.init == false {
		return
	}

	p.observerList = append(p.observerList, &o)
}

func (p *FileExporter) UnregisterObserver(o FileExporterObserver) {
	if p.init == false {
		return
	}

	p.observerList = removeFromslice(p.observerList, &o)
}

func (p *FileExporter) Notify(event core.NonBlockingChanEvent) {
	switch event {
	case core.EvLowWatermark:
		p.counters.cmdChanEvLowWatermark++
		p.client.Pause(false)
	case core.EvHighWatermark:
		p.counters.cmdChanEvHighWatermark++
		p.client.Pause(true)
	default:
	}
}

func (p *FileExporter) cmdThread() {
	defer p.wg.Done()
	var err error

	for {
		select {
		case obj, more := <-p.cmdChan.GetC():
			if !more {
				return
			}

			cmd := obj.(*fileExporterCmd)
			switch cmd.id {
			case cmdWrite:
				p.counters.cmdWrite++
				p.counters.cmdChanLen = uint64(p.cmdChan.GetLen())

				if p.enabled == false {
					break
				}

				p.counters.txWrites++

				_, err = p.writeInt(*&cmd.writeBuffer, cmd.writeTempRecordsNum, cmd.writeDataRecordsNum)
				if err != nil {
					p.counters.txWritesFailed++
				}
			case cmdRotate:
				p.counters.cmdRotate++
				p.counters.cmdChanLen = uint64(p.cmdChan.GetLen())

				if p.enabled == false {
					break
				}

				if err := p.rotateInt(); err != nil {
					return
				}
			}
		case <-p.maxIntervalTimer.C:
			p.counters.maxIntervalTimerExpired++

			if p.enabled == false {
				break
			}

			if err := p.rotateInt(); err != nil {
				return
			}
		case <-p.done:
			log.Debug("Shutting down File exporter commands thread")
			return
		}
	}
}

func (p *FileExporter) writeInt(b []byte, tempRecordsNum uint32, dataRecordsNum uint32) (int, error) {
	writeLen := len(b)

	if writeLen > p.maxSize {
		return 0, fmt.Errorf(
			"Failed to write - write length %d exceeds maximum file size %d", writeLen, p.maxSize,
		)
	}

	var n int
	var err error

	filename := p.filePath()
	_, err = os.Stat(filename)
	if p.file == nil || os.IsNotExist(err) {
		if err = p.openNew(); err != nil {
			return 0, err
		}
	}

	if p.fileSize+writeLen > p.maxSize {
		p.counters.maxSizeExceeded++
		if err := p.rotateInt(); err != nil {
			return 0, err
		}
	}

	n, err = p.fileWriter.Write(b)
	if err != nil {
		return 0, err
	}

	p.fileSize += n
	p.tempRecordsNum += tempRecordsNum
	p.dataRecordsNum += dataRecordsNum

	p.counters.txBytes += uint64(n)
	p.counters.txTempRecords += uint64(tempRecordsNum)
	p.counters.txDataRecords += uint64(dataRecordsNum)

	return n, err
}

func (p *FileExporter) rotateInt() error {
	p.counters.fileRotates++

	if err := p.fileClose(); err != nil {
		p.counters.fileRotatesFailed++
		return err
	}

	if err := p.openNew(); err != nil {
		p.counters.fileRotatesFailed++
		return err
	}

	return nil
}

func (p *FileExporter) fileClose() error {
	p.stopIntervalTimer()

	if p.file == nil {
		return nil
	}

	p.fileWriter.Flush()
	err := p.file.Close()
	p.file = nil

	if err := p.rotateExistingFile(); err != nil {
		return fmt.Errorf("Failed to rotate file: %s", err)
	}

	return err
}

func (p *FileExporter) close() error {
	p.done <- true
	p.wg.Wait()
	p.cmdChan.Close()
	close(p.done)

	err := p.fileClose()

	p.init = false

	return err
}

// Get number of rotated files in directory.
func (p *FileExporter) getNumOfRotatedFiles() (int, error) {
	files, err := ioutil.ReadDir(p.dir)
	if err != nil {
		return 0, err
	}

	// Count only rotated file exporter files
	n := 0
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		match := p.fileFormatRegex.Match([]byte(f.Name()))
		if !match {
			continue
		}

		if !strings.HasPrefix(f.Name(), p.namePrefix) {
			continue
		}
		if !strings.HasSuffix(f.Name(), p.nameExt) &&
			!strings.HasSuffix(f.Name(), p.nameExt+compressSuffix) {
			continue
		}

		n++
	}

	return n, nil
}

func (p *FileExporter) rotateExistingFile() error {
	// Check if there's an in progress file to rotate
	name := p.filePath()
	_, err := os.Stat(name)
	if err != nil {
		return nil
	}

	if p.maxFiles > 0 {
		numOfRotatedFiles, _ := p.getNumOfRotatedFiles()
		if numOfRotatedFiles >= p.maxFiles {
			p.counters.maxFilesExceeded++
			return nil
		}
	}

	newName := p.rotatedFileName(name)
	if err := os.Rename(name, newName); err != nil {
		return fmt.Errorf("Failed to rename file: %s", err)
	}

	if p.compress {
		if err := compressFile(newName, newName+compressSuffix); err != nil {
			return fmt.Errorf("Failed to compress rotated file: %s", err)
		}
		newName = newName + compressSuffix
	}

	event := new(FileExporterEvent)
	event.id = EvFileCreated
	event.filePath = newName
	event.fileSize = p.fileSize
	event.tempRecordsNum = p.tempRecordsNum
	event.dataRecordsNum = p.dataRecordsNum
	p.notifyObservers(*event)

	return nil
}

func (p *FileExporter) openNew() error {
	err := os.MkdirAll(p.dir, 0755)
	if err != nil {
		return fmt.Errorf("Failed to create directory for: %s", err)
	}

	name := p.filePath()
	info, err := os.Stat(name)
	mode := os.FileMode(0666)
	if err == nil {
		mode = info.Mode()
		if err := p.rotateExistingFile(); err != nil {
			return fmt.Errorf("Failed to rotate file: %s", err)
		}
	}

	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("Failed to open new file: %s", err)
	}

	if p.fileWriter != nil {
		p.fileWriter.Reset(f)
	} else {
		p.fileWriter = bufio.NewWriter(f)
	}
	p.file = f
	p.fileSize = 0
	p.tempRecordsNum = 0
	p.dataRecordsNum = 0

	p.creationTime = currentTime()
	p.index++

	p.startIntervalTimer()

	return nil
}

func timeFromName(filename, prefix, ext string) (time.Time, error) {
	if !strings.HasPrefix(filename, prefix) {
		return time.Time{}, errors.New("mismatched prefix")
	}
	if !strings.HasSuffix(filename, ext) {
		return time.Time{}, errors.New("mismatched extension")
	}
	ts := filename[len(prefix) : len(filename)-len(ext)]
	return time.Parse(rotatedFileTimeFormat, ts)
}

func removeFromslice(observerList []*FileExporterObserver, observerToRemove *FileExporterObserver) []*FileExporterObserver {
	observerListLength := len(observerList)
	for i, observer := range observerList {
		if observerToRemove == observer {
			observerList[observerListLength-1], observerList[i] = observerList[i], observerList[observerListLength-1]
			return observerList[:observerListLength-1]
		}
	}
	return observerList
}

func (p *FileExporter) notifyObservers(event FileExporterEvent) {
	log.Info("notifyObservers \n", event)

	switch event.id {
	case EvFileCreated:
		p.counters.evFileCreated++
	case EvFileRemoved:
		p.counters.evFileRemoved++
	}

	for _, observer := range p.observerList {
		(*observer).notify(event)
	}
}

func (p *FileExporter) fileName() string {
	return p.name
}

func (p *FileExporter) filePath() string {
	return filepath.Join(p.dir, p.fileName())
}

func (p *FileExporter) rotatedFileName(name string) string {
	dir := filepath.Dir(name)

	var creation_timestamp string
	if p.creationTime.Nanosecond() == 0 {
		creation_timestamp = currentTime().Format(rotatedFileTimeFormat)
	} else {
		creation_timestamp = p.creationTime.Format(rotatedFileTimeFormat)
	}
	current_timestamp := currentTime().Format(rotatedFileTimeFormat)

	rotatedFileName := filepath.Join(dir, fmt.Sprintf("%s_%v.%s-%s%s",
		p.namePrefix, p.index, creation_timestamp, current_timestamp, p.nameExt))

	return rotatedFileName
}

func (p *FileExporter) newMaxIntervalTimer() {
	if p.maxIntervalTimer == nil && p.maxInterval > 0 {
		p.maxIntervalTimer = time.NewTimer(p.maxInterval)
		p.maxIntervalTimer.Stop()
	}
}

func (p *FileExporter) startIntervalTimer() {
	if p.maxIntervalTimer != nil && p.maxInterval > 0 {
		p.maxIntervalTimer.Reset(p.maxInterval)
	}
}

func (p *FileExporter) stopIntervalTimer() {
	if p.maxIntervalTimer != nil {
		p.maxIntervalTimer.Stop()
	}
}
