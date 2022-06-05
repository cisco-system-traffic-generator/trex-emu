package ipfix

import (
	"emu/core"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type FileExporterParams struct {
	Name        string        `json:"name"`
	MaxSize     int           `json:"max_size"`
	MaxInterval time.Duration `json:"max_interval"`
	Compress    bool          `json:"compress"`
	Dir         string        `json:"dir"`
	MaxFiles    int           `json:"max_files"`
}

type FileExporterStats struct {
	writes                 uint64
	writesFailed           uint64
	txBytes                uint64
	filesExported          uint64
	filesExportFailed      uint64
	cmdChanEvLowWatermark  uint64
	cmdChanEvHighWatermark uint64
	evFileCreated          uint64
	evFileRemoved          uint64
	cmdWrite               uint64
	cmdTimerTick           uint64
	cmdRotate              uint64
	maxFilesExceeded       uint64
	fileRotates            uint64
	fileRotatesFailed      uint64
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
	id       FileExporterEventId
	filePath string
}

type FileExporterObserver interface {
	notify(event FileExporterEvent)
}

type FileExporter struct {
	name         string
	namePrefix   string
	nameExt      string
	maxSize      int
	maxInterval  time.Duration
	compress     bool
	dir          string
	maxFiles     int
	init         bool
	file         *os.File
	creationTime time.Time
	// Running index for created files
	index uint64
	// Current size
	size               int
	observerList       []*FileExporterObserver
	fileFormatRegexStr string
	fileFormatRegex    *regexp.Regexp
	cmdChan            *core.NonBlockingChan
	wg                 sync.WaitGroup
	client             *PluginIPFixClient
	timer              core.CHTimerObj
	timerCtx           *core.TimerCtx
	counters           FileExporterStats
	countersDb         *core.CCounterDb
}

type FileExporterInfoJson struct {
	ExporterType string `json:"exporter_type"`
}

const (
	fileExporterType                 = "file"
	fileExporterCountersDbName       = "IPFIX file exporter"
	rotatedFileTimeFormat            = "20060102150405" /* yyyyMMddHHmmss */
	compressSuffix                   = ".gz"
	fileFormatRegexStr               = `\d+\.(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})-(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).`
	fileExporterChanCapacity         = 200
	fileExporterChanLowWatermarkThr  = 40
	fileExporterChanHighWatermarkThr = 160
)

type fileExporterCmdId int

const (
	cmdWrite fileExporterCmdId = iota
	cmdRotate
	cmdTimerTick
)

func (s fileExporterCmdId) String() string {
	switch s {
	case cmdWrite:
		return "cmdWrite"
	case cmdRotate:
		return "cmdRotate"
	case cmdTimerTick:
		return "cmdTimerTick"
	}
	return "unknown"
}

type fileExporterCmd struct {
	id          fileExporterCmdId
	writeBuffer []byte
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
	p.maxInterval = params.MaxInterval
	p.compress = params.Compress
	p.maxFiles = params.MaxFiles
	p.dir = params.Dir
	p.client = client

	// If MaxSize is not provided assume no size limit
	if params.MaxSize == 0 {
		p.maxSize = math.MaxInt
	}

	// Minimum aggregation time is one second
	if p.maxInterval < time.Second && p.maxInterval != 0 {
		p.maxInterval = time.Second
	}

	p.namePrefix, p.nameExt = prefixAndExt(p.name)
	p.fileFormatRegexStr = fileFormatRegexStr

	p.fileFormatRegex = regexp.MustCompile(p.fileFormatRegexStr)

	p.timerCtx = client.Tctx.GetTimerCtx()
	p.timer.SetCB(p, 0, 0)

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
		Counter:  &p.counters.filesExported,
		Name:     "filesExported",
		Help:     "Num of exported files",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.filesExportFailed,
		Name:     "filesExportFailed",
		Help:     "Num of failed file exports",
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
		Counter:  &p.counters.evFileCreated,
		Name:     "evFileCreated",
		Help:     "Num of file created events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.evFileRemoved,
		Name:     "evFileRemoved",
		Help:     "Num of file removed events",
		Unit:     "ops",
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
		Counter:  &p.counters.cmdTimerTick,
		Name:     "cmdTimerTick",
		Help:     "Num of command channel timer tick events",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.cmdRotate,
		Name:     "cmdRotate",
		Help:     "Num of command rotate events",
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
		Counter:  &p.counters.fileRotates,
		Name:     "filesRotates",
		Help:     "Num of files rotates",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.fileRotatesFailed,
		Name:     "fileRotatesFailed",
		Help:     "Num of failed failed file rotation",
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

	return &res
}

func (p *FileExporter) Write(b []byte) (int, error) {
	if p.init == false {
		return 0, errors.New("Failed to write - file exporter object is uninitialized")
	}

	var cmd *fileExporterCmd
	cmd = new(fileExporterCmd)
	cmd.id = cmdWrite
	cmd.writeBuffer = b

	p.counters.writes++

	err := p.cmdChan.Write(cmd, false)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (p *FileExporter) Close() error {
	if p.init == false {
		return nil
	}

	return p.close()
}

func (p *FileExporter) Rotate() error {
	if p.init == false {
		return nil
	}

	var cmd *fileExporterCmd
	cmd = new(fileExporterCmd)
	cmd.id = cmdRotate

	err := p.cmdChan.Write(cmd, false)
	if err != nil {
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
		p.client.Pause(false)
	case core.EvHighWatermark:
		p.client.Pause(true)
	default:
	}
}

func (p *FileExporter) OnEvent(a, b interface{}) {
	p.timerCtx.Stop(&p.timer)

	var cmd *fileExporterCmd
	cmd = new(fileExporterCmd)
	cmd.id = cmdTimerTick

	err := p.cmdChan.Write(cmd, false)
	if err != nil {
		return
	}
}

func (p *FileExporter) cmdThread() {
	defer p.wg.Done()
	for {
		obj, err, more := p.cmdChan.Read(true)
		if err != nil || !more {
			return
		}

		cmd := obj.(*fileExporterCmd)
		switch cmd.id {
		case cmdWrite:
			p.counters.cmdWrite++
			_, err = p.writeInt(*&cmd.writeBuffer)
			if err == nil {
				p.counters.txBytes += uint64(len(*&cmd.writeBuffer))
			} else {
				p.counters.writesFailed++
			}
		case cmdTimerTick:
			p.counters.cmdTimerTick++
			expiryTime := p.creationTime.Add(p.maxInterval)
			if currentTime().After(expiryTime) {
				p.Rotate()
			}
		case cmdRotate:
			p.counters.cmdRotate++
			if err := p.rotateInt(); err != nil {
				p.counters.fileRotatesFailed++
				return
			}
		default:
		}
	}
}

func (p *FileExporter) writeInt(b []byte) (int, error) {
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

	if p.size+writeLen > p.maxSize {
		if err := p.rotateInt(); err != nil {
			return 0, err
		}
	}

	n, err = p.file.Write(b)
	p.size += n

	return n, err
}

func (p *FileExporter) rotateInt() error {
	p.counters.fileRotates++
	if err := p.fileClose(); err != nil {
		return err
	}

	if err := p.openNew(); err != nil {
		return err
	}

	return nil
}

func (p *FileExporter) fileClose() error {
	if p.timer.IsRunning() {
		p.timerCtx.Stop(&p.timer)
	}

	if p.file == nil {
		return nil
	}

	err := p.file.Close()
	p.file = nil

	if err := p.rotateExistingFile(); err != nil {
		return fmt.Errorf("Failed to rotate file: %s", err)
	}

	return err
}

func (p *FileExporter) close() error {
	p.cmdChan.Close()
	p.wg.Wait()

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

	newname := p.rotatedFileName(name)
	if err := os.Rename(name, newname); err != nil {
		return fmt.Errorf("Failed to rename file: %s", err)
	}

	if p.compress {
		if err := compressFile(newname, newname+compressSuffix); err != nil {
			return fmt.Errorf("Failed to compress rotated file: %s", err)
		}
		newname = newname + compressSuffix
	}

	p.notifyObservers(FileExporterEvent{filePath: newname, id: EvFileCreated})

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

	p.file = f
	p.size = 0
	p.creationTime = currentTime()
	p.index++

	if p.maxInterval > 0 {
		if p.timer.IsRunning() {
			p.timerCtx.Stop(&p.timer)
		}

		p.timerCtx.Start(&p.timer, p.maxInterval)
	}

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
	log.Info("notifyObservers ", event.id, event.filePath)

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
