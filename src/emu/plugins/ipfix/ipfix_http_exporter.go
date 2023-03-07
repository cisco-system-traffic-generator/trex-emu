package ipfix

import (
	"bytes"
	"context"
	"crypto/tls"
	"emu/core"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type HttpExporterParams struct {
	Name                     string   `json:"name"`
	Url                      string   `json:"url"`
	Dir                      string   `json:"dir"`
	MaxSize                  int      `json:"max_size"`
	MaxInterval              Duration `json:"max_interval"`
	MaxFiles                 int      `json:"max_files"`
	MaxPosts                 uint64   `json:"max_posts"` // Max number of posts to send (0 - no limit)
	Compress                 bool     `json:"compress"`
	TlsCertFile              string   `json:"tls_cert_file"`
	TlsKeyFile               string   `json:"tls_key_file"`
	StoreExportedFilesOnDisk bool     `json:"store_exported_files_on_disk"`
	InputChanCapacity        uint     `json:"input_channel_capacity"`
}

type HttpExporterStats struct {
	apiWrites              uint64
	apiWritesFailed        uint64
	txTempRecords          uint64 // Total number of template records sent
	txDataRecords          uint64 // Total number of data records sent
	filesExport            uint64
	filesExportFailed      uint64
	filesExportFailedRetry uint64
	filesExportRetry       uint64
	filesExportEmpty       uint64 // Num of empty export files (records num is zero)
	failedToCreateRequest  uint64
	failedToSendRequest    uint64
	httpStatus2xx          uint64
	httpStatus3xx          uint64
	httpStatus4xx          uint64
	httpStatus5xx          uint64
	bytesUploaded          uint64 // Total number of bytes uploaded successfully
	tempRecordsUploaded    uint64 // Total number of template records uploaded successfully
	dataRecordsUploaded    uint64 // Total number of data records uploaded successfully
	maxPosts               uint64 // Max number of posts to send (0 - no limit)
	maxPostsExceeded       uint64 // Number of times post was blocked since maxPosts limit reached
}

type HttpExporter struct {
	url                      url.URL
	tlsCertFile              string
	tlsKeyFile               string
	maxPosts                 uint64
	httpRespTimeout          time.Duration
	removeDirOnClose         bool
	storeExportedFilesOnDisk bool
	inputChanCapacity        uint
	enabled                  bool
	init                     bool
	fileExporter             *FileExporter
	fileExporterEvQueue      chan FileExporterEvent
	retryTimer               *time.Timer
	done                     chan bool
	wg                       sync.WaitGroup
	httpClient               *http.Client
	counters                 HttpExporterStats
	countersDb               *core.CCounterDb
	retryWaitState           bool
	currFileToSend           string
	currFileTempRecordsNum   uint32
	currFileDataRecordsNum   uint32
	currPostsNum             uint64 // Number of posts attempts made until now
	fileInfoDb               []*HttpExporterFileInfo
	currFileInfo             *HttpExporterFileInfo
	currCancelFunc           context.CancelFunc
	client                   *PluginIPFixClient
}

type HttpExporterFileInfo struct {
	Name                string                      `json:"name"`
	Time                string                      `json:"time"`
	Status              HttpExporterFileSendStatus  `json:"status"`
	HttpStatus          string                      `json:"http_status_code"`
	HttpResponseMsg     string                      `json:"http_response_msg"`
	TransportStatus     HttpExporterTransportStatus `json:"transport_status"`
	BytesUploaded       int64                       `json:"bytes_uploaded"`
	TempRecordsUploaded uint32                      `json:"temp_records_uploaded"`
	DataRecordsUploaded uint32                      `json:"data_records_uploaded"`
}

func (p *HttpExporter) beginFileInfo(filePath string) {
	p.currFileInfo = new(HttpExporterFileInfo)
	p.currFileInfo.Name = filepath.Base(filePath)
	p.currFileInfo.Time = currentTime().Format("2006-01-02 15:04:05.000")
	p.currFileInfo.Status = StInProgress
}

func (p *HttpExporter) endFileInfo() {
	if p.currFileInfo.HttpStatus == "" {
		p.currFileInfo.HttpStatus = "n/a"
	}

	if p.currFileInfo.HttpResponseMsg == "" {
		p.currFileInfo.HttpResponseMsg = "n/a"
	}

	p.fileInfoDb = append(p.fileInfoDb, p.currFileInfo)
	p.currFileInfo = nil
	if len(p.fileInfoDb) > FileInfoDbMaxNum {
		p.fileInfoDb = p.fileInfoDb[1:]
	}
}

type HttpExporterInfo struct {
	ExporterType string                 `json:"exporter_type"`
	Enabled      string                 `json:"enabled"`
	Files        []HttpExporterFileInfo `json:"files"`
}

type HttpExporterFileSendStatus string

const (
	StInProgress HttpExporterFileSendStatus = "inProgress"
	StSuccess    HttpExporterFileSendStatus = "success"
	StFailed     HttpExporterFileSendStatus = "failed"
)

type HttpExporterTransportStatus string

const (
	TrSuccess HttpExporterTransportStatus = "success"
	TrFailed  HttpExporterTransportStatus = "failed"
)

const (
	httpExporterType           = "http"
	httpExporterCountersDbName = "IPFIX http exporter"
	defaultEventsQueueMaxSize  = 128
	defaultHttpClientTimeout   = 180 * time.Second
	defaultHttpRespTimeout     = 0
	defaultRetryTimeout        = 60 * time.Second
	FileInfoDbMaxNum           = 30

	headerContType     = "Content-Type"
	headerContEncoding = "content-encoding"
	headerExpFilename  = "x-exporter-filename"
	headerExpTimestamp = "x-exporter-timestamp"
	headerExpVersion   = "x-exporter-version"

	// Dst URL specifiers: a specifier in DST URL init JSON will be replaced with its corresponding
	// Id (example: device-%d --> device-76)
	dstUrlTenantIdSpecifier   = "%t"
	dstUrlSiteIdSpecifier     = "%s"
	dstUrlDeviceIdSpecifier   = "%d"
	dstUrlDeviceUuidSpecifier = "%u"
)

func NewHttpExporter(client *PluginIPFixClient, params *HttpExporterParams) (*HttpExporter, error) {
	if params.Url == "" || params.Name == "" || params.Dir == "" {
		return nil, fmt.Errorf("Failed to create exporter, invalid parameters %s %s", params.Name, params.Url)
	}

	var err error
	var url *url.URL

	if url, err = url.Parse(params.Url); err != nil {
		return nil, err
	}

	p := new(HttpExporter)
	p.client = client

	kernelMode := client.Tctx.GetKernelMode()
	if kernelMode != p.GetKernelMode() {
		return nil, ErrExporterWrongKernelMode
	}

	p.newHttpExporterCountersDb()

	fileExporterParams := new(FileExporterParams)
	fileExporterParams.Name = params.Name
	fileExporterParams.MaxSize = params.MaxSize
	fileExporterParams.MaxInterval = params.MaxInterval
	fileExporterParams.Compress = params.Compress
	fileExporterParams.Dir = params.Dir
	fileExporterParams.MaxFiles = params.MaxFiles
	fileExporterParams.InputChanCapacity = params.InputChanCapacity

	p.fileExporter, err = NewFileExporter(client, fileExporterParams)
	if err != nil {
		return nil, err
	}

	p.url = *url
	p.tlsCertFile = params.TlsCertFile
	p.tlsKeyFile = params.TlsKeyFile
	p.storeExportedFilesOnDisk = params.StoreExportedFilesOnDisk
	p.httpRespTimeout = defaultHttpRespTimeout
	p.maxPosts = params.MaxPosts
	p.counters.maxPosts = p.maxPosts

	err = p.createHttpClient()
	if err != nil {
		return nil, err
	}

	p.fileExporter.RegisterObserver(p)

	p.fileExporterEvQueue = make(chan FileExporterEvent, defaultEventsQueueMaxSize)
	p.done = make(chan bool)

	p.retryTimer = time.NewTimer(defaultRetryTimeout)
	p.retryTimer.Stop()

	p.wg.Add(1)
	go p.cmdThread()
	p.enabled = true
	p.init = true

	log.Info("\nIPFIX HTTP exporter created with the following parameters: ",
		"\n\tname - ", p.fileExporter.GetName(),
		"\n\turl - ", p.url,
		"\n\ttlsCertFile - ", p.tlsCertFile,
		"\n\ttlsKeyFile - ", p.tlsKeyFile,
		"\n\tdir - ", p.fileExporter.GetDir(),
		"\n\tmaxSize - ", p.fileExporter.GetMaxSize(),
		"\n\tmaxInterval - ", p.fileExporter.GetMaxInterval(),
		"\n\tcompress - ", p.fileExporter.GetCompress(),
		"\n\tmaxFiles - ", p.fileExporter.GetMaxFiles(),
		"\n\tinputChanCapacity - ", p.fileExporter.GetInputChanCapacity(),
		"\n\tmaxPosts - ", p.maxPosts,
		"\n\tstoreExportedFilesOnDisk - ", p.storeExportedFilesOnDisk)

	return p, nil
}

func (p *HttpExporter) newHttpExporterCountersDb() {
	p.countersDb = core.NewCCounterDb(httpExporterCountersDbName)

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
		Counter:  &p.counters.txTempRecords,
		Name:     "txTempRecords",
		Help:     "Total num of template records transmitted",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.txDataRecords,
		Name:     "txDataRecords",
		Help:     "Total num of data records transmitted",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.filesExport,
		Name:     "filesExport",
		Help:     "Num of files export",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.filesExportFailed,
		Name:     "filesExportFailed",
		Help:     "Num of failed files export",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.filesExportFailedRetry,
		Name:     "filesExportFailedRetry",
		Help:     "Num of failed files export - need to retry",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.filesExportRetry,
		Name:     "filesExportRetry",
		Help:     "Num of file send retries",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.filesExportEmpty,
		Name:     "filesExportEmpty",
		Help:     "Num of empty export files",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.failedToCreateRequest,
		Name:     "failedToCreateRequest",
		Help:     "Num of failures to create http request",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.failedToSendRequest,
		Name:     "failedToSendRequest",
		Help:     "Num of failures to send http request",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.httpStatus2xx,
		Name:     "httpStatus2xx",
		Help:     "Num of HTTP 2xx status code responses",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.httpStatus3xx,
		Name:     "httpStatus3xx",
		Help:     "Num of HTTP 3xx status code responses",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.httpStatus4xx,
		Name:     "httpStatus4xx",
		Help:     "Num of HTTP 4xx status code responses",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.httpStatus5xx,
		Name:     "httpStatus5xx",
		Help:     "Num of HTTP 5xx status code responses",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.bytesUploaded,
		Name:     "bytesUploaded",
		Help:     "Total num of bytes uploaded successfully",
		Unit:     "bytes",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.tempRecordsUploaded,
		Name:     "tempRecordsUploaded",
		Help:     "Total num of template records uploaded successfully",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.dataRecordsUploaded,
		Name:     "dataRecordsUploaded",
		Help:     "Total num of data records uploaded successfully",
		Unit:     "records",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.maxPosts,
		Name:     "maxPosts",
		Help:     "Max num of HTTP posts (0 - no limit)",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})

	p.countersDb.Add(&core.CCounterRec{
		Counter:  &p.counters.maxPostsExceeded,
		Name:     "maxPostsExceeded",
		Help:     "Num of max posts exceeded",
		Unit:     "ops",
		DumpZero: false,
		Info:     core.ScINFO})
}

func (p *HttpExporter) GetName() string {
	return p.fileExporter.GetName()
}

func (p *HttpExporter) GetMaxSize() int {
	return p.fileExporter.GetMaxSize()
}

func (p *HttpExporter) GetType() string {
	return httpExporterType
}

func (p *HttpExporter) GetCountersDbVec() *core.CCounterDbVec {
	db := core.NewCCounterDbVec(httpExporterCountersDbName)
	db.Add(p.countersDb)
	db.AddVec(p.fileExporter.GetCountersDbVec())
	return db
}

func (p *HttpExporter) GetKernelMode() bool {
	return true
}

func (p *HttpExporter) GetInfoJson() interface{} {
	var res HttpExporterInfo

	res.ExporterType = p.GetType()
	res.Enabled = strconv.FormatBool(p.enabled)

	res.Files = make([]HttpExporterFileInfo, len(p.fileInfoDb))

	for i, fileInfo := range p.fileInfoDb {
		if fileInfo == nil {
			continue
		}

		res.Files[i] = *fileInfo
	}

	return &res
}

func (p *HttpExporter) Write(b []byte, tempRecordsNum uint32, dataRecordsNum uint32) (int, error) {
	if !p.init {
		return 0, fmt.Errorf("Failed to write - http exporter object is uninitialized")
	}

	if !p.enabled {
		return 0, nil
	}

	p.counters.apiWrites++

	n, err := p.fileExporter.Write(b, tempRecordsNum, dataRecordsNum)
	if err != nil {
		p.counters.apiWritesFailed++
	}

	return n, err
}

func (p *HttpExporter) Close() error {
	if !p.init {
		return nil
	}

	p.init = false

	p.retryTimer.Stop()

	p.fileExporter.UnregisterObserver(p)

	err := p.fileExporter.Close()
	if err != nil {
		return err
	}

	if !p.storeExportedFilesOnDisk {
		err = os.RemoveAll(p.fileExporter.GetDir())
		if err != nil {
			return err
		}
	}

	if p.currCancelFunc != nil {
		p.currCancelFunc()
	}

	p.done <- true
	p.wg.Wait()
	close(p.done)
	close(p.fileExporterEvQueue)

	return err
}

func (p *HttpExporter) Enable(enable bool) error {
	p.enabled = enable
	p.fileExporter.Enable(enable)

	if enable {
		log.Debug("HTTP exporter - enabled")
	} else {
		log.Debug("HTTP exporter - disabled")
	}
	return nil
}

func (p *HttpExporter) notify(event FileExporterEvent) {
	select {
	case p.fileExporterEvQueue <- event:
		/* Sent event */
	default:
		log.Debug("No event sent, queue is full")
		/* No event sent, queue is full */
	}
}

func (p *HttpExporter) handlefileExporterEv(event FileExporterEvent) {
	switch event.id {
	case EvFileCreated:
		log.Debug("Got fileCreated event - \n", event)
		err := p.sendFile(event.filePath, event.tempRecordsNum, event.dataRecordsNum)
		if err != nil {
			log.Debug("Failed to send file, error: ", err)
		}
	case EvFileRemoved:
		log.Debug("Got fileRemoved event - \n", event)
		/* not supported */
	default:
	}
}

func (p *HttpExporter) cmdThread() {
	defer p.wg.Done()
	for {
		switch p.retryWaitState {
		case false:
			select {
			case event := <-p.fileExporterEvQueue:
				if !p.init {
					break
				}

				p.handlefileExporterEv(event)
			case <-p.done:
				log.Debug("Shutting down HTTP exporter commands thread")
				return
			}
		case true:
			select {
			case <-p.retryTimer.C:
				if !p.init {
					break
				}

				log.Debug("HTTP file upload retry timer expired")
				p.retryWaitState = false
				p.counters.filesExportRetry++
				err := p.sendFile(p.currFileToSend, p.currFileTempRecordsNum, p.currFileDataRecordsNum)
				if err != nil {
					log.Debug("Failed to send file, error: ", err)
				}
			case <-p.done:
				log.Debug("Shutting down HTTP exporter commands thread")
				return
			}
		}
	}
}

func (p *HttpExporter) startRetryTimer() {
	p.retryTimer = time.NewTimer(defaultRetryTimeout)
	p.retryTimer.Stop()
}

func (p *HttpExporter) createHttpClient() error {
	var err error
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if p.tlsCertFile != "" && p.tlsKeyFile != "" {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(p.tlsCertFile, p.tlsKeyFile)
		if err != nil {
			return err
		}
		httpTransport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	if p.httpRespTimeout != 0 {
		httpTransport.ResponseHeaderTimeout = p.httpRespTimeout
	}

	p.httpClient = &http.Client{Transport: httpTransport, Timeout: defaultHttpClientTimeout}

	return err
}

func (p *HttpExporter) createHttpPostRequest(url *url.URL, filePath string) (*http.Request, context.CancelFunc, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	fileContents, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	fi, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	file.Close()

	filename := fi.Name()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("sendfile", filename)
	if err != nil {
		return nil, nil, err
	}
	part.Write(fileContents)

	err = writer.Close()
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	r, err := http.NewRequestWithContext(ctx, "POST", url.String(), body)
	if err != nil {
		return nil, nil, err
	}
	r.Header.Add(headerContType, writer.FormDataContentType())
	if p.fileExporter.GetCompress() {
		r.Header.Add(headerContEncoding, "gzip")
	}
	r.Header.Add(headerExpFilename, filename)
	r.Header.Add(headerExpTimestamp, "20200116111214") // does not matter
	r.Header.Add(headerExpVersion, "1")

	return r, cancel, nil
}

func (p *HttpExporter) preSendFile(filePath string, tempRecordsNum uint32, dataRecordsNum uint32) {
	p.currFileToSend = filePath
	p.currFileTempRecordsNum = tempRecordsNum
	p.currFileDataRecordsNum = dataRecordsNum
	p.currCancelFunc = nil
	p.currPostsNum++
	p.beginFileInfo(filePath)
}

func (p *HttpExporter) postSendFile() {
	p.endFileInfo()
	if !p.retryWaitState && !p.storeExportedFilesOnDisk {
		os.Remove(p.currFileToSend)
	}
}

func (p *HttpExporter) sendFile(filePath string, tempRecordsNum uint32, dataRecordsNum uint32) error {
	var err error

	log.Info("Trying to send file: ",
		"\n\tfile name:", filePath,
		"\n\ttemp records num:", tempRecordsNum,
		"\n\tdata records num:", dataRecordsNum,
		"\n\tdestination URL:", p.url.String())

	if tempRecordsNum == 0 && dataRecordsNum == 0 {
		p.counters.filesExportEmpty++
	}

	if p.maxPosts != 0 && p.currPostsNum >= p.maxPosts {
		logMsg := fmt.Sprintf("Current num of posts (%v) exceeded the configured max posts (%v) - avoid sending file",
			p.currPostsNum, p.maxPosts)
		log.Info(logMsg)
		p.counters.maxPostsExceeded++
		os.Remove(filePath)

		// We reached the configured maximum number of posts - disable exporter
		p.Enable(false)
		return nil
	}

	p.preSendFile(filePath, tempRecordsNum, dataRecordsNum)
	defer p.postSendFile()

	p.counters.filesExport++
	p.counters.txTempRecords += uint64(tempRecordsNum)
	p.counters.txDataRecords += uint64(dataRecordsNum)

	req, cancel, err := p.createHttpPostRequest(&p.url, filePath)
	if err != nil {
		p.counters.filesExportFailed++
		p.counters.failedToCreateRequest++
		p.currFileInfo.TransportStatus = TrFailed
		p.currFileInfo.Status = StFailed
		return err
	}

	p.currCancelFunc = cancel

	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.counters.filesExportFailed++
		p.counters.failedToSendRequest++
		p.currFileInfo.TransportStatus = TrFailed
		p.currFileInfo.Status = StFailed
		return err
	}

	p.currFileInfo.TransportStatus = TrSuccess

	body, _ := ioutil.ReadAll(resp.Body)
	log.Info("Received HTTP response status:", resp.Status, ", response message:", string(body))

	switch resp.StatusCode / 100 {
	case 2 /* 2xx */ :
		p.counters.httpStatus2xx++
	case 3 /* 3xx */ :
		p.counters.filesExportFailed++
		p.counters.httpStatus3xx++
	case 4 /* 4xx */ :
		p.counters.filesExportFailed++
		p.counters.httpStatus4xx++
	case 5 /* 5xx */ :
		p.counters.filesExportFailed++
		p.counters.httpStatus5xx++
		p.counters.filesExportFailedRetry++

		p.retryWaitState = true
		p.retryTimer = time.NewTimer(defaultRetryTimeout)
	default:
		p.counters.filesExportFailed++
	}

	if resp.StatusCode/100 == 2 {
		p.currFileInfo.Status = StSuccess
	} else {
		p.currFileInfo.Status = StFailed
	}
	p.currFileInfo.HttpResponseMsg = string(body)
	p.currFileInfo.HttpStatus = resp.Status
	if p.currFileInfo.Status == StSuccess {
		p.currFileInfo.BytesUploaded, _ = getFileSize(p.currFileToSend)
		p.counters.bytesUploaded += uint64(p.currFileInfo.BytesUploaded)

		p.currFileInfo.TempRecordsUploaded = p.currFileTempRecordsNum
		p.counters.tempRecordsUploaded += uint64(p.currFileTempRecordsNum)

		p.currFileInfo.DataRecordsUploaded = p.currFileDataRecordsNum
		p.counters.dataRecordsUploaded += uint64(p.currFileDataRecordsNum)
	}

	return nil
}
