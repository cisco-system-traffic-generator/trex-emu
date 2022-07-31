package ipfix

import (
	"bytes"
	"crypto/tls"
	"emu/core"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type HttpExporterParams struct {
	Name             string   `json:"name"`
	Url              string   `json:"url"`
	TlsCertFile      string   `json:"tls_cert_file"`
	TlsKeyFile       string   `json:"tls_key_file"`
	Dir              string   `json:"dir"`
	MaxSize          int      `json:"max_size"`
	MaxInterval      Duration `json:"max_interval"`
	Compress         bool     `json:"compress"`
	MaxFiles         int      `json:"max_files"`
	MaxPosts         uint64   `json:"max_posts"` // Max number of posts to send (0 - no limit)
	removeDirOnClose bool
}

type HttpExporterStats struct {
	writes                 uint64
	writesFailed           uint64
	txBytes                uint64
	filesExported          uint64
	filesExportFailed      uint64
	filesExportFailedRetry uint64
	filesExportRetry       uint64
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
	url                    url.URL
	tlsCertFile            string
	tlsKeyFile             string
	maxPosts               uint64
	httpRespTimeout        time.Duration
	removeDirOnClose       bool
	init                   bool
	fileExporter           *FileExporter
	fileExporterEvQueue    chan FileExporterEvent
	retryTimer             *time.Timer
	lock                   sync.Mutex
	done                   chan bool
	wg                     sync.WaitGroup
	httpClient             *http.Client
	counters               HttpExporterStats
	countersDb             *core.CCounterDb
	retryWaitState         bool
	currFileToSend         string
	currFileTempRecordsNum uint32
	currFileDataRecordsNum uint32
	currPostsNum           uint64 // Number of posts attempts made until now
	fileInfoDb             []*HttpExporterFileInfo
	currFileInfo           *HttpExporterFileInfo
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
	p.currFileInfo.Time = currentTime().Format("2006-01-02 15:04:05")
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

	p.fileExporter, err = NewFileExporter(client, fileExporterParams)
	if err != nil {
		return nil, err
	}

	p.url = *url
	p.tlsCertFile = params.TlsCertFile
	p.tlsKeyFile = params.TlsKeyFile
	p.removeDirOnClose = params.removeDirOnClose
	p.httpRespTimeout = defaultHttpRespTimeout
	p.maxPosts = params.MaxPosts
	p.counters.maxPosts = p.maxPosts

	err = p.createHttpClient()
	if err != nil {
		return nil, err
	}

	p.fileExporter.RegisterObserver(p)

	p.fileExporterEvQueue = make(chan FileExporterEvent, defaultEventsQueueMaxSize /* TBD */)
	p.done = make(chan bool)

	p.retryTimer = time.NewTimer(defaultRetryTimeout)
	p.retryTimer.Stop()

	p.wg.Add(1)
	go p.observerThread()

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
		"\n\tmax_posts - ", p.maxPosts,
		"\n\tremoveDirOnClose - ", p.removeDirOnClose)

	return p, nil
}

func (p *HttpExporter) newHttpExporterCountersDb() {
	p.countersDb = core.NewCCounterDb(httpExporterCountersDbName)

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
		Help:     "Num of files successfully exported",
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
	if p.init == false {
		return 0, fmt.Errorf("Failed to write - http exporter object is uninitialized")
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	p.counters.writes++

	n, err := p.fileExporter.Write(b, tempRecordsNum, dataRecordsNum)
	if err == nil {
		p.counters.txBytes += uint64(len(b))
	} else {
		p.counters.writesFailed++
	}

	return n, err
}

func (p *HttpExporter) Close() error {
	if p.init == false {
		return nil
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	p.retryTimer.Stop()

	p.fileExporter.UnregisterObserver(p)

	err := p.fileExporter.Close()
	if err != nil {
		return err
	}

	if p.removeDirOnClose {
		err = os.RemoveAll(p.fileExporter.GetDir())
		if err != nil {
			return err
		}
	}

	p.done <- true
	p.wg.Wait()
	close(p.done)
	close(p.fileExporterEvQueue)

	p.init = false

	return err
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

func (p *HttpExporter) observerThread() {
	defer p.wg.Done()
	for {
		switch p.retryWaitState {
		case false:
			select {
			case event := <-p.fileExporterEvQueue:
				p.handlefileExporterEv(event)
			case <-p.done:
				log.Debug("Shutting down observer thread")
				return
			}
		case true:
			select {
			case <-p.retryTimer.C:
				log.Debug("HTTP file upload retry timer expired")
				p.retryWaitState = false
				p.counters.filesExportRetry++
				err := p.sendFile(p.currFileToSend, p.currFileTempRecordsNum, p.currFileDataRecordsNum)
				if err != nil {
					log.Debug("Failed to send file, error: ", err)
				}
			case <-p.done:
				log.Debug("Shutting down observer thread")
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

func (p *HttpExporter) createHttpPostRequest(url *url.URL, filePath string) (*http.Request, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	fileContents, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	file.Close()

	filename := fi.Name()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("sendfile", filename)
	if err != nil {
		return nil, err
	}
	part.Write(fileContents)

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	r, _ := http.NewRequest("POST", url.String(), body)
	r.Header.Add(headerContType, writer.FormDataContentType())
	r.Header.Add(headerContEncoding, "gzip")
	r.Header.Add(headerExpFilename, filename)
	r.Header.Add(headerExpTimestamp, "20200116111214") // does not matter
	r.Header.Add(headerExpVersion, "1")

	return r, nil
}

func (p *HttpExporter) preSendFile(filePath string, tempRecordsNum uint32, dataRecordsNum uint32) {
	p.currFileToSend = filePath
	p.currFileTempRecordsNum = tempRecordsNum
	p.currFileDataRecordsNum = dataRecordsNum
	p.currPostsNum++
	p.beginFileInfo(filePath)
}

func (p *HttpExporter) postSendFile() {
	p.endFileInfo()
	if !p.retryWaitState {
		os.Remove(p.currFileToSend)
	}
}

func (p *HttpExporter) sendFile(filePath string, tempRecordsNum uint32, dataRecordsNum uint32) error {
	var err error

	log.Info("Trying to send file: ",
		"\n\tfile name:", filePath,
		"\n\tdestination URL:", p.url.String())

	if p.maxPosts != 0 && p.currPostsNum >= p.maxPosts {
		p.counters.maxPostsExceeded++
		os.Remove(filePath)
		return nil
	}

	p.preSendFile(filePath, tempRecordsNum, dataRecordsNum)
	defer p.postSendFile()

	req, err := p.createHttpPostRequest(&p.url, filePath)
	if err != nil {
		p.counters.filesExportFailed++
		p.counters.failedToCreateRequest++
		p.currFileInfo.TransportStatus = TrFailed
		p.currFileInfo.Status = StFailed
		return err
	}

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
		p.counters.filesExported++
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
