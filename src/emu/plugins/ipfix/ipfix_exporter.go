package ipfix

import (
	"emu/core"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/intel-go/fastjson"
)

const (
	defaultFileExporterName        = "fnf_agg.ipfix"
	defaultFileExporterMaxSize     = 1048576
	defaultFileExporterMaxInterval = 60 * time.Second
	defaultFileExporterCompress    = true
	defaultFileExporterDir         = ""
	defaultFileExporterMaxFiles    = 100
)

const (
	defaultUdpExporterUseEmuClientIpAddr = false
)

var (
	ErrExporterWrongKernelMode error = errors.New("Failed to create exporter - wrong kernel mode")
)

// Interface type for exporters
type Exporter interface {
	Write(b []byte, tempRecordsNum uint32, dataRecordsNum uint32) (n int, err error)
	Close() error
	Enable(enable bool) error
	GetMaxSize() int
	GetType() string
	GetCountersDbVec() *core.CCounterDbVec
	GetInfoJson() interface{}
	// Indicates whether the exporter relies on kernel level IO (sockets or files)
	GetKernelMode() bool
}

func CreateExporter(client *PluginIPFixClient, dstUrl *url.URL, initJson *fastjson.RawMessage) (Exporter, error) {
	if client == nil || dstUrl == nil {
		return nil, errors.New("Failed to create exporter - client or dstUrl are nil")
	}

	creator := exporterCreators[dstUrl.Scheme]
	exporter, err := creator(client, dstUrl, initJson)

	return exporter, err
}

type exporterCreatorFunc func(client *PluginIPFixClient, dstUrl *url.URL, initJson *fastjson.RawMessage) (Exporter, error)

var exporterCreators = map[string]exporterCreatorFunc{
	"emu-udp": createEmuUdpExporter,
	"udp":     createUdpExporter,
	"file":    createFileExporter,
	"http":    createHttpExporter,
	"https":   createHttpExporter}

func createEmuUdpExporter(client *PluginIPFixClient, dstUrl *url.URL, initJson *fastjson.RawMessage) (Exporter, error) {
	if dstUrl.Scheme != "emu-udp" {
		return nil, errors.New("Invalid dst URL scheme used to create file exporter (should be emu-udp)")
	}

	emuUdpExporter, err := NewEmuUdpExporter(dstUrl.Host, client.Client, client)
	if err != nil {
		return nil, err
	}

	return emuUdpExporter, nil
}

func createUdpExporter(client *PluginIPFixClient, dstUrl *url.URL, initJson *fastjson.RawMessage) (Exporter, error) {
	if dstUrl.Scheme != "udp" {
		return nil, errors.New("Invalid dst URL scheme used to create file exporter (should be udp)")
	}

	params := &UdpExporterParams{
		UseEmuClientIpAddr: defaultUdpExporterUseEmuClientIpAddr,
		hostport:           dstUrl.Host,
	}

	if initJson != nil {
		err := client.Tctx.UnmarshalValidate(*initJson, params)
		if err != nil {
			return nil, err
		}
	}

	udpExporter, err := NewUdpExporter(client, params)
	if err != nil {
		return nil, err
	}

	return udpExporter, nil
}

func createFileExporter(client *PluginIPFixClient, dstUrl *url.URL, initJson *fastjson.RawMessage) (Exporter, error) {
	if dstUrl.Scheme != "file" {
		return nil, errors.New("Invalid dst URL scheme used to create file exporter (should be file)")
	}

	params := &FileExporterParams{
		Name:        defaultFileExporterName,
		Dir:         defaultFileExporterDir,
		MaxSize:     defaultFileExporterMaxSize,
		MaxInterval: Duration{Duration: defaultFileExporterMaxInterval},
		MaxFiles:    defaultFileExporterMaxFiles,
		Compress:    defaultFileExporterCompress,
	}

	if len(dstUrl.Path) > 0 {
		params.Name = filepath.Base(dstUrl.Path)
		params.Dir = filepath.Dir(dstUrl.Path)
	}

	if initJson != nil {
		err := client.Tctx.UnmarshalValidate(*initJson, params)
		if err != nil {
			return nil, err
		}
	}

	// Create unique directory per EMU client in the user's dir
	params.Dir = getClientDirExporterName(params.Dir, params.Name, client.Client)

	fileExporter, err := NewFileExporter(client, params)
	if err != nil {
		return nil, err
	}

	return fileExporter, nil
}

func createHttpExporter(client *PluginIPFixClient, dstUrl *url.URL, initJson *fastjson.RawMessage) (Exporter, error) {
	if dstUrl.Scheme != "http" && dstUrl.Scheme != "https" {
		return nil, errors.New("Invalid dst URL scheme used to create HTTP/HTTPS exporter (should be http or https)")
	}

	params := &HttpExporterParams{
		Name:        defaultFileExporterName,
		Dir:         defaultFileExporterDir,
		MaxSize:     defaultFileExporterMaxSize,
		MaxInterval: Duration{Duration: defaultFileExporterMaxInterval},
		MaxFiles:    defaultFileExporterMaxFiles,
		Compress:    defaultFileExporterCompress,
	}

	params.Url = dstUrl.String()

	if initJson != nil {
		err := client.Tctx.UnmarshalValidate(*initJson, params)
		if err != nil {
			return nil, err
		}
	}

	// Create unique directory per EMU client in the user given dir
	params.Dir = getClientDirExporterName(params.Dir, params.Name, client.Client)

	fileExporter, err := NewHttpExporter(client, params)
	if err != nil {
		return nil, err
	}

	return fileExporter, nil
}

func getClientDirExporterName(dir string, name string, client *core.CClient) string {
	pid := ""
	if dir == "" {
		dir = os.TempDir()
		pid = fmt.Sprintf("%s_", strconv.Itoa(os.Getpid()))
	}

	strippedMac := strings.ReplaceAll(client.Mac.String(), ":", "")
	filename := filepath.Base(name)
	ext := filepath.Ext(filename)
	prefix := filename[:len(filename)-len(ext)]
	var dirname string
	if ext == "." {
		dirname = fmt.Sprintf("%s_%s%s", prefix, pid, strippedMac)
	} else {
		dirname = fmt.Sprintf("%s_%s%s%s", prefix, pid, strippedMac, ext)
	}

	res := fmt.Sprintf("%s/%s", dir, dirname)

	return res
}
