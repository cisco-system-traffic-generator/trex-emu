package ipfix

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"github.com/op/go-logging"
)

var (
	// We define currentTime so it can be mocked out by tests.
	currentTime = time.Now
	// Logger used by IPFix package
	log = logging.MustGetLogger("IPFix")
)

func configureLogger(verbose bool) {
	var format = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000000} %{shortfunc} %{level:s} %{id:03x}%{color:reset} ▶ %{message}`,
	)

	backend := logging.NewLogBackend(os.Stderr, "[IPFIX] ", 0)
	backendformatter := logging.NewBackendFormatter(backend, format)
	backendLeveled := logging.AddModuleLevel(backendformatter)

	if verbose {
		backendLeveled.SetLevel(logging.DEBUG, "")
	} else {
		backendLeveled.SetLevel(logging.WARNING, "")
	}

	log.SetBackend(backendLeveled)
}

func compressFile(src_file_path, dst_file_path string) (err error) {
	f, err := os.Open(src_file_path)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	defer f.Close()

	file_info, err := os.Stat(src_file_path)
	if err != nil {
		return fmt.Errorf("failed to stat log file: %v", err)
	}
	stat := file_info.Sys().(*syscall.Stat_t)

	gzf, err := os.OpenFile(dst_file_path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file_info.Mode())
	if err != nil {
		return fmt.Errorf("failed to open compressed log file: %v", err)
	}
	defer gzf.Close()

	os.Chown(dst_file_path, int(stat.Uid), int(stat.Gid))
	if err != nil {
		return fmt.Errorf("failed to chown compressed log file: %v", err)
	}

	gz, _ := gzip.NewWriterLevel(gzf, gzip.BestSpeed)

	defer func() {
		if err != nil {
			os.Remove(dst_file_path)
			err = fmt.Errorf("failed to compress log file: %v", err)
		}
	}()

	if _, err := io.Copy(gz, f); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := gzf.Close(); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(src_file_path); err != nil {
		return err
	}

	return nil
}

func prefixAndExt(name string) (prefix, ext string) {
	filename := filepath.Base(name)
	ext = filepath.Ext(filename)
	prefix = filename[:len(filename)-len(ext)]
	return prefix, ext
}

func getFileSize(filePath string) (int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}

	fi, err := file.Stat()
	if err != nil {
		return 0, err
	}

	file.Close()

	return fi.Size(), nil
}

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}

type Duration struct {
	time.Duration
}

func (duration *Duration) UnmarshalJSON(b []byte) error {
	var unmarshalledJson interface{}

	err := json.Unmarshal(b, &unmarshalledJson)
	if err != nil {
		return err
	}

	switch value := unmarshalledJson.(type) {
	case float64:
		duration.Duration = time.Duration(value)
	case string:
		duration.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid duration: %#v", unmarshalledJson)
	}

	return nil
}
