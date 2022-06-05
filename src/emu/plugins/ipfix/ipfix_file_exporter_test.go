package ipfix

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const (
	dirTimeFormat    = "2006010215040500" /* yyyyMMddHHmmss */
	testExporterName = "fnf_agg.ipfix"
)

var fakeCurrentTime = time.Now()

func fakeTime() time.Time {
	return fakeCurrentTime
}

func incFakeTime(duration time.Duration) {
	fakeCurrentTime = fakeCurrentTime.Add(duration)
}

func TestIPFixFileExporterBasicTestUtils(t *testing.T) {
	dir := makeTempDir("TestIPFixFileExporterBasicTestUtils", t)
	defer os.RemoveAll(dir)

	assertPathExists(dir, t)
	assertPathNotExist(dir+"_", t)

	for i := 1; i <= 100; i++ {
		name := rotatedExportFileName(dir, time.Minute)
		size := rand.Intn(1000)
		content := createFileWithRandomContent(name, size, t)
		assertFileExistsWithContent(name, content, t)
		incFakeTime(time.Minute)
	}

	assertDirFileCount(dir, 100, t)
}

func TestIPFixFileExporterCompressFileUtil(t *testing.T) {
	dir := makeTempDir("TestIPFixFileExporterCompressFileUtil", t)
	defer os.RemoveAll(dir)

	assertPathExists(dir, t)

	for i := 1; i <= 100; i++ {
		name := rotatedExportFileName(dir, time.Minute)
		size := rand.Intn(1000)
		content := createFileWithRandomContent(name, size, t)
		assertFileExistsWithContent(name, content, t)
		err := compressFile(name, name+".gz")
		assertNil(err, t)
		incFakeTime(time.Minute)
	}

	assertDirFileCount(dir, 100, t)
}

//func TestIPFixFileExporterBasic(t *testing.T) {
//	currentTime = time.Now
//
//	dir := os.TempDir() + "/TestIPFixFileExporterBasic"
//	defer os.RemoveAll(dir)
//
//	exporter, err := NewFileExporter(nil, &FileExporterParams{
//		Name:        "testfile.ext",
//		MaxSize:     10,
//		MaxInterval: time.Second,
//		Dir:         dir,
//	})
//
//	assertNil(err, t)
//
//	defer exporter.Close()
//
//	for i := 1; i <= 10; i++ {
//		b := createRandomByteBuffer(5)
//		n, err := exporter.Write(b)
//		assertNil(err, t)
//		assert(n == len(b), t, "wrong len")
//		//time.Sleep(10 * time.Second)
//	}
//
//	exporter.close()
//
//	assertDirFileCount(dir, 5, t)
//}

func exportFileName(dir string) string {
	return filepath.Join(dir, testExporterName)
}

func rotatedExportFileName(dir string, duration time.Duration) string {
	filename := filepath.Base(testExporterName)
	ext := filepath.Ext(filename)
	prefix := filename[:len(filename)-len(ext)]
	basename := fmt.Sprintf("%s.%s-%s%s", prefix, fakeTime().Format(rotatedFileTimeFormat),
		fakeTime().Add(duration).Format(rotatedFileTimeFormat), ext)
	return filepath.Join(dir, basename)
}

func makeTempDir(name string, t testing.TB) string {
	dir := time.Now().Format(name + "_" + dirTimeFormat)
	dir = filepath.Join(os.TempDir(), dir)
	assertNil(os.Mkdir(dir, 0700), t)
	return dir
}

func createRandomByteBuffer(size int) []byte {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, size)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}

	return b
}

func createFileWithRandomContent(path string, size int, t testing.TB) []byte {
	b := createRandomByteBuffer(size)
	assert((len(b) == size), t, "xxx")
	err := os.WriteFile(path, b, 0644)
	assertNil(err, t)
	return b
}

func assertDirFileCount(dir string, exp int, t testing.TB) {
	files, err := ioutil.ReadDir(dir)
	assertNil(err, t)
	assertEquals(exp, len(files), t)
}

func assertFileExistsWithContent(path string, content []byte, t testing.TB) {
	info, err := os.Stat(path)
	assertNil(err, t)
	assertEquals(int64(len(content)), info.Size(), t)

	b, err := ioutil.ReadFile(path)
	assertNil(err, t)
	assertEquals(content, b, t)
}

func assertPathNotExist(path string, t testing.TB) {
	_, err := os.Stat(path)
	if !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("assertPathNotExist failed for file ['%v'], got error - %v\n", path, err)
		t.FailNow()
	}
}

func assertPathExists(path string, t testing.TB) {
	_, err := os.Stat(path)
	if err != nil {
		fmt.Printf("assertPathExists failed for file ['%v'], got error - %v\n", path, err)
		t.FailNow()
	}
}

func assert(condition bool, t testing.TB, msg string, v ...interface{}) {
	if !condition {
		fmt.Printf("assert failed: "+msg+"\n", v...)
		t.FailNow()
	}
}

func assertEquals(exp, act interface{}, t testing.TB) {
	if !reflect.DeepEqual(exp, act) {
		fmt.Printf("assertEquals failed: exp: %v (%T), got: %v (%T)\n", exp, exp, act, act)
		t.FailNow()
	}
}

func assertNil(obtained interface{}, t testing.TB) {
	if !_isNil(obtained) {
		fmt.Printf("assertNil failed: expected nil, got: %v\n", obtained)
		t.FailNow()
	}
}

func assertNotNil(obtained interface{}, t testing.TB) {
	if _isNil(obtained) {
		fmt.Printf("assertNotNil: expected non-nil, got: %v\n", obtained)
		t.FailNow()
	}
}

func _isNil(obtained interface{}) bool {
	if obtained == nil {
		return true
	}

	switch v := reflect.ValueOf(obtained); v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}

	return false
}
