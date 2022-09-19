package core

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path"
	"strconv"
	"time"
)

type ResourceUsage struct {
	ElapsedTime time.Duration
	CpuTicks    int64
	Rss         int64
	updateTime  time.Time
}

func (p *ResourceUsage) GetCpuPercent() float64 {
	if p.ElapsedTime == 0 {
		return 0
	}

	cpu := (100 * (cpuTicksToNanoseconds(p.CpuTicks) / float64(p.ElapsedTime.Nanoseconds())))

	return cpu
}

func (p *ResourceUsage) String() string {
	return fmt.Sprintf("ElapsedTime = %v; CpuPercent = %v; Rss = %v", p.ElapsedTime, p.GetCpuPercent(), p.Rss)
}

type ResourceMonitorCounters struct {
	elapsedTimeMs int64
	cpuPercent    int64
	rss           int64
}

type ResourceMonitor struct {
	prevUsage     *ResourceUsage
	diffUsage     *ResourceUsage
	procStatPath  string
	countersDb    *CCounterDb
	countersDbVec *CCounterDbVec
	counters      ResourceMonitorCounters
	isInit        bool
}

func (p *ResourceMonitor) Init() error {
	p.procStatPath = path.Join("/proc", strconv.Itoa(os.Getpid()), "stat")
	usage, err := p.readStat()
	if err != nil {
		return err
	}

	p.prevUsage = usage
	p.diffUsage = &ResourceUsage{
		updateTime:  usage.updateTime,
		ElapsedTime: 0,
		CpuTicks:    0,
		Rss:         usage.Rss}

	p.newCountersDb()

	p.isInit = true

	return nil
}

func (p *ResourceMonitor) GetCountersDbVec() *CCounterDbVec {
	return p.countersDbVec
}

func (p *ResourceMonitor) Update(reset bool) error {
	if !p.isInit {
		return errors.New("resource monitor uninitialized")
	}

	usage, err := p.readStat()
	if err != nil {
		return err
	}

	if reset {
		p.prevUsage = usage
	}

	p.diffUsage = &ResourceUsage{
		updateTime:  usage.updateTime,
		ElapsedTime: usage.updateTime.Sub(p.prevUsage.updateTime),
		CpuTicks:    usage.CpuTicks - p.prevUsage.CpuTicks,
		Rss:         usage.Rss}

	p.counters.elapsedTimeMs = p.diffUsage.ElapsedTime.Milliseconds()
	p.counters.cpuPercent = int64(p.diffUsage.GetCpuPercent())
	p.counters.rss = p.diffUsage.Rss

	return nil
}

func (p *ResourceMonitor) GetResourceUsage() (*ResourceUsage, error) {
	if !p.isInit {
		return nil, errors.New("resource monitor uninitialized")
	}

	return p.diffUsage, nil
}

func (p *ResourceMonitor) newCountersDb() {
	p.countersDbVec = NewCCounterDbVec("Resource monitor")
	p.countersDb = NewCCounterDb("Resource monitor")
	p.countersDb.Add(&CCounterRec{
		Counter:  &p.counters.elapsedTimeMs,
		Name:     "elapsedTimeMs",
		Help:     "Elapsed time since reset",
		Unit:     "milliseconds",
		DumpZero: false,
		Info:     ScINFO})
	p.countersDb.Add(&CCounterRec{
		Counter:  &p.counters.cpuPercent,
		Name:     "cpuPercent",
		Help:     "CPU utilization since reset",
		Unit:     "percent",
		DumpZero: true,
		Info:     ScINFO})
	p.countersDb.Add(&CCounterRec{
		Counter:  &p.counters.rss,
		Name:     "rss",
		Help:     "RSS memory consumption",
		Unit:     "bytes",
		DumpZero: false,
		Info:     ScINFO})
	p.countersDbVec.Add(p.countersDb)
}

var (
	sepSpace = []byte{' '}
	pageSize = int64(os.Getpagesize())
)

func cpuTicksToNanoseconds(ticks int64) float64 {
	// const ticksInSec = 100 // Linux constant
	return float64(ticks) * math.Pow(10, 7)
}

func parseInt(b string) (int64, error) {
	return strconv.ParseInt(string(b), 10, 64)
}

func parseIntBytes(b []byte) (int64, error) {
	return parseInt(string(b))
}

func (p *ResourceMonitor) readStat() (*ResourceUsage, error) {
	procStatFileBytes, err := ioutil.ReadFile(p.procStatPath)
	if err != nil {
		return nil, fmt.Errorf("could not read stats file %s, error: %w", p.procStatPath, err)
	}
	parts := bytes.SplitN(procStatFileBytes, sepSpace, 25)
	if len(parts) < 25 {
		return nil, fmt.Errorf("expected at least 25 parts in stat file, got: %d", len(parts))
	}
	utime, err := parseIntBytes(parts[13])
	if err != nil {
		return nil, fmt.Errorf("could not parse utime, error: %w", err)
	}
	ktime, err := parseIntBytes(parts[14])
	if err != nil {
		return nil, fmt.Errorf("could not parse ktime, error: %w", err)
	}
	cutime, err := parseIntBytes(parts[15])
	if err != nil {
		return nil, fmt.Errorf("could not parse cutime, error: %w", err)
	}
	cktime, err := parseIntBytes(parts[16])
	if err != nil {
		return nil, fmt.Errorf("could not parse cktime, error: %w", err)
	}
	rssPages, err := parseIntBytes(parts[23])
	if err != nil {
		return nil, fmt.Errorf("could not parse rssPages, error: %w", err)
	}

	totalTicks := utime + ktime + cutime + cktime
	currentRss := rssPages * pageSize

	resourceUsage := ResourceUsage{
		updateTime:  time.Now(),
		ElapsedTime: 0,
		CpuTicks:    totalTicks,
		Rss:         currentRss}

	return &resourceUsage, nil
}
