package core

import (
	"errors"
	"sync"
	"time"
)

type BufferedTimer struct {
	timer     *time.Timer
	ticksChan chan time.Time
	interval  time.Duration // the duration of the tick
	capacity  int
	done      chan bool
	wg        sync.WaitGroup
}

func NewBufferedTimer(interval time.Duration, capacity int) (*BufferedTimer, error) {
	if capacity <= 0 {
		return nil, errors.New("Invalid parameter")
	}

	p := new(BufferedTimer)
	p.interval = interval
	p.capacity = capacity
	p.timer = time.NewTimer(interval)
	p.ticksChan = make(chan time.Time, capacity)

	p.wg.Add(1)
	p.done = make(chan bool)
	go p.timerThread()

	return p, nil
}

func (p *BufferedTimer) GetC() <-chan time.Time {
	return p.ticksChan
}

func (p *BufferedTimer) Stop() {
	p.done <- true
	p.wg.Wait()
	close(p.done)
}

func (p *BufferedTimer) timerThread() {
	var t time.Time
	defer p.wg.Done()
	for {
		select {
		case t = <-p.timer.C:
			p.timer.Reset(p.interval)
			p.ticksChan <- t
		case <-p.done:
			return
		}
	}
}
