package core

import (
	"errors"
	"time"
)

type BufferedTimer struct {
	timer     *time.Timer
	ticksChan chan time.Time
	interval  time.Duration // the duration of the tick
	capacity  int
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
	go p.timerThread()

	return p, nil
}

func (p *BufferedTimer) GetC() <-chan time.Time {
	return p.ticksChan
}

func (p *BufferedTimer) timerThread() {
	var t time.Time
	for {
		select {
		case t = <-p.timer.C:
			p.timer.Reset(p.interval)
			p.ticksChan <- t
		}
	}
}
