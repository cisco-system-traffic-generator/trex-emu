package core

import (
	"errors"
	"time"
)

type NonBlockingChanErr error

var (
	ErrInvalidParam NonBlockingChanErr = errors.New("Invalid parameter")
	ErrIsFull       NonBlockingChanErr = errors.New("Channel is full")
	ErrIsEmpty      NonBlockingChanErr = errors.New("Channel is empty")
)

type NonBlockingChanEvent int

const (
	EvLowWatermark NonBlockingChanEvent = iota
	EvHighWatermark
)

func (s NonBlockingChanEvent) String() string {
	switch s {
	case EvLowWatermark:
		return "evLowWatermark"
	case EvHighWatermark:
		return "evHighWatermark"
	}
	return "unknown"
}

type nonBlockingChanObserver interface {
	Notify(event NonBlockingChanEvent)
}

type NonBlockingChan struct {
	ch               chan interface{}
	capacity         uint16
	lowWatermarkThr  uint16
	highWatermarkThr uint16
	observer         nonBlockingChanObserver
	highWatermark    bool
	timer            CHTimerObj
	timerCtx         *TimerCtx
}

const (
	nonBlockingChanTimerInterval = time.Millisecond
)

func NewNonBlockingChan(capacity, lowWatermarkThr, highWatermarkThr uint16, timerCtx *TimerCtx) (*NonBlockingChan, NonBlockingChanErr) {
	if lowWatermarkThr >= highWatermarkThr {
		return nil, ErrInvalidParam
	}

	if lowWatermarkThr >= capacity || highWatermarkThr >= capacity {
		return nil, ErrInvalidParam
	}

	if timerCtx == nil {
		return nil, ErrInvalidParam
	}

	p := new(NonBlockingChan)
	p.capacity = capacity
	p.lowWatermarkThr = lowWatermarkThr
	p.highWatermarkThr = highWatermarkThr
	p.ch = make(chan interface{}, capacity)
	p.timerCtx = timerCtx
	p.timer.SetCB(p, 0, 0)

	return p, nil
}

func (p *NonBlockingChan) handleLowWatermark() {
	p.highWatermark = false
	if p.observer != nil {
		(p.observer).Notify(EvLowWatermark)
	}
}

func (p *NonBlockingChan) OnEvent(a, b interface{}) {
	if len(p.ch) < int(p.lowWatermarkThr) && p.highWatermark {
		p.handleLowWatermark()
	} else {
		p.timerCtx.Start(&p.timer, time.Millisecond)
	}
}

func (p *NonBlockingChan) handleHighWatermark() {
	p.highWatermark = true

	if p.observer != nil {
		(p.observer).Notify(EvHighWatermark)
	}

	p.timerCtx.Start(&p.timer, time.Millisecond)
}

func (p *NonBlockingChan) Write(obj interface{}, block bool) error {
	if !block {
		select {
		case p.ch <- obj:
			// Object written to channel
		default:
			// No object written to channel - queue is full
			return ErrIsFull
		}
	} else {
		p.ch <- obj
	}

	if len(p.ch) > int(p.highWatermarkThr) && !p.highWatermark {
		p.handleHighWatermark()
	}

	return nil
}

func (p *NonBlockingChan) Read(block bool) (interface{}, error, bool) {
	var obj interface{}
	var more bool

	if !block {
		select {
		case obj, more = <-p.ch:
			// Object read from channel
		default:
			// No object read from channel, queue is empty
			return nil, ErrIsEmpty, true
		}
	} else {
		obj, more = <-p.ch
	}

	if !more {
		// Channel is closed and empty
		return nil, nil, false
	}

	return obj, nil, true
}

func (p *NonBlockingChan) Close() {
	if p.timer.IsRunning() {
		p.timerCtx.Stop(&p.timer)
	}

	close(p.ch)
}

func (p *NonBlockingChan) RegisterObserver(o nonBlockingChanObserver) {
	p.observer = o
}
