package utils

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cheggaaa/pb/v3"
)

type ProgressManager struct {
	bar *pb.ProgressBar
	mu  sync.Mutex
}

func NewProgressBar(total int) *ProgressManager {
	bar := pb.New(total).
		SetTemplate(pb.ProgressBarTemplate(`{{ cyan "🔎 Scanning:" }} {{ bar . "⏳ " "▓" "░" " " " ⏳" }} {{percent .}} {{counters .}}`)).
		SetRefreshRate(100 * time.Millisecond).
		SetWriter(os.Stderr).
		Start()

	pm := &ProgressManager{bar: bar}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		pm.Finish()
		os.Exit(1)
	}()

	return pm
}

func (p *ProgressManager) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bar.Increment()
}

func (p *ProgressManager) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bar.Finish()
}
