package logger

import (
	"fmt"
	"log"
	"runtime"
	"time"
)

func MemoryBenchmark(msg string) {
	//For memory benchmarks we can't log it via channels
	//as the time won't be the same and therefore the memory
	//so we build the message then send it to the logger to
	//be logged when possible.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	details := fmt.Sprintf("[%s]", msg)
	details += fmt.Sprintf("Alloc = %v MiB", bToMb(m.Alloc))
	details += fmt.Sprintf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	details += fmt.Sprintf("\tSys = %v MiB", bToMb(m.Sys))
	lr := LogRequest{MEMORY_LOG, details}
	logger.logRequests <- lr
}

func logMemory(msg string) {
	log.Println(msg)
}

func MemoryBenchmarkEvery(duration time.Duration) chan struct{} {
	ticker := time.NewTicker(duration)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				MemoryBenchmark("Periodic Memory Check")
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	return quit
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
