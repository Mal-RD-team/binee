package logger

import (
	"log"
	"time"
)

var logger *Logger

const (
	MEMORY_LOG = iota
	TIME_LOG
	MSG_LOG
	REQUEST_CLOSE
)

type Logger struct {
	logRequests               chan LogRequest
	PeriodicTasksStopChannels []chan struct{}
	logs                      []string
}

type LogRequest struct {
	Type uint32
	Msg  string
}

func Init() {
	logger = &Logger{logRequests: make(chan LogRequest)}
	go startLogging(logger)
	stopChannel := MemoryBenchmarkEvery(10 * time.Millisecond)
	logger.PeriodicTasksStopChannels = append(logger.PeriodicTasksStopChannels, stopChannel)
}

func startLogging(bm *Logger) {
	log.Println("Started Logging")
	for true {
		select {
		case logRequest := <-bm.logRequests:
			switch logRequest.Type {
			case MSG_LOG:
				log.Println(logRequest.Msg)
				break
			case MEMORY_LOG:
				logMemory(logRequest.Msg)
			case REQUEST_CLOSE:
				return
			default:
				log.Println("invalid logging request")
			}
		}
	}
}

func Log(msg string) {
	lr := LogRequest{MSG_LOG, msg}
	logger.logRequests <- lr
}

func End() {
	for _, stopChannel := range logger.PeriodicTasksStopChannels {
		stopChannel <- struct{}{}
		close(stopChannel)
	}
	logger.logRequests <- LogRequest{REQUEST_CLOSE, ""} //this exists to make sure the channel is empty and all requests were fulfilled
	close(logger.logRequests)
	log.Println("Finished Logging")
}
