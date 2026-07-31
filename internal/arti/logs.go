package arti

// Arti's own log records, for routing into an application's logger.
//
// Without this, everything Arti has to say about bootstrap, guards, circuits
// and onion service publication is discarded, which makes "it seems stuck"
// impossible to tell apart from "it is working slowly".

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

// logPollInterval bounds how long a single poll blocks, so [StopLogging] takes
// effect promptly.
const logPollInterval = 250 * time.Millisecond

// logBuffer is how far a slow log consumer may fall behind before records are
// dropped.
const logBuffer = 256

// LogRecord is one message from Arti.
type LogRecord struct {
	// Level is "ERROR", "WARN", "INFO", "DEBUG" or "TRACE".
	Level string `json:"level"`
	// Target is the emitting module, e.g. "tor_dirmgr::bootstrap".
	Target string `json:"target"`
	// Message is the formatted text, including any structured fields.
	Message string `json:"message"`
}

// String renders a record the way a log line usually looks.
func (r LogRecord) String() string {
	return r.Level + " " + r.Target + ": " + r.Message
}

// Logging is process-wide because tracing permits a single subscriber, so the
// state behind it is too.
var (
	logMu       sync.Mutex
	logStarted  bool
	logStop     chan struct{}
	logChannels []chan LogRecord
)

// EnableLogging starts collecting Arti's log records and returns a channel of
// them.
//
// The level is a [tracing EnvFilter] directive: "info" for a readable trace of
// bootstrap and publication, "debug", or something narrower such as
// "info,tor_dirmgr=debug".
//
// This affects the whole process, not a single [Client], because tracing
// permits only one subscriber. Calling it again returns an additional channel
// at the level already in force; the level is fixed by the first call.
// Records are dropped rather than queued for a consumer that falls behind.
//
// [tracing EnvFilter]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html
func EnableLogging(level string) (<-chan LogRecord, error) {
	if strings.TrimSpace(level) == "" {
		return nil, errors.New("arti: a log level is required")
	}

	logMu.Lock()
	defer logMu.Unlock()

	if !logStarted {
		// LIBTOR_LOG may have installed the subscriber already, in which case
		// records are queued and there is nothing more to set up.
		if err := enableLogging(level); err != nil && !alreadyInstalled() {
			return nil, err
		}
		logStarted = true
		logStop = make(chan struct{})
		go pumpLogs(logStop)
	}

	ch := make(chan LogRecord, logBuffer)
	logChannels = append(logChannels, ch)
	return ch, nil
}

// alreadyInstalled reports whether the environment installed the subscriber.
//
// That is not an error: the records still arrive, they are simply also being
// mirrored to stderr.
func alreadyInstalled() bool {
	return strings.TrimSpace(envLogDirectives()) != ""
}

// StopLogging stops collecting records and closes every channel handed out by
// [EnableLogging].
//
// The subscriber itself cannot be uninstalled - tracing does not allow it - so
// a later [EnableLogging] resumes delivery at the original level.
func StopLogging() {
	logMu.Lock()
	defer logMu.Unlock()

	if !logStarted {
		return
	}
	close(logStop)
	logStarted = false
	for _, ch := range logChannels {
		close(ch)
	}
	logChannels = nil
}

// pumpLogs moves records from the backend to the subscribers.
func pumpLogs(stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		record, err := nextLogRecord(logPollInterval)
		if err != nil || record == nil {
			continue
		}

		logMu.Lock()
		// A record that arrives during StopLogging must not be sent on a
		// channel that is being closed, so re-check under the same lock.
		if logStarted {
			for _, ch := range logChannels {
				select {
				case ch <- *record:
				default:
				}
			}
		}
		logMu.Unlock()
	}
}

// envLogDirectives reports the LIBTOR_LOG setting, if any.
func envLogDirectives() string { return os.Getenv("LIBTOR_LOG") }
