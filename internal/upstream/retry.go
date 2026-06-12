// Package upstream proxies MCP JSON-RPC to the adapter over HTTPS with DPoP,
// the Go port of src/upstream.ts and src/retry.ts.
package upstream

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var transientStatus = map[int]bool{408: true, 429: true, 502: true, 503: true, 504: true}

// WithBackoff invokes fn (a fetch-like call), retrying transient statuses
// (408/429/502/503/504) and network errors with exponential backoff. It does
// NOT retry a context deadline/cancel (the deadline already passed) or any other
// 4xx. Returns the last response when retries are exhausted; returns the last
// error on persistent network failure.
func WithBackoff(fn func() (*http.Response, error), retries, baseMs int, sleep func(time.Duration)) (*http.Response, error) {
	if sleep == nil {
		sleep = time.Sleep
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		res, err := fn()
		if err != nil {
			lastErr = err
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || attempt >= retries {
				return nil, err
			}
			sleep(backoff(baseMs, attempt))
			continue
		}
		if attempt < retries && transientStatus[res.StatusCode] {
			res.Body.Close()
			sleep(backoff(baseMs, attempt))
			continue
		}
		return res, nil
	}
	return nil, lastErr
}

func backoff(baseMs, attempt int) time.Duration {
	return time.Duration(baseMs*(1<<attempt)) * time.Millisecond
}
