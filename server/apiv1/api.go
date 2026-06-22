// Package apiv1 handles all the API responses
package apiv1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/araddon/dateparse"
	"github.com/axllent/mailpit/config"
	"github.com/axllent/mailpit/internal/logger"
)

// FourOFour returns a basic 404 message
func fourOFour(w http.ResponseWriter) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, "404 page not found")
}

// HTTPError returns a basic error message (400 response)
func httpError(w http.ResponseWriter, msg string) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprint(w, msg)
}

// httpJSONError returns a basic error message (400 response) in JSON format
func httpJSONError(w http.ResponseWriter, msg string) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	e := struct{ Error string }{Error: msg}

	if err := json.NewEncoder(w).Encode(e); err != nil {
		httpError(w, err.Error())
	}
}

// Get the start and limit based on query params. Defaults to 0, 50
func getStartLimit(req *http.Request) (start int, beforeTS int64, sinceTS int64, untilTS int64, limit int) {
	start = 0
	limit = 50
	beforeTS = 0
	sinceTS = 0
	untilTS = 0

	s := req.URL.Query().Get("start")
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		start = n
	}

	l := req.URL.Query().Get("limit")
	if n, err := strconv.Atoi(l); err == nil && n > -1 {
		limit = n
	}

	b := req.URL.Query().Get("before")
	if b != "" {
		if t, err := parseDateParam(b); err == nil {
			beforeTS = t
		} else {
			logger.Log().Warnf("ignoring invalid before: date \"%s\"", b)
		}
	}

	since := req.URL.Query().Get("since")
	if since != "" {
		if t, err := parseDateParam(since); err == nil {
			sinceTS = t
		} else {
			logger.Log().Warnf("ignoring invalid since: date \"%s\"", since)
		}
	}

	until := req.URL.Query().Get("until")
	if until != "" {
		if t, err := parseDateParam(until); err == nil {
			untilTS = t
		} else {
			logger.Log().Warnf("ignoring invalid until: date \"%s\"", until)
		}
	}

	return start, beforeTS, sinceTS, untilTS, limit
}

// parseDateParam parses a date string, supporting both Unix timestamps (seconds or milliseconds)
// and common date formats via dateparse. Returns UnixMilli timestamp.
func parseDateParam(s string) (int64, error) {
	// first try to parse as Unix timestamp (digits only)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1e12 {
			// milliseconds (13+ digits)
			return n, nil
		}
		// seconds (10 digits)
		return n * 1000, nil
	}
	// fall back to dateparse for string formats
	t, err := dateparse.ParseLocal(s)
	if err != nil {
		return 0, err
	}
	return t.UnixMilli(), nil
}

// GetOptions returns a blank response
func GetOptions(w http.ResponseWriter, _ *http.Request) {

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(""))
}
