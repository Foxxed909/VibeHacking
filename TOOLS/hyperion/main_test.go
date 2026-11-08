package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRequestFailureClassification(t *testing.T) {
	cases := []struct {
		name string
		status int
		err, asserted, challenged, failed bool
	}{
		{"ok", 200, false, true, false, false},
		{"redirect", 302, false, true, false, false},
		{"forbidden", 403, false, true, false, true},
		{"rate_limited", 429, false, true, false, true},
		{"server_error", 503, false, false, true, true},
		{"network_error", 0, true, true, false, true},
		{"bad_body", 200, false, false, false, true},
		{"challenge_200", 200, false, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := requestFailed(c.status, c.err, c.asserted, c.challenged); got != c.failed {
				t.Fatalf("failed=%v, want %v", got, c.failed)
			}
		})
	}
}

func TestRejectNonFiniteRates(t *testing.T) {
	for _, rate := range []string{"NaN", "+Inf", "-Inf", "1e309", "1e308g", "-1"} {
		if _, err := parseRate(rate); err == nil {
			t.Fatalf("accepted invalid rate %q", rate)
		}
	}
}

func TestLoopbackResponseMetrics(t *testing.T) {
	cases := []struct {
		name string
		status int
		challenge, truncate bool
		expect string
		failed bool
	}{
		{"healthy", 200, false, false, "healthy", false},
		{"forbidden", 403, false, false, "", true},
		{"rate_limited", 429, false, false, "", true},
		{"challenge_200", 200, true, false, "", true},
		{"assertion_failed", 200, false, false, "absent", true},
		{"truncated_body", 200, false, true, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.challenge {
					w.Header().Set("CF-Mitigated", "challenge")
				}
				if c.truncate {
					w.Header().Set("Content-Length", "100")
				}
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte("healthy"))
			}))
			defer server.Close()
			file := filepath.Join(t.TempDir(), "nested", "metrics.json")
			cfg := config{target: server.URL, method: "GET", profile: "constant", rate: "10",
				duration: 100*time.Millisecond, timeout: time.Second, workers: 1,
				apdexTMs: 100, circuitBreaker: true, abort5xxPct: 80,
				expectText: c.expect, jsonFile: file}
			code, err := run(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if (code != 0) != c.failed {
				t.Fatalf("exit=%d, failed=%v", code, c.failed)
			}
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var metrics map[string]any
			if err := json.Unmarshal(data, &metrics); err != nil {
				t.Fatal(err)
			}
			if metrics["total_requests"].(float64) < 1 {
				t.Fatal("no samples recorded")
			}
			if c.failed {
				if metrics["successful_rps"].(float64) != 0 || metrics["error_rate_pct"].(float64) != 100 {
					t.Fatalf("blocked traffic reported as success: %s", data)
				}
			} else if metrics["successful_rps"].(float64) <= 0 || metrics["failed_requests"].(float64) != 0 {
				t.Fatalf("healthy response metrics: %s", data)
			}
		})
	}
}

func TestLatencyIncludesResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(30*time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "metrics.json")
	code, err := run(config{target: server.URL, method: "GET", profile: "constant", rate: "5",
		duration: 100*time.Millisecond, timeout: time.Second, workers: 1, apdexTMs: 100,
		jsonFile: file})
	if err != nil || code != 0 {
		t.Fatalf("run: code=%d, err=%v", code, err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var metrics struct { Latency map[string]float64 `json:"latency_ms"` }
	if err := json.Unmarshal(data, &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics.Latency["avg"] < 25 {
		t.Fatalf("body latency omitted: %.2fms", metrics.Latency["avg"])
	}
}

func TestRateLimitedTrafficTripsCircuitBreaker(t *testing.T) {
	var live liveCounters
	live.failed.Store(50)
	live.status429.Store(50)
	stopped := false
	checkCircuitBreaker(&live, config{circuitBreaker: true, abort5xxPct: 80}, func() { stopped = true })
	if !stopped || !live.tripped.Load() {
		t.Fatal("rate-limited requests did not stop the run")
	}
}

func TestMinimumRPSUsesSuccessfulResponses(t *testing.T) {
	var live liveCounters
	live.successful.Store(1)
	live.failed.Store(9)
	live.status2xx.Store(1)
	live.status429.Store(9)
	shards := []workerShard{{count: 10}}
	_, failed := mergeAndReport(config{sloMinRPS: 5, sloErrPct: 95}, nil,
		time.Second, &live, shards, 200, 1, 200, 1)
	if !failed {
		t.Fatal("attempted traffic satisfied the successful-RPS SLO")
	}
}

func TestEmptyRunAndReportWriteFailureCannotPass(t *testing.T) {
	var live liveCounters
	if _, failed := mergeAndReport(config{}, nil, time.Millisecond, &live, nil, 200, 1, 200, 1); !failed {
		t.Fatal("empty run passed")
	}
	parent := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	live.successful.Store(1)
	shards := []workerShard{{count: 1}}
	report, failed := mergeAndReport(config{jsonFile: filepath.Join(parent, "metrics.json")},
		nil, time.Millisecond, &live, shards, 200, 1, 200, 1)
	if !failed || !strings.Contains(report, "FAIL: JSON report") {
		t.Fatal("report write failure was hidden")
	}
}
