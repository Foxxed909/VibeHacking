package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	guardCode          = "XXLMILLEAMEAN"
	maxExternalRPS     = 9999.99
	maxExternalWorkers = 256
	// 14x Maelstrom's 250,000 RPS private lab ceiling (3,500,000 RPS)
	maxPrivateRPS = 3500000.0
	// O(1) HDR-style histogram: 60,000 buckets of 0.1ms (100us) from 0ms to 6000ms + overflow
	histBuckets   = 60000
	histStepMicro = 100
)

type headerList []string

func (h *headerList) String() string {
	return strings.Join(*h, ",")
}

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type weightedEndpoint struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

type config struct {
	target         string
	endpoints      string
	profile        string
	method         string
	rate           string
	duration       time.Duration
	workers        int
	payload        string
	headers        headerList
	timeout        time.Duration
	guard          string
	cacheBust      bool
	expectStatus   int
	expectText     string
	apdexTMs       float64
	sloP95Ms       float64
	sloP99Ms       float64
	sloErrPct      float64
	sloApdex       float64
	sloMinRPS      float64
	circuitBreaker bool
	abort5xxPct    float64
	reportFile     string
	jsonFile       string
}

type liveCounters struct {
	total               atomic.Int64
	status2xx           atomic.Int64
	status3xx           atomic.Int64
	status4xx           atomic.Int64
	status429           atomic.Int64
	status5xx           atomic.Int64
	statusCF52x         atomic.Int64
	statusOther         atomic.Int64
	errors              atomic.Int64
	assertFails         atomic.Int64
	cacheHits           atomic.Int64
	cacheMisses         atomic.Int64
	cacheDynamic        atomic.Int64
	cacheBypass         atomic.Int64
	wafChallenges       atomic.Int64
	serverlessThrottles atomic.Int64
	bytes               atomic.Int64
	sumMicros           atomic.Int64
	tripped             atomic.Bool
}

type workerShard struct {
	hist        [histBuckets]uint64
	overflow    uint64
	count       uint64
	sumMs       float64
	sumSqMs     float64
	minMs       float64
	maxMs       float64
	apdexSat    uint64
	apdexTol    uint64
	stageCounts [4]uint64
	stageSumMs  [4]float64
	stage5xxErr [4]uint64
}

type stageSummary struct {
	Stage      int     `json:"stage"`
	Label      string  `json:"label"`
	Requests   uint64  `json:"requests"`
	RPS        float64 `json:"rps"`
	AvgMs      float64 `json:"avg_ms"`
	ErrRatePct float64 `json:"error_rate_pct"`
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		exitError(err)
	}
	if err := verifyGuard(cfg.guard); err != nil {
		exitError(err)
	}
	if err := validateTarget(cfg.target); err != nil {
		exitError(err)
	}
	code, err := run(cfg)
	if err != nil {
		exitError(err)
	}
	os.Exit(code)
}

func verifyGuard(supplied string) error {
	candidate := strings.TrimSpace(supplied)
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv("VIBE_HYPERION_GUARD"))
	}
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv("VIBE_GUARD_CODE"))
	}
	if subtle.ConstantTimeCompare([]byte(candidate), []byte(guardCode)) == 1 {
		return nil
	}
	return fmt.Errorf("guard lock active: pass --guard %s (or set VIBE_HYPERION_GUARD) for authorized capacity testing", guardCode)
}

func parseFlags() (config, error) {
	defaultWorkers := runtime.NumCPU() * 64
	if defaultWorkers < 64 {
		defaultWorkers = 64
	}

	var cfg config
	var targetShort, methodShort, rateShort, payloadShort, guardShort, profileShort string
	var durationShort time.Duration
	var workersShort int

	flag.StringVar(&cfg.target, "target", "http://localhost:3456/", "Target URL endpoint")
	flag.StringVar(&targetShort, "t", "", "Target URL endpoint")
	flag.StringVar(&cfg.endpoints, "endpoints", "", "Weighted subpaths on the same host (e.g. '/:50,/api/config:30,/api/guestbook:20')")
	flag.StringVar(&cfg.profile, "profile", "constant", "Load profile: constant, ramp, step, spike, sawtooth, stress-knee")
	flag.StringVar(&profileShort, "P", "", "Load profile")
	flag.StringVar(&cfg.method, "method", "GET", "HTTP method")
	flag.StringVar(&methodShort, "m", "", "HTTP method")
	flag.StringVar(&cfg.rate, "rate", "1000", "Target rate (RPS, e.g. 5000, 100k, 3.5m, or 0 for local full-send)")
	flag.StringVar(&rateShort, "r", "", "Target rate")
	flag.DurationVar(&cfg.duration, "duration", 15*time.Second, "Test duration, e.g. 15s, 2m")
	flag.DurationVar(&durationShort, "d", 0, "Test duration")
	flag.IntVar(&cfg.workers, "workers", defaultWorkers, "Concurrent workers/goroutines")
	flag.IntVar(&workersShort, "w", 0, "Concurrent workers/goroutines")
	flag.StringVar(&cfg.payload, "payload", "", "Optional payload file for POST/PUT/PATCH (supports {{seq}}, {{timestamp}})")
	flag.StringVar(&payloadShort, "p", "", "Optional payload file")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-request timeout")
	flag.StringVar(&cfg.guard, "guard", "", "Required authorization guard code")
	flag.StringVar(&guardShort, "g", "", "Required authorization guard code")
	flag.BoolVar(&cfg.cacheBust, "cache-bust", false, "Append dynamic cache-busting query/header tokens per request")
	flag.IntVar(&cfg.expectStatus, "expect-status", 0, "Optional expected HTTP status code assertion")
	flag.StringVar(&cfg.expectText, "expect-text", "", "Optional substring assertion that must appear in HTTP 200 responses")
	flag.Float64Var(&cfg.apdexTMs, "apdex-t", 100.0, "Apdex satisfactory latency threshold T in ms (default 100ms)")
	flag.Float64Var(&cfg.sloP95Ms, "slo-p95", 0, "Optional SLO gate: fail if p95 latency (ms) exceeds threshold")
	flag.Float64Var(&cfg.sloP99Ms, "slo-p99", 0, "Optional SLO gate: fail if p99 latency (ms) exceeds threshold")
	flag.Float64Var(&cfg.sloErrPct, "slo-err-pct", 0, "Optional SLO gate: fail if error/5xx rate (%) exceeds threshold")
	flag.Float64Var(&cfg.sloApdex, "slo-apdex", 0, "Optional SLO gate: fail if Apdex score (0.0-1.0) is below threshold")
	flag.Float64Var(&cfg.sloMinRPS, "slo-min-rps", 0, "Optional SLO gate: fail if achieved RPS is below threshold")
	flag.BoolVar(&cfg.circuitBreaker, "circuit-breaker", true, "Auto-abort if target 5xx/error rate exceeds abort-5xx-pct after 50+ requests")
	flag.Float64Var(&cfg.abort5xxPct, "abort-5xx-pct", 80.0, "Circuit-breaker error/5xx percentage threshold (default 80%)")
	flag.StringVar(&cfg.reportFile, "report-file", "", "Optional Markdown report output path")
	flag.StringVar(&cfg.jsonFile, "json-out", "", "Optional JSON telemetry output path")
	flag.Var(&cfg.headers, "headers", "Custom header 'Name: value' (repeatable)")
	flag.Var(&cfg.headers, "H", "Custom header 'Name: value' (repeatable)")

	flag.Parse()

	if targetShort != "" {
		cfg.target = targetShort
	}
	if methodShort != "" {
		cfg.method = methodShort
	}
	if rateShort != "" {
		cfg.rate = rateShort
	}
	if durationShort > 0 {
		cfg.duration = durationShort
	}
	if workersShort > 0 {
		cfg.workers = workersShort
	}
	if payloadShort != "" {
		cfg.payload = payloadShort
	}
	if guardShort != "" {
		cfg.guard = guardShort
	}
	if profileShort != "" {
		cfg.profile = profileShort
	}

	cfg.method = strings.ToUpper(strings.TrimSpace(cfg.method))
	cfg.profile = strings.ToLower(strings.TrimSpace(cfg.profile))
	if cfg.workers < 1 {
		cfg.workers = 1
	}
	if cfg.duration <= 0 {
		return cfg, fmt.Errorf("duration must be greater than zero")
	}
	if cfg.timeout <= 0 {
		return cfg, fmt.Errorf("timeout must be greater than zero")
	}
	if cfg.apdexTMs <= 0 {
		cfg.apdexTMs = 100.0
	}

	switch cfg.method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return cfg, fmt.Errorf("unsupported method %q", cfg.method)
	}

	switch cfg.profile {
	case "constant", "ramp", "step", "spike", "sawtooth", "stress-knee":
	default:
		return cfg, fmt.Errorf("unsupported profile %q (use constant, ramp, step, spike, sawtooth, or stress-knee)", cfg.profile)
	}

	return cfg, nil
}

func validateTarget(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("target scheme must be http or https")
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("target URL must include a host")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return nil
		}
		return fmt.Errorf("refusing target %s: public IP not listed in authorized_targets.txt", host)
	}
	allowed := loadAuthorizedHosts()
	if allowed[strings.ToLower(host)] {
		return nil
	}
	return fmt.Errorf("refusing target %s: hostname not listed in authorized_targets.txt", host)
}

func loadAuthorizedHosts() map[string]bool {
	allowed := map[string]bool{}
	path := findAuthorizedFile()
	if path == "" {
		return allowed
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return allowed
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.ContainsAny(line, "*?") {
			continue
		}
		host := line
		if strings.Contains(host, "://") {
			if u, e := url.Parse(host); e == nil && u.Hostname() != "" {
				host = u.Hostname()
			}
		}
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			allowed[host] = true
		}
	}
	return allowed
}

func findAuthorizedFile() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "authorized_targets.txt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func isPublicInternetTarget(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	host := parsed.Hostname()
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return true
		}
	}
	return false
}

func validateTrafficLimits(cfg config, rate float64) error {
	if isPublicInternetTarget(cfg.target) {
		if rate <= 0 {
			return fmt.Errorf("full-send is disabled for public internet targets; use localhost/private labs")
		}
		if rate > maxExternalRPS {
			return fmt.Errorf("public internet Hyperion rate %.2f rps exceeds %.2f rps safety cap", rate, maxExternalRPS)
		}
		if cfg.workers > maxExternalWorkers {
			return fmt.Errorf("public internet Hyperion workers %d exceeds %d worker cap", cfg.workers, maxExternalWorkers)
		}
		return nil
	}
	if rate > maxPrivateRPS {
		return fmt.Errorf("private-target Hyperion rate %.2f rps exceeds %.0f rps local safety cap", rate, maxPrivateRPS)
	}
	return nil
}

func buildWeightedRing(baseRaw, endpointsCSV string) ([]string, []weightedEndpoint, error) {
	baseURL, err := url.Parse(baseRaw)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(endpointsCSV) == "" {
		return []string{baseRaw}, []weightedEndpoint{{URL: baseRaw, Weight: 1}}, nil
	}
	var ring []string
	var specs []weightedEndpoint
	for _, item := range strings.Split(endpointsCSV, ",") {
		raw := strings.TrimSpace(item)
		if raw == "" {
			continue
		}
		weight := 1
		sub := raw
		if colonIdx := strings.LastIndex(raw, ":"); colonIdx > 0 && !strings.HasPrefix(raw, "http") {
			if w, e := strconv.Atoi(raw[colonIdx+1:]); e == nil && w > 0 && w <= 100 {
				weight = w
				sub = raw[:colonIdx]
			}
		}
		if !strings.HasPrefix(sub, "/") {
			sub = "/" + sub
		}
		rel, err := url.Parse(sub)
		if err != nil {
			continue
		}
		resolved := baseURL.ResolveReference(rel)
		if strings.EqualFold(resolved.Host, baseURL.Host) {
			uStr := resolved.String()
			specs = append(specs, weightedEndpoint{URL: uStr, Weight: weight})
			for i := 0; i < weight; i++ {
				ring = append(ring, uStr)
			}
		}
	}
	if len(ring) == 0 {
		ring = []string{baseRaw}
		specs = []weightedEndpoint{{URL: baseRaw, Weight: 1}}
	}
	return ring, specs, nil
}

func effectiveRate(baseRate float64, profile string, progress float64) float64 {
	if baseRate <= 0 {
		return 0
	}
	p := math.Max(0, math.Min(1, progress))
	switch profile {
	case "ramp":
		return baseRate * (0.10 + 0.90*p)
	case "step", "stress-knee":
		switch {
		case p < 0.25:
			return baseRate * 0.25
		case p < 0.50:
			return baseRate * 0.50
		case p < 0.75:
			return baseRate * 0.75
		default:
			return baseRate
		}
	case "spike":
		if p >= 0.40 && p <= 0.65 {
			return baseRate
		}
		return baseRate * 0.20
	case "sawtooth":
		wave := math.Mod(p*4.0, 1.0)
		return baseRate * (0.20 + 0.80*wave)
	default:
		return baseRate
	}
}

func probeSingleLatency(client *http.Client, targetURL, method string, headers map[string]string) (int, float64) {
	t0 := time.Now()
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return 0, 0
	}
	req.Header.Set("User-Agent", "Hyperion/2.0 authorized-security-test")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, float64(time.Since(t0).Microseconds()) / 1000.0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, float64(time.Since(t0).Microseconds()) / 1000.0
}

func run(cfg config) (int, error) {
	rate, err := parseRate(cfg.rate)
	if err != nil {
		return 2, err
	}
	if err := validateTrafficLimits(cfg, rate); err != nil {
		return 2, err
	}
	ringURLs, specs, err := buildWeightedRing(cfg.target, cfg.endpoints)
	if err != nil {
		return 2, err
	}
	payloadTemplate, err := loadPayload(cfg.payload)
	if err != nil {
		return 2, err
	}
	headerMap, err := parseHeaders(cfg.headers)
	if err != nil {
		return 2, err
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	dialer := &net.Dialer{
		Timeout:   cfg.timeout,
		KeepAlive: 60 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          cfg.workers * 8,
		MaxIdleConnsPerHost:   cfg.workers * 8,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.timeout,
		ResponseHeaderTimeout: cfg.timeout,
		ExpectContinueTimeout: time.Second,
		WriteBufferSize:       32 * 1024,
		ReadBufferSize:        32 * 1024,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: cfg.timeout}

	// Pre-flight baseline latency probe
	preStatus, preLatencyMs := probeSingleLatency(client, ringURLs[0], cfg.method, headerMap)

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopNow := func() { stopOnce.Do(func() { close(stop) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Println("\nSIGINT received. Draining Hyperion sharded workers...")
		stopNow()
	}()

	start := time.Now()
	go func() {
		time.Sleep(cfg.duration)
		stopNow()
	}()

	var live liveCounters
	shards := make([]workerShard, cfg.workers)
	var wg sync.WaitGroup
	hasDynamicMacros := bytes.Contains(payloadTemplate, []byte("{{"))
	expectBytes := []byte(cfg.expectText)

	fmt.Println("================================================================")
	fmt.Println(" ⚡ HYPERION v2.0 — 14x Sharded Resilience, HDR & SLO Engine")
	fmt.Println("================================================================")
	fmt.Printf("target=%s endpoints=%d profile=%s method=%s duration=%s workers=%d rate=%s\n",
		cfg.target, len(specs), cfg.profile, cfg.method, cfg.duration, cfg.workers, cfg.rate)
	fmt.Printf("preflight: status=%d latency=%.2fms | guard=VERIFIED\n\n", preStatus, preLatencyMs)

	// Per-worker autonomous sharded loop (zero shared channel contention!)
	workerBaseRate := 0.0
	if rate > 0 {
		workerBaseRate = rate / float64(cfg.workers)
	}

	for wID := 0; wID < cfg.workers; wID++ {
		wg.Add(1)
		go func(id int, shard *workerShard) {
			defer wg.Done()
			nextSlot := time.Now()
			localSeq := uint64(id)

			for {
				select {
				case <-stop:
					return
				default:
				}

				now := time.Now()
				elapsed := now.Sub(start)
				if elapsed >= cfg.duration {
					return
				}
				progress := elapsed.Seconds() / math.Max(cfg.duration.Seconds(), 0.001)
				stageIdx := int(progress * 4.0)
				if stageIdx < 0 {
					stageIdx = 0
				} else if stageIdx > 3 {
					stageIdx = 3
				}

				if workerBaseRate > 0 {
					effWorkerRate := effectiveRate(workerBaseRate, cfg.profile, progress)
					if effWorkerRate > 0.1 {
						interval := time.Duration(float64(time.Second) / effWorkerRate)
						if now.Before(nextSlot) {
							sleepDur := nextSlot.Sub(now)
							select {
							case <-stop:
								return
							case <-time.After(sleepDur):
							}
						}
						nextSlot = nextSlot.Add(interval)
						if time.Now().Sub(nextSlot) > 50*time.Millisecond {
							nextSlot = time.Now()
						}
					}
				}

				seq := live.total.Add(1)
				targetURL := ringURLs[int(localSeq)%len(ringURLs)]
				localSeq += uint64(cfg.workers)

				if cfg.cacheBust {
					sep := "?"
					if strings.Contains(targetURL, "?") {
						sep = "&"
					}
					targetURL = fmt.Sprintf("%s%s_cb=%d", targetURL, sep, seq)
				}

				bodyBytes := payloadTemplate
				if hasDynamicMacros {
					s := string(payloadTemplate)
					s = strings.ReplaceAll(s, "{{seq}}", strconv.FormatInt(seq, 10))
					s = strings.ReplaceAll(s, "{{timestamp}}", strconv.FormatInt(time.Now().UnixMilli(), 10))
					bodyBytes = []byte(s)
				}

				reqStart := time.Now()
				var bodyReader io.Reader
				if len(bodyBytes) > 0 {
					bodyReader = bytes.NewReader(bodyBytes)
				}
				req, err := http.NewRequest(cfg.method, targetURL, bodyReader)
				if err != nil {
					live.errors.Add(1)
					shard.stage5xxErr[stageIdx]++
					continue
				}
				req.Header.Set("User-Agent", "Hyperion/2.0 authorized-security-test")
				req.Header.Set("Accept", "*/*")
				for k, v := range headerMap {
					req.Header.Set(k, v)
				}
				if cfg.cacheBust {
					req.Header.Set("X-Request-Sequence", strconv.FormatInt(seq, 10))
				}
				if len(bodyBytes) > 0 && req.Header.Get("Content-Type") == "" {
					req.Header.Set("Content-Type", "application/json")
				}

				resp, err := client.Do(req)
				latMicros := time.Since(reqStart).Microseconds()
				latMs := float64(latMicros) / 1000.0
				live.sumMicros.Add(latMicros)

				// Record in lock-free local worker shard
				shard.count++
				shard.sumMs += latMs
				shard.sumSqMs += latMs * latMs
				if shard.count == 1 || latMs < shard.minMs {
					shard.minMs = latMs
				}
				if latMs > shard.maxMs {
					shard.maxMs = latMs
				}
				bucket := int(latMicros / histStepMicro)
				if bucket < 0 {
					bucket = 0
				}
				if bucket < histBuckets {
					shard.hist[bucket]++
				} else {
					shard.overflow++
				}
				shard.stageCounts[stageIdx]++
				shard.stageSumMs[stageIdx] += latMs

				if err != nil {
					live.errors.Add(1)
					shard.stage5xxErr[stageIdx]++
					checkCircuitBreaker(&live, cfg, stopNow)
					continue
				}

				var nBytes int64
				assertOk := true
				if len(expectBytes) > 0 {
					buf, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
					nBytes = int64(len(buf))
					if !bytes.Contains(buf, expectBytes) {
						assertOk = false
					}
					_, _ = io.Copy(io.Discard, resp.Body)
				} else {
					nBytes, _ = io.Copy(io.Discard, resp.Body)
				}
				_ = resp.Body.Close()
				live.bytes.Add(nBytes)

				// Inspect Cloudflare / Vercel / AWS CloudFront edge cache & WAF headers
				cacheHdr := strings.ToLower(resp.Header.Get("CF-Cache-Status") + " " + resp.Header.Get("X-Vercel-Cache") + " " + resp.Header.Get("X-Cache"))
				switch {
				case strings.Contains(cacheHdr, "hit") || strings.Contains(cacheHdr, "prerender") || strings.Contains(cacheHdr, "stale"):
					live.cacheHits.Add(1)
				case strings.Contains(cacheHdr, "miss") || strings.Contains(cacheHdr, "expired") || strings.Contains(cacheHdr, "revalidated"):
					live.cacheMisses.Add(1)
				case strings.Contains(cacheHdr, "dynamic"):
					live.cacheDynamic.Add(1)
				case strings.Contains(cacheHdr, "bypass"):
					live.cacheBypass.Add(1)
				}
				if resp.Header.Get("CF-Mitigated") != "" || resp.Header.Get("X-Vercel-Mitigated") != "" || resp.Header.Get("X-Amzn-Waf-Action") != "" {
					live.wafChallenges.Add(1)
				}
				errHdr := strings.ToLower(resp.Header.Get("X-Vercel-Error") + " " + resp.Header.Get("X-Amzn-ErrorType"))
				if resp.StatusCode == 504 || strings.Contains(errHdr, "timeout") || strings.Contains(errHdr, "throttl") || strings.Contains(errHdr, "toomanyrequests") {
					live.serverlessThrottles.Add(1)
				}

				if cfg.expectStatus > 0 && resp.StatusCode != cfg.expectStatus {
					assertOk = false
				}
				if !assertOk {
					live.assertFails.Add(1)
				}

				st := resp.StatusCode
				switch {
				case st >= 200 && st < 300:
					live.status2xx.Add(1)
					if latMs <= cfg.apdexTMs {
						shard.apdexSat++
					} else if latMs <= cfg.apdexTMs*4.0 {
						shard.apdexTol++
					}
				case st >= 300 && st < 400:
					live.status3xx.Add(1)
					if latMs <= cfg.apdexTMs {
						shard.apdexSat++
					} else if latMs <= cfg.apdexTMs*4.0 {
						shard.apdexTol++
					}
				case st == 429:
					live.status4xx.Add(1)
					live.status429.Add(1)
				case st >= 400 && st < 500:
					live.status4xx.Add(1)
				case st >= 500 && st < 600:
					live.status5xx.Add(1)
					if st >= 520 && st <= 526 {
						live.statusCF52x.Add(1)
					}
					shard.stage5xxErr[stageIdx]++
					checkCircuitBreaker(&live, cfg, stopNow)
				default:
					live.statusOther.Add(1)
				}
			}
		}(wID, &shards[wID])
	}

	// Live 1-second atomic telemetry ticker
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var prevTotal, prevMicros int64
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				curTotal := live.total.Load()
				curMicros := live.sumMicros.Load()
				deltaReq := curTotal - prevTotal
				deltaMicros := curMicros - prevMicros
				prevTotal = curTotal
				prevMicros = curMicros
				avgWinMs := 0.0
				if deltaReq > 0 {
					avgWinMs = (float64(deltaMicros) / 1000.0) / float64(deltaReq)
				}
				fmt.Printf("[%6.1fs] rps=%8d total=%9d 2xx=%d 4xx=%d(429:%d) 5xx=%d err=%d avg=%.2fms\n",
					time.Since(start).Seconds(), deltaReq, curTotal,
					live.status2xx.Load(), live.status4xx.Load(), live.status429.Load(),
					live.status5xx.Load(), live.errors.Load(), avgWinMs)
			}
		}
	}()

	wg.Wait()
	stopNow()
	<-monitorDone

	// Post-load recovery probe
	postStatus, postLatencyMs := probeSingleLatency(client, ringURLs[0], cfg.method, headerMap)

	report, sloFailed := mergeAndReport(cfg, specs, start, &live, shards, preStatus, preLatencyMs, postStatus, postLatencyMs)
	fmt.Println(report)

	if cfg.reportFile != "" {
		if err := os.WriteFile(cfg.reportFile, []byte(report), 0o644); err != nil {
			return 1, err
		}
	}
	if live.tripped.Load() || sloFailed {
		return 1, nil
	}
	return 0, nil
}

func checkCircuitBreaker(live *liveCounters, cfg config, stopNow func()) {
	if !cfg.circuitBreaker || live.tripped.Load() {
		return
	}
	tot := live.total.Load()
	if tot < 50 {
		return
	}
	bad := live.status5xx.Load() + live.errors.Load()
	if (float64(bad)*100.0)/float64(tot) >= cfg.abort5xxPct {
		if live.tripped.CompareAndSwap(false, true) {
			fmt.Printf("\n[!] CIRCUIT BREAKER TRIPPED: error/5xx rate >= %.1f%%. Halting load to protect target.\n", cfg.abort5xxPct)
			stopNow()
		}
	}
}

func mergeAndReport(
	cfg config,
	specs []weightedEndpoint,
	start time.Time,
	live *liveCounters,
	shards []workerShard,
	preStatus int,
	preLatencyMs float64,
	postStatus int,
	postLatencyMs float64,
) (string, bool) {
	elapsed := time.Since(start)
	var mergedHist [histBuckets]uint64
	var totalCount, overflow, apdexSat, apdexTol uint64
	var sumMs, sumSqMs, minMs, maxMs float64
	var stageCounts [4]uint64
	var stageSumMs [4]float64
	var stage5xxErr [4]uint64

	for _, s := range shards {
		if s.count == 0 {
			continue
		}
		if totalCount == 0 || s.minMs < minMs {
			minMs = s.minMs
		}
		if s.maxMs > maxMs {
			maxMs = s.maxMs
		}
		totalCount += s.count
		overflow += s.overflow
		sumMs += s.sumMs
		sumSqMs += s.sumSqMs
		apdexSat += s.apdexSat
		apdexTol += s.apdexTol
		for i := 0; i < 4; i++ {
			stageCounts[i] += s.stageCounts[i]
			stageSumMs[i] += s.stageSumMs[i]
			stage5xxErr[i] += s.stage5xxErr[i]
		}
		for b := 0; b < histBuckets; b++ {
			mergedHist[b] += s.hist[b]
		}
	}

	histQuantile := func(q float64) float64 {
		if totalCount == 0 {
			return 0
		}
		targetRank := uint64(math.Ceil((q / 100.0) * float64(totalCount)))
		if targetRank == 0 {
			targetRank = 1
		}
		var cum uint64
		for b := 0; b < histBuckets; b++ {
			cum += mergedHist[b]
			if cum >= targetRank {
				return (float64(b) + 0.5) * (float64(histStepMicro) / 1000.0)
			}
		}
		return maxMs
	}

	p50 := histQuantile(50.0)
	p75 := histQuantile(75.0)
	p90 := histQuantile(90.0)
	p95 := histQuantile(95.0)
	p99 := histQuantile(99.0)
	p999 := histQuantile(99.9)
	p9999 := histQuantile(99.99)

	avgMs := 0.0
	jitterMs := 0.0
	apdex := 0.0
	if totalCount > 0 {
		avgMs = sumMs / float64(totalCount)
		variance := (sumSqMs / float64(totalCount)) - (avgMs * avgMs)
		if variance > 0 {
			jitterMs = math.Sqrt(variance)
		}
		apdex = (float64(apdexSat) + 0.5*float64(apdexTol)) / float64(totalCount)
	}

	rps := float64(totalCount) / math.Max(elapsed.Seconds(), 0.001)
	s2xx := live.status2xx.Load()
	s3xx := live.status3xx.Load()
	s4xx := live.status4xx.Load()
	s429 := live.status429.Load()
	s5xx := live.status5xx.Load()
	errs := live.errors.Load()
	assertFails := live.assertFails.Load()
	errPct := 0.0
	if totalCount > 0 {
		errPct = (float64(s5xx+errs) * 100.0) / float64(totalCount)
	}

	slowdown := 1.0
	if preLatencyMs > 0 && postLatencyMs > 0 {
		slowdown = postLatencyMs / preLatencyMs
	}

	stageDur := math.Max(elapsed.Seconds()/4.0, 0.001)
	var stages []stageSummary
	stageLabels := [4]string{"Q1 (0-25%)", "Q2 (25-50%)", "Q3 (50-75%)", "Q4 (75-100%)"}
	kneeRPS := 0.0
	q1Avg := 0.0
	for i := 0; i < 4; i++ {
		c := stageCounts[i]
		sAvg := 0.0
		sErr := 0.0
		if c > 0 {
			sAvg = stageSumMs[i] / float64(c)
			sErr = (float64(stage5xxErr[i]) * 100.0) / float64(c)
		}
		sRPS := float64(c) / stageDur
		if i == 0 {
			q1Avg = sAvg
		} else if kneeRPS == 0 && ((q1Avg > 0 && sAvg > q1Avg*2.5) || sErr >= 5.0) {
			kneeRPS = sRPS
		}
		stages = append(stages, stageSummary{
			Stage:      i + 1,
			Label:      stageLabels[i],
			Requests:   c,
			RPS:        sRPS,
			AvgMs:      sAvg,
			ErrRatePct: sErr,
		})
	}

	sloFailed := false
	var sloNotes []string
	if cfg.sloP95Ms > 0 {
		if p95 > cfg.sloP95Ms {
			sloFailed = true
			sloNotes = append(sloNotes, fmt.Sprintf("FAIL: p95 %.2fms > %.2fms", p95, cfg.sloP95Ms))
		} else {
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: p95 %.2fms <= %.2fms", p95, cfg.sloP95Ms))
		}
	}
	if cfg.sloP99Ms > 0 {
		if p99 > cfg.sloP99Ms {
			sloFailed = true
			sloNotes = append(sloNotes, fmt.Sprintf("FAIL: p99 %.2fms > %.2fms", p99, cfg.sloP99Ms))
		} else {
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: p99 %.2fms <= %.2fms", p99, cfg.sloP99Ms))
		}
	}
	if cfg.sloErrPct > 0 {
		if errPct > cfg.sloErrPct {
			sloFailed = true
			sloNotes = append(sloNotes, fmt.Sprintf("FAIL: err/5xx %.2f%% > %.2f%%", errPct, cfg.sloErrPct))
		} else {
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: err/5xx %.2f%% <= %.2f%%", errPct, cfg.sloErrPct))
		}
	}
	if cfg.sloApdex > 0 {
		if apdex < cfg.sloApdex {
			sloFailed = true
			sloNotes = append(sloNotes, fmt.Sprintf("FAIL: Apdex %.3f < %.3f", apdex, cfg.sloApdex))
		} else {
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: Apdex %.3f >= %.3f", apdex, cfg.sloApdex))
		}
	}
	if cfg.sloMinRPS > 0 {
		if rps < cfg.sloMinRPS {
			sloFailed = true
			sloNotes = append(sloNotes, fmt.Sprintf("FAIL: RPS %.1f < %.1f", rps, cfg.sloMinRPS))
		} else {
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: RPS %.1f >= %.1f", rps, cfg.sloMinRPS))
		}
	}

	// Compute HMAC-SHA256 tamper-evident run receipt
	sigInput := fmt.Sprintf("hyperion|%s|%d|%.2f|%.2f|%t", cfg.target, totalCount, rps, p95, sloFailed)
	mac := hmac.New(sha256.New, []byte(guardCode))
	mac.Write([]byte(sigInput))
	receiptSig := hex.EncodeToString(mac.Sum(nil))[:24]

	if cfg.jsonFile != "" {
		payload := map[string]any{
			"engine":            "hyperion-go-sharded-hdr",
			"version":           "2.0.0",
			"guard_verified":    true,
			"receipt_hmac":      receiptSig,
			"target":            cfg.target,
			"endpoints":         specs,
			"profile":           cfg.profile,
			"duration_seconds":  elapsed.Seconds(),
			"workers":           cfg.workers,
			"total_requests":    totalCount,
			"average_rps":       rps,
			"saturation_knee":   kneeRPS,
			"apdex_score":       apdex,
			"status_2xx":        s2xx,
			"status_3xx":        s3xx,
			"status_4xx":        s4xx,
			"status_429_ratelim": s429,
			"status_5xx":        s5xx,
			"transport_errors":  errs,
			"assertion_failures": assertFails,
			"error_rate_pct":    errPct,
			"circuit_tripped":   live.tripped.Load(),
			"slo_failed":        sloFailed,
			"preflight_ms":      preLatencyMs,
			"postflight_ms":     postLatencyMs,
			"recovery_slowdown": slowdown,
			"stages":            stages,
			"latency_ms": map[string]float64{
				"min":    minMs,
				"avg":    avgMs,
				"stdev":  jitterMs,
				"p50":    p50,
				"p75":    p75,
				"p90":    p90,
				"p95":    p95,
				"p99":    p99,
				"p999":   p999,
				"p9999":  p9999,
				"max":    maxMs,
			},
		}
		if raw, err := json.MarshalIndent(payload, "", "  "); err == nil {
			_ = os.WriteFile(cfg.jsonFile, raw, 0o644)
		}
	}

	var b strings.Builder
	b.WriteString("\n## ⚡ Hyperion v2.0 Resilience, HDR & SLO Report\n\n")
	fmt.Fprintf(&b, "- Target: `%s` (%d weighted endpoint(s))\n", cfg.target, len(specs))
	fmt.Fprintf(&b, "- Profile / Method / Workers: `%s` / `%s` / `%d`\n", cfg.profile, cfg.method, cfg.workers)
	fmt.Fprintf(&b, "- Total Requests / Throughput: `%d` (`%.1f RPS` over `%s`)\n", totalCount, rps, elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "- Apdex Score (T=%.0fms): `%.3f` | Saturation Knee: `%s`\n",
		cfg.apdexTMs, apdex, func() string {
			if kneeRPS > 0 {
				return fmt.Sprintf("%.1f RPS", kneeRPS)
			}
			return "none (target scaled linearly)"
		}())
	fmt.Fprintf(&b, "- HTTP Status (2xx / 3xx / 4xx / 429-RL / 5xx / err): `%d / %d / %d / %d / %d / %d` (err rate: `%.2f%%`)\n",
		s2xx, s3xx, s4xx, s429, s5xx, errs, errPct)
	fmt.Fprintf(&b, "- Latency min / avg / jitter(σ) / max: `%.2fms / %.2fms / %.2fms / %.2fms`\n",
		minMs, avgMs, jitterMs, maxMs)
	fmt.Fprintf(&b, "- HDR Percentiles p50 / p75 / p90 / p95 / p99 / p99.9 / p99.99: `%.2fms / %.2fms / %.2fms / %.2fms / %.2fms / %.2fms / %.2fms`\n",
		p50, p75, p90, p95, p99, p999, p9999)
	fmt.Fprintf(&b, "- Pre/Post Recovery: `pre=%.2fms (HTTP %d) -> post=%.2fms (HTTP %d) [slowdown=%.2fx]`\n",
		preLatencyMs, preStatus, postLatencyMs, postStatus, slowdown)
	fmt.Fprintf(&b, "- Guard Receipt HMAC: `%s`\n", receiptSig)
	if len(sloNotes) > 0 {
		fmt.Fprintf(&b, "- SLO Gate: `%s`\n", strings.Join(sloNotes, " | "))
	}
	return b.String(), sloFailed
}

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range values {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("header must be in 'Name: value' format: %q", raw)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("header name cannot be empty")
		}
		out[key] = val
	}
	return out, nil
}

func loadPayload(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}

func parseRate(raw string) (float64, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return 0, fmt.Errorf("rate cannot be empty")
	}
	if s == "0" || s == "full" || s == "full-send" || s == "max" {
		return 0, nil
	}
	perMinute := false
	for _, suffix := range []string{"/min", "rpm", "permin", "per-minute"} {
		if strings.HasSuffix(s, suffix) {
			perMinute = true
			s = strings.TrimSuffix(s, suffix)
			break
		}
	}
	for _, suffix := range []string{"/s", "rps", "persec", "per-second"} {
		if strings.HasSuffix(s, suffix) {
			s = strings.TrimSuffix(s, suffix)
			break
		}
	}
	mult := 1.0
	if strings.HasSuffix(s, "k") {
		mult = 1_000
		s = strings.TrimSuffix(s, "k")
	} else if strings.HasSuffix(s, "m") {
		mult = 1_000_000
		s = strings.TrimSuffix(s, "m")
	} else if strings.HasSuffix(s, "g") {
		mult = 1_000_000_000
		s = strings.TrimSuffix(s, "g")
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid rate %q", raw)
	}
	v *= mult
	if perMinute {
		v /= 60.0
	}
	return v, nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "hyperion: %v\n", err)
	os.Exit(2)
}
