package main

import (
	"bufio"
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

// IMPROVEMENTS over v2.0:
//   1. --warmup <duration>: fires low-rate requests before the timed test begins so
//      connection pools are established, JIT is compiled, caches are warm, and the
//      first measured request isn't penalised by cold-start latency.
//   2. SSE streaming latency measurement: when a response carries
//      Content-Type: text/event-stream, Hyperion records the time-to-first-byte
//      (TTFB) separately from full-response latency. SSE streams on /api/chat
//      can stay open for 30s+; without TTFB the latency histogram is dominated
//      by stream duration rather than server-side processing time.
//   3. sseHits / sseFirstByteMs counters added to JSON telemetry output.

const (
	guardCode          = "XXLMILLEAMEAN"
	maxExternalRPS     = 9999.99
	maxExternalWorkers = 256
	maxPrivateRPS      = 3500000.0
	histBuckets        = 60000
	histStepMicro      = 100
)

type headerList []string

func (h *headerList) String() string      { return strings.Join(*h, ",") }
func (h *headerList) Set(value string) error { *h = append(*h, value); return nil }

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
	// IMPROVEMENT: warmup duration — fires requests at 10% rate before the timed test
	warmup         time.Duration
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
	// IMPROVEMENT: SSE streaming counters
	sseHits         atomic.Int64
	sseSumFirstByteUs atomic.Int64
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
	return fmt.Errorf("guard lock active: pass --guard %s (or set VIBE_HYPERION_GUARD)", guardCode)
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
	flag.StringVar(&cfg.endpoints, "endpoints", "", "Weighted subpaths (e.g. '/:50,/api/config:30')")
	flag.StringVar(&cfg.profile, "profile", "constant", "Load profile: constant, ramp, step, spike, sawtooth, stress-knee")
	flag.StringVar(&profileShort, "P", "", "Load profile")
	flag.StringVar(&cfg.method, "method", "GET", "HTTP method")
	flag.StringVar(&methodShort, "m", "", "HTTP method")
	flag.StringVar(&cfg.rate, "rate", "1000", "Target rate (RPS, k/m suffix, or 0 for full-send)")
	flag.StringVar(&rateShort, "r", "", "Target rate")
	flag.DurationVar(&cfg.duration, "duration", 15*time.Second, "Test duration e.g. 15s, 2m")
	flag.DurationVar(&durationShort, "d", 0, "Test duration")
	// IMPROVEMENT: --warmup flag
	flag.DurationVar(&cfg.warmup, "warmup", 0, "Warmup duration before the timed test (e.g. 5s). Sends requests at 10% rate to fill connection pools and JIT caches.")
	flag.IntVar(&cfg.workers, "workers", defaultWorkers, "Concurrent workers/goroutines")
	flag.IntVar(&workersShort, "w", 0, "Concurrent workers/goroutines")
	flag.StringVar(&cfg.payload, "payload", "", "Optional payload file (supports {{seq}}, {{timestamp}})")
	flag.StringVar(&payloadShort, "p", "", "Optional payload file")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-request timeout")
	flag.StringVar(&cfg.guard, "guard", "", "Required authorization guard code")
	flag.StringVar(&guardShort, "g", "", "Required authorization guard code")
	flag.BoolVar(&cfg.cacheBust, "cache-bust", false, "Append cache-busting token per request")
	flag.IntVar(&cfg.expectStatus, "expect-status", 0, "Expected HTTP status assertion")
	flag.StringVar(&cfg.expectText, "expect-text", "", "Expected response body substring assertion")
	flag.Float64Var(&cfg.apdexTMs, "apdex-t", 100.0, "Apdex T threshold in ms")
	flag.Float64Var(&cfg.sloP95Ms, "slo-p95", 0, "SLO: fail if p95 latency (ms) exceeds this")
	flag.Float64Var(&cfg.sloP99Ms, "slo-p99", 0, "SLO: fail if p99 latency (ms) exceeds this")
	flag.Float64Var(&cfg.sloErrPct, "slo-err-pct", 0, "SLO: fail if error/5xx rate (%) exceeds this")
	flag.Float64Var(&cfg.sloApdex, "slo-apdex", 0, "SLO: fail if Apdex score is below this")
	flag.Float64Var(&cfg.sloMinRPS, "slo-min-rps", 0, "SLO: fail if achieved RPS is below this")
	flag.BoolVar(&cfg.circuitBreaker, "circuit-breaker", true, "Auto-abort on high error rate")
	flag.Float64Var(&cfg.abort5xxPct, "abort-5xx-pct", 80.0, "Circuit-breaker error % threshold")
	flag.StringVar(&cfg.reportFile, "report-file", "", "Markdown report output path")
	flag.StringVar(&cfg.jsonFile, "json-out", "", "JSON telemetry output path")
	flag.Var(&cfg.headers, "headers", "Custom header 'Name: value' (repeatable)")
	flag.Var(&cfg.headers, "H", "Custom header 'Name: value' (repeatable)")
	flag.Parse()

	if targetShort != "" { cfg.target = targetShort }
	if methodShort != "" { cfg.method = methodShort }
	if rateShort != "" { cfg.rate = rateShort }
	if durationShort > 0 { cfg.duration = durationShort }
	if workersShort > 0 { cfg.workers = workersShort }
	if payloadShort != "" { cfg.payload = payloadShort }
	if guardShort != "" { cfg.guard = guardShort }
	if profileShort != "" { cfg.profile = profileShort }

	cfg.method = strings.ToUpper(strings.TrimSpace(cfg.method))
	cfg.profile = strings.ToLower(strings.TrimSpace(cfg.profile))
	if cfg.workers < 1 { cfg.workers = 1 }
	if cfg.duration <= 0 { return cfg, fmt.Errorf("duration must be > 0") }
	if cfg.timeout <= 0 { return cfg, fmt.Errorf("timeout must be > 0") }
	if cfg.apdexTMs <= 0 { cfg.apdexTMs = 100.0 }

	switch cfg.method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return cfg, fmt.Errorf("unsupported method %q", cfg.method)
	}
	switch cfg.profile {
	case "constant", "ramp", "step", "spike", "sawtooth", "stress-knee":
	default:
		return cfg, fmt.Errorf("unsupported profile %q", cfg.profile)
	}
	return cfg, nil
}

func validateTarget(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil { return fmt.Errorf("invalid URL: %w", err) }
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	host := parsed.Hostname()
	if host == "" { return fmt.Errorf("URL must include a host") }
	if strings.EqualFold(host, "localhost") { return nil }
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() { return nil }
		return fmt.Errorf("refusing %s: public IP not in authorized_targets.txt", host)
	}
	if loadAuthorizedHosts()[strings.ToLower(host)] { return nil }
	return fmt.Errorf("refusing %s: not in authorized_targets.txt", host)
}

func loadAuthorizedHosts() map[string]bool {
	allowed := map[string]bool{}
	path := findAuthorizedFile()
	if path == "" { return allowed }
	data, err := os.ReadFile(path)
	if err != nil { return allowed }
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.ContainsAny(line, "*?") { continue }
		host := line
		if strings.Contains(host, "://") {
			if u, e := url.Parse(host); e == nil && u.Hostname() != "" { host = u.Hostname() }
		}
		if h, _, e := net.SplitHostPort(host); e == nil { host = h }
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" { allowed[host] = true }
	}
	return allowed
}

func findAuthorizedFile() string {
	dir, err := os.Getwd()
	if err != nil { return "" }
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "authorized_targets.txt")
		if _, err := os.Stat(candidate); err == nil { return candidate }
		parent := filepath.Dir(dir)
		if parent == dir { break }
		dir = parent
	}
	return ""
}

func isPublicInternetTarget(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil { return true }
	host := parsed.Hostname()
	if host == "" || strings.EqualFold(host, "localhost") { return false }
	if ip := net.ParseIP(host); ip != nil {
		return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 { return true }
	for _, ip := range ips {
		if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) { return true }
	}
	return false
}

func validateTrafficLimits(cfg config, rate float64) error {
	if isPublicInternetTarget(cfg.target) {
		if rate <= 0 { return fmt.Errorf("full-send disabled for public targets") }
		if rate > maxExternalRPS { return fmt.Errorf("rate %.2f exceeds %.2f rps public cap", rate, maxExternalRPS) }
		if cfg.workers > maxExternalWorkers { return fmt.Errorf("workers %d exceeds %d public cap", cfg.workers, maxExternalWorkers) }
		return nil
	}
	if rate > maxPrivateRPS { return fmt.Errorf("rate %.2f exceeds %.0f rps private cap", rate, maxPrivateRPS) }
	return nil
}

func buildWeightedRing(baseRaw, csv string) ([]string, []weightedEndpoint, error) {
	base, err := url.Parse(baseRaw)
	if err != nil { return nil, nil, err }
	if strings.TrimSpace(csv) == "" {
		return []string{baseRaw}, []weightedEndpoint{{URL: baseRaw, Weight: 1}}, nil
	}
	var ring []string
	var specs []weightedEndpoint
	for _, item := range strings.Split(csv, ",") {
		raw := strings.TrimSpace(item)
		if raw == "" { continue }
		weight := 1
		sub := raw
		if idx := strings.LastIndex(raw, ":"); idx > 0 && !strings.HasPrefix(raw, "http") {
			if w, e := strconv.Atoi(raw[idx+1:]); e == nil && w > 0 && w <= 100 {
				weight = w; sub = raw[:idx]
			}
		}
		if !strings.HasPrefix(sub, "/") { sub = "/" + sub }
		rel, e := url.Parse(sub)
		if e != nil { continue }
		resolved := base.ResolveReference(rel)
		if strings.EqualFold(resolved.Host, base.Host) {
			uStr := resolved.String()
			specs = append(specs, weightedEndpoint{URL: uStr, Weight: weight})
			for i := 0; i < weight; i++ { ring = append(ring, uStr) }
		}
	}
	if len(ring) == 0 {
		return []string{baseRaw}, []weightedEndpoint{{URL: baseRaw, Weight: 1}}, nil
	}
	return ring, specs, nil
}

func effectiveRate(base float64, profile string, progress float64) float64 {
	if base <= 0 { return 0 }
	p := math.Max(0, math.Min(1, progress))
	switch profile {
	case "ramp":   return base * (0.10 + 0.90*p)
	case "step", "stress-knee":
		switch { case p < 0.25: return base * 0.25; case p < 0.50: return base * 0.50; case p < 0.75: return base * 0.75; default: return base }
	case "spike":
		if p >= 0.40 && p <= 0.65 { return base }
		return base * 0.20
	case "sawtooth": return base * (0.20 + 0.80*math.Mod(p*4.0, 1.0))
	default: return base
	}
}

func probeSingle(client *http.Client, target, method string, headers map[string]string) (int, float64) {
	t0 := time.Now()
	req, err := http.NewRequest(method, target, nil)
	if err != nil { return 0, 0 }
	req.Header.Set("User-Agent", "Hyperion/2.0 authorized-security-test")
	for k, v := range headers { req.Header.Set(k, v) }
	resp, err := client.Do(req)
	if err != nil { return 0, float64(time.Since(t0).Microseconds()) / 1000.0 }
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, float64(time.Since(t0).Microseconds()) / 1000.0
}

// IMPROVEMENT: runWarmup fires requests at 10% of the target rate for `dur`
// so TCP connections are established, TLS sessions are cached, JIT is compiled,
// and server-side caches are primed before the timed measurement begins.
func runWarmup(client *http.Client, cfg config, ringURLs []string, payloadTemplate []byte,
	headerMap map[string]string, dur time.Duration) {
	if dur <= 0 { return }
	rate, _ := parseRate(cfg.rate)
	warmupRate := math.Max(rate*0.10, 1)
	fmt.Printf("[warmup] Firing %.0f RPS for %s to prime connection pools and caches...\n", warmupRate, dur)

	done := make(chan struct{})
	go func() { time.Sleep(dur); close(done) }()

	tick := 10 * time.Millisecond
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	var carry float64
	var idx int64
	for {
		select {
		case <-done: fmt.Println("[warmup] done — starting timed test")
			return
		case <-ticker.C:
			carry += warmupRate * tick.Seconds()
			count := int(carry)
			if count < 1 { continue }
			carry -= float64(count)
			for i := 0; i < count; i++ {
				targetURL := ringURLs[atomic.AddInt64(&idx, 1)%int64(len(ringURLs))]
				var body io.Reader
				if len(payloadTemplate) > 0 { body = bytes.NewReader(payloadTemplate) }
				req, err := http.NewRequest(cfg.method, targetURL, body)
				if err != nil { continue }
				req.Header.Set("User-Agent", "Hyperion/2.0 warmup")
				for k, v := range headerMap { req.Header.Set(k, v) }
				resp, err := client.Do(req)
				if err != nil { continue }
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
	}
}

func run(cfg config) (int, error) {
	rate, err := parseRate(cfg.rate)
	if err != nil { return 2, err }
	if err := validateTrafficLimits(cfg, rate); err != nil { return 2, err }
	ringURLs, specs, err := buildWeightedRing(cfg.target, cfg.endpoints)
	if err != nil { return 2, err }
	payloadTemplate, err := loadPayload(cfg.payload)
	if err != nil { return 2, err }
	headerMap, err := parseHeaders(cfg.headers)
	if err != nil { return 2, err }

	runtime.GOMAXPROCS(runtime.NumCPU())
	dialer := &net.Dialer{Timeout: cfg.timeout, KeepAlive: 60 * time.Second}
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

	preStatus, preLatencyMs := probeSingle(client, ringURLs[0], cfg.method, headerMap)

	fmt.Println("================================================================")
	fmt.Println(" ⚡ HYPERION v2.1 — 14x Sharded Resilience, HDR & SLO Engine")
	fmt.Println("================================================================")
	fmt.Printf("target=%s endpoints=%d profile=%s method=%s duration=%s workers=%d rate=%s\n",
		cfg.target, len(specs), cfg.profile, cfg.method, cfg.duration, cfg.workers, cfg.rate)
	fmt.Printf("preflight: status=%d latency=%.2fms | guard=VERIFIED\n", preStatus, preLatencyMs)
	if cfg.warmup > 0 {
		fmt.Printf("warmup: %s\n", cfg.warmup)
	}
	fmt.Println()

	// IMPROVEMENT: run warmup phase before the timed test
	runWarmup(client, cfg, ringURLs, payloadTemplate, headerMap, cfg.warmup)

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopNow := func() { stopOnce.Do(func() { close(stop) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; fmt.Println("\nSIGINT — draining..."); stopNow() }()

	start := time.Now()
	go func() { time.Sleep(cfg.duration); stopNow() }()

	var live liveCounters
	shards := make([]workerShard, cfg.workers)
	var wg sync.WaitGroup
	hasDynamicMacros := bytes.Contains(payloadTemplate, []byte("{{"))
	expectBytes := []byte(cfg.expectText)

	workerBaseRate := 0.0
	if rate > 0 { workerBaseRate = rate / float64(cfg.workers) }

	for wID := 0; wID < cfg.workers; wID++ {
		wg.Add(1)
		go func(id int, shard *workerShard) {
			defer wg.Done()
			nextSlot := time.Now()
			localSeq := uint64(id)

			for {
				select {
				case <-stop: return
				default:
				}
				now := time.Now()
				elapsed := now.Sub(start)
				if elapsed >= cfg.duration { return }
				progress := elapsed.Seconds() / math.Max(cfg.duration.Seconds(), 0.001)
				stageIdx := int(progress * 4.0)
				if stageIdx < 0 { stageIdx = 0 } else if stageIdx > 3 { stageIdx = 3 }

				if workerBaseRate > 0 {
					eff := effectiveRate(workerBaseRate, cfg.profile, progress)
					if eff > 0.1 {
						interval := time.Duration(float64(time.Second) / eff)
						if now.Before(nextSlot) {
							select {
							case <-stop: return
							case <-time.After(nextSlot.Sub(now)):
							}
						}
						nextSlot = nextSlot.Add(interval)
						if time.Now().Sub(nextSlot) > 50*time.Millisecond { nextSlot = time.Now() }
					}
				}

				seq := live.total.Add(1)
				targetURL := ringURLs[int(localSeq)%len(ringURLs)]
				localSeq += uint64(cfg.workers)

				if cfg.cacheBust {
					sep := "?"; if strings.Contains(targetURL, "?") { sep = "&" }
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
				if len(bodyBytes) > 0 { bodyReader = bytes.NewReader(bodyBytes) }
				req, err := http.NewRequest(cfg.method, targetURL, bodyReader)
				if err != nil { live.errors.Add(1); shard.stage5xxErr[stageIdx]++; continue }

				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Sec-CH-UA", `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`)
				req.Header.Set("Sec-CH-UA-Mobile", "?0")
				req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				for k, v := range headerMap { req.Header.Set(k, v) }
				if cfg.cacheBust { req.Header.Set("X-Request-Sequence", strconv.FormatInt(seq, 10)) }
				if len(bodyBytes) > 0 && req.Header.Get("Content-Type") == "" {
					req.Header.Set("Content-Type", "application/json")
				}

				resp, err := client.Do(req)
				latMicros := time.Since(reqStart).Microseconds()
				latMs := float64(latMicros) / 1000.0
				live.sumMicros.Add(latMicros)

				shard.count++
				shard.sumMs += latMs
				shard.sumSqMs += latMs * latMs
				if shard.count == 1 || latMs < shard.minMs { shard.minMs = latMs }
				if latMs > shard.maxMs { shard.maxMs = latMs }
				bucket := int(latMicros / histStepMicro)
				if bucket < 0 { bucket = 0 }
				if bucket < histBuckets { shard.hist[bucket]++ } else { shard.overflow++ }
				shard.stageCounts[stageIdx]++
				shard.stageSumMs[stageIdx] += latMs

				if err != nil { live.errors.Add(1); shard.stage5xxErr[stageIdx]++; checkCircuitBreaker(&live, cfg, stopNow); continue }

				ct := resp.Header.Get("Content-Type")
				var nBytes int64
				assertOk := true

				// IMPROVEMENT: SSE streaming TTFB measurement.
				// For text/event-stream responses, record time-to-first-byte separately
				// from full-response latency. A 30s open SSE stream would otherwise
				// dominate the latency histogram and hide real server processing time.
				if strings.Contains(ct, "text/event-stream") {
					ttfbUs := time.Since(reqStart).Microseconds()
					live.sseHits.Add(1)
					live.sseSumFirstByteUs.Add(ttfbUs)
					// Drain SSE stream without blocking the histogram measurement.
					// We record the TTFB latency (headers received) rather than stream end.
					scanner := bufio.NewScanner(resp.Body)
					var sseLines int
					for scanner.Scan() && sseLines < 50 {
						nBytes += int64(len(scanner.Bytes()))
						sseLines++
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					// Override latMs with TTFB for histogram accuracy
					latMicros = ttfbUs
					latMs = float64(latMicros) / 1000.0
					// Update shard with TTFB-based latency
					shard.sumMs = shard.sumMs - shard.stageSumMs[stageIdx] // undo full
					shard.stageSumMs[stageIdx] += latMs
					shard.sumMs += shard.stageSumMs[stageIdx]
					if latMs < shard.minMs { shard.minMs = latMs }
					bucket2 := int(latMicros / histStepMicro)
					if bucket2 >= 0 && bucket2 < histBuckets { shard.hist[bucket2]++ }
				} else if len(expectBytes) > 0 {
					buf, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
					nBytes = int64(len(buf))
					if !bytes.Contains(buf, expectBytes) { assertOk = false }
					_, _ = io.Copy(io.Discard, resp.Body)
				} else {
					nBytes, _ = io.Copy(io.Discard, resp.Body)
				}
				_ = resp.Body.Close()
				live.bytes.Add(nBytes)

				// Edge cache / WAF header inspection
				cacheHdr := strings.ToLower(resp.Header.Get("CF-Cache-Status") + " " + resp.Header.Get("X-Vercel-Cache") + " " + resp.Header.Get("X-Cache"))
				switch {
				case strings.Contains(cacheHdr, "hit") || strings.Contains(cacheHdr, "prerender") || strings.Contains(cacheHdr, "stale"): live.cacheHits.Add(1)
				case strings.Contains(cacheHdr, "miss") || strings.Contains(cacheHdr, "expired") || strings.Contains(cacheHdr, "revalidated"): live.cacheMisses.Add(1)
				case strings.Contains(cacheHdr, "dynamic"): live.cacheDynamic.Add(1)
				case strings.Contains(cacheHdr, "bypass"): live.cacheBypass.Add(1)
				}
				if resp.Header.Get("CF-Mitigated") != "" || resp.Header.Get("X-Vercel-Mitigated") != "" || resp.Header.Get("X-Amzn-Waf-Action") != "" {
					live.wafChallenges.Add(1)
				}
				errHdr := strings.ToLower(resp.Header.Get("X-Vercel-Error") + " " + resp.Header.Get("X-Amzn-ErrorType"))
				if resp.StatusCode == 504 || strings.Contains(errHdr, "timeout") || strings.Contains(errHdr, "throttl") || strings.Contains(errHdr, "toomanyrequests") {
					live.serverlessThrottles.Add(1)
				}

				if cfg.expectStatus > 0 && resp.StatusCode != cfg.expectStatus { assertOk = false }
				if !assertOk { live.assertFails.Add(1) }

				st := resp.StatusCode
				switch {
				case st >= 200 && st < 300:
					live.status2xx.Add(1)
					if latMs <= cfg.apdexTMs { shard.apdexSat++ } else if latMs <= cfg.apdexTMs*4.0 { shard.apdexTol++ }
				case st >= 300 && st < 400:
					live.status3xx.Add(1)
					if latMs <= cfg.apdexTMs { shard.apdexSat++ } else if latMs <= cfg.apdexTMs*4.0 { shard.apdexTol++ }
				case st == 429: live.status4xx.Add(1); live.status429.Add(1)
				case st >= 400 && st < 500: live.status4xx.Add(1)
				case st >= 500 && st < 600:
					live.status5xx.Add(1)
					if st >= 520 && st <= 526 { live.statusCF52x.Add(1) }
					shard.stage5xxErr[stageIdx]++
					checkCircuitBreaker(&live, cfg, stopNow)
				default: live.statusOther.Add(1)
				}
			}
		}(wID, &shards[wID])
	}

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var prevTotal, prevMicros int64
		for {
			select {
			case <-stop: return
			case <-ticker.C:
				curTotal := live.total.Load()
				curMicros := live.sumMicros.Load()
				deltaReq := curTotal - prevTotal
				deltaMicros := curMicros - prevMicros
				prevTotal = curTotal
				prevMicros = curMicros
				avgWinMs := 0.0
				if deltaReq > 0 { avgWinMs = (float64(deltaMicros) / 1000.0) / float64(deltaReq) }
				fmt.Printf("[%6.1fs] rps=%8d total=%9d 2xx=%d 4xx=%d(429:%d) 5xx=%d err=%d avg=%.2fms sse=%d\n",
					time.Since(start).Seconds(), deltaReq, curTotal,
					live.status2xx.Load(), live.status4xx.Load(), live.status429.Load(),
					live.status5xx.Load(), live.errors.Load(), avgWinMs, live.sseHits.Load())
			}
		}
	}()

	wg.Wait()
	stopNow()
	<-monitorDone

	postStatus, postLatencyMs := probeSingle(client, ringURLs[0], cfg.method, headerMap)
	report, sloFailed := mergeAndReport(cfg, specs, start, &live, shards, preStatus, preLatencyMs, postStatus, postLatencyMs)
	fmt.Println(report)

	if cfg.reportFile != "" {
		if err := os.WriteFile(cfg.reportFile, []byte(report), 0o644); err != nil { return 1, err }
	}
	if live.tripped.Load() || sloFailed { return 1, nil }
	return 0, nil
}

func checkCircuitBreaker(live *liveCounters, cfg config, stopNow func()) {
	if !cfg.circuitBreaker || live.tripped.Load() { return }
	tot := live.total.Load()
	if tot < 50 { return }
	bad := live.status5xx.Load() + live.errors.Load()
	if (float64(bad)*100.0)/float64(tot) >= cfg.abort5xxPct {
		if live.tripped.CompareAndSwap(false, true) {
			fmt.Printf("\n[!] CIRCUIT BREAKER TRIPPED: error rate >= %.1f%%. Halting.\n", cfg.abort5xxPct)
			stopNow()
		}
	}
}

func mergeAndReport(cfg config, specs []weightedEndpoint, start time.Time,
	live *liveCounters, shards []workerShard, preStatus int, preLatencyMs float64, postStatus int, postLatencyMs float64) (string, bool) {

	elapsed := time.Since(start)
	var mergedHist [histBuckets]uint64
	var totalCount, overflow, apdexSat, apdexTol uint64
	var sumMs, sumSqMs, minMs, maxMs float64
	var stageCounts [4]uint64
	var stageSumMs [4]float64
	var stage5xxErr [4]uint64

	for _, s := range shards {
		if s.count == 0 { continue }
		if totalCount == 0 || s.minMs < minMs { minMs = s.minMs }
		if s.maxMs > maxMs { maxMs = s.maxMs }
		totalCount += s.count; overflow += s.overflow
		sumMs += s.sumMs; sumSqMs += s.sumSqMs
		apdexSat += s.apdexSat; apdexTol += s.apdexTol
		for i := 0; i < 4; i++ { stageCounts[i] += s.stageCounts[i]; stageSumMs[i] += s.stageSumMs[i]; stage5xxErr[i] += s.stage5xxErr[i] }
		for b := 0; b < histBuckets; b++ { mergedHist[b] += s.hist[b] }
	}

	hq := func(q float64) float64 {
		if totalCount == 0 { return 0 }
		rank := uint64(math.Ceil((q / 100.0) * float64(totalCount))); if rank == 0 { rank = 1 }
		var cum uint64
		for b := 0; b < histBuckets; b++ { cum += mergedHist[b]; if cum >= rank { return (float64(b)+0.5)*(float64(histStepMicro)/1000.0) } }
		return maxMs
	}
	p50, p75, p90, p95, p99, p999, p9999 := hq(50), hq(75), hq(90), hq(95), hq(99), hq(99.9), hq(99.99)

	avgMs, jitterMs, apdex := 0.0, 0.0, 0.0
	if totalCount > 0 {
		avgMs = sumMs / float64(totalCount)
		if v := (sumSqMs/float64(totalCount)) - (avgMs*avgMs); v > 0 { jitterMs = math.Sqrt(v) }
		apdex = (float64(apdexSat) + 0.5*float64(apdexTol)) / float64(totalCount)
	}

	rps := float64(totalCount) / math.Max(elapsed.Seconds(), 0.001)
	s2xx, s3xx, s4xx, s429, s5xx, errs := live.status2xx.Load(), live.status3xx.Load(), live.status4xx.Load(), live.status429.Load(), live.status5xx.Load(), live.errors.Load()
	assertFails := live.assertFails.Load()
	errPct := 0.0; if totalCount > 0 { errPct = (float64(s5xx+errs)*100.0)/float64(totalCount) }
	slowdown := 1.0; if preLatencyMs > 0 && postLatencyMs > 0 { slowdown = postLatencyMs/preLatencyMs }

	// SSE stats
	sseHits := live.sseHits.Load()
	sseAvgTtfbMs := 0.0
	if sseHits > 0 { sseAvgTtfbMs = (float64(live.sseSumFirstByteUs.Load()) / 1000.0) / float64(sseHits) }

	stageDur := math.Max(elapsed.Seconds()/4.0, 0.001)
	var stages []stageSummary
	stageLabels := [4]string{"Q1 (0-25%)", "Q2 (25-50%)", "Q3 (50-75%)", "Q4 (75-100%)"}
	kneeRPS, q1Avg := 0.0, 0.0
	for i := 0; i < 4; i++ {
		c := stageCounts[i]; sAvg, sErr := 0.0, 0.0
		if c > 0 { sAvg = stageSumMs[i]/float64(c); sErr = (float64(stage5xxErr[i])*100.0)/float64(c) }
		sRPS := float64(c)/stageDur
		if i == 0 { q1Avg = sAvg } else if kneeRPS == 0 && ((q1Avg > 0 && sAvg > q1Avg*2.5) || sErr >= 5.0) { kneeRPS = sRPS }
		stages = append(stages, stageSummary{Stage: i+1, Label: stageLabels[i], Requests: c, RPS: sRPS, AvgMs: sAvg, ErrRatePct: sErr})
	}

	sloFailed := false
	var sloNotes []string
	checkSLO := func(label string, actual, threshold float64, gt bool) {
		if threshold <= 0 { return }
		if gt && actual > threshold { sloFailed = true; sloNotes = append(sloNotes, fmt.Sprintf("FAIL: %s %.2f > %.2f", label, actual, threshold))
		} else if !gt && actual < threshold { sloFailed = true; sloNotes = append(sloNotes, fmt.Sprintf("FAIL: %s %.2f < %.2f", label, actual, threshold))
		} else {
			dir := "<="; if !gt { dir = ">=" }
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: %s %.2f %s %.2f", label, actual, dir, threshold))
		}
	}
	checkSLO("p95ms", p95, cfg.sloP95Ms, true)
	checkSLO("p99ms", p99, cfg.sloP99Ms, true)
	checkSLO("err%", errPct, cfg.sloErrPct, true)
	checkSLO("apdex", apdex, cfg.sloApdex, false)
	checkSLO("rps", rps, cfg.sloMinRPS, false)

	sigInput := fmt.Sprintf("hyperion|%s|%d|%.2f|%.2f|%t", cfg.target, totalCount, rps, p95, sloFailed)
	mac := hmac.New(sha256.New, []byte(guardCode))
	mac.Write([]byte(sigInput))
	receiptSig := hex.EncodeToString(mac.Sum(nil))[:24]

	if cfg.jsonFile != "" {
		out := map[string]any{
			"engine": "hyperion-go-sharded-hdr", "version": "2.1.0",
			"guard_verified": true, "receipt_hmac": receiptSig,
			"target": cfg.target, "endpoints": specs, "profile": cfg.profile,
			"duration_seconds": elapsed.Seconds(), "workers": cfg.workers,
			"total_requests": totalCount, "average_rps": rps, "saturation_knee": kneeRPS,
			"apdex_score": apdex, "status_2xx": s2xx, "status_3xx": s3xx,
			"status_4xx": s4xx, "status_429_ratelim": s429, "status_5xx": s5xx,
			"transport_errors": errs, "assertion_failures": assertFails, "error_rate_pct": errPct,
			"circuit_tripped": live.tripped.Load(), "slo_failed": sloFailed,
			"preflight_ms": preLatencyMs, "postflight_ms": postLatencyMs, "recovery_slowdown": slowdown,
			// IMPROVEMENT: SSE counters in JSON telemetry
			"sse_hits": sseHits, "sse_avg_ttfb_ms": sseAvgTtfbMs,
			"stages": stages,
			"latency_ms": map[string]float64{
				"min": minMs, "avg": avgMs, "stdev": jitterMs,
				"p50": p50, "p75": p75, "p90": p90, "p95": p95, "p99": p99, "p999": p999, "p9999": p9999, "max": maxMs,
			},
		}
		if raw, err := json.MarshalIndent(out, "", "  "); err == nil { _ = os.WriteFile(cfg.jsonFile, raw, 0o644) }
	}

	var b strings.Builder
	b.WriteString("\n## ⚡ Hyperion v2.1 Resilience, HDR & SLO Report\n\n")
	fmt.Fprintf(&b, "- Target: `%s` (%d endpoint(s))\n", cfg.target, len(specs))
	fmt.Fprintf(&b, "- Profile / Method / Workers: `%s` / `%s` / `%d`\n", cfg.profile, cfg.method, cfg.workers)
	if cfg.warmup > 0 { fmt.Fprintf(&b, "- Warmup: `%s` at 10%% rate before timed test\n", cfg.warmup) }
	fmt.Fprintf(&b, "- Total Requests / Throughput: `%d` (`%.1f RPS` over `%s`)\n", totalCount, rps, elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "- Apdex (T=%.0fms): `%.3f` | Saturation Knee: `%s`\n", cfg.apdexTMs, apdex, func() string {
		if kneeRPS > 0 { return fmt.Sprintf("%.1f RPS", kneeRPS) }; return "none (scaled linearly)"
	}())
	fmt.Fprintf(&b, "- HTTP (2xx/3xx/4xx/429/5xx/err): `%d/%d/%d/%d/%d/%d` err=`%.2f%%`\n", s2xx, s3xx, s4xx, s429, s5xx, errs, errPct)
	fmt.Fprintf(&b, "- Latency min/avg/jitter(σ)/max: `%.2fms/%.2fms/%.2fms/%.2fms`\n", minMs, avgMs, jitterMs, maxMs)
	fmt.Fprintf(&b, "- HDR p50/p75/p90/p95/p99/p99.9/p99.99: `%.2fms/%.2fms/%.2fms/%.2fms/%.2fms/%.2fms/%.2fms`\n", p50, p75, p90, p95, p99, p999, p9999)
	if sseHits > 0 { fmt.Fprintf(&b, "- SSE Streaming: `%d` stream(s) | avg TTFB: `%.2fms`\n", sseHits, sseAvgTtfbMs) }
	fmt.Fprintf(&b, "- Pre/Post Recovery: `pre=%.2fms(HTTP %d) → post=%.2fms(HTTP %d) [%.2fx]`\n", preLatencyMs, preStatus, postLatencyMs, postStatus, slowdown)
	fmt.Fprintf(&b, "- Guard Receipt HMAC: `%s`\n", receiptSig)
	if len(sloNotes) > 0 { fmt.Fprintf(&b, "- SLO Gate: `%s`\n", strings.Join(sloNotes, " | ")) }
	return b.String(), sloFailed
}

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range values {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 { return nil, fmt.Errorf("header must be 'Name: value': %q", raw) }
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if k == "" { return nil, fmt.Errorf("header name cannot be empty") }
		out[k] = v
	}
	return out, nil
}

func loadPayload(path string) ([]byte, error) {
	if path == "" { return nil, nil }
	return os.ReadFile(path)
}

func parseRate(raw string) (float64, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" { return 0, fmt.Errorf("rate cannot be empty") }
	if s == "0" || s == "full" || s == "full-send" || s == "max" { return 0, nil }
	perMin := false
	for _, suf := range []string{"/min", "rpm", "permin", "per-minute"} {
		if strings.HasSuffix(s, suf) { perMin = true; s = strings.TrimSuffix(s, suf); break }
	}
	for _, suf := range []string{"/s", "rps", "persec", "per-second"} {
		if strings.HasSuffix(s, suf) { s = strings.TrimSuffix(s, suf); break }
	}
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "k"): mult = 1_000; s = strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "m"): mult = 1_000_000; s = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "g"): mult = 1_000_000_000; s = strings.TrimSuffix(s, "g")
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 { return 0, fmt.Errorf("invalid rate %q", raw) }
	v *= mult
	if perMin { v /= 60.0 }
	return v, nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "hyperion: %v\n", err)
	os.Exit(2)
}
