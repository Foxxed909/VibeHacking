package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
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
	maxPrivateRPS      = 250000.0
	reservoirCap       = 500000
)

type headerList []string

func (h *headerList) String() string {
	return strings.Join(*h, ",")
}

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
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
	sloP95Ms       float64
	sloErrPct      float64
	circuitBreaker bool
	reportFile     string
	jsonFile       string
}

type sampleResult struct {
	status  int
	latency time.Duration
	bytes   int64
	err     string
}

type metrics struct {
	total       int64
	status2xx   int64
	status3xx   int64
	status4xx   int64
	status5xx   int64
	statusOther int64
	errors      int64
	bytes       int64
	latenciesMs []float64
	sumMs       float64
	sumSqMs     float64
	minMs       float64
	maxMs       float64
	tripped     bool
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
	flag.StringVar(&cfg.endpoints, "endpoints", "", "Comma-separated subpaths on the same host (e.g. '/,/api/config,/api/guestbook')")
	flag.StringVar(&cfg.profile, "profile", "constant", "Load profile: constant, ramp, step, spike")
	flag.StringVar(&profileShort, "P", "", "Load profile: constant, ramp, step, spike")
	flag.StringVar(&cfg.method, "method", "GET", "HTTP method")
	flag.StringVar(&methodShort, "m", "", "HTTP method")
	flag.StringVar(&cfg.rate, "rate", "1000", "Target rate (RPS, e.g. 5000, 50k, 120000rpm, or 0 for local full-send)")
	flag.StringVar(&rateShort, "r", "", "Target rate")
	flag.DurationVar(&cfg.duration, "duration", 15*time.Second, "Test duration, e.g. 15s, 2m")
	flag.DurationVar(&durationShort, "d", 0, "Test duration")
	flag.IntVar(&cfg.workers, "workers", defaultWorkers, "Concurrent workers/goroutines")
	flag.IntVar(&workersShort, "w", 0, "Concurrent workers/goroutines")
	flag.StringVar(&cfg.payload, "payload", "", "Optional payload file for POST/PUT/PATCH")
	flag.StringVar(&payloadShort, "p", "", "Optional payload file")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-request timeout")
	flag.StringVar(&cfg.guard, "guard", "", "Required authorization guard code")
	flag.StringVar(&guardShort, "g", "", "Required authorization guard code")
	flag.Float64Var(&cfg.sloP95Ms, "slo-p95", 0, "Optional SLO gate: fail if p95 latency (ms) exceeds this threshold")
	flag.Float64Var(&cfg.sloErrPct, "slo-err-pct", 0, "Optional SLO gate: fail if error/5xx rate (%) exceeds this threshold")
	flag.BoolVar(&cfg.circuitBreaker, "circuit-breaker", true, "Auto-abort if target 5xx/error rate exceeds 80% after 50+ requests")
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

	switch cfg.method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return cfg, fmt.Errorf("unsupported method %q", cfg.method)
	}

	switch cfg.profile {
	case "constant", "ramp", "step", "spike":
	default:
		return cfg, fmt.Errorf("unsupported profile %q (use constant, ramp, step, or spike)", cfg.profile)
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

func buildScenarioURLs(baseRaw, endpointsCSV string) ([]string, error) {
	baseURL, err := url.Parse(baseRaw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(endpointsCSV) == "" {
		return []string{baseRaw}, nil
	}
	var out []string
	for _, item := range strings.Split(endpointsCSV, ",") {
		sub := strings.TrimSpace(item)
		if sub == "" {
			continue
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
			out = append(out, resolved.String())
		}
	}
	if len(out) == 0 {
		out = append(out, baseRaw)
	}
	return out, nil
}

func effectiveRate(baseRate float64, profile string, progress float64) float64 {
	if baseRate <= 0 {
		return 0
	}
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	switch profile {
	case "ramp":
		return baseRate * (0.10 + 0.90*progress)
	case "step":
		switch {
		case progress < 0.25:
			return baseRate * 0.25
		case progress < 0.50:
			return baseRate * 0.50
		case progress < 0.75:
			return baseRate * 0.75
		default:
			return baseRate
		}
	case "spike":
		if progress >= 0.40 && progress <= 0.65 {
			return baseRate
		}
		return baseRate * 0.25
	default:
		return baseRate
	}
}

func run(cfg config) (int, error) {
	rate, err := parseRate(cfg.rate)
	if err != nil {
		return 2, err
	}
	if err := validateTrafficLimits(cfg, rate); err != nil {
		return 2, err
	}
	scenarioURLs, err := buildScenarioURLs(cfg.target, cfg.endpoints)
	if err != nil {
		return 2, err
	}
	payload, err := loadPayload(cfg.payload)
	if err != nil {
		return 2, err
	}
	headerMap, err := parseHeaders(cfg.headers)
	if err != nil {
		return 2, err
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          cfg.workers * 4,
		MaxIdleConnsPerHost:   cfg.workers * 4,
		MaxConnsPerHost:       cfg.workers * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.timeout,
		ResponseHeaderTimeout: cfg.timeout,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: cfg.timeout}

	stop := make(chan struct{})
	var stopOnce sync.Once
	var trippedFlag atomic.Bool
	stopNow := func() { stopOnce.Do(func() { close(stop) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Println("\nSIGINT received. Draining Hyperion workers...")
		stopNow()
	}()

	start := time.Now()
	go func() {
		time.Sleep(cfg.duration)
		stopNow()
	}()

	jobs := make(chan int, cfg.workers*8)
	results := make(chan sampleResult, cfg.workers*16)
	var wg sync.WaitGroup

	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobs {
				reqStart := time.Now()
				targetURL := scenarioURLs[seq%len(scenarioURLs)]
				req, err := newRequest(targetURL, cfg.method, payload, headerMap)
				if err != nil {
					results <- sampleResult{status: 0, latency: time.Since(reqStart), err: err.Error()}
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					results <- sampleResult{status: 0, latency: time.Since(reqStart), err: err.Error()}
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				results <- sampleResult{status: resp.StatusCode, latency: time.Since(reqStart), bytes: n}
			}
		}()
	}

	go producer(stop, jobs, rate, cfg.profile, start, cfg.duration)
	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Println("================================================")
	fmt.Println(" ⚡ HYPERION — Next-Gen Resilience & SLO Engine")
	fmt.Println("================================================")
	fmt.Printf("target=%s endpoints=%d profile=%s method=%s duration=%s workers=%d rate=%s\n",
		cfg.target, len(scenarioURLs), cfg.profile, cfg.method, cfg.duration, cfg.workers, cfg.rate)

	final := collect(results, start, cfg.circuitBreaker, stopNow, &trippedFlag)
	final.tripped = trippedFlag.Load()
	report, sloFailed := buildReports(cfg, scenarioURLs, start, final)
	fmt.Println(report)

	if cfg.reportFile != "" {
		if err := os.WriteFile(cfg.reportFile, []byte(report), 0o644); err != nil {
			return 1, err
		}
	}
	if final.tripped || sloFailed {
		return 1, nil
	}
	return 0, nil
}

func producer(stop <-chan struct{}, jobs chan<- int, baseRate float64, profile string, start time.Time, duration time.Duration) {
	defer close(jobs)
	seq := 0
	if baseRate <= 0 {
		for {
			select {
			case <-stop:
				return
			case jobs <- seq:
				seq++
			}
		}
	}

	tick := 10 * time.Millisecond
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	var carry float64
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			progress := time.Since(start).Seconds() / math.Max(duration.Seconds(), 0.001)
			curRate := effectiveRate(baseRate, profile, progress)
			carry += curRate * tick.Seconds()
			count := int(carry)
			if count < 1 {
				continue
			}
			carry -= float64(count)
			for i := 0; i < count; i++ {
				select {
				case <-stop:
					return
				case jobs <- seq:
					seq++
				}
			}
		}
	}
}

func newRequest(targetURL, method string, payload []byte, headers map[string]string) (*http.Request, error) {
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Hyperion/1.0 authorized-security-test")
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if len(payload) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func collect(results <-chan sampleResult, start time.Time, circuitBreaker bool, stopNow func(), tripped *atomic.Bool) metrics {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var total metrics
	var window metrics
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		select {
		case r, ok := <-results:
			if !ok {
				return total
			}
			recordSample(&total, r, rng)
			recordSample(&window, r, rng)
			if circuitBreaker && total.total >= 50 && !tripped.Load() {
				bad := total.status5xx + total.errors
				if float64(bad)/float64(total.total) >= 0.80 {
					tripped.Store(true)
					fmt.Println("\n[!] CIRCUIT BREAKER TRIPPED: >=80% error/5xx rate detected. Halting load to protect target.")
					stopNow()
				}
			}
		case <-ticker.C:
			printWindow(time.Since(start), window)
			window = metrics{}
		}
	}
}

func recordSample(m *metrics, r sampleResult, rng *rand.Rand) {
	m.total++
	m.bytes += r.bytes
	if r.err != "" || r.status == 0 {
		m.errors++
	} else if r.status >= 200 && r.status < 300 {
		m.status2xx++
	} else if r.status >= 300 && r.status < 400 {
		m.status3xx++
	} else if r.status >= 400 && r.status < 500 {
		m.status4xx++
	} else if r.status >= 500 && r.status < 600 {
		m.status5xx++
	} else {
		m.statusOther++
	}

	ms := float64(r.latency.Microseconds()) / 1000.0
	m.sumMs += ms
	m.sumSqMs += ms * ms
	if m.total == 1 || ms < m.minMs {
		m.minMs = ms
	}
	if ms > m.maxMs {
		m.maxMs = ms
	}
	if len(m.latenciesMs) < reservoirCap {
		m.latenciesMs = append(m.latenciesMs, ms)
	} else {
		j := rng.Int63n(m.total)
		if j < int64(reservoirCap) {
			m.latenciesMs[j] = ms
		}
	}
}

func printWindow(elapsed time.Duration, m metrics) {
	if m.total == 0 {
		return
	}
	p50, _, p95, p99, _ := computePercentiles(m.latenciesMs)
	fmt.Printf("[%6.1fs] rps=%8.1f 2xx=%d 4xx=%d 5xx=%d err=%d p50=%.1fms p95=%.1fms p99=%.1fms\n",
		elapsed.Seconds(), float64(m.total), m.status2xx, m.status4xx, m.status5xx, m.errors, p50, p95, p99)
}

func computePercentiles(samples []float64) (p50, p90, p95, p99, p999 float64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0, 0
	}
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	pick := func(q float64) float64 {
		idx := int(math.Ceil((q/100.0)*float64(len(cp)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(cp) {
			idx = len(cp) - 1
		}
		return cp[idx]
	}
	return pick(50), pick(90), pick(95), pick(99), pick(99.9)
}

func buildReports(cfg config, scenarioURLs []string, start time.Time, m metrics) (string, bool) {
	elapsed := time.Since(start)
	p50, p90, p95, p99, p999 := computePercentiles(m.latenciesMs)
	rps := float64(m.total) / math.Max(elapsed.Seconds(), 0.001)
	avgMs := 0.0
	jitterMs := 0.0
	if m.total > 0 {
		avgMs = m.sumMs / float64(m.total)
		variance := (m.sumSqMs / float64(m.total)) - (avgMs * avgMs)
		if variance > 0 {
			jitterMs = math.Sqrt(variance)
		}
	}
	errCount := m.status5xx + m.errors
	errPct := 0.0
	if m.total > 0 {
		errPct = (float64(errCount) * 100.0) / float64(m.total)
	}

	sloFailed := false
	var sloNotes []string
	if cfg.sloP95Ms > 0 {
		if p95 > cfg.sloP95Ms {
			sloFailed = true
			sloNotes = append(sloNotes, fmt.Sprintf("FAIL: p95 %.1fms > SLO %.1fms", p95, cfg.sloP95Ms))
		} else {
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: p95 %.1fms <= SLO %.1fms", p95, cfg.sloP95Ms))
		}
	}
	if cfg.sloErrPct > 0 {
		if errPct > cfg.sloErrPct {
			sloFailed = true
			sloNotes = append(sloNotes, fmt.Sprintf("FAIL: error/5xx %.2f%% > SLO %.2f%%", errPct, cfg.sloErrPct))
		} else {
			sloNotes = append(sloNotes, fmt.Sprintf("PASS: error/5xx %.2f%% <= SLO %.2f%%", errPct, cfg.sloErrPct))
		}
	}

	if cfg.jsonFile != "" {
		payload := map[string]any{
			"engine":            "hyperion-go",
			"target":            cfg.target,
			"scenario_urls":     scenarioURLs,
			"profile":           cfg.profile,
			"duration_seconds":  elapsed.Seconds(),
			"total_requests":    m.total,
			"average_rps":       rps,
			"status_2xx":        m.status2xx,
			"status_3xx":        m.status3xx,
			"status_4xx":        m.status4xx,
			"status_5xx":        m.status5xx,
			"transport_errors":  m.errors,
			"error_rate_pct":    errPct,
			"circuit_tripped":   m.tripped,
			"slo_failed":        sloFailed,
			"latency_ms": map[string]float64{
				"min":   m.minMs,
				"avg":   avgMs,
				"stdev": jitterMs,
				"p50":   p50,
				"p90":   p90,
				"p95":   p95,
				"p99":   p99,
				"p999":  p999,
				"max":   m.maxMs,
			},
		}
		if raw, err := json.MarshalIndent(payload, "", "  "); err == nil {
			_ = os.WriteFile(cfg.jsonFile, raw, 0o644)
		}
	}

	var b strings.Builder
	b.WriteString("\n## Hyperion Resilience & SLO Report\n\n")
	fmt.Fprintf(&b, "- Target: `%s` (%d scenario endpoint(s))\n", cfg.target, len(scenarioURLs))
	fmt.Fprintf(&b, "- Profile / Method: `%s` / `%s`\n", cfg.profile, cfg.method)
	fmt.Fprintf(&b, "- Duration / Workers: `%s` / `%d`\n", elapsed.Round(time.Millisecond), cfg.workers)
	fmt.Fprintf(&b, "- Total requests: `%d` (`%.1f RPS`)\n", m.total, rps)
	fmt.Fprintf(&b, "- 2xx / 3xx / 4xx / 5xx / errors: `%d / %d / %d / %d / %d` (error/5xx rate: `%.2f%%`)\n",
		m.status2xx, m.status3xx, m.status4xx, m.status5xx, m.errors, errPct)
	fmt.Fprintf(&b, "- Latency min / avg / jitter(σ) / max: `%.1fms / %.1fms / %.1fms / %.1fms`\n",
		m.minMs, avgMs, jitterMs, m.maxMs)
	fmt.Fprintf(&b, "- Percentiles p50 / p90 / p95 / p99 / p99.9: `%.1fms / %.1fms / %.1fms / %.1fms / %.1fms`\n",
		p50, p90, p95, p99, p999)
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
