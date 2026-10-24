package main

import (
	"bytes"
	"crypto/tls"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IMPROVEMENTS over v1.0:
//   1. Ramp profile: rate climbs from 10% to 100% over the test duration so the
//      saturation knee is visible in the live output, not just in retrospect.
//   2. Live p50/p95 per second window: each tick now prints median and p95 from
//      the window's latency slice — previously only rps and status counts were shown.
//   3. Per-endpoint breakdown in the final report when --endpoints is used.
//   4. p99 added to the final report percentile row.
//   5. stdev (jitter) added to the final report.

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ",") }
func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type config struct {
	target     string
	endpoints  string // comma-separated "path:weight" pairs on the same host
	profile    string // constant | ramp
	method     string
	rate       string
	duration   time.Duration
	workers    int
	payload    string
	headers    headerList
	timeout    time.Duration
	reportFile string
}

type result struct {
	status  int
	latency time.Duration
	bytes   int64
	err     string
	urlKey  string // path key for per-endpoint breakdown
}

type counters struct {
	total       int64
	status2xx   int64
	status3xx   int64
	status4xx   int64
	status5xx   int64
	statusOther int64
	errors      int64
	bytes       int64
	latencies   []float64 // ms
}

type endpointCounter struct {
	mu        sync.Mutex
	latencies []float64
	total     int64
	errors    int64
}

const (
	maxExternalRPS     = 9999.99
	maxExternalWorkers = 256
	maxPrivateRPS      = 250000.0
)

func main() {
	cfg, err := parseFlags()
	if err != nil {
		exitError(err)
	}
	if err := validateTarget(cfg.target); err != nil {
		exitError(err)
	}
	if err := run(cfg); err != nil {
		exitError(err)
	}
}

func parseFlags() (config, error) {
	defaultWorkers := runtime.NumCPU() * 64
	if defaultWorkers < 64 {
		defaultWorkers = 64
	}
	var cfg config
	var targetShort, methodShort, rateShort, payloadShort, profileShort string
	var durationShort time.Duration
	var workersShort int

	flag.StringVar(&cfg.target, "target", "http://localhost:3456/", "Target URL endpoint")
	flag.StringVar(&targetShort, "t", "", "Target URL endpoint")
	flag.StringVar(&cfg.endpoints, "endpoints", "", "Weighted subpaths: '/:50,/api/config:30,/api/guestbook:20'")
	// IMPROVEMENT: ramp profile added
	flag.StringVar(&cfg.profile, "profile", "constant", "Load profile: constant | ramp")
	flag.StringVar(&profileShort, "P", "", "Load profile")
	flag.StringVar(&cfg.method, "method", "GET", "HTTP method")
	flag.StringVar(&methodShort, "m", "", "HTTP method")
	flag.StringVar(&cfg.rate, "rate", "1000", "Target rate (RPS, k/m suffix, or 0 for full-send)")
	flag.StringVar(&rateShort, "r", "", "Target rate")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "Test duration e.g. 30s, 5m")
	flag.DurationVar(&durationShort, "d", 0, "Test duration")
	flag.IntVar(&cfg.workers, "workers", defaultWorkers, "Concurrent workers")
	flag.IntVar(&workersShort, "w", 0, "Concurrent workers")
	flag.StringVar(&cfg.payload, "payload", "", "Optional payload file for POST/PUT/PATCH")
	flag.StringVar(&payloadShort, "p", "", "Optional payload file")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-request timeout")
	flag.StringVar(&cfg.reportFile, "report-file", "", "Optional markdown report output path")
	flag.Var(&cfg.headers, "headers", "Custom header 'Name: value' (repeatable)")
	flag.Var(&cfg.headers, "H", "Custom header 'Name: value' (repeatable)")
	flag.Parse()

	if targetShort != "" { cfg.target = targetShort }
	if methodShort != "" { cfg.method = methodShort }
	if rateShort != "" { cfg.rate = rateShort }
	if durationShort > 0 { cfg.duration = durationShort }
	if workersShort > 0 { cfg.workers = workersShort }
	if payloadShort != "" { cfg.payload = payloadShort }
	if profileShort != "" { cfg.profile = profileShort }

	cfg.method = strings.ToUpper(strings.TrimSpace(cfg.method))
	cfg.profile = strings.ToLower(strings.TrimSpace(cfg.profile))
	if cfg.workers < 1 { cfg.workers = 1 }
	if cfg.duration <= 0 { return cfg, fmt.Errorf("duration must be greater than zero") }
	if cfg.timeout <= 0 { return cfg, fmt.Errorf("timeout must be greater than zero") }

	switch cfg.method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return cfg, fmt.Errorf("unsupported method %q", cfg.method)
	}
	switch cfg.profile {
	case "constant", "ramp":
	default:
		return cfg, fmt.Errorf("unsupported profile %q — use constant or ramp", cfg.profile)
	}
	return cfg, nil
}

// effectiveRate returns the RPS to target given the current progress (0.0–1.0).
// IMPROVEMENT: ramp climbs from 10% to 100% linearly — lets the live p95 window
// show the inflection point where latency starts rising ahead of hitting rate limit.
func effectiveRate(baseRate float64, profile string, progress float64) float64 {
	if baseRate <= 0 {
		return 0
	}
	p := math.Max(0, math.Min(1, progress))
	if profile == "ramp" {
		return baseRate * (0.10 + 0.90*p)
	}
	return baseRate
}

func buildRing(baseRaw, csv string) ([]string, error) {
	base, err := url.Parse(baseRaw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(csv) == "" {
		return []string{baseRaw}, nil
	}
	var ring []string
	for _, item := range strings.Split(csv, ",") {
		raw := strings.TrimSpace(item)
		if raw == "" {
			continue
		}
		weight := 1
		sub := raw
		if idx := strings.LastIndex(raw, ":"); idx > 0 && !strings.HasPrefix(raw, "http") {
			if w, e := strconv.Atoi(raw[idx+1:]); e == nil && w > 0 {
				weight = w
				sub = raw[:idx]
			}
		}
		if !strings.HasPrefix(sub, "/") {
			sub = "/" + sub
		}
		rel, e := url.Parse(sub)
		if e != nil {
			continue
		}
		resolved := base.ResolveReference(rel)
		if strings.EqualFold(resolved.Host, base.Host) {
			for i := 0; i < weight; i++ {
				ring = append(ring, resolved.String())
			}
		}
	}
	if len(ring) == 0 {
		return []string{baseRaw}, nil
	}
	return ring, nil
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
		return fmt.Errorf("refusing target %s: public IP not in authorized_targets.txt", host)
	}
	allowed := loadAuthorizedHosts()
	if allowed[strings.ToLower(host)] {
		return nil
	}
	return fmt.Errorf("refusing target %s: hostname not in authorized_targets.txt", host)
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
	if host == "" || strings.EqualFold(host, "localhost") {
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
			return fmt.Errorf("full-send disabled for public targets; use localhost/private labs")
		}
		if rate > maxExternalRPS {
			return fmt.Errorf("public Maelstrom rate %.2f rps exceeds %.2f rps cap", rate, maxExternalRPS)
		}
		if cfg.workers > maxExternalWorkers {
			return fmt.Errorf("public Maelstrom workers %d exceeds %d cap", cfg.workers, maxExternalWorkers)
		}
		return nil
	}
	if rate > maxPrivateRPS {
		return fmt.Errorf("private Maelstrom rate %.2f rps exceeds %.0f rps local cap", rate, maxPrivateRPS)
	}
	return nil
}

func run(cfg config) error {
	rate, err := parseRate(cfg.rate)
	if err != nil {
		return err
	}
	if err := validateTrafficLimits(cfg, rate); err != nil {
		return err
	}
	ring, err := buildRing(cfg.target, cfg.endpoints)
	if err != nil {
		return err
	}
	payload, err := loadPayload(cfg.payload)
	if err != nil {
		return err
	}
	headerMap, err := parseHeaders(cfg.headers)
	if err != nil {
		return err
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
	stopNow := func() { stopOnce.Do(func() { close(stop) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; fmt.Println("\nSIGINT — draining workers..."); stopNow() }()
	go func() { time.Sleep(cfg.duration); stopNow() }()

	jobs := make(chan string, cfg.workers*8) // jobs carry the target URL
	results := make(chan result, cfg.workers*16)
	var wg sync.WaitGroup

	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go worker(&wg, client, cfg, payload, headerMap, jobs, results)
	}

	// IMPROVEMENT: producer now respects ramp profile via effectiveRate()
	start := time.Now()
	go func() {
		defer close(jobs)
		if rate <= 0 {
			var idx int64
			for {
				select {
				case <-stop:
					return
				case jobs <- ring[atomic.AddInt64(&idx, 1)%int64(len(ring))]:
				}
			}
		}
		tick := 10 * time.Millisecond
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		var carry float64
		var idx int64
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				progress := time.Since(start).Seconds() / math.Max(cfg.duration.Seconds(), 0.001)
				effRate := effectiveRate(rate, cfg.profile, progress)
				carry += effRate * tick.Seconds()
				count := int(carry)
				if count < 1 {
					continue
				}
				carry -= float64(count)
				for i := 0; i < count; i++ {
					select {
					case <-stop:
						return
					case jobs <- ring[atomic.AddInt64(&idx, 1)%int64(len(ring))]:
					}
				}
			}
		}
	}()

	go func() { wg.Wait(); close(results) }()

	fmt.Println("================================")
	fmt.Println(" MAELSTROM v1.1 - Load Tester")
	fmt.Println("================================")
	fmt.Printf("target=%s endpoints=%d profile=%s method=%s duration=%s workers=%d rate=%s\n",
		cfg.target, len(ring), cfg.profile, cfg.method, cfg.duration, cfg.workers, cfg.rate)
	if rate <= 0 {
		fmt.Println("mode=full-send")
	} else {
		fmt.Printf("mode=rate-limited rps=%.2f\n", rate)
	}
	fmt.Println()

	// Per-endpoint tracking map
	epCounters := map[string]*endpointCounter{}
	for _, u := range ring {
		p := pathKey(u)
		if _, ok := epCounters[p]; !ok {
			epCounters[p] = &endpointCounter{}
		}
	}

	final := collect(results, start, epCounters)
	report := markdownReport(cfg, start, final, rate, epCounters)
	fmt.Println(report)

	if cfg.reportFile != "" {
		if err := os.WriteFile(cfg.reportFile, []byte(report), 0o644); err != nil {
			return err
		}
		fmt.Printf("Report written: %s\n", cfg.reportFile)
	}
	return nil
}

func pathKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

func worker(wg *sync.WaitGroup, client *http.Client, cfg config, payload []byte,
	headers map[string]string, jobs <-chan string, results chan<- result) {
	defer wg.Done()
	for targetURL := range jobs {
		t0 := time.Now()
		req, err := newRequest(cfg.method, targetURL, payload, headers)
		if err != nil {
			results <- result{latency: time.Since(t0), err: err.Error(), urlKey: pathKey(targetURL)}
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			results <- result{latency: time.Since(t0), err: err.Error(), urlKey: pathKey(targetURL)}
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		results <- result{status: resp.StatusCode, latency: time.Since(t0), bytes: n, urlKey: pathKey(targetURL)}
	}
}

func newRequest(method, targetURL string, payload []byte, headers map[string]string) (*http.Request, error) {
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if len(payload) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func collect(results <-chan result, start time.Time, epCounters map[string]*endpointCounter) counters {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var total counters
	var window counters
	for {
		select {
		case r, ok := <-results:
			if !ok {
				// IMPROVEMENT: print final window with p50/p95
				printWindow(time.Since(start), window)
				return total
			}
			addResult(&total, r)
			addResult(&window, r)
			// Per-endpoint accumulation
			if ep, ok2 := epCounters[r.urlKey]; ok2 {
				ep.mu.Lock()
				ep.total++
				if r.err != "" || r.status == 0 {
					ep.errors++
				} else {
					ep.latencies = append(ep.latencies, float64(r.latency.Microseconds())/1000)
				}
				ep.mu.Unlock()
			}
		case <-ticker.C:
			printWindow(time.Since(start), window)
			window = counters{}
		}
	}
}

func addResult(c *counters, r result) {
	c.total++
	c.bytes += r.bytes
	if r.err != "" || r.status == 0 {
		c.errors++
	} else if r.status >= 200 && r.status < 300 {
		c.status2xx++
	} else if r.status >= 300 && r.status < 400 {
		c.status3xx++
	} else if r.status >= 400 && r.status < 500 {
		c.status4xx++
	} else if r.status >= 500 && r.status < 600 {
		c.status5xx++
	} else {
		c.statusOther++
	}
	if len(c.latencies) < 250_000 {
		c.latencies = append(c.latencies, float64(r.latency.Microseconds())/1000)
	}
}

func printWindow(elapsed time.Duration, c counters) {
	if c.total == 0 {
		fmt.Printf("[%6.1fs] rps=%8.1f total=%d\n", elapsed.Seconds(), 0.0, c.total)
		return
	}
	rps := float64(c.total)
	// IMPROVEMENT: live p50/p95 per second window
	p50, p95, p99 := percentiles(c.latencies)
	fmt.Printf("[%6.1fs] rps=%8.1f 2xx=%d 4xx=%d 5xx=%d err=%d p50=%.1fms p95=%.1fms p99=%.1fms mb=%.2f\n",
		elapsed.Seconds(), rps, c.status2xx, c.status4xx, c.status5xx, c.errors, p50, p95, p99,
		float64(c.bytes)/(1024*1024))
}

func markdownReport(cfg config, start time.Time, c counters, rate float64, epCounters map[string]*endpointCounter) string {
	elapsed := time.Since(start)
	p50, p95, p99 := percentiles(c.latencies)
	// IMPROVEMENT: stdev (jitter) in report
	jitter := stdev(c.latencies)
	rps := float64(c.total) / math.Max(elapsed.Seconds(), 0.001)
	success := c.status2xx + c.status3xx
	failure := c.status4xx + c.status5xx + c.statusOther + c.errors

	var b strings.Builder
	b.WriteString("\n## Maelstrom v1.1 Report\n\n")
	fmt.Fprintf(&b, "- Target: `%s` | Profile: `%s`\n", cfg.target, cfg.profile)
	fmt.Fprintf(&b, "- Method: `%s` | Workers: `%d` | Duration: `%s`\n", cfg.method, cfg.workers, elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "- Total requests: `%d` | Average RPS: `%.1f`\n", c.total, rps)
	fmt.Fprintf(&b, "- Success: `%d` | Failure/error: `%d`\n", success, failure)
	fmt.Fprintf(&b, "- 2xx/3xx/4xx/5xx/other/err: `%d/%d/%d/%d/%d/%d`\n",
		c.status2xx, c.status3xx, c.status4xx, c.status5xx, c.statusOther, c.errors)
	// IMPROVEMENT: p99 + jitter in report
	fmt.Fprintf(&b, "- Latency p50/p95/p99/jitter(σ): `%.1fms / %.1fms / %.1fms / %.1fms`\n", p50, p95, p99, jitter)
	fmt.Fprintf(&b, "- Data transferred: `%.2f MB`\n", float64(c.bytes)/(1024*1024))

	// IMPROVEMENT: per-endpoint breakdown
	if len(epCounters) > 1 {
		b.WriteString("\n### Per-Endpoint Breakdown\n\n")
		b.WriteString("| Path | Requests | p50 ms | p95 ms | Errors |\n")
		b.WriteString("|------|----------|--------|--------|--------|\n")
		paths := make([]string, 0, len(epCounters))
		for k := range epCounters {
			paths = append(paths, k)
		}
		sort.Strings(paths)
		for _, path := range paths {
			ep := epCounters[path]
			ep.mu.Lock()
			ep50, ep95, _ := percentiles(ep.latencies)
			epTotal := ep.total
			epErr := ep.errors
			ep.mu.Unlock()
			fmt.Fprintf(&b, "| `%s` | %d | %.1f | %.1f | %d |\n", path, epTotal, ep50, ep95, epErr)
		}
	}
	return b.String()
}

func percentiles(values []float64) (float64, float64, float64) {
	if len(values) == 0 {
		return 0, 0, 0
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	return pickPercentile(cp, 50), pickPercentile(cp, 95), pickPercentile(cp, 99)
}

func pickPercentile(sorted []float64, pct int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil((float64(pct)/100)*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// IMPROVEMENT: stdev (jitter) calculation
func stdev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	var varSum float64
	for _, v := range values {
		d := v - mean
		varSum += d * d
	}
	return math.Sqrt(varSum / float64(len(values)))
}

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range values {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("header must be 'Name: value': %q", raw)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("header name cannot be empty")
		}
		out[key] = value
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
	switch {
	case strings.HasSuffix(s, "k"):
		mult = 1_000; s = strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "m"):
		mult = 1_000_000; s = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "g"):
		mult = 1_000_000_000; s = strings.TrimSuffix(s, "g")
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate %q", raw)
	}
	if value < 0 {
		return 0, fmt.Errorf("rate cannot be negative")
	}
	v := value * mult
	if perMinute {
		v /= 60
	}
	return v, nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "maelstrom: %v\n", err)
	os.Exit(1)
}
