package main

// Maelstrom v3 — VibeHacking load engine
// Authorization + public caps retained.
// New: UA rotation, multi-path, proxy, TLS skip, warmup, cache-bust,
//      proper rate limiter, error classification, JSON + Markdown reports,
//      richer live stats, body string, per-path stats.

import (
	"bytes"
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
	maxExternalRPS     = 9999.99
	maxExternalWorkers = 256
	maxPrivateRPS      = 250000.0
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
	"curl/8.7.1",
	"python-httpx/0.27.0",
}

type headerList []string

func (h *headerList) String() string   { return strings.Join(*h, ",") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

type config struct {
	target, method, rate, bodyStr, payloadFile, pathsFile, proxyURL, reportFile, jsonReport string
	duration, timeout                                                                       time.Duration
	workers, warmup                                                                        int
	headers                                                                                headerList
	tlsSkip, noRotateUA, cacheBust                                                         bool
}

type result struct {
	status  int
	latency time.Duration
	bytes   int64
	path    string
	err     string
	errKind string // timeout | connect | tls | reset | dns | other | ""
}

type counters struct {
	total, s2xx, s3xx, s4xx, s5xx, sOther, errors, bytes int64
	errTimeout, errConnect, errTLS, errReset, errDNS, errOther int64
	latencies                                                 []float64
}

type pathStats struct {
	mu        sync.Mutex
	counts    map[string]int64
	latencies map[string][]float64
}

func newPathStats() *pathStats {
	return &pathStats{counts: map[string]int64{}, latencies: map[string][]float64{}}
}
func (ps *pathStats) add(path string, latency float64) {
	ps.mu.Lock()
	ps.counts[path]++
	if len(ps.latencies[path]) < 50000 {
		ps.latencies[path] = append(ps.latencies[path], latency)
	}
	ps.mu.Unlock()
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		exitErr(err)
	}
	if err := validateTarget(cfg.target); err != nil {
		exitErr(err)
	}
	if err := run(cfg); err != nil {
		exitErr(err)
	}
}

func parseFlags() (config, error) {
	defaultWorkers := runtime.NumCPU() * 64
	if defaultWorkers < 64 {
		defaultWorkers = 64
	}
	var cfg config
	var tShort, mShort, rShort, pShort string
	var dShort time.Duration
	var wShort int

	flag.StringVar(&cfg.target, "target", "http://localhost:3456/", "Target URL")
	flag.StringVar(&tShort, "t", "", "Target (short)")
	flag.StringVar(&cfg.method, "method", "GET", "HTTP method")
	flag.StringVar(&mShort, "m", "", "Method (short)")
	flag.StringVar(&cfg.rate, "rate", "1000", "RPS (0/full/max = full-send)")
	flag.StringVar(&rShort, "r", "", "Rate (short)")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "Duration")
	flag.DurationVar(&dShort, "d", 0, "Duration (short)")
	flag.IntVar(&cfg.workers, "workers", defaultWorkers, "Worker goroutines")
	flag.IntVar(&wShort, "w", 0, "Workers (short)")
	flag.StringVar(&cfg.bodyStr, "body", "", "Inline request body")
	flag.StringVar(&cfg.payloadFile, "payload", "", "Payload file")
	flag.StringVar(&pShort, "p", "", "Payload (short)")
	flag.StringVar(&cfg.pathsFile, "paths", "", "Path wordlist (one per line)")
	flag.StringVar(&cfg.proxyURL, "proxy", "", "Proxy URL")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-request timeout")
	flag.StringVar(&cfg.reportFile, "report-file", "", "Markdown report path")
	flag.StringVar(&cfg.jsonReport, "json", "", "JSON report path")
	flag.IntVar(&cfg.warmup, "warmup", 0, "Warmup requests before measurement")
	flag.BoolVar(&cfg.tlsSkip, "tls-skip", false, "Skip TLS verify")
	flag.BoolVar(&cfg.noRotateUA, "no-rotate-ua", false, "Fixed User-Agent")
	flag.BoolVar(&cfg.cacheBust, "cache-bust", false, "Append ?v=nonce every request")
	flag.Var(&cfg.headers, "H", "Header: value (repeatable)")
	flag.Var(&cfg.headers, "headers", "Header: value (repeatable)")
	flag.Parse()

	if tShort != "" {
		cfg.target = tShort
	}
	if mShort != "" {
		cfg.method = mShort
	}
	if rShort != "" {
		cfg.rate = rShort
	}
	if dShort > 0 {
		cfg.duration = dShort
	}
	if wShort > 0 {
		cfg.workers = wShort
	}
	if pShort != "" {
		cfg.payloadFile = pShort
	}

	cfg.method = strings.ToUpper(strings.TrimSpace(cfg.method))
	if cfg.workers < 1 {
		cfg.workers = 1
	}
	if cfg.duration <= 0 {
		return cfg, fmt.Errorf("duration must be > 0")
	}
	switch cfg.method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return cfg, fmt.Errorf("unsupported method %q", cfg.method)
	}
	return cfg, nil
}

func validateTarget(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("host required")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return nil
		}
		return fmt.Errorf("refusing public IP %s — add exact hostname to authorized_targets.txt", host)
	}
	allowed := loadAuthorizedHosts()
	if allowed[strings.ToLower(host)] {
		return nil
	}
	return fmt.Errorf("refusing %s — hostname not in authorized_targets.txt", host)
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
			return fmt.Errorf("full-send disabled for public targets")
		}
		if rate > maxExternalRPS {
			return fmt.Errorf("public rate %.2f exceeds %.2f rps cap", rate, maxExternalRPS)
		}
		if cfg.workers > maxExternalWorkers {
			return fmt.Errorf("public workers %d exceeds %d cap", cfg.workers, maxExternalWorkers)
		}
		return nil
	}
	if rate > maxPrivateRPS {
		return fmt.Errorf("private rate %.2f exceeds %.0f rps local cap", rate, maxPrivateRPS)
	}
	return nil
}

func loadPaths(file, base string) []string {
	if file == "" {
		return []string{base}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return []string{base}
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "http") {
			out = append(out, line)
		} else {
			p, _ := url.Parse(base)
			p.Path = "/" + strings.TrimPrefix(line, "/")
			out = append(out, p.String())
		}
	}
	if len(out) == 0 {
		return []string{base}
	}
	return out
}

func buildClient(cfg config) *http.Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.tlsSkip}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          cfg.workers * 4,
		MaxIdleConnsPerHost:   cfg.workers * 4,
		MaxConnsPerHost:       cfg.workers * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.timeout,
		ResponseHeaderTimeout: cfg.timeout,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsCfg,
	}
	if cfg.proxyURL != "" {
		if pu, err := url.Parse(cfg.proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{Transport: transport, Timeout: cfg.timeout}
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "connection refused") || strings.Contains(s, "connect:"):
		return "connect"
	case strings.Contains(s, "tls") || strings.Contains(s, "certificate") || strings.Contains(s, "x509"):
		return "tls"
	case strings.Contains(s, "reset") || strings.Contains(s, "broken pipe"):
		return "reset"
	case strings.Contains(s, "no such host") || strings.Contains(s, "dns"):
		return "dns"
	default:
		return "other"
	}
}

func run(cfg config) error {
	rate, err := parseRate(cfg.rate)
	if err != nil {
		return err
	}
	if err := validateTrafficLimits(cfg, rate); err != nil {
		return err
	}

	payload, _ := loadPayload(cfg.payloadFile)
	if len(payload) == 0 && cfg.bodyStr != "" {
		payload = []byte(cfg.bodyStr)
	}
	headerMap, _ := parseHeaders(cfg.headers)
	paths := loadPaths(cfg.pathsFile, cfg.target)
	runtime.GOMAXPROCS(runtime.NumCPU())
	client := buildClient(cfg)
	ps := newPathStats()

	stop := make(chan struct{})
	var once sync.Once
	stopNow := func() { once.Do(func() { close(stop) }) }
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Println("\nSIGINT — draining...")
		stopNow()
	}()
	go func() {
		time.Sleep(cfg.duration)
		stopNow()
	}()

	fmt.Println("================================")
	fmt.Println(" MAELSTROM v3")
	fmt.Println("================================")
	fmt.Printf("target=%s method=%s duration=%s workers=%d rate=%s\n",
		cfg.target, cfg.method, cfg.duration, cfg.workers, cfg.rate)
	fmt.Printf("paths=%d tls-skip=%v proxy=%s rotate-ua=%v cache-bust=%v\n",
		len(paths), cfg.tlsSkip, orStr(cfg.proxyURL, "none"), !cfg.noRotateUA, cfg.cacheBust)
	if rate <= 0 {
		fmt.Println("mode=full-send (worker-limited)")
	} else {
		fmt.Printf("mode=rate-limited rps=%.2f\n", rate)
	}

	// warmup
	if cfg.warmup > 0 {
		fmt.Printf("[warmup] %d requests...\n", cfg.warmup)
		var wg sync.WaitGroup
		for i := 0; i < cfg.warmup; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				req, _ := newRequest(cfg, paths[i%len(paths)], payload, headerMap)
				if req != nil {
					resp, err := client.Do(req)
					if err == nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
				}
			}(i)
		}
		wg.Wait()
		fmt.Println("[warmup] done")
	}

	jobs := make(chan string, cfg.workers*8)
	results := make(chan result, cfg.workers*16)
	var wg sync.WaitGroup

	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				eff := path
				if cfg.cacheBust {
					eff = bustURL(path)
				}
				t0 := time.Now()
				req, err := newRequest(cfg, eff, payload, headerMap)
				if err != nil {
					results <- result{0, 0, 0, path, err.Error(), "other"}
					continue
				}
				resp, err := client.Do(req)
				lat := time.Since(t0)
				if err != nil {
					results <- result{0, lat, 0, path, err.Error(), classifyError(err)}
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				ps.add(path, float64(lat.Microseconds())/1000)
				results <- result{resp.StatusCode, lat, n, path, "", ""}
			}
		}()
	}

	// producer with proper rate limiting
	go func() {
		defer close(jobs)
		var idx int64
		if rate <= 0 {
			for {
				select {
				case <-stop:
					return
				case jobs <- paths[atomic.AddInt64(&idx, 1)%int64(len(paths))]:
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
				carry += rate * tick.Seconds()
				n := int(carry)
				if n < 1 {
					continue
				}
				carry -= float64(n)
				for i := 0; i < n; i++ {
					select {
					case <-stop:
						return
					case jobs <- paths[atomic.AddInt64(&idx, 1)%int64(len(paths))]:
					}
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	start := time.Now()
	final := collect(results, start)
	report := markdownReport(cfg, start, final, paths, ps)
	fmt.Println(report)

	if cfg.reportFile != "" {
		_ = os.WriteFile(cfg.reportFile, []byte(report), 0o644)
		fmt.Printf("Report written: %s\n", cfg.reportFile)
	}
	if cfg.jsonReport != "" {
		b, _ := buildJSONReport(cfg, start, final)
		_ = os.WriteFile(cfg.jsonReport, b, 0o644)
		fmt.Printf("JSON written: %s\n", cfg.jsonReport)
	}
	return nil
}

func bustURL(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + fmt.Sprintf("v=%x", rand.Int63())
}

func newRequest(cfg config, path string, payload []byte, headers map[string]string) (*http.Request, error) {
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(cfg.method, path, body)
	if err != nil {
		return nil, err
	}
	if cfg.noRotateUA {
		req.Header.Set("User-Agent", userAgents[0])
	} else {
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	if len(payload) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func collect(results <-chan result, start time.Time) counters {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var total, window counters
	for {
		select {
		case r, ok := <-results:
			if !ok {
				printWindow(time.Since(start), window)
				return total
			}
			addResult(&total, r)
			addResult(&window, r)
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
		switch r.errKind {
		case "timeout":
			c.errTimeout++
		case "connect":
			c.errConnect++
		case "tls":
			c.errTLS++
		case "reset":
			c.errReset++
		case "dns":
			c.errDNS++
		default:
			c.errOther++
		}
	} else if r.status < 300 {
		c.s2xx++
	} else if r.status < 400 {
		c.s3xx++
	} else if r.status < 500 {
		c.s4xx++
	} else if r.status < 600 {
		c.s5xx++
	} else {
		c.sOther++
	}
	if len(c.latencies) < 500_000 {
		c.latencies = append(c.latencies, float64(r.latency.Microseconds())/1000)
	}
}

func printWindow(elapsed time.Duration, c counters) {
	p50, p95, p99 := percentiles(c.latencies)
	fmt.Printf("[%6.1fs] rps=%8.1f 2xx=%d 4xx=%d 5xx=%d err=%d (to=%d conn=%d tls=%d) p50=%.1f p95=%.1f p99=%.1f mb=%.2f\n",
		elapsed.Seconds(), float64(c.total), c.s2xx, c.s4xx, c.s5xx, c.errors,
		c.errTimeout, c.errConnect, c.errTLS, p50, p95, p99, float64(c.bytes)/(1024*1024))
}

func markdownReport(cfg config, start time.Time, c counters, paths []string, ps *pathStats) string {
	elapsed := time.Since(start)
	p50, p95, p99 := percentiles(c.latencies)
	rps := float64(c.total) / math.Max(elapsed.Seconds(), 0.001)
	var b strings.Builder
	b.WriteString("\n## Maelstrom v3 Report\n\n")
	fmt.Fprintf(&b, "- Target: `%s`\n", cfg.target)
	fmt.Fprintf(&b, "- Method: `%s`\n", cfg.method)
	fmt.Fprintf(&b, "- Duration: `%s`\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "- Workers: `%d`\n", cfg.workers)
	fmt.Fprintf(&b, "- Rate setting: `%s`\n", cfg.rate)
	fmt.Fprintf(&b, "- Total requests: `%d`\n", c.total)
	fmt.Fprintf(&b, "- Average RPS: `%.1f`\n", rps)
	fmt.Fprintf(&b, "- 2xx / 3xx / 4xx / 5xx / other / errors: `%d / %d / %d / %d / %d / %d`\n",
		c.s2xx, c.s3xx, c.s4xx, c.s5xx, c.sOther, c.errors)
	fmt.Fprintf(&b, "- Error breakdown (timeout/connect/tls/reset/dns/other): `%d / %d / %d / %d / %d / %d`\n",
		c.errTimeout, c.errConnect, c.errTLS, c.errReset, c.errDNS, c.errOther)
	fmt.Fprintf(&b, "- Latency p50 / p95 / p99: `%.1fms / %.1fms / %.1fms`\n", p50, p95, p99)
	fmt.Fprintf(&b, "- Data transferred: `%.2f MB`\n", float64(c.bytes)/(1024*1024))
	if len(paths) > 1 {
		b.WriteString("\n### Per-path\n\n")
		ps.mu.Lock()
		for path, count := range ps.counts {
			lats := ps.latencies[path]
			pp50, _, _ := percentiles(lats)
			short := path
			if len(short) > 70 {
				short = "..." + short[len(short)-67:]
			}
			fmt.Fprintf(&b, "- `%s` → hits=%d p50=%.1fms\n", short, count, pp50)
		}
		ps.mu.Unlock()
	}
	return b.String()
}

func buildJSONReport(cfg config, start time.Time, c counters) ([]byte, error) {
	elapsed := time.Since(start)
	p50, p95, p99 := percentiles(c.latencies)
	rps := float64(c.total) / math.Max(elapsed.Seconds(), 0.001)
	m := map[string]interface{}{
		"target": cfg.target, "method": cfg.method,
		"elapsed_s": elapsed.Seconds(), "total": c.total, "rps": rps,
		"s2xx": c.s2xx, "s3xx": c.s3xx, "s4xx": c.s4xx, "s5xx": c.s5xx, "errors": c.errors,
		"err_timeout": c.errTimeout, "err_connect": c.errConnect, "err_tls": c.errTLS,
		"err_reset": c.errReset, "err_dns": c.errDNS, "err_other": c.errOther,
		"p50_ms": p50, "p95_ms": p95, "p99_ms": p99,
		"bytes": c.bytes, "mb": float64(c.bytes) / (1024 * 1024),
	}
	return json.MarshalIndent(m, "", "  ")
}

func percentiles(v []float64) (float64, float64, float64) {
	if len(v) == 0 {
		return 0, 0, 0
	}
	cp := append([]float64(nil), v...)
	sort.Float64s(cp)
	return pick(cp, 50), pick(cp, 95), pick(cp, 99)
}
func pick(s []float64, pct int) float64 {
	idx := int(math.Ceil(float64(pct)/100*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func parseHeaders(vals []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range vals {
		if parts := strings.SplitN(raw, ":", 2); len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
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
	if s == "" || s == "0" || s == "full" || s == "full-send" || s == "max" {
		return 0, nil
	}
	perMin := false
	for _, sf := range []string{"/min", "rpm", "permin", "per-minute"} {
		if strings.HasSuffix(s, sf) {
			perMin = true
			s = strings.TrimSuffix(s, sf)
			break
		}
	}
	for _, sf := range []string{"/s", "rps", "persec", "per-second"} {
		s = strings.TrimSuffix(s, sf)
	}
	mult := 1.0
	if strings.HasSuffix(s, "k") {
		mult = 1000
		s = strings.TrimSuffix(s, "k")
	}
	if strings.HasSuffix(s, "m") {
		mult = 1e6
		s = strings.TrimSuffix(s, "m")
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	v *= mult
	if perMin {
		v /= 60
	}
	return v, nil
}
func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
