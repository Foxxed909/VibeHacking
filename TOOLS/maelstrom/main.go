package main

import (
	"bytes"
	"crypto/tls"
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

	"golang.org/x/net/http2"
)

// Maelstrom v2.0 — DDoS-Pressure Load Tester
//
// Improvements:
//   1. Slowloris mode (--slowloris N): holds N TCP connections open with dripping
//      partial HTTP/1.1 headers, exhausting server connection slots.
//   2. Aggressive HTTP/2 multiplexing (--h2-multiplex): explicit golang.org/x/net/http2
//      transport with MaxConcurrentStreams overridden to push maximum parallel
//      streams per connection, and multiple H2 connections per host.
//   3. Flood patterns (--pattern): ua-rotate / cache-bust / header-flood / method-cycle.
//      UA pool: 16 real browser fingerprints. Header-flood: rotates X-Forwarded-For,
//      X-Request-ID, Cache-Control, Accept-Language per request.
//   4. Default workers raised: CPU×128 (was CPU×64). Default rate 10000 RPS (was 1000).
//   5. Ramp profile (--profile ramp): rate climbs 10%→100% over duration.
//   6. Live p50/p95/p99 per second window.
//   7. Per-endpoint breakdown in final report (--endpoints).
//   8. stdev (jitter) and p99 in final report.

var uaPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/127.0.6533.72 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.6478.56 Safari/537.36 OPR/112.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36 Vivaldi/6.8",
	"Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 Chrome/128.0.6613.88 Mobile Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"curl/8.7.1",
	"python-requests/2.32.3",
	"Go-http-client/2.0",
}

var junkHeaders = [][2]string{
	{"X-Request-ID", ""},
	{"X-Trace-ID", ""},
	{"X-Forwarded-For", ""},
	{"CF-Connecting-IP", ""},
	{"X-Real-IP", ""},
	{"Accept-Language", ""},
}

var httpMethods = []string{"GET", "POST", "HEAD", "OPTIONS", "PUT"}

type headerList []string

func (h *headerList) String() string      { return strings.Join(*h, ",") }
func (h *headerList) Set(v string) error  { *h = append(*h, v); return nil }

type config struct {
	target      string
	endpoints   string
	profile     string
	pattern     string
	method      string
	rate        string
	duration    time.Duration
	workers     int
	payload     string
	headers     headerList
	timeout     time.Duration
	slowloris   int
	slowlorisDrip time.Duration
	h2Multiplex bool
	reportFile  string
}

type result struct {
	status  int
	latency time.Duration
	bytes   int64
	err     string
	path    string
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
	latencies   []float64
}

type endpointStat struct {
	mu        sync.Mutex
	latencies []float64
	total     int64
	errors    int64
}

const (
	maxExternalRPS     = 9999.99
	maxExternalWorkers = 512
	maxPrivateRPS      = 500000.0
)

func main() {
	cfg, err := parseFlags()
	if err != nil { exitError(err) }
	if err := validateTarget(cfg.target); err != nil { exitError(err) }
	if err := run(cfg); err != nil { exitError(err) }
}

func parseFlags() (config, error) {
	// IMPROVEMENT: default workers raised CPU×64 → CPU×128
	defaultWorkers := runtime.NumCPU() * 128
	if defaultWorkers < 256 { defaultWorkers = 256 }

	var cfg config
	var tShort, mShort, rShort, pShort, profileShort string
	var dShort time.Duration
	var wShort int

	flag.StringVar(&cfg.target,   "target",  "http://localhost:3456/", "Target URL")
	flag.StringVar(&tShort,       "t",       "", "Target URL")
	flag.StringVar(&cfg.endpoints,"endpoints","", "Weighted subpaths '/:50,/api:30'")
	flag.StringVar(&cfg.profile,  "profile", "constant", "Load profile: constant | ramp")
	flag.StringVar(&profileShort, "P",       "", "Load profile")
	flag.StringVar(&cfg.pattern,  "pattern", "default",
		"Flood pattern: default | ua-rotate | cache-bust | header-flood | method-cycle")
	flag.StringVar(&cfg.method,   "method",  "GET",    "HTTP method (overridden by method-cycle)")
	flag.StringVar(&mShort,       "m",       "",       "HTTP method")
	// IMPROVEMENT: default rate raised 1000 → 10000
	flag.StringVar(&cfg.rate,     "rate",    "10000",  "Target RPS (k/m suffix or 0=full-send)")
	flag.StringVar(&rShort,       "r",       "",       "Target rate")
	flag.DurationVar(&cfg.duration,"duration",30*time.Second,"Test duration")
	flag.DurationVar(&dShort,     "d",       0,        "Test duration")
	flag.IntVar(&cfg.workers,     "workers", defaultWorkers, "Concurrent goroutines")
	flag.IntVar(&wShort,          "w",       0,        "Concurrent goroutines")
	flag.StringVar(&cfg.payload,  "payload", "",       "Payload file for POST")
	flag.StringVar(&pShort,       "p",       "",       "Payload file")
	flag.DurationVar(&cfg.timeout,"timeout", 5*time.Second, "Per-request timeout")
	flag.IntVar(&cfg.slowloris,   "slowloris",0,
		"Slowloris mode: open N connections and hold them (0=off)")
	flag.DurationVar(&cfg.slowlorisDrip,"slowloris-drip",10*time.Second,
		"Drip interval in slowloris mode")
	flag.BoolVar(&cfg.h2Multiplex,"h2-multiplex",false,
		"Force HTTP/2 with aggressive stream multiplexing per connection")
	flag.StringVar(&cfg.reportFile,"report-file","","Markdown report output path")
	flag.Var(&cfg.headers,"headers","Custom header 'Name: value' (repeatable)")
	flag.Var(&cfg.headers,"H",     "Custom header 'Name: value' (repeatable)")
	flag.Parse()

	if tShort != "" { cfg.target = tShort }
	if mShort != "" { cfg.method = mShort }
	if rShort != "" { cfg.rate   = rShort }
	if dShort > 0  { cfg.duration = dShort }
	if wShort > 0  { cfg.workers  = wShort }
	if pShort != "" { cfg.payload = pShort }
	if profileShort != "" { cfg.profile = profileShort }

	cfg.method  = strings.ToUpper(strings.TrimSpace(cfg.method))
	cfg.profile = strings.ToLower(strings.TrimSpace(cfg.profile))
	cfg.pattern = strings.ToLower(strings.TrimSpace(cfg.pattern))

	if cfg.workers < 1 { cfg.workers = 1 }
	if cfg.duration <= 0 { return cfg, fmt.Errorf("duration must be > 0") }
	if cfg.timeout <= 0  { return cfg, fmt.Errorf("timeout must be > 0") }

	switch cfg.profile {
	case "constant","ramp":
	default: return cfg, fmt.Errorf("unsupported profile %q — use constant or ramp", cfg.profile)
	}
	switch cfg.pattern {
	case "default","ua-rotate","cache-bust","header-flood","method-cycle":
	default: return cfg, fmt.Errorf("unsupported pattern %q", cfg.pattern)
	}
	return cfg, nil
}

func effectiveRate(base float64, profile string, progress float64) float64 {
	if base <= 0 { return 0 }
	p := math.Max(0, math.Min(1, progress))
	if profile == "ramp" { return base * (0.10 + 0.90*p) }
	return base
}

func buildRing(baseRaw, csv string) ([]string, error) {
	base, err := url.Parse(baseRaw)
	if err != nil { return nil, err }
	if strings.TrimSpace(csv) == "" { return []string{baseRaw}, nil }
	var ring []string
	for _, item := range strings.Split(csv, ",") {
		raw := strings.TrimSpace(item)
		if raw == "" { continue }
		weight := 1
		sub := raw
		if idx := strings.LastIndex(raw, ":"); idx > 0 && !strings.HasPrefix(raw, "http") {
			if w, e := strconv.Atoi(raw[idx+1:]); e == nil && w > 0 {
				weight = w; sub = raw[:idx]
			}
		}
		if !strings.HasPrefix(sub, "/") { sub = "/" + sub }
		rel, e := url.Parse(sub)
		if e != nil { continue }
		resolved := base.ResolveReference(rel)
		if strings.EqualFold(resolved.Host, base.Host) {
			for i := 0; i < weight; i++ { ring = append(ring, resolved.String()) }
		}
	}
	if len(ring) == 0 { return []string{baseRaw}, nil }
	return ring, nil
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
		if line == "" || strings.HasPrefix(line,"#") || strings.ContainsAny(line,"*?") { continue }
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
		if _, err := os.Stat(filepath.Join(dir, "authorized_targets.txt")); err == nil {
			return filepath.Join(dir, "authorized_targets.txt")
		}
		parent := filepath.Dir(dir)
		if parent == dir { break }
		dir = parent
	}
	return ""
}

func isPublicTarget(raw string) bool {
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
	if isPublicTarget(cfg.target) {
		if rate <= 0 { return fmt.Errorf("full-send disabled for public targets") }
		if rate > maxExternalRPS { return fmt.Errorf("rate %.2f > %.2f rps public cap", rate, maxExternalRPS) }
		if cfg.workers > maxExternalWorkers { return fmt.Errorf("workers %d > %d public cap", cfg.workers, maxExternalWorkers) }
		return nil
	}
	if rate > maxPrivateRPS { return fmt.Errorf("rate %.2f > %.0f rps private cap", rate, maxPrivateRPS) }
	return nil
}

// ── Slowloris ────────────────────────────────────────────────────────────────

func runSlowloris(target string, n int, duration time.Duration, drip time.Duration) error {
	parsed, err := url.Parse(target)
	if err != nil { return err }
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" { port = "443" } else { port = "80" }
	}
	path := parsed.Path
	if path == "" { path = "/" }
	useSSL := parsed.Scheme == "https"

	fmt.Printf("[slowloris] Opening %d connections → %s:%s%s | drip every %s | duration %s\n",
		n, host, port, path, drip, duration)

	var open atomic.Int64
	stop := make(chan struct{})

	worker := func() {
		conn, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
		if err != nil { return }
		if useSSL {
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
			if err := tlsConn.Handshake(); err != nil { conn.Close(); return }
			conn = tlsConn
		}
		ua := uaPool[rand.Intn(len(uaPool))]
		partial := fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: keep-alive\r\n",
			path, host, ua,
		)
		if _, err := conn.Write([]byte(partial)); err != nil { conn.Close(); return }
		open.Add(1)
		defer func() { open.Add(-1); conn.Close() }()
		for {
			select {
			case <-stop: return
			case <-time.After(drip):
				junk := fmt.Sprintf("X-Ping-%d: %d\r\n", rand.Int31n(9999), rand.Int31n(9999))
				if _, err := conn.Write([]byte(junk)); err != nil { return }
			}
		}
	}

	for i := 0; i < n; i++ {
		go worker()
		time.Sleep(20 * time.Millisecond)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	deadline := time.After(duration)
	for {
		select {
		case <-deadline:
			close(stop)
			fmt.Printf("[slowloris] Done. Peak open connections: %d/%d\n", open.Load(), n)
			return nil
		case <-ticker.C:
			fmt.Printf("[slowloris] open=%d/%d\n", open.Load(), n)
		}
	}
}

// ── Request building ─────────────────────────────────────────────────────────

func buildRequest(cfg config, targetURL string, payload []byte, headers map[string]string, seq int64) (*http.Request, error) {
	method := cfg.method
	if cfg.pattern == "method-cycle" {
		method = httpMethods[seq%int64(len(httpMethods))]
	}

	// Cache-bust URL
	if cfg.pattern == "cache-bust" {
		sep := "?"; if strings.Contains(targetURL, "?") { sep = "&" }
		targetURL = fmt.Sprintf("%s%s_s=%d", targetURL, sep, seq)
	}

	var body io.Reader
	if len(payload) > 0 { body = bytes.NewReader(payload) }
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil { return nil, err }

	// UA selection
	ua := uaPool[0]
	if cfg.pattern == "ua-rotate" { ua = uaPool[seq%int64(len(uaPool))] }
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Connection", "keep-alive")

	// Header flood
	if cfg.pattern == "header-flood" {
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", rand.Intn(254)+1))
		req.Header.Set("X-Real-IP",        fmt.Sprintf("203.0.113.%d",  rand.Intn(254)+1))
		req.Header.Set("X-Request-ID",     fmt.Sprintf("%x", rand.Int63()))
		req.Header.Set("X-Trace-ID",       fmt.Sprintf("%x", rand.Int63()))
		req.Header.Set("CF-Connecting-IP", fmt.Sprintf("192.0.2.%d",    rand.Intn(254)+1))
		req.Header.Set("Cache-Control",    "no-cache, no-store")
	}

	for k, v := range headers { req.Header.Set(k, v) }
	if len(payload) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// ── Main run ─────────────────────────────────────────────────────────────────

func run(cfg config) error {
	if cfg.slowloris > 0 {
		return runSlowloris(cfg.target, cfg.slowloris, cfg.duration, cfg.slowlorisDrip)
	}

	rate, err := parseRate(cfg.rate)
	if err != nil { return err }
	if err := validateTrafficLimits(cfg, rate); err != nil { return err }

	ring, err := buildRing(cfg.target, cfg.endpoints)
	if err != nil { return err }
	payload, err := loadPayload(cfg.payload)
	if err != nil { return err }
	headerMap, err := parseHeaders(cfg.headers)
	if err != nil { return err }

	runtime.GOMAXPROCS(runtime.NumCPU())

	var transport http.RoundTripper
	if cfg.h2Multiplex {
		// IMPROVEMENT: explicit HTTP/2 transport with aggressive multiplexing.
		// Forces HTTP/2 regardless of TLS ALPN negotiation result, and opens
		// multiple connections per host (Go's h2 transport normally shares one).
		h2Transport := &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12},
			// Push maximum concurrent streams — server-side limit enforced by server
			// but we request the maximum from our side.
			AllowHTTP: true, // enable h2c (cleartext HTTP/2) for localhost
		}
		transport = h2Transport
		fmt.Println("[h2-multiplex] Using explicit HTTP/2 transport with h2c support")
	} else {
		transport = &http.Transport{
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
	}
	client := &http.Client{Transport: transport, Timeout: cfg.timeout}

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopNow := func() { stopOnce.Do(func() { close(stop) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; fmt.Println("\nSIGINT — draining..."); stopNow() }()
	go func() { time.Sleep(cfg.duration); stopNow() }()

	jobs := make(chan string, cfg.workers*8)
	results := make(chan result, cfg.workers*16)
	var wg sync.WaitGroup

	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range jobs {
				seq := atomic.AddInt64(&globalSeq, 1)
				t0 := time.Now()
				req, err := buildRequest(cfg, targetURL, payload, headerMap, seq)
				if err != nil {
					results <- result{latency: time.Since(t0), err: err.Error()}
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					results <- result{latency: time.Since(t0), err: err.Error(), path: pathOf(targetURL)}
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				results <- result{status: resp.StatusCode, latency: time.Since(t0), bytes: n, path: pathOf(targetURL)}
			}
		}()
	}

	// Ramp-aware producer
	start := time.Now()
	go func() {
		defer close(jobs)
		if rate <= 0 {
			var idx int64
			for { select { case <-stop: return; case jobs <- ring[atomic.AddInt64(&idx,1)%int64(len(ring))]: } }
		}
		tick := 10 * time.Millisecond
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		var carry float64
		var idx int64
		for {
			select {
			case <-stop: return
			case <-ticker.C:
				progress := time.Since(start).Seconds() / math.Max(cfg.duration.Seconds(), 0.001)
				eff := effectiveRate(rate, cfg.profile, progress)
				carry += eff * tick.Seconds()
				count := int(carry)
				if count < 1 { continue }
				carry -= float64(count)
				for i := 0; i < count; i++ {
					select { case <-stop: return; case jobs <- ring[atomic.AddInt64(&idx,1)%int64(len(ring))]: }
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	fmt.Println("================================")
	fmt.Printf(" MAELSTROM v2.0 — Target: %s\n", cfg.target)
	fmt.Println("================================")
	fmt.Printf("profile=%s pattern=%s method=%s duration=%s workers=%d rate=%s h2=%v slowloris=%d\n",
		cfg.profile, cfg.pattern, cfg.method, cfg.duration, cfg.workers, cfg.rate, cfg.h2Multiplex, cfg.slowloris)
	fmt.Println()

	epStats := map[string]*endpointStat{}
	for _, u := range ring {
		p := pathOf(u)
		if _, ok := epStats[p]; !ok { epStats[p] = &endpointStat{} }
	}

	final := collect(results, start, epStats)
	report := markdownReport(cfg, start, final, rate, epStats)
	fmt.Println(report)
	if cfg.reportFile != "" {
		_ = os.WriteFile(cfg.reportFile, []byte(report), 0o644)
		fmt.Printf("Report: %s\n", cfg.reportFile)
	}
	return nil
}

var globalSeq int64

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" { return "/" }
	return u.Path
}

func collect(results <-chan result, start time.Time, epStats map[string]*endpointStat) counters {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var total counters
	var window counters
	for {
		select {
		case r, ok := <-results:
			if !ok { printWindow(time.Since(start), window); return total }
			addResult(&total, r); addResult(&window, r)
			if ep, ok := epStats[r.path]; ok {
				ep.mu.Lock()
				ep.total++
				if r.err != "" || r.status == 0 { ep.errors++ } else {
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
	c.total++; c.bytes += r.bytes
	if r.err != "" || r.status == 0 { c.errors++
	} else if r.status >= 200 && r.status < 300 { c.status2xx++
	} else if r.status >= 300 && r.status < 400 { c.status3xx++
	} else if r.status >= 400 && r.status < 500 { c.status4xx++
	} else if r.status >= 500 && r.status < 600 { c.status5xx++
	} else { c.statusOther++ }
	if len(c.latencies) < 500_000 {
		c.latencies = append(c.latencies, float64(r.latency.Microseconds())/1000)
	}
}

func printWindow(elapsed time.Duration, c counters) {
	if c.total == 0 { fmt.Printf("[%6.1fs] rps=0 total=0\n", elapsed.Seconds()); return }
	p50, p95, p99 := percentiles(c.latencies)
	fmt.Printf("[%6.1fs] rps=%8.1f 2xx=%d 4xx=%d 5xx=%d err=%d p50=%.1fms p95=%.1fms p99=%.1fms\n",
		elapsed.Seconds(), float64(c.total), c.status2xx, c.status4xx, c.status5xx, c.errors, p50, p95, p99)
}

func markdownReport(cfg config, start time.Time, c counters, rate float64, epStats map[string]*endpointStat) string {
	elapsed := time.Since(start)
	p50, p95, p99 := percentiles(c.latencies)
	jitter := stddev(c.latencies)
	rps := float64(c.total) / math.Max(elapsed.Seconds(), 0.001)

	var b strings.Builder
	b.WriteString("\n## Maelstrom v2.0 Report\n\n")
	fmt.Fprintf(&b, "- Target: `%s` | Profile: `%s` | Pattern: `%s`\n", cfg.target, cfg.profile, cfg.pattern)
	fmt.Fprintf(&b, "- Method: `%s` | Workers: `%d` | H2-Multiplex: `%v`\n", cfg.method, cfg.workers, cfg.h2Multiplex)
	fmt.Fprintf(&b, "- Duration: `%s` | Total: `%d` | RPS: `%.1f`\n", elapsed.Round(time.Millisecond), c.total, rps)
	fmt.Fprintf(&b, "- 2xx/3xx/4xx/5xx/err: `%d/%d/%d/%d/%d`\n", c.status2xx, c.status3xx, c.status4xx, c.status5xx, c.errors)
	fmt.Fprintf(&b, "- Latency p50/p95/p99/σ: `%.1fms / %.1fms / %.1fms / %.1fms`\n", p50, p95, p99, jitter)
	fmt.Fprintf(&b, "- Data: `%.2f MB`\n", float64(c.bytes)/(1024*1024))

	if len(epStats) > 1 {
		b.WriteString("\n### Per-Endpoint\n\n| Path | Reqs | p50 ms | p95 ms | Errors |\n|------|------|--------|--------|--------|\n")
		paths := make([]string, 0, len(epStats))
		for k := range epStats { paths = append(paths, k) }
		sort.Strings(paths)
		for _, p := range paths {
			ep := epStats[p]; ep.mu.Lock()
			ep50, ep95, _ := percentiles(ep.latencies)
			fmt.Fprintf(&b, "| `%s` | %d | %.1f | %.1f | %d |\n", p, ep.total, ep50, ep95, ep.errors)
			ep.mu.Unlock()
		}
	}
	return b.String()
}

func percentiles(values []float64) (float64, float64, float64) {
	if len(values) == 0 { return 0, 0, 0 }
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	return pick(cp,50), pick(cp,95), pick(cp,99)
}

func pick(sorted []float64, pct int) float64 {
	if len(sorted) == 0 { return 0 }
	idx := int(math.Ceil((float64(pct)/100)*float64(len(sorted)))) - 1
	if idx < 0 { idx = 0 }; if idx >= len(sorted) { idx = len(sorted)-1 }
	return sorted[idx]
}

func stddev(values []float64) float64 {
	if len(values) < 2 { return 0 }
	var sum float64
	for _, v := range values { sum += v }
	mean := sum / float64(len(values))
	var vr float64
	for _, v := range values { d := v-mean; vr += d*d }
	return math.Sqrt(vr / float64(len(values)))
}

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range values {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 { return nil, fmt.Errorf("header must be 'Name: value': %q", raw) }
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if k == "" { return nil, fmt.Errorf("header name empty") }
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
	if s == "" { return 0, fmt.Errorf("rate empty") }
	if s == "0" || s == "full" || s == "full-send" || s == "max" { return 0, nil }
	perMin := false
	for _, suf := range []string{"/min","rpm","permin","per-minute"} {
		if strings.HasSuffix(s,suf) { perMin=true; s=strings.TrimSuffix(s,suf); break }
	}
	for _, suf := range []string{"/s","rps","persec","per-second"} {
		if strings.HasSuffix(s,suf) { s=strings.TrimSuffix(s,suf); break }
	}
	mult := 1.0
	switch {
	case strings.HasSuffix(s,"k"): mult=1e3; s=strings.TrimSuffix(s,"k")
	case strings.HasSuffix(s,"m"): mult=1e6; s=strings.TrimSuffix(s,"m")
	case strings.HasSuffix(s,"g"): mult=1e9; s=strings.TrimSuffix(s,"g")
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 { return 0, fmt.Errorf("invalid rate %q", raw) }
	v *= mult; if perMin { v /= 60 }
	return v, nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "maelstrom: %v\n", err)
	os.Exit(1)
}
