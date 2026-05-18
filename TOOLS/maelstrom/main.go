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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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
	target     string
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
	var targetShort, methodShort, rateShort, payloadShort string
	var durationShort time.Duration
	var workersShort int

	flag.StringVar(&cfg.target, "target", "http://localhost:3456/", "Target URL endpoint")
	flag.StringVar(&targetShort, "t", "", "Target URL endpoint")
	flag.StringVar(&cfg.method, "method", "GET", "HTTP method")
	flag.StringVar(&methodShort, "m", "", "HTTP method")
	flag.StringVar(&cfg.rate, "rate", "1000", "Target rate. Bare value is RPS; supports 3m/min, 50000rps, 120000rpm. Use 0 for full-send.")
	flag.StringVar(&rateShort, "r", "", "Target rate")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "Test duration, e.g. 30s, 5m")
	flag.DurationVar(&durationShort, "d", 0, "Test duration")
	flag.IntVar(&cfg.workers, "workers", defaultWorkers, "Concurrent workers/goroutines")
	flag.IntVar(&workersShort, "w", 0, "Concurrent workers/goroutines")
	flag.StringVar(&cfg.payload, "payload", "", "Path to optional payload file for POST/PUT/PATCH")
	flag.StringVar(&payloadShort, "p", "", "Path to optional payload file")
	flag.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Per-request timeout")
	flag.StringVar(&cfg.reportFile, "report-file", "", "Optional markdown report output path")
	flag.Var(&cfg.headers, "headers", "Custom header, e.g. 'Authorization: Bearer ...'. Repeatable.")
	flag.Var(&cfg.headers, "H", "Custom header, e.g. 'Authorization: Bearer ...'. Repeatable.")

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

	cfg.method = strings.ToUpper(strings.TrimSpace(cfg.method))
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
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("target host must resolve before testing: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("target host resolved to no IPs")
	}
	for _, ip := range ips {
		if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return fmt.Errorf("refusing public target %s (%s). Maelstrom stress mode is for localhost/private/LAN/VPN targets only", host, ip.String())
		}
	}
	return nil
}

func run(cfg config) error {
	rate, err := parseRate(cfg.rate)
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
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.timeout,
	}

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopNow := func() { stopOnce.Do(func() { close(stop) }) }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Println("\nSIGINT received. Stopping new requests and draining workers...")
		stopNow()
	}()

	go func() {
		time.Sleep(cfg.duration)
		stopNow()
	}()

	jobs := make(chan struct{}, cfg.workers*8)
	results := make(chan result, cfg.workers*16)
	var wg sync.WaitGroup

	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go worker(&wg, client, cfg, payload, headerMap, jobs, results)
	}

	go producer(stop, jobs, rate)
	go func() {
		wg.Wait()
		close(results)
	}()

	start := time.Now()
	fmt.Println("================================")
	fmt.Println(" MAELSTROM - Private Target Load Tester")
	fmt.Println("================================")
	fmt.Printf("target=%s method=%s duration=%s workers=%d rate=%s timeout=%s\n", cfg.target, cfg.method, cfg.duration, cfg.workers, cfg.rate, cfg.timeout)
	if rate <= 0 {
		fmt.Println("mode=full-send (local worker-limited)")
	} else {
		fmt.Printf("mode=rate-limited rps=%.2f rpm=%.0f\n", rate, rate*60)
	}
	fmt.Println("")

	final := collect(results, start)
	report := markdownReport(cfg, start, final)
	fmt.Println(report)

	if cfg.reportFile != "" {
		if err := os.WriteFile(cfg.reportFile, []byte(report), 0o644); err != nil {
			return err
		}
		fmt.Printf("Report written: %s\n", cfg.reportFile)
	}
	return nil
}

func producer(stop <-chan struct{}, jobs chan<- struct{}, rate float64) {
	defer close(jobs)

	if rate <= 0 {
		for {
			select {
			case <-stop:
				return
			case jobs <- struct{}{}:
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
			count := int(carry)
			if count < 1 {
				continue
			}
			carry -= float64(count)
			for i := 0; i < count; i++ {
				select {
				case <-stop:
					return
				case jobs <- struct{}{}:
				}
			}
		}
	}
}

func worker(wg *sync.WaitGroup, client *http.Client, cfg config, payload []byte, headers map[string]string, jobs <-chan struct{}, results chan<- result) {
	defer wg.Done()
	for range jobs {
		start := time.Now()
		req, err := newRequest(cfg, payload, headers)
		if err != nil {
			results <- result{status: 0, latency: time.Since(start), err: err.Error()}
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			results <- result{status: 0, latency: time.Since(start), err: err.Error()}
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		results <- result{status: resp.StatusCode, latency: time.Since(start), bytes: n}
	}
}

func newRequest(cfg config, payload []byte, headers map[string]string) (*http.Request, error) {
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(cfg.method, cfg.target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Maelstrom/1.0 private-load-test")
	req.Header.Set("Accept", "*/*")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if len(payload) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func collect(results <-chan result, start time.Time) counters {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var total counters
	var window counters
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
	p50, p95, p99 := percentiles(c.latencies)
	fmt.Printf("[%6.1fs] rps=%8.1f 2xx=%d 3xx=%d 4xx=%d 5xx=%d err=%d p50=%.1fms p95=%.1fms p99=%.1fms mb=%.2f\n",
		elapsed.Seconds(), rps, c.status2xx, c.status3xx, c.status4xx, c.status5xx, c.errors, p50, p95, p99, float64(c.bytes)/(1024*1024))
}

func markdownReport(cfg config, start time.Time, c counters) string {
	elapsed := time.Since(start)
	p50, p95, p99 := percentiles(c.latencies)
	rps := float64(c.total) / math.Max(elapsed.Seconds(), 0.001)
	success := c.status2xx + c.status3xx
	failure := c.status4xx + c.status5xx + c.statusOther + c.errors

	var b strings.Builder
	b.WriteString("\n## Maelstrom Report\n\n")
	fmt.Fprintf(&b, "- Target: `%s`\n", cfg.target)
	fmt.Fprintf(&b, "- Method: `%s`\n", cfg.method)
	fmt.Fprintf(&b, "- Duration: `%s`\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(&b, "- Workers: `%d`\n", cfg.workers)
	fmt.Fprintf(&b, "- Total requests: `%d`\n", c.total)
	fmt.Fprintf(&b, "- Average RPS: `%.1f`\n", rps)
	fmt.Fprintf(&b, "- Success responses: `%d`\n", success)
	fmt.Fprintf(&b, "- Failure/error responses: `%d`\n", failure)
	fmt.Fprintf(&b, "- 2xx / 3xx / 4xx / 5xx / other / errors: `%d / %d / %d / %d / %d / %d`\n", c.status2xx, c.status3xx, c.status4xx, c.status5xx, c.statusOther, c.errors)
	fmt.Fprintf(&b, "- Latency p50 / p95 / p99: `%.1fms / %.1fms / %.1fms`\n", p50, p95, p99)
	fmt.Fprintf(&b, "- Data transferred: `%.2f MB`\n", float64(c.bytes)/(1024*1024))
	if len(c.latencies) == 250_000 {
		b.WriteString("- Note: latency percentiles are based on the first 250,000 recorded samples.\n")
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

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range values {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("header must be in 'Name: value' format: %q", raw)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
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

	value, err := parseScaledNumber(s)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("rate cannot be negative")
	}
	if perMinute {
		value = value / 60
	}
	return value, nil
}

func parseScaledNumber(raw string) (float64, error) {
	s := strings.TrimSpace(raw)
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
	value, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate %q", raw)
	}
	return value * mult, nil
}

func exitError(err error) {
	fmt.Fprintf(os.Stderr, "maelstrom: %v\n", err)
	os.Exit(1)
}
