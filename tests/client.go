// tests/client.go
//
// HTTP/3 test client — fires a suite of sample requests against
// a local MsQuic server and prints a pass/fail summary.
//
// Usage:
//   go run tests/client.go
//   go run tests/client.go -addr localhost:4433 -insecure -count 20
//
// Dependencies (go get before running):
//   github.com/quic-go/quic-go
//   github.com/quic-go/quic-go/http3

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// ── CLI flags ─────────────────────────────────────────────────────────────────

var (
	addr      = flag.String("addr", "localhost:4433", "server address (host:port)")
	insecure  = flag.Bool("insecure", true, "skip TLS certificate verification")
	timeout   = flag.Duration("timeout", 5*time.Second, "per-request timeout")
	count     = flag.Int("count", 5, "number of times to repeat the full suite")
	parallel  = flag.Int("parallel", 4, "max concurrent requests")
	verbose   = flag.Bool("v", false, "print response bodies")
)

// ── Test case definition ──────────────────────────────────────────────────────

type testCase struct {
	name   string
	method string
	path   string
	body   []byte        // nil → no body
	expect int           // expected HTTP status code
}

// suite defines the sample requests sent on each round.
var suite = []testCase{
	{
		name:   "GET /",
		method: http.MethodGet,
		path:   "/",
		expect: http.StatusOK,
	},
	{
		name:   "GET /healthz",
		method: http.MethodGet,
		path:   "/healthz",
		expect: http.StatusOK,
	},
	{
		name:   "GET /echo",
		method: http.MethodGet,
		path:   "/echo?msg=hello-quic",
		expect: http.StatusOK,
	},
	{
		name:   "POST /echo",
		method: http.MethodPost,
		path:   "/echo",
		body:   []byte(`{"message":"http3 post test"}`),
		expect: http.StatusOK,
	},
	{
		name:   "GET /large (64 KB)",
		method: http.MethodGet,
		path:   "/large",
		expect: http.StatusOK,
	},
	{
		name:   "GET /slow (latency probe)",
		method: http.MethodGet,
		path:   "/slow",
		expect: http.StatusOK,
	},
	{
		name:   "HEAD /",
		method: http.MethodHead,
		path:   "/",
		expect: http.StatusOK,
	},
	{
		name:   "GET /notfound (expect 404)",
		method: http.MethodGet,
		path:   "/notfound",
		expect: http.StatusNotFound,
	},
	{
		name:   "POST /data (binary payload)",
		method: http.MethodPost,
		path:   "/data",
		body:   bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256), // 1 KB
		expect: http.StatusOK,
	},
	{
		name:   "GET /headers",
		method: http.MethodGet,
		path:   "/headers",
		expect: http.StatusOK,
	},
}

// ── Result ────────────────────────────────────────────────────────────────────

type result struct {
	tc       testCase
	round    int
	status   int
	duration time.Duration
	err      error
	passed   bool
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	log.SetFlags(0)

	base := fmt.Sprintf("https://%s", *addr)

	// ── Build HTTP/3 client ───────────────────────────────────────────────────
	tlsCfg := &tls.Config{
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{"h3"},   // ← was "h3", confirm it matches -alpn
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
	}
	defer transport.Close()

	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
	}

	// ── Work queue ────────────────────────────────────────────────────────────
	type job struct {
		tc    testCase
		round int
	}

	jobs := make(chan job)
	results := make(chan result)

	// Produce jobs
	go func() {
		for r := 1; r <= *count; r++ {
			for _, tc := range suite {
				jobs <- job{tc, r}
			}
		}
		close(jobs)
	}()

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < *parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- runRequest(client, base, j.tc, j.round)
			}
		}()
	}

	// Close results when all workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// ── Collect & print ───────────────────────────────────────────────────────
	var (
		passed  int64
		failed  int64
		total   int64
		totalMS int64
	)

	type row struct {
		round    int
		name     string
		status   string
		latency  string
		pass     string
		errStr   string
	}
	var rows []row

	for res := range results {
		atomic.AddInt64(&total, 1)
		atomic.AddInt64(&totalMS, res.duration.Milliseconds())

		if res.passed {
			atomic.AddInt64(&passed, 1)
		} else {
			atomic.AddInt64(&failed, 1)
		}

		statusStr := fmt.Sprintf("%d", res.status)
		passStr   := "✓"
		errStr    := ""

		if !res.passed {
			passStr = "✗"
			if res.err != nil {
				errStr = res.err.Error()
			} else {
				errStr = fmt.Sprintf("want %d got %d", res.tc.expect, res.status)
			}
		}
		if res.status == 0 {
			statusStr = "---"
		}

		if *verbose || !res.passed {
			rows = append(rows, row{
				round:   res.round,
				name:    res.tc.name,
				status:  statusStr,
				latency: fmt.Sprintf("%dms", res.duration.Milliseconds()),
				pass:    passStr,
				errStr:  errStr,
			})
		}
	}

	// ── Summary table ─────────────────────────────────────────────────────────
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	if len(rows) > 0 {
		fmt.Fprintln(w, "ROUND\tTEST\tSTATUS\tLATENCY\tRESULT\tNOTE")
		fmt.Fprintln(w, "─────\t────\t──────\t───────\t──────\t────")
		for _, r := range rows {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
				r.round, r.name, r.status, r.latency, r.pass, r.errStr)
		}
		fmt.Fprintln(w)
	}

	avgMS := int64(0)
	if total > 0 {
		avgMS = totalMS / total
	}

	fmt.Fprintf(w, "Requests\t%d\n", total)
	fmt.Fprintf(w, "Passed  \t%d\n", passed)
	fmt.Fprintf(w, "Failed  \t%d\n", failed)
	fmt.Fprintf(w, "Avg latency\t%dms\n", avgMS)
	_ = w.Flush()

	fmt.Println()
	if failed == 0 {
		fmt.Println("All tests passed.")
	} else {
		fmt.Printf("%d test(s) FAILED.\n", failed)
		os.Exit(1)
	}
}

// ── runRequest executes one HTTP/3 request and returns a result ───────────────

func runRequest(client *http.Client, base string, tc testCase, round int) result {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := base + tc.path

	var bodyReader io.Reader
	if tc.body != nil {
		bodyReader = bytes.NewReader(tc.body)
	}

	req, err := http.NewRequestWithContext(ctx, tc.method, url, bodyReader)
	if err != nil {
		return result{tc: tc, round: round, err: err}
	}

	// Tag every request so the server can identify test traffic
	req.Header.Set("User-Agent", "quic-test-client/1.0")
	req.Header.Set("X-Test-Round", fmt.Sprintf("%d", round))
	if tc.body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	start := time.Now()
	resp, err := client.Do(req)
	dur   := time.Since(start)

	if err != nil {
		return result{tc: tc, round: round, duration: dur, err: err}
	}
	defer resp.Body.Close()

	// Drain the body so the connection is reused cleanly
	_, _ = io.Copy(io.Discard, resp.Body)

	passed := resp.StatusCode == tc.expect
	return result{
		tc:       tc,
		round:    round,
		status:   resp.StatusCode,
		duration: dur,
		passed:   passed,
	}
}