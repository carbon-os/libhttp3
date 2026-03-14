// tests/webtransport_client.go
//
// WebTransport test client — mirrors examples/webtransport_client.cpp
// Runs four tests against a local h3_webtransport_server instance.
//
// Usage:
//   go run tests/webtransport_client.go
//   go run tests/webtransport_client.go -addr localhost:4006 -insecure
//
// Dependencies:
//   go get github.com/quic-go/quic-go
//   go get github.com/quic-go/webtransport-go

package main

import (
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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	webtransport "github.com/quic-go/webtransport-go"
)

// ── CLI flags ─────────────────────────────────────────────────────────────────

var (
	addr     = flag.String("addr", "localhost:4006", "server address (host:port)")
	insecure = flag.Bool("insecure", true, "skip TLS certificate verification")
	timeout  = flag.Duration("timeout", 10*time.Second, "per-test timeout")
	verbose  = flag.Bool("v", false, "extra per-stream logging")
)

// ── Result tracking ───────────────────────────────────────────────────────────

type result struct {
	name    string
	passed  bool
	elapsed time.Duration
	note    string
}

var (
	results   []result
	resultsMu sync.Mutex
)

func record(name string, passed bool, elapsed time.Duration, note string) {
	resultsMu.Lock()
	results = append(results, result{name, passed, elapsed, note})
	resultsMu.Unlock()
	mark := "✓"
	if !passed {
		mark = "✗"
	}
	log.Printf("  %s  %-40s  %s  %s", mark, name, elapsed.Round(time.Millisecond), note)
}

func pass(name string, elapsed time.Duration)              { record(name, true, elapsed, "") }
func fail(name string, elapsed time.Duration, note string) { record(name, false, elapsed, note) }

// ── Shared QUIC config ────────────────────────────────────────────────────────

func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
	}
}

// ── Dialer factory ────────────────────────────────────────────────────────────

func newDialer() *webtransport.Dialer {
	return &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *insecure,
			NextProtos:         []string{"h3"},
		},
		QUICConfig: quicConfig(),
	}
}

func dial(ctx context.Context, d *webtransport.Dialer, path string) (*http.Response, *webtransport.Session, error) {
	url := fmt.Sprintf("https://%s%s", *addr, path)
	return d.Dial(ctx, url, http.Header{})
}

// ── Test 1: /echo ─────────────────────────────────────────────────────────────
// Open a bidi stream, send a message, read the echo back.
// Send a datagram, receive the echo back.

func testEcho(d *webtransport.Dialer) {
	log.Println("\n=== test_echo ===")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, sess, err := dial(ctx, d, "/echo")
	if err != nil {
		fail("echo/dial", 0, err.Error())
		return
	}
	defer sess.CloseWithError(0, "test_echo done")
	log.Printf("[echo] connected  status=%d", resp.StatusCode)

	// ── bidi stream round-trip ────────────────────────────────────────────────
	{
		start := time.Now()
		stream, err := sess.OpenStreamSync(ctx)
		if err != nil {
			fail("echo/bidi/open", time.Since(start), err.Error())
			goto datagram
		}

		const payload = "hello-webtransport"
		if _, err := stream.Write([]byte(payload)); err != nil {
			fail("echo/bidi/write", time.Since(start), err.Error())
			stream.Close()
			goto datagram
		}
		stream.Close() // FIN send side so server knows we are done writing

		got, err := io.ReadAll(stream)
		if err != nil && err != io.EOF {
			fail("echo/bidi/read", time.Since(start), err.Error())
			goto datagram
		}
		if string(got) == payload {
			pass("echo/bidi/round-trip", time.Since(start))
		} else {
			fail("echo/bidi/round-trip", time.Since(start),
				fmt.Sprintf("want %q got %q", payload, string(got)))
		}
	}

datagram:
	// ── datagram round-trip ───────────────────────────────────────────────────
	{
		start := time.Now()
		const dgPayload = "datagram-ping"

		if err := sess.SendDatagram([]byte(dgPayload)); err != nil {
			fail("echo/datagram/send", time.Since(start), err.Error())
			return
		}

		dgCtx, dgCancel := context.WithTimeout(ctx, 3*time.Second)
		defer dgCancel()

		got, err := sess.ReceiveDatagram(dgCtx)
		if err != nil {
			fail("echo/datagram/recv", time.Since(start), err.Error())
			return
		}
		if string(got) == dgPayload {
			pass("echo/datagram/round-trip", time.Since(start))
		} else {
			fail("echo/datagram/round-trip", time.Since(start),
				fmt.Sprintf("want %q got %q", dgPayload, string(got)))
		}
	}
}

// ── Test 2: /chat ─────────────────────────────────────────────────────────────
// Expect server-pushed unidi welcome stream.
// Open a bidi stream, send a message, receive the "server heard: …" reply.

func testChat(d *webtransport.Dialer) {
	log.Println("\n=== test_chat ===")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, sess, err := dial(ctx, d, "/chat")
	if err != nil {
		fail("chat/dial", 0, err.Error())
		return
	}
	defer sess.CloseWithError(0, "test_chat done")
	log.Printf("[chat] connected  status=%d", resp.StatusCode)

	// ── receive welcome unidi stream from server ───────────────────────────────
	{
		start := time.Now()
		uCtx, uCancel := context.WithTimeout(ctx, 3*time.Second)
		defer uCancel()

		// AcceptUniStream returns *webtransport.ReceiveStream
		us, err := sess.AcceptUniStream(uCtx)
		if err != nil {
			fail("chat/welcome-stream/accept", time.Since(start), err.Error())
			goto bidi
		}
		welcome, err := io.ReadAll(us)
		if err != nil && err != io.EOF {
			fail("chat/welcome-stream/read", time.Since(start), err.Error())
			goto bidi
		}
		log.Printf("[chat] welcome: %s", string(welcome))
		if len(welcome) > 0 {
			pass("chat/welcome-stream", time.Since(start))
		} else {
			fail("chat/welcome-stream", time.Since(start), "empty welcome message")
		}
	}

bidi:
	// ── bidi stream: send message, read server reply ───────────────────────────
	{
		start := time.Now()
		stream, err := sess.OpenStreamSync(ctx)
		if err != nil {
			fail("chat/bidi/open", time.Since(start), err.Error())
			return
		}

		const msg = "hi from go client"
		if _, err := stream.Write([]byte(msg)); err != nil {
			fail("chat/bidi/write", time.Since(start), err.Error())
			stream.Close()
			return
		}
		stream.Close()

		got, err := io.ReadAll(stream)
		if err != nil && err != io.EOF {
			fail("chat/bidi/read", time.Since(start), err.Error())
			return
		}
		expected := "server heard: " + msg
		if string(got) == expected {
			pass("chat/bidi/reply", time.Since(start))
		} else {
			fail("chat/bidi/reply", time.Since(start),
				fmt.Sprintf("want %q got %q", expected, string(got)))
		}
	}
}

// ── Test 3: /stream_test ──────────────────────────────────────────────────────
// Server opens 3 unidi streams, 2 bidi streams, sends 5 datagrams.
// Client receives all of them and echoes bidi streams back.

func testStreamTest(d *webtransport.Dialer) {
	log.Println("\n=== test_stream_test ===")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, sess, err := dial(ctx, d, "/stream_test")
	if err != nil {
		fail("stream_test/dial", 0, err.Error())
		return
	}
	defer sess.CloseWithError(0, "test_stream_test done")
	log.Printf("[stream_test] connected  status=%d", resp.StatusCode)

	var (
		unidiCount    int64
		bidiCount     int64
		datagramCount int64
		wg            sync.WaitGroup
	)

	// ── Accept server-initiated unidi streams ─────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			uCtx, uCancel := context.WithTimeout(ctx, 2*time.Second)
			us, err := sess.AcceptUniStream(uCtx) // *webtransport.ReceiveStream
			uCancel()
			if err != nil {
				break
			}
			wg.Add(1)
			go func(s *webtransport.ReceiveStream) {
				defer wg.Done()
				data, err := io.ReadAll(s)
				if err != nil && err != io.EOF {
					log.Printf("[stream_test] unidi read err: %v", err)
					return
				}
				atomic.AddInt64(&unidiCount, 1)
				if *verbose {
					log.Printf("[stream_test] unidi rx: %s", string(data))
				}
			}(us)
		}
	}()

	// ── Accept server-initiated bidi streams, echo data back ──────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			bCtx, bCancel := context.WithTimeout(ctx, 2*time.Second)
			bs, err := sess.AcceptStream(bCtx) // *webtransport.Stream
			bCancel()
			if err != nil {
				break
			}
			wg.Add(1)
			go func(s *webtransport.Stream) {
				defer wg.Done()
				data, err := io.ReadAll(s)
				if err != nil && err != io.EOF {
					log.Printf("[stream_test] bidi read err: %v", err)
					return
				}
				_, _ = s.Write(data)
				s.Close()
				atomic.AddInt64(&bidiCount, 1)
				if *verbose {
					log.Printf("[stream_test] bidi echo: %s", string(data))
				}
			}(bs)
		}
	}()

	// ── Receive datagrams ─────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			dgCtx, dgCancel := context.WithTimeout(ctx, 2*time.Second)
			dg, err := sess.ReceiveDatagram(dgCtx)
			dgCancel()
			if err != nil {
				break
			}
			atomic.AddInt64(&datagramCount, 1)
			if *verbose {
				log.Printf("[stream_test] datagram rx: %s", string(dg))
			}
		}
	}()

	wg.Wait()
	start := time.Now()

	u := atomic.LoadInt64(&unidiCount)
	b := atomic.LoadInt64(&bidiCount)
	dg := atomic.LoadInt64(&datagramCount)
	log.Printf("[stream_test] unidi=%d bidi=%d datagrams=%d", u, b, dg)

	if u == 3 {
		pass("stream_test/unidi-streams", time.Since(start))
	} else {
		fail("stream_test/unidi-streams", time.Since(start),
			fmt.Sprintf("want 3 got %d", u))
	}
	if b == 2 {
		pass("stream_test/bidi-streams", time.Since(start))
	} else {
		fail("stream_test/bidi-streams", time.Since(start),
			fmt.Sprintf("want 2 got %d", b))
	}
	if dg == 5 {
		pass("stream_test/datagrams", time.Since(start))
	} else {
		fail("stream_test/datagrams", time.Since(start),
			fmt.Sprintf("want 5 got %d", dg))
	}
}

// ── Test 4: rejected path ─────────────────────────────────────────────────────
// Server has no WebTransport handler for /does-not-exist; expects non-200.

func testRejected(d *webtransport.Dialer) {
	log.Println("\n=== test_rejected ===")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	start := time.Now()
	resp, sess, err := dial(ctx, d, "/does-not-exist")

	if err != nil {
		pass("rejected/non-200", time.Since(start))
		log.Printf("[rejected] dial error (expected): %v", err)
		return
	}
	if sess != nil {
		sess.CloseWithError(0, "")
	}
	if resp != nil && resp.StatusCode != http.StatusOK {
		pass("rejected/non-200", time.Since(start))
		log.Printf("[rejected] got status %d (expected)", resp.StatusCode)
	} else {
		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}
		fail("rejected/non-200", time.Since(start),
			fmt.Sprintf("expected rejection, got status %d", statusCode))
	}
}

// ── Plain HTTP/3 sanity check ─────────────────────────────────────────────────

func testHTTP() {
	log.Println("\n=== plain HTTP/3 sanity check ===")

	start := time.Now()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *insecure,
			NextProtos:         []string{"h3"},
		},
		QUICConfig: quicConfig(),
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: *timeout}
	url := fmt.Sprintf("https://%s/healthz", *addr)
	resp, err := client.Get(url)
	if err != nil {
		fail("http/GET /healthz", time.Since(start), err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		pass("http/GET /healthz", time.Since(start))
		log.Printf("[http] body: %s", string(body))
	} else {
		fail("http/GET /healthz", time.Since(start),
			fmt.Sprintf("status %d", resp.StatusCode))
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	log.SetFlags(0)

	log.Printf("WebTransport Go client  addr=%s", *addr)

	d := newDialer()

	testHTTP()
	testEcho(d)
	testChat(d)
	testStreamTest(d)
	testRejected(d)

	// ── Summary table ─────────────────────────────────────────────────────────
	var passed, failed int64
	for _, r := range results {
		if r.passed {
			passed++
		} else {
			failed++
		}
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "TEST\tPASS\tLATENCY\tNOTE")
	fmt.Fprintln(w, "────\t────\t───────\t────")
	for _, r := range results {
		mark := "✓"
		if !r.passed {
			mark = "✗"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			r.name, mark, r.elapsed.Round(time.Millisecond), r.note)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Passed\t%d\n", passed)
	fmt.Fprintf(w, "Failed\t%d\n", failed)
	_ = w.Flush()

	fmt.Println()
	if failed == 0 {
		fmt.Println("All tests passed.")
	} else {
		fmt.Printf("%d test(s) FAILED.\n", failed)
		os.Exit(1)
	}
}