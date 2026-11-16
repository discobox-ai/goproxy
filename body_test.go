package goproxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const truncatedPrefix = "first part of the body "

// truncatingOrigin answers with a prefix of the body and then breaks off: a
// chunked response loses its last chunk, a known-length one falls short of its
// Content-Length. complete answers the whole body instead.
func truncatingOrigin(knownLength, complete bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		full := truncatedPrefix + strings.Repeat("x", 64<<10)
		if knownLength {
			w.Header().Set("Content-Length", strconv.Itoa(len(full)))
		}
		w.WriteHeader(http.StatusOK)
		if complete {
			_, _ = io.WriteString(w, full)
			return
		}
		_, _ = io.WriteString(w, truncatedPrefix)
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	})
}

// An origin body that fails after a prefix reaches the client as an incomplete
// transfer on every proxy path — plain HTTP, MITM over HTTP/1.1 and MITM over
// HTTP/2 — chunked or with a known length, and whether or not filters replaced
// the request's context and the response's body. A body that does not fail
// still arrives whole.
func TestUpstreamBodyFailureIsAnIncompleteTransfer(t *testing.T) {
	for _, path := range []string{"http", "mitm-h1", "mitm-h2"} {
		for _, framing := range []string{"chunked", "known-length"} {
			for _, filtered := range []bool{false, true} {
				for _, complete := range []bool{false, true} {
					name := path + "/" + framing
					if filtered {
						name += "/filtered"
					}
					if complete {
						name += "/complete"
					}
					t.Run(name, func(t *testing.T) {
						testUpstreamBody(t, path, framing == "known-length", filtered, complete)
					})
				}
			}
		}
	}
}

func testUpstreamBody(t *testing.T, path string, knownLength, filtered, complete bool) {
	t.Helper()
	origin := httptest.NewUnstartedServer(truncatingOrigin(knownLength, complete))
	origin.Config.ErrorLog = nil
	if path == "http" {
		origin.Start()
	} else {
		origin.EnableHTTP2 = path == "mitm-h2"
		origin.StartTLS()
	}
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.AllowHTTP2 = path == "mitm-h2"
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: path == "mitm-h2",
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test origin
	}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	if filtered {
		// A request filter may hand back a request on a context of its own;
		// the response is still aborted.
		proxy.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return req.WithContext(context.Background()), nil
		})
		proxy.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(resp.Body), resp.Body}
			return resp
		})
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AddCert(goproxy.GoproxyCa.Leaf)
	nextProtos := []string{"http/1.1"}
	if path == "mitm-h2" {
		nextProtos = []string{"h2"}
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: path == "mitm-h2",
		TLSClientConfig:   &tls.Config{RootCAs: caPool, InsecureSkipVerify: true, NextProtos: nextProtos}, //nolint:gosec // test proxy
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL+"/file", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err, "the response head should reach the client before the body fails")
	defer resp.Body.Close()
	if path == "mitm-h2" {
		require.Equal(t, 2, resp.ProtoMajor, "client should speak HTTP/2 to the MITM")
	}
	body, err := io.ReadAll(resp.Body)
	if complete {
		require.NoError(t, err)
		assert.Equal(t, len(truncatedPrefix)+64<<10, len(body))
		return
	}
	require.Error(t, err, "read %d bytes ending cleanly, want an incomplete transfer", len(body))
	assert.NotErrorIs(t, err, context.DeadlineExceeded, "the transfer should fail at once, not hang")
	assert.Equal(t, truncatedPrefix, string(body), "the client should get every byte the origin sent")
}

type failingBody struct{ err error }

func (b failingBody) Read([]byte) (int, error) { return 0, b.err }
func (failingBody) Close() error               { return nil }

// A caller that invokes the proxy's handler itself, outside an http.Server,
// gets the response as written rather than a panic when the body fails.
func TestUpstreamBodyFailureOutsideAServerDoesNotPanic(t *testing.T) {
	origin := httptest.NewServer(truncatingOrigin(false, true))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
		resp.Body = failingBody{errors.New("upstream went away")}
		return resp
	})
	req := httptest.NewRequest(http.MethodGet, origin.URL+"/file", nil)
	rec := httptest.NewRecorder()
	assert.NotPanics(t, func() { proxy.ServeHTTP(rec, req) })
	assert.Equal(t, http.StatusOK, rec.Code)
}
