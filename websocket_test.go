package goproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebSocketMitm(t *testing.T) {
	// Start a WebSocket echo server
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		defer func() {
			_ = c.Close(websocket.StatusNormalClosure, "")
		}()

		ctx := r.Context()
		for {
			mt, message, err := c.Read(ctx)
			if err != nil {
				break
			}
			err = c.Write(ctx, mt, append([]byte("ECHO: "), message...))
			if err != nil {
				break
			}
		}
	}))
	backend.StartTLS()
	defer backend.Close()

	// Start goproxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	// Configure WebSocket client to use proxy
	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, backend.URL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	})
	require.NoError(t, err)
	defer func() {
		_ = c.Close(websocket.StatusNormalClosure, "")
	}()

	// Verify bidirectional communication
	message := []byte("Hello WebSocket")
	err = c.Write(ctx, websocket.MessageText, message)
	require.NoError(t, err)

	mt, response, err := c.Read(ctx)
	require.NoError(t, err)

	assert.Equal(t, websocket.MessageText, mt)
	assert.Equal(t, "ECHO: Hello WebSocket", string(response))
}

// TestWebSocketEarlyClientFrame covers the plain HTTP path, where the client
// connection is taken by hijackConnection rather than by the MITM loop.
//
// A client may send its first frame in the same write as the upgrade request.
// net/http has then already read those bytes into the request parser's buffer,
// and a relay that reads the raw connection never sees them: the origin waits
// for a frame that will not arrive and the client waits for the reply. The
// bytes here are not real framing because the bug is about bytes, not frames.
func TestWebSocketEarlyClientFrame(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err := rw.Flush(); err != nil {
			return
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(rw, payload); err != nil {
			return
		}
		_, _ = rw.Write(append([]byte("ECHO"), payload...))
		_ = rw.Flush()
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	var dialer net.Dialer
	raw, err := dialer.DialContext(context.Background(), "tcp", proxyURL.Host)
	require.NoError(t, err)
	defer func() {
		_ = raw.Close()
	}()
	require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))

	upgrade := "GET " + origin.URL + " HTTP/1.1\r\n" +
		"Host: " + originURL.Host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	// The whole point of the test: one write carrying both.
	_, err = raw.Write(append([]byte(upgrade), []byte("ping")...))
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	reply := make([]byte, 8)
	_, err = io.ReadFull(br, reply)
	require.NoError(t, err, "the origin never received the payload sent with the upgrade request")
	assert.Equal(t, "ECHOping", string(reply))
}
