package goproxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
)

func headerContains(header http.Header, name string, value string) bool {
	for _, v := range header[name] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(value, strings.TrimSpace(s)) {
				return true
			}
		}
	}
	return false
}

func isWebSocketHandshake(header http.Header) bool {
	return headerContains(header, "Connection", "Upgrade") &&
		headerContains(header, "Upgrade", "websocket")
}

func (proxy *ProxyHttpServer) hijackConnection(ctx *ProxyCtx, w http.ResponseWriter) (net.Conn, error) {
	// Connect to Client
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		ctx.Warnf("Hijack error: %v", err)
		return nil, err
	}
	// The client can send its first frame in the same write as the upgrade
	// request, in which case net/http has already read those bytes into the
	// request parser's buffer. Relaying from the raw connection alone loses
	// them: the origin waits for a frame it will never see and the client waits
	// for the reply. Hand back a connection that replays them first.
	if rw != nil {
		if buffered := rw.Reader.Buffered(); buffered > 0 {
			pending, peekErr := rw.Reader.Peek(buffered)
			if peekErr == nil {
				return &bufferedClientConn{
					Conn:   clientConn,
					reader: io.MultiReader(bytes.NewReader(bytes.Clone(pending)), clientConn),
				}, nil
			}
		}
	}
	return clientConn, nil
}

// bufferedClientConn is a client connection that yields bytes the HTTP request
// parser had already buffered before those still on the wire.
type bufferedClientConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedClientConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (proxy *ProxyHttpServer) proxyWebsocket(ctx *ProxyCtx, remoteConn io.ReadWriter, proxyClient io.ReadWriter) {
	// 2 is the number of goroutines, this code is implemented according to
	// https://stackoverflow.com/questions/52031332/wait-for-one-goroutine-to-finish
	waitChan := make(chan struct{}, 2)
	go func() {
		_ = copyOrWarn(ctx, remoteConn, proxyClient)
		waitChan <- struct{}{}
	}()

	go func() {
		_ = copyOrWarn(ctx, proxyClient, remoteConn)
		waitChan <- struct{}{}
	}()

	// Wait until one end closes the connection
	<-waitChan
}
