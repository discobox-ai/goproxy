package goproxy

import (
	"io"
	"net/http"
)

// copyResponseBody copies an upstream response body to the client, keeping a
// failure to read the body apart from a failure to write it: only the first
// means the client is about to be handed a message shorter than the one the
// upstream sent. readErr is never io.EOF.
func copyResponseBody(dst io.Writer, src io.Reader) (n int64, readErr, writeErr error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			n += int64(nw)
			if ew == nil && nw != nr {
				ew = io.ErrShortWrite
			}
			if ew != nil {
				return n, nil, ew
			}
		}
		if er == io.EOF {
			return n, nil, nil
		}
		if er != nil {
			return n, er, nil
		}
	}
}

// abortIncompleteResponse ends the response being written to w for r without
// completing it, once its body could not be read to the end, so the client
// sees an incomplete message rather than the clean end of a shorter one: an
// HTTP/1.1 connection closes without the last chunk (or before the declared
// Content-Length), and an HTTP/2 stream is reset rather than ended. Returning
// from the handler instead would let the server finalize the message.
//
// It first flushes what was written, so the client still gets the response
// head and every byte the upstream did send, and then panics with
// http.ErrAbortHandler, as net/http/httputil.ReverseProxy does, which net/http
// and golang.org/x/net/http2 recover from quietly. Like ReverseProxy, it
// panics only when an http.Server is serving r, so a caller invoking the
// proxy's handler directly is not handed a panic; there it returns and the
// response ends as written.
func abortIncompleteResponse(w http.ResponseWriter, r *http.Request) {
	if r.Context().Value(http.ServerContextKey) == nil {
		return
	}
	_ = http.NewResponseController(w).Flush()
	panic(http.ErrAbortHandler)
}
