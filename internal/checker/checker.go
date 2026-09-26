package checker

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-faster/errors"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/dcs"
)

const (
	// MinTimeout is the minimum check timeout in seconds.
	MinTimeout = 3
	// MaxTimeout is the maximum check timeout in seconds.
	MaxTimeout = 30
	// DefaultTimeout is the default check timeout in seconds.
	DefaultTimeout = 5

	tcpTimeout         = 1500 * time.Millisecond
	minTimeoutDuration = time.Duration(MinTimeout) * time.Second
)

// DecodeSecret decodes an MTProxy secret from hex or base64 encoding. It tries
// hex first, then base64 variants (raw URL, URL-padded, raw standard, standard).
// Trailing junk characters are stripped and retried if the initial decode fails.
func DecodeSecret(s string) ([]byte, error) {
	// The trim set overlaps the base64 alphabets ('+', '/', '_'), so the raw
	// input must be tried before the trimmed one or a secret ending in those
	// characters decodes to the wrong bytes. Hex is tried on both forms first
	// so a hex secret with junk appended can't be misread as base64.
	candidates := []string{s, strings.TrimRight(s, "!@#$%^&*()_+`~[]{}|;:',.<>?/ \t\n\r")}
	for _, c := range candidates {
		if b, err := hex.DecodeString(c); err == nil {
			return b, nil
		}
	}
	for _, c := range candidates {
		for _, enc := range []*base64.Encoding{
			base64.RawURLEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.StdEncoding,
		} {
			if b, err := enc.DecodeString(c); err == nil {
				return b, nil
			}
		}
	}
	return nil, errors.Errorf("unable to decode secret %q as hex or base64", s)
}

// TCPCheck performs a fast TCP connectivity check to server:port with DNS
// caching. It returns nil if a TCP connection can be established.
func TCPCheck(server string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %d", port)
	}
	ips, err := CachedLookupHost(server)
	if err != nil {
		return err
	}
	targetHost := server
	if len(ips) > 0 {
		targetHost = ips[0].String()
	}
	addr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", port))
	dialer := net.Dialer{
		Timeout:   tcpTimeout,
		KeepAlive: -1,
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	conn.Close()
	return nil
}

// CheckProxy performs a full MTProto handshake through the proxy at
// server:port using the given secret. It returns the round-trip ping in
// milliseconds on success. timeoutSec bounds the entire check.
func CheckProxy(ctx context.Context, server string, port int, secret string, timeoutSec int) (ping int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("PANIC in CheckProxy %s:%d: %v\n%s", server, port, r, debug.Stack())
		}
	}()

	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %d", port)
	}

	decodedSecret, err := DecodeSecret(secret)
	if err != nil {
		return 0, errors.Wrap(err, "decode secret")
	}

	targetHost := server
	if ips, err := CachedLookupHost(server); err == nil && len(ips) > 0 {
		targetHost = ips[0].String()
	}
	addr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", port))

	resolver, err := dcs.MTProxy(addr, decodedSecret, dcs.MTProxyOptions{})
	if err != nil {
		return 0, errors.Wrap(err, "create MTProxy resolver")
	}

	var (
		appID   = 6
		appHash = "eb06d4abfb49dc3eeb1aeb98ae0f581e"
	)

	if id := os.Getenv("APP_ID"); id != "" {
		if n, err := strconv.Atoi(id); err == nil {
			appID = n
		}
	}

	if hash := os.Getenv("APP_HASH"); hash != "" {
		appHash = hash
	}

	client := telegram.NewClient(appID, appHash, newCheckOptions(resolver))

	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var pingResult int64
	err = client.Run(checkCtx, func(ctx context.Context) error {
		start := time.Now()
		_, apiErr := client.API().HelpGetNearestDC(ctx)
		if apiErr != nil {
			return errors.Wrap(apiErr, "help.getNearestDC")
		}
		pingResult = time.Since(start).Milliseconds()
		return nil
	})
	if err != nil {
		return 0, err
	}
	// client.Run reports a cancelled context as success: it ends with
	// `if err := g.Wait(); !errors.Is(err, context.Canceled) { return err }`,
	// because context.Canceled is how it signals a normal shutdown once the
	// callback has returned. Without this check a cancelled check would be
	// reported as a working proxy with a 0 ms ping. checkCtx is the right
	// thing to test: on the success path gotd cancels its own derived group
	// context, not this one, so a real ping still gets through.
	if err := checkCtx.Err(); err != nil {
		return 0, err
	}
	return pingResult, nil
}
