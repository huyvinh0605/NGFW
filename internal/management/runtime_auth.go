package management

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/net/websocket"
)

// Session/event reads include M3 inspection evidence and require VIEWER or
// higher when authentication is configured. Health and legacy config reads
// retain their existing public contract; no-auth embedded test APIs still work.
func runtimeReadPath(path string) bool {
	for _, prefix := range []string{"/api/v1/inspection", "/api/v1/security/events", "/api/v1/sessions", "/api/v1/events"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return path == "/ws/events" || path == "/ws/stats"
}

const webSocketProtocol = "ngfw.v1"
const webSocketCredentialPrefix = "ngfw.auth."

// Browsers cannot set Authorization on a WebSocket constructor. Carry the
// credential in an encoded subprotocol, never in URLs or the selected protocol.
// A malformed or ambiguous credential fails authentication before upgrade.
func webSocketCredential(r *http.Request) string {
	var token string
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, raw := range strings.Split(header, ",") {
			protocol := strings.TrimSpace(raw)
			if !strings.HasPrefix(protocol, webSocketCredentialPrefix) {
				continue
			}
			if token != "" || len(protocol) > 8192 {
				return ""
			}
			decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(protocol, webSocketCredentialPrefix))
			if err != nil || len(decoded) == 0 || len(decoded) > 4096 {
				return ""
			}
			token = string(decoded)
		}
	}
	return token
}

func authenticatedWebSocket(handler websocket.Handler) websocket.Server {
	return websocket.Server{Handler: handler, Handshake: func(config *websocket.Config, r *http.Request) error {
		origin, err := websocket.Origin(config, r)
		if err != nil {
			return err
		}
		if origin == nil {
			return errors.New("null origin")
		}
		config.Origin = origin
		requested := config.Protocol
		config.Protocol = nil
		for _, protocol := range requested {
			if protocol == webSocketProtocol {
				config.Protocol = []string{webSocketProtocol}
				break
			}
		}
		return nil
	}}
}
