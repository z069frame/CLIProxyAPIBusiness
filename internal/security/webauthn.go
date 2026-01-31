package security

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	internalsettings "github.com/router-for-me/CLIProxyAPIBusiness/internal/settings"
)

// Default WebAuthn relying party configuration.
const (
	// webAuthnRPID is the default relying party ID.
	webAuthnRPID = "localhost"
	// webAuthnRPName is the default relying party display name.
	webAuthnRPName = "ZeroFrameTech Admin"
	// webAuthnOrigin is the default WebAuthn origin.
	webAuthnOrigin = "http://localhost"
)

// NewWebAuthn builds a WebAuthn configuration using DB-backed overrides.
func NewWebAuthn() (*webauthn.WebAuthn, error) {
	rpName := webAuthnRPName
	if override := dbConfigString("WEB_AUTHN_RP_NAME"); override != "" {
		rpName = override
	}

	origins := dbConfigStrings("WEB_AUTHN_ORIGINS")
	if len(origins) == 0 {
		if override := dbConfigString("WEB_AUTHN_ORIGIN"); override != "" {
			origins = []string{override}
		}
	}
	if len(origins) == 0 {
		origins = []string{webAuthnOrigin}
	}

	rpID := webAuthnRPID
	if override := dbConfigString("WEB_AUTHN_RPID"); override != "" {
		rpID = override
	} else if derived := deriveRPIDFromOrigins(origins); derived != "" {
		rpID = derived
	}

	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     origins,
	})
}

// deriveRPIDFromOrigins extracts an RP ID from the configured origins.
func deriveRPIDFromOrigins(origins []string) string {
	for _, origin := range origins {
		if host := originHost(origin); host != "" {
			return host
		}
	}
	return ""
}

// originHost parses an origin string and returns its hostname.
func originHost(origin string) string {
	trimmed := strings.TrimSpace(origin)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.TrimSpace(parsed.Hostname())
}

// dbConfigString reads a string from the DB config snapshot.
func dbConfigString(key string) string {
	raw, ok := internalsettings.DBConfigValue(key)
	if !ok {
		return ""
	}
	return parseDBConfigString(raw)
}

// parseDBConfigString extracts a string value from JSON config payloads.
func parseDBConfigString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var s string
	if errUnmarshal := json.Unmarshal(raw, &s); errUnmarshal == nil {
		return strings.TrimSpace(s)
	}
	// wrapper allows parsing values wrapped in a { "value": ... } object.
	var wrapper struct {
		Value json.RawMessage `json:"value"`
	}
	if errUnmarshal := json.Unmarshal(raw, &wrapper); errUnmarshal == nil {
		if len(wrapper.Value) > 0 {
			return parseDBConfigString(wrapper.Value)
		}
	}
	return ""
}

// dbConfigStrings reads a string slice from the DB config snapshot.
func dbConfigStrings(key string) []string {
	raw, ok := internalsettings.DBConfigValue(key)
	if !ok {
		return nil
	}
	return parseDBConfigStrings(raw)
}

// parseDBConfigStrings extracts a string slice from JSON config payloads.
func parseDBConfigStrings(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	var values []string
	if errUnmarshal := json.Unmarshal(raw, &values); errUnmarshal == nil {
		return normalizeConfigStrings(values)
	}
	if single := parseDBConfigString(raw); single != "" {
		return []string{single}
	}
	// wrapper allows parsing values wrapped in a { "value": ... } object.
	var wrapper struct {
		Value json.RawMessage `json:"value"`
	}
	if errUnmarshal := json.Unmarshal(raw, &wrapper); errUnmarshal == nil {
		if len(wrapper.Value) > 0 {
			return parseDBConfigStrings(wrapper.Value)
		}
	}
	return nil
}

// normalizeConfigStrings trims and filters empty strings.
func normalizeConfigStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
