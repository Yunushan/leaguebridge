package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestStringRemovesSensitiveValues(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		secret string
	}{
		{"email", "contact alice.smith+games@example.com for help", "alice.smith+games@example.com"},
		{"local email", "account buildbot@localhost", "buildbot@localhost"},
		{"bearer", "Authorization Bearer abc.def-123_SECRET", "abc.def-123_SECRET"},
		{"basic authorization", "proxy Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="},
		{"authorization header", "Authorization: Basic dXNlcjpwYXNz\nnext line", "dXNlcjpwYXNz"},
		{"cookie header", "Cookie: session=abc123; preference=dark\nstatus ok", "abc123"},
		{"json password", `{"password":"correct horse battery staple"}`, "correct horse battery staple"},
		{"escaped JSON password", `{"password":"abc\\\"def-secret"}`, "def-secret"},
		{"spaced password", "password: correct horse battery staple", "correct horse battery staple"},
		{"environment token", "ACCESS_TOKEN=opaque-value-123", "opaque-value-123"},
		{"command option", "launcher --password swordfish", "swordfish"},
		{"token phrase", "access token abcdef0123456789", "abcdef0123456789"},
		{"url credentials", "https://alice:swordfish@server.example/path", "swordfish"},
		{"jwt", "credential eyJhbGciOiJIUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl", "eyJhbGciOiJIUzI1NiJ9"},
		{"known token", "key RGAPI-0123456789abcdef", "RGAPI-0123456789abcdef"},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nc2VjcmV0\n-----END OPENSSH PRIVATE KEY-----", "c2VjcmV0"},
		{"marker prefix bypass", "password=[REDACTED_SECRET]still-a-secret", "still-a-secret"},
		{"windows home", `at C:\Users\Alice\AppData\Local\Riot`, "Alice"},
		{"escaped windows home", `json C:\\Users\\Alice\\AppData\\Local`, "Alice"},
		{"windows profiles home", `at D:\Profiles\Alice\Riot`, "Alice"},
		{"legacy windows home", `at C:\Documents and Settings\Alice\Riot`, "Alice"},
		{"UNC home", `at \\fileserver\Users\Alice\Riot`, "fileserver"},
		{"unix home", "at /home/alice/.config/leaguebridge", "alice"},
		{"BSD home", "at /usr/home/alice/.config/leaguebridge", "alice"},
		{"Wine home", "/home/alice/.wine/drive_c/users/steamuser/AppData", "steamuser"},
		{"mac home", "at /Users/alice/Library/Application Support", "alice"},
		{"root home", "at /root/.config/leaguebridge", "/root"},
		{"tilde home", "path=~alice/.config", "~alice"},
		{"runtime user", "socket /run/user/1000/league.sock", "1000"},
		{"user assignment", "username=alice", "alice"},
		{"ipv4", "peer 192.168.10.42:443", "192.168.10.42"},
		{"IPv4 leading zeroes", "peer 192.168.001.042:443", "192.168.001.042"},
		{"ipv6", "peer [2001:db8::cafe]:443", "2001:db8::cafe"},
		{"scoped ipv6", "peer fe80::1%eth0", "fe80::1%eth0"},
		{"mac address", "adapter aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"host assignment", "hostname=yunus-gaming-pc", "yunus-gaming-pc"},
		{"host phrase", "machine name yunus-gaming-pc", "yunus-gaming-pc"},
		{"machine ID", "machine-id=0123456789abcdef", "0123456789abcdef"},
		{"serial number", "serial_number=desktop-12345", "desktop-12345"},
		{"private hostname", "connected to gaming-pc.local", "gaming-pc.local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.input)
			if strings.Contains(got, tt.secret) {
				t.Fatalf("sensitive value remains in %q", got)
			}
			if !strings.Contains(got, "[REDACTED_") {
				t.Fatalf("redaction marker missing from %q", got)
			}
			if twice := String(got); twice != got {
				t.Fatalf("redaction is not idempotent:\nfirst:  %q\nsecond: %q", got, twice)
			}
		})
	}
}

func TestStringLeavesUsefulPublicContext(t *testing.T) {
	input := "See https://support-leagueoflegends.riotgames.com/; the host is ready, no machine indicator was found, and remote handoff is experimental; complete a local Practice Tool session before streaming; retry at 12:34:56; version dead:beef is invalid"
	if got := String(input); got != input {
		t.Fatalf("unexpected redaction:\nwant: %q\n got: %q", input, got)
	}
	if got := Host("gaming-pc.example"); got != hostMarker {
		t.Fatalf("Host returned %q", got)
	}
	if got := Host("   "); got != "" {
		t.Fatalf("empty Host returned %q", got)
	}
}

func FuzzStringDoesNotLeakLabeledSecrets(f *testing.F) {
	for _, seed := range []string{"hunter2", "correct horse battery staple", "ümlaut", "line\nbreak", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		secret := base64.RawURLEncoding.EncodeToString([]byte(raw))
		if len(secret) < 8 {
			secret += "01234567"
		}
		input := `password="` + secret + `" token=` + secret + ` --api-key ` + secret
		got := String(input)
		if strings.Contains(got, secret) {
			t.Fatalf("encoded secret leaked from %q", got)
		}
		if twice := String(got); twice != got {
			t.Fatalf("redaction is not idempotent: %q != %q", got, twice)
		}
	})
}
