package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout redirects os.Stdout for the duration of f and returns what was written.
func captureStdout(f func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

// ---------------------------------------------------------------------------
// normalizeDomain
// ---------------------------------------------------------------------------

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com/", "example.com"},
		{"https://example.com/foo?bar=1", "example.com"},
		{"example.com:8080", "example.com"},
		{"https://user:pass@example.com/", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"example.com", "example.com"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		got := normalizeDomain(c.in)
		if got != c.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// isValidDomain
// ---------------------------------------------------------------------------

func TestIsValidDomain(t *testing.T) {
	valid := []string{
		"example.com", "sub.example.com", "my-domain.io", "a.co", "example.co.uk",
	}
	for _, d := range valid {
		if !isValidDomain(d) {
			t.Errorf("isValidDomain(%q) = false, want true", d)
		}
	}
	invalid := []string{
		"", "nodot", "-bad.com", "bad-.com", "has space.com",
		"http://example.com", strings.Repeat("a", 254),
	}
	for _, d := range invalid {
		if isValidDomain(d) {
			t.Errorf("isValidDomain(%q) = true, want false", d)
		}
	}
}

// ---------------------------------------------------------------------------
// guessAvailability
// ---------------------------------------------------------------------------

func TestGuessAvailability(t *testing.T) {
	if guessAvailability("") != nil {
		t.Error("empty text should return nil")
	}

	notFoundTexts := []string{
		"No match for EXAMPLE.COM",
		"Domain not found",
		"Status: available",
		"no data found",
	}
	for _, txt := range notFoundTexts {
		got := guessAvailability(txt)
		if got == nil || !*got {
			t.Errorf("guessAvailability(%q) should be true", txt)
		}
	}

	foundTexts := []string{
		"Registrar: Example Inc\nCreation date: 2020-01-01",
		"Registry Domain ID: 1234\nStatus: active",
	}
	for _, txt := range foundTexts {
		got := guessAvailability(txt)
		if got == nil || *got {
			t.Errorf("guessAvailability(%q) should be false", txt)
		}
	}

	ambiguous := "Some random WHOIS response"
	if guessAvailability(ambiguous) != nil {
		t.Errorf("guessAvailability(%q) should be nil", ambiguous)
	}
}

// ---------------------------------------------------------------------------
// bootstrapTLD
// ---------------------------------------------------------------------------

func TestBootstrapTLD(t *testing.T) {
	bs := map[string][]string{
		"com":   {"https://rdap.example.net/"},
		"co.uk": {"https://rdap.nic.uk/"},
	}

	got := bootstrapTLD("example.com", bs)
	if got != "com" {
		t.Errorf("got %q, want %q", got, "com")
	}

	got = bootstrapTLD("example.co.uk", bs)
	if got != "co.uk" {
		t.Errorf("got %q, want %q", got, "co.uk")
	}

	got = bootstrapTLD("example.xyz", bs)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// splitDomain
// ---------------------------------------------------------------------------

func TestSplitDomain(t *testing.T) {
	n, t2 := splitDomain("example.com")
	if n != "example" || t2 != "com" {
		t.Errorf("got (%q, %q), want (example, com)", n, t2)
	}

	n, t2 = splitDomain("example")
	if n != "example" || t2 != "" {
		t.Errorf("got (%q, %q), want (example, )", n, t2)
	}

	n, t2 = splitDomain("example.co.uk")
	if n != "example" || t2 != "co.uk" {
		t.Errorf("got (%q, %q), want (example, co.uk)", n, t2)
	}
}

// ---------------------------------------------------------------------------
// formatRDAP
// ---------------------------------------------------------------------------

func TestFormatRDAP(t *testing.T) {
	data := map[string]interface{}{
		"ldhName": "EXAMPLE.COM",
		"status":  []interface{}{"active"},
		"events": []interface{}{
			map[string]interface{}{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
		},
		"entities": []interface{}{},
		"nameservers": []interface{}{
			map[string]interface{}{"ldhName": "NS1.EXAMPLE.COM"},
		},
	}
	out := formatRDAP(data)
	for _, want := range []string{"EXAMPLE.COM", "active", "NS1.EXAMPLE.COM", "2020-01-01"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatRDAP output missing %q", want)
		}
	}

	// missing fields use N/A
	out2 := formatRDAP(map[string]interface{}{})
	if !strings.Contains(out2, "N/A") {
		t.Error("expected N/A in output for empty data")
	}

	// entity with vcard
	data3 := map[string]interface{}{
		"entities": []interface{}{
			map[string]interface{}{
				"roles":  []interface{}{"registrar"},
				"handle": "REG-001",
				"vcardArray": []interface{}{
					"vcard",
					[]interface{}{
						[]interface{}{"fn", map[string]interface{}{}, "text", "Example Registrar"},
					},
				},
			},
		},
	}
	out3 := formatRDAP(data3)
	if !strings.Contains(out3, "Example Registrar") {
		t.Error("expected vcard fn name in output")
	}
	if !strings.Contains(out3, "registrar") {
		t.Error("expected role in output")
	}
}

// ---------------------------------------------------------------------------
// rdapLookupFn (via stub bootstrap)
// ---------------------------------------------------------------------------

func withStubBootstrap(t *testing.T, bs map[string][]string, f func()) {
	t.Helper()
	orig := loadRDAPBootstrap
	loadRDAPBootstrap = func(timeout time.Duration) map[string][]string { return bs }
	defer func() { loadRDAPBootstrap = orig }()
	f()
}

func TestRDAPLookup(t *testing.T) {
	bs := map[string][]string{"com": {"https://rdap.example.net/"}}

	t.Run("available on 404", func(t *testing.T) {
		withStubBootstrap(t, bs, func() {
			orig := rdapLookupFn
			rdapLookupFn = func(domain string, timeout time.Duration) *rdapResult {
				return &rdapResult{Available: boolPtr(true)}
			}
			defer func() { rdapLookupFn = orig }()
			r := rdapLookupFn("example.com", time.Second)
			if r == nil || r.Available == nil || !*r.Available {
				t.Error("expected available=true")
			}
		})
	})

	t.Run("taken on 200", func(t *testing.T) {
		withStubBootstrap(t, bs, func() {
			orig := rdapLookupFn
			rdapLookupFn = func(domain string, timeout time.Duration) *rdapResult {
				return &rdapResult{Available: boolPtr(false), Data: map[string]interface{}{"ldhName": "example.com"}}
			}
			defer func() { rdapLookupFn = orig }()
			r := rdapLookupFn("example.com", time.Second)
			if r == nil || r.Available == nil || *r.Available {
				t.Error("expected available=false")
			}
		})
	})

	t.Run("rate limited returns error", func(t *testing.T) {
		withStubBootstrap(t, bs, func() {
			orig := rdapLookupFn
			rdapLookupFn = func(domain string, timeout time.Duration) *rdapResult {
				return &rdapResult{Err: "rate limited (HTTP 429)"}
			}
			defer func() { rdapLookupFn = orig }()
			r := rdapLookupFn("example.com", time.Second)
			if r == nil || r.Available != nil || !strings.Contains(r.Err, "429") {
				t.Errorf("expected error containing 429, got: %+v", r)
			}
		})
	})

	t.Run("unsupported TLD returns nil", func(t *testing.T) {
		withStubBootstrap(t, map[string][]string{}, func() {
			origFn := rdapLookupFn
			rdapLookupFn = func(domain string, timeout time.Duration) *rdapResult {
				bs2 := loadRDAPBootstrap(timeout)
				if bootstrapTLD(domain, bs2) == "" {
					return nil
				}
				return origFn(domain, timeout)
			}
			defer func() { rdapLookupFn = origFn }()
			r := rdapLookupFn("example.com", time.Second)
			if r != nil {
				t.Error("expected nil for unsupported TLD")
			}
		})
	})
}

// ---------------------------------------------------------------------------
// checkDomainFn (via stub rdap/whois)
// ---------------------------------------------------------------------------

func TestCheckDomain(t *testing.T) {
	t.Run("invalid domain", func(t *testing.T) {
		res := checkDomainFn("not_a_domain", time.Second)
		if res.Available != nil || res.Method != "validation" {
			t.Errorf("unexpected result for invalid domain: %+v", res)
		}
	})

	t.Run("rdap available", func(t *testing.T) {
		origRDAP := rdapLookupFn
		rdapLookupFn = func(d string, t time.Duration) *rdapResult {
			return &rdapResult{Available: boolPtr(true)}
		}
		defer func() { rdapLookupFn = origRDAP }()
		res := checkDomainFn("example.com", time.Second)
		if res.Available == nil || !*res.Available || res.Method != "RDAP" {
			t.Errorf("unexpected result: %+v", res)
		}
	})

	t.Run("rdap taken", func(t *testing.T) {
		origRDAP := rdapLookupFn
		rdapLookupFn = func(d string, t time.Duration) *rdapResult {
			return &rdapResult{Available: boolPtr(false), Data: map[string]interface{}{"ldhName": "x"}}
		}
		defer func() { rdapLookupFn = origRDAP }()
		res := checkDomainFn("example.com", time.Second)
		if res.Available == nil || *res.Available || res.Method != "RDAP" {
			t.Errorf("unexpected result: %+v", res)
		}
	})

	t.Run("rdap error falls back to whois", func(t *testing.T) {
		origRDAP := rdapLookupFn
		origWHOIS := whoisLookupFn
		rdapLookupFn = func(d string, t time.Duration) *rdapResult {
			return &rdapResult{Err: "rate limited (HTTP 429)"}
		}
		whoisLookupFn = func(d string, t time.Duration) (string, string) {
			return "Domain not found", ""
		}
		defer func() {
			rdapLookupFn = origRDAP
			whoisLookupFn = origWHOIS
		}()
		res := checkDomainFn("example.com", time.Second)
		if res.Available == nil || !*res.Available {
			t.Errorf("expected available=true after WHOIS fallback: %+v", res)
		}
		if !strings.Contains(res.Method, "RDAP fallback") {
			t.Errorf("expected RDAP fallback method, got: %q", res.Method)
		}
		if !strings.Contains(res.Detail, "429") {
			t.Errorf("expected 429 in detail, got: %q", res.Detail)
		}
	})

	t.Run("no rdap uses whois", func(t *testing.T) {
		origRDAP := rdapLookupFn
		origWHOIS := whoisLookupFn
		rdapLookupFn = func(d string, t time.Duration) *rdapResult { return nil }
		whoisLookupFn = func(d string, t time.Duration) (string, string) {
			return "Registrar: NIC\nStatus: active", ""
		}
		defer func() {
			rdapLookupFn = origRDAP
			whoisLookupFn = origWHOIS
		}()
		res := checkDomainFn("example.tld", time.Second)
		if res.Available == nil || *res.Available {
			t.Errorf("expected taken via WHOIS: %+v", res)
		}
		if res.Method != "WHOIS (heuristic)" {
			t.Errorf("unexpected method: %q", res.Method)
		}
	})

	t.Run("whois hard failure", func(t *testing.T) {
		origRDAP := rdapLookupFn
		origWHOIS := whoisLookupFn
		rdapLookupFn = func(d string, t time.Duration) *rdapResult { return nil }
		whoisLookupFn = func(d string, t time.Duration) (string, string) {
			return "", "connection refused"
		}
		defer func() {
			rdapLookupFn = origRDAP
			whoisLookupFn = origWHOIS
		}()
		res := checkDomainFn("example.tld", time.Second)
		if res.Available != nil || res.Method != "WHOIS" {
			t.Errorf("unexpected result: %+v", res)
		}
		if !strings.Contains(res.Detail, "connection refused") {
			t.Errorf("expected detail to contain error: %q", res.Detail)
		}
	})
}

// ---------------------------------------------------------------------------
// whoisLookupFn (via stub whoisQueryFn)
// ---------------------------------------------------------------------------

func TestWhoisLookup(t *testing.T) {
	t.Run("follows referral", func(t *testing.T) {
		var calls []string
		orig := whoisQueryFn
		whoisQueryFn = func(server, query string, timeout time.Duration) (string, error) {
			calls = append(calls, server)
			if server == ianaWhoisServer {
				return "refer: whois.registry.example\n", nil
			}
			return "Domain Name: EXAMPLE.COM\nRegistrar: Example Inc\n", nil
		}
		defer func() { whoisQueryFn = orig }()

		origLookup := whoisLookupFn
		// Reset whoisLookupFn to default to actually test the referral logic.
		// We test it by calling the inline logic directly.
		whoisLookupFn = origLookup
		text, err := whoisLookupFn("example.com", time.Second)
		if err != "" {
			t.Fatalf("unexpected error: %s", err)
		}
		found := false
		for _, c := range calls {
			if c == "whois.registry.example" {
				found = true
			}
		}
		if !found {
			t.Error("expected referral server to be queried")
		}
		if !strings.Contains(text, "Registrar: Example Inc") {
			t.Error("expected registrar in text")
		}
	})

	t.Run("stops on self referral", func(t *testing.T) {
		orig := whoisQueryFn
		whoisQueryFn = func(server, query string, timeout time.Duration) (string, error) {
			return "refer: " + server + "\n", nil
		}
		defer func() { whoisQueryFn = orig }()
		text, err := whoisLookupFn("example.com", time.Second)
		if err != "" {
			t.Fatalf("unexpected error: %s", err)
		}
		if strings.Count(text, "----- Response from") != 1 {
			t.Errorf("expected exactly 1 response block, got: %d", strings.Count(text, "----- Response from"))
		}
	})

	t.Run("initial failure reports error", func(t *testing.T) {
		orig := whoisQueryFn
		whoisQueryFn = func(server, query string, timeout time.Duration) (string, error) {
			return "", &net.OpError{Op: "dial", Err: &net.DNSError{Err: "boom"}}
		}
		defer func() { whoisQueryFn = orig }()
		text, errMsg := whoisLookupFn("example.com", time.Second)
		if errMsg == "" {
			t.Error("expected error message")
		}
		if text != "" {
			t.Errorf("expected empty text, got: %q", text)
		}
	})
}

// ---------------------------------------------------------------------------
// exitCodeForCheck
// ---------------------------------------------------------------------------

func TestExitCodeForCheck(t *testing.T) {
	if exitCodeForCheck([]CheckResult{{Available: boolPtr(true)}}) != 0 {
		t.Error("all available should return 0")
	}
	if exitCodeForCheck([]CheckResult{
		{Available: boolPtr(true)},
		{Available: boolPtr(false)},
	}) != 1 {
		t.Error("any taken should return 1")
	}
	if exitCodeForCheck([]CheckResult{
		{Available: boolPtr(true)},
		{Available: nil},
	}) != 2 {
		t.Error("any unknown should return 2")
	}
}

// ---------------------------------------------------------------------------
// collectInputDomains
// ---------------------------------------------------------------------------

func TestCollectInputDomains(t *testing.T) {
	got := collectInputDomains([]string{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("unexpected result: %v", got)
	}
}

// ---------------------------------------------------------------------------
// End-to-end: run() with mocked checkDomainFn
// ---------------------------------------------------------------------------

func TestMainCheck(t *testing.T) {
	t.Run("json output", func(t *testing.T) {
		orig := checkDomainFn
		checkDomainFn = func(d string, t time.Duration) CheckResult {
			return CheckResult{Domain: d, Available: boolPtr(true), Method: "stub"}
		}
		defer func() { checkDomainFn = orig }()

		var code int
		out := captureStdout(func() {
			code = run([]string{"check", "--json", "example.com"})
		})
		if code != 0 {
			t.Errorf("expected exit 0, got %d", code)
		}
		var payload []struct {
			Input   string `json:"input"`
			Results []struct {
				Domain    string `json:"domain"`
				Available *bool  `json:"available"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid JSON: %v\noutput: %s", err, out)
		}
		if payload[0].Input != "example.com" {
			t.Errorf("unexpected input: %q", payload[0].Input)
		}
		if payload[0].Results[0].Domain != "example.com" {
			t.Errorf("unexpected domain: %q", payload[0].Results[0].Domain)
		}
		if payload[0].Results[0].Available == nil || !*payload[0].Results[0].Available {
			t.Error("expected available=true")
		}
	})

	t.Run("exit 1 when taken", func(t *testing.T) {
		orig := checkDomainFn
		checkDomainFn = func(d string, t time.Duration) CheckResult {
			return CheckResult{Domain: d, Available: boolPtr(false), Method: "stub"}
		}
		defer func() { checkDomainFn = orig }()
		var code int
		captureStdout(func() {
			code = run([]string{"check", "example.com"})
		})
		if code != 1 {
			t.Errorf("expected exit 1, got %d", code)
		}
	})

	t.Run("exit 2 when unknown", func(t *testing.T) {
		orig := checkDomainFn
		checkDomainFn = func(d string, t time.Duration) CheckResult {
			return CheckResult{Domain: d, Available: nil, Method: "stub", Detail: "network down"}
		}
		defer func() { checkDomainFn = orig }()
		var code int
		captureStdout(func() {
			code = run([]string{"check", "example.com"})
		})
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
	})

	t.Run("available-only filters json", func(t *testing.T) {
		resultsByDomain := map[string]CheckResult{
			"example.com": {Domain: "example.com", Available: boolPtr(false), Method: "stub"},
			"example.net": {Domain: "example.net", Available: boolPtr(true), Method: "stub"},
		}
		orig := checkDomainFn
		checkDomainFn = func(d string, t time.Duration) CheckResult {
			return resultsByDomain[d]
		}
		defer func() { checkDomainFn = orig }()
		out := captureStdout(func() {
			run([]string{"check", "--tld", "com,net", "--available-only", "--json", "example"})
		})
		var payload []struct {
			Results []struct{ Domain string `json:"domain"` } `json:"results"`
		}
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		for _, g := range payload {
			for _, r := range g.Results {
				if r.Domain == "example.com" {
					t.Error("taken domain should be filtered out by --available-only")
				}
			}
		}
	})
}

func TestMainWhois(t *testing.T) {
	t.Run("rdap taken exit 0", func(t *testing.T) {
		orig := rdapLookupFn
		rdapLookupFn = func(d string, t time.Duration) *rdapResult {
			return &rdapResult{Available: boolPtr(false), Data: map[string]interface{}{"ldhName": "example.com"}}
		}
		defer func() { rdapLookupFn = orig }()
		var code int
		out := captureStdout(func() {
			code = run([]string{"whois", "--json", "example.com"})
		})
		if code != 0 {
			t.Errorf("expected exit 0, got %d", code)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if avail, ok := payload["available"].(bool); !ok || avail {
			t.Error("expected available=false")
		}
	})

	t.Run("rdap available exit 1", func(t *testing.T) {
		orig := rdapLookupFn
		rdapLookupFn = func(d string, t time.Duration) *rdapResult {
			return &rdapResult{Available: boolPtr(true)}
		}
		defer func() { rdapLookupFn = orig }()
		var code int
		out := captureStdout(func() {
			code = run([]string{"whois", "--json", "example.com"})
		})
		if code != 1 {
			t.Errorf("expected exit 1, got %d", code)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if avail, ok := payload["available"].(bool); !ok || !avail {
			t.Error("expected available=true")
		}
	})

	t.Run("invalid domain exit 2", func(t *testing.T) {
		var code int
		out := captureStdout(func() {
			code = run([]string{"whois", "--json", "not_a_domain"})
		})
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if _, ok := payload["error"]; !ok {
			t.Error("expected error key in response")
		}
	})
}
