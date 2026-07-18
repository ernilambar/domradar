// domradar — CLI tool to check domain name availability and WHOIS/RDAP details.
//
// Author: Nilambar Sharma
// Repo:   https://github.com/ernilambar/domradar
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

const version = "1.0.0"

const (
	ianaWhoisServer  = "whois.iana.org"
	whoisPort        = 43
	rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"
	defaultTimeout   = 6 * time.Second
	bootstrapTTL     = 24 * time.Hour
)

var userAgent = "domradar/" + version + " (+https://github.com/ernilambar/domradar)"

// osExit is an indirection so tests can intercept exit calls.
var osExit = os.Exit

// ---------------------------------------------------------------------------
// WHOIS heuristics
// ---------------------------------------------------------------------------

var notFoundPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)no match for`),
	regexp.MustCompile(`(?i)not found`),
	regexp.MustCompile(`(?i)no data found`),
	regexp.MustCompile(`(?i)no entries found`),
	regexp.MustCompile(`(?i)no object found`),
	regexp.MustCompile(`(?i)domain not found`),
	regexp.MustCompile(`(?i)status:\s*available`),
	regexp.MustCompile(`(?i)status:\s*free`),
	regexp.MustCompile(`(?i)available for registration`),
	regexp.MustCompile(`(?i)no matching record`),
	regexp.MustCompile(`(?i)is available for registration`),
	regexp.MustCompile(`(?i)has not been registered`),
	regexp.MustCompile(`(?i)domain status:\s*no object found`),
}

var foundPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)registrar:`),
	regexp.MustCompile(`(?i)creation date:`),
	regexp.MustCompile(`(?i)registry domain id:`),
	regexp.MustCompile(`(?i)status:\s*active`),
	regexp.MustCompile(`(?i)status:\s*ok`),
}

var referralRE = regexp.MustCompile(`(?i)(?:refer|whois server|referralserver)\s*:\s*([a-zA-Z0-9.\-]+)`)

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// CheckResult holds the result of a domain availability check.
// Available is nil when the status could not be determined.
type CheckResult struct {
	Domain    string
	Available *bool
	Method    string
	Detail    string
}

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// Bootstrap cache (disk + in-memory)
// ---------------------------------------------------------------------------

var (
	bootstrapData map[string][]string
	bootstrapMu   sync.Mutex
)

func userCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "domradar")
}

func loadBootstrapFromDisk() map[string][]string {
	path := filepath.Join(userCacheDir(), "bootstrap.json")
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > bootstrapTTL {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string][]string
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	return m
}

func saveBootstrapToDisk(m map[string][]string) {
	dir := userCacheDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	data, _ := json.Marshal(m)
	tmp := filepath.Join(dir, "bootstrap.json.tmp")
	if os.WriteFile(tmp, data, 0644) == nil {
		os.Rename(tmp, filepath.Join(dir, "bootstrap.json"))
	}
}

func fetchBootstrap(timeout time.Duration) map[string][]string {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", rdapBootstrapURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var raw struct {
		Services [][]json.RawMessage `json:"services"`
	}
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return nil
	}
	m := make(map[string][]string)
	for _, entry := range raw.Services {
		if len(entry) < 2 {
			continue
		}
		var tlds, urls []string
		if json.Unmarshal(entry[0], &tlds) != nil || json.Unmarshal(entry[1], &urls) != nil {
			continue
		}
		for _, tld := range tlds {
			m[strings.ToLower(tld)] = urls
		}
	}
	return m
}

// loadRDAPBootstrap is a var so tests can replace it.
var loadRDAPBootstrap = func(timeout time.Duration) map[string][]string {
	bootstrapMu.Lock()
	defer bootstrapMu.Unlock()
	if bootstrapData != nil {
		return bootstrapData
	}
	if disk := loadBootstrapFromDisk(); disk != nil {
		bootstrapData = disk
		return disk
	}
	fetched := fetchBootstrap(timeout)
	if fetched == nil {
		return map[string][]string{}
	}
	bootstrapData = fetched
	saveBootstrapToDisk(fetched)
	return fetched
}

// ---------------------------------------------------------------------------
// RDAP
// ---------------------------------------------------------------------------

type rdapResult struct {
	Available *bool
	Data      map[string]interface{}
	Err       string
}

func bootstrapTLD(domain string, bootstrap map[string][]string) string {
	labels := strings.Split(strings.ToLower(domain), ".")
	for i := 1; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if _, ok := bootstrap[candidate]; ok {
			return candidate
		}
	}
	return ""
}

var rdapClient = &http.Client{
	Transport: &http.Transport{MaxIdleConnsPerHost: 4},
}

// rdapLookupFn is a var so tests can replace it.
var rdapLookupFn = func(domain string, timeout time.Duration) *rdapResult {
	bootstrap := loadRDAPBootstrap(timeout)
	tld := bootstrapTLD(domain, bootstrap)
	if tld == "" {
		return nil
	}
	bases := bootstrap[tld]
	rdapClient.Timeout = timeout

	var lastErr string
	for _, base := range bases {
		u := strings.TrimRight(base, "/") + "/domain/" + domain
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		req.Header.Set("Accept", "application/rdap+json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := rdapClient.Do(req)
		if err != nil {
			lastErr = "connection error: " + err.Error()
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case resp.StatusCode == 200:
			var data map[string]interface{}
			if json.Unmarshal(body, &data) != nil {
				lastErr = "malformed RDAP JSON"
				continue
			}
			return &rdapResult{Available: boolPtr(false), Data: data}
		case resp.StatusCode == 404:
			return &rdapResult{Available: boolPtr(true)}
		case resp.StatusCode == 429:
			lastErr = "rate limited (HTTP 429)"
		case resp.StatusCode >= 500:
			lastErr = fmt.Sprintf("server error (HTTP %d)", resp.StatusCode)
		default:
			lastErr = fmt.Sprintf("unexpected HTTP %d", resp.StatusCode)
		}
	}
	if lastErr == "" {
		lastErr = "no RDAP endpoint reachable"
	}
	return &rdapResult{Err: lastErr}
}

// ---------------------------------------------------------------------------
// RDAP formatter
// ---------------------------------------------------------------------------

func formatRDAP(data map[string]interface{}) string {
	var lines []string
	ldhName, _ := data["ldhName"].(string)
	if ldhName == "" {
		ldhName = "N/A"
	}
	lines = append(lines, "Domain:     "+ldhName)

	if sr, ok := data["status"].([]interface{}); ok {
		var ss []string
		for _, s := range sr {
			if v, ok := s.(string); ok {
				ss = append(ss, v)
			}
		}
		if len(ss) > 0 {
			lines = append(lines, "Status:     "+strings.Join(ss, ", "))
		}
	}

	if er, ok := data["events"].([]interface{}); ok {
		for _, ev := range er {
			if e, ok := ev.(map[string]interface{}); ok {
				action, _ := e["eventAction"].(string)
				date, _ := e["eventDate"].(string)
				if action == "" {
					action = "event"
				}
				if date == "" {
					date = "N/A"
				}
				label := strings.ReplaceAll(action, "_", " ")
				if len(label) > 0 {
					label = strings.ToUpper(label[:1]) + label[1:]
				}
				lines = append(lines, fmt.Sprintf("%-12s%s", label, date))
			}
		}
	}

	if er, ok := data["entities"].([]interface{}); ok {
		for _, ent := range er {
			if e, ok := ent.(map[string]interface{}); ok {
				name, _ := e["handle"].(string)
				if vc, ok := e["vcardArray"].([]interface{}); ok && len(vc) > 1 {
					if items, ok := vc[1].([]interface{}); ok {
						for _, item := range items {
							if arr, ok := item.([]interface{}); ok && len(arr) >= 4 {
								if prop, _ := arr[0].(string); prop == "fn" {
									if fn, ok := arr[3].(string); ok {
										name = fn
									}
								}
							}
						}
					}
				}
				if name == "" {
					name = "N/A"
				}
				var roles []string
				if rr, ok := e["roles"].([]interface{}); ok {
					for _, r := range rr {
						if rs, ok := r.(string); ok {
							roles = append(roles, rs)
						}
					}
				}
				roleStr := strings.Join(roles, ", ")
				if roleStr == "" {
					roleStr = "unknown role"
				}
				lines = append(lines, fmt.Sprintf("Entity:     %s (%s)", name, roleStr))
			}
		}
	}

	if nr, ok := data["nameservers"].([]interface{}); ok && len(nr) > 0 {
		lines = append(lines, "Nameservers:")
		for _, ns := range nr {
			if n, ok := ns.(map[string]interface{}); ok {
				ldh, _ := n["ldhName"].(string)
				if ldh == "" {
					ldh = "N/A"
				}
				lines = append(lines, "  - "+ldh)
			}
		}
	}

	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// WHOIS
// ---------------------------------------------------------------------------

// whoisQueryFn is a var so tests can replace it.
var whoisQueryFn = func(server, query string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, whoisPort), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	data, err := io.ReadAll(conn)
	return string(data), err
}

// whoisLookupFn is a var so tests can replace it.
var whoisLookupFn = func(domain string, timeout time.Duration) (string, string) {
	server := ianaWhoisServer
	seen := map[string]bool{}
	var fullText strings.Builder

	for i := 0; i < 3; i++ {
		key := strings.ToLower(server)
		if seen[key] {
			break
		}
		seen[key] = true
		text, err := whoisQueryFn(server, domain, timeout)
		if err != nil {
			if fullText.Len() > 0 {
				return fullText.String(), ""
			}
			return "", fmt.Sprintf("Error querying %s: %v", server, err)
		}
		fmt.Fprintf(&fullText, "\n----- Response from %s -----\n%s", server, text)
		m := referralRE.FindStringSubmatch(text)
		if m != nil {
			referral := strings.TrimRight(strings.TrimSpace(m[1]), ".")
			if referral != "" && strings.ToLower(referral) != key {
				server = referral
				continue
			}
		}
		break
	}
	return fullText.String(), ""
}

func guessAvailability(text string) *bool {
	if text == "" {
		return nil
	}
	for _, p := range notFoundPatterns {
		if p.MatchString(text) {
			return boolPtr(true)
		}
	}
	for _, p := range foundPatterns {
		if p.MatchString(text) {
			return boolPtr(false)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Domain normalization and validation
// ---------------------------------------------------------------------------

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$`)

func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if !labelRE.MatchString(lbl) {
			return false
		}
	}
	return true
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

func normalizeDomain(domain string) string {
	d := strings.TrimSpace(domain)
	if d == "" {
		return ""
	}
	if !strings.Contains(d, "://") {
		d = "http://" + d
	}
	u, err := url.Parse(d)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	host = strings.Trim(host, ".")
	if host == "" {
		return ""
	}
	if hasNonASCII(host) {
		if encoded, err := idna.Lookup.ToASCII(host); err == nil {
			host = encoded
		}
	}
	return host
}

// ---------------------------------------------------------------------------
// checkDomain
// ---------------------------------------------------------------------------

// checkDomainFn is a var so tests can replace it.
var checkDomainFn = func(domain string, timeout time.Duration) CheckResult {
	domain = normalizeDomain(domain)
	if !isValidDomain(domain) {
		return CheckResult{Domain: domain, Method: "validation", Detail: "invalid domain name"}
	}
	r := rdapLookupFn(domain, timeout)
	if r != nil {
		if r.Available == nil {
			text, whoisErr := whoisLookupFn(domain, timeout)
			if whoisErr != "" && text == "" {
				return CheckResult{Domain: domain, Method: "RDAP", Detail: r.Err}
			}
			avail := guessAvailability(text)
			return CheckResult{Domain: domain, Available: avail, Method: "WHOIS (RDAP fallback)", Detail: r.Err}
		}
		return CheckResult{Domain: domain, Available: r.Available, Method: "RDAP"}
	}
	text, err := whoisLookupFn(domain, timeout)
	if err != "" && text == "" {
		return CheckResult{Domain: domain, Method: "WHOIS", Detail: err}
	}
	avail := guessAvailability(text)
	return CheckResult{Domain: domain, Available: avail, Method: "WHOIS (heuristic)"}
}

var popularTLDs = []string{"com", "net", "org", "io", "co", "dev", "app", "ai"}

func splitDomain(domain string) (name, tld string) {
	idx := strings.Index(domain, ".")
	if idx < 0 {
		return domain, ""
	}
	return domain[:idx], domain[idx+1:]
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

func statusLabel(available *bool) string {
	if available == nil {
		return "UNKNOWN"
	}
	if *available {
		return "AVAILABLE"
	}
	return "TAKEN"
}

func printResultLine(res CheckResult) {
	detail := ""
	if res.Detail != "" {
		detail = " (" + res.Detail + ")"
	}
	fmt.Printf("  %-28s %-20s [%s]%s\n",
		res.Domain, statusLabel(res.Available), res.Method, detail)
}

func exitCodeForCheck(results []CheckResult) int {
	for _, r := range results {
		if r.Available == nil {
			return 2
		}
	}
	for _, r := range results {
		if r.Available != nil && !*r.Available {
			return 1
		}
	}
	return 0
}

func collectInputDomains(args []string) []string {
	var out []string
	for _, arg := range args {
		if arg == "-" {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				s := strings.TrimSpace(scanner.Text())
				if s == "" || strings.HasPrefix(s, "#") {
					continue
				}
				out = append(out, s)
			}
		} else {
			out = append(out, arg)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// check command
// ---------------------------------------------------------------------------

type checkArgs struct {
	Domains       []string
	TLD           string
	AvailableOnly bool
	JSON          bool
	Timeout       float64
}

func cmdCheck(args checkArgs) int {
	var tldsPool []string
	if args.TLD != "" {
		for _, t := range strings.Split(args.TLD, ",") {
			t = strings.TrimSpace(strings.TrimLeft(t, "."))
			if t != "" {
				tldsPool = append(tldsPool, strings.ToLower(t))
			}
		}
	}
	timeout := time.Duration(args.Timeout * float64(time.Second))
	inputs := collectInputDomains(args.Domains)

	if len(inputs) == 0 {
		const msg = "no domains provided"
		if args.JSON {
			fmt.Printf(`{"error":%q}`, msg)
			fmt.Println()
		} else {
			fmt.Fprintln(os.Stderr, "Error: "+msg+".")
		}
		return 2
	}

	type group struct {
		Input   string
		Results []CheckResult
	}

	var groups []group
	var allResults []CheckResult

	for _, raw := range inputs {
		n, t := splitDomain(strings.ToLower(raw))
		var targets []string
		if t != "" {
			targets = []string{n + "." + t}
		} else {
			pool := tldsPool
			if len(pool) == 0 {
				pool = popularTLDs
			}
			for _, tld := range pool {
				targets = append(targets, n+"."+tld)
			}
		}

		results := make([]CheckResult, len(targets))
		if len(targets) == 1 {
			results[0] = checkDomainFn(targets[0], timeout)
		} else {
			var mu sync.Mutex
			var wg sync.WaitGroup
			for i, d := range targets {
				wg.Add(1)
				go func(i int, d string) {
					defer wg.Done()
					r := checkDomainFn(d, timeout)
					mu.Lock()
					results[i] = r
					mu.Unlock()
				}(i, d)
			}
			wg.Wait()
		}
		sort.Slice(results, func(i, j int) bool { return results[i].Domain < results[j].Domain })
		allResults = append(allResults, results...)
		groups = append(groups, group{Input: raw, Results: results})
	}

	if args.JSON {
		type jsonResult struct {
			Domain    string `json:"domain"`
			Available *bool  `json:"available"`
			Method    string `json:"method"`
			Detail    string `json:"detail"`
		}
		type jsonGroup struct {
			Input   string       `json:"input"`
			Results []jsonResult `json:"results"`
		}
		var payload []jsonGroup
		for _, g := range groups {
			var entries []jsonResult
			for _, r := range g.Results {
				if args.AvailableOnly && (r.Available == nil || !*r.Available) {
					continue
				}
				entries = append(entries, jsonResult{
					Domain:    r.Domain,
					Available: r.Available,
					Method:    r.Method,
					Detail:    r.Detail,
				})
			}
			payload = append(payload, jsonGroup{Input: g.Input, Results: entries})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		enc.Encode(payload)
	} else {
		for _, g := range groups {
			var visible []CheckResult
			for _, r := range g.Results {
				if !args.AvailableOnly || (r.Available != nil && *r.Available) {
					visible = append(visible, r)
				}
			}
			if len(visible) == 0 {
				continue
			}
			fmt.Printf("\n%s\n", g.Input)
			for _, r := range visible {
				printResultLine(r)
			}
		}
	}

	return exitCodeForCheck(allResults)
}

// ---------------------------------------------------------------------------
// whois command
// ---------------------------------------------------------------------------

type whoisArgs struct {
	Domain  string
	Raw     bool
	JSON    bool
	Timeout float64
}

func cmdWhois(args whoisArgs) int {
	domain := normalizeDomain(args.Domain)
	timeout := time.Duration(args.Timeout * float64(time.Second))

	if !isValidDomain(domain) {
		msg := "invalid domain name: " + args.Domain
		if args.JSON {
			b, _ := json.Marshal(map[string]string{"domain": args.Domain, "error": msg})
			fmt.Println(string(b))
		} else {
			fmt.Fprintln(os.Stderr, "Error: "+msg)
		}
		return 2
	}

	if !args.Raw {
		r := rdapLookupFn(domain, timeout)
		if r != nil {
			if r.Available != nil && *r.Available {
				if args.JSON {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					enc.SetEscapeHTML(false)
					enc.Encode(map[string]interface{}{
						"domain": domain, "available": true,
						"method": "RDAP", "record": nil,
					})
				} else {
					fmt.Printf("%s appears to be AVAILABLE (RDAP 404 — no registration data).\n", domain)
				}
				return 1
			}
			if r.Available != nil && !*r.Available {
				if args.JSON {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					enc.SetEscapeHTML(false)
					enc.Encode(map[string]interface{}{
						"domain": domain, "available": false,
						"method": "RDAP", "record": r.Data,
					})
				} else {
					fmt.Printf("RDAP record for %s:\n\n%s\n", domain, formatRDAP(r.Data))
				}
				return 0
			}
			// RDAP errored — fall through to WHOIS
			if !args.JSON {
				fmt.Printf("RDAP unavailable (%s), falling back to WHOIS...\n\n", r.Err)
			}
		} else if !args.JSON {
			fmt.Print("RDAP not available for this TLD, falling back to WHOIS...\n\n")
		}
	}

	text, err := whoisLookupFn(domain, timeout)
	if err != "" && text == "" {
		if args.JSON {
			b, _ := json.Marshal(map[string]string{"domain": domain, "error": err})
			fmt.Println(string(b))
		} else {
			fmt.Fprintln(os.Stderr, "Error: "+err)
		}
		return 2
	}

	avail := guessAvailability(text)
	if args.JSON {
		type whoisJSON struct {
			Domain    string `json:"domain"`
			Available *bool  `json:"available"`
			Method    string `json:"method"`
			Text      string `json:"text"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		enc.Encode(whoisJSON{
			Domain:    domain,
			Available: avail,
			Method:    "WHOIS",
			Text:      strings.TrimSpace(text),
		})
	} else {
		fmt.Println(strings.TrimSpace(text))
		if avail != nil && *avail {
			fmt.Print("\nHeuristic: this domain looks AVAILABLE.\n")
		} else if avail != nil && !*avail {
			fmt.Print("\nHeuristic: this domain looks TAKEN.\n")
		} else {
			fmt.Print("\nHeuristic: could not determine availability from this WHOIS response.\n")
		}
	}

	if avail != nil && *avail {
		return 1
	}
	if avail != nil && !*avail {
		return 0
	}
	return 2
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const helpText = `domradar — Check domain name availability and inspect WHOIS/RDAP records.

USAGE
  domradar <command> [options]

COMMANDS
  check <domain>... [--tld <tlds>] [--available-only] [--json]
      Check availability of one or more domains.

  whois <domain> [--raw] [--json]
      Show detailed WHOIS/RDAP info for a domain.

  -V, --version   Show version and exit.
  -h, --help      Show this help.
`

// normalizeArgs converts GNU --long-flag into Go's -long-flag form.
func normalizeArgs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		if strings.HasPrefix(a, "--") && len(a) > 2 {
			out = append(out, a[1:])
			continue
		}
		out = append(out, a)
	}
	return out
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(helpText)
		return 0
	}
	switch args[0] {
	case "-h", "--help":
		fmt.Print(helpText)
		return 0
	case "-V", "--version":
		fmt.Printf("domradar %s\n", version)
		return 0
	}
	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "check":
		return runCheck(rest)
	case "whois":
		return runWhois(rest)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, helpText)
		return 2
	}
}

func runCheck(rest []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	tld := fs.String("tld", "", "Comma-separated TLDs for bare names")
	availableOnly := fs.Bool("available-only", false, "Only show AVAILABLE domains")
	jsonOut := fs.Bool("json", false, "Machine-readable JSON output")
	timeout := fs.Float64("timeout", defaultTimeout.Seconds(), "Network timeout in seconds")
	fs.Parse(normalizeArgs(rest))

	return cmdCheck(checkArgs{
		Domains:       fs.Args(),
		TLD:           *tld,
		AvailableOnly: *availableOnly,
		JSON:          *jsonOut,
		Timeout:       *timeout,
	})
}

func runWhois(rest []string) int {
	fs := flag.NewFlagSet("whois", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	raw := fs.Bool("raw", false, "Force raw legacy WHOIS instead of RDAP")
	jsonOut := fs.Bool("json", false, "Machine-readable JSON output")
	timeout := fs.Float64("timeout", defaultTimeout.Seconds(), "Network timeout in seconds")
	fs.Parse(normalizeArgs(rest))

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: domain is required")
		return 2
	}

	return cmdWhois(whoisArgs{
		Domain:  fs.Arg(0),
		Raw:     *raw,
		JSON:    *jsonOut,
		Timeout: *timeout,
	})
}

func main() {
	osExit(run(os.Args[1:]))
}
