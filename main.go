// NetMon Go - high-perf network monitor & firewall
//
// Build:
//   Windows: install Npcap SDK (https://npcap.com/dist/npcap-sdk-1.13.zip),
//            extract, set env: set CGO_ENABLED=1
//            go build -o netmon.exe .
//   Linux:   sudo apt install libpcap-dev
//            go build -o netmon .
//
// Run as Administrator (Windows) or sudo (Linux).
//   ./netmon
// Open http://127.0.0.1:18472
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

//go:embed index.html
var indexHTMLBytes []byte

const (
	historySecs   = 60
	dbFlushMS     = 2000
	flowIdleSecs  = 300 // prune flows idle > 5 min
	pruneEverySec = 60
	wsWriteWait   = 5 * time.Second
	wsPongWait    = 60 * time.Second
	wsPingPeriod  = 30 * time.Second

	// GeoIP via ip-api.com (free, 45 req/min, batch up to 100 IPs)
	geoBatchEndpoint = "http://ip-api.com/batch"
	geoBatchSize     = 100
	geoBatchEverySec = 6 // ~10 req/min, well under the limit
	geoCacheMax      = 50000
)

/* ---------------- Types ---------------- */

type FlowKey struct {
	Proto              string
	LAddr, RAddr       string
	LPort, RPort       uint16
}

type Flow struct {
	Bytes, Sent, Recv uint64
	SentPrev, RecvPrev uint64 // snapshot at last bucket tick
	RateSent, RateRecv uint64 // bytes/sec, refreshed each second
	PID               int32
	Name              string
	Domain            string // best-known hostname (DNS / SNI / Host header / rDNS)
	SNI               string // TLS Server Name Indication seen on this flow
	HTTPHost          string // HTTP Host header seen on this flow
	First, Last       int64  // unix ms
	Threat            int    // mirror of GeoInfo threat for quick UI access
}

type ProcStat struct {
	Sent, Recv         uint64
	SentPrev, RecvPrev uint64
	RateSent, RateRecv uint64
	Conns              map[FlowKey]struct{}
	RemoteIPs          map[string]struct{}
	Name               string
}

type Alert struct {
	TS    int64  `json:"ts"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

type BWPoint struct {
	TS   int64  `json:"ts"`
	Sent uint64 `json:"sent"`
	Recv uint64 `json:"recv"`
}

// Custom MarshalJSON to emit array form for compactness on the wire.
func (b BWPoint) MarshalJSON() ([]byte, error) {
	return json.Marshal([3]uint64{uint64(b.TS), b.Sent, b.Recv})
}

// GeoInfo is enrichment data for a remote IP.
type GeoInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	ASN         string `json:"asn"`
	ASName      string `json:"as_name"`
	Threat      int    `json:"threat"` // 0=safe, 1=suspicious, 2=risky
}

// Rule is a declarative firewall rule. Exactly one match field should be set.
type Rule struct {
	ID          int64  `json:"id"`
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name"`
	Action      string `json:"action"` // "block" or "alert"
	MatchType   string `json:"match_type"`  // process|country|asn|cidr|port
	MatchValue  string `json:"match_value"`
	HitCount    int64  `json:"hit_count"`
	Created     int64  `json:"created"`
}

/* ---------------- Monitor ---------------- */

type Monitor struct {
	mu sync.RWMutex

	flows       map[FlowKey]*Flow
	procs       map[int32]*ProcStat
	domains     map[string]int
	dnsCache    map[string]string // ip -> hostname
	blocked     map[string]bool

	totalSent, totalRecv, totalPkts uint64
	// Public-only counters: exclude loopback + RFC1918/RFC4193 LAN traffic.
	// The dashboard "Uploaded / Downloaded" cards show these so the user sees
	// internet activity, not chatty p2p / localhost noise.
	pubSent, pubRecv uint64

	bwHistory []BWPoint
	curBucket int64
	curSent   uint64
	curRecv   uint64

	alerts          []Alert
	alertNewProc    atomic.Bool
	alertBwThresh   atomic.Uint64 // bytes/sec; 0 = off
	lastBwAlertTS   int64         // unix sec of last bandwidth-spike alert (cooldown)
	seenProcs       map[int32]bool

	// Capture
	captureMu     sync.Mutex
	captureCtx    context.Context
	captureCancel context.CancelFunc
	running       atomic.Bool
	paused        atomic.Bool
	captureIface  string // "(all)" or specific

	// PID cache
	pidCacheMu sync.RWMutex
	pidCache   map[string]int32        // "ip:port" -> pid
	pidNames   map[int32]string
	pidCacheTS time.Time
	localIPs   map[string]bool

	// PCAP
	pcapMu       sync.Mutex
	pcapWriter   *pcapgo.Writer
	pcapFile     *os.File
	pcapPath     string
	pcapLinkType layers.LinkType // link type the file was opened with

	// DB
	db         *sql.DB
	dbQueue    chan []any
	dnsQueue   chan [2]string // {query, answerIP}
	alertQueue chan Alert
	dbStop     chan struct{}

	// Reverse DNS
	rdnsQueue chan string
	rdnsMu    sync.Mutex
	rdnsSeen  map[string]bool

	// GeoIP enrichment
	geoEnabled atomic.Bool
	geoMu      sync.RWMutex
	geoCache   map[string]*GeoInfo // ip -> info (also negative cache via empty Country)
	geoPending []string            // pending IPs to lookup

	// Rules engine
	rulesMu sync.RWMutex
	rules   []*Rule

	// BPF filter applied at capture-open time
	bpfMu     sync.RWMutex
	bpfFilter string

	// Push channel (broadcast deltas to WS clients)
	subsMu sync.RWMutex
	subs   map[chan []byte]bool

	// Debug toggle (read at runtime by hot paths that may want verbose logging)
	debugMode atomic.Bool

	// Counters for storage health
	dbDropped atomic.Uint64 // packets dropped due to full dbQueue
	dbWrites  atomic.Uint64 // total packets persisted
	flowsPersisted atomic.Uint64

	// Bulk-block progress (ad-block list import). UI polls these via /api/status.
	bulkBlockTotal atomic.Uint64
	bulkBlockDone  atomic.Uint64
	bulkBlockMsg   atomic.Value // string

	// Per-packet logging toggle. Off by default — flows table is the system of
	// record. With this on, every packet is also written to `packets`, which
	// makes netmon.db grow ~200 bytes/packet (1 GB/hour at 1000 pkts/sec).
	logPackets atomic.Bool

	// Retention windows in days, user-configurable via /api/settings.
	// 0 = keep forever (no auto-prune for that table).
	retentionPacketDays  atomic.Int64 // packets table
	retentionArchiveDays atomic.Int64 // flows + dns + alerts
}

func NewMonitor() (*Monitor, error) {
	m := &Monitor{
		flows:     make(map[FlowKey]*Flow),
		procs:     make(map[int32]*ProcStat),
		domains:   make(map[string]int),
		dnsCache:  make(map[string]string),
		blocked:   make(map[string]bool),
		seenProcs: make(map[int32]bool),
		bwHistory: make([]BWPoint, 0, historySecs),
		curBucket: time.Now().Unix(),
		pidCache:  make(map[string]int32),
		pidNames:  make(map[int32]string),
		localIPs:  make(map[string]bool),
		dbQueue:    make(chan []any, 5000),
		dnsQueue:   make(chan [2]string, 2000),
		alertQueue: make(chan Alert, 500),
		dbStop:     make(chan struct{}),
		rdnsQueue: make(chan string, 1000),
		rdnsSeen:  make(map[string]bool),
		geoCache:  make(map[string]*GeoInfo),
		subs:      make(map[chan []byte]bool),
	}
	m.alertNewProc.Store(true)
	m.geoEnabled.Store(true)
	m.debugMode.Store(true)
	m.retentionPacketDays.Store(7)
	m.retentionArchiveDays.Store(30)
	m.bulkBlockMsg.Store("idle")
	if err := m.initDB(); err != nil {
		return nil, err
	}
	m.loadBlocked()
	m.loadRules()
	m.seedDefaultRules()
	m.refreshLocalIPs()
	go m.dbWorker()
	go m.dnsWorker()
	go m.alertWorker()
	go m.bucketTicker()
	go m.rdnsWorker()
	go m.pruneTicker()
	go m.geoWorker()
	go m.retentionTicker()
	return m, nil
}

// retentionTicker auto-prunes old packet/dns rows so the SQLite file stays
// small even on long captures, then VACUUMs to reclaim space.
// Defaults: keep 7 days of packets, 30 days of flows + dns + alerts.
func (m *Monitor) retentionTicker() {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		m.runRetention(true)
	}
}

// runRetention deletes rows older than the configured windows. A window of 0
// means "keep forever" for that table. Returns total rows pruned. When vacuum
// is true and anything was pruned, the file is VACUUMed to reclaim space.
func (m *Monitor) runRetention(vacuum bool) int64 {
	if m.db == nil {
		return 0
	}
	now := time.Now()
	pktDays := m.retentionPacketDays.Load()
	arcDays := m.retentionArchiveDays.Load()
	var a, b, c, d int64
	if pktDays > 0 {
		cut := now.Add(-time.Duration(pktDays) * 24 * time.Hour).UnixMilli()
		if r, _ := m.db.Exec("DELETE FROM packets WHERE ts < ?", cut); r != nil {
			a, _ = r.RowsAffected()
		}
	}
	if arcDays > 0 {
		cut := now.Add(-time.Duration(arcDays) * 24 * time.Hour).UnixMilli()
		if r, _ := m.db.Exec("DELETE FROM dns WHERE ts < ?", cut); r != nil {
			b, _ = r.RowsAffected()
		}
		if r, _ := m.db.Exec("DELETE FROM flows WHERE last_ts < ?", cut); r != nil {
			c, _ = r.RowsAffected()
		}
		if r, _ := m.db.Exec("DELETE FROM alerts WHERE ts < ?", cut); r != nil {
			d, _ = r.RowsAffected()
		}
	}
	total := a + b + c + d
	if total > 0 {
		log.Printf("retention: pruned packets=%d dns=%d flows=%d alerts=%d", a, b, c, d)
		if vacuum {
			if _, err := m.db.Exec("VACUUM"); err != nil && m.debugMode.Load() {
				log.Printf("VACUUM: %v", err)
			}
		}
	}
	return total
}

func (m *Monitor) initDB() error {
	// Performance PRAGMAs baked into the DSN:
	//  _journal=WAL        readers never block the writer
	//  _synchronous=NORMAL safe under WAL, far fewer fsyncs than FULL
	//  _cache_size=-16000  16 MB page cache (negative = KiB)
	//  _busy_timeout=5000  wait up to 5s for a lock instead of erroring
	db, err := sql.Open("sqlite3",
		"netmon.db?_journal=WAL&_synchronous=NORMAL&_cache_size=-16000&_busy_timeout=5000")
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS packets(
			ts INTEGER, src TEXT, sport INT, dst TEXT, dport INT,
			proto TEXT, length INT, pid INT, pname TEXT, domain TEXT);
		CREATE TABLE IF NOT EXISTS dns(ts INT, query TEXT, answer TEXT);
		CREATE TABLE IF NOT EXISTS blocked(ip TEXT PRIMARY KEY, ts INT);
		CREATE TABLE IF NOT EXISTS alerts(ts INT, level TEXT, msg TEXT);
		CREATE TABLE IF NOT EXISTS rules(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			enabled INTEGER NOT NULL DEFAULT 1,
			name TEXT NOT NULL,
			action TEXT NOT NULL,
			match_type TEXT NOT NULL,
			match_value TEXT NOT NULL,
			hit_count INTEGER NOT NULL DEFAULT 0,
			created INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS flows(
			first_ts INTEGER, last_ts INTEGER,
			proto TEXT, laddr TEXT, lport INT, raddr TEXT, rport INT,
			pid INT, process TEXT,
			domain TEXT, sni TEXT, http_host TEXT,
			country_code TEXT, country TEXT, asn TEXT, isp TEXT,
			sent INT, recv INT, threat INT, blocked INT,
			PRIMARY KEY(first_ts, proto, laddr, lport, raddr, rport, pid)
		);
		CREATE INDEX IF NOT EXISTS i_pkt_ts ON packets(ts);
		CREATE INDEX IF NOT EXISTS i_pkt_pid ON packets(pid);
		CREATE INDEX IF NOT EXISTS i_pkt_dst ON packets(dst);
		CREATE INDEX IF NOT EXISTS i_flow_last ON flows(last_ts);
		CREATE INDEX IF NOT EXISTS i_flow_proc ON flows(process);
		CREATE INDEX IF NOT EXISTS i_flow_raddr ON flows(raddr);`)
	if err != nil {
		return err
	}
	// SQLite is a single-writer engine. Cap the pool to ONE connection so all
	// callers serialize through it instead of each opening a fresh cgo handle
	// (which, under load, spawns thousands of goroutines + connections and
	// crashes the process). WAL mode still allows concurrent readers via the
	// file, and our access volume is modest.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Extra speed PRAGMAs not expressible in the DSN.
	for _, p := range []string{
		"PRAGMA temp_store=MEMORY;", // sorts/temp tables in RAM
		"PRAGMA mmap_size=268435456;", // 256 MB memory-mapped I/O
		"PRAGMA wal_autocheckpoint=1000;",
	} {
		if _, err := db.Exec(p); err != nil {
			log.Printf("pragma %q: %v", p, err)
		}
	}

	m.db = db
	m.migrateFlowsTable()
	return nil
}

// migrateFlowsTable drops + recreates flows when an old schema (with an `id`
// AUTOINCREMENT column and no composite PRIMARY KEY) is detected. The old
// schema cannot deduplicate on INSERT OR REPLACE, so a one-time wipe is
// cheaper than carrying dupes forward. Logged so user knows what happened.
func (m *Monitor) migrateFlowsTable() {
	rows, err := m.db.Query("PRAGMA table_info(flows)")
	if err != nil {
		return
	}
	defer rows.Close()
	hasID := false
	hasFirstTs := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			continue
		}
		if name == "id" {
			hasID = true
		}
		if name == "first_ts" && pk > 0 {
			hasFirstTs = true
		}
	}
	if hasID && !hasFirstTs {
		log.Printf("migrating flows table to composite-PK schema (old rows discarded)")
		if _, err := m.db.Exec("DROP TABLE flows"); err == nil {
			_, _ = m.db.Exec(`CREATE TABLE flows(
				first_ts INTEGER, last_ts INTEGER,
				proto TEXT, laddr TEXT, lport INT, raddr TEXT, rport INT,
				pid INT, process TEXT,
				domain TEXT, sni TEXT, http_host TEXT,
				country_code TEXT, country TEXT, asn TEXT, isp TEXT,
				sent INT, recv INT, threat INT, blocked INT,
				PRIMARY KEY(first_ts, proto, laddr, lport, raddr, rport, pid));`)
			_, _ = m.db.Exec(`CREATE INDEX IF NOT EXISTS i_flow_last  ON flows(last_ts);`)
			_, _ = m.db.Exec(`CREATE INDEX IF NOT EXISTS i_flow_proc  ON flows(process);`)
			_, _ = m.db.Exec(`CREATE INDEX IF NOT EXISTS i_flow_raddr ON flows(raddr);`)
		}
	}
}

func (m *Monitor) loadBlocked() {
	rows, err := m.db.Query("SELECT ip FROM blocked")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			m.blocked[ip] = true
		}
	}
}

func (m *Monitor) loadRules() {
	rows, err := m.db.Query(
		"SELECT id,enabled,name,action,match_type,match_value,hit_count,created FROM rules")
	if err != nil {
		return
	}
	defer rows.Close()
	m.rulesMu.Lock()
	defer m.rulesMu.Unlock()
	m.rules = m.rules[:0]
	for rows.Next() {
		var r Rule
		var enabled int
		if rows.Scan(&r.ID, &enabled, &r.Name, &r.Action, &r.MatchType,
			&r.MatchValue, &r.HitCount, &r.Created) != nil {
			continue
		}
		r.Enabled = enabled == 1
		m.rules = append(m.rules, &r)
	}
}

// seedDefaultRules installs a curated baseline of alert rules on first launch.
// Skips if any of the same (match_type, match_value) already exists, so it's safe
// to call repeatedly. Triggered only when the rules table is completely empty.
func (m *Monitor) seedDefaultRules() {
	m.rulesMu.RLock()
	n := len(m.rules)
	m.rulesMu.RUnlock()
	if n > 0 {
		return // user already has rules — never auto-add
	}
	defaults := []Rule{
		// Remote-access protocols leaving the host
		{Name: "SSH outbound (port 22)", MatchType: "port", MatchValue: "22", Action: "alert"},
		{Name: "Telnet outbound (port 23)", MatchType: "port", MatchValue: "23", Action: "alert"},
		{Name: "RDP outbound (port 3389)", MatchType: "port", MatchValue: "3389", Action: "alert"},
		{Name: "SMB outbound (port 445)", MatchType: "port", MatchValue: "445", Action: "alert"},
		{Name: "FTP outbound (port 21)", MatchType: "port", MatchValue: "21", Action: "alert"},
		{Name: "WinRM outbound (5985)", MatchType: "port", MatchValue: "5985", Action: "alert"},
		{Name: "WinRM-S outbound (5986)", MatchType: "port", MatchValue: "5986", Action: "alert"},
		// C2 / anonymizer
		{Name: "IRC outbound (port 6667)", MatchType: "port", MatchValue: "6667", Action: "alert"},
		{Name: "Tor relay port (9001)", MatchType: "port", MatchValue: "9001", Action: "alert"},
		{Name: "SOCKS proxy (1080)", MatchType: "port", MatchValue: "1080", Action: "alert"},
		// Database egress
		{Name: "MSSQL outbound (1433)", MatchType: "port", MatchValue: "1433", Action: "alert"},
		{Name: "MySQL outbound (3306)", MatchType: "port", MatchValue: "3306", Action: "alert"},
		{Name: "PostgreSQL outbound (5432)", MatchType: "port", MatchValue: "5432", Action: "alert"},
		// Crypto mining
		{Name: "Crypto-mining pool (3333)", MatchType: "port", MatchValue: "3333", Action: "alert"},
		{Name: "Crypto-mining pool (4444)", MatchType: "port", MatchValue: "4444", Action: "alert"},
		{Name: "Crypto-mining pool (14444)", MatchType: "port", MatchValue: "14444", Action: "alert"},
		// Living-off-the-land binaries on the wire (Windows-centric)
		{Name: "PowerShell on the wire", MatchType: "process", MatchValue: "powershell", Action: "alert"},
		{Name: "cmd.exe on the wire", MatchType: "process", MatchValue: "cmd.exe", Action: "alert"},
		{Name: "rundll32 on the wire", MatchType: "process", MatchValue: "rundll32", Action: "alert"},
		{Name: "regsvr32 on the wire", MatchType: "process", MatchValue: "regsvr32", Action: "alert"},
		{Name: "mshta on the wire", MatchType: "process", MatchValue: "mshta", Action: "alert"},
		{Name: "certutil on the wire", MatchType: "process", MatchValue: "certutil", Action: "alert"},
		{Name: "bitsadmin on the wire", MatchType: "process", MatchValue: "bitsadmin", Action: "alert"},
		// High-risk regions (alert-only; user can change to block)
		{Name: "Connection to KP (North Korea)", MatchType: "country", MatchValue: "KP", Action: "alert"},
		{Name: "Connection to IR (Iran)", MatchType: "country", MatchValue: "IR", Action: "alert"},
	}
	for _, r := range defaults {
		r.Enabled = true
		if _, err := m.AddRule(r); err != nil {
			log.Printf("seedDefaults: %v: %v", r.Name, err)
		}
	}
	log.Printf("seeded %d default alert rules", len(defaults))
}

// AddRule persists and activates a new rule.
func (m *Monitor) AddRule(r Rule) (Rule, error) {
	if r.Action != "block" && r.Action != "alert" {
		return r, fmt.Errorf("action must be 'block' or 'alert'")
	}
	switch r.MatchType {
	case "process", "country", "asn", "cidr", "port":
	default:
		return r, fmt.Errorf("match_type must be one of: process, country, asn, cidr, port")
	}
	if r.MatchValue == "" {
		return r, fmt.Errorf("match_value required")
	}
	if r.MatchType == "cidr" {
		if _, _, err := net.ParseCIDR(r.MatchValue); err != nil {
			// Allow a bare IP too
			if net.ParseIP(r.MatchValue) == nil {
				return r, fmt.Errorf("invalid CIDR or IP: %s", r.MatchValue)
			}
		}
	}
	if r.Name == "" {
		r.Name = fmt.Sprintf("%s=%s", r.MatchType, r.MatchValue)
	}
	// Dedupe: same (match_type, match_value, action) already exists?
	m.rulesMu.RLock()
	for _, ex := range m.rules {
		if ex.MatchType == r.MatchType && ex.MatchValue == r.MatchValue && ex.Action == r.Action {
			m.rulesMu.RUnlock()
			return *ex, fmt.Errorf("rule already exists (id=%d)", ex.ID)
		}
	}
	m.rulesMu.RUnlock()
	r.Created = time.Now().UnixMilli()
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	res, err := m.db.Exec(
		"INSERT INTO rules(enabled,name,action,match_type,match_value,hit_count,created) VALUES(?,?,?,?,?,0,?)",
		enabled, r.Name, r.Action, r.MatchType, r.MatchValue, r.Created)
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	m.rulesMu.Lock()
	m.rules = append(m.rules, &r)
	m.rulesMu.Unlock()
	log.Printf("AddRule: id=%d %s %s=%s action=%s", r.ID, r.Name, r.MatchType, r.MatchValue, r.Action)
	return r, nil
}

func (m *Monitor) DeleteRule(id int64) error {
	_, err := m.db.Exec("DELETE FROM rules WHERE id=?", id)
	if err != nil {
		return err
	}
	m.rulesMu.Lock()
	defer m.rulesMu.Unlock()
	for i, r := range m.rules {
		if r.ID == id {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			break
		}
	}
	return nil
}

func (m *Monitor) ToggleRule(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := m.db.Exec("UPDATE rules SET enabled=? WHERE id=?", v, id)
	if err != nil {
		return err
	}
	m.rulesMu.Lock()
	defer m.rulesMu.Unlock()
	for _, r := range m.rules {
		if r.ID == id {
			r.Enabled = enabled
			break
		}
	}
	return nil
}

func (m *Monitor) ListRules() []Rule {
	m.rulesMu.RLock()
	defer m.rulesMu.RUnlock()
	out := make([]Rule, len(m.rules))
	for i, r := range m.rules {
		out[i] = *r
	}
	return out
}

// evaluateRules checks rules against a (process, remoteIP) pair and applies actions.
// Called from handlePacket the first time a flow is created. Returns true if blocked.
func (m *Monitor) evaluateRules(pname string, remoteIP string, rport uint16) bool {
	m.rulesMu.RLock()
	rules := make([]*Rule, 0, len(m.rules))
	for _, r := range m.rules {
		if r.Enabled {
			rules = append(rules, r)
		}
	}
	m.rulesMu.RUnlock()
	if len(rules) == 0 {
		return false
	}

	geo := m.geoLookupCached(remoteIP)
	ipParsed := net.ParseIP(remoteIP)

	for _, r := range rules {
		match := false
		switch r.MatchType {
		case "process":
			match = strings.EqualFold(pname, r.MatchValue) ||
				strings.Contains(strings.ToLower(pname), strings.ToLower(r.MatchValue))
		case "country":
			if geo != nil {
				match = strings.EqualFold(geo.CountryCode, r.MatchValue)
			}
		case "asn":
			if geo != nil {
				match = geo.ASN == r.MatchValue || strings.Contains(geo.ASN, r.MatchValue)
			}
		case "cidr":
			if _, ipnet, err := net.ParseCIDR(r.MatchValue); err == nil && ipParsed != nil {
				match = ipnet.Contains(ipParsed)
			} else if v := net.ParseIP(r.MatchValue); v != nil && ipParsed != nil {
				match = v.Equal(ipParsed)
			}
		case "port":
			if p, err := strconv.Atoi(r.MatchValue); err == nil {
				match = uint16(p) == rport
			}
		}
		if !match {
			continue
		}
		// Hit!
		atomic.AddInt64(&r.HitCount, 1)
		_, _ = m.db.Exec("UPDATE rules SET hit_count=hit_count+1 WHERE id=?", r.ID)

		if r.Action == "block" {
			go func(ip, ruleName string) {
				ok, msg := m.Block(ip)
				m.mu.Lock()
				if ok {
					m.addAlertLocked("warn",
						fmt.Sprintf("Rule '%s' blocked %s", ruleName, ip))
				} else {
					m.addAlertLocked("error",
						fmt.Sprintf("Rule '%s' tried to block %s but failed: %s", ruleName, ip, msg))
				}
				m.mu.Unlock()
			}(remoteIP, r.Name)
			return true
		}
		// alert action
		m.mu.Lock()
		m.addAlertLocked("warn",
			fmt.Sprintf("Rule '%s' matched %s (%s)", r.Name, remoteIP, pname))
		m.mu.Unlock()
	}
	return false
}

/* ---------------- GeoIP worker ---------------- */

func (m *Monitor) geoLookupCached(ip string) *GeoInfo {
	m.geoMu.RLock()
	g := m.geoCache[ip]
	m.geoMu.RUnlock()
	return g
}

func (m *Monitor) queueGeoLookup(ip string) {
	if !m.geoEnabled.Load() || isPrivateIP(ip) {
		return
	}
	m.geoMu.Lock()
	if _, ok := m.geoCache[ip]; ok {
		m.geoMu.Unlock()
		return
	}
	// Mark as "queued" so we don't enqueue duplicates
	m.geoCache[ip] = nil
	if len(m.geoPending) < geoBatchSize*4 {
		m.geoPending = append(m.geoPending, ip)
	}
	m.geoMu.Unlock()
}

func (m *Monitor) geoWorker() {
	t := time.NewTicker(geoBatchEverySec * time.Second)
	defer t.Stop()
	httpClient := &http.Client{Timeout: 8 * time.Second}
	for range t.C {
		if !m.geoEnabled.Load() {
			continue
		}
		m.geoMu.Lock()
		if len(m.geoPending) == 0 {
			m.geoMu.Unlock()
			continue
		}
		batch := m.geoPending
		if len(batch) > geoBatchSize {
			batch = batch[:geoBatchSize]
			m.geoPending = m.geoPending[geoBatchSize:]
		} else {
			m.geoPending = m.geoPending[:0]
		}
		m.geoMu.Unlock()

		type req struct {
			Query  string `json:"query"`
			Fields string `json:"fields"`
		}
		body := make([]req, len(batch))
		for i, ip := range batch {
			body[i] = req{
				Query:  ip,
				Fields: "status,query,country,countryCode,city,isp,org,as,asname",
			}
		}
		jb, _ := json.Marshal(body)
		resp, err := httpClient.Post(geoBatchEndpoint, "application/json", bytes.NewReader(jb))
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		var results []struct {
			Status      string `json:"status"`
			Query       string `json:"query"`
			Country     string `json:"country"`
			CountryCode string `json:"countryCode"`
			City        string `json:"city"`
			ISP         string `json:"isp"`
			Org         string `json:"org"`
			AS          string `json:"as"`
			ASName      string `json:"asname"`
		}
		if err := json.Unmarshal(raw, &results); err != nil {
			continue
		}
		m.geoMu.Lock()
		for _, r := range results {
			if r.Status != "success" {
				// Mark as failed (empty Country); will not retry
				m.geoCache[r.Query] = &GeoInfo{}
				continue
			}
			g := &GeoInfo{
				Country: r.Country, CountryCode: r.CountryCode,
				City: r.City, ISP: r.ISP, Org: r.Org,
				ASN: r.AS, ASName: r.ASName,
				Threat: scoreThreat(r.CountryCode, r.AS),
			}
			m.geoCache[r.Query] = g
		}
		// Cap cache size
		if len(m.geoCache) > geoCacheMax {
			// Drop oldest by re-creating (cheap and correct)
			i := 0
			drop := len(m.geoCache) - geoCacheMax/2
			for k := range m.geoCache {
				if i >= drop {
					break
				}
				delete(m.geoCache, k)
				i++
			}
		}
		m.geoMu.Unlock()
	}
}

// scoreThreat assigns a heuristic threat level for a remote endpoint.
// 0=safe, 1=suspicious, 2=high. Heuristic only — meant to highlight, not accuse.
var suspiciousCountries = map[string]bool{
	"KP": true, "IR": true,
}
var riskyKeywords = []string{"bulletproof", "tor exit", "anonymous"}

func scoreThreat(cc, asInfo string) int {
	if suspiciousCountries[cc] {
		return 2
	}
	low := strings.ToLower(asInfo)
	for _, kw := range riskyKeywords {
		if strings.Contains(low, kw) {
			return 2
		}
	}
	return 0
}

/* ---------------- Application-layer parsing ---------------- */

// parseTLSSNI tries to extract the Server Name Indication from a TLS ClientHello.
// Returns empty string if the payload isn't a ClientHello or SNI is absent.
// This is a defensive byte-walk; partial / fragmented hellos return "".
func parseTLSSNI(payload []byte) string {
	// TLS record: type(1) version(2) length(2) handshake(...)
	if len(payload) < 6 {
		return ""
	}
	if payload[0] != 0x16 { // handshake
		return ""
	}
	p := payload[5:]
	// Handshake: type(1) length(3) version(2) random(32) sid_len(1) sid...
	if len(p) < 4 || p[0] != 0x01 { // ClientHello
		return ""
	}
	p = p[4:]
	if len(p) < 2+32+1 {
		return ""
	}
	p = p[2+32:] // skip version + random
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return ""
	}
	p = p[sidLen:]
	// cipher suites
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen+1 {
		return ""
	}
	p = p[csLen:]
	// compression methods
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen+2 {
		return ""
	}
	p = p[cmLen:]
	// extensions
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return ""
	}
	exts := p[:extLen]
	for len(exts) >= 4 {
		extType := int(exts[0])<<8 | int(exts[1])
		extDataLen := int(exts[2])<<8 | int(exts[3])
		if len(exts) < 4+extDataLen {
			return ""
		}
		extData := exts[4 : 4+extDataLen]
		exts = exts[4+extDataLen:]
		if extType != 0 { // server_name
			continue
		}
		// server_name_list: total length(2) then entries: name_type(1) name_len(2) name
		if len(extData) < 5 {
			return ""
		}
		if extData[2] != 0 { // host_name type
			return ""
		}
		nameLen := int(extData[3])<<8 | int(extData[4])
		if len(extData) < 5+nameLen {
			return ""
		}
		name := string(extData[5 : 5+nameLen])
		return name
	}
	return ""
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "),
	[]byte("HEAD "), []byte("DELETE "), []byte("OPTIONS "),
	[]byte("PATCH "), []byte("CONNECT "),
}

// parseHTTPHost extracts the Host header from a plaintext HTTP/1.x request payload.
func parseHTTPHost(payload []byte) string {
	if len(payload) < 16 {
		return ""
	}
	isHTTP := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(payload, m) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return ""
	}
	// Limit search to first 2KB
	limit := len(payload)
	if limit > 2048 {
		limit = 2048
	}
	idx := bytes.Index(payload[:limit], []byte("\r\nHost:"))
	if idx < 0 {
		idx = bytes.Index(payload[:limit], []byte("\r\nhost:"))
	}
	if idx < 0 {
		return ""
	}
	start := idx + 7
	end := bytes.Index(payload[start:limit], []byte("\r\n"))
	if end < 0 {
		return ""
	}
	host := strings.TrimSpace(string(payload[start : start+end]))
	return host
}

func (m *Monitor) dbWorker() {
	buf := make([][]any, 0, 1024)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		tx, err := m.db.Begin()
		if err != nil {
			buf = buf[:0]
			return
		}
		st, err := tx.Prepare("INSERT INTO packets VALUES(?,?,?,?,?,?,?,?,?,?)")
		if err != nil {
			tx.Rollback()
			buf = buf[:0]
			return
		}
		for _, r := range buf {
			_, _ = st.Exec(r...)
		}
		st.Close()
		_ = tx.Commit()
		buf = buf[:0]
	}
	tick := time.NewTicker(time.Duration(dbFlushMS) * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case rec := <-m.dbQueue:
			buf = append(buf, rec)
			if len(buf) >= 1000 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-m.dbStop:
			flush()
			return
		}
	}
}

// dnsWorker batches DNS-answer rows into the dns table. One goroutine, one
// transaction every 2s — never one goroutine per packet.
func (m *Monitor) dnsWorker() {
	buf := make([][2]string, 0, 256)
	flush := func() {
		if len(buf) == 0 || m.db == nil {
			return
		}
		tx, err := m.db.Begin()
		if err != nil {
			buf = buf[:0]
			return
		}
		st, err := tx.Prepare("INSERT INTO dns(ts,query,answer) VALUES(?,?,?)")
		if err != nil {
			_ = tx.Rollback()
			buf = buf[:0]
			return
		}
		now := time.Now().UnixMilli()
		for _, r := range buf {
			_, _ = st.Exec(now, r[0], r[1])
		}
		_ = st.Close()
		_ = tx.Commit()
		buf = buf[:0]
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case rec := <-m.dnsQueue:
			buf = append(buf, rec)
			if len(buf) >= 256 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-m.dbStop:
			flush()
			return
		}
	}
}

func (m *Monitor) bucketTicker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	tick := 0
	for range t.C {
		tick++
		// Every 30 ticks (~30s) snapshot live flows to disk so crashes don't lose data.
		if tick%30 == 0 {
			var snap []struct {
				k FlowKey
				f *Flow
			}
			m.mu.RLock()
			for k, f := range m.flows {
				snap = append(snap, struct {
					k FlowKey
					f *Flow
				}{k, f})
			}
			m.mu.RUnlock()
			m.persistFlows(snap)
			if m.debugMode.Load() {
				log.Printf("flow snapshot: persisted %d", len(snap))
			}
		}
		now := time.Now().Unix()
		m.mu.Lock()
		for m.curBucket < now {
			m.bwHistory = append(m.bwHistory, BWPoint{
				TS: m.curBucket, Sent: m.curSent, Recv: m.curRecv,
			})
			if len(m.bwHistory) > historySecs {
				m.bwHistory = m.bwHistory[len(m.bwHistory)-historySecs:]
			}
			// Alert check with 60s cooldown so a sustained spike doesn't
			// pour 200 identical entries into the alert ring inside 3 minutes.
			th := m.alertBwThresh.Load()
			if th > 0 && m.curSent+m.curRecv > th && m.curBucket-m.lastBwAlertTS >= 60 {
				m.addAlertLocked("warn",
					fmt.Sprintf("Bandwidth spike: %s/s", fmtBytes(m.curSent+m.curRecv)))
				m.lastBwAlertTS = m.curBucket
			}
			m.curBucket++
			m.curSent = 0
			m.curRecv = 0
		}
		// Per-flow + per-process rates: delta since last tick.
		for _, f := range m.flows {
			f.RateSent = f.Sent - f.SentPrev
			f.RateRecv = f.Recv - f.RecvPrev
			f.SentPrev = f.Sent
			f.RecvPrev = f.Recv
		}
		for _, p := range m.procs {
			p.RateSent = p.Sent - p.SentPrev
			p.RateRecv = p.Recv - p.RecvPrev
			p.SentPrev = p.Sent
			p.RecvPrev = p.Recv
		}
		m.mu.Unlock()
		m.pushStatus()
	}
}

// rdnsWorker resolves IPs to hostnames that DNS sniffing missed.
func (m *Monitor) rdnsWorker() {
	for ip := range m.rdnsQueue {
		m.rdnsMu.Lock()
		if m.rdnsSeen[ip] {
			m.rdnsMu.Unlock()
			continue
		}
		m.rdnsSeen[ip] = true
		m.rdnsMu.Unlock()

		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			continue
		}
		host := strings.TrimSuffix(names[0], ".")
		if host == "" {
			continue
		}
		m.mu.Lock()
		if _, ok := m.dnsCache[ip]; !ok {
			m.dnsCache[ip] = host
			m.domains[host]++
		}
		// Backfill existing flows so UI filters by host can match.
		for fk, ff := range m.flows {
			if fk.RAddr == ip && ff.Domain == "" {
				ff.Domain = host
			}
		}
		m.mu.Unlock()
	}
}

// pruneTicker drops flows that have been idle longer than flowIdleSecs.
// On eviction we persist the full enriched flow record to the flows table so
// that long-term history retains SNI / HTTP Host / GeoIP fields that the
// per-packet packets table does not carry.
func (m *Monitor) pruneTicker() {
	t := time.NewTicker(pruneEverySec * time.Second)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().UnixMilli() - int64(flowIdleSecs)*1000
		var evicted []struct {
			k FlowKey
			f *Flow
		}
		m.mu.Lock()
		for k, f := range m.flows {
			if f.Last < cutoff {
				evicted = append(evicted, struct {
					k FlowKey
					f *Flow
				}{k, f})
				delete(m.flows, k)
			}
		}
		m.mu.Unlock()
		m.persistFlows(evicted)
	}
}

// persistFlow writes the final enriched record of a flow to the flows table.
func (m *Monitor) persistFlow(k FlowKey, f *Flow) {
	if m.db == nil || f == nil {
		return
	}
	var cc, country, asn, isp string
	var threat int
	m.geoMu.RLock()
	if g := m.geoCache[k.RAddr]; g != nil {
		cc, country, asn, isp, threat = g.CountryCode, g.Country, g.ASN, g.ISP, g.Threat
	}
	m.geoMu.RUnlock()
	m.mu.RLock()
	blocked := m.blocked[k.RAddr]
	m.mu.RUnlock()
	blockedI := 0
	if blocked {
		blockedI = 1
	}
	_, err := m.db.Exec(
		`INSERT OR REPLACE INTO flows(first_ts,last_ts,proto,laddr,lport,raddr,rport,pid,process,
			domain,sni,http_host,country_code,country,asn,isp,sent,recv,threat,blocked)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.First, f.Last, k.Proto, k.LAddr, k.LPort, k.RAddr, k.RPort,
		f.PID, f.Name, f.Domain, f.SNI, f.HTTPHost,
		cc, country, asn, isp, f.Sent, f.Recv, threat, blockedI,
	)
	if err != nil {
		if m.debugMode.Load() {
			log.Printf("persistFlow: %v", err)
		}
		return
	}
	m.flowsPersisted.Add(1)
}

// persistFlows writes a batch of flows in a single transaction. Far cheaper
// than N individual INSERTs when the periodic snapshot covers hundreds of
// flows — one fsync at commit, not one per row.
func (m *Monitor) persistFlows(items []struct {
	k FlowKey
	f *Flow
}) {
	if m.db == nil || len(items) == 0 {
		return
	}
	tx, err := m.db.Begin()
	if err != nil {
		if m.debugMode.Load() {
			log.Printf("persistFlows begin: %v", err)
		}
		return
	}
	st, err := tx.Prepare(`INSERT OR REPLACE INTO flows(first_ts,last_ts,proto,laddr,lport,raddr,rport,pid,process,
		domain,sni,http_host,country_code,country,asn,isp,sent,recv,threat,blocked)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	defer st.Close()
	var n uint64
	for _, e := range items {
		f, k := e.f, e.k
		if f == nil {
			continue
		}
		var cc, country, asn, isp string
		var threat int
		m.geoMu.RLock()
		if g := m.geoCache[k.RAddr]; g != nil {
			cc, country, asn, isp, threat = g.CountryCode, g.Country, g.ASN, g.ISP, g.Threat
		}
		m.geoMu.RUnlock()
		m.mu.RLock()
		blocked := m.blocked[k.RAddr]
		m.mu.RUnlock()
		blockedI := 0
		if blocked {
			blockedI = 1
		}
		if _, err := st.Exec(
			f.First, f.Last, k.Proto, k.LAddr, k.LPort, k.RAddr, k.RPort,
			f.PID, f.Name, f.Domain, f.SNI, f.HTTPHost,
			cc, country, asn, isp, f.Sent, f.Recv, threat, blockedI,
		); err == nil {
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		if m.debugMode.Load() {
			log.Printf("persistFlows commit: %v", err)
		}
		return
	}
	m.flowsPersisted.Add(n)
}

func (m *Monitor) refreshLocalIPs() {
	ips := make(map[string]bool)
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ips[ipn.IP.String()] = true
			}
		}
	}
	m.pidCacheMu.Lock()
	m.localIPs = ips
	m.pidCacheMu.Unlock()
}

func (m *Monitor) refreshPIDCache() {
	m.pidCacheMu.RLock()
	stale := time.Since(m.pidCacheTS) > 2*time.Second
	m.pidCacheMu.RUnlock()
	if !stale {
		return
	}

	conns, err := psnet.Connections("inet")
	if err != nil {
		return
	}
	cache := make(map[string]int32, len(conns))
	names := make(map[int32]string)
	for _, c := range conns {
		if c.Laddr.IP == "" {
			continue
		}
		key := fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port)
		cache[key] = c.Pid
		if c.Pid > 0 {
			if _, ok := names[c.Pid]; !ok {
				if p, err := process.NewProcess(c.Pid); err == nil {
					if n, err := p.Name(); err == nil {
						names[c.Pid] = n
					}
				}
			}
		}
	}
	m.pidCacheMu.Lock()
	m.pidCache = cache
	m.pidNames = names
	m.pidCacheTS = time.Now()
	m.pidCacheMu.Unlock()
	m.refreshLocalIPs()
}

func (m *Monitor) pidFor(laddr string, lport uint16) (int32, string) {
	m.refreshPIDCache()
	m.pidCacheMu.RLock()
	defer m.pidCacheMu.RUnlock()
	key := fmt.Sprintf("%s:%d", laddr, lport)
	for _, k := range []string{key,
		fmt.Sprintf("0.0.0.0:%d", lport),
		fmt.Sprintf("::%d", lport)} {
		if pid, ok := m.pidCache[k]; ok {
			return pid, m.pidNames[pid]
		}
	}
	return 0, "unknown"
}

func (m *Monitor) addAlertLocked(level, msg string) {
	a := Alert{TS: time.Now().UnixMilli(), Level: level, Msg: msg}
	m.alerts = append([]Alert{a}, m.alerts...)
	if len(m.alerts) > 200 {
		m.alerts = m.alerts[:200]
	}
	// Persist via the worker so we don't hold m.mu while waiting on the DB conn.
	// Drop on full queue — the in-memory ring above keeps the alert visible.
	select {
	case m.alertQueue <- a:
	default:
	}
}

// alertWorker flushes alert rows in small batches so we never block the hot
// path on a DB write that's serialised behind dbWorker's transaction.
func (m *Monitor) alertWorker() {
	buf := make([]Alert, 0, 64)
	flush := func() {
		if len(buf) == 0 || m.db == nil {
			return
		}
		tx, err := m.db.Begin()
		if err != nil {
			buf = buf[:0]
			return
		}
		st, err := tx.Prepare("INSERT INTO alerts VALUES(?,?,?)")
		if err != nil {
			_ = tx.Rollback()
			buf = buf[:0]
			return
		}
		for _, a := range buf {
			_, _ = st.Exec(a.TS, a.Level, a.Msg)
		}
		_ = st.Close()
		_ = tx.Commit()
		buf = buf[:0]
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case a := <-m.alertQueue:
			buf = append(buf, a)
			if len(buf) >= 64 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-m.dbStop:
			flush()
			return
		}
	}
}

/* ---------------- Capture ---------------- */

func (m *Monitor) logDebug(format string, args ...any) {
	if m.debugMode.Load() {
		log.Printf("[debug] "+format, args...)
	}
}

func (m *Monitor) Start(iface string) error {
	m.captureMu.Lock()
	defer m.captureMu.Unlock()
	if m.running.Load() {
		return fmt.Errorf("already running")
	}

	// Resolve devices first so we can fail early
	var targets []string
	if iface == "" || iface == "(all)" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			return err
		}
		for _, d := range devs {
			if len(d.Addresses) == 0 {
				continue
			}
			targets = append(targets, d.Name)
		}
	} else {
		targets = []string{iface}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no usable interfaces found")
	}
	log.Printf("Start: iface=%q targets=%v", iface, targets)

	ctx, cancel := context.WithCancel(context.Background())
	m.captureCtx = ctx
	m.captureCancel = cancel

	displayIface := iface
	if displayIface == "" {
		displayIface = "(all)"
	}
	m.mu.Lock()
	m.captureIface = displayIface
	m.mu.Unlock()
	m.running.Store(true)
	m.paused.Store(false)

	var wg sync.WaitGroup
	for _, dev := range targets {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			m.captureOnDevice(ctx, name)
		}(dev)
	}
	go func() {
		wg.Wait()
		m.mu.Lock()
		m.captureIface = ""
		m.mu.Unlock()
		m.running.Store(false)
	}()
	m.mu.Lock()
	m.addAlertLocked("info", fmt.Sprintf("Capture started on %d interface(s)", len(targets)))
	m.mu.Unlock()
	return nil
}

func (m *Monitor) Stop() {
	log.Printf("Stop: capture cancel issued")
	m.captureMu.Lock()
	defer m.captureMu.Unlock()
	if m.captureCancel != nil {
		m.captureCancel()
	}
	m.StopPCAP()
	// Persist all currently-live flows so their enriched state survives.
	var snap []struct {
		k FlowKey
		f *Flow
	}
	m.mu.RLock()
	for k, f := range m.flows {
		snap = append(snap, struct {
			k FlowKey
			f *Flow
		}{k, f})
	}
	m.mu.RUnlock()
	m.persistFlows(snap)
	m.running.Store(false)
	log.Printf("Stop: persisted %d flows on shutdown", len(snap))
}

func (m *Monitor) captureOnDevice(ctx context.Context, dev string) {
	log.Printf("capture: opening device %q", dev)
	handle, err := pcap.OpenLive(dev, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("capture: open %s failed: %v", dev, err)
		m.mu.Lock()
		m.addAlertLocked("error", fmt.Sprintf("Open %s: %v", dev, err))
		m.mu.Unlock()
		return
	}
	defer func() {
		log.Printf("capture: closed device %q", dev)
		handle.Close()
	}()

	// Apply BPF filter if set
	m.bpfMu.RLock()
	bpf := m.bpfFilter
	m.bpfMu.RUnlock()
	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			m.mu.Lock()
			m.addAlertLocked("error", fmt.Sprintf("BPF on %s: %v", dev, err))
			m.mu.Unlock()
		}
	}

	linkType := handle.LinkType()
	source := gopacket.NewPacketSource(handle, linkType)
	source.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	packets := source.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}
			if m.paused.Load() {
				continue
			}
			m.handlePacket(pkt, linkType)
		}
	}
}

func (m *Monitor) handlePacket(pkt gopacket.Packet, linkType layers.LinkType) {
	// PCAP write: only when the device link type matches what the file was opened with,
	// otherwise the resulting pcap would be malformed.
	m.pcapMu.Lock()
	if m.pcapWriter != nil && linkType == m.pcapLinkType {
		ci := pkt.Metadata().CaptureInfo
		_ = m.pcapWriter.WritePacket(ci, pkt.Data())
	}
	m.pcapMu.Unlock()

	// DNS answers
	if dnsLayer := pkt.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		if dns.QR && len(dns.Answers) > 0 {
			var qname string
			if len(dns.Questions) > 0 {
				qname = string(dns.Questions[0].Name)
			}
			for _, ans := range dns.Answers {
				if (ans.Type == layers.DNSTypeA || ans.Type == layers.DNSTypeAAAA) && ans.IP != nil {
					ip := ans.IP.String()
					m.mu.Lock()
					m.dnsCache[ip] = qname
					if qname != "" {
						m.domains[qname]++
						// Backfill existing flows for this IP so chips/filters can find them
						for fk, ff := range m.flows {
							if fk.RAddr == ip && ff.Domain == "" {
								ff.Domain = qname
							}
						}
					}
					m.mu.Unlock()
					// Persist DNS answer through the bounded queue. NEVER spawn a
					// goroutine per packet here — under DNS load that explodes into
					// thousands of goroutines each opening a SQLite connection.
					if qname != "" {
						select {
						case m.dnsQueue <- [2]string{qname, ip}:
						default:
							// queue full — drop the dns log row, keep counting
						}
					}
				}
			}
		}
	}

	// IP layer
	var src, dst string
	var proto string
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return
	}
	switch v := netLayer.(type) {
	case *layers.IPv4:
		src, dst = v.SrcIP.String(), v.DstIP.String()
	case *layers.IPv6:
		src, dst = v.SrcIP.String(), v.DstIP.String()
	default:
		return
	}

	var sport, dport uint16
	var tcpPayload []byte
	tr := pkt.TransportLayer()
	switch t := tr.(type) {
	case *layers.TCP:
		proto = "TCP"
		sport, dport = uint16(t.SrcPort), uint16(t.DstPort)
		tcpPayload = t.Payload
	case *layers.UDP:
		proto = "UDP"
		sport, dport = uint16(t.SrcPort), uint16(t.DstPort)
	default:
		proto = "IP"
	}

	// Wire length is what was on the network; pkt.Data() may be truncated by SnapLen.
	length := uint64(pkt.Metadata().CaptureInfo.Length)
	if length == 0 {
		length = uint64(len(pkt.Data()))
	}

	m.pidCacheMu.RLock()
	outbound := m.localIPs[src]
	m.pidCacheMu.RUnlock()

	var laddr, raddr string
	var lport, rport uint16
	if outbound {
		laddr, lport, raddr, rport = src, sport, dst, dport
	} else {
		laddr, lport, raddr, rport = dst, dport, src, sport
	}

	pid, pname := m.pidFor(laddr, lport)

	m.mu.RLock()
	domain := m.dnsCache[raddr]
	m.mu.RUnlock()

	// Application-layer DPI on outbound TCP payloads. Both parsers fast-bail on
	// payloads that don't look right (first byte / method-prefix check), so trying
	// them on every TCP packet is cheap. This catches non-standard ports too.
	var sni, httpHost string
	if outbound && proto == "TCP" && len(tcpPayload) > 0 && len(tcpPayload) < 16384 {
		sni = parseTLSSNI(tcpPayload)
		if sni == "" {
			httpHost = parseHTTPHost(tcpPayload)
		}
	}
	bestDomain := domain
	if bestDomain == "" {
		if sni != "" {
			bestDomain = sni
		} else if httpHost != "" {
			bestDomain = httpHost
		}
	}

	// Queue reverse DNS for unresolved public IPs
	if bestDomain == "" && !isPrivateIP(raddr) {
		m.rdnsMu.Lock()
		seen := m.rdnsSeen[raddr]
		m.rdnsMu.Unlock()
		if !seen {
			select {
			case m.rdnsQueue <- raddr:
			default:
			}
		}
	}

	// Queue GeoIP lookup
	m.queueGeoLookup(raddr)

	key := FlowKey{Proto: proto, LAddr: laddr, RAddr: raddr, LPort: lport, RPort: rport}
	now := time.Now().UnixMilli()

	m.mu.Lock()
	f, isNew := m.flows[key], false
	if f == nil {
		isNew = true
		f = &Flow{PID: pid, Name: pname, Domain: bestDomain, SNI: sni, HTTPHost: httpHost, First: now}
		m.flows[key] = f
		// Also seed domains map when SNI/Host fills in
		if bestDomain != "" {
			if _, ok := m.dnsCache[raddr]; !ok {
				m.dnsCache[raddr] = bestDomain
				m.domains[bestDomain]++
			}
		}
	}
	f.Bytes += length
	f.Last = now
	if outbound {
		f.Sent += length
	} else {
		f.Recv += length
	}
	if f.Domain == "" && bestDomain != "" {
		f.Domain = bestDomain
	}
	if f.SNI == "" && sni != "" {
		f.SNI = sni
	}
	if f.HTTPHost == "" && httpHost != "" {
		f.HTTPHost = httpHost
	}

	ps, exists := m.procs[pid]
	if !exists {
		ps = &ProcStat{
			Name:      pname,
			Conns:     make(map[FlowKey]struct{}),
			RemoteIPs: make(map[string]struct{}),
		}
		m.procs[pid] = ps
	}
	if ps.Name == "" {
		ps.Name = pname
	}
	publicRemote := !isPrivateIP(raddr)
	if outbound {
		ps.Sent += length
		m.totalSent += length
		m.curSent += length
		if publicRemote {
			m.pubSent += length
		}
	} else {
		ps.Recv += length
		m.totalRecv += length
		m.curRecv += length
		if publicRemote {
			m.pubRecv += length
		}
	}
	ps.Conns[key] = struct{}{}
	if !isPrivateIP(raddr) {
		ps.RemoteIPs[raddr] = struct{}{}
	}
	m.totalPkts++

	if m.alertNewProc.Load() && outbound && pid > 0 && !m.seenProcs[pid] &&
		pname != "" && pname != "unknown" {
		m.seenProcs[pid] = true
		m.addAlertLocked("info",
			fmt.Sprintf("New outbound: %s (PID %d) → %s:%d", pname, pid, raddr, rport))
	}
	m.mu.Unlock()

	// Evaluate rules on new outbound flows (after releasing lock — rules may call Block)
	if isNew && outbound {
		_ = m.evaluateRules(pname, raddr, rport)
	}

	// Per-packet DB log is OFF by default to keep netmon.db small.
	// Flows table (one row per session) is sufficient for forensics; enable
	// this only when you need wireshark-style per-packet history.
	if m.logPackets.Load() {
		select {
		case m.dbQueue <- []any{now, src, sport, dst, dport, proto, length, pid, pname, bestDomain}:
			m.dbWrites.Add(1)
		default:
			m.dbDropped.Add(1)
		}
	}
}

/* ---------------- PCAP ---------------- */

func (m *Monitor) StartPCAP(path string) error {
	m.pcapMu.Lock()
	defer m.pcapMu.Unlock()
	if m.pcapWriter != nil {
		return fmt.Errorf("already recording")
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	// We commit to Ethernet for the file header. Most desktop interfaces
	// (Ethernet, Wi-Fi) report LinkTypeEthernet. Non-matching link types
	// (loopback, raw IP, cellular) will be skipped during write to avoid
	// producing a corrupt pcap.
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return err
	}
	m.pcapWriter = w
	m.pcapFile = f
	m.pcapPath = path
	m.pcapLinkType = layers.LinkTypeEthernet
	m.mu.Lock()
	m.addAlertLocked("info", "PCAP recording → "+path)
	m.mu.Unlock()
	return nil
}

func (m *Monitor) StopPCAP() {
	m.pcapMu.Lock()
	defer m.pcapMu.Unlock()
	if m.pcapFile != nil {
		path := m.pcapPath
		m.pcapFile.Close()
		m.pcapWriter = nil
		m.pcapFile = nil
		m.pcapPath = ""
		m.mu.Lock()
		m.addAlertLocked("info", "PCAP saved: "+path)
		m.mu.Unlock()
	}
}

/* ---------------- Blocking ---------------- */

func (m *Monitor) Block(ip string) (bool, string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false, "no ip"
	}
	if net.ParseIP(ip) == nil {
		log.Printf("Block: invalid IP rejected: %q", ip)
		return false, "invalid IP address"
	}
	log.Printf("Block: %s", ip)
	var err error
	if runtime.GOOS == "windows" {
		rname := "NetMon-Block-" + ip
		for _, dir := range []string{"out", "in"} {
			cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+rname+"-"+dir, "dir="+dir, "action=block", "remoteip="+ip)
			if err = cmd.Run(); err != nil {
				return false, err.Error()
			}
		}
	} else {
		for _, args := range [][]string{
			{"iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"},
			{"iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"},
		} {
			if err = exec.Command(args[0], args[1:]...).Run(); err != nil {
				return false, err.Error()
			}
		}
	}
	m.mu.Lock()
	m.blocked[ip] = true
	m.addAlertLocked("info", "Blocked "+ip)
	m.mu.Unlock()
	_, _ = m.db.Exec("INSERT OR REPLACE INTO blocked VALUES(?,?)", ip, time.Now().UnixMilli())
	return true, "blocked"
}

func (m *Monitor) Unblock(ip string) (bool, string) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return false, "invalid IP address"
	}
	if runtime.GOOS == "windows" {
		rname := "NetMon-Block-" + ip
		for _, dir := range []string{"out", "in"} {
			_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+rname+"-"+dir).Run()
		}
	} else {
		_ = exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run()
		_ = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
	}
	m.mu.Lock()
	delete(m.blocked, ip)
	m.addAlertLocked("info", "Unblocked "+ip)
	m.mu.Unlock()
	_, _ = m.db.Exec("DELETE FROM blocked WHERE ip=?", ip)
	return true, "unblocked"
}

func (m *Monitor) BlockProcess(pid int32) (int, int) {
	m.mu.RLock()
	ips := []string{}
	if ps, ok := m.procs[pid]; ok {
		for ip := range ps.RemoteIPs {
			ips = append(ips, ip)
		}
	}
	m.mu.RUnlock()
	ok, fail := 0, 0
	for _, ip := range ips {
		if s, _ := m.Block(ip); s {
			ok++
		} else {
			fail++
		}
	}
	return ok, fail
}

func (m *Monitor) BlockDomain(domain string) (int, string) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return 0, err.Error()
	}
	ok := 0
	for _, ip := range ips {
		if s, _ := m.Block(ip.String()); s {
			ok++
		}
	}
	return ok, ""
}

/* ---------------- Bulk domain block + hosts/AdGuard list import ---------------- */

// domainLineRE matches hostnames inside hosts files and AdGuard ||rules.
// Captures the domain portion only.
var (
	hostsRE   = regexp.MustCompile(`^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::|::1)\s+([A-Za-z0-9._-]+)`)
	adGuardRE = regexp.MustCompile(`^\|\|([A-Za-z0-9._-]+)\^`)
	plainRE   = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,})\s*$`)
)

// parseHostsList extracts unique domain entries from common ad-block formats:
//   - hosts files (StevenBlack, MVPS): "0.0.0.0 ads.example.com"
//   - AdGuard / uBlock filter rules:  "||ads.example.com^"
//   - plain domain-per-line lists
//
// Comment lines (# …) and trivial entries (localhost, broadcasthost) are
// dropped. Returns a stable-ordered slice with duplicates removed.
func parseHostsList(body []byte) []string {
	skip := map[string]bool{
		"localhost": true, "localhost.localdomain": true,
		"broadcasthost": true, "local": true, "ip6-localhost": true,
		"ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
		"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true,
	}
	seen := make(map[string]bool, 1024)
	out := make([]string, 0, 1024)
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || skip[d] || seen[d] {
			return
		}
		seen[d] = true
		out = append(out, d)
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "!"); i == 0 { // AdGuard comment
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := hostsRE.FindStringSubmatch(line); m != nil {
			add(m[1])
			continue
		}
		if m := adGuardRE.FindStringSubmatch(line); m != nil {
			add(m[1])
			continue
		}
		if m := plainRE.FindStringSubmatch(line); m != nil {
			add(m[1])
			continue
		}
	}
	return out
}

// BulkBlock resolves and blocks a slice of domains asynchronously. Progress
// is published via bulkBlockDone / bulkBlockTotal so the UI can show a bar.
// Caps the input to bulkBlockMaxDomains to keep runaway lists from eating
// the box; a 100k host file would otherwise hammer the resolver for hours.
const bulkBlockMaxDomains = 10000

func (m *Monitor) BulkBlock(domains []string) int {
	if len(domains) > bulkBlockMaxDomains {
		domains = domains[:bulkBlockMaxDomains]
	}
	m.bulkBlockTotal.Store(uint64(len(domains)))
	m.bulkBlockDone.Store(0)
	m.bulkBlockMsg.Store("starting bulk block (" + strconv.Itoa(len(domains)) + " domains)")
	go func(list []string) {
		defer m.bulkBlockMsg.Store("idle")
		// Cap concurrency so we don't exhaust the OS DNS resolver / sockets.
		sem := make(chan struct{}, 16)
		var wg sync.WaitGroup
		for _, d := range list {
			d := d
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				_, _ = m.BlockDomain(d)
				m.bulkBlockDone.Add(1)
			}()
		}
		wg.Wait()
		m.bulkBlockMsg.Store(fmt.Sprintf("done (%d/%d)",
			m.bulkBlockDone.Load(), m.bulkBlockTotal.Load()))
	}(domains)
	return len(domains)
}

/* ---------------- System DNS configuration (Windows / netsh) ---------------- */

type ifaceDNSInfo struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers"`
	Source  string   `json:"source"` // "DHCP" or "Static"
}

// dnsStateRE captures IPv4 / IPv6 address lines emitted by `netsh ... show dnsservers`.
var dnsStateRE = regexp.MustCompile(`((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)`)

// DNSState returns the current DNS resolver configuration per usable interface.
// Windows: parses `netsh interface ipv4 show dnsservers`. Other OSes: returns
// a single placeholder entry sourced from /etc/resolv.conf style probing.
func (m *Monitor) DNSState() ([]ifaceDNSInfo, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("DNS config only supported on Windows in this build")
	}
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "dnsservers").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	var infos []ifaceDNSInfo
	var cur *ifaceDNSInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		// New iface block — line starts with "Configuration for interface"
		if strings.HasPrefix(trim, "Configuration for interface") {
			if cur != nil {
				infos = append(infos, *cur)
			}
			name := strings.TrimSpace(strings.Trim(strings.TrimPrefix(trim,
				"Configuration for interface"), " \""))
			cur = &ifaceDNSInfo{Name: name}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.Contains(trim, "configured through DHCP") {
			cur.Source = "DHCP"
		} else if strings.Contains(trim, "Statically Configured DNS Servers") {
			cur.Source = "Static"
		} else if strings.Contains(trim, "None") && cur.Source == "" {
			cur.Source = "None"
		}
		if ip := dnsStateRE.FindString(trim); ip != "" {
			// Skip lines like "Register with which suffix" that don't carry an IP
			cur.Servers = append(cur.Servers, ip)
		}
	}
	if cur != nil {
		infos = append(infos, *cur)
	}
	return infos, nil
}

// DNSSet replaces an interface's DNS configuration with the given primary +
// optional secondary resolvers. Empty primary = no-op. Windows only.
func (m *Monitor) DNSSet(iface, primary, secondary string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("DNS config only supported on Windows in this build")
	}
	iface = strings.TrimSpace(iface)
	primary = strings.TrimSpace(primary)
	secondary = strings.TrimSpace(secondary)
	if iface == "" {
		return fmt.Errorf("interface name required")
	}
	if net.ParseIP(primary) == nil {
		return fmt.Errorf("invalid primary DNS: %q", primary)
	}
	if secondary != "" && net.ParseIP(secondary) == nil {
		return fmt.Errorf("invalid secondary DNS: %q", secondary)
	}
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+iface, "static", primary, "primary", "validate=no")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	if secondary != "" {
		cmd = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
			"name="+iface, secondary, "index=2", "validate=no")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	m.addAlertLocked("info", fmt.Sprintf("DNS for %q set to %s / %s", iface, primary, secondary))
	return nil
}

// DNSReset restores the interface to DHCP-supplied DNS resolvers.
func (m *Monitor) DNSReset(iface string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("DNS config only supported on Windows in this build")
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return fmt.Errorf("interface name required")
	}
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+iface, "source=dhcp")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	m.addAlertLocked("info", fmt.Sprintf("DNS for %q reset to DHCP", iface))
	return nil
}

func (m *Monitor) SetBPFFilter(s string) {
	m.bpfMu.Lock()
	m.bpfFilter = s
	m.bpfMu.Unlock()
}

func (m *Monitor) GetBPFFilter() string {
	m.bpfMu.RLock()
	defer m.bpfMu.RUnlock()
	return m.bpfFilter
}

func (m *Monitor) ClearStats() {
	m.mu.Lock()
	m.flows = make(map[FlowKey]*Flow)
	m.procs = make(map[int32]*ProcStat)
	m.domains = make(map[string]int)
	m.totalSent = 0
	m.totalRecv = 0
	m.pubSent = 0
	m.pubRecv = 0
	m.totalPkts = 0
	m.curSent = 0
	m.curRecv = 0
	m.curBucket = time.Now().Unix()
	m.lastBwAlertTS = 0
	m.bwHistory = m.bwHistory[:0]
	m.alerts = m.alerts[:0]
	m.seenProcs = make(map[int32]bool)
	m.mu.Unlock()
}

/* ---------------- Push (broadcast) ---------------- */

func (m *Monitor) subscribe() chan []byte {
	ch := make(chan []byte, 32)
	m.subsMu.Lock()
	m.subs[ch] = true
	m.subsMu.Unlock()
	return ch
}

func (m *Monitor) unsubscribe(ch chan []byte) {
	m.subsMu.Lock()
	delete(m.subs, ch)
	m.subsMu.Unlock()
	close(ch)
}

func (m *Monitor) broadcast(msg []byte) {
	m.subsMu.RLock()
	defer m.subsMu.RUnlock()
	for ch := range m.subs {
		select {
		case ch <- msg:
		default:
			// slow client, drop
		}
	}
}

func (m *Monitor) pushStatus() {
	payload := m.statusPayload()
	envelope := map[string]any{"type": "status", "data": payload}
	b, _ := json.Marshal(envelope)
	m.broadcast(b)
}

/* ---------------- Snapshot for API/WS ---------------- */

func (m *Monitor) statusPayload() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	histCopy := make([]BWPoint, len(m.bwHistory))
	copy(histCopy, m.bwHistory)
	return map[string]any{
		"running":               m.running.Load(),
		"paused":                m.paused.Load(),
		"iface":                 m.captureIface,
		"total_sent":            m.totalSent,
		"total_recv":            m.totalRecv,
		"public_sent":           m.pubSent,
		"public_recv":           m.pubRecv,
		"total_packets":         m.totalPkts,
		"active_flows":          len(m.flows),
		"processes":             len(m.procs),
		"domains":               len(m.domains),
		"blocked":               len(m.blocked),
		"bw_history":            histCopy,
		"pcap_recording":        m.pcapWriter != nil,
		"pcap_path":             m.pcapPath,
		"alert_new_process":     m.alertNewProc.Load(),
		"alert_bw_threshold_mb": float64(m.alertBwThresh.Load()) / (1024 * 1024),
		"geo_enabled":           m.geoEnabled.Load(),
		"bpf_filter":            m.GetBPFFilter(),
		"rules_count":           len(m.rules),
		"db_writes":             m.dbWrites.Load(),
		"db_dropped":            m.dbDropped.Load(),
		"flows_persisted":       m.flowsPersisted.Load(),
		"debug_enabled":         m.debugMode.Load(),
		"bulk_block_total":      m.bulkBlockTotal.Load(),
		"bulk_block_done":       m.bulkBlockDone.Load(),
		"bulk_block_msg":        m.bulkBlockMsg.Load(),
	}
}

func (m *Monitor) GetConnections(limit int, q string) []map[string]any {
	q = strings.ToLower(strings.TrimSpace(q))
	// Build rows entirely INSIDE the read lock so Flow fields can't mutate
	// out from under us. We then sort/filter the copies.
	m.mu.RLock()
	rows := make([]map[string]any, 0, len(m.flows))
	for k, f := range m.flows {
		row := map[string]any{
			"proto":     k.Proto,
			"laddr":     k.LAddr,
			"lport":     k.LPort,
			"raddr":     k.RAddr,
			"rport":     k.RPort,
			"domain":    f.Domain,
			"sni":       f.SNI,
			"http_host": f.HTTPHost,
			"pid":       f.PID,
			"process":   f.Name,
			"sent":      f.Sent,
			"recv":      f.Recv,
			"rate_sent": f.RateSent,
			"rate_recv": f.RateRecv,
			"first":     f.First,
			"last":      f.Last,
			"blocked":   m.blocked[k.RAddr],
			"private":   isPrivateIP(k.RAddr),
		}
		rows = append(rows, row)
	}
	m.mu.RUnlock()

	// Enrich with GeoIP outside the main lock
	m.geoMu.RLock()
	for _, row := range rows {
		ip, _ := row["raddr"].(string)
		if g := m.geoCache[ip]; g != nil && g.CountryCode != "" {
			row["country"] = g.Country
			row["country_code"] = g.CountryCode
			row["city"] = g.City
			row["isp"] = g.ISP
			row["org"] = g.Org
			row["asn"] = g.ASN
			row["threat"] = g.Threat
		}
	}
	m.geoMu.RUnlock()

	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["last"].(int64) > rows[j]["last"].(int64)
	})

	out := make([]map[string]any, 0, limit)
	for _, row := range rows {
		if q != "" {
			text := strings.ToLower(fmt.Sprintf("%v", row))
			if !strings.Contains(text, q) {
				continue
			}
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (m *Monitor) GetProcesses(limit int, q string) []map[string]any {
	q = strings.ToLower(strings.TrimSpace(q))
	m.mu.RLock()
	rows := make([]map[string]any, 0, len(m.procs))
	for pid, ps := range m.procs {
		rows = append(rows, map[string]any{
			"pid":        pid,
			"name":       ps.Name,
			"sent":       ps.Sent,
			"recv":       ps.Recv,
			"rate_sent":  ps.RateSent,
			"rate_recv":  ps.RateRecv,
			"conns":      len(ps.Conns),
			"remote_ips": len(ps.RemoteIPs),
		})
	}
	m.mu.RUnlock()

	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["sent"].(uint64)+rows[i]["recv"].(uint64) >
			rows[j]["sent"].(uint64)+rows[j]["recv"].(uint64)
	})

	out := make([]map[string]any, 0, limit)
	for _, row := range rows {
		if q != "" {
			text := strings.ToLower(fmt.Sprintf("%v", row))
			if !strings.Contains(text, q) {
				continue
			}
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (m *Monitor) GetDomains(limit int, q string) []map[string]any {
	q = strings.ToLower(strings.TrimSpace(q))
	m.mu.RLock()
	type kv struct {
		d string
		h int
	}
	items := make([]kv, 0, len(m.domains))
	for d, h := range m.domains {
		items = append(items, kv{d, h})
	}
	m.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].h > items[j].h })
	out := make([]map[string]any, 0, limit)
	for _, it := range items {
		if q != "" && !strings.Contains(strings.ToLower(it.d), q) {
			continue
		}
		out = append(out, map[string]any{"domain": it.d, "hits": it.h})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (m *Monitor) GetBlocked() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.blocked))
	for ip := range m.blocked {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func (m *Monitor) GetAlerts() []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Alert, len(m.alerts))
	copy(out, m.alerts)
	return out
}

/* ---------------- Helpers ---------------- */

func isPrivateIP(ip string) bool {
	if ip == "" {
		return true
	}
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsPrivate() {
		return true
	}
	return false
}

func fmtBytes(n uint64) string {
	f := float64(n)
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

/* ---------------- HTTP Server ---------------- */

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

type Server struct {
	mon *Monitor
}

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.serveIndex)
	mux.HandleFunc("/api/interfaces", s.apiInterfaces)
	mux.HandleFunc("/api/status", s.apiStatus)
	mux.HandleFunc("/api/connections", s.apiConnections)
	mux.HandleFunc("/api/processes", s.apiProcesses)
	mux.HandleFunc("/api/domains", s.apiDomains)
	mux.HandleFunc("/api/blocked", s.apiBlocked)
	mux.HandleFunc("/api/alerts", s.apiAlerts)
	mux.HandleFunc("/api/history", s.apiHistory)
	mux.HandleFunc("/api/capture/start", s.apiStart)
	mux.HandleFunc("/api/capture/stop", s.apiStop)
	mux.HandleFunc("/api/capture/pause", s.apiPause)
	mux.HandleFunc("/api/capture/bpf", s.apiBPF)
	mux.HandleFunc("/api/clear", s.apiClear)
	mux.HandleFunc("/api/block", s.apiBlock)
	mux.HandleFunc("/api/unblock", s.apiUnblock)
	mux.HandleFunc("/api/pcap/start", s.apiPcapStart)
	mux.HandleFunc("/api/pcap/stop", s.apiPcapStop)
	mux.HandleFunc("/api/alerts/config", s.apiAlertCfg)
	mux.HandleFunc("/api/rules", s.apiRules)
	mux.HandleFunc("/api/rules/add", s.apiRulesAdd)
	mux.HandleFunc("/api/rules/delete", s.apiRulesDelete)
	mux.HandleFunc("/api/rules/toggle", s.apiRulesToggle)
	mux.HandleFunc("/api/settings", s.apiSettings)
	mux.HandleFunc("/ws", s.wsHandler)
	mux.HandleFunc("/favicon.ico", s.serveFavicon)
	mux.HandleFunc("/favicon.svg", s.serveFavicon)
	mux.HandleFunc("/api/debug", s.apiDebug)
	mux.HandleFunc("/api/flows-history", s.apiFlowsHistory)
	mux.HandleFunc("/api/maintenance", s.apiMaintenance)
	mux.HandleFunc("/api/dns/state", s.apiDNSState)
	mux.HandleFunc("/api/dns/set", s.apiDNSSet)
	mux.HandleFunc("/api/dns/reset", s.apiDNSReset)
	mux.HandleFunc("/api/block/bulk", s.apiBlockBulk)
	mux.HandleFunc("/api/block/import", s.apiBlockImport)
}

/* ---------------- DNS + ad-block list handlers ---------------- */

func (s *Server) apiDNSState(w http.ResponseWriter, _ *http.Request) {
	infos, err := s.mon.DNSState()
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error(), "interfaces": []any{}})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "interfaces": infos})
}

func (s *Server) apiDNSSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface     string `json:"iface"`
		Primary   string `json:"primary"`
		Secondary string `json:"secondary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": "bad request: " + err.Error()})
		return
	}
	if err := s.mon.DNSSet(req.Iface, req.Primary, req.Secondary); err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "msg": "DNS updated"})
}

func (s *Server) apiDNSReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface string `json:"iface"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.mon.DNSReset(req.Iface); err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "msg": "DNS reset to DHCP"})
}

func (s *Server) apiBlockBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains []string `json:"domains"`
		Text    string   `json:"text"` // optional: textarea paste
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	if req.Text != "" {
		req.Domains = append(req.Domains, parseHostsList([]byte(req.Text))...)
	}
	// Dedupe + drop blanks
	seen := make(map[string]bool, len(req.Domains))
	clean := make([]string, 0, len(req.Domains))
	for _, d := range req.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		clean = append(clean, d)
	}
	if len(clean) == 0 {
		writeJSON(w, map[string]any{"ok": false, "msg": "no domains parsed"})
		return
	}
	queued := s.mon.BulkBlock(clean)
	writeJSON(w, map[string]any{"ok": true, "queued": queued})
}

func (s *Server) apiBlockImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		writeJSON(w, map[string]any{"ok": false, "msg": "URL must start with http:// or https://"})
		return
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(req.URL)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": "fetch failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		writeJSON(w, map[string]any{"ok": false, "msg": "HTTP " + resp.Status})
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024)) // 16 MB cap
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": "read body: " + err.Error()})
		return
	}
	domains := parseHostsList(body)
	if len(domains) == 0 {
		writeJSON(w, map[string]any{"ok": false, "msg": "no domains parsed from list"})
		return
	}
	queued := s.mon.BulkBlock(domains)
	writeJSON(w, map[string]any{
		"ok":     true,
		"parsed": len(domains),
		"queued": queued,
	})
}

// apiFlowsHistory returns persisted enriched flows from the flows table.
func (s *Server) apiFlowsHistory(w http.ResponseWriter, r *http.Request) {
	seconds := 3600
	if v := r.URL.Query().Get("seconds"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			seconds = n
		}
	}
	limit := 1000
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10000 {
			limit = n
		}
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	since := time.Now().UnixMilli() - int64(seconds)*1000
	args := []any{since}
	where := "last_ts > ?"
	if q != "" {
		where += " AND (process LIKE ? OR domain LIKE ? OR raddr LIKE ? OR sni LIKE ? OR http_host LIKE ? OR country LIKE ? OR asn LIKE ?)"
		like := "%" + q + "%"
		args = append(args, like, like, like, like, like, like, like)
	}
	args = append(args, limit)
	rows, err := s.mon.db.Query(`SELECT first_ts,last_ts,proto,laddr,lport,raddr,rport,pid,process,
		domain,sni,http_host,country_code,country,asn,isp,sent,recv,threat,blocked
		FROM flows WHERE `+where+` ORDER BY last_ts DESC LIMIT ?`, args...)
	if err != nil {
		writeJSON(w, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			ft, lt, sent, recv      int64
			lport, rport, pid       int
			threat, blockedI        int
			proto, laddr, raddr     string
			process, domain, sni    string
			httpHost                string
			cc, country, asn, isp   string
		)
		if err := rows.Scan(&ft, &lt, &proto, &laddr, &lport, &raddr, &rport,
			&pid, &process, &domain, &sni, &httpHost, &cc, &country, &asn, &isp,
			&sent, &recv, &threat, &blockedI); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"first_ts": ft, "last_ts": lt, "proto": proto,
			"laddr": laddr, "lport": lport, "raddr": raddr, "rport": rport,
			"pid": pid, "process": process, "domain": domain,
			"sni": sni, "http_host": httpHost,
			"country_code": cc, "country": country, "asn": asn, "isp": isp,
			"sent": sent, "recv": recv, "threat": threat, "blocked": blockedI == 1,
		})
	}
	writeJSON(w, out)
}

func (s *Server) apiDebug(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Enabled != nil {
			s.mon.debugMode.Store(*req.Enabled)
			log.Printf("debug mode set: %v", *req.Enabled)
		}
		writeJSON(w, map[string]any{"ok": true, "enabled": s.mon.debugMode.Load()})
		return
	}
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	lines := debugRing.Snapshot()
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	writeJSON(w, map[string]any{
		"enabled": s.mon.debugMode.Load(),
		"lines":   lines,
	})
}

func (s *Server) serveFavicon(w http.ResponseWriter, _ *http.Request) {
	const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>` +
		`<rect width='32' height='32' rx='6' fill='#0d1117'/>` +
		`<circle cx='16' cy='16' r='4' fill='#58a6ff'/>` +
		`<circle cx='16' cy='16' r='9' fill='none' stroke='#3fb950' stroke-width='2'/>` +
		`<circle cx='16' cy='16' r='13' fill='none' stroke='#d29922' stroke-width='1.5' opacity='.7'/>` +
		`</svg>`
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(svg))
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTMLBytes)
}

func (s *Server) apiInterfaces(w http.ResponseWriter, _ *http.Request) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		writeJSON(w, map[string]any{"interfaces": []string{"(all)"}, "error": err.Error()})
		return
	}
	out := []string{"(all)"}
	for _, d := range devs {
		label := d.Name
		if d.Description != "" {
			label = d.Description + "  [" + d.Name + "]"
		}
		out = append(out, label)
	}
	writeJSON(w, map[string]any{"interfaces": out})
}

func (s *Server) apiStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.mon.statusPayload())
}

func (s *Server) apiConnections(w http.ResponseWriter, r *http.Request) {
	limit := parseInt(r.URL.Query().Get("limit"), 500)
	writeJSON(w, s.mon.GetConnections(limit, r.URL.Query().Get("q")))
}

func (s *Server) apiProcesses(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mon.GetProcesses(parseInt(r.URL.Query().Get("limit"), 300),
		r.URL.Query().Get("q")))
}

func (s *Server) apiDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mon.GetDomains(parseInt(r.URL.Query().Get("limit"), 500),
		r.URL.Query().Get("q")))
}

func (s *Server) apiBlocked(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"ips": s.mon.GetBlocked()})
}

func (s *Server) apiAlerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.mon.GetAlerts())
}

func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	secs := parseInt(r.URL.Query().Get("seconds"), 3600)
	q := strings.ToLower(r.URL.Query().Get("q"))
	limit := parseInt(r.URL.Query().Get("limit"), 5000)
	since := time.Now().UnixMilli() - int64(secs)*1000

	rows, err := s.mon.db.Query(
		"SELECT ts,proto,src,sport,dst,dport,length,pid,pname,domain "+
			"FROM packets WHERE ts>=? ORDER BY ts DESC LIMIT ?", since, limit)
	if err != nil {
		writeJSON(w, []any{})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts int64
		var proto, src, dst, pname, domain string
		var sport, dport, length int
		var pid int32
		if err := rows.Scan(&ts, &proto, &src, &sport, &dst, &dport, &length, &pid, &pname, &domain); err != nil {
			continue
		}
		row := map[string]any{
			"ts": ts, "proto": proto, "src": src, "sport": sport,
			"dst": dst, "dport": dport, "length": length,
			"pid": pid, "process": pname, "domain": domain,
		}
		if q != "" {
			if !strings.Contains(strings.ToLower(fmt.Sprintf("%v", row)), q) {
				continue
			}
		}
		out = append(out, row)
	}
	writeJSON(w, out)
}

type startReq struct {
	Iface string `json:"iface"`
}

func (s *Server) apiStart(w http.ResponseWriter, r *http.Request) {
	var req startReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	// If frontend sent "Description [name]", strip to bracketed name
	iface := req.Iface
	if i := strings.LastIndex(iface, "["); i != -1 {
		if j := strings.LastIndex(iface, "]"); j > i {
			iface = iface[i+1 : j]
		}
	}
	err := s.mon.Start(iface)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "iface": iface})
}

func (s *Server) apiStop(w http.ResponseWriter, _ *http.Request) {
	s.mon.Stop()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) apiPause(w http.ResponseWriter, _ *http.Request) {
	p := !s.mon.paused.Load()
	s.mon.paused.Store(p)
	writeJSON(w, map[string]any{"paused": p})
}

func (s *Server) apiClear(w http.ResponseWriter, _ *http.Request) {
	s.mon.ClearStats()
	writeJSON(w, map[string]any{"ok": true})
}

type blockReq struct {
	IP     string `json:"ip,omitempty"`
	Domain string `json:"domain,omitempty"`
	PID    int32  `json:"pid,omitempty"`
}

func (s *Server) apiBlock(w http.ResponseWriter, r *http.Request) {
	var req blockReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.IP != "" {
		ok, msg := s.mon.Block(req.IP)
		writeJSON(w, map[string]any{"ok": ok, "msg": msg})
		return
	}
	if req.Domain != "" {
		n, errStr := s.mon.BlockDomain(req.Domain)
		msg := fmt.Sprintf("blocked %d IPs for %s", n, req.Domain)
		if errStr != "" {
			msg = errStr
		}
		writeJSON(w, map[string]any{"ok": errStr == "", "count": n, "msg": msg})
		return
	}
	if req.PID != 0 {
		ok, fail := s.mon.BlockProcess(req.PID)
		writeJSON(w, map[string]any{"ok": true, "blocked": ok, "failed": fail,
			"msg": fmt.Sprintf("blocked %d IPs (%d failed)", ok, fail)})
		return
	}
	http.Error(w, "ip, domain, or pid required", 400)
}

type unblockReq struct {
	IP string `json:"ip"`
}

func (s *Server) apiUnblock(w http.ResponseWriter, r *http.Request) {
	var req unblockReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	ok, msg := s.mon.Unblock(req.IP)
	writeJSON(w, map[string]any{"ok": ok, "msg": msg})
}

type pcapReq struct {
	Path string `json:"path,omitempty"`
}

func (s *Server) apiPcapStart(w http.ResponseWriter, r *http.Request) {
	var req pcapReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Path == "" {
		req.Path = fmt.Sprintf("netmon-%s.pcap", time.Now().Format("20060102-150405"))
	}
	err := s.mon.StartPCAP(req.Path)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "path": req.Path, "msg": req.Path})
}

func (s *Server) apiPcapStop(w http.ResponseWriter, _ *http.Request) {
	s.mon.StopPCAP()
	writeJSON(w, map[string]any{"ok": true})
}

type alertCfgReq struct {
	NewProcess    bool    `json:"new_process"`
	BwThresholdMB float64 `json:"bw_threshold_mb"`
}

func (s *Server) apiAlertCfg(w http.ResponseWriter, r *http.Request) {
	var req alertCfgReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mon.alertNewProc.Store(req.NewProcess)
	th := uint64(0)
	if req.BwThresholdMB > 0 {
		th = uint64(req.BwThresholdMB * 1024 * 1024)
	}
	s.mon.alertBwThresh.Store(th)
	writeJSON(w, map[string]any{"ok": true})
}

type bpfReq struct {
	Filter string `json:"filter"`
}

func (s *Server) apiBPF(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"filter": s.mon.GetBPFFilter()})
		return
	}
	var req bpfReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mon.SetBPFFilter(strings.TrimSpace(req.Filter))
	writeJSON(w, map[string]any{"ok": true, "filter": s.mon.GetBPFFilter(),
		"note": "Filter applies on next capture start"})
}

func (s *Server) apiRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.mon.ListRules())
}

func (s *Server) apiRulesAdd(w http.ResponseWriter, r *http.Request) {
	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "bad JSON", 400)
		return
	}
	rule.Enabled = true
	added, err := s.mon.AddRule(rule)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "rule": added})
}

type ruleIDReq struct {
	ID      int64 `json:"id"`
	Enabled bool  `json:"enabled,omitempty"`
}

func (s *Server) apiRulesDelete(w http.ResponseWriter, r *http.Request) {
	var req ruleIDReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.mon.DeleteRule(req.ID); err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) apiRulesToggle(w http.ResponseWriter, r *http.Request) {
	var req ruleIDReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.mon.ToggleRule(req.ID, req.Enabled); err != nil {
		writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

type settingsReq struct {
	GeoEnabled           *bool  `json:"geo_enabled,omitempty"`
	LogPackets           *bool  `json:"log_packets,omitempty"`
	RetentionPacketDays  *int64 `json:"retention_packet_days,omitempty"`
	RetentionArchiveDays *int64 `json:"retention_archive_days,omitempty"`
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{
			"geo_enabled":            s.mon.geoEnabled.Load(),
			"log_packets":            s.mon.logPackets.Load(),
			"retention_packet_days":  s.mon.retentionPacketDays.Load(),
			"retention_archive_days": s.mon.retentionArchiveDays.Load(),
			"bpf_filter":             s.mon.GetBPFFilter(),
		})
		return
	}
	var req settingsReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.GeoEnabled != nil {
		s.mon.geoEnabled.Store(*req.GeoEnabled)
	}
	if req.LogPackets != nil {
		s.mon.logPackets.Store(*req.LogPackets)
		log.Printf("log_packets = %v", *req.LogPackets)
	}
	if req.RetentionPacketDays != nil {
		v := *req.RetentionPacketDays
		if v < 0 {
			v = 0
		}
		s.mon.retentionPacketDays.Store(v)
		log.Printf("retention_packet_days = %d", v)
	}
	if req.RetentionArchiveDays != nil {
		v := *req.RetentionArchiveDays
		if v < 0 {
			v = 0
		}
		s.mon.retentionArchiveDays.Store(v)
		log.Printf("retention_archive_days = %d", v)
	}
	writeJSON(w, map[string]any{"ok": true})
}

// apiMaintenance runs an on-demand prune and/or VACUUM.
func (s *Server) apiMaintenance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // "prune" | "vacuum"
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	switch req.Action {
	case "prune":
		n := s.mon.runRetention(true)
		writeJSON(w, map[string]any{"ok": true, "pruned": n})
	case "vacuum":
		if _, err := s.mon.db.Exec("VACUUM"); err != nil {
			writeJSON(w, map[string]any{"ok": false, "msg": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeJSON(w, map[string]any{"ok": false, "msg": "action must be 'prune' or 'vacuum'"})
	}
}

func (s *Server) wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Configure read side: pong handler resets the deadline.
	conn.SetReadLimit(1 << 16)
	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	writeJSONMsg := func(v any) error {
		conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return conn.WriteMessage(websocket.TextMessage, b)
	}

	ch := s.mon.subscribe()
	defer s.mon.unsubscribe(ch)

	// Initial snapshot
	if err := writeJSONMsg(map[string]any{"type": "status", "data": s.mon.statusPayload()}); err != nil {
		return
	}
	if err := writeJSONMsg(map[string]any{"type": "flows", "data": s.mon.GetConnections(500, "")}); err != nil {
		return
	}

	flowTick := time.NewTicker(time.Second)
	defer flowTick.Stop()
	pingTick := time.NewTicker(wsPingPeriod)
	defer pingTick.Stop()

	// Reader goroutine: detects disconnect / handles pongs
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case msg := <-ch:
			conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-flowTick.C:
			if err := writeJSONMsg(map[string]any{
				"type": "flows", "data": s.mon.GetConnections(500, ""),
			}); err != nil {
				return
			}
		case <-pingTick.C:
			conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

/* ---------------- Main ---------------- */

// rotatingFile is an io.Writer that rotates the underlying log file when it
// reaches maxBytes, gzipping the previous file and keeping the last `keep`
// archives (netmon.log.1.gz, netmon.log.2.gz, …). Safe for concurrent use.
type rotatingFile struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	written  int64
	maxBytes int64
	keep     int
}

func newRotatingFile(path string, maxBytes int64, keep int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	r.f = f
	if st, err := f.Stat(); err == nil {
		r.written = st.Size()
	}
	return nil
}
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.written += int64(n)
	if r.written >= r.maxBytes {
		_ = r.rotateLocked()
	}
	return n, err
}
func (r *rotatingFile) rotateLocked() error {
	_ = r.f.Close()
	r.f = nil
	r.written = 0
	// Shift archives: .keep-1.gz → drop, .i.gz → .(i+1).gz
	for i := r.keep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d.gz", r.path, i)
		to := fmt.Sprintf("%s.%d.gz", r.path, i+1)
		if i == r.keep-1 {
			_ = os.Remove(to)
		}
		_ = os.Rename(from, to)
	}
	// Gzip current → .1.gz, then re-open empty.
	if err := gzipFile(r.path, r.path+".1.gz"); err != nil {
		log.Printf("log rotation gzip failed: %v", err)
	}
	_ = os.Remove(r.path)
	return r.open()
}
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		return err
	}
	return gz.Close()
}

// logRing keeps the last N log lines in memory for the /api/debug endpoint.
type logRing struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func (r *logRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, strings.TrimRight(string(p), "\n"))
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
	return len(p), nil
}
func (r *logRing) Snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

var debugRing = &logRing{max: 2000}

func setupLogging(path string, debug bool) (io.Closer, error) {
	rot, err := newRotatingFile(path, 5*1024*1024, 5) // 5MB, keep 5 archives
	if err != nil {
		return nil, err
	}
	// stdout + rotating file + in-memory ring (for /api/debug)
	log.SetOutput(io.MultiWriter(os.Stdout, rot, debugRing))
	flags := log.LstdFlags | log.Lmsgprefix
	if debug {
		flags |= log.Lshortfile | log.Lmicroseconds
	}
	log.SetFlags(flags)
	log.Printf("=== NetMon log started (debug=%v) ===", debug)
	return io.NopCloser(strings.NewReader("")), nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18472", "listen address (host:port)")
	logPath := flag.String("log", "netmon.log", "path to log file ('-' to skip file)")
	debug := flag.Bool("debug", true, "enable debug-level logging (file+line, microseconds)")
	background := flag.Bool("background", false, "hide console window (Windows) — runs silently in tray-style mode")
	autostart := flag.Bool("autostart", true, "start capture immediately on launch (no need to click ▶ Start)")
	iface := flag.String("iface", "(all)", "default interface to capture on when -autostart is set")
	openBrowser := flag.Bool("open", false, "open default web browser to the UI on launch")
	flag.Parse()

	if *logPath != "-" {
		f, err := setupLogging(*logPath, *debug)
		if err != nil {
			fmt.Printf("log setup failed: %v (continuing to stdout only)\n", err)
		} else {
			defer f.Close()
		}
	}

	if runtime.GOOS == "windows" {
		log.Println("NOTE: Windows requires Administrator and Npcap installed.")
	} else if os.Geteuid() != 0 {
		log.Println("NOTE: not running as root - capture/iptables may fail.")
	}

	mon, err := NewMonitor()
	if err != nil {
		log.Fatal(err)
	}
	mon.debugMode.Store(*debug)
	srv := &Server{mon: mon}

	mux := http.NewServeMux()
	srv.routes(mux)

	if *autostart {
		if err := mon.Start(*iface); err != nil {
			log.Printf("autostart failed: %v", err)
		} else {
			log.Printf("autostart: capture running on %q", *iface)
		}
	}

	if *background {
		hideConsoleWindow()
		log.Println("background mode: console hidden, see netmon.log for output")
	}

	// Bind the listener BEFORE optionally opening a browser, so the browser
	// doesn't race the server and land on a "refused connection" page.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	log.Printf("listening on http://%s", ln.Addr())
	fmt.Printf("\nNetMon (Go) → http://%s\n\n", ln.Addr())

	if *openBrowser {
		go openURL("http://" + ln.Addr().String())
	}

	if err := http.Serve(ln, mux); err != nil {
		log.Fatal(err)
	}
}

// openURL launches the default browser. Best-effort; failures logged only.
func openURL(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd, args = "open", []string{url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	if err := exec.Command(cmd, args...).Start(); err != nil {
		log.Printf("openURL: %v", err)
	}
}
