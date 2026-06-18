// Package main - Высокопроизводительный движок сигнатурного анализа
// Разработан для микросервисной архитектуры адаптивной фильтрации
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/mattn/go-sqlite3"
)

// Signature представляет структуру сигнатуры для обнаружения угроз
type Signature struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"` // exact, regex, content
	Protocol    string `json:"protocol"`     // TCP, UDP, ICMP, ALL
	Severity    int    `json:"severity"`
	Description string `json:"description"`
	compiled    *regexp.Regexp
}

// ThreatEvent представляет событие обнаруженной угрозы
type ThreatEvent struct {
	SignatureID    int       `json:"signature_id"`
	SignatureName  string    `json:"signature_name"`
	Timestamp      time.Time `json:"timestamp"`
	SourceIP       string    `json:"source_ip"`
	DestIP         string    `json:"dest_ip"`
	SourcePort     uint16    `json:"source_port"`
	DestPort       uint16    `json:"dest_port"`
	Protocol       string    `json:"protocol"`
	MatchedContent string    `json:"matched_content"`
	Confidence     float64   `json:"confidence"`
	ThreatType     string    `json:"threat_type"`
	Severity       int       `json:"severity"`
}

// Config представляет конфигурацию системы
type Config struct {
	Interface      string `json:"interface"`
	DatabasePath   string `json:"database_path"`
	APIPort        int    `json:"api_port"`
	WorkerCount    int    `json:"worker_count"`
	BufferSize     int    `json:"buffer_size"`
	SYNThreshold   int    `json:"syn_threshold"`
	HTTPThreshold  int    `json:"http_threshold"`
	UDPThreshold   int    `json:"udp_threshold"`
	TimeWindowSec  int    `json:"time_window_sec"`
	EnableBlocking bool   `json:"enable_blocking"`
}

// RateLimiter для обнаружения DoS атак
type RateLimiter struct {
	mu       sync.RWMutex
	counters map[string]*PacketCounter
	window   time.Duration
}

type PacketCounter struct {
	count     int64
	lastReset time.Time
}

// SignatureEngine - основной движок анализа
type SignatureEngine struct {
	config       *Config
	signatures   []Signature
	sigMutex     sync.RWMutex
	db           *sql.DB
	rateLimiter  *RateLimiter
	threatChan   chan ThreatEvent
	packetChan   chan gopacket.Packet
	stats        *EngineStats
	ctx          context.Context
	cancel       context.CancelFunc
	blockedIPs   sync.Map
	eventCache   *EventCache
}

// EngineStats - статистика работы движка
type EngineStats struct {
	PacketsProcessed uint64
	ThreatsDetected  uint64
	PacketsDropped   uint64
	StartTime        time.Time
}

// EventCache для предотвращения дублирования событий
type EventCache struct {
	mu     sync.RWMutex
	events map[string]time.Time
	ttl    time.Duration
}

// NewEventCache создает новый кэш событий
func NewEventCache(ttl time.Duration) *EventCache {
	ec := &EventCache{
		events: make(map[string]time.Time),
		ttl:    ttl,
	}
	go ec.cleanup()
	return ec
}

func (ec *EventCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		ec.mu.Lock()
		now := time.Now()
		for key, ts := range ec.events {
			if now.Sub(ts) > ec.ttl {
				delete(ec.events, key)
			}
		}
		ec.mu.Unlock()
	}
}

func (ec *EventCache) IsDuplicate(key string) bool {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	if _, exists := ec.events[key]; exists {
		return true
	}
	ec.events[key] = time.Now()
	return false
}

// NewRateLimiter создает новый ограничитель скорости
func NewRateLimiter(window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		counters: make(map[string]*PacketCounter),
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, counter := range rl.counters {
			if now.Sub(counter.lastReset) > rl.window*2 {
				delete(rl.counters, key)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Increment(key string) int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.counters[key]

	if !exists || now.Sub(counter.lastReset) > rl.window {
		rl.counters[key] = &PacketCounter{count: 1, lastReset: now}
		return 1
	}

	counter.count++
	return counter.count
}

func (rl *RateLimiter) GetCount(key string) int64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if counter, exists := rl.counters[key]; exists {
		if time.Now().Sub(counter.lastReset) <= rl.window {
			return counter.count
		}
	}
	return 0
}

// LoadConfig загружает конфигурацию
func LoadConfig(path string) (*Config, error) {
	config := &Config{
		Interface:      "eth0",
		DatabasePath:   "signatures.db",
		APIPort:        8080,
		WorkerCount:    4,
		BufferSize:     10000,
		SYNThreshold:   50,
		HTTPThreshold:  100,
		UDPThreshold:   200,
		TimeWindowSec:  60,
		EnableBlocking: false,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Конфигурационный файл не найден, используются значения по умолчанию: %v", err)
		return config, nil
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("ошибка парсинга конфигурации: %v", err)
	}

	return config, nil
}

// NewSignatureEngine создает новый движок
func NewSignatureEngine(config *Config) (*SignatureEngine, error) {
	ctx, cancel := context.WithCancel(context.Background())

	db, err := sql.Open("sqlite3", config.DatabasePath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ошибка подключения к БД: %v", err)
	}

	engine := &SignatureEngine{
		config:      config,
		db:          db,
		rateLimiter: NewRateLimiter(time.Duration(config.TimeWindowSec) * time.Second),
		threatChan:  make(chan ThreatEvent, 1000),
		packetChan:  make(chan gopacket.Packet, config.BufferSize),
		stats:       &EngineStats{StartTime: time.Now()},
		ctx:         ctx,
		cancel:      cancel,
		eventCache:  NewEventCache(5 * time.Minute),
	}

	if err := engine.initDB(); err != nil {
		cancel()
		return nil, err
	}

	if err := engine.LoadSignatures(); err != nil {
		cancel()
		return nil, err
	}

	return engine, nil
}

func (e *SignatureEngine) initDB() error {
	_, err := e.db.Exec(`
		CREATE TABLE IF NOT EXISTS signatures (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			pattern TEXT NOT NULL,
			pattern_type TEXT CHECK(pattern_type IN ('exact', 'regex', 'content')),
			protocol TEXT CHECK(protocol IN ('TCP', 'UDP', 'ICMP', 'ALL')),
			severity INTEGER CHECK(severity BETWEEN 1 AND 10),
			description TEXT,
			enabled BOOLEAN DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

// LoadSignatures загружает сигнатуры из БД
func (e *SignatureEngine) LoadSignatures() error {
	rows, err := e.db.Query(`
		SELECT id, name, pattern, pattern_type, protocol, severity, description
		FROM signatures WHERE enabled = 1
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var signatures []Signature
	for rows.Next() {
		var sig Signature
		if err := rows.Scan(&sig.ID, &sig.Name, &sig.Pattern, &sig.PatternType,
			&sig.Protocol, &sig.Severity, &sig.Description); err != nil {
			log.Printf("Ошибка чтения сигнатуры: %v", err)
			continue
		}

		// Компиляция regex паттернов
		if sig.PatternType == "regex" {
			compiled, err := regexp.Compile("(?i)" + sig.Pattern)
			if err != nil {
				log.Printf("Ошибка компиляции regex для сигнатуры %s: %v", sig.Name, err)
				continue
			}
			sig.compiled = compiled
		}

		signatures = append(signatures, sig)
	}

	e.sigMutex.Lock()
	e.signatures = signatures
	e.sigMutex.Unlock()

	log.Printf("Загружено %d сигнатур", len(signatures))
	return nil
}

// Start запускает движок
func (e *SignatureEngine) Start() error {
	// Запуск обработчиков пакетов
	for i := 0; i < e.config.WorkerCount; i++ {
		go e.packetWorker(i)
	}

	// Запуск обработчика угроз
	go e.threatHandler()

	// Запуск API сервера
	go e.startAPIServer()

	// Запуск захвата пакетов
	return e.startCapture()
}

func (e *SignatureEngine) startCapture() error {
	handle, err := pcap.OpenLive(e.config.Interface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("ошибка открытия интерфейса %s: %v", e.config.Interface, err)
	}
	defer handle.Close()

	// BPF фильтр для TCP и UDP трафика
	if err := handle.SetBPFFilter("tcp or udp or icmp"); err != nil {
		log.Printf("Предупреждение: не удалось установить BPF фильтр: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Printf("Захват пакетов запущен на интерфейсе %s", e.config.Interface)

	for {
		select {
		case <-e.ctx.Done():
			return nil
		case packet := <-packetSource.Packets():
			select {
			case e.packetChan <- packet:
				atomic.AddUint64(&e.stats.PacketsProcessed, 1)
			default:
				atomic.AddUint64(&e.stats.PacketsDropped, 1)
			}
		}
	}
}

func (e *SignatureEngine) packetWorker(id int) {
	log.Printf("Запущен обработчик пакетов #%d", id)

	for {
		select {
		case <-e.ctx.Done():
			return
		case packet := <-e.packetChan:
			e.analyzePacket(packet)
		}
	}
}

func (e *SignatureEngine) analyzePacket(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var protocol string
	var payload []byte

	// Извлечение IP информации
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		return
	}

	// Проверка блокировки IP
	if _, blocked := e.blockedIPs.Load(srcIP); blocked {
		return
	}

	// Анализ транспортного уровня
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "TCP"
		payload = tcp.Payload

		// Проверка SYN флуда
		if tcp.SYN && !tcp.ACK {
			key := fmt.Sprintf("%s_syn", srcIP)
			count := e.rateLimiter.Increment(key)
			if count > int64(e.config.SYNThreshold) {
				e.reportThreat(ThreatEvent{
					SignatureID:    9999,
					SignatureName:  "SYN Flood Detection",
					Timestamp:      time.Now(),
					SourceIP:       srcIP,
					DestIP:         dstIP,
					SourcePort:     srcPort,
					DestPort:       dstPort,
					Protocol:       protocol,
					MatchedContent: fmt.Sprintf("SYN packets: %d in %ds", count, e.config.TimeWindowSec),
					Confidence:     0.9,
					ThreatType:     "DOS",
					Severity:       8,
				})
			}
		}

		// HTTP флуд детектирование
		if dstPort == 80 || dstPort == 8080 || dstPort == 443 {
			key := fmt.Sprintf("%s_http", srcIP)
			count := e.rateLimiter.Increment(key)
			if count > int64(e.config.HTTPThreshold) {
				e.reportThreat(ThreatEvent{
					SignatureID:    9998,
					SignatureName:  "HTTP Flood Detection",
					Timestamp:      time.Now(),
					SourceIP:       srcIP,
					DestIP:         dstIP,
					SourcePort:     srcPort,
					DestPort:       dstPort,
					Protocol:       "HTTP",
					MatchedContent: fmt.Sprintf("HTTP requests: %d in %ds", count, e.config.TimeWindowSec),
					Confidence:     0.85,
					ThreatType:     "DOS",
					Severity:       7,
				})
			}
		}

	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = "UDP"
		payload = udp.Payload

		// UDP флуд детектирование
		key := fmt.Sprintf("%s_udp", srcIP)
		count := e.rateLimiter.Increment(key)
		if count > int64(e.config.UDPThreshold) {
			e.reportThreat(ThreatEvent{
				SignatureID:    9997,
				SignatureName:  "UDP Flood Detection",
				Timestamp:      time.Now(),
				SourceIP:       srcIP,
				DestIP:         dstIP,
				SourcePort:     srcPort,
				DestPort:       dstPort,
				Protocol:       protocol,
				MatchedContent: fmt.Sprintf("UDP packets: %d in %ds", count, e.config.TimeWindowSec),
				Confidence:     0.85,
				ThreatType:     "DOS",
				Severity:       7,
			})
		}

	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		protocol = "ICMP"
	} else {
		return
	}

	// Анализ payload на сигнатуры
	if len(payload) > 0 {
		e.analyzePayload(payload, srcIP, dstIP, srcPort, dstPort, protocol)
	}
}

func (e *SignatureEngine) analyzePayload(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, protocol string) {
	payloadStr := string(payload)
	payloadLower := strings.ToLower(payloadStr)

	e.sigMutex.RLock()
	signatures := e.signatures
	e.sigMutex.RUnlock()

	for _, sig := range signatures {
		// Фильтрация по протоколу
		if sig.Protocol != "ALL" && sig.Protocol != protocol {
			continue
		}

		var matched bool
		var matchedContent string

		switch sig.PatternType {
		case "exact":
			if strings.Contains(payloadStr, sig.Pattern) {
				matched = true
				matchedContent = sig.Pattern
			}
		case "content":
			patternLower := strings.ToLower(sig.Pattern)
			if strings.Contains(payloadLower, patternLower) {
				matched = true
				matchedContent = sig.Pattern
			}
		case "regex":
			if sig.compiled != nil {
				if match := sig.compiled.FindString(payloadStr); match != "" {
					matched = true
					matchedContent = match
				}
			}
		}

		if matched {
			// Ограничение длины matched content
			if len(matchedContent) > 200 {
				matchedContent = matchedContent[:200] + "..."
			}

			threatType := e.classifyThreat(sig.Name)
			confidence := e.calculateConfidence(sig.PatternType, sig.Severity)

			e.reportThreat(ThreatEvent{
				SignatureID:    sig.ID,
				SignatureName:  sig.Name,
				Timestamp:      time.Now(),
				SourceIP:       srcIP,
				DestIP:         dstIP,
				SourcePort:     srcPort,
				DestPort:       dstPort,
				Protocol:       protocol,
				MatchedContent: matchedContent,
				Confidence:     confidence,
				ThreatType:     threatType,
				Severity:       sig.Severity,
			})
		}
	}

	// Дополнительные детекторы
	e.detectXSS(payloadStr, srcIP, dstIP, srcPort, dstPort, protocol)
	e.detectSQLi(payloadStr, srcIP, dstIP, srcPort, dstPort, protocol)
}

func (e *SignatureEngine) detectXSS(payload, srcIP, dstIP string, srcPort, dstPort uint16, protocol string) {
	xssPatterns := []string{
		`(?i)<script[^>]*>`,
		`(?i)javascript\s*:`,
		`(?i)on(?:load|error|click|mouseover|focus)\s*=`,
		`(?i)<iframe[^>]*src\s*=`,
		`(?i)eval\s*\(`,
		`(?i)document\.(?:cookie|write|location)`,
	}

	for _, pattern := range xssPatterns {
		re := regexp.MustCompile(pattern)
		if match := re.FindString(payload); match != "" {
			e.reportThreat(ThreatEvent{
				SignatureID:    9996,
				SignatureName:  "XSS Attack Detection",
				Timestamp:      time.Now(),
				SourceIP:       srcIP,
				DestIP:         dstIP,
				SourcePort:     srcPort,
				DestPort:       dstPort,
				Protocol:       protocol,
				MatchedContent: match,
				Confidence:     0.85,
				ThreatType:     "XSS",
				Severity:       8,
			})
			return
		}
	}
}

func (e *SignatureEngine) detectSQLi(payload, srcIP, dstIP string, srcPort, dstPort uint16, protocol string) {
	sqliPatterns := []string{
		`(?i)\bunion\s+select\b`,
		`(?i)\b(?:sleep|benchmark|pg_sleep|waitfor)\s*\(`,
		`(?i)\b(?:convert|cast|extractvalue|updatexml)\s*\(`,
		`(?i)(['\"]\s*--|['\"]\s*#|/\*.*?\*/)`,
		`(?i)\b(?:information_schema|pg_catalog|sys\.|mysql\.)`,
		`(?i)'\s*or\s+'?\d+'?\s*=\s*'?\d+`,
		`(?i)'\s*or\s+'[^']*'\s*=\s*'`,
	}

	for _, pattern := range sqliPatterns {
		re := regexp.MustCompile(pattern)
		if match := re.FindString(payload); match != "" {
			e.reportThreat(ThreatEvent{
				SignatureID:    9995,
				SignatureName:  "SQL Injection Detection",
				Timestamp:      time.Now(),
				SourceIP:       srcIP,
				DestIP:         dstIP,
				SourcePort:     srcPort,
				DestPort:       dstPort,
				Protocol:       protocol,
				MatchedContent: match,
				Confidence:     0.88,
				ThreatType:     "SQLI",
				Severity:       9,
			})
			return
		}
	}
}

func (e *SignatureEngine) reportThreat(threat ThreatEvent) {
	// Проверка на дублирование
	cacheKey := fmt.Sprintf("%d-%s-%s", threat.SignatureID, threat.SourceIP, threat.MatchedContent[:min(50, len(threat.MatchedContent))])
	if e.eventCache.IsDuplicate(cacheKey) {
		return
	}

	select {
	case e.threatChan <- threat:
		atomic.AddUint64(&e.stats.ThreatsDetected, 1)
	default:
		log.Printf("Канал угроз переполнен, событие пропущено")
	}
}

func (e *SignatureEngine) threatHandler() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case threat := <-e.threatChan:
			e.logThreat(threat)

			// Автоматическая блокировка IP при высокой критичности
			if e.config.EnableBlocking && threat.Severity >= 8 {
				e.blockIP(threat.SourceIP, 5*time.Minute)
			}
		}
	}
}

func (e *SignatureEngine) logThreat(threat ThreatEvent) {
	log.Printf("[THREAT] %s | %s -> %s:%d | Type: %s | Severity: %d | Confidence: %.2f | Match: %s",
		threat.SignatureName,
		threat.SourceIP,
		threat.DestIP,
		threat.DestPort,
		threat.ThreatType,
		threat.Severity,
		threat.Confidence,
		threat.MatchedContent,
	)
}

func (e *SignatureEngine) blockIP(ip string, duration time.Duration) {
	e.blockedIPs.Store(ip, time.Now())
	log.Printf("[BLOCK] IP %s заблокирован на %v", ip, duration)

	go func() {
		time.Sleep(duration)
		e.blockedIPs.Delete(ip)
		log.Printf("[UNBLOCK] IP %s разблокирован", ip)
	}()
}

func (e *SignatureEngine) classifyThreat(name string) string {
	nameLower := strings.ToLower(name)
	switch {
	case strings.Contains(nameLower, "xss"):
		return "XSS"
	case strings.Contains(nameLower, "sql"):
		return "SQLI"
	case strings.Contains(nameLower, "dos") || strings.Contains(nameLower, "flood"):
		return "DOS"
	case strings.Contains(nameLower, "rce") || strings.Contains(nameLower, "exec"):
		return "RCE"
	default:
		return "OTHER"
	}
}

func (e *SignatureEngine) calculateConfidence(patternType string, severity int) float64 {
	base := 0.7
	typeBonus := map[string]float64{
		"exact":   0.2,
		"regex":   0.1,
		"content": 0.05,
	}[patternType]
	severityBonus := float64(severity) * 0.02

	conf := base + typeBonus + severityBonus
	if conf > 1.0 {
		conf = 1.0
	}
	return conf
}

// API Server
func (e *SignatureEngine) startAPIServer() {
	mux := http.NewServeMux()

	// Статистика
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := map[string]interface{}{
			"packets_processed": atomic.LoadUint64(&e.stats.PacketsProcessed),
			"threats_detected":  atomic.LoadUint64(&e.stats.ThreatsDetected),
			"packets_dropped":   atomic.LoadUint64(&e.stats.PacketsDropped),
			"uptime_seconds":    time.Since(e.stats.StartTime).Seconds(),
			"signatures_loaded": len(e.signatures),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	// Сигнатуры
	mux.HandleFunc("/api/signatures", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			e.sigMutex.RLock()
			json.NewEncoder(w).Encode(e.signatures)
			e.sigMutex.RUnlock()
		case "POST":
			var sig Signature
			if err := json.NewDecoder(r.Body).Decode(&sig); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := e.addSignature(sig); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Перезагрузка сигнатур
	mux.HandleFunc("/api/signatures/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := e.LoadSignatures(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]int{"loaded": len(e.signatures)})
	})

	// Health check
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// Блокировка IP
	mux.HandleFunc("/api/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP       string `json:"ip"`
			Duration int    `json:"duration_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if net.ParseIP(req.IP) == nil {
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			return
		}
		duration := time.Duration(req.Duration) * time.Second
		if duration <= 0 {
			duration = 5 * time.Minute
		}
		e.blockIP(req.IP, duration)
		w.WriteHeader(http.StatusOK)
	})

	addr := fmt.Sprintf(":%d", e.config.APIPort)
	log.Printf("API сервер запущен на порту %d", e.config.APIPort)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("Ошибка API сервера: %v", err)
	}
}

func (e *SignatureEngine) addSignature(sig Signature) error {
	_, err := e.db.Exec(`
		INSERT INTO signatures (name, pattern, pattern_type, protocol, severity, description)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sig.Name, sig.Pattern, sig.PatternType, sig.Protocol, sig.Severity, sig.Description)

	if err != nil {
		return err
	}

	return e.LoadSignatures()
}

func (e *SignatureEngine) Stop() {
	log.Println("Остановка движка...")
	e.cancel()
	e.db.Close()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	configPath := flag.String("config", "config.json", "Путь к конфигурационному файлу")
	iface := flag.String("interface", "", "Сетевой интерфейс")
	flag.Parse()

	config, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	if *iface != "" {
		config.Interface = *iface
	}

	engine, err := NewSignatureEngine(config)
	if err != nil {
		log.Fatalf("Ошибка создания движка: %v", err)
	}

	// Обработка сигналов завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Получен сигнал завершения...")
		engine.Stop()
		os.Exit(0)
	}()

	log.Println("Запуск Adaptive Signature Engine (Go version)...")
	if err := engine.Start(); err != nil {
		log.Fatalf("Ошибка запуска движка: %v", err)
	}
}
