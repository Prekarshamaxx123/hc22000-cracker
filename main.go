package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type HashInfo struct {
	PMKIDHex string
	APMACRaw []byte
	STAMACRaw []byte
	SSID     string
}

type Config struct {
	Charset    string
	MinLen     int
	MaxLen     int
	Mode       string // "cpu", "gpu", "all"
	LimitPct   int    // 1-100
}

func normalizeMAC(mac string) string {
	mac = strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(mac))
	return mac
}

func parseMAC(macStr string) ([]byte, error) {
	return hex.DecodeString(macStr)
}

func parseHC22000(path string) (*HashInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		info, err := parseHC22000Line(line)
		if err != nil {
			continue
		}
		if info != nil {
			return info, nil
		}
	}
	return nil, fmt.Errorf("no valid hc22000 entry found in file")
}

func parseHC22000Line(line string) (*HashInfo, error) {
	sep := "*"
	if strings.Contains(line, "*") {
		sep = "*"
	} else if strings.Contains(line, ":") {
		sep = ":"
	} else {
		return nil, fmt.Errorf("unknown separator")
	}

	parts := strings.Split(line, sep)
	if len(parts) < 4 {
		return nil, fmt.Errorf("too few fields")
	}

	start := 0
	if parts[0] == "WPA" && len(parts) > 2 {
		start = 2
	}

	pmkidStr := strings.TrimSpace(parts[start])
	bssidStr := strings.TrimSpace(parts[start+1])
	staStr := strings.TrimSpace(parts[start+2])

	pmkidStr = strings.ToLower(pmkidStr)
	bssidStr = normalizeMAC(bssidStr)
	staStr = normalizeMAC(staStr)

	if (len(pmkidStr) != 32 && len(pmkidStr) != 64) || !isHexString(pmkidStr) {
		return nil, fmt.Errorf("invalid PMKID length: got %d hex chars, expected 32 or 64", len(pmkidStr))
	}
	if len(bssidStr) != 12 || !isHexString(bssidStr) {
		return nil, fmt.Errorf("invalid BSSID")
	}
	if len(staStr) != 12 || !isHexString(staStr) {
		staStr = ""
	}

	essidParts := parts[start+3:]
	essid := strings.Join(essidParts, sep)
	essid = strings.TrimRight(essid, "*")
	essid = strings.TrimSpace(essid)
	if essid == "" {
		return nil, fmt.Errorf("empty ESSID")
	}

	apMAC, err := parseMAC(bssidStr)
	if err != nil {
		return nil, fmt.Errorf("bad AP MAC: %w", err)
	}
	var staMAC []byte
	if staStr != "" {
		staMAC, err = parseMAC(staStr)
		if err != nil {
			staMAC = nil
		}
	}
	if staMAC == nil || len(staMAC) != 6 {
		staMAC = []byte{0, 0, 0, 0, 0, 0}
	}

	return &HashInfo{
		PMKIDHex: pmkidStr,
		APMACRaw: apMAC,
		STAMACRaw: staMAC,
		SSID:     essid,
	}, nil
}

func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func computePMK(password []byte, ssid []byte) []byte {
	return pbkdf2.Key(password, ssid, 4096, 32, sha1.New)
}

func computePMKID(pmk []byte, apMAC, staMAC []byte) []byte {
	msg := make([]byte, 8+6+6)
	copy(msg[0:8], "PMK Name")
	copy(msg[8:14], apMAC)
	copy(msg[14:20], staMAC)
	mac := hmac.New(sha1.New, pmk)
	mac.Write(msg)
	return mac.Sum(nil)[:16]
}

func powUint64(base uint64, exp int) uint64 {
	result := uint64(1)
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}

func passwordFromIndex(idx uint64, charset string, length int) string {
	csLen := uint64(len(charset))
	pw := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		pw[i] = charset[idx%csLen]
		idx /= csLen
	}
	return string(pw)
}

func passwordFromGlobalIndex(idx uint64, charset string, minLen, maxLen int) string {
	csLen := uint64(len(charset))
	for length := minLen; length <= maxLen; length++ {
		total := powUint64(csLen, length)
		if idx < total {
			return passwordFromIndex(idx, charset, length)
		}
		idx -= total
	}
	return ""
}

func totalCombinations(charset string, minLen, maxLen int) uint64 {
	csLen := uint64(len(charset))
	var total uint64
	for l := minLen; l <= maxLen; l++ {
		add := powUint64(csLen, l)
		if total+add < total {
			return math.MaxUint64
		}
		total += add
	}
	return total
}

func promptString(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func main() {
	fmt.Println("=== WPA PMKID Cracker ===")
	fmt.Println()

	hc22000Path := promptString("Enter hc22000 file path: ")
	hashInfo, err := parseHC22000(hc22000Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  SSID:   %s\n", hashInfo.SSID)
	fmt.Printf("  BSSID:  %s\n", hex.EncodeToString(hashInfo.APMACRaw))
	fmt.Printf("  STA:    %s\n", hex.EncodeToString(hashInfo.STAMACRaw))
	fmt.Printf("  PMKID:  %s\n", hashInfo.PMKIDHex)
	fmt.Println()

	fmt.Println("Select charset:")
	fmt.Println("  1) a-z")
	fmt.Println("  2) A-Z")
	fmt.Println("  3) 0-9")
	fmt.Println("  4) a-z + A-Z")
	fmt.Println("  5) a-z + A-Z + 0-9")
	fmt.Println("  6) All printable")
	fmt.Println("  7) Manual (custom)")
	csChoice := promptString("Choice (1-7): ")

	var charset string
	switch csChoice {
	case "1":
		charset = "abcdefghijklmnopqrstuvwxyz"
	case "2":
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "3":
		charset = "0123456789"
	case "4":
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "5":
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	case "6":
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?`~ "
	case "7":
		charset = promptString("Enter custom charset: ")
		if charset == "" {
			fmt.Println("Charset cannot be empty")
			os.Exit(1)
		}
	default:
		fmt.Println("Invalid choice")
		os.Exit(1)
	}
	// Remove duplicate characters from charset
	charset = dedupeChars(charset)
	fmt.Printf("  Charset (%d chars): %s\n", len(charset), charset)
	fmt.Println()

	lenInput := promptString("Password length (e.g. 8 or 8:12): ")
	minLen, maxLen, err := parseLength(lenInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Length range: %d - %d\n", minLen, maxLen)
	fmt.Println()

	total := totalCombinations(charset, minLen, maxLen)
	if total == math.MaxUint64 {
		fmt.Println("  Total combinations: > 18 quintillion (overflow)")
	} else {
		fmt.Printf("  Total combinations: %d\n", total)
	}
	fmt.Println()

	mode := promptString("Mode (cpu/gpu/all) [cpu]: ")
	if mode == "" {
		mode = "cpu"
	}
	mode = strings.ToLower(mode)
	if mode != "cpu" && mode != "gpu" && mode != "all" {
		mode = "cpu"
	}
	fmt.Printf("  Mode: %s\n", mode)
	fmt.Println()

	limitStr := promptString("Resource limit %% (1-100) [80]: ")
	limit := 80
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err == nil && l >= 1 && l <= 100 {
			limit = l
		}
	}
	fmt.Printf("  Resource limit: %d%%\n", limit)
	fmt.Println()

	fmt.Println("Starting crack...")
	fmt.Println()

	crack(hashInfo, &Config{
		Charset:  charset,
		MinLen:   minLen,
		MaxLen:   maxLen,
		Mode:     mode,
		LimitPct: limit,
	})
}

func dedupeChars(s string) string {
	seen := make(map[rune]bool)
	result := make([]rune, 0, len(s))
	for _, r := range s {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}
	return string(result)
}

func parseLength(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("length cannot be empty")
	}
	if strings.Contains(s, ":") {
		parts := strings.SplitN(s, ":", 2)
		min, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		max, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || min < 1 || max < min {
			return 0, 0, fmt.Errorf("invalid length range, use e.g. 8:12")
		}
		return min, max, nil
	}
	l, err := strconv.Atoi(s)
	if err != nil || l < 1 {
		return 0, 0, fmt.Errorf("invalid length, use e.g. 8")
	}
	return l, l, nil
}

func crack(hashInfo *HashInfo, config *Config) {
	if config.Mode == "cpu" || config.Mode == "all" {
		crackCPU(hashInfo, config)
	} else if config.Mode == "gpu" {
		crackGPU(hashInfo, config)
	}
}

func crackCPU(hashInfo *HashInfo, config *Config) {
	numCPU := runtime.NumCPU()
	numWorkers := int(float64(numCPU) * float64(config.LimitPct) / 100.0)
	if numWorkers < 1 {
		numWorkers = 1
	}
	oldProcs := runtime.GOMAXPROCS(0)
	newProcs := numWorkers
	if newProcs < 1 {
		newProcs = 1
	}
	runtime.GOMAXPROCS(newProcs)

	targetPMKID, err := hex.DecodeString(hashInfo.PMKIDHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding PMKID: %v\n", err)
		return
	}
	targetPMKID = targetPMKID[:16]
	ssid := []byte(hashInfo.SSID)
	apMAC := hashInfo.APMACRaw
	staMAC := hashInfo.STAMACRaw

	total := totalCombinations(config.Charset, config.MinLen, config.MaxLen)

	fmt.Printf("CPU workers: %d (of %d cores, %d%% limit)\n", numWorkers, numCPU, config.LimitPct)
	fmt.Println()

	var counter uint64
	var found int32
	var foundPW string
	var attempts uint64
	startTime := time.Now()

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			for {
				if atomic.LoadInt32(&found) == 1 {
					return
				}
				idx := atomic.AddUint64(&counter, 1) - 1
				if total != math.MaxUint64 && idx >= total {
					return
				}
				pw := passwordFromGlobalIndex(idx, config.Charset, config.MinLen, config.MaxLen)
				if pw == "" {
					return
				}
				pmk := computePMK([]byte(pw), ssid)
				pmkid := computePMKID(pmk, apMAC, staMAC)
				if string(pmkid) == string(targetPMKID) {
					atomic.StoreInt32(&found, 1)
					foundPW = pw
					return
				}
				atomic.AddUint64(&attempts, 1)
			}
		}(w)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	prevAttempts := uint64(0)
	for range ticker.C {
		curAttempts := atomic.LoadUint64(&attempts)
		speed := curAttempts - prevAttempts
		prevAttempts = curAttempts
		elapsed := time.Since(startTime)

		if atomic.LoadInt32(&found) == 1 {
			fmt.Printf("\n\n=== PASSWORD FOUND ===\n")
			fmt.Printf("Password: %s\n", foundPW)
			fmt.Printf("Elapsed:  %s\n", formatDuration(elapsed))
			fmt.Printf("Attempts: %d\n", curAttempts)
			fmt.Printf("Speed:    %s/s\n", formatNumber(speed))
			fmt.Println("=======================\n")
			runtime.GOMAXPROCS(oldProcs)
			return
		}

		curIdx := atomic.LoadUint64(&counter)
		var pct float64
		if total != math.MaxUint64 && total > 0 {
			pct = float64(curIdx) * 100.0 / float64(total)
		}

		currentPW := "---"
		if curIdx > 0 {
			currentPW = passwordFromGlobalIndex(curIdx-1, config.Charset, config.MinLen, config.MaxLen)
			if currentPW == "" {
				currentPW = "---"
			}
		}

		pctStr := ""
		if total != math.MaxUint64 && total > 0 {
			pctStr = fmt.Sprintf("%5.2f%%", pct)
		} else {
			pctStr = "  --- "
		}

		fmt.Printf("\r[%s] Speed: %s/s | %s | Trying: %-*s | Cores: %d/%d",
			formatDuration(elapsed),
			formatNumber(speed),
			pctStr,
			max(20, config.MaxLen+2), currentPW,
			numWorkers, numCPU,
		)

		if curIdx >= total && total != math.MaxUint64 && atomic.LoadInt32(&found) == 0 {
			fmt.Printf("\n\n=== NOT FOUND ===\n")
			fmt.Printf("All %d combinations exhausted.\n", total)
			fmt.Printf("Elapsed: %s\n", formatDuration(elapsed))
			runtime.GOMAXPROCS(oldProcs)
			return
		}
	}
}



func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func formatNumber(n uint64) string {
	s := strconv.FormatUint(n, 10)
	parts := make([]string, 0, len(s)/3+1)
	for i := len(s); i > 0; i -= 3 {
		start := i - 3
		if start < 0 {
			start = 0
		}
		parts = append([]string{s[start:i]}, parts...)
	}
	return strings.Join(parts, ",")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
