//go:build gpu

package main

/*
#cgo CFLAGS: -I/usr/local/cuda/include
#cgo LDFLAGS: crack.o -L/usr/local/cuda/lib64 -L/usr/lib/x86_64-linux-gnu -lcudart -lcuda
#include <cuda_runtime.h>
#include <stdlib.h>

int cuda_crack(
    const char *charset, int charset_len,
    const unsigned char *ssid, int ssid_len,
    const unsigned char *target,
    const unsigned char *ap_mac, const unsigned char *sta_mac,
    int pw_length, unsigned long long start, unsigned long long count,
    char *found_pw
);
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

func crackGPU(hashInfo *HashInfo, config *Config, startAt, count uint64) {
	targetPMKID, _ := hex.DecodeString(hashInfo.PMKIDHex)
	targetPMKID = targetPMKID[:16]
	ssidBytes := []byte(hashInfo.SSID)
	apMAC := hashInfo.APMACRaw
	staMAC := hashInfo.STAMACRaw

	csCharset := C.CString(config.Charset)
	defer C.free(unsafe.Pointer(csCharset))

	startTime := time.Now()
	var gFound int32
	var gAttempts uint64
	chunkSize := uint64(500000)

	fmt.Printf("CUDA GPU cracking")
	if config.MinLen == config.MaxLen && count > 0 {
		total := powUint64(uint64(len(config.Charset)), config.MinLen)
		pct := float64(count) * 100.0 / float64(total)
		fmt.Printf(" (%.0f%% of length %d)", pct, config.MinLen)
	}
	fmt.Println()
	fmt.Println()

	for length := config.MinLen; length <= config.MaxLen && atomic.LoadInt32(&gFound) == 0; length++ {
		totalForLen := powUint64(uint64(len(config.Charset)), length)
		var processed uint64

		lenStart := uint64(0)
		lenEnd := totalForLen
		if config.MinLen == config.MaxLen && count > 0 {
			lenStart = startAt
			lenEnd = startAt + count
			if lenEnd > totalForLen {
				lenEnd = totalForLen
			}
		}

		for start := lenStart; start < lenEnd && atomic.LoadInt32(&gFound) == 0; start += chunkSize {
			end := start + chunkSize
			if end > lenEnd {
				end = lenEnd
			}
			ws := end - start

			foundPW := make([]byte, 64)
			found := C.cuda_crack(
				csCharset, C.int(len(config.Charset)),
				(*C.uchar)(unsafe.Pointer(&ssidBytes[0])), C.int(len(ssidBytes)),
				(*C.uchar)(unsafe.Pointer(&targetPMKID[0])),
				(*C.uchar)(unsafe.Pointer(&apMAC[0])),
				(*C.uchar)(unsafe.Pointer(&staMAC[0])),
				C.int(length),
				C.ulonglong(start),
				C.ulonglong(ws),
				(*C.char)(unsafe.Pointer(&foundPW[0])),
			)

			processed += ws
			atomic.AddUint64(&gAttempts, ws)

			if found < 0 {
				fmt.Printf("\nCUDA error. Falling back to CPU...\n")
				crackCPU(hashInfo, config, 0)
				return
			}
			if found != 0 {
				pwStr := strings.TrimRight(string(foundPW), "\x00")
				elapsed := time.Since(startTime)
				fmt.Printf("\n\n=== PASSWORD FOUND ===\n")
				fmt.Printf("Password: %s\n", pwStr)
				fmt.Printf("Elapsed:  %s\n", formatDuration(elapsed))
				fmt.Printf("Attempts: %d\n", atomic.LoadUint64(&gAttempts))
				fmt.Println("=======================\n")
				os.Exit(0)
			}

			elapsed := time.Since(startTime)
			speed := uint64(float64(atomic.LoadUint64(&gAttempts)) / elapsed.Seconds())
			pct := float64(processed) * 100.0 / float64(lenEnd-lenStart)
			fmt.Printf("\r[%s] CUDA Speed: %s/s | Len %d | %5.2f%%",
				formatDuration(elapsed), formatNumber(speed), length, pct)
		}
	}

	if atomic.LoadInt32(&gFound) == 0 {
		elapsed := time.Since(startTime)
		fmt.Printf("\n[%s] CUDA: range exhausted.\n", formatDuration(elapsed))
	}
}
