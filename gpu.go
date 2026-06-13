//go:build gpu

package main

/*
#cgo LDFLAGS: -lOpenCL
#define CL_TARGET_OPENCL_VERSION 300
#include <CL/cl.h>
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

const kernelSource = `
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void sha1_transform(__private uint *state, __private const uchar *block) {
    uint w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint)block[i*4] << 24) | ((uint)block[i*4+1] << 16) |
               ((uint)block[i*4+2] << 8) | (uint)block[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        uint t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = ROTL(t, 1);
    }

    uint a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20)          { f = (b & c) | ((~b) & d);    k = 0x5A827999U; }
        else if (i < 40)     { f = b ^ c ^ d;               k = 0x6ED9EBA1U; }
        else if (i < 60)     { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCU; }
        else                 { f = b ^ c ^ d;               k = 0xCA62C1D6U; }
        uint tmp = ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROTL(b, 30); b = a; a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void sha1(__private const uchar *msg, uint len, __private uchar *digest, __private uchar *scratch) {
    uint state[5] = { 0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U, 0xC3D2E1F0U };
    uint off;
    for (off = 0; off + 64 <= len; off += 64) sha1_transform(state, msg + off);

    __private uchar *b = scratch;
    uint rem = len - off;
    for (uint i = 0; i < rem; i++) b[i] = msg[off + i];
    b[rem] = 0x80U;
    if (rem >= 56) {
        for (uint i = rem+1; i < 64; i++) b[i] = 0;
        sha1_transform(state, b);
        for (uint i = 0; i < 56; i++) b[i] = 0;
    } else {
        for (uint i = rem+1; i < 56; i++) b[i] = 0;
    }
    ulong bits = (ulong)len * 8;
    for (int i = 0; i < 8; i++) b[56+i] = (uchar)(bits >> (56 - i*8));
    sha1_transform(state, b);
    for (int i = 0; i < 5; i++) {
        digest[i*4]   = (uchar)(state[i] >> 24);
        digest[i*4+1] = (uchar)(state[i] >> 16);
        digest[i*4+2] = (uchar)(state[i] >> 8);
        digest[i*4+3] = (uchar)(state[i]);
    }
}

void hmac_sha1(__private const uchar *key, uint klen, __private const uchar *msg, uint mlen,
               __private uchar *mac, __private uchar *scratch) {
    __private uchar *ipad = scratch;
    __private uchar *opad = scratch + 64;
    __private uchar *inner = scratch + 128;
    __private uchar *idig = scratch + 260;
    __private uchar *buf  = scratch + 320;

    uchar kbuf[64];
    __private const uchar *kp = key;
    uint ak = klen;
    if (klen > 64) { sha1(key, klen, kbuf, buf); kp = kbuf; ak = 20; }

    for (int i = 0; i < 64; i++) {
        uchar k = (i < (int)ak) ? kp[i] : 0;
        ipad[i] = k ^ 0x36U;
        opad[i] = k ^ 0x5CU;
    }
    for (int i = 0; i < 64; i++) inner[i] = ipad[i];
    for (uint i = 0; i < mlen; i++) inner[64+i] = msg[i];
    sha1(inner, 64+mlen, idig, buf);
    for (int i = 0; i < 64; i++) inner[i] = opad[i];
    for (int i = 0; i < 20; i++) inner[64+i] = idig[i];
    sha1(inner, 64+20, mac, buf);
}

void pbkdf2(__private const uchar *pw, uint pwlen, __private const uchar *salt, uint slen,
            uint iter, uint dklen, __private uchar *out, __private uchar *scratch) {
    __private uchar *sb = scratch;
    __private uchar *u  = scratch + 128;
    __private uchar *t  = scratch + 160;
    __private uchar *hs = scratch + 192;

    uint blk = (dklen + 19) / 20;
    for (uint b = 1; b <= blk; b++) {
        for (uint i = 0; i < slen; i++) sb[i] = salt[i];
        sb[slen]   = (uchar)(b >> 24);
        sb[slen+1] = (uchar)(b >> 16);
        sb[slen+2] = (uchar)(b >> 8);
        sb[slen+3] = (uchar)(b);
        hmac_sha1(pw, pwlen, sb, slen+4, u, hs);
        for (int i = 0; i < 20; i++) t[i] = u[i];
        for (uint j = 2; j <= iter; j++) {
            hmac_sha1(pw, pwlen, u, 20, u, hs);
            for (int i = 0; i < 20; i++) t[i] ^= u[i];
        }
        uint cl = (b == blk) ? (dklen - (b-1)*20) : 20;
        for (uint i = 0; i < cl; i++) out[(b-1)*20 + i] = t[i];
    }
}

__kernel void crack_pmkid(
    __global const uchar *charset,
    uint charset_len,
    uint pw_length,
    __global const uchar *ssid,
    uint ssid_len,
    __global const uchar *target_pmkid,
    __global const uchar *ap_mac,
    __global const uchar *sta_mac,
    ulong global_start,
    __global volatile int *found,
    __global uchar *found_password
) {
    ulong idx = global_start + get_global_id(0);
    if (*found) return;

    uchar pw[64];
    ulong tmp = idx;
    for (int i = (int)pw_length - 1; i >= 0; i--) {
        pw[i] = charset[tmp % charset_len];
        tmp /= charset_len;
    }

    uchar local_ssid[64];
    uint local_ssid_len = ssid_len;
    for (uint i = 0; i < ssid_len && i < 64; i++) local_ssid[i] = ssid[i];

    uchar local_ap[6], local_sta[6];
    for (int i = 0; i < 6; i++) { local_ap[i] = ap_mac[i]; local_sta[i] = sta_mac[i]; }

    uchar local_target[16];
    for (int i = 0; i < 16; i++) local_target[i] = target_pmkid[i];

    uchar pmk[32];
    uchar scr[1024];
    pbkdf2(pw, pw_length, local_ssid, local_ssid_len, 4096, 32, pmk, scr);

    uchar pm_msg[20];
    pm_msg[0]='P';pm_msg[1]='M';pm_msg[2]='K';pm_msg[3]=' ';
    pm_msg[4]='N';pm_msg[5]='a';pm_msg[6]='m';pm_msg[7]='e';
    for (int i=0;i<6;i++) pm_msg[8+i]=local_ap[i];
    for (int i=0;i<6;i++) pm_msg[14+i]=local_sta[i];

    uchar pr[20];
    hmac_sha1(pmk, 32, pm_msg, 20, pr, scr+128);

    int ok = 1;
    for (int i=0;i<16;i++) if (pr[i]!=local_target[i]) { ok=0; break; }
    if (ok) {
        *found = 1;
        for (uint i=0;i<pw_length;i++) found_password[i]=pw[i];
    }
}
`

func gpuErr(msg string, err C.cl_int) {
	if err != C.CL_SUCCESS {
		panic(fmt.Sprintf("OpenCL error %d at %s", int32(err), msg))
	}
}

func crackGPU(hashInfo *HashInfo, config *Config) {
	targetPMKID, _ := hex.DecodeString(hashInfo.PMKIDHex)
	targetPMKID = targetPMKID[:16]
	ssidBytes := []byte(hashInfo.SSID)
	apMAC := hashInfo.APMACRaw
	staMAC := hashInfo.STAMACRaw

	var plat C.cl_platform_id
	var dev C.cl_device_id
	var err C.cl_int

	C.clGetPlatformIDs(1, &plat, nil)
	if C.clGetDeviceIDs(plat, C.CL_DEVICE_TYPE_GPU, 1, &dev, nil) != C.CL_SUCCESS {
		fmt.Println("No OpenCL GPU device, falling back to CPU")
		crackCPU(hashInfo, config)
		return
	}

	ctx := C.clCreateContext(nil, 1, &dev, nil, nil, &err)
	gpuErr("createContext", err)
	var props [3]C.cl_queue_properties
	props[0] = C.CL_QUEUE_PROPERTIES
	props[1] = 0
	props[2] = 0
	q := C.clCreateCommandQueueWithProperties(ctx, dev, &props[0], &err)
	gpuErr("createCommandQueue", err)

	csrc := C.CString(kernelSource)
	defer C.free(unsafe.Pointer(csrc))
	srclen := C.size_t(len(kernelSource))
	prog := C.clCreateProgramWithSource(ctx, 1, &csrc, &srclen, &err)
	gpuErr("createProgramWithSource", err)

	opts := C.CString("")
	defer C.free(unsafe.Pointer(opts))
	be := C.clBuildProgram(prog, 1, &dev, opts, nil, nil)
	if be != C.CL_SUCCESS {
		var logLen C.size_t
		C.clGetProgramBuildInfo(prog, dev, C.CL_PROGRAM_BUILD_LOG, 0, nil, &logLen)
		log := make([]byte, logLen)
		C.clGetProgramBuildInfo(prog, dev, C.CL_PROGRAM_BUILD_LOG, logLen, unsafe.Pointer(&log[0]), nil)
		fmt.Fprintf(os.Stderr, "Kernel build error:\n%s\n", string(log))
		return
	}

	ker := C.clCreateKernel(prog, C.CString("crack_pmkid"), &err)
	gpuErr("createKernel", err)

	csCharset := C.CString(config.Charset)
	defer C.free(unsafe.Pointer(csCharset))
	charsetBuf := C.clCreateBuffer(ctx, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(len(config.Charset)), unsafe.Pointer(csCharset), &err)
	gpuErr("charsetBuf", err)

	ssidBuf := C.clCreateBuffer(ctx, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(len(ssidBytes)), unsafe.Pointer(&ssidBytes[0]), &err)
	gpuErr("ssidBuf", err)

	pmkidBuf := C.clCreateBuffer(ctx, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(16), unsafe.Pointer(&targetPMKID[0]), &err)
	gpuErr("pmkidBuf", err)

	apBuf := C.clCreateBuffer(ctx, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(6), unsafe.Pointer(&apMAC[0]), &err)
	gpuErr("apBuf", err)

	staBuf := C.clCreateBuffer(ctx, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(6), unsafe.Pointer(&staMAC[0]), &err)
	gpuErr("staBuf", err)

	foundBuf := C.clCreateBuffer(ctx, C.CL_MEM_READ_WRITE, C.size_t(4), nil, &err)
	gpuErr("foundBuf", err)
	foundPWBuf := C.clCreateBuffer(ctx, C.CL_MEM_READ_WRITE, C.size_t(64), nil, &err)
	gpuErr("foundPWBuf", err)

	zero := C.cl_int(0)
	C.clEnqueueFillBuffer(q, foundBuf, unsafe.Pointer(&zero), C.size_t(4), 0, C.size_t(4), 0, nil, nil)
	C.clFinish(q)

	csLen := C.uint(len(config.Charset))
	ssidLen := C.uint(len(ssidBytes))

	set := func(idx int, sz C.size_t, p unsafe.Pointer) {
		e := C.clSetKernelArg(ker, C.cl_uint(idx), sz, p)
		if e != C.CL_SUCCESS {
			panic(fmt.Sprintf("arg %d failed: %d", idx, int32(e)))
		}
	}

	set(0, C.size_t(unsafe.Sizeof(charsetBuf)), unsafe.Pointer(&charsetBuf))
	set(1, C.size_t(unsafe.Sizeof(csLen)), unsafe.Pointer(&csLen))
	// arg 2 set per-length in loop
	set(3, C.size_t(unsafe.Sizeof(ssidBuf)), unsafe.Pointer(&ssidBuf))
	set(4, C.size_t(unsafe.Sizeof(ssidLen)), unsafe.Pointer(&ssidLen))
	set(5, C.size_t(unsafe.Sizeof(pmkidBuf)), unsafe.Pointer(&pmkidBuf))
	set(6, C.size_t(unsafe.Sizeof(apBuf)), unsafe.Pointer(&apBuf))
	set(7, C.size_t(unsafe.Sizeof(staBuf)), unsafe.Pointer(&staBuf))
	// arg 8 set per-chunk in loop
	set(9, C.size_t(unsafe.Sizeof(foundBuf)), unsafe.Pointer(&foundBuf))
	set(10, C.size_t(unsafe.Sizeof(foundPWBuf)), unsafe.Pointer(&foundPWBuf))

	var cu C.cl_uint
	C.clGetDeviceInfo(dev, C.CL_DEVICE_MAX_COMPUTE_UNITS, C.size_t(unsafe.Sizeof(cu)), unsafe.Pointer(&cu), nil)

	chunkSize := uint64(500000)
	startTime := time.Now()
	var gFound int32
	var gAttempts uint64

	fmt.Printf("GPU: %d compute units, chunk size %s\n", int(cu), formatNumber(chunkSize))
	fmt.Println()

	for length := config.MinLen; length <= config.MaxLen && atomic.LoadInt32(&gFound) == 0; length++ {
		csLen2 := C.uint(length)
		set(2, C.size_t(unsafe.Sizeof(csLen2)), unsafe.Pointer(&csLen2))

		totalForLen := powUint64(uint64(len(config.Charset)), length)
		var processed uint64

		for start := uint64(0); start < totalForLen && atomic.LoadInt32(&gFound) == 0; start += chunkSize {
			end := start + chunkSize
			if end > totalForLen {
				end = totalForLen
			}
			ws := end - start

			gStart := C.cl_ulong(start)
			set(8, C.size_t(unsafe.Sizeof(gStart)), unsafe.Pointer(&gStart))

			if start == 0 && length == config.MinLen {
				C.clEnqueueFillBuffer(q, foundBuf, unsafe.Pointer(&zero), C.size_t(4), 0, C.size_t(4), 0, nil, nil)
				C.clFinish(q)
			}

			gs := C.size_t(ws)
			e := C.clEnqueueNDRangeKernel(q, ker, 1, nil, &gs, nil, 0, nil, nil)
			if e != C.CL_SUCCESS {
				gpuErr("enqueue", e)
			}
			C.clFinish(q)

			var fc C.cl_int
			C.clEnqueueReadBuffer(q, foundBuf, C.CL_TRUE, 0, C.size_t(4), unsafe.Pointer(&fc), 0, nil, nil)

			processed += ws
			atomic.AddUint64(&gAttempts, ws)

			if fc != 0 {
				pwBytes := make([]byte, 64)
				C.clEnqueueReadBuffer(q, foundPWBuf, C.CL_TRUE, 0, C.size_t(64), unsafe.Pointer(&pwBytes[0]), 0, nil, nil)
				pwStr := strings.TrimRight(string(pwBytes), "\x00")
				atomic.StoreInt32(&gFound, 1)

				elapsed := time.Since(startTime)
				fmt.Printf("\n\n=== PASSWORD FOUND ===\n")
				fmt.Printf("Password: %s\n", pwStr)
				fmt.Printf("Elapsed:  %s\n", formatDuration(elapsed))
				fmt.Printf("Attempts: %d\n", atomic.LoadUint64(&gAttempts))
				fmt.Println("=======================\n")
				goto cleanup
			}

			elapsed := time.Since(startTime)
			speed := uint64(float64(atomic.LoadUint64(&gAttempts)) / elapsed.Seconds())
			pct := float64(processed) * 100.0 / float64(totalForLen)
			fmt.Printf("\r[%s] GPU Speed: %s/s | Len %d | %5.2f%%",
				formatDuration(elapsed), formatNumber(speed), length, pct)
		}
	}

	if atomic.LoadInt32(&gFound) == 0 {
		elapsed := time.Since(startTime)
		fmt.Printf("\n\n=== NOT FOUND ===\n")
		fmt.Printf("All combinations exhausted.\n")
		fmt.Printf("Elapsed: %s\n", formatDuration(elapsed))
	}

cleanup:
	C.clReleaseMemObject(charsetBuf)
	C.clReleaseMemObject(ssidBuf)
	C.clReleaseMemObject(pmkidBuf)
	C.clReleaseMemObject(apBuf)
	C.clReleaseMemObject(staBuf)
	C.clReleaseMemObject(foundBuf)
	C.clReleaseMemObject(foundPWBuf)
	C.clReleaseKernel(ker)
	C.clReleaseProgram(prog)
	C.clReleaseCommandQueue(q)
	C.clReleaseContext(ctx)
}
