//go:build !gpu

package main

import "fmt"

func crackGPU(hashInfo *HashInfo, config *Config, startAt, count uint64) {
	fmt.Println("GPU (CUDA) not compiled in. No NVIDIA GPU detected.")
	fmt.Println()
	fmt.Println("Falling back to CPU mode...")
	crackCPU(hashInfo, config, 0)
}
