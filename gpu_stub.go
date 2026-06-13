//go:build !gpu

package main

import "fmt"

func crackGPU(hashInfo *HashInfo, config *Config) {
	fmt.Println("GPU mode not compiled in.")
	fmt.Println()
	fmt.Println("To enable GPU support:")
	fmt.Println("  sudo apt install ocl-icd-opencl-dev opencl-headers")
	fmt.Println("  go build -tags gpu")
	fmt.Println()
	fmt.Println("Falling back to CPU mode...")
	crackCPU(hashInfo, config)
}
