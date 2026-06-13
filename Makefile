.PHONY: all cpu gpu clean

all: cpu

cpu:
	go mod tidy
	go build -o hashcrack .

gpu:
	nvcc -c -o crack.o crack.cu -arch=sm_75
	go mod tidy
	go build -tags gpu -o hashcrack .

clean:
	rm -f hashcrack crack.o
