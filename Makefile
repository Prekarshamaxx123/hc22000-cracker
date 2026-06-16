.PHONY: all cpu gpu release clean run

all: cpu

cpu:
	go mod tidy
	CGO_ENABLED=0 go build -o hashcrack .

gpu:
	nvcc -c -o crack.o crack.cu -arch=sm_75 -O3
	go mod tidy
	go build -tags gpu -o hashcrack .

release: gpu
	strip hashcrack
	@echo "Static binary: hashcrack ($$(ls -lh hashcrack | awk '{print $$5}'))"

run: gpu
	./hashcrack

clean:
	rm -f hashcrack crack.o hashcrack.exe
