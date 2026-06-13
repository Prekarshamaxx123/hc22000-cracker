.PHONY: all cpu gpu clean

all: cpu

cpu:
	go mod tidy
	go build -o hashcrack .

gpu:
	go mod tidy
	go build -tags gpu -o hashcrack .

clean:
	rm -f hashcrack
