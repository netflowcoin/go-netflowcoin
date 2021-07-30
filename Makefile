# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: sdvn android ios sdvn-cross evm all test clean
.PHONY: sdvn-linux sdvn-linux-386 sdvn-linux-amd64 sdvn-linux-mips64 sdvn-linux-mips64le
.PHONY: sdvn-linux-arm sdvn-linux-arm-5 sdvn-linux-arm-6 sdvn-linux-arm-7 sdvn-linux-arm64
.PHONY: sdvn-darwin sdvn-darwin-386 sdvn-darwin-amd64
.PHONY: sdvn-windows sdvn-windows-386 sdvn-windows-amd64

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run

sdvn:
	$(GORUN) build/ci.go install ./cmd/sdvn
	@echo "Done building."
	@echo "Run \"$(GOBIN)/sdvn\" to launch sdvn."

all:
	$(GORUN) build/ci.go install

android:
	$(GORUN) build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/sdvn.aar\" to use the library."
	@echo "Import \"$(GOBIN)/sdvn-sources.jar\" to add javadocs"
	@echo "For more info see https://stackoverflow.com/questions/20994336/android-studio-how-to-attach-javadoc"

ios:
	$(GORUN) build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/sdvn.framework\" to use the library."

test: all
	$(GORUN) build/ci.go test

lint: ## Run linters.
	$(GORUN) build/ci.go lint

clean:
	env GO111MODULE=on go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Cross Compilation Targets (xgo)

sdvn-cross: sdvn-linux sdvn-darwin sdvn-windows sdvn-android sdvn-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-*

sdvn-linux: sdvn-linux-386 sdvn-linux-amd64 sdvn-linux-arm sdvn-linux-mips64 sdvn-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-*

sdvn-linux-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/sdvn
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep 386

sdvn-linux-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/sdvn
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep amd64

sdvn-linux-arm: sdvn-linux-arm-5 sdvn-linux-arm-6 sdvn-linux-arm-7 sdvn-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep arm

sdvn-linux-arm-5:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/sdvn
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep arm-5

sdvn-linux-arm-6:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/sdvn
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep arm-6

sdvn-linux-arm-7:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/sdvn
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep arm-7

sdvn-linux-arm64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/sdvn
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep arm64

sdvn-linux-mips:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/sdvn
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep mips

sdvn-linux-mipsle:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/sdvn
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep mipsle

sdvn-linux-mips64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/sdvn
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep mips64

sdvn-linux-mips64le:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/sdvn
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-linux-* | grep mips64le

sdvn-darwin: sdvn-darwin-386 sdvn-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-darwin-*

sdvn-darwin-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/sdvn
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-darwin-* | grep 386

sdvn-darwin-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/sdvn
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-darwin-* | grep amd64

sdvn-windows: sdvn-windows-386 sdvn-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-windows-*

sdvn-windows-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/sdvn
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-windows-* | grep 386

sdvn-windows-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/sdvn
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/sdvn-windows-* | grep amd64
