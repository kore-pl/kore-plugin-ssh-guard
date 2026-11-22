# kore-plugin-ssh-guard 构建入口：build / dist / check / clean。
SHELL := /bin/bash

ID := ssh-guard
BIN := bin/$(ID)
DIST := dist
VERSION := $(shell sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' info.json | head -n 1)
PACKAGE := $(DIST)/$(ID)-$(VERSION).tar.gz

.PHONY: build dist check clean

# 静态构建：G-16 兼容性基线（CGO_ENABLED=0 + GOAMD64=v1 + trimpath + -s -w）。
build:
	CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o $(BIN) .

# 确定性打包：显式列条目、固定 mtime/owner、gzip -9n。
# size_bytes 回填最终 tar.gz 的实际字节数并迭代到不动点（偏差 0%）。
dist: build
	@set -eo pipefail; \
	rm -rf $(DIST)/stage $(PACKAGE) $(PACKAGE).sha256; \
	mkdir -p $(DIST)/stage/bin; \
	cp $(BIN) $(DIST)/stage/bin/$(ID); \
	size=0; \
	for _ in 1 2 3 4 5; do \
		sed "s/\"size_bytes\": 0/\"size_bytes\": $$size/" info.json > $(DIST)/stage/info.json; \
		( cd $(DIST)/stage && sha256sum info.json bin/$(ID) > SHA256SUMS ); \
		tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
		    -cf - -C $(DIST)/stage info.json bin SHA256SUMS | gzip -9n > $(PACKAGE); \
		next=$$(stat -c%s $(PACKAGE)); \
		if [ "$$next" = "$$size" ]; then break; fi; \
		size=$$next; \
	done; \
	( cd $(DIST) && sha256sum $(ID)-$(VERSION).tar.gz > $(ID)-$(VERSION).tar.gz.sha256 ); \
	rm -rf $(DIST)/stage; \
	echo "打包完成: $(PACKAGE) size_bytes=$$(tar -xzOf $(PACKAGE) info.json | sed -n 's/.*"size_bytes": \([0-9]*\).*/\1/p')"

# 门禁：gofmt（有输出即失败）→ go vet → go test。
check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt 需要格式化："; echo "$$out"; exit 1; fi; echo "gofmt: clean"
	go vet ./...
	go test -timeout 200s ./...

clean:
	rm -rf bin dist
	rm -f go.work.sum
