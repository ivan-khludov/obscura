.PHONY: build build-cli build-tui build-all release-snapshot test test-apply-coverage test-backup-coverage test-certs-coverage test-cmd-coverage test-config-coverage test-doctor-coverage test-domain-coverage test-fallback-coverage test-firewall-coverage test-install-coverage test-logs-coverage test-manifest-coverage test-orchestration-coverage test-platform-coverage test-protocol-coverage test-qr-coverage test-render-coverage test-runtime-coverage test-singboxcheck-coverage test-sshd-coverage test-store-coverage test-sysctl-coverage test-systemd-coverage test-version-coverage lint fmt tidy integration lab lab-shell lab-smoke lab-clean docker-check e2e e2e-clean e2e-http e2e-http-clean e2e-socks5 e2e-socks5-clean e2e-shadowsocks e2e-shadowsocks-clean e2e-trojan e2e-trojan-clean e2e-wireguard e2e-wireguard-clean e2e-vmess e2e-vmess-clean e2e-vless e2e-vless-clean e2e-hysteria2 e2e-hysteria2-clean e2e-tuic e2e-tuic-clean

VERSION ?= $(shell awk -F'"' '/^var Version = /{print $$2; exit}' internal/version/version.go)
LDFLAGS := -ldflags "-X github.com/ivan-khludov/obscura/internal/version.Version=$(VERSION)"
GOLANGCI_LINT := $(shell go env GOPATH)/bin/golangci-lint
COVERAGE_MIN ?= 95

define assert_coverage
	@pct=$$(go tool cover -func=$(1) | awk '/^total:/ {print $$3}' | tr -d '%'); \
	awk -v p="$$pct" -v min=$(COVERAGE_MIN) 'BEGIN { if (p+0 < min+0) { printf "$(2) coverage %.1f%% < $(COVERAGE_MIN)%%\n", p; exit 1 } }'
endef

define assert_coverage_verbose
	@pct=$$(go tool cover -func=$(1) | awk '/^total:/ {print $$3}' | tr -d '%'); \
	if awk -v p="$$pct" -v min=$(COVERAGE_MIN) 'BEGIN { exit (p+0 >= min+0 ? 0 : 1) }'; then :; else \
		echo "$(2) coverage $$pct% < $(COVERAGE_MIN)%"; \
		echo "=== uncovered ==="; \
		go tool cover -func=$(1) | awk '$$3 != "100.0%" {print}'; \
		exit 1; \
	fi
endef

build:
	go build $(LDFLAGS) -o bin/obscura ./cmd/obscura

build-cli:
	go build $(LDFLAGS) -o bin/obscura-cli ./cmd/obscura-cli

build-tui:
	go build $(LDFLAGS) -o bin/obscura-tui ./cmd/obscura-tui

build-all: build build-cli build-tui

release-snapshot:
	goreleaser release --snapshot --clean

test:
	go test ./... -race -count=1

test-apply-coverage:
	go test ./internal/apply/tests -coverpkg=./internal/apply -coverprofile=coverage.out -covermode=atomic
	$(call assert_coverage,coverage.out,apply)

test-backup-coverage:
	go test ./internal/backup/tests -coverpkg=./internal/backup -coverprofile=backup-coverage.out -covermode=atomic
	$(call assert_coverage,backup-coverage.out,backup)

test-certs-coverage:
	go test ./internal/certs/tests -coverpkg=./internal/certs -coverprofile=certs-coverage.out -covermode=atomic
	$(call assert_coverage,certs-coverage.out,certs)

test-cmd-coverage:
	go test ./internal/cmd/tests -coverpkg=./internal/cmd -coverprofile=cmd-coverage.out -covermode=atomic
	$(call assert_coverage,cmd-coverage.out,cmd)

test-config-coverage:
	go test ./internal/config/tests -coverpkg=./internal/config -coverprofile=config-coverage.out -covermode=atomic
	$(call assert_coverage,config-coverage.out,config)

test-doctor-coverage:
	go test ./internal/doctor/tests -coverpkg=./internal/doctor -coverprofile=doctor-coverage.out -covermode=atomic
	$(call assert_coverage,doctor-coverage.out,doctor)

test-domain-coverage:
	go test ./internal/domain/tests -coverpkg=./internal/domain -coverprofile=domain-coverage.out -covermode=atomic
	$(call assert_coverage,domain-coverage.out,domain)

test-fallback-coverage:
	go test ./internal/fallback/tests -coverpkg=./internal/fallback -coverprofile=fallback-coverage.out -covermode=atomic
	$(call assert_coverage,fallback-coverage.out,fallback)

test-firewall-coverage:
	go test ./internal/firewall/tests -coverpkg=./internal/firewall -coverprofile=firewall-coverage.out -covermode=atomic
	$(call assert_coverage,firewall-coverage.out,firewall)

test-install-coverage:
	go test ./internal/install/tests -coverpkg=./internal/install -coverprofile=install-coverage.out -covermode=atomic
	$(call assert_coverage,install-coverage.out,install)

test-logs-coverage:
	go test ./internal/logs/tests -coverpkg=./internal/logs -coverprofile=logs-coverage.out -covermode=atomic
	$(call assert_coverage,logs-coverage.out,logs)

test-manifest-coverage:
	go test ./internal/manifest/tests -coverpkg=./internal/manifest -coverprofile=manifest-coverage.out -covermode=atomic
	$(call assert_coverage,manifest-coverage.out,manifest)

test-orchestration-coverage:
	go test ./internal/orchestration/tests -coverpkg=./internal/orchestration -coverprofile=orchestration-coverage.out -covermode=atomic
	$(call assert_coverage,orchestration-coverage.out,orchestration)

test-platform-coverage:
	go test ./internal/platform/tests -coverpkg=./internal/platform -coverprofile=platform-coverage.out -covermode=atomic
	$(call assert_coverage,platform-coverage.out,platform)

test-qr-coverage:
	go test ./internal/qr/tests -coverpkg=./internal/qr -coverprofile=qr-coverage.out -covermode=atomic
	$(call assert_coverage,qr-coverage.out,qr)

test-render-coverage:
	go test ./internal/render/tests -coverpkg=./internal/render -coverprofile=render-coverage.out -covermode=atomic
	$(call assert_coverage,render-coverage.out,render)

test-singboxcheck-coverage:
	go test ./internal/singboxcheck/tests -coverpkg=./internal/singboxcheck -coverprofile=singboxcheck-coverage.out -covermode=atomic
	$(call assert_coverage,singboxcheck-coverage.out,singboxcheck)

test-sshd-coverage:
	go test ./internal/sshd/tests -coverpkg=./internal/sshd -coverprofile=sshd-coverage.out -covermode=atomic
	$(call assert_coverage,sshd-coverage.out,sshd)

test-store-coverage:
	go test ./internal/store/tests -coverpkg=./internal/store -coverprofile=store-coverage.out -covermode=atomic
	$(call assert_coverage,store-coverage.out,store)

test-sysctl-coverage:
	go test ./internal/sysctl/tests -coverpkg=./internal/sysctl -coverprofile=sysctl-coverage.out -covermode=atomic
	$(call assert_coverage,sysctl-coverage.out,sysctl)

test-systemd-coverage:
	go test ./internal/systemd/tests -coverpkg=./internal/systemd -coverprofile=systemd-coverage.out -covermode=atomic
	$(call assert_coverage,systemd-coverage.out,systemd)

test-version-coverage:
	go test ./internal/version/tests -coverpkg=./internal/version -coverprofile=version-coverage.out -covermode=atomic
	$(call assert_coverage,version-coverage.out,version)

test-protocol-coverage:
	@set -e; \
	pkgs="protocol protocol/auth protocol/testutil protocol/inbound protocol/listen protocol/socks5 protocol/httpproxy protocol/shadowsocks protocol/wireguard protocol/ech protocol/trojan protocol/vless protocol/vmess protocol/hysteria2 protocol/tuic"; \
	for pkg in $$pkgs; do \
		out=$$(echo "protocol-$${pkg}-coverage.out" | tr '/' '-'); \
		echo "=== $$pkg ==="; \
		go test ./internal/$$pkg/tests -coverpkg=./internal/$$pkg -coverprofile="$$out" -covermode=atomic; \
		pct=$$(go tool cover -func="$$out" | awk '/^total:/ {print $$3}' | tr -d '%'); \
		awk -v p="$$pct" -v min=$(COVERAGE_MIN) -v pkg="$$pkg" 'BEGIN { if (p+0 < min+0) { printf "protocol %s coverage %.1f%% < $(COVERAGE_MIN)%%\n", pkg, p; exit 1 } }'; \
	done

test-runtime-coverage:
	go test ./internal/runtime/tests -coverpkg=./internal/runtime -coverprofile=runtime-coverage.out -covermode=atomic
	$(call assert_coverage,runtime-coverage.out,runtime)

test-service-coverage:
	go test ./internal/service/tests -coverpkg=./internal/service -coverprofile=service-coverage.out -covermode=atomic
	$(call assert_coverage_verbose,service-coverage.out,service)

test-tui-coverage:
	go test ./internal/tui/tests -coverpkg=./internal/tui -coverprofile=tui-coverage.out -covermode=atomic
	$(call assert_coverage,tui-coverage.out,tui)

lint:
	@test -x '$(GOLANGCI_LINT)' || { \
		echo "golangci-lint not found. Install with:"; \
		echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		echo "Or add \$$(go env GOPATH)/bin to PATH."; \
		exit 1; \
	}
	$(GOLANGCI_LINT) run ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

integration:
	go test ./test/integration/... -tags=integration -count=1

docker-check:
	@docker info >/dev/null 2>&1 || { \
		echo "Docker: permission denied on /var/run/docker.sock."; \
		echo ""; \
		echo "If you just ran: sudo usermod -aG docker \"$$USER\""; \
		echo "  1. Log out and back in (or reboot), OR run: newgrp docker"; \
		echo "  2. Verify: groups | grep -w docker"; \
		echo "  3. Retry: make lab"; \
		echo ""; \
		echo "Do not use sudo make lab — it uses root's Docker context."; \
		exit 1; \
	}

lab: docker-check
	docker compose -f deploy/lab/docker-compose.yml up -d --build --wait
	@echo ""
	@echo "Lab is ready (systemd, ufw, obscura). Opening shell — exit bash to leave the container running."
	@echo "Tip: use --json on commands for readable output, e.g. obscura vpn list --json"
	@echo ""
	docker compose -f deploy/lab/docker-compose.yml exec -it obscura-lab bash

lab-shell: docker-check
	docker compose -f deploy/lab/docker-compose.yml exec -it obscura-lab bash

lab-smoke: docker-check
	docker compose -f deploy/lab/docker-compose.yml up -d --build --wait
	docker compose -f deploy/lab/docker-compose.yml exec -T obscura-lab /usr/local/bin/smoke.sh

lab-clean: docker-check
	docker compose -f deploy/lab/docker-compose.yml down -v --rmi local

e2e: docker-check
	$(MAKE) e2e-http
	$(MAKE) e2e-socks5
	$(MAKE) e2e-shadowsocks
	$(MAKE) e2e-trojan
	$(MAKE) e2e-wireguard
	$(MAKE) e2e-vmess
	$(MAKE) e2e-vless
	$(MAKE) e2e-hysteria2
	$(MAKE) e2e-tuic

e2e-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-http down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-socks5 down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-shadowsocks down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-trojan down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-wireguard down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-vmess down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-vless down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-hysteria2 down -v --remove-orphans || true
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-tuic down -v --remove-orphans || true

e2e-http: docker-check
	go test ./test/e2e/http/... -tags=e2e -count=1 -v -timeout 15m

e2e-socks5: docker-check
	go test ./test/e2e/socks5/... -tags=e2e -count=1 -v -timeout 15m

e2e-http-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-http down -v --remove-orphans

e2e-socks5-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-socks5 down -v --remove-orphans

e2e-shadowsocks: docker-check
	go test ./test/e2e/shadowsocks/... -tags=e2e -count=1 -v -timeout 15m

e2e-shadowsocks-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-shadowsocks down -v --remove-orphans

e2e-trojan: docker-check
	go test ./test/e2e/trojan/... -tags=e2e -count=1 -v -timeout 20m

e2e-trojan-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-trojan down -v --remove-orphans

e2e-wireguard: docker-check
	go test ./test/e2e/wireguard/... -tags=e2e -count=1 -v -timeout 20m

e2e-wireguard-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-wireguard down -v --remove-orphans

e2e-vmess: docker-check
	go test ./test/e2e/vmess/... -tags=e2e -count=1 -v -timeout 20m

e2e-vmess-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-vmess down -v --remove-orphans

e2e-vless: docker-check
	go test ./test/e2e/vless/... -tags=e2e -count=1 -v -timeout 20m

e2e-vless-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-vless down -v --remove-orphans

e2e-hysteria2: docker-check
	go test ./test/e2e/hysteria2/... -tags=e2e -count=1 -v -timeout 20m

e2e-hysteria2-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-hysteria2 down -v --remove-orphans

e2e-tuic: docker-check
	go test ./test/e2e/tuic/... -tags=e2e -count=1 -v -timeout 20m

e2e-tuic-clean: docker-check
	docker compose -f deploy/e2e/docker-compose.yml -p obscura-e2e-tuic down -v --remove-orphans
