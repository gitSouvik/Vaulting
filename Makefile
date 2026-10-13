.PHONY: all build clean test bench demo lint docker-up docker-down

PYTHON ?= python3

all: build test

build:
	@echo "==> Building C core library..."
	$(MAKE) -C c_src all

clean:
	@echo "==> Cleaning build artifacts and cache..."
	$(MAKE) -C c_src clean || true
	rm -rf *.egg-info build dist .pytest_cache .hypothesis .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name ".DS_Store" -delete

test: build
	@echo "==> Running pytest test suite..."
	$(PYTHON) -m pytest tests/ -v

test-fast: build
	@echo "==> Running fast test suite..."
	$(PYTHON) -m pytest tests/ -q

bench: build
	@echo "==> Running Aho-Corasick scanner benchmark..."
	$(PYTHON) benchmarks/bench_scanner.py
	@echo ""
	@echo "==> Running key rotation benchmark..."
	$(PYTHON) benchmarks/bench_rotation.py

demo: build
	@echo "==> Running live end-to-end leak & rotation demo..."
	$(PYTHON) -m demo.run_demo

lint:
	@echo "==> Running linter..."
	ruff check vaulting/ tests/ benchmarks/

docker-up:
	@echo "==> Starting Vaulting observability stack..."
	docker compose up -d

docker-down:
	@echo "==> Stopping Vaulting stack..."
	docker compose down
