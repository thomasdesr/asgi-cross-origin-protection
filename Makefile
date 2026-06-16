.PHONY: dev lint format test mutants build

dev:
	uv sync --all-groups
	prek install

# prek is the single entry point: it runs ruff, ty, zizmor, and the file checks,
# fixing what it can. The same hooks run on every commit.
lint:
	prek run --all-files

format:
	uv run ruff format .

test:
	uv run pytest

# Mutation testing. PYTEST_ADDOPTS disables the coverage gate, which every
# mutant trips (instrumented coverage drops below the 100% fail-under).
mutants:
	PYTEST_ADDOPTS="--no-cov" uv run --group mutation mutmut run

build:
	uv build
