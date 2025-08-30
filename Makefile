#!/usr/bin/make -f

.DEFAULT_GOAL := help

CPUS=1

MINIMUM_COVERAGE=99

.env: ## Make the dotenv file in a dev environment
	@cp .env.dev .env

.PHONY: mypy
mypy: ## Show typing errors in changed files.
	@git diff --diff-filter=d --name-only --exit-code origin/main  '*.py' > /dev/null  || mypy --pretty $$(git diff --diff-filter=d --name-only origin/main  '*.py' | tr "\n" ' ')


.PHONY: mypy
mypy_all: ## Show typing errors in all files.
	@mypy --pretty --exclude conftest.py .


.PHONY: lint_import_sorting
lint_import_sorting:  ## Check imports are in the correct order
	@git diff --diff-filter=d --name-only --exit-code origin/main  '*.py' > /dev/null || isort -c $$(git diff --diff-filter=d --name-only origin/main '*.py')


.PHONY: lint_unused_imports
lint_unused_imports:  ## Check for any unused imports
	@git diff --diff-filter=d --name-only --exit-code origin/main  '*.py' > /dev/null || flake8 --select=F401 --per-file-ignores='__init__.py:F401' $$(git diff --diff-filter=d --name-only origin/main '*.py')


.PHONY: lint_code_style
lint_code_style:  ## Check the code conforms with `black` code style.
	@git diff --diff-filter=d --name-only --exit-code origin/main  '*.py' > /dev/null || black --check $$(git diff --diff-filter=d --name-only origin/main '*.py')
	@git diff --diff-filter=d --name-only --exit-code origin/main  '*.ipynb' > /dev/null || black --check $$(git diff --diff-filter=d --name-only origin/main '*.ipynb')


.PHONY: lint
lint: lint_import_sorting lint_unused_imports lint_code_style ## Lint any changed files.
	:


.PHONY: remove_unused_imports
remove_unused_imports: ## Remove any unused import statements.
	@git diff --diff-filter=d --name-only --exit-code origin/main '*.py' > /dev/null || autoflake --in-place --remove-unused-variables  --remove-all-unused-imports --ignore-init-module-imports $$(git diff --diff-filter=d --name-only origin/main '*.py')
	@git diff --diff-filter=d --name-only --exit-code origin/main '*.ipynb' > /dev/null || autoflake --in-place --remove-unused-variables  --remove-all-unused-imports --ignore-init-module-imports $$(git diff --diff-filter=d --name-only origin/main '*.ipynb')


.PHONY: sort_imports
sort_imports:  ## Sorts imports alphabetically
	@git diff --diff-filter=d --name-only --exit-code origin/main '*.py' > /dev/null || isort $$(git diff --diff-filter=d --name-only origin/main '*.py')
	@git diff --diff-filter=d --name-only --exit-code origin/main '*.ipynb' > /dev/null || isort $$(git diff --diff-filter=d --name-only origin/main '*.ipynb')


.PHONY: apply_code_style
apply_code_style: ## Apply the `black` code style.
	@git diff --diff-filter=d --name-only --exit-code origin/main  '*.py' > /dev/null || black $$(git diff --diff-filter=d --name-only origin/main '*.py')
	@git diff --diff-filter=d --name-only --exit-code origin/main  '*.ipynb' > /dev/null || black $$(git diff --diff-filter=d --name-only origin/main '*.ipynb')


.PHONY: fmt
fmt: remove_unused_imports sort_imports apply_code_style ## Format any changed files
	:

.PHONY: test_all
test_all: ## Run all the tests.
	pytest --cov=. --cov-report=html --cov-fail-under=$(MINIMUM_COVERAGE) -Werror .


.PHONY: migrate
migrate:  ## Run migrations
	flask db upgrade

.PHONY: check_migrations
check_migrations: migrate## Check if alembic revision command with autogenerate has pending upgrade ops.
	flask db check

.PHONY: ci
ci: .env lint mypy_all check_migrations test_all ## Run all check that would be run in CI
	:

.PHONY: local_run
local_run: .env migrate ##  Run the app locally
	flask run --debug --port 8080

.PHONY: recreate_db
recreate_db:  ## Recreate the database
	flask shell <<< 'from db import db; db.drop_all(); db.create_all()'

.PHONY: schemathesis
schemathesis:  recreate_db  ## Use schemathesis to test the API
	schemathesis run http://127.0.0.1:8080/docs/openapi.json --generation-unique-inputs --output-sanitize false

.PHONY: jwt
jwt: ## Use schemathesis to test the API
	@flask jwt

.PHONY: help
help: ## Display this help text
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

