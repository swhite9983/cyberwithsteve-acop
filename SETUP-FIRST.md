# One-time setup on the Ubuntu host

Two things could not be written directly into `M:\ACOP` by the remote file
bridge, because `Makefile` is a protected filename. Both are one command each.

## 1. Restore the Makefile

The file was delivered as `scripts/acop.mk`. On the deployment host:

```bash
mv scripts/acop.mk Makefile
```

(or `make -f scripts/acop.mk <target>` if you prefer to leave it where it is.)

## 2. Initialise the git repository

```bash
cd /path/to/acop
git init
git add -A
git status                    # confirm .env is NOT listed
git commit -m "Milestone 1: ACOP foundation

FastAPI + PostgreSQL + Alembic + Ollama client + health reporting.
Adds provider-neutral identity and an append-only audit log ahead of the
brief, per docs/ARCHITECTURE-REVIEW.md.

Verified: ruff clean, mypy strict clean, 111 tests passing, migrations
applied and rolled back against PostgreSQL 16, live server exercised
end to end including dependency-failure behaviour."
git branch -M main
git remote add origin <your-gitea-or-github-remote>
git push -u origin main
```

**Before the first commit**, confirm your secrets are excluded:

```bash
git check-ignore -v .env      # must print a match
git ls-files | grep -i env    # should show only .env.example
chmod 600 .env
```

## 3. Bring the stack up

```bash
cp .env.example .env
# edit .env: ACOP_POSTGRES_PASSWORD, ACOP_OLLAMA_BASE_URL, ACOP_OLLAMA_MODEL, ACOP_API_KEYS
make up
make ps
ACOP_VERIFY_API_KEY=<your key> make verify
python scripts/check_qwen.py
```

Full detail in `README.md`.
