# Secrets handling

Section 24 of the design brief: secrets must never be stored in source code,
git, prompts, RAG documents, logs, or CMDB records.

## Current state (Milestone 1)

### Where secrets live

| Secret | Storage | Notes |
|---|---|---|
| PostgreSQL password | `ACOP_POSTGRES_PASSWORD` in `.env` | `.env` is git-ignored |
| API key secrets | `ACOP_API_KEYS` JSON in `.env` | Plaintext; see limitations |

Nothing else is a secret in Milestone 1. ACOP holds no device credentials, no
SNMP community strings, and no SSH keys — because it has no integrations yet.

### Controls in place

**Typed as secrets.** Every credential field is `pydantic.SecretStr`, so it is
redacted in reprs, tracebacks, and any structured payload that renders the
settings object. A test asserts the password does not appear in `repr(settings)`.

**Redaction in two independent paths.** `acop.core.redaction` masks
secret-bearing keys, and it is applied both as a structlog processor (every log
line) and in `AuditService.record` (every audit row). Two paths rather than one
because the audit log outlives log retention.

Recognised key fragments include `password`, `secret`, `token`, `api_key`,
`authorization`, `credential`, `private_key`, `ssh_key`, and `community` (SNMP).

**Deliberate exclusion:** `hash` is *not* treated as a secret fragment.
Configuration hashes are first-class evidence for drift detection in Milestone 7
and must remain readable. `password_hash` is still covered by the `password`
fragment.

**Constant-time comparison.** API keys are compared with
`secrets.compare_digest`, and every configured key is compared rather than
breaking on first match, so response time does not reveal a key's position in
the configured list.

**No credentials in error output.** The health report and every error response
carry a categorical message and a correlation ID, never raw driver or upstream
error text. Tests assert the database password and the string `asyncpg` are
absent from responses.

**Git hygiene.** `.gitignore` excludes `.env`, `*.pem`, `*.key`, `*.crt`,
`id_rsa*`, `id_ed25519*`, `secrets/`, `credentials/`, `*.kdbx`, and the
`knowledge/discovered/` and `knowledge/imported/` trees, which will hold
discovered infrastructure data containing hostnames and addresses.

## Known limitations, and when each is resolved

| Limitation | Risk | Accepted because | Resolved by |
|---|---|---|---|
| API key secrets are plaintext in `.env` | Filesystem read discloses credentials | ACOP holds no credential that can change infrastructure | Secrets manager, before Milestone 12 |
| No credential rotation, expiry, or revocation list | A leaked key is valid indefinitely | Single operator, single key, not internet-exposed | Identity provider integration |
| No rate limiting on authentication attempts | Online guessing | Not internet-exposed; keys are 256-bit | Before any external exposure |
| No TLS between ACOP and PostgreSQL | Traffic readable on the host network | Same Docker host, private bridge network | If the database moves to a separate host |
| `.env` is world-readable if permissions are not set | Local disclosure | Single-admin host | `chmod 600 .env` — do this now |

The comparison is already constant-time, so moving to hashed storage is a
storage change rather than a logic change.

## Target state

**Before Milestone 12** — the first milestone in which ACOP can change
infrastructure, and therefore the first in which it holds credentials worth
stealing:

1. Integrate OpenBao (already running in the lab).
2. ACOP authenticates to OpenBao with AppRole; the role ID and a wrapped secret
   ID are the only values in the environment.
3. Device credentials, API tokens and the database password are fetched at
   startup and on a lease-renewal schedule, never written to disk.
4. Audit every secret retrieval — OpenBao's own audit device plus an ACOP audit
   record, so a credential fetch appears in the same timeline as the action that
   needed it.

**Mapping.** NIST CSF PR.DS-1, PR.DS-5, PR.AC-1. CIS Controls 3.11 (encrypt
sensitive data at rest), 5.2 (unique passwords), 6.5 (MFA for administrative
access — via the identity provider, later).

## Operator checklist

```bash
chmod 600 .env                    # restrict the environment file
git check-ignore -v .env          # confirm it is ignored before the first commit
git log --all --full-history -- .env   # confirm it was never committed
openssl rand -hex 32              # generate an API key
openssl rand -base64 32           # generate a database password
```

If a secret is ever committed, rotate it. Removing it from history does not
un-disclose it.
