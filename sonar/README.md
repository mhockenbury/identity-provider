# SonarCloud issues export

Pulls every issue from a SonarCloud project into a local `.xlsx` or
`.csv` for review.

Adapted from upstream:
<https://github.com/talha2k/sonarqube-issues-export-to-excel>.

**Local change**: token is optional. Public SonarCloud projects allow
anonymous reads on `/api/issues/search`, so we skip the Authorization
header when `SONAR_TOKEN` is unset. Set the token for private projects
or to bypass anonymous rate limits.

Outputs (`sonar/sonarqube_issues.*`) are gitignored.

## Setup

`make sonar-export` creates a local Python venv at `sonar/.venv/` on
first run and installs the three deps (`requests`, `pandas`,
`openpyxl`) into it. The venv is gitignored. No global Python install
gets touched.

## Configure

Three env vars. Add to `/tmp/idp-env` (already gitignored) or set
inline:

```bash
export SONAR_URL='https://sonarcloud.io/api/issues/search'
export SONAR_PROJECT_KEY='mhockenbury_identity-provider'
export SONAR_TOKEN='<your-sonarcloud-user-token>'
```

Generate a token at <https://sonarcloud.io/account/security>. Treat
it like a password — never commit, never paste in chat. Rotate
immediately if exposed.

## Run

```bash
make sonar-export             # xlsx (default)
make sonar-export FMT=csv     # csv
```

Or directly:

```bash
python3 sonar/sonar_export.py
python3 sonar/sonar_export.py --format csv
```

Output lands at `sonar/sonarqube_issues.xlsx` (or `.csv`) in the repo
root, gitignored.

## Notes

- The script walks 30-day windows from 2000-01-01 to today; for a
  brand-new project this is wasteful but harmless. ~5 seconds.
- Includes ALL issues — open, resolved, false-positive, etc. Filter
  in the spreadsheet rather than at fetch time.
- Hits SonarCloud's free-tier rate limits with very chatty projects;
  if that happens add a `time.sleep(0.1)` between page requests.

## Refresh + triage workflow

When asked to "review SonarCloud" — refresh the export first, then
triage. Don't review the stale CSV.

### 1. Refresh

`make sonar-export FMT=csv` requires `SONAR_PROJECT_KEY` (and
optionally `SONAR_URL`, `SONAR_TOKEN`) in the environment. `/tmp/idp-env`
does **not** contain these by default — it holds runtime secrets, not
sonar config. Two ways to refresh:

```bash
# Inline (works without editing /tmp/idp-env)
cd sonar && SONAR_URL='https://sonarcloud.io/api/issues/search' \
  SONAR_PROJECT_KEY='mhockenbury_identity-provider' \
  .venv/bin/python sonar_export.py --format csv

# Or add the two SONAR_* exports to /tmp/idp-env, then:
set -a && source /tmp/idp-env && set +a && make sonar-export FMT=csv
```

Public project, anonymous reads work — no token needed for refresh.

### 2. Triage (use the venv's pandas, not a one-off install)

The venv created by `make sonar-export` already has pandas. From
`sonar/`:

```bash
.venv/bin/python <<'EOF'
import pandas as pd
df = pd.read_csv("sonarqube_issues.csv")
open_df = df[df['issueStatus'] == 'OPEN']
print("Open:", len(open_df))
print(open_df['severity'].value_counts())
print(open_df['type'].value_counts())
# Group BLOCKER/CRITICAL + all VULNERABILITY by rule, then list file:line
EOF
```

### 3. What to flag (signal vs. noise on this project)

- **Always inspect**: `type == VULNERABILITY` and `severity == BLOCKER`.
  Most are likely false positives in a lab project (dev creds in
  `docker-compose.yml`, `Secure` cookie flag bound to issuer scheme),
  but verify in source before dismissing.
- **Real signal**:
  - `go:S3776` (cognitive complexity) — points at the gnarliest
    functions; worth a human look.
  - `shelldre:S7677` (errors to stderr) — legit bug class in scripts.
  - `go:S1192` (duplicate literals) — only worth extracting for the
    most-repeated ones (e.g. shared route paths).
- **Usually noise on this project**:
  - `secrets:S6698` / `yaml:S2068` on `docker-compose.yml` — local-only
    dev creds on a private docker network. Mark "Won't Fix / Safe" in
    the SonarCloud UI rather than rotating the CSV.
  - `go:S2092` on `internal/http/session.go` — `Secure` is already
    bound to `ISSUER_URL` scheme via a `secure bool` param.
  - `godre:S8196` (single-method interface naming) — Sonar's Go
    opinions are often non-idiomatic; ignore unless it actually reads
    weird.
  - `shelldre:S7688` (`[[ ]]` vs `[ ]`) — mechanical, low-value churn.
  - TypeScript style nits (`S6582`, `S3358`, `S7781`, `S4325`) — only
    fix opportunistically.

### 4. Output format

When summarizing for the user: severity table, then "what matters" /
"false positives" / "skip" buckets with file:line for anything they'd
need to act on. Don't list all 100+ issues.
