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
