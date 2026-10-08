# Security Policy

## Reporting a vulnerability

Please email con.stackhouse@gmail.com rather than opening a public issue.

## Dependency scanning

CI runs `pip-audit` against `requirements.txt` on every push and pull request. Any known
vulnerability fails the build unless it is listed in the register below with a documented decision.

## Accepted risk register

| ID | Package | Severity | Decision | Owner | Review by |
| --- | --- | --- | --- | --- | --- |
| PYSEC-2026-3740 / CVE-2026-81726 | nltk 3.10.3 | High (CVSS 4.0: 8.3) | Accept temporarily | Connor Stackhouse | 2027-01-07 |

### PYSEC-2026-3740: nltk path traversal in model-artifact APIs

**Issue.** Path traversal in nltk's model-artifact APIs (`TransitionParser`, `AveragedPerceptron`,
`PerceptronTagger`, and the maxent parameter APIs). Raw file operations on caller-controlled paths
bypass nltk's path-security enforcement, so an attacker could read or write files outside the allowed
directories.

**Exposure in this repo: not reachable.** The only nltk consumer is
`text-analysis/nltk_corpus_analyzer.py`, which uses `PlaintextCorpusReader`, `stopwords`,
`word_tokenize`, `nltk.Text`, and `nltk.data.find`/`nltk.download`. None of the affected parser, tagger,
or maxent APIs are imported or called. Confirmed with a code search on 2026-10-07.

**Why not upgrade.** 3.10.3 is the newest release. Advisory sources disagree on whether it contains the
fix (OSV lists 3.10.3 as fixed, while the advisory text and pip-audit treat it as affected), so there is
no release that clearly resolves the issue.

**Compensating control.** The exception covers this one advisory ID only (`--ignore-vuln` in
`.github/workflows/ci.yml`). Every other dependency vulnerability still fails the build.

**Exit criteria.** Remove the exception when either:
- nltk publishes a release that pip-audit no longer flags, then bump `requirements.txt`, or
- the code starts using any of the affected APIs, in which case this acceptance is void.

If neither has happened by the review date, re-check the advisory and renew or close this entry.
