# vuln-triage progress

## Milestones
- [x] 0. Setup: OpenAI API key (env only, never committed), gh CLI logged in as LorenzoAPB, local git repo, Python 3.13 venv
- [ ] 1. Pydantic schema + single structured-output call
- [ ] 2. CVSS computed in code + guardrails (evidence, unknowns, low confidence, non-report refusal)
- [ ] 3. Human approve/edit/reject on CLI + JSONL logging/telemetry
- [ ] 4. Eval set (30-60 public/synthetic reports) + metrics, one command
- [ ] 5. pytest (API mocked) + GitHub Actions (lint, tests, cheap eval)
- [ ] 6. README, architecture diagram, results, demo recording, polish

## Session log
- 2026-11-11: Milestone 0 done. Deps: openai 3.49.0, pydantic 2.14.3, cvss 3.6 (RedHat lib; sanity check AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical), pytest, ruff. No GitHub remote yet (create private repo before first push, with Lorenzo's OK).

## Weak spots to revisit
- (none yet)
