"""Drive a real CLI session for the README recording. Not part of the package.

  pip install asciinema pexpect   # plus agg: https://github.com/asciinema/agg
  asciinema rec --cols 110 --rows 34 -c "python docs/record_demo.py" docs/demo.cast
  agg docs/demo.cast docs/demo.gif

It replays recorded responses from the v3 held-out eval run on gpt-4o-mini
(VULN_TRIAGE_CACHE=evals/recordings, --model gpt-4o-mini), so it makes no API calls.
"""

import os
import sys
import time

import pexpect

ENV = {**os.environ, "VULN_TRIAGE_CACHE": "evals/recordings"}


def type_out(text: str, delay: float = 0.04) -> None:
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)


def run(command: str, answers: list[tuple[str, str]]) -> None:
    """Show `command` at a prompt, run it, and answer each (prompt, reply) in order."""
    type_out("$ ", 0)
    type_out(command + "\n")
    child = pexpect.spawn("bash", ["-c", command], env=ENV, encoding="utf-8", dimensions=(34, 110))
    child.logfile_read = sys.stdout
    for prompt, reply in answers:
        child.expect_exact(prompt)
        time.sleep(1.2)
        for ch in reply:
            child.send(ch)
            time.sleep(0.06)
        child.send("\r")
    child.expect(pexpect.EOF)
    time.sleep(2)


run(
    "vuln-triage triage --model gpt-4o-mini examples/CVE-2023-22771.txt",
    [
        ("[r]eject > ", "e"),
        ("Field", "vector"),
        ("New value > ", "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N"),
        ("[r]eject > ", "a"),
    ],
)
run(
    "vuln-triage triage --model gpt-4o-mini examples/synthetic-thin-xss.txt",
    [("[r]eject > ", "r"), ("Reason > ", "asked reporter for repro steps")],
)
run("tail -n 2 logs/triage.jsonl | jq -c '{decision, reject_reason, changed: (.overrides | keys)}'", [])
