# Validation

Local validation of `0.2.0a1` on 2026-11-13 used Python 3.12.14 on Linux. The unit/integration suite has 69 test methods and passes with:

```bash
python3 -I -m unittest discover -s tests -v
```

The tests cover the 12 published npm releases, nearby unflagged versions, selected source signatures, npm aliases, Python uv/Poetry/requirements parsing, private-source omission, invalid inventories, scan levels and budgets, symlink refusal, content-cache invalidation for same-size/same-mtime edits, OSV pagination/batching/failure handling, conservative command decisions, hook errors, and actual subprocess MCP stdio exchanges. Fixtures are inert; no malware is downloaded or executed.

The additional prevention suite first reproduced eight failures in the alpha. It now covers missing direct/transitive lock entries, stale declarations, workspace representation, nearest nested resolution, conflicting/unsupported constraints, malformed Python dependency shapes, proposed malicious install targets and aliases, registry privacy, batched target lookup, target/project coverage separation, structured startup configuration, cached parse failures, JSON comments, documentation context, the new MCP/CLI dependency tool, and offline diagnostics.

The suite uses deterministic OSV transport stubs. A live OSV response has not been verified in this workspace because outbound shell networking requires additional environment permission. Client-specific testing inside a live Claude Code session and full MCP conformance testing are still outstanding. The original alpha passed GitHub CI. The updated workflow targets Python 3.11, 3.12, and 3.13 on Linux and macOS; check the actual PR run for its result. Action pins were resolved from official GitHub action repositories on 2026-11-10.

## Synthetic performance check

The measurements below describe the original `0.1.0` alpha. A new measurement of the same fixture is recorded separately in [benchmark-v02.json](benchmark-v02.json), including the expanded coverage fields. Each measurement consists of a cold scan and a repeat scan in the same Scanner process; none is a statistical or cross-machine comparison.

A temporary project contained 2,500 synthetic npm lock entries and 500 benign JavaScript files, totaling 1,082,824 input bytes across 501 files. On this workspace:

| Measurement | Result |
| --- | --- |
| First standard offline scan | 183.06 ms |
| Repeat scan in the same Scanner process | 54.61 ms |
| Compact result size | 274 characters |
| Repeat scan static cache hits | 501 files |

The result correctly remained `review` because advisories were offline. [benchmark.json](benchmark.json) records the measured summary. These are two illustrative measurements on one synthetic fixture, not a statistical benchmark, a token count, or a malware-detection-rate estimate. Network latency is excluded. Large repositories, many findings, deep scans, different hardware, and online checks will cost more.

The scanner makes no LLM calls. MCP tool definitions and results still consume the connected agent's context tokens. A findings-heavy report is larger, and details are paginated separately. Hook invocations start new processes, so their static cache does not persist across commands.

Before a stable release: independent security review, parser fuzzing, legitimate-project false-positive measurements, isolated adversarial fixtures, and real client/sandbox integration are needed.
