# Validation

Local validation of `0.3.0a1` on 2026-11-14 used Python 3.12.14 on Linux. The unit/integration suite defines 227 test methods. Run it with isolated Python startup, which the trusted setup/launch paths require:

```bash
python3 -I -m unittest discover -s tests -v
```

| Platform | Executed methods | Platform-specific skips |
| --- | --- | --- |
| Linux/macOS | 201 | 26 native Windows methods |
| Native Windows | 115 | 112 POSIX-specific methods |

The [nine-job CI workflow](../.github/workflows/tests.yml) runs Python 3.11, 3.12, and 3.13 on Linux, macOS, and Windows. [PR #5 checks](https://github.com/DocBadTouch/Protection-Agency/pull/5/checks) record results for this milestone's commits. A skipped POSIX test is not Windows evidence. The native Windows jobs use local NTFS; this does not establish support for every Windows version or filesystem.

The tests cover the 12 published npm releases, nearby unflagged versions, selected source signatures, npm aliases, Python uv/Poetry/requirements parsing, private-source omission, invalid inventories, scan levels and budgets, symlink refusal, content-cache invalidation for same-size/same-mtime edits, OSV pagination/batching/failure handling, conservative command decisions, hook errors, and actual subprocess MCP stdio exchanges. Fixtures are inert; no malware is downloaded or executed.

The additional prevention suite first reproduced eight failures in the alpha. It now covers missing direct/transitive lock entries, stale declarations, workspace representation, nearest nested resolution, conflicting/unsupported constraints, malformed Python dependency shapes, proposed malicious install targets and aliases, registry privacy, batched target lookup, target/project coverage separation, structured startup configuration, cached parse failures, JSON comments, documentation context, the new MCP/CLI dependency tool, and offline diagnostics.

The 45 launch tests use an inert trusted client outside a temporary project. Marker files prove that refused/incomplete/expired/changed launches do not start that client and that allowed launches use the selected working directory, literal arguments, and exit status. They cover scanner errors, high-priority refusal, offline/advisory gaps, non-TTY/declined/interrupted review, same-size/same-mtime content changes, new startup files, replaced roots, executable changes, Git helper/hook/config layouts, child environment/PATH sanitization, and help/argument handling. One test performs an actual pseudo-terminal challenge exchange and verifies the marker is absent until the challenge is answered. No live malware or project hook is executed by inspection.

The 31 hook-integration tests edit owned temporary settings outside a temporary project. They cover semantic preservation, idempotence, dry runs, surgical uninstall after later edits, exact original-byte private backups, duplicate/malformed/over-budget JSON, symlinks/hardlinks/unsafe permissions, active/unsafe locks, concurrent content/directory changes, failed replacement, and post-commit sync failure. Project hook-disable controls block scans/install and invalidate diagnostics. Modified commands, matchers, async options, timeouts, duplicates, and failure policies are rejected without execution. Trusted subprocess probes validate deny/read/error responses; marker files establish that unrelated configured hooks and project Python startup code are not run. Timeout, malformed response, and settings-drift probes fail without exposing captured content. CLI setup/removal and argument requirements are exercised end to end.

The 35 onboarding tests cover the guided wizard's explicit online/installation choices, cancellation/EOF/nonterminal refusal, no-write preview, prompt-time settings drift, custom profiles, unsafe paths, failed post-install probes, safe shell hints, inert demo failures, readable scan/doctor/removal results, client discovery, project shadow/symlink rejection, literal client arguments, and marker-backed gate refusals/previews. Two additional real pseudo-terminal exchanges establish that wizard settings are absent until consent and that readable `open --review` does not start the inert client until the challenge is answered. They do not use a native Claude executable or exercise a model session.

The 21 agent tests cover capability reporting, profile selection, canonical Codex configuration, preservation/idempotence/removal, trusted probes, explicit deny/error behavior without unsupported `ask`, user/project hook-suppression controls, startup surfaces, guided agent selection, selected-client discovery, and package-shim identity normalization. They exercise adapter protocols without a native model session.

The 26 dedicated Windows tests cover Unicode bounded reads, native directory enumeration, required junction refusal, reserved/ADS/UNC/rooted path refusal, private original-byte backups, validated owner-rights ACLs, foreign-write rejection on files and parents, hard links, native locks, snapshot/concurrent-edit conflicts, replacement failure cleanup, post-commit flush warnings, cmd/PowerShell relay quoting with special source paths, both trusted adapter probes, native Python marker/literal-argument launches, refused/dry-run launches, batch refusal, setup function output, and inherited shell override rejection. Junction tests do not silently skip for lack of symlink privilege. The native client is an inert trusted executable, not Codex or Claude.

The suite uses deterministic OSV transport stubs. Empty public inventories in launch tests complete without external requests; hook protocol probes use offline fast paths even for online profiles. Live OSV access has not been validated in this workspace. No real Codex/Claude model session was exercised: native hook loading/trust, installed-version compatibility, timeout behavior, settings precedence, all execution-tool paths, and full MCP conformance testing remain outstanding. The Codex contract reference is `0.169.0`; Claude's failure-policy reference is `2.1.295`. These are implementation references, not detected client versions. Action pins were resolved from official GitHub action repositories on 2026-11-10.

Documentation review checks command/option names against actual CLI help, parses example JSON, compares the hook example with the canonical generated profile, verifies local links, and checks version references against source/package metadata. These checks establish documentation consistency, not real-client compatibility. See [Getting started](GETTING-STARTED.md), [Detailed usage](USAGE.md), and the [CLI reference](CLI.md) for the current operational contract. The five-minute first-time target has not been measured with uncoached newcomers; fewer review prompts have not been established by this milestone, and execution-review policy is unchanged.

## Synthetic performance check

The measurements below describe the original `0.1.0` alpha. A historical `0.2.0a1` measurement of the same fixture is recorded separately in [benchmark-v02.json](benchmark-v02.json), including the expanded coverage fields. Neither record measures the current `0.3.0a1` source. Each measurement consists of a cold scan and a repeat scan in the same Scanner process; none is a statistical or cross-machine comparison.

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
