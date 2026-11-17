# Backend protocol evidence — 2026-11-16

Scope: native Rust/std-only probe, task-owned directories under `target/protocol-probe-*`. No dependencies added, antivirus settings changed or remediation flags enabled. After successful protocol verification, the captured command/parser was implemented in `scanner/avast.rs`. The probe source is `target/protocol_probe.rs`; raw stdout, stderr and chunk timings are retained beside each scan directory.

Avast executable: `C:\Program Files\AVAST Software\Avast\ashCmd.exe`, file/product version **26.8.11125.0**. Rust probe compiled with rustc 1.100.0.

## Established Avast clean behavior

Capture directory: `target/protocol-probe-clean-1794850118227684400`.

Arguments: absolute Unicode scan directory followed by `/_ /a /p=4 /s /e=0 /t=A`; stdin null, both pipes captured, hidden child window.

Inputs: harmless 67-byte EML and empty EML. Both remained byte-for-byte unchanged. Exit code 0; 7.095 seconds total, stdout first arrived at 7.070 seconds as a single 483-byte chunk. This small fixture does not establish streaming before completion.

Each file record is absolute path, TAB, `OK`, CRLF. Both the harmless file and empty file received `OK`. Aggregate German lines are prefixed `#`, including checked file count 2, directory count 1, infected count 0 and byte count 67. stderr empty.

stdout is not UTF-8. In the Unicode parent `Grüße`, the raw bytes are `47 72 FC DF 65`. This is compatible with Windows-1252/Latin-1 for those characters, but does not establish a general code-page contract. Do not globally assume this mapping or use lossy UTF-8 for path attribution. The original raw bytes are in `stdout.bin`.

## Positive Avast attempts — no usable detection contract

Each positive fixture directory contained the harmless and empty EML plus two standard non-malicious EICAR test files. All four files remained byte-for-byte unchanged after each attempt.

1. `target/protocol-probe-positive-1794850182070145100`: absolute target with the same arguments as the clean probe. No stdout/stderr was captured. The probe requested termination and eventually confirmed exit code 1 with `terminated=true`; total duration 231.996 seconds. The original probe did not separately time process creation, so the long delay cannot be confidently assigned to scan work versus process creation/termination. **Exit 1 was forced and is not detection evidence.**
2. `target/protocol-probe-dontpanic-1794850699134774900`: cwd set to the Unicode scan directory, target `.`, arguments `/_ /a /s /e=0 /t=A /d` (no `/p` remediation flag). Spawn returned at 10.281 seconds. No stdout/stderr arrived within 60 seconds after spawn. Kill requested at 70.379 seconds; wait subsequently confirmed exit code 1 with `terminated=true`, total 139.061 seconds. **Neither continuation nor positive grammar was established.**

At this stage no positive/error/archive output syntax had been captured and continuation was unresolved. The later MIME-contained probes below establish those facts without confusing resident protection with command behavior. A production directory parser must never treat every batch member as infected from exit status.

## Final absolute-target /d probe (working host runtime)

Capture directory: `target/protocol-probe-absolute-dontpanic-1794851869268124600`. Absolute Unicode directory; `/_ /a /s /e=0 /t=A /d`, null stdin, captured pipes. Child PID 6232 spawned in 32 ms. Normal exit 1 at 9.578 seconds; first stdout chunk arrived at 9.572 seconds (996 bytes), stderr empty. This tiny fixture does not prove records arrive materially before process completion.

Observed records: clean/empty files use `path<TAB>OK`; detected fixture uses `path<TAB>EICAR Test-NOT virus!!!`; a second fixture uses `path<TAB>ERR<TAB>Das System kann die angegebene Datei nicht finden`. A scanner-created `unp12337726518589203273.tmp` path also reported ERR. Summaries remain comment-prefixed German text. Raw output is not UTF-8.

**Integrity gate failed:** both EICAR test files failed the post-scan byte-equality check, whereas harmless and empty EMLs remained unchanged. Do not adopt `/d` alone as non-remediating. The observation does not distinguish the command's own actions from concurrent resident antivirus protection. This run captures positive/error grammar but does not establish safe batch continuation. No antivirus settings were changed.

## Explicit /p=4 plus /d and pre-launch integrity

Capture directory: `target/protocol-probe-p4-dontpanic-1794851961804759200`. Absolute target; `/_ /a /s /e=0 /t=A /p=4 /d`. Added a harmless nonempty end sentinel. Before starting ashCmd, both EICAR files had already disappeared/failed byte equality, while all three harmless files were intact. Thus this environment's resident protection interferes with raw EICAR fixtures independently of the command under test.

Child PID 3040 spawned in 7 ms; normal exit 0 at 3.049 seconds; first stdout 609 bytes at 3.043 seconds. Only the three harmless files were scanned, all receiving OK and remaining unchanged. **This is not evidence of continuation after detection.** No product setting/exclusion was altered.

## MIME-contained EICAR: non-remediation established, continuation disproved

Capture directory: `target/protocol-probe-mime-p4-1794852074719221500`. Two base64 MIME-contained EICAR messages avoid the resident protection's removal of raw EICAR files. Also included a harmless first EML, empty EML and harmless end sentinel. Every file was byte-identical before child spawn and after exit.

Absolute directory with `/_ /a /s /e=0 /t=A /p=4 /d`; child PID 7668 spawned in 4 ms. Normal exit 1 at 5.966 seconds, first stdout at 5.959 seconds as one 785-byte chunk; no stderr.

Observed exact record grammar (outer path abbreviated here; original bytes retained):

- `100-test.eml|>PartNo_0#925606545<TAB>OK`
- `100-test.eml|>standard-test.txt#943030176<TAB>EICAR Test-NOT virus!!!`
- `100-test.eml<TAB>ERR<TAB>Error 0x0000A41B`

The first harmless EML was scanned, then the first encoded message's attachment was detected. **The second encoded message, empty file and end sentinel were never scanned.** Thus `/p=4 /d` preserves these originals but still stops at the first detection; it is not a verified continuing batch invocation. Nested resource paths use `|>` followed by member name and a numeric `#` suffix. Outer-path ERR and a prior positive coexist and must not erase each other. No settings were changed.

## Verified continuing invocation: MIME fixtures with /d and no /p

Capture directory: `target/protocol-probe-mime-donly-1794852141417188300`. Absolute directory followed by `/_ /a /s /e=0 /t=A /d` with null stdin, no `/p` argument. Same five-file set as the prior probe: two encoded EICAR EMLs, first harmless EML, empty EML and last harmless sentinel. **All five files were byte-identical immediately before process creation and after normal exit.**

Child PID 4216 spawned in 5 ms; normal exit 1 at 5.810 seconds. One 1392-byte stdout chunk at 5.804 seconds, empty stderr. Both EICAR messages were detected and all following inputs were scanned. Thus this installed version/fixture establishes continuing non-remediating directory behavior with `/d` and without `/p=4`. It supersedes the earlier unresolved continuation gate. Resident protection can still independently remove raw test files, as the pre-launch checks established.

For each encoded message the sequence was nested harmless part OK; nested `standard-test.txt#943030176` named EICAR detection; then outer EML OK. **Outer OK is successful container traversal and does not contradict a nested detection.** Nested records must not independently establish that the entire outer input finished. Keep per-file coverage separate from positive evidence.

The clean and positive probe sets both used a Unicode directory. `Get-WinSystemLocale` and `Get-Culture` report de-DE with ANSI code page 1252; captured ü/ß bytes FC/DF agree. Any implementation supporting this captured Windows-1252 profile must be explicit about that support; this is not evidence of universal automatic locale/encoding detection. Tiny probes buffered output until near exit, so they prove correct pipe records but not early per-file flushing by Avast.

## Relative-target failure result (earlier run)

Capture directory: `target/protocol-probe-clean-relative-1794850820721399600`.

cwd set to the Unicode scan directory, target `.`, arguments `/_ /a /s /e=0 /t=A /p=4`. Harmless and empty inputs remained unchanged. Spawn 122 ms; stderr arrived at 1.676 seconds; normal exit 42003 at 1.782 seconds. stdout empty. stderr: `!!!!!!!!!!!!!internal error!!!!!!!!!!!!!!!` followed by CRLF.

This does not establish that relative targets are generally unsupported; it establishes that the tested invocation failed in this environment. Do not adopt relative paths solely to avoid encoding issues without another verified contract.

## Defender unavailable locally

Executable selected from installed platform directory: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2107.4-0\MpCmdRun.exe`.

Arguments: `-Scan -ScanType 3 -File <task-owned Unicode directory> -DisableRemediation`. Both sandboxed and outside-sandbox attempts failed normally with exit 2 and `CmdTool: Failed with hr = 0x80004005`. The outside-sandbox invocation completed in 820 ms; inputs unchanged.

The existing `MpCmdRun.log`, read as UTF-16, explicitly records `WARN: Product/Feature disabled` for the attempt. No Defender service/settings were changed. Captures:

- `target/protocol-probe-defender-clean-1794850183216771100`
- `target/protocol-probe-defender-clean-1794850240667967000`

No new Defender directory attribution/coverage contract can be claimed. Parent reports the user approved retaining the existing per-message Defender path; no additional Defender probe was run after that instruction.

## Process and validation status

All launched probe sessions have returned; positive children were confirmed reaped after forced termination. Their exit values are not genuine scan verdicts. A separate CIM inventory request was denied by the environment, so no wider process inventory is claimed. Fixtures were retained to preserve evidence and avoid unsafe cleanup while termination was uncertain.

Standalone probe compilation succeeded. Files under target are exploratory artifacts, not runtime requirements or distributable sidecars.

## New pipeline integration checks

Executed against the new directory scanner and batch builder:

- Seven Avast parser/command tests passed.
- Two accumulator regressions passed: nested detection then outer OK remains complete positive; nested OK alone cannot establish outer completion.
- Ignored installed-Avast clean integration passed: one directory scan of four prepared files, complete clean reports, all input bytes unchanged.
- Ignored installed-Avast MIME integration attributed both encoded messages, left the clean sentinel undetected, and preserved all original EML bytes. All three reports were conservatively incomplete. The initial test then failed its overly strict empty-cleanup assertion; retained directory was `C:\Users\Rahnit\AppData\Local\Temp\toolbox-directory-test-31480-1794854825588419800-0\batch-31480-1794854825589118100-0`. A later read-only listing showed that directory empty, so the exact transient cleanup obstacle is not established. No unknown files were deleted.

The ignored MIME test was corrected to preserve the positive-attribution and unchanged-original assertions, print coverage reasons, and explicitly report narrowly bounded retained paths rather than demanding that installed antivirus activity never interferes with cleanup. That final test edit has not yet been rerun by this subtask; the root agent owns final test execution to avoid concurrent linker/file locks. The exact filter is `installed_avast_mime_batch_preserves_attribution_or_rejects_resident_interference` with `--ignored --nocapture --test-threads=1`.
