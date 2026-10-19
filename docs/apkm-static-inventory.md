# APKM read-only static inventory helper

**scripts/apkm-static-inventory.py** is an **experimental, standalone companion script** for inventorying an APKM-style ZIP that contains exactly one root-level **base.apk** and optional split APKs. It is not a REA CLI/MCP workflow and does not replace REA's Android/JADX analysis.

The helper writes a JSON report and a Markdown report with:

- the outer archive SHA-256 and per-member hashes/sizes;
- ZIP integrity results and APK split names;
- each APK's DEX filenames, manifest presence and native-library paths;
- explicit limitations so per-member inventory is not presented as merged split evidence.

## Run

Requires Python 3.10 or later and only the Python standard library. No APK is installed, executed, patched, signed, or extracted to disk. The script reads archive members into memory and writes report files only to a new output directory.

~~~sh
python scripts/apkm-static-inventory.py /path/to/download.apkm --out apkm-report
~~~

The output directory must not already exist. The accepted shape is intentionally narrow: one root-level **base.apk** plus zero or more **.apk** members. This prototype does not claim support for AAB, XAPK, or every APKS/APKM variation.

The parser applies entry-count, member-size, total uncompressed-size, manifest-size and DEX-size bounds. It rejects ambiguous duplicate paths, path-traversal names and malformed embedded ZIPs. Those checks are defensive triage, not APK authenticity verification. A successful CRC/ZIP check does not establish publisher identity or benign behavior.

## Tests

Run the standalone regression tests with:

~~~sh
python scripts/apkm-static-inventory.test.py
~~~

The fixtures cover a valid minimal base-plus-split bundle and selected malformed/ambiguous inputs. They are unit tests, not integration tests against JADX or a production APKM download.

## Scope and interpretation

The report does **not** decode manifest attributes, inspect DEX table contents or method bodies, resolve Android resources, verify APK signing certificates/signing-blocks, inspect runtime behavior, or combine manifests, resources, code, or evidence across splits. Run REA/JADX against each relevant APK member and preserve its SHA-256 when producing code-level conclusions.

This is an exploratory helper aligned with the questions in [upstream issue #1813](https://github.com/morluto/rea/issues/1813). Existing upstream work is also tracking split-set consistency and compiled-manifest parsing; this helper intentionally does not duplicate those features inside the application architecture.
