#!/usr/bin/env python3
"""Read-only inventory of APKM-style ZIP bundles containing a base APK and splits.

This experimental companion records container/member identities and basic APK
structure. It does not install or execute APKs, extract them to disk, decompile
methods, verify signing certificates, or merge evidence across splits.

Usage: python scripts/apkm-static-inventory.py bundle.apkm --out apkm-report
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

MAX_ARCHIVE_UNCOMPRESSED = 1_000_000_000
MAX_MEMBER_UNCOMPRESSED = 512_000_000
MAX_APK_BYTES = 512_000_000
MAX_APK_UNCOMPRESSED = 1_000_000_000
MAX_MANIFEST_BYTES = 16_000_000
MAX_DEX_BYTES = 256_000_000
MAX_ARCHIVE_ENTRIES = 100_000
MAX_APK_MEMBERS = 100


def stream_sha256(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_member_paths(infos: list[zipfile.ZipInfo], label: str) -> list[zipfile.ZipInfo]:
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise ValueError(f"{label} contains too many entries")
    names = [item.filename for item in infos]
    if len(names) != len(set(names)):
        raise ValueError(f"{label} contains duplicate member names")
    files = []
    for item in infos:
        name = item.filename.replace("\\", "/")
        if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
            raise ValueError(f"unsafe member path in {label}: {item.filename!r}")
        if item.is_dir():
            continue
        if item.file_size > MAX_MEMBER_UNCOMPRESSED:
            raise ValueError(f"member exceeds size limit in {label}: {item.filename}")
        files.append(item)
    return files


def inspect_apk(name: str, apk_data: bytes, digest: str) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(io.BytesIO(apk_data)) as apk:
            infos = apk.infolist()
            files = validate_member_paths(infos, f"embedded APK {name}")
            total = sum(item.file_size for item in files)
            if total > MAX_APK_UNCOMPRESSED:
                raise ValueError(f"embedded APK expands beyond total size limit: {name}")
            for item in files:
                if item.filename == "AndroidManifest.xml" and item.file_size > MAX_MANIFEST_BYTES:
                    raise ValueError(f"embedded manifest exceeds size limit: {name}")
                if re.fullmatch(r"classes\d*\.dex", item.filename) and item.file_size > MAX_DEX_BYTES:
                    raise ValueError(f"embedded DEX exceeds size limit: {name}:{item.filename}")
            bad_member = apk.testzip()
            if bad_member is not None:
                raise ValueError(f"embedded APK ZIP integrity failed: {name}:{bad_member}")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"embedded APK is not a valid ZIP: {name}") from exc

    names = [item.filename for item in files]
    dex_files = sorted(
        (n for n in names if re.fullmatch(r"classes\d*\.dex", n)),
        key=lambda n: int(re.search(r"classes(\d*)\.dex", n).group(1) or 1),
    )
    native_libraries = sorted(
        n for n in names if re.search(r"(^|/)lib/[^/]+/[^/]+\.so$", n)
    )
    manifests = [item for item in files if item.filename == "AndroidManifest.xml"]
    if len(manifests) > 1:
        raise ValueError(f"embedded APK has ambiguous manifest entries: {name}")
    return {
        "name": name,
        "bytes": len(apk_data),
        "sha256": digest,
        "zip_integrity": "passed",
        "uncompressed_bytes": total,
        "entry_count": len(files),
        "manifest_present": bool(manifests),
        "manifest_bytes": manifests[0].file_size if manifests else None,
        "dex_files": dex_files,
        "native_libraries": native_libraries,
    }


def analyze(bundle_path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(bundle_path) as outer:
        all_infos = outer.infolist()
        files = validate_member_paths(all_infos, "outer bundle")
        total = sum(item.file_size for item in files)
        if total > MAX_ARCHIVE_UNCOMPRESSED:
            raise ValueError("bundle exceeds total uncompressed size limit")
        bases = [item for item in files if item.filename == "base.apk"]
        if len(bases) != 1:
            raise ValueError("expected exactly one root-level base.apk (APKM-style bundle)")
        apk_infos = [item for item in files if item.filename.lower().endswith(".apk")]
        if len(apk_infos) > MAX_APK_MEMBERS:
            raise ValueError("bundle contains more than the configured APK member limit")
        for item in apk_infos:
            if item.file_size > MAX_APK_BYTES:
                raise ValueError(f"APK member exceeds configured size limit: {item.filename}")
        bad_member = outer.testzip()
        if bad_member is not None:
            raise ValueError(f"outer ZIP integrity failed: {bad_member}")
        outer_members = [
            {"name": item.filename, "bytes": item.file_size,
             "compressed_bytes": item.compress_size,
             "sha256": stream_sha256(outer, item)}
            for item in files
        ]
        outer_hash_by_name = {item["name"]: item["sha256"] for item in outer_members}
        split_apks = []
        for item in apk_infos:
            apk_data = outer.read(item)
            split_apks.append(
                inspect_apk(item.filename, apk_data, outer_hash_by_name[item.filename])
            )

    bundle_hash = hashlib.sha256()
    with bundle_path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            bundle_hash.update(chunk)
    return {
        "artifact": {"filename": bundle_path.name, "bytes": bundle_path.stat().st_size,
                     "sha256": bundle_hash.hexdigest()},
        "zip_integrity": "passed",
        "outer_uncompressed_bytes": total,
        "outer_member_count": len(files),
        "outer_members": outer_members,
        "split_apks": split_apks,
        "base_apk_sha256": outer_hash_by_name["base.apk"],
        "limitations": [
            "This is a container/member inventory, not Android manifest decoding or decompilation.",
            "ZIP CRC checks do not authenticate the publisher or prove the APK is benign.",
            "DEX bodies, manifest attributes, resources, certificate signatures and runtime behavior were not analyzed.",
            "Split manifests, code and resources are not merged; analyze each relevant APK separately with REA/JADX.",
        ],
    }


def render_markdown(data: dict[str, Any]) -> str:
    artifact = data["artifact"]
    lines = [
        "# APKM Static Inventory Report", "",
        "> Read-only container inventory. Not a decompilation, runtime test, signature verification, or security certification.", "",
        "## Artifact", "", f"- File: {artifact['filename']}",
        f"- Bytes: {artifact['bytes']:,}", f"- SHA-256: {artifact['sha256']}",
        f"- Outer ZIP integrity: {data['zip_integrity']}",
        f"- Base APK SHA-256: {data['base_apk_sha256']}", "",
        "## APK members", "",
        "| Member | Bytes | ZIP check | Manifest | DEX files | Native libraries | SHA-256 |",
        "|---|---:|---|---|---:|---:|---|",
    ]
    for item in data["split_apks"]:
        lines.append(
            f"| {item['name']} | {item['bytes']:,} | {item['zip_integrity']} | "
            f"{'yes' if item['manifest_present'] else 'no'} | {len(item['dex_files'])} | "
            f"{len(item['native_libraries'])} | {item['sha256']} |"
        )
        for dex in item["dex_files"]:
            lines.append(f"  - DEX: {dex}")
        for library in item["native_libraries"]:
            lines.append(f"  - Native library: {library}")
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in data["limitations"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="APKM-style ZIP with one base.apk and optional split APKs")
    parser.add_argument("--out", type=Path, default=Path("apkm-report"), help="new output directory")
    args = parser.parse_args()
    if not args.bundle.is_file():
        parser.error(f"bundle does not exist: {args.bundle}")
    if args.out.exists():
        parser.error(f"output directory already exists: {args.out}")
    try:
        data = analyze(args.bundle)
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "report.json").write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (args.out / "report.md").write_text(render_markdown(data), encoding="utf-8")
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, ValueError) as exc:
        print(f"inventory failed safely: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"Reports written to: {args.out.resolve()}")
    print(f"APK members: {len(data['split_apks'])}; outer integrity: {data['zip_integrity']}")
    print("Inventory only: manifest semantics, JADX analysis, signatures and runtime behavior were not checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
