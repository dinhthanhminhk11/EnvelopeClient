#!/usr/bin/env bash
# Verifies the Apple static libraries of doodleart-core, the Mach-O counterpart of tools/check-so.sh (theme-x spec 2026-11-05
# §4.5). build-ios.sh runs it on every slice it builds; CI and the iOS team can run it on any build output, an
# unpacked xcframework or a fetched Core/ directory.
#
#   tools/check-macho.sh [--type debug|release] [--keys FILE] <dir | .a | Mach-O file>...
#
# A directory is searched for *.a files; a DoodleArtCore.manifest.json at its top is checked against the libraries
# below it, and every *.xcframework below it must hold exactly the iOS, Simulator and macOS arm64 slices with the
# module headers in Headers/DoodleArtCore. Checked on every static library (build-ios.sh prelinks the Rust staticlib
# into a single object):
#   - exported (defined external) symbols are exactly the functions of include/doodleart_core.h, without doodleart_debug_*
#     in a release library; no JNI_OnLoad / Java_*, no Rust runtime symbol;
#   - every member is built for one Apple platform, no newer than the app's deployment target (iOS 16.0, macOS 13.0),
#     and matches the slice named in its path (aarch64-apple-ios[-sim|darwin], ios-arm64[-simulator], macos-arm64);
#   - no LLVM bitcode (__LLVM segment) and no DWARF left (build-ios.sh prelinks with ld -r -S);
#   - imports (nm -u): printed grouped by Apple's required-reason API families for PrivacyInfo.xcprivacy; any of
#     those APIs except _fstat (ALLOWED_REQUIRED_REASON), and ptrace, fails; the imports only the Apple risk scan makes
#     and the unwinder catch_unwind needs must be there (WIRING; the scan's dyld / getenv calls and the clock are not
#     visible this way, see WIRING);
#   - no plaintext sensitive string: the SENSITIVE list of tools/check-so.sh (read from that file) plus the strings of
#     src/risk/apple.rs, no "doodleart-stub", no unmapped source path of this crate and none under its unkeyed remapped
#     name (src/m<first 8 hex of SHA-256(path)>.rs, guessable: tools/remap-paths.sh), no $HOME / user / crate /
#     target directory path;
#   - the embedded server keys: every public key and kid of the expected key config (--keys, a path relative to the
#     current directory; else $DOODLEART_SERVER_KEYS_FILE, relative to this crate as build.rs reads it; else
#     config/server-keys.<type>.conf) is in the library; the key config's tags `project` / `build_type`, when present,
#     match the project config and the build type (both required with DOODLEART_PROJECT_CONF, as in build.rs; without
#     the project tag and without DOODLEART_PROJECT_CONF, every key must be in config/server-keys.<type>.conf); a release
#     library contains no key of config/server-keys.debug.conf (DoodleArt's debug keys: another project relies on the
#     build_type tag) and no "doodleart_debug" string (the debug clock hook), and its key config has no kid "dev".
# Any other Mach-O file (an app binary taken from an .ipa) only gets the string checks: a linked, stripped app hides
# the library's symbols, so the export and import checks only make sense on the static library.
#
# The build type comes from --type or from the manifests. Needs python3 and the rustup llvm-tools component
# (`rustup component add llvm-tools`): Apple's nm cannot read the LLVM 21 bitcode members of an unprocessed Rust
# static library. Exit status 0 = all checks passed.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python3 >/dev/null || { echo "check-macho: python3 missing" >&2; exit 1; }
command -v rustc >/dev/null || { echo "check-macho: rustc missing (the llvm-tools component lives in its sysroot)" >&2; exit 1; }
LLVM_BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
for tool in llvm-nm llvm-objdump; do
  [[ -x "$LLVM_BIN/$tool" ]] || { echo "check-macho: $LLVM_BIN/$tool missing: rustup component add llvm-tools" >&2; exit 1; }
done

exec python3 -I - "$CRATE_DIR" "$LLVM_BIN" "$@" <<'PY'
import hashlib
import json
import os
import plistlib
import re
import shlex
import subprocess
import sys

CRATE_DIR, LLVM_BIN = sys.argv[1], sys.argv[2]
USAGE = "usage: tools/check-macho.sh [--type debug|release] [--keys FILE] <dir | .a | Mach-O file>..."

# Deployment targets of build-ios.sh (iOS: ios/ios_doodle_art/Podfile; macOS: the host slice for `swift test`).
MAX_MINOS = {"ios": (16, 0), "iossimulator": (16, 0), "macos": (13, 0)}

# Strings of src/risk/apple.rs (paths, image tokens, details), matched case-insensitively. They are read through
# obfstr; any plaintext copy means a string escaped it.
APPLE_SENSITIVE = [
    "/var/jb", "binpack", "procursus", "bootstrapped", "cydia", "sileo", "zebra.app", "/etc/apt", "/var/lib/apt",
    "dpkg", "substrate", "preferenceloader", "libhooker", "libsubstitute", "substitute-", "tweakinject",
    "tweakloader", "ellekit", "libblackjack", "systemhook", "sslkillswitch", "cycript", "frida", "fridagadget",
    "dyld_insert_libraries", "jailbreak", "root.paths", "root.write", "root.unchecked", "hook.dyld_image",
    "hook.dyld_env", "frida.dyld_image", "frida.port", "debugger.traced", "debugger.unchecked",
    "emulator.simulator", "risk/apple", "kinfo_proc",
]
# Never in an Apple library, whatever the build type.
ALWAYS_ABSENT = ["doodleart-stub", "JNI_OnLoad", "Java_", "jni-sys", "jni_sys"]

# Apple's required-reason API families (PrivacyInfo.xcprivacy, NSPrivacyAccessedAPITypes), as C / Objective-C
# symbols. arm64 has no $INODE64 variants; they are listed for completeness.
REQUIRED_REASON = {
    "File timestamp (NSPrivacyAccessedAPICategoryFileTimestamp)": [
        "_stat", "_lstat", "_fstat", "_fstatat", "_getattrlist", "_getattrlistbulk", "_fgetattrlist",
        "_getattrlistat", "_stat$INODE64", "_lstat$INODE64", "_fstat$INODE64", "_fstatat$INODE64",
    ],
    "System boot time (NSPrivacyAccessedAPICategorySystemBootTime)": [
        "_mach_absolute_time", "_OBJC_CLASS_$_NSProcessInfo",
    ],
    "Disk space (NSPrivacyAccessedAPICategoryDiskSpace)": [
        "_statfs", "_fstatfs", "_statvfs", "_fstatvfs", "_statfs$INODE64", "_fstatfs$INODE64",
        "_OBJC_CLASS_$_NSFileManager",
    ],
    "User defaults (NSPrivacyAccessedAPICategoryUserDefaults)": [
        "_OBJC_CLASS_$_NSUserDefaults", "_CFPreferencesCopyAppValue", "_CFPreferencesSetAppValue",
        "_CFPreferencesCopyValue", "_CFPreferencesSetValue", "_CFPreferencesAppSynchronize",
    ],
    "Active keyboards (NSPrivacyAccessedAPICategoryActiveKeyboards)": ["_OBJC_CLASS_$_UITextInputMode"],
}
# The one required-reason import the library may keep, with why. Everything else of REQUIRED_REASON is forbidden:
# the core's own code avoids those APIs (apple.rs probes with access/open, the clock is clock_gettime(CLOCK_MONOTONIC)).
ALLOWED_REQUIRED_REASON = {
    "_fstat": "Rust std (File::metadata: the size of the image the backtrace symbolizer maps); not called by the "
    "core's own code. The app declares the File timestamp reason in PrivacyInfo.xcprivacy (C617.1: files inside the "
    "app container, here the app's own executable).",
}
# Forbidden beyond the required-reason APIs: ptrace (PT_DENY_ATTACH style anti-debugging is an App Review risk; the
# debugger check reads P_TRACED through sysctl).
FORBIDDEN_EXTRA = ["_ptrace"]
# Imports that only the Apple risk scan makes (its filesystem probes access/unlink, its debugger check sysctl, the
# loopback connect of frida.port socket/connect: no other code of an Apple library opens a socket, so LTO drops them
# with the check; a scan compiled out, or a filesystem probe compiled into the macOS slice, shows here; the macOS slice
# skips the filesystem probes), and the unwinder: catch_unwind at every entry needs panic = "unwind", without which
# __Unwind_RaiseException is gone. NOT listed, because Rust std imports them on its own (its backtrace symbolizer, its
# Instant): _dyld_image_count, _dyld_get_image_name, getenv and clock_gettime. Their use by the scan, and frida.port
# end to end, are proven at run time by tests/c-abi/risk_probe.c (tools/c-abi-smoke.sh, on the macOS slice), the
# clock by the unit test clock::tests::mono_ms_reads_the_sleep_counting_clock.
WIRING = {
    "ios": (["_access", "_unlink", "_sysctl", "_socket", "_connect", "__Unwind_RaiseException"], []),
    "iossimulator": (["_access", "_unlink", "_sysctl", "_socket", "_connect", "__Unwind_RaiseException"], []),
    "macos": (["_sysctl", "_socket", "_connect", "__Unwind_RaiseException"], ["_access", "_unlink"]),
}
PATH_PLATFORM = [
    ("aarch64-apple-ios-sim", "iossimulator"), ("x86_64-apple-ios", "iossimulator"),
    ("ios-arm64-simulator", "iossimulator"), ("aarch64-apple-ios", "ios"),
    ("ios-arm64", "ios"), ("aarch64-apple-darwin", "macos"), ("macos-arm64", "macos"),
]


def fail_usage(message):
    print(f"check-macho: {message}\n{USAGE}", file=sys.stderr)
    sys.exit(2)


def parse_args(argv):
    build_type = keys_file = None
    paths = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--type", "--keys"):
            if index + 1 >= len(argv):
                fail_usage(f"{arg} needs a value")
            if arg == "--type":
                build_type = argv[index + 1]
            else:
                keys_file = argv[index + 1]
            index += 2
        elif arg.startswith("-"):
            fail_usage(f"unknown option {arg}")
        else:
            paths.append(arg)
            index += 1
    if build_type not in (None, "debug", "release"):
        fail_usage(f"--type must be debug or release, not {build_type!r}")
    if not paths:
        fail_usage("nothing to check")
    return build_type, keys_file, paths


def run(tool, *args):
    result = subprocess.run([os.path.join(LLVM_BIN, tool), *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{tool} {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def read_conf(path):
    """KEY = value lines, `#` comments, as build.rs reads the key and project configs."""
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line and "=" in line:
                key, value = (part.strip() for part in line.split("=", 1))
                values[key] = value
    return values


def server_keys(path):
    """[(kid, 32-byte public key)] of a server key config, current first."""
    conf = read_conf(path)
    keys = []
    for slot in ("current", "next"):
        kid, key = conf.get(f"{slot}.kid", ""), conf.get(f"{slot}.public_key", "")
        if not kid and not key:
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError(f"{path}: {slot}.public_key is not 64 lowercase hex characters")
        keys.append((kid, bytes.fromhex(key)))
    if not keys:
        raise ValueError(f"{path}: no server key")
    return keys


def header_functions():
    with open(os.path.join(CRATE_DIR, "include/doodleart_core.h"), encoding="utf-8") as handle:
        names = re.findall(r"^(?:DoodleArtBuf|int32_t|void)\s+(doodleart_[a-z0-9_]+)\(", handle.read(), re.MULTILINE)
    if len(names) < 17:
        raise ValueError("include/doodleart_core.h: fewer than the 17 functions of spec §4.4")
    return sorted(names)


def check_so_sensitive():
    """The SENSITIVE array of tools/check-so.sh, the Android list, so both checks stay in step."""
    with open(os.path.join(CRATE_DIR, "tools/check-so.sh"), encoding="utf-8") as handle:
        match = re.search(r"^SENSITIVE=\((.*?)^\)", handle.read(), re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError("tools/check-so.sh: SENSITIVE=( ... ) not found")
    tokens = shlex.split(match.group(1))
    if len(tokens) < 10:
        raise ValueError("tools/check-so.sh: SENSITIVE parsed to fewer than 10 tokens")
    return tokens


def crate_source_files():
    root = os.path.join(CRATE_DIR, "src")
    files = []
    for directory, _, names in os.walk(root):
        for name in names:
            if name.endswith(".rs"):
                files.append(os.path.relpath(os.path.join(directory, name), root))
    return sorted(files)


def minos_tuple(text):
    return tuple(int(part) for part in text.split("."))[:2]


def platforms_of(path):
    """{member: (platform, minos)} from the LC_BUILD_VERSION / LC_VERSION_MIN_* load commands."""
    members = {}
    member, command = os.path.basename(path), None
    for line in run("llvm-objdump", "--macho", "--private-headers", path).splitlines():
        header = re.match(r"^\S.*\((.+)\):$", line)
        if header:
            member, command = header.group(1), None
            continue
        words = line.split()
        if len(words) == 2 and words[0] == "cmd":
            command = words[1]
            if command.startswith("LC_VERSION_MIN_"):
                platform = {"IPHONEOS": "ios", "MACOSX": "macos"}.get(command[len("LC_VERSION_MIN_"):], command)
                members.setdefault(member, [None, None])[0] = platform
        elif len(words) == 2 and command == "LC_BUILD_VERSION" and words[0] in ("platform", "minos"):
            members.setdefault(member, [None, None])[0 if words[0] == "platform" else 1] = words[1]
        elif len(words) == 2 and command and command.startswith("LC_VERSION_MIN_") and words[0] == "version":
            members.setdefault(member, [None, None])[1] = words[1]
    return members


def sections_of(path):
    return run("llvm-objdump", "--macho", "--section-headers", path)


class Report:
    def __init__(self):
        self.failed = False

    def ok(self, message):
        print(f"   {message}")

    def fail(self, message):
        print(f"   FAIL {message}")
        self.failed = True


def string_checks(report, data, build_type, sensitive, sources):
    leaked = [token for token in sensitive if token.encode() in data]
    lowered = data.lower()
    leaked += [token for token in APPLE_SENSITIVE if token.encode() in lowered]
    leaked += [token for token in ALWAYS_ABSENT if token.encode() in data]
    if build_type == "release" and b"doodleart_debug" in data:
        leaked.append("doodleart_debug (debug clock hook)")
    if leaked:
        report.fail(f"plaintext strings: {' '.join(sorted(set(leaked)))}")
    else:
        report.ok("plaintext sensitive strings: none")
    # Source paths: build-ios.sh maps every file of src/ to a keyed name (tools/remap-paths.sh). An unmapped one shows
    # as src/<path> without a crate directory in front (dependencies stay crates/<registry>/<crate>/src/..., always
    # after a "/"); an unkeyed one as src/m<first 8 hex of SHA-256(path)>.rs, which a word list of guessed paths
    # reverses.
    unmapped = sorted({rel for rel in sources if rel != "lib.rs"
                       for match in re.finditer(re.escape(f"src/{rel}").encode(), data)
                       if match.start() == 0 or data[match.start() - 1:match.start()] != b"/"})
    if b"doodleart-core/src/" in data:
        unmapped.append("doodleart-core/src/")
    if unmapped:
        report.fail(f"unmapped source paths: {' '.join(unmapped)}")
    unkeyed = sorted(f"{name}={rel}" for rel in sources
                     for name in [f"src/m{hashlib.sha256(rel.encode()).hexdigest()[:8]}.rs"] if name.encode() in data)
    if unkeyed:
        report.fail(f"source files under their unkeyed (guessable) remapped names: {' '.join(unkeyed)}")
    homes = [b"/Users/", os.path.expanduser("~").encode(), CRATE_DIR.encode()]
    target_dir = os.environ.get("CARGO_TARGET_DIR", "")
    if target_dir:
        homes.append(os.path.realpath(target_dir).encode())
        homes.append(target_dir.encode())
    found = sorted({home.decode(errors="replace") for home in homes if len(home) > 1 and home in data})
    if found:
        report.fail(f"absolute paths in the binary (remap-path-prefix): {' '.join(found)}")
    leaked_path = re.search(rb"[A-Za-z0-9_./~-]*(\.cargo/registry|~/)[A-Za-z0-9_./-]*\.rs", data)
    if leaked_path:
        report.fail(f"unmapped dependency path: {leaked_path.group(0).decode(errors='replace')}")


def key_checks(report, data, build_type, expected_keys, debug_keys):
    missing = [kid for kid, key in expected_keys if key not in data or kid.encode() not in data]
    if missing:
        report.fail(f"server keys of the expected key config missing (kid {', '.join(missing)})")
    else:
        report.ok(f"server keys: {', '.join(kid for kid, _ in expected_keys)}")
    if build_type == "release":
        leaked = [kid for kid, key in debug_keys if key in data]
        if leaked:
            report.fail(f"a debug server key is embedded (kid {', '.join(leaked)} of config/server-keys.debug.conf)")


def check_archive(report, path, data, build_type, expected_exports, expect_platform):
    members = run("llvm-ar", "t", path).split() if os.path.exists(os.path.join(LLVM_BIN, "llvm-ar")) else []
    platforms = platforms_of(path)
    kinds = sorted({value[0] or "?" for value in platforms.values()})
    if len(kinds) != 1 or kinds[0] not in MAX_MINOS:
        report.fail(f"members are not built for one Apple platform: {kinds}")
        platform = None
    else:
        platform = kinds[0]
        newest = max((value[1] or "0.0" for value in platforms.values()), key=minos_tuple)
        report.ok(f"platform {platform}, newest minos {newest}, {len(members) or len(platforms)} member(s)")
        if minos_tuple(newest) > MAX_MINOS[platform]:
            limit = ".".join(map(str, MAX_MINOS[platform]))
            report.fail(f"built for {platform} {newest}, newer than the deployment target {limit}")
        if expect_platform and expect_platform != platform:
            report.fail(f"the path names a {expect_platform} slice but the library is built for {platform}")
    sections = sections_of(path)
    if re.search(r"__LLVM|__bitcode|__bundle", sections):
        report.fail("LLVM bitcode (__LLVM segment) left: not prelinked by build-ios.sh")
    if re.search(r"__debug_|__apple_names|__DWARF", sections):
        report.fail("DWARF debug sections left (ld -r -S)")

    symbols = run("llvm-nm", "-A", "-P", path).splitlines()
    defined, undefined = set(), set()
    for line in symbols:
        fields = line.split(": ", 1)[-1].split()
        if len(fields) < 2:
            continue
        name, kind = fields[0], fields[1]
        if kind == "U":
            undefined.add(name)
        elif kind.isupper():
            defined.add(name)
    exported = sorted(defined)
    if exported == expected_exports:
        report.ok(f"exports: the {len(exported)} functions of include/doodleart_core.h"
                  + ("" if build_type == "debug" else " (no doodleart_debug_*)"))
    else:
        extra = [name for name in exported if name not in expected_exports]
        missing = [name for name in expected_exports if name not in defined]
        shown = " ".join(extra[:12]) + (f" ... (+{len(extra) - 12})" if len(extra) > 12 else "")
        report.fail(f"exports differ from the header: extra [{shown}] missing [{' '.join(missing)}]")
    jni = sorted(name for name in defined | undefined if name.startswith(("_JNI_", "_Java_")))
    if jni:
        report.fail(f"JNI symbols: {' '.join(jni)}")

    imports = sorted(undefined - defined)
    internal = [name for name in imports if name.startswith("_doodleart_")]
    if internal:
        report.fail(f"unresolved own symbols: {' '.join(internal)}")
    report.ok(f"imports ({len(imports)}): {' '.join(imports)}")
    forbidden = list(FORBIDDEN_EXTRA)
    for family, names in REQUIRED_REASON.items():
        used = [name for name in names if name in imports]
        if used:
            report.ok(f"required-reason API, {family}: {' '.join(used)}")
            for name in used:
                if name in ALLOWED_REQUIRED_REASON:
                    report.ok(f"  {name}: {ALLOWED_REQUIRED_REASON[name]}")
        forbidden += [name for name in names if name not in ALLOWED_REQUIRED_REASON]
    bad = sorted(name for name in imports if name in forbidden)
    if bad:
        report.fail(f"forbidden imports: {' '.join(bad)}")
    if platform in WIRING:
        needed, absent = WIRING[platform]
        missing = [name for name in needed if name not in imports]
        unexpected = [name for name in absent if name in imports]
        if missing:
            report.fail(f"imports of the Apple risk scan / unwinder missing on {platform}: {' '.join(missing)}")
        if unexpected:
            report.fail(f"filesystem probe imports on {platform}: {' '.join(unexpected)}")
    return hashlib.sha256(data).hexdigest()


def check_manifest(report, manifest_path, build_type, expected_keys, project_id, found_hashes):
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    print(f"== {manifest_path}")
    problems = []
    if manifest.get("buildType") != build_type:
        problems.append(f"buildType {manifest.get('buildType')!r}, expected {build_type!r}")
    if manifest.get("projectId") != project_id:
        problems.append(f"projectId {manifest.get('projectId')!r}, expected {project_id!r}")
    kids = [kid for kid, _ in expected_keys]
    if manifest.get("kids") != kids:
        problems.append(f"kids {manifest.get('kids')}, expected {kids}")
    hashes = manifest.get("sha256") or {}
    libraries = {value for key, value in hashes.items() if key.endswith(".a")}
    unknown = sorted(path for path, digest in found_hashes.items() if digest not in libraries)
    if unknown:
        problems.append(f"libraries not listed in the manifest's sha256: {' '.join(unknown)}")
    absent = sorted(key for key, value in hashes.items() if key.endswith(".a") and value not in found_hashes.values())
    if found_hashes and absent:
        problems.append(f"libraries of the manifest's sha256 not found: {' '.join(absent)}")
    for problem in problems:
        report.fail(problem)
    if not problems:
        report.ok(f"manifest: {build_type}, projectId {project_id}, kids {', '.join(kids)}, "
                  f"{len(found_hashes)} librar{'y' if len(found_hashes) == 1 else 'ies'} match its sha256")
    return manifest.get("buildType")


# Library identifiers xcodebuild -create-xcframework gives the three slices, and their Info.plist platform/variant.
XCFRAMEWORK_SLICES = {("ios", ""), ("ios", "simulator"), ("macos", "")}


def check_xcframework(report, root):
    """Info.plist of an xcframework: exactly the three arm64 slices, each library present, module headers beside it."""
    print(f"== {root}")
    try:
        with open(os.path.join(root, "Info.plist"), "rb") as handle:
            info = plistlib.load(handle)
        libraries = info["AvailableLibraries"]
        platforms = []
        for library in libraries:
            identifier = library["LibraryIdentifier"]
            platforms.append((library["SupportedPlatform"], library.get("SupportedPlatformVariant", "")))
            if library.get("SupportedArchitectures") != ["arm64"]:
                report.fail(f"{identifier}: architectures {library.get('SupportedArchitectures')}, expected arm64")
            if not os.path.isfile(os.path.join(root, identifier, library["LibraryPath"])):
                report.fail(f"{identifier}: {library['LibraryPath']} missing")
            headers = os.path.join(root, identifier, library.get("HeadersPath", ""), "DoodleArtCore")
            for name in ("doodleart_core.h", "module.modulemap"):
                if not library.get("HeadersPath") or not os.path.isfile(os.path.join(headers, name)):
                    report.fail(f"{identifier}: Headers/DoodleArtCore/{name} missing")
        if sorted(platforms) != sorted(XCFRAMEWORK_SLICES):
            report.fail(f"slices {sorted(platforms)}, expected iOS device, iOS Simulator and macOS")
        else:
            report.ok(f"xcframework: {', '.join(sorted(library['LibraryIdentifier'] for library in libraries))}")
    except (OSError, KeyError, TypeError, plistlib.InvalidFileException) as error:
        report.fail(f"unreadable Info.plist: {error!r}")


def main():
    build_type, keys_file, paths = parse_args(sys.argv[3:])
    libraries, binaries, manifests, xcframeworks = [], [], [], []
    for path in paths:
        if os.path.isdir(path):
            manifest = os.path.join(path, "DoodleArtCore.manifest.json")
            if os.path.isfile(manifest):
                manifests.append((manifest, path))
            for directory, dirs, names in os.walk(path):
                dirs.sort()
                xcframeworks += [os.path.join(directory, name) for name in dirs if name.endswith(".xcframework")]
                libraries += [os.path.join(directory, name) for name in sorted(names) if name.endswith(".a")]
        elif os.path.isfile(path):
            with open(path, "rb") as handle:
                magic = handle.read(8)
            if magic.startswith(b"!<arch>\n"):
                libraries.append(path)
            elif magic[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                binaries.append(path)
            else:
                fail_usage(f"{path}: neither a static library nor a Mach-O file")
        else:
            fail_usage(f"{path}: no such file or directory")
    if build_type is None:
        types = set()
        for manifest, _ in manifests:
            with open(manifest, encoding="utf-8") as handle:
                types.add(json.load(handle).get("buildType"))
        if len(types) != 1 or not types <= {"debug", "release"}:
            fail_usage("pass --type: no manifest, or manifests of different build types")
        build_type = types.pop()
    if not libraries and not binaries:
        fail_usage(f"no static library (*.a) under {' '.join(paths)}")

    # --keys is a command-line path (relative to the current directory); DOODLEART_SERVER_KEYS_FILE and
    # DOODLEART_PROJECT_CONF are relative to this crate, as build.rs resolves them.
    if keys_file:
        expected_keys_path = os.path.abspath(keys_file)
    else:
        expected_keys_path = os.path.join(CRATE_DIR, os.environ.get("DOODLEART_SERVER_KEYS_FILE")
                                          or f"config/server-keys.{build_type}.conf")
    expected_keys = server_keys(expected_keys_path)
    debug_keys = server_keys(os.path.join(CRATE_DIR, "config/server-keys.debug.conf"))
    project_override = os.environ.get("DOODLEART_PROJECT_CONF") or ""
    project_id = read_conf(os.path.join(CRATE_DIR, project_override or "config/project.conf")).get("PROJECT_ID", "")
    expected_exports = ["_" + name for name in header_functions()
                        if build_type == "debug" or not name.startswith("doodleart_debug_")]
    sensitive = check_so_sensitive()
    sources = crate_source_files()

    report = Report()
    print(f"check-macho: {build_type}, keys {os.path.relpath(expected_keys_path, CRATE_DIR)}")
    if build_type == "release" and any(kid == "dev" for kid, _ in expected_keys):
        report.fail(f"the release key config {expected_keys_path} has the kid dev")
    key_tags = read_conf(expected_keys_path)
    tagged_project, tagged_type = key_tags.get("project", ""), key_tags.get("build_type", "")
    if tagged_project and tagged_project != project_id:
        report.fail(f"the key config {expected_keys_path} is for project {tagged_project}, the project config is "
                    f"{project_id}")
    if tagged_type and tagged_type != build_type:
        report.fail(f"the key config {expected_keys_path} is for the build type {tagged_type}, not {build_type}")
    if project_override and not (tagged_project and tagged_type):
        report.fail(f"DOODLEART_PROJECT_CONF selects project {project_id}: its key config must name project and "
                    f"build_type (build.rs)")
    committed_keys_path = os.path.join(CRATE_DIR, f"config/server-keys.{build_type}.conf")
    if not project_override and not tagged_project and \
            os.path.abspath(expected_keys_path) != os.path.abspath(committed_keys_path):
        # As build.rs: an untagged key config with the default project config is DoodleArt's only when DoodleArt committed
        # every key in it (an Apple library refuses it otherwise).
        try:
            committed = server_keys(committed_keys_path)
        except ValueError:
            committed = []
        foreign = [kid for kid, key in expected_keys if (kid, key) not in committed]
        if foreign:
            report.fail(f"the key config {expected_keys_path} has no project tag and keys (kid {', '.join(foreign)}) "
                        f"that config/server-keys.{build_type}.conf does not have (build.rs refuses it)")
    found_hashes = {}
    for path in libraries:
        with open(path, "rb") as handle:
            data = handle.read()
        print(f"== {path} ({len(data)} bytes)")
        lowered_path = path.replace("\\", "/")
        expect_platform = next((platform for marker, platform in PATH_PLATFORM if f"/{marker}/" in lowered_path
                                or lowered_path.startswith(f"{marker}/")), None)
        try:
            found_hashes[path] = check_archive(report, path, data, build_type, expected_exports, expect_platform)
        except (RuntimeError, OSError) as error:
            report.fail(str(error))
        string_checks(report, data, build_type, sensitive, sources)
        key_checks(report, data, build_type, expected_keys, debug_keys)
    for root in xcframeworks:
        check_xcframework(report, root)
    for path in binaries:
        with open(path, "rb") as handle:
            data = handle.read()
        print(f"== {path} ({len(data)} bytes, Mach-O file: string checks only)")
        string_checks(report, data, build_type, sensitive, sources)
    for manifest, root in manifests:
        below = {path: digest for path, digest in found_hashes.items()
                 if os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)}
        check_manifest(report, manifest, build_type, expected_keys, project_id, below)
    print("check-macho: FAILED" if report.failed else "check-macho: OK")
    sys.exit(1 if report.failed else 0)


try:
    main()
except (ValueError, OSError, json.JSONDecodeError) as error:
    print(f"check-macho: {error}", file=sys.stderr)
    sys.exit(1)
PY
