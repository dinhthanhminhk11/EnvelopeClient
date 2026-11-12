# shellcheck shell=bash
# Source path remapping of the shipped libraries, sourced by build-android.sh and build-ios.sh (one implementation, so
# the Android and Apple libraries cannot drift). Defines functions only.
#
# Panic locations embed source paths ("src/risk/frida.rs") even in stripped binaries, and they are among the few
# anchors left in a library whose symbols are stripped and whose strings go through obfstr. Every file of src/ is
# mapped to src/m<first 8 hex of SHA-256(REMAP_SALT || 0x00 || path under src/)>.rs:
#   - keyed: REMAP_SALT is a per-project value of the project config (committed, never shipped). Without it a name
#     cannot be checked against a guess ("risk/frida.rs"), which an unkeyed hash of the path allows with a short word
#     list. tools/check-so.sh and tools/check-macho.sh fail when an unkeyed name appears in a library;
#   - stable: a name depends on its own path and the salt only, so adding or removing a file (iOS-only or test code a
#     build never compiles) changes no other name, and with it no obfstr key (obfstr derives its keys from file!(),
#     the remapped name, line and column): a library stays byte-identical unless code it compiles changes.

# SHA-256 of stdin as 64 hex characters.
doodleart_sha256_hex() {
  if command -v shasum >/dev/null; then shasum -a 256; else sha256sum; fi | cut -c 1-64
}

# doodleart_remap_salt <project config>: prints its REMAP_SALT (32 to 64 lowercase hex characters, build.rs checks the
# same rule) or fails with the command that creates one. Never prints the value on failure.
doodleart_remap_salt() {
  local salt
  salt="$(sed -E -n -e 's/#.*//' -e 's/^[[:space:]]*REMAP_SALT[[:space:]]*=[[:space:]]*//p' "$1" | tail -n 1 |
    sed -E 's/[[:space:]]+$//')"
  if [[ ! "$salt" =~ ^[0-9a-f]{32,64}$ ]]; then
    echo "$1: REMAP_SALT must be 32 to 64 lowercase hex characters, one per project (create one with" \
      "\`od -An -N16 -tx1 /dev/urandom | tr -d ' \\n'\` and commit it in the project config)" >&2
    return 1
  fi
  printf '%s' "$salt"
}

# doodleart_remap_name <salt> <path under src/>: m + the first 8 hex of SHA-256(salt || 0x00 || path).
doodleart_remap_name() {
  printf 'm%s' "$(printf '%s\0%s' "$1" "$2" | doodleart_sha256_hex | cut -c 1-8)"
}

# doodleart_remap_flags <crate dir> <salt>: appends one --remap-path-prefix pair per file of src/ to the RUSTFLAGS_LIST
# array of the caller (cargo passes local sources to rustc as relative paths, "src/risk/frida.rs": both spellings are
# mapped). Rustc applies the LAST matching --remap-path-prefix: call this after the general prefixes. Fails when two
# names collide.
doodleart_remap_flags() {
  local crate_dir="$1" salt="$2" source name names="" collisions
  while IFS= read -r source; do
    name="$(doodleart_remap_name "$salt" "$source")"
    names="$names$name"$'\n'
    RUSTFLAGS_LIST+=("--remap-path-prefix=src/$source=src/$name.rs" "--remap-path-prefix=$crate_dir/src/$source=src/$name.rs")
  done < <(cd "$crate_dir/src" && find . -name '*.rs' | sed 's|^\./||' | LC_ALL=C sort)
  collisions="$(printf '%s' "$names" | LC_ALL=C sort | uniq -d)"
  if [[ -n "$collisions" ]]; then
    echo "remapped source names collide: $collisions (rename a file)" >&2
    return 1
  fi
}

# doodleart_unkeyed_remap_names <crate dir>: "src/m<first 8 hex of SHA-256(path)>.rs <path>" per file of src/, the names an
# unkeyed hash would give (the guard of tools/check-so.sh; tools/check-macho.sh computes the same in Python).
doodleart_unkeyed_remap_names() {
  local source
  while IFS= read -r source; do
    printf 'src/m%s.rs %s\n' "$(printf '%s' "$source" | doodleart_sha256_hex | cut -c 1-8)" "$source"
  done < <(cd "$1/src" && find . -name '*.rs' | sed 's|^\./||' | LC_ALL=C sort)
}
