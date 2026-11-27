#!/bin/sh
# Pack one staged directory as a reproducible .tar.gz (plan S2-S3, unit L3).
#
# Usage: packaging/linux/tarball.sh STAGE_DIR OUTPUT.tar.gz [--libdeflate]
#
# The archive holds the directory STAGE_DIR under its own name. Owner and group are 0,
# entries are sorted, every time is SOURCE_DATE_EPOCH, and gzip writes no name or time:
# the same input gives the same bytes. GNU tar is required (Debian, Ubuntu).
set -eu

fail() {
    printf 'tarball.sh: %s\n' "$*" >&2
    exit 1
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    fail 'usage: tarball.sh STAGE_DIR OUTPUT.tar.gz [--libdeflate]'
fi
stage=$1
output=$2
compressor=${3:-gzip}
case "$compressor" in
    gzip) command -v gzip >/dev/null || fail 'missing tool: gzip' ;;
    --libdeflate) command -v libdeflate-gzip >/dev/null || fail 'missing tool: libdeflate-gzip' ;;
    *) fail "unknown compression option: $compressor" ;;
esac
[ -d "$stage" ] || fail "not a directory: $stage"
case "$output" in
    *.tar.gz) ;;
    *) fail "the output must end in .tar.gz: $output" ;;
esac
[ -n "${SOURCE_DATE_EPOCH:-}" ] || fail 'set SOURCE_DATE_EPOCH'
tar --version 2>/dev/null | head -n 1 | grep -q 'GNU tar' || fail 'GNU tar is required'

parent=$(dirname -- "$stage")
name=$(basename -- "$stage")
work=$(mktemp -d "$output.work.XXXXXXXX")
trap 'rm -rf "$work"' 0
trap 'exit 1' 1 2 3 15
# Finish tar before compressing: a failed tar must not publish a valid gzip of
# truncated input. libdeflate also needs a complete file rather than a pipe.
tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -C "$parent" -cf "$work/archive.tar" "$name"
case "$compressor" in
    gzip) gzip -n -9 < "$work/archive.tar" > "$work/archive.tar.gz" ;;
    # Same gzip format and fixed header (no filename or mtime), with a stronger
    # encoder for release vault packages that must fit the Worker's 25 MiB cap.
    --libdeflate) libdeflate-gzip -12 -n -c "$work/archive.tar" > "$work/archive.tar.gz" ;;
esac
mv -f "$work/archive.tar.gz" "$output"
