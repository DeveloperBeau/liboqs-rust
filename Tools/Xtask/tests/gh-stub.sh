#!/usr/bin/env bash
# A stand-in for gh. The test sets GH_LOG, STUB_TAG, STUB_MODE and STUB_ROWS.
printf '%s\n' "$*" >> "$GH_LOG"
if [[ "$1" == api ]]; then
  if [[ "$STUB_MODE" == api-fail ]]; then
    echo "HTTP 503" >&2
    exit 1
  fi
  printf '%s\n' "$STUB_TAG"
  exit 0
fi
if [[ "$1" == issue && "$2" == list ]]; then
  if [[ "$STUB_MODE" == list-fail ]]; then
    echo "list failed" >&2
    exit 1
  fi
  if [[ "$*" != *"--state all"* ]]; then
    exit 0
  fi
  cat "$STUB_ROWS"
  exit 0
fi
if [[ "$1" == issue && "$2" == edit ]]; then
  if [[ "$STUB_MODE" == edit-fail ]]; then
    echo "edit failed" >&2
    exit 1
  fi
  exit 0
fi
if [[ "$1" == issue && "$2" == create ]]; then
  if [[ "$STUB_MODE" == create-fail ]]; then
    echo "create failed" >&2
    exit 1
  fi
  exit 0
fi
echo "unexpected gh call: $*" >&2
exit 1
