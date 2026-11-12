#!/usr/bin/env bash
# Reads LIBOQS_VERSION and the latest liboqs release. When the release is newer,
# keeps one open issue for the pinned version. A closed issue with the same
# title is not opened again.

set -euo pipefail

# Exits 0 when the first version is newer than the second.
version_is_newer() {
  local first="$1"
  local second="$2"
  local first_parts=()
  local second_parts=()
  local count index first_part second_part
  IFS='.' read -r -a first_parts <<< "${first}"
  IFS='.' read -r -a second_parts <<< "${second}"
  count="${#first_parts[@]}"
  if ((${#second_parts[@]} > count)); then
    count="${#second_parts[@]}"
  fi
  for ((index = 0; index < count; index++)); do
    first_part="${first_parts[${index}]:-0}"
    second_part="${second_parts[${index}]:-0}"
    if ((10#${first_part} > 10#${second_part})); then
      return 0
    fi
    if ((10#${first_part} < 10#${second_part})); then
      return 1
    fi
  done
  return 1
}

# True when the login is the GitHub Actions app.
# `gh issue list --json author` reports that app as app/github-actions.
# github-actions[bot] and github-actions are the other logins of the same app.
is_actions_author() {
  local login="${1,,}"
  case "${login}" in
    app/github-actions | 'github-actions[bot]' | github-actions)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version_file="${root}/LIBOQS_VERSION"

if [[ ! -f "${version_file}" ]]; then
  echo "LIBOQS_VERSION is missing" >&2
  exit 1
fi

pinned="$(tr -d '[:space:]' < "${version_file}")"
pinned="${pinned#v}"
pinned="${pinned#V}"

if [[ ! "${pinned}" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
  echo "LIBOQS_VERSION is not a numeric version: ${pinned}" >&2
  exit 1
fi

if ! raw_tag="$(gh api repos/open-quantum-safe/liboqs/releases/latest --jq .tag_name)"; then
  echo "the GitHub API call for the latest liboqs release failed" >&2
  exit 1
fi

raw_tag="$(printf '%s' "${raw_tag}" | tr -d '[:space:]')"
if [[ -z "${raw_tag}" ]]; then
  echo "the GitHub API call for the latest liboqs release returned an empty tag" >&2
  exit 1
fi

latest="${raw_tag#v}"
latest="${latest#V}"
if [[ ! "${latest}" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
  echo "the latest liboqs release tag is not a numeric version: ${raw_tag}" >&2
  exit 1
fi

if [[ "${latest}" == "${pinned}" ]]; then
  echo "liboqs ${pinned} is current"
  exit 0
fi

if version_is_newer "${pinned}" "${latest}"; then
  echo "pinned liboqs ${pinned} is newer than the latest release ${latest}"
  exit 0
fi

title="liboqs ${latest} is available (pinned ${pinned})"
body="$(cat <<EOF
[Release notes](https://github.com/open-quantum-safe/liboqs/releases/tag/${raw_tag})

A bump must land in liboqs-swift, liboqs-zig and liboqs-rust together and keep parity, snapshot and known answers green.
EOF
)"

repo_args=()
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
  repo_args=(--repo "${GITHUB_REPOSITORY}")
fi

# One bounded search of open and closed notices for this pin.
notice_re="^liboqs [0-9]+([.][0-9]+)* is available \\(pinned ${pinned}\\)$"

if ! issue_rows="$(gh issue list "${repo_args[@]}" --state all --limit 50 --search "in:title \"is available (pinned ${pinned})\"" --json number,state,title,author --jq '.[] | [.number, .state, .title, .author.login] | @tsv')"; then
  echo "the call to list issues failed" >&2
  exit 1
fi

open_match=""
while IFS=$'\t' read -r number issue_state existing_title author_login; do
  if [[ -z "${number}" ]]; then
    continue
  fi
  if ! is_actions_author "${author_login}"; then
    continue
  fi
  state_name="${issue_state^^}"
  if [[ "${existing_title}" == "${title}" && "${state_name}" == "CLOSED" ]]; then
    echo "a closed issue already has the title: ${title}"
    exit 0
  fi
  if [[ "${existing_title}" == "${title}" && "${state_name}" == "OPEN" ]]; then
    echo "an open issue already has the title: ${title}"
    exit 0
  fi
  if [[ -z "${open_match}" && "${state_name}" == "OPEN" && "${existing_title}" =~ ${notice_re} ]]; then
    open_match="${number}"
  fi
done <<< "${issue_rows}"

if [[ -n "${open_match}" ]]; then
  if ! gh issue edit "${repo_args[@]}" "${open_match}" --title "${title}" --body "${body}"; then
    echo "the call to update the open liboqs issue failed" >&2
    exit 1
  fi
  exit 0
fi

if ! gh issue create "${repo_args[@]}" --title "${title}" --body "${body}"; then
  echo "the call to open the liboqs update issue failed" >&2
  exit 1
fi
