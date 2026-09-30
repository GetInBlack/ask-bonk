#!/bin/bash
set -euo pipefail

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
helper="${repo_root}/github/script/git-credential-readonly.ts"
sentinel_askpass="${repo_root}/test/fixtures/sentinel-askpass.sh"
sentinel="$(mktemp)"
global_config="$(mktemp)"
trap 'rm -f "${sentinel}" "${global_config}"' EXIT

printf '[core]\n\taskPass = %s\n' "${sentinel_askpass}" > "${global_config}"

credential_fill() (
  # Simulate hostile inherited configuration before applying the exact
  # step-scoped environment from github/action.yml.
  export ASKPASS_SENTINEL="${sentinel}"
  export GIT_CONFIG_GLOBAL="${global_config}"
  export GIT_ASKPASS="${sentinel_askpass}"
  export SSH_ASKPASS="${sentinel_askpass}"

  export GH_TOKEN="dummy-read-only-token"
  export GITHUB_REPOSITORY="GetInBlack/private-repo"
  export GITHUB_SERVER_URL="https://github.com"
  export GIT_CONFIG_COUNT=4
  export GIT_CONFIG_KEY_0="credential.helper"
  export GIT_CONFIG_VALUE_0=""
  export GIT_CONFIG_KEY_1="credential.useHttpPath"
  export GIT_CONFIG_VALUE_1="true"
  export GIT_CONFIG_KEY_2="core.askPass"
  export GIT_CONFIG_VALUE_2="/bin/false"
  export GIT_CONFIG_KEY_3="credential.helper"
  export GIT_CONFIG_VALUE_3="!${helper}"
  export GIT_ASKPASS=/bin/false
  export SSH_ASKPASS=/bin/false
  export GIT_TERMINAL_PROMPT=0

  git credential fill
)

valid_output="$(
  printf 'protocol=https\nhost=github.com\npath=GetInBlack/private-repo.git\n\n' |
    credential_fill
)"
case "${valid_output}" in
  *'username=x-access-token'*'password=dummy-read-only-token'*) ;;
  *)
    echo "exact repository did not receive the read-only credential" >&2
    exit 1
    ;;
esac

if printf 'protocol=https\nhost=attacker.example\npath=GetInBlack/private-repo.git\n\n' |
  credential_fill >/dev/null 2>&1; then
  echo "attacker host unexpectedly received a credential" >&2
  exit 1
fi

if printf 'protocol=https\nhost=github.com\npath=attacker/repo.git\n\n' |
  credential_fill >/dev/null 2>&1; then
  echo "attacker repository unexpectedly received a credential" >&2
  exit 1
fi

if [ -s "${sentinel}" ]; then
  echo "an inherited askpass helper was invoked" >&2
  exit 1
fi
