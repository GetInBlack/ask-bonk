#!/bin/sh
set -eu

: "${ASKPASS_SENTINEL:?}"
printf 'invoked\n' >> "${ASKPASS_SENTINEL}"
printf '%s\n' "sentinel-credential"
