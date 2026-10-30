#!/usr/bin/env bash
# Descarga el log de ejemplo (OpenSSH_2k.log) del dataset publico loghub.
# Dataset: https://github.com/logpai/loghub  (uso academico/investigacion, citar el repositorio)
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
git clone --depth 1 --filter=blob:none --sparse https://github.com/logpai/loghub.git "$tmp/loghub"
(cd "$tmp/loghub" && git sparse-checkout set OpenSSH)
cp "$tmp/loghub/OpenSSH/OpenSSH_2k.log" ./OpenSSH_2k.log
rm -rf "$tmp"
echo "Listo: data/OpenSSH_2k.log"
