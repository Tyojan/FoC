#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULT_DIR="${RESULT_DIR:-/home/sawa/ango/result/x86_64}"
TARGET_DIR="${TARGET_DIR:-/home/sawa/ango/target/x86_64}"
KHUNT_VENV_ACTIVATE="${KHUNT_VENV_ACTIVATE:-/home/sawa/ango/.venv_khunt/bin/activate}"
FOC_VENV_ACTIVATE="${FOC_VENV_ACTIVATE:-/home/sawa/FoC/.venv/bin/activate}"
MODEL_PATH="${MODEL_PATH:-/home/sawa/FoC/FoC-BinLLM-220m-ft/}"
CUDA_VISIBLE_DEVICES_VALUE="${CUDA_VISIBLE_DEVICES_VALUE:-1}"
ZIP_DIR="${ZIP_DIR:-$ROOT_DIR/result_zips}"
SHORT_SHA="${SHORT_SHA:-$(git -C "$ROOT_DIR" rev-parse --short=7 HEAD 2>/dev/null || date +%Y%m%d)}"

log() {
  printf '[+] %s\n' "$*"
}

require_file() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "Missing required path: $path" >&2
    exit 1
  fi
}

activate_venv() {
  local activate_file="$1"
  require_file "$activate_file"
  # shellcheck disable=SC1090
  source "$activate_file"
}

find_ghidra_headless() {
  if [[ -n "${GHIDRA_HEADLESS:-}" && -x "$GHIDRA_HEADLESS" ]]; then
    printf '%s\n' "$GHIDRA_HEADLESS"
    return 0
  fi

  if command -v analyzeHeadless >/dev/null 2>&1; then
    command -v analyzeHeadless
    return 0
  fi

  if [[ -n "${GHIDRA_HOME:-}" && -x "$GHIDRA_HOME/support/analyzeHeadless" ]]; then
    printf '%s\n' "$GHIDRA_HOME/support/analyzeHeadless"
    return 0
  fi

  return 1
}

prepare_stripped_copy() {
  local source_binary="$1"
  local stripped_binary="$2"

  if [[ -f "$stripped_binary" ]]; then
    return 0
  fi

  require_file "$source_binary"
  mkdir -p "$(dirname "$stripped_binary")"
  cp "$source_binary" "$stripped_binary"

  if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "$stripped_binary" 2>/dev/null || strip --strip-all "$stripped_binary" 2>/dev/null || true
  fi
}

cleanup_previous_outputs() {
  mkdir -p "$RESULT_DIR"
  find "$RESULT_DIR" -maxdepth 1 -type f -name '*.json' -delete
}

run_bin2json() {
  local binary="$1"
  local output_json="$2"
  local ghidra_headless

  ghidra_headless="$(find_ghidra_headless)"

  if [[ -f "$output_json" ]]; then
    log "$output_json already exists, skipping Ghidra export"
    return 0
  fi

  log "Exporting Ghidra JSON for $(basename "$binary")"
  python3 "$ROOT_DIR/bin2json.py" \
    "$binary" \
    "$output_json" \
    --backend ghidra \
    --ghidra-headless "$ghidra_headless" \
    --arch x86_64 \
    --bit 64 \
    --include-library \
    --include-thunks
}

run_llm_analysis() {
  local dump_json="$1"
  local llm_json="$2"

  if [[ -f "$llm_json" ]]; then
    log "$llm_json already exists, skipping LLM analysis"
    return 0
  fi

  require_file "$FOC_VENV_ACTIVATE"
  deactivate >/dev/null 2>&1 || true
  # shellcheck disable=SC1090
  source "$FOC_VENV_ACTIVATE"

  log "Running LLM analysis for $(basename "$dump_json")"
  CUDA_VISIBLE_DEVICES="$CUDA_VISIBLE_DEVICES_VALUE" python "$ROOT_DIR/evaluate_model.py" \
    --model_path "$MODEL_PATH" \
    --data_file "$dump_json" \
    --batch_size 16 \
    --src_domain pcode \
    --tgt_domain comment_and_name \
    --max_tgt_len 256

  # evaluate_model.py writes its results into the model path directory with a
  # filename like: evaluate_model.py.<datafile_basename>.pcode2comment_and_name.<timestamp>.json
  local base
  base="$(basename "$dump_json")"
  shopt -s nullglob
  local candidates=("$MODEL_PATH"/evaluate_model.py."$base".pcode2comment_and_name.*.json)
  shopt -u nullglob
  if (( ${#candidates[@]} > 0 )); then
    # pick the newest file
    local latest="$candidates[0]"
    for f in "${candidates[@]}"; do
      if [[ "$f" -nt "$latest" ]]; then
        latest="$f"
      fi
    done
    cp "$latest" "$llm_json"
    log "Copied generated JSON to $llm_json"
  else
    log "WARNING: evaluate_model.py did not produce expected JSON in $MODEL_PATH"
  fi
}

package_ghidra_outputs() {
  mkdir -p "$ZIP_DIR"
  local zip_name="${SHORT_SHA}-x86-ghidra-FoC-stripped.zip"
  local zip_path="$ZIP_DIR/$zip_name"

  shopt -s nullglob
  local files=("$RESULT_DIR"/*_ghidra*.json)
  if (( ${#files[@]} == 0 )); then
    log "No Ghidra JSON files to package"
    return 0
  fi

  (
    cd "$RESULT_DIR"
    zip -r "$zip_path" "${files[@]##$RESULT_DIR/}" >/dev/null
  )
  log "Created $zip_path"

  rm -f "$RESULT_DIR"/*_ghidra*.json
}

main() {
  require_file "$ROOT_DIR/bin2json.py"
  require_file "$ROOT_DIR/evaluate_model.py"
  require_file "$KHUNT_VENV_ACTIVATE"
  require_file "$FOC_VENV_ACTIVATE"

  cleanup_previous_outputs

  activate_venv "$KHUNT_VENV_ACTIVATE"

  local entries=(
    "libsodium|$TARGET_DIR/libsodium-1.0.20/src/libsodium/.libs/libsodium.so.26.2.0_stripped|$RESULT_DIR/libsodium_ghidra_stripped.json|$RESULT_DIR/libsodium_ghidra_stripped-foc.json|libsodium-ghidra-FoC-stripped-x86_64"
    "mbedtls_ssl|$TARGET_DIR/mbedtls/tests/test_suite_ssl_stripped|$RESULT_DIR/mbedtls_ssl_ghidra_stripped.json|$RESULT_DIR/mbedtls_ssl_ghidra_stripped-foc.json|mbedtls-ssl-ghidra-FoC-stripped-x86_64"
    "zlib|$TARGET_DIR/zlib-1.3.1/libz.so.1.3.1_stripped|$RESULT_DIR/zlib_ghidra_stripped.json|$RESULT_DIR/zlib_ghidra_stripped-foc.json|zlib-ghidra-FoC-stripped-x86_64"
    "tcat|$TARGET_DIR/gsm-1.0-pl22/bin/tcat_stripped|$RESULT_DIR/tcat_ghidra_stripped.json|$RESULT_DIR/tcat_ghidra_stripped-foc.json|tcat-ghidra-FoC-stripped-x86_64"
    "djpeg|$TARGET_DIR/jpeg-6b/djpeg_stripped|$RESULT_DIR/djpeg_ghidra_stripped.json|$RESULT_DIR/djpeg_ghidra_stripped-foc.json|djpeg-ghidra-FoC-stripped-x86_64"
    "libpng16|$TARGET_DIR/libpng-1.6.43/.libs/libpng16.so.16.43.0_stripped|$RESULT_DIR/libpng16_ghidra_stripped.json|$RESULT_DIR/libpng16_ghidra_stripped-foc.json|libpng16-ghidra-FoC-stripped-x86_64"
    "libavcodec|$TARGET_DIR/ffmpeg/libavcodec/libavcodec.so.62_stripped|$RESULT_DIR/libavcodec_ghidra_stripped.json|$RESULT_DIR/libavcodec_ghidra_stripped-foc.json|libavcodec-ghidra-FoC-stripped-x86_64"
  )

  local entry name binary dump_json llm_json artifact source_binary
  for entry in "${entries[@]}"; do
    IFS='|' read -r name binary dump_json llm_json artifact <<< "$entry"
    source_binary="${binary%_stripped}"

    activate_venv "$KHUNT_VENV_ACTIVATE"
    prepare_stripped_copy "$source_binary" "$binary"
    run_bin2json "$binary" "$dump_json"
    run_llm_analysis "$dump_json" "$llm_json"
    log "Finished $name ($artifact)"
  done

  package_ghidra_outputs
}

main "$@"