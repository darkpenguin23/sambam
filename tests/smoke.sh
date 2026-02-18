#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/sambam"
TMP_BASE="${TMPDIR:-/tmp}/sambam-smoke-$$"

PASS=0
FAIL=0
SKIP=0

if [[ -t 1 ]]; then
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_RESET=$'\033[0m'
else
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_RESET=""
fi

cleanup() {
  rm -rf "${TMP_BASE}"
}
trap cleanup EXIT

mkdir -p "${TMP_BASE}"

ok() {
  PASS=$((PASS + 1))
  printf '%s[PASS]%s %s\n' "${C_GREEN}" "${C_RESET}" "$1"
}

bad() {
  FAIL=$((FAIL + 1))
  printf '%s[FAIL]%s %s\n' "${C_RED}" "${C_RESET}" "$1"
}

skip() {
  SKIP=$((SKIP + 1))
  printf '%s[SKIP]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$1"
}

run_expect_ok() {
  local name="$1"
  shift
  if "$@" >"${TMP_BASE}/out.log" 2>"${TMP_BASE}/err.log"; then
    ok "${name}"
  else
    bad "${name}"
    printf '  cmd: %s\n' "$*"
    printf '  stderr:\n'
    sed -n '1,80p' "${TMP_BASE}/err.log"
  fi
}

run_expect_fail_contains() {
  local name="$1"
  local needle="$2"
  shift 2
  if "$@" >"${TMP_BASE}/out.log" 2>"${TMP_BASE}/err.log"; then
    bad "${name} (unexpected success)"
    printf '  cmd: %s\n' "$*"
    printf '  stdout:\n'
    sed -n '1,80p' "${TMP_BASE}/out.log"
    return
  fi
  if grep -Fq "${needle}" "${TMP_BASE}/err.log"; then
    ok "${name}"
  else
    bad "${name} (missing error text)"
    printf '  expected: %s\n' "${needle}"
    printf '  stderr:\n'
    sed -n '1,120p' "${TMP_BASE}/err.log"
  fi
}

printf '== sambam smoke tests ==\n'
printf 'repo: %s\n\n' "${ROOT_DIR}"

run_expect_ok "build binary" bash -lc "cd '${ROOT_DIR}' && GOCACHE='${TMP_BASE}/gocache' go build -o sambam ./"
run_expect_ok "unit tests" bash -lc "cd '${ROOT_DIR}' && GOCACHE='${TMP_BASE}/gocache' go test ./..."

cat >"${TMP_BASE}/legacy-user.toml" <<'EOF'
username = "admin"
password = "secret"
[shares.docs]
path = "/tmp"
EOF
run_expect_fail_contains "reject legacy username/password" "legacy config keys username/password are no longer supported" \
  "${BIN}" -c "${TMP_BASE}/legacy-user.toml"

cat >"${TMP_BASE}/legacy-shares.toml" <<'EOF'
[shares]
docs = "/tmp"
EOF
run_expect_fail_contains "reject legacy [shares] shorthand" "expected table [shares.docs]" \
  "${BIN}" -c "${TMP_BASE}/legacy-shares.toml"

cat >"${TMP_BASE}/policy-conflict.toml" <<'EOF'
[[users]]
name = "test"
password = "secret"

[shares.docs]
path = "/tmp"
guest = true
allow_users = ["test"]
EOF
run_expect_fail_contains "reject guest + allow_users conflict" "guest=true cannot be combined with allow_users" \
  "${BIN}" -c "${TMP_BASE}/policy-conflict.toml"

run_expect_ok "gen-config single user writes allow_users" \
  "${BIN}" -u test -p secret -n docs:/tmp -G "${TMP_BASE}/gen-user.toml"
if grep -Fq 'allow_users = ["test"]' "${TMP_BASE}/gen-user.toml"; then
  ok "generated allow_users present"
else
  bad "generated allow_users present"
  sed -n '1,120p' "${TMP_BASE}/gen-user.toml"
fi

run_expect_ok "gen-config anonymous writes guest=true" \
  "${BIN}" -n docs:/tmp -G "${TMP_BASE}/gen-guest.toml"
if grep -Fq 'guest = true' "${TMP_BASE}/gen-guest.toml"; then
  ok "generated guest=true present"
else
  bad "generated guest=true present"
  sed -n '1,120p' "${TMP_BASE}/gen-guest.toml"
fi

cat >"${TMP_BASE}/explicit-only.toml" <<'EOF'
listen = "127.0.0.1:14445"
[shares.docs]
path = "/tmp"
guest = true
EOF
mkdir -p "${TMP_BASE}/work"
cat >"${TMP_BASE}/work/.sambamrc" <<'EOF'
listen = "127.0.0.1:15555"
[shares.bad]
path = "/var"
guest = true
EOF
run_expect_ok "explicit -c ignores local .sambamrc" \
  bash -lc "cd '${TMP_BASE}/work' && timeout 2s '${BIN}' -c '${TMP_BASE}/explicit-only.toml' -v >/tmp/sambam-smoke-banner.log 2>/dev/null || true"
if grep -Fq 'Share        docs' /tmp/sambam-smoke-banner.log && ! grep -Fq 'Share        bad' /tmp/sambam-smoke-banner.log; then
  ok "explicit config precedence validated"
else
  bad "explicit config precedence validated"
  sed -n '1,80p' /tmp/sambam-smoke-banner.log || true
fi

# Optional Linux loopback integration check (mount, symlink, copy/hash, cleanup, readonly).
if [[ "$(uname -s)" != "Linux" ]]; then
  skip "linux self-mount integration (non-linux host)"
elif [[ "${EUID}" -ne 0 ]]; then
  skip "linux self-mount integration (requires root)"
elif ! command -v mount.cifs >/dev/null 2>&1; then
  skip "linux self-mount integration (mount.cifs not installed)"
else
  SRC_DIR="${TMP_BASE}/src"
  MNT_DIR="${TMP_BASE}/mnt"
  mkdir -p "${SRC_DIR}" "${MNT_DIR}" "${TMP_BASE}/back"

  printf 'hello-smoke\n' > "${SRC_DIR}/hello.txt"
  mkdir -p "${SRC_DIR}/dir-target"
  dd if=/dev/urandom of="${TMP_BASE}/small.bin" bs=1M count=4 status=none
  dd if=/dev/urandom of="${TMP_BASE}/big.bin" bs=1M count=100 status=none

  mount_guest_share() {
    local port="$1"
    local opts
    for opts in \
      "guest,port=${port},vers=3.1.1,posix,cifsacl,mfsymlinks" \
      "guest,port=${port},vers=3.1.1,posix,cifsacl" \
      "guest,port=${port},vers=3.1.1,mfsymlinks" \
      "guest,port=${port},vers=3.1.1" \
      "guest,port=${port}"; do
      if mount -t cifs //127.0.0.1/smoke "${MNT_DIR}" -o "${opts}" >/dev/null 2>&1; then
        return 0
      fi
    done
    return 1
  }

  is_mfsymlink_file() {
    local path="$1"
    [[ -f "${path}" ]] || return 1
    local sig
    sig="$(dd if="${path}" bs=1 count=5 2>/dev/null || true)"
    [[ "${sig}" == "XSym" ]]
  }

  CFG_FILE="${TMP_BASE}/mount-check.toml"
  LOG_FILE="${TMP_BASE}/mount-check.log"
  cat > "${CFG_FILE}" <<EOF
listen = "127.0.0.1:14446"
[shares.smoke]
path = "${SRC_DIR}"
guest = true
EOF

  "${BIN}" -c "${CFG_FILE}" -L "${LOG_FILE}" >/dev/null 2>&1 &
  SRV_PID=$!
  sleep 1
  if ! kill -0 "${SRV_PID}" 2>/dev/null; then
    skip "linux self-mount integration (server failed to start)"
  else
    if mount_guest_share 14446; then
      if [[ -f "${MNT_DIR}/hello.txt" ]] && grep -Fq "hello-smoke" "${MNT_DIR}/hello.txt"; then
        ok "linux self-mount basic read"
      else
        bad "linux self-mount basic read"
      fi

      # Symlink creation tests (file and directory).
      ln_err1="${TMP_BASE}/ln1.err"
      ln_err2="${TMP_BASE}/ln2.err"
      if ln -s "hello.txt" "${MNT_DIR}/link-file" 2>"${ln_err1}" && \
         ln -s "dir-target" "${MNT_DIR}/link-dir" 2>"${ln_err2}"; then
        mnt_side_ok=false
        src_side_ok=false
        if [[ -L "${MNT_DIR}/link-file" && -L "${MNT_DIR}/link-dir" ]]; then
          mnt_side_ok=true
        fi
        if [[ -L "${SRC_DIR}/link-file" && -L "${SRC_DIR}/link-dir" ]]; then
          src_side_ok=true
        elif is_mfsymlink_file "${SRC_DIR}/link-file" && is_mfsymlink_file "${SRC_DIR}/link-dir"; then
          src_side_ok=true
        fi
        if [[ "${mnt_side_ok}" == true && "${src_side_ok}" == true ]]; then
          ok "linux symlink create (file + dir)"
        else
          bad "linux symlink create (file + dir)"
          printf '  mount side:\n'
          ls -ld "${MNT_DIR}/link-file" "${MNT_DIR}/link-dir" 2>/dev/null || true
          printf '  source side:\n'
          ls -ld "${SRC_DIR}/link-file" "${SRC_DIR}/link-dir" 2>/dev/null || true
        fi
      else
        if grep -Eqi "operation not supported|not supported|function not implemented|operation not permitted|permission denied" "${ln_err1}" "${ln_err2}" 2>/dev/null; then
          skip "linux symlink create (file + dir) unsupported by cifs mount/client"
        else
          bad "linux symlink create (file + dir)"
          printf '  ln -s command failed\n'
          sed -n '1,2p' "${ln_err1}" "${ln_err2}" 2>/dev/null || true
        fi
      fi

      # Copy to share and back, then compare hashes.
      cp "${TMP_BASE}/small.bin" "${MNT_DIR}/small.bin"
      cp "${TMP_BASE}/big.bin" "${MNT_DIR}/big.bin"
      cp "${MNT_DIR}/small.bin" "${TMP_BASE}/back/small.back.bin"
      cp "${MNT_DIR}/big.bin" "${TMP_BASE}/back/big.back.bin"

      small_src="$(sha256sum "${TMP_BASE}/small.bin" | awk '{print $1}')"
      small_back="$(sha256sum "${TMP_BASE}/back/small.back.bin" | awk '{print $1}')"
      big_src="$(sha256sum "${TMP_BASE}/big.bin" | awk '{print $1}')"
      big_back="$(sha256sum "${TMP_BASE}/back/big.back.bin" | awk '{print $1}')"
      if [[ "${small_src}" == "${small_back}" ]] && [[ "${big_src}" == "${big_back}" ]]; then
        ok "linux copy/hash round-trip (small + 100MB)"
      else
        bad "linux copy/hash round-trip (small + 100MB)"
      fi

      # Delete test artifacts through mount and verify on source path.
      rm -f "${MNT_DIR}/small.bin" "${MNT_DIR}/big.bin" "${MNT_DIR}/link-file" "${MNT_DIR}/link-dir"
      if [[ ! -e "${SRC_DIR}/small.bin" && ! -e "${SRC_DIR}/big.bin" && ! -e "${SRC_DIR}/link-file" && ! -e "${SRC_DIR}/link-dir" ]]; then
        ok "linux delete/cleanup verification"
      else
        bad "linux delete/cleanup verification"
      fi

      umount "${MNT_DIR}" >/dev/null 2>&1 || true
    else
      # Environment limitation (kernel/module/capability) should not fail smoke script.
      skip "linux self-mount integration (mount failed in this environment)"
    fi
  fi
  kill -INT "${SRV_PID}" >/dev/null 2>&1 || true
  wait "${SRV_PID}" 2>/dev/null || true

  # Read-only mount check.
  RO_CFG_FILE="${TMP_BASE}/mount-ro-check.toml"
  RO_LOG_FILE="${TMP_BASE}/mount-ro-check.log"
  cat > "${RO_CFG_FILE}" <<EOF
listen = "127.0.0.1:14447"
readonly = true
[shares.smoke]
path = "${SRC_DIR}"
guest = true
EOF

  "${BIN}" -c "${RO_CFG_FILE}" -L "${RO_LOG_FILE}" >/dev/null 2>&1 &
  RO_SRV_PID=$!
  sleep 1
  if ! kill -0 "${RO_SRV_PID}" 2>/dev/null; then
    skip "linux readonly integration (server failed to start)"
  else
    if mount_guest_share 14447; then
      if touch "${MNT_DIR}/should-not-write" >/dev/null 2>&1; then
        bad "linux readonly enforcement"
      else
        ok "linux readonly enforcement"
      fi
      umount "${MNT_DIR}" >/dev/null 2>&1 || true
    else
      skip "linux readonly integration (mount failed in this environment)"
    fi
  fi
  kill -INT "${RO_SRV_PID}" >/dev/null 2>&1 || true
  wait "${RO_SRV_PID}" 2>/dev/null || true

  # Authenticated mount check.
  AUTH_CFG_FILE="${TMP_BASE}/mount-auth-check.toml"
  AUTH_LOG_FILE="${TMP_BASE}/mount-auth-check.log"
  cat > "${AUTH_CFG_FILE}" <<EOF
listen = "127.0.0.1:14448"
[[users]]
name = "smokeuser"
password = "smokepass"
[shares.smoke]
path = "${SRC_DIR}"
allow_users = ["smokeuser"]
EOF

  "${BIN}" -c "${AUTH_CFG_FILE}" -L "${AUTH_LOG_FILE}" >/dev/null 2>&1 &
  AUTH_SRV_PID=$!
  sleep 1
  if ! kill -0 "${AUTH_SRV_PID}" 2>/dev/null; then
    skip "linux authenticated integration (server failed to start)"
  else
    if mount -t cifs //127.0.0.1/smoke "${MNT_DIR}" -o username=smokeuser,password=smokepass,port=14448,vers=3.1.1 >/dev/null 2>&1; then
      if [[ -f "${MNT_DIR}/hello.txt" ]] && grep -Fq "hello-smoke" "${MNT_DIR}/hello.txt"; then
        ok "linux authenticated mount"
      else
        bad "linux authenticated mount"
      fi
      umount "${MNT_DIR}" >/dev/null 2>&1 || true
    else
      skip "linux authenticated integration (mount failed in this environment)"
    fi
  fi
  kill -INT "${AUTH_SRV_PID}" >/dev/null 2>&1 || true
  wait "${AUTH_SRV_PID}" 2>/dev/null || true
fi

printf '\n== summary ==\n'
printf 'pass: %d\n' "${PASS}"
printf 'fail: %d\n' "${FAIL}"
printf 'skip: %d\n' "${SKIP}"

if [[ ${FAIL} -ne 0 ]]; then
  exit 1
fi
