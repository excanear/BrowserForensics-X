#!/usr/bin/env bash
# =============================================================================
#  BrowserForensics-X — multi-browser DFIR acquisition & analysis toolkit
#  Single-file tool: Bash orchestrates discovery, controlled acquisition,
#  hashing, manifests, audit logging, parallel execution and verification.
#  Binary/structured formats (SQLite, LevelDB, SNSS, mozLz4, plist,
#  binarycookies, cache formats) are parsed by an embedded Python 3 engine
#  (stdlib only) that is written to a private temp dir at runtime.
#
#  Forensic principles enforced by design:
#   * sources are only read; analysis runs exclusively on hashed copies
#   * every acquired file: SHA-256 of source and copy + stat metadata
#   * tamper-evident (hash-chained) audit log; verify subcommand
#   * secrets / personal data redacted in derived output by default
#   * files found in evidence are never executed, sourced or imported
#   * no network access of any kind
# =============================================================================
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    echo "BrowserForensics-X requires bash >= 4.4 (found ${BASH_VERSION:-unknown}). On macOS: brew install bash" >&2
    exit 3
fi
set -Eeuo pipefail
shopt -s nullglob
umask 077
BFX_ORIG_LOCALE="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
export LC_ALL=C TZ=UTC

readonly BFX_NAME="BrowserForensics-X"
readonly BFX_VERSION="1.0.0"
export BFX_VERSION
BFX_SELF="${BASH_SOURCE[0]}"
case "$BFX_SELF" in /*) ;; *) BFX_SELF="$PWD/$BFX_SELF" ;; esac
readonly BFX_SELF

# exit codes
readonly E_OK=0 E_ERR=1 E_USAGE=2 E_DEPS=3 E_INTEGRITY=4 E_PARTIAL=5

# ------------------------------------------------------------------ settings
LOG_LEVEL=info QUIET=0 USE_COLOR=auto
CMD="" CASE_DIR="" CASE_ID="" EXAMINER="${USER:-${USERNAME:-unknown}}" NOTES=""
declare -a ROOTS=() SOURCES_ARG=() LIMITATIONS=()
LIVE=1 DEEP=0 DEPTH=8 OS_ARTIFACTS=1 NO_CACHE=0 FULL=0 MAX_FILE_SIZE=$((2*1024*1024*1024))
JOBS=0 REDACT=1 RECOVER=1 FS_CORR=1 KEEP_WORK=0 FORMATS="html,json,csv,md" OUT_DIR=""
F_SINCE="" F_UNTIL="" F_DOMAIN="" F_PROFILE="" F_BROWSER="" F_TYPE="" F_CLASS=""
TL_FORMAT=table TL_LIMIT=0 BROWSER_SEL="" FAMILY_HINT="" KEEP_TMP=0 OFFLINE=1

# runtime
TMP_DIR="" LOCK_DIR="" PY="" PY_VERSION="" PY_PLATFORM="" PY_SQLITE="" PY_NATIVE_WIN=0 ENGINE=""
HOST_OS="" HASH_TOOL="" GNU_FIND=0 RUN_USER="${USER:-${USERNAME:-unknown}}" CMDLINE=""
declare -a PROFILE_ROWS=() SOURCE_ROWS=()
declare -A SEEN_PROFILE=()
PCOUNT=0 EVSEQ=0 ACQ_OK=0 ACQ_FAIL=0 ACQ_SKIP=0 ACQ_BYTES=0

# ------------------------------------------------------------------ logging
now_utc() { local t; printf -v t '%(%Y-%m-%dT%H:%M:%SZ)T' -1; printf '%s' "$t"; }
log() {
    local lvl=$1; shift
    local msg="$*" ts; printf -v ts '%(%Y-%m-%dT%H:%M:%SZ)T' -1
    if [[ -n ${CASE_DIR:-} && -d ${CASE_DIR}/logs ]]; then
        printf '%s [%s] %s\n' "$ts" "${lvl^^}" "$msg" >> "$CASE_DIR/logs/bfx.log" 2>/dev/null || true
    fi
    local n=20 m=20
    case $lvl in debug) n=10 ;; warn) n=30 ;; error) n=40 ;; esac
    case $LOG_LEVEL in debug) m=10 ;; warn) m=30 ;; error) m=40 ;; esac
    (( n >= m )) || return 0
    [[ $QUIET == 1 && $lvl != error && $lvl != warn ]] && return 0
    local g c lab
    case $lvl in
        debug) g=${G_DBG:-.} c=$C_DIM lab=debug ;; info) g=${G_INFO:-*} c=$C_PRI lab=info ;;
        warn) g=${G_WARN:-!} c=$C_WARN lab=warn ;; *) g=${G_ERR:-x} c=$C_ERR lab=error ;;
    esac
    (( UI_PROG_ACTIVE )) && ui_progress_end
    local t=""; [[ $LOG_LEVEL == debug ]] && t="${C_DIM}${ts:11:8}${C_R} "
    if [[ $lvl == info || $lvl == debug ]]; then
        local d=""; [[ $lvl == debug ]] && d=$C_DIM
        printf '    %s%s%s %s%s%s%s\n' "$c" "$g" "$C_R" "$t" "$d" "$msg" "$C_R" >&2
    else
        printf '    %s%s %s%s %s%s\n' "$c" "$g" "$C_B" "$lab" "$C_R$t" "$c$msg$C_R" >&2
    fi
}
die() {
    local code=$1; shift
    log error "$*"
    [[ $code == "$E_USAGE" ]] && printf '      %shelp: %s help%s\n' "$C_DIM" "${BFX_SELF##*/}" "$C_R" >&2
    exit "$code"
}
say() { [[ $QUIET == 1 ]] || printf '%s\n' "$*"; }

jset() {  # jset VAR value -> VAR holds a quoted JSON string (no fork: forks are expensive on MSYS/Cygwin)
    local s=$2
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
    s=${s//[$'\x01'-$'\x08'$'\x0b'$'\x0c'$'\x0e'-$'\x1f'$'\x7f']/?}
    printf -v "$1" '"%s"' "$s"
}
jstr() { local _j; jset _j "$1"; printf '%s' "$_j"; }
json_escape() { local _j; jset _j "$1"; _j=${_j#\"}; printf '%s' "${_j%\"}"; }

record_error() {  # stage profile_id item message
    [[ -n ${CASE_DIR:-} && -d $CASE_DIR ]] || return 0
    printf '{"ts":%s,"stage":%s,"profile_id":%s,"item":%s,"message":%s}\n' "$(jstr "$(now_utc)")" "$(jstr "$1")" \
        "$(jstr "$2")" "$(jstr "$3")" "$(jstr "$4")" >> "$CASE_DIR/errors.jsonl"
}
add_limitation() { local l; for l in "${LIMITATIONS[@]+"${LIMITATIONS[@]}"}"; do [[ $l == "$1" ]] && return 0; done; LIMITATIONS+=("$1"); }

# ------------------------------------------------------------------ hashing
sha256_stdin() {
    case $HASH_TOOL in
        sha256sum) sha256sum | cut -c1-64 ;;
        shasum) shasum -a 256 | cut -c1-64 ;;
        openssl) openssl dgst -sha256 -r | cut -c1-64 ;;
        *) die $E_DEPS "no SHA-256 implementation available" ;;
    esac
}
sha256_file() {
    case $HASH_TOOL in
        sha256sum) sha256sum -- "$1" | cut -c1-64 ;;
        shasum) shasum -a 256 -- "$1" | cut -c1-64 ;;
        openssl) openssl dgst -sha256 -r -- "$1" | cut -c1-64 ;;
    esac
}
# hash_nul_list LISTFILE OUTFILE : NUL-separated paths in, "hash<TAB>path\0" out
hash_nul_list() {
    local list=$1 out=$2 line p
    : > "$out"
    [[ -s $list ]] || return 0
    if [[ -z ${HASH_ZERO:-} ]]; then
        if [[ $HASH_TOOL == sha256sum ]] && sha256sum --help 2>&1 | grep -q -- '--zero'; then HASH_ZERO=1; else HASH_ZERO=0; fi
    fi
    if [[ $HASH_ZERO == 1 ]]; then
        xargs -0 sha256sum -z -- < "$list" 2>/dev/null | while IFS= read -r -d '' line; do
            printf '%s\t%s\0' "${line:0:64}" "${line:66}"
        done > "$out" || true
    else
        while IFS= read -r -d '' p; do
            local hsh; hsh=$(sha256_file "$p" 2>/dev/null) || continue
            printf '%s\t%s\0' "$hsh" "$p"
        done < "$list" > "$out"
    fi
}

# ------------------------------------------------------------------ audit log (hash-chained)
audit() {
    [[ -n ${CASE_DIR:-} && -d $CASE_DIR ]] || return 0
    local f="$CASE_DIR/audit.log" prev="GENESIS" ev=$1; shift
    local msg="$*"; msg=${msg//$'\t'/ }; msg=${msg//$'\n'/ }; msg=${msg//$'\r'/ }
    if [[ -n ${AUDIT_PREV:-} && ${AUDIT_FILE:-} == "$f" ]]; then prev=$AUDIT_PREV
    elif [[ -s $f ]]; then prev=$(tail -n 1 "$f"); prev=${prev##*$'\t'}; fi
    local ts; printf -v ts '%(%Y-%m-%dT%H:%M:%SZ)T' -1
    local line="$ts"$'\t'"$RUN_USER@${HOSTNAME:-host}"$'\t'"$ev"$'\t'"$msg"$'\t'"$prev"
    local hsh; hsh=$(printf '%s' "$line" | sha256_stdin)
    printf '%s\t%s\n' "$line" "$hsh" >> "$f"
    AUDIT_PREV=$hsh AUDIT_FILE=$f
}
verify_audit_chain() {
    local f=$1 prev="GENESIS" n=0 l body h p calc
    [[ -f $f ]] || { echo "missing audit log"; return 1; }
    while IFS= read -r l || [[ -n $l ]]; do
        n=$((n+1)); h=${l##*$'\t'}; body=${l%$'\t'*}; p=${body##*$'\t'}
        if [[ $p != "$prev" ]]; then echo "audit chain broken at line $n (previous-hash mismatch)"; return 1; fi
        calc=$(printf '%s' "$body" | sha256_stdin)
        if [[ $calc != "$h" ]]; then echo "audit line $n altered (hash mismatch)"; return 1; fi
        prev=$h
    done < "$f"
    echo "audit chain intact ($n entries)"
}

# ------------------------------------------------------------------ cleanup / traps
cleanup() {
    local rc=$?
    trap - EXIT ERR
    local j
    for j in $(jobs -pr 2>/dev/null); do kill "$j" 2>/dev/null || true; done
    if [[ -n ${TMP_DIR:-} && -d $TMP_DIR && ${TMP_DIR##*/} == bfx.* && $KEEP_TMP == 0 ]]; then
        rm -rf -- "$TMP_DIR" 2>/dev/null || true
    fi
    if [[ -n ${CASE_DIR:-} && -d ${CASE_DIR}/work && $KEEP_WORK == 0 ]]; then
        rm -rf -- "${CASE_DIR}/work" 2>/dev/null || true
    fi
    if [[ -n ${LOCK_DIR:-} && -d $LOCK_DIR ]]; then
        rm -f -- "$LOCK_DIR/pid" 2>/dev/null; rmdir -- "$LOCK_DIR" 2>/dev/null || true
        (( rc != 0 && rc != E_PARTIAL )) && audit "abort" "command=$CMD exit=$rc" || true
    fi
    exit "$rc"
}
on_err() { case $2 in return*|exit*) return 0 ;; esac; log error "unexpected failure at line $1: $2"; }
trap cleanup EXIT
trap 'on_err "$LINENO" "$BASH_COMMAND"' ERR
trap 'log warn "interrupted by signal"; exit 130' INT TERM HUP

# ------------------------------------------------------------------ environment / dependencies
detect_os() {
    case "$(uname -s 2>/dev/null)" in
        Linux) if grep -qi microsoft /proc/version 2>/dev/null; then HOST_OS=wsl; else HOST_OS=linux; fi ;;
        Darwin) HOST_OS=macos ;;
        MINGW*|MSYS*|CYGWIN*) HOST_OS=windows ;;
        *) HOST_OS=unknown ;;
    esac
}
detect_hash() {
    if command -v sha256sum >/dev/null 2>&1; then HASH_TOOL=sha256sum
    elif command -v shasum >/dev/null 2>&1; then HASH_TOOL=shasum
    elif command -v openssl >/dev/null 2>&1; then HASH_TOOL=openssl
    else HASH_TOOL=""; fi
    find --version 2>/dev/null | grep -q GNU && GNU_FIND=1 || GNU_FIND=0
}
run_timeout() { local s=$1; shift; if command -v timeout >/dev/null 2>&1; then timeout "$s" "$@"; else "$@"; fi; }
find_python() {
    [[ ${BFX_NO_PYTHON:-0} == 1 ]] && return 1
    local c out
    for c in ${BFX_PYTHON:-} python3 python; do
        command -v "$c" >/dev/null 2>&1 || continue
        out=$(run_timeout 30 "$c" -I -B -c 'import sys,sqlite3,json,plistlib,zlib,hmac,csv,html,xml.etree.ElementTree
assert sys.version_info >= (3, 8)
print("%d.%d.%d|%s|%s" % (sys.version_info[0], sys.version_info[1], sys.version_info[2], sqlite3.sqlite_version, sys.platform))' 2>/dev/null) || continue
        [[ $out == *"|"*"|"* ]] || continue
        PY=$(command -v "$c"); PY_VERSION=${out%%|*}; PY_PLATFORM=${out##*|}; out=${out#*|}; PY_SQLITE=${out%%|*}
        [[ $PY_PLATFORM == win32 && $HOST_OS == windows ]] && PY_NATIVE_WIN=1 || PY_NATIVE_WIN=0
        return 0
    done
    return 1
}
native_path() {  # path as understood by the Python interpreter
    if [[ $PY_NATIVE_WIN == 1 ]] && command -v cygpath >/dev/null 2>&1; then cygpath -m -- "$1"; else printf '%s' "$1"; fi
}
ensure_tmp() {
    [[ -n $TMP_DIR ]] && return 0
    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bfx.XXXXXXXX") || die $E_ERR "cannot create temporary directory"
}
require_python() {
    [[ -n $PY ]] || find_python || die $E_DEPS "Python >= 3.8 (stdlib sqlite3) is required for '$CMD'. Acquisition/verify work without it. Set BFX_PYTHON=/path/to/python3 if installed in a non-standard location."
    if [[ -z $ENGINE ]]; then
        ensure_tmp
        ENGINE="$TMP_DIR/bfx_engine.py"
        engine_source > "$ENGINE"
        chmod 0500 "$ENGINE" 2>/dev/null || true
    fi
}
engine() {  # run the embedded engine from a neutral cwd, isolated mode, no bytecode
    require_python
    ( cd "$TMP_DIR" && MSYS2_ARG_CONV_EXCL='*' PYTHONIOENCODING=utf-8 PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
        "$PY" -I -B "$(native_path "$ENGINE")" "$@" )
}
cmd_deps() {
    detect_os; detect_hash
    ui_to_stdout
    local ok=1 t line="" miss=""
    ui_section "Environment" "$BFX_NAME $BFX_VERSION"
    ui_kv "Host" "$HOST_OS ${C_DIM}$(uname -sr 2>/dev/null)${C_R}"
    ui_ok "Bash ${C_B}${BASH_VERSION%%(*}${C_R} ${C_DIM}(requires >= 4.4)${C_R}"
    if [[ -n $HASH_TOOL ]]; then ui_ok "SHA-256 via ${C_B}$HASH_TOOL${C_R}"; else ui_bad "SHA-256 tool missing (sha256sum / shasum / openssl)"; ok=0; fi
    if [[ $GNU_FIND == 1 ]]; then ui_ok "GNU find ${C_DIM}(batched stat)${C_R}"; else ui_warnl "BSD find ${C_DIM}(per-file stat fallback, slower)${C_R}"; fi
    ui_section "Core utilities"
    for t in find cp mkdir chmod stat date awk sed sort xargs tail cut grep comm uname; do
        if command -v "$t" >/dev/null 2>&1; then line+="${C_OK}${G_OK}${C_R} $t  "; else line+="${C_ERR}${G_ERR} $t${C_R}  "; miss+=" $t"; ok=0; fi
    done
    printf '    %s\n' "$line" >&"$UI_FD"
    [[ -n $miss ]] && ui_bad "missing:$miss"
    ui_section "Analysis engine"
    if find_python; then
        ui_ok "Python ${C_B}$PY_VERSION${C_R} ${G_SEP} SQLite $PY_SQLITE ${G_SEP} $PY_PLATFORM"
        ui_note "$PY"
    else
        ui_warnl "Python 3.8+ not found ${C_DIM}— analyze / report / timeline / selftest unavailable; discover, acquire and verify still work${C_R}"
    fi
    ui_section "Optional"
    for t in sqlite3 jq cygpath getfattr xattr file; do
        if command -v "$t" >/dev/null 2>&1; then printf '    %s%s%s %-9s %s%s%s\n' "$C_OK" "$G_OK" "$C_R" "$t" "$C_DIM" "$(command -v "$t")" "$C_R" >&"$UI_FD"
        else printf '    %s%s %-9s not installed — not required%s\n' "$C_DIM" "$G_RING" "$t" "$C_R" >&"$UI_FD"; fi
    done
    ui_section "Network"
    ui_ok "never used ${C_DIM}— offline by design, no telemetry, no lookups${C_R}"
    printf '\n' >&"$UI_FD"
    if (( ok )) && [[ -n $PY ]]; then ui_box "$C_OK" "READY" "${C_OK}${G_OK}${C_R} Full pipeline available: discover ${G_SEP} acquire ${G_SEP} analyze ${G_SEP} report ${G_SEP} verify"
    elif (( ok )); then ui_box "$C_WARN" "PARTIAL" "${C_WARN}${G_WARN}${C_R} Acquisition and verification available; install Python 3.8+ for analysis"
    else ui_box "$C_ERR" "NOT READY" "${C_ERR}${G_ERR}${C_R} Required tools are missing (see above)"; return $E_DEPS; fi
}

# ------------------------------------------------------------------ argument helpers
parse_size() {
    local v=${1^^} n
    [[ $v =~ ^([0-9]+)([KMGT]?)B?$ ]] || return 1
    n=${BASH_REMATCH[1]}
    case ${BASH_REMATCH[2]} in K) n=$((n*1024)) ;; M) n=$((n*1024**2)) ;; G) n=$((n*1024**3)) ;; T) n=$((n*1024**4)) ;; esac
    printf '%s' "$n"
}
valid_date() {
    [[ $1 =~ ^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])([T\ ]([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9](\.[0-9]{1,6})?)?)?(Z|[+-][0-9]{2}:?[0-9]{2})?$ ]]
}
need_arg() { [[ $# -ge 2 && -n ${2:-} && ${2:0:2} != "--" ]] || die $E_USAGE "option $1 requires a value (see --help)"; }
abspath() {
    local p=$1
    if [[ -d $p ]]; then (cd -- "$p" && pwd -P); else
        local d b; d=$(dirname -- "$p"); b=$(basename -- "$p")
        [[ -d $d ]] || return 1
        printf '%s/%s' "$(cd -- "$d" && pwd -P)" "$b"
    fi
}

# =============================================================================
#  Terminal UI layer
#  * capability detection: truecolor / 256 / 16 / no colour, Unicode / ASCII,
#    terminal width, TTY per stream; honours NO_COLOR, --no-color, BFX_ASCII=1
#  * all chrome (banner, steps, progress, panels) goes to stderr; data output
#    (timeline, tsv, json) stays clean on stdout
#  * fork-free rendering (forks are expensive on MSYS/Cygwin)
# =============================================================================
UI_ERR=0 UI_OUT=0 UI_UNI=0 UI_DEPTH=0 UI_COLS=100 UI_FD=2 UI_PROG_ACTIVE=0 UI_LINKS=0 UI_N=0
UI_ANSI_RE=$'\e\\[[0-9;]*m'
C_R="" C_B="" C_D="" C_I="" C_PRI="" C_SEC="" C_ACC="" C_OK="" C_WARN="" C_ERR="" C_MUT="" C_DIM="" C_TXT=""
C_ORG="" C_BLU="" C_INK="" B_PRI="" B_OK="" B_WARN="" B_ERR="" B_SEC="" B_MUT=""
declare -a UI_GRAD=() UI_BARG=()

ui_fg() {  # VAR r g b c256 c16
    case $UI_DEPTH in
        24) printf -v "$1" '\033[38;2;%d;%d;%dm' "$2" "$3" "$4" ;;
        8) printf -v "$1" '\033[38;5;%dm' "$5" ;;
        4) printf -v "$1" '\033[%sm' "$6" ;;
        *) printf -v "$1" '%s' "" ;;
    esac
}
ui_bg() {
    case $UI_DEPTH in
        24) printf -v "$1" '\033[48;2;%d;%d;%dm' "$2" "$3" "$4" ;;
        8) printf -v "$1" '\033[48;5;%dm' "$5" ;;
        4) printf -v "$1" '\033[%sm' "$6" ;;
        *) printf -v "$1" '%s' "" ;;
    esac
}
ui_palette() {
    if (( UI_DEPTH > 0 )); then C_R=$'\e[0m' C_B=$'\e[1m' C_D=$'\e[2m' C_I=$'\e[3m'; else C_R="" C_B="" C_D="" C_I=""; fi
    ui_fg C_PRI 34 211 238 45 96;    ui_fg C_SEC 167 139 250 141 95;  ui_fg C_ACC 244 114 182 211 95
    ui_fg C_OK 52 211 153 79 92;     ui_fg C_WARN 251 191 36 220 93;  ui_fg C_ERR 248 113 113 203 91
    ui_fg C_MUT 148 163 184 247 37;  ui_fg C_DIM 100 116 139 243 90;  ui_fg C_TXT 241 245 249 255 97
    ui_fg C_ORG 251 146 60 209 33;   ui_fg C_BLU 96 165 250 75 94;    ui_fg C_INK 15 23 42 234 30
    ui_bg B_PRI 34 211 238 45 46;    ui_bg B_OK 52 211 153 79 42;     ui_bg B_WARN 251 191 36 220 43
    ui_bg B_ERR 248 113 113 203 41;  ui_bg B_SEC 167 139 250 141 45;  ui_bg B_MUT 71 85 105 240 100
    local -a rgb=("34 211 238" "56 189 248" "99 163 250" "139 140 248" "192 132 252" "244 114 182")
    local -a c8=(51 45 39 105 141 213) c4=(96 96 94 95 95 95)
    local i r g b
    UI_GRAD=()
    for i in 0 1 2 3 4 5; do read -r r g b <<< "${rgb[i]}"; ui_fg "UI_GRAD[$i]" "$r" "$g" "$b" "${c8[i]}" "${c4[i]}"; done
    UI_BARG=()
    for ((i = 0; i < 28; i++)); do   # cyan -> violet -> pink progress gradient
        if (( i < 14 )); then r=$((34 + (167-34)*i/13)); g=$((211 + (139-211)*i/13)); b=$((238 + (250-238)*i/13))
        else r=$((167 + (244-167)*(i-14)/13)); g=$((139 + (114-139)*(i-14)/13)); b=$((250 + (182-250)*(i-14)/13)); fi
        if (( UI_DEPTH == 24 )); then printf -v "UI_BARG[$i]" '\033[38;2;%d;%d;%dm' "$r" "$g" "$b"; else UI_BARG[i]=$C_PRI; fi
    done
}
ui_glyphs() {
    if (( UI_UNI )); then
        G_OK='✔' G_ERR='✖' G_WARN='▲' G_INFO='●' G_DBG='·' G_ARR='›' G_DIA='◆' G_DOT='•' G_SEP='·' G_ELL='…' G_RING='○' G_HALF='◐'
        BX_TL='╭' BX_TR='╮' BX_BL='╰' BX_BR='╯' BX_H='─' BX_V='│' BX_LT='├' BX_RT='┤' BX_TT='┬' BX_BT='┴' BX_X='┼'
        BAR_F='━' BAR_E='─' G_BLK='█' G_LBAR='▌' G_RBAR='▐'
    else
        G_OK='+' G_ERR='x' G_WARN='!' G_INFO='*' G_DBG='.' G_ARR='>' G_DIA='#' G_DOT='-' G_SEP='|' G_ELL='~' G_RING='o' G_HALF='o'
        BX_TL='+' BX_TR='+' BX_BL='+' BX_BR='+' BX_H='-' BX_V='|' BX_LT='+' BX_RT='+' BX_TT='+' BX_BT='+' BX_X='+'
        BAR_F='#' BAR_E='.' G_BLK='#' G_LBAR='[' G_RBAR=']'
    fi
}
ui_init() {
    [[ -t 2 ]] && UI_ERR=1 || UI_ERR=0
    [[ -t 1 ]] && UI_OUT=1 || UI_OUT=0
    if [[ ${BFX_FORCE_TTY:-0} == 1 ]]; then UI_ERR=1; UI_OUT=1; fi
    UI_UNI=0
    if [[ ${BFX_ASCII:-0} != 1 ]]; then
        case "${BFX_ORIG_LOCALE,,}" in *utf-8*|*utf8*) UI_UNI=1 ;; esac
        [[ $HOST_OS == windows || -n ${WT_SESSION:-} || ${TERM_PROGRAM:-} =~ ^(mintty|iTerm.app|vscode|WezTerm|Apple_Terminal)$ ]] && UI_UNI=1
    fi
    if [[ $USE_COLOR == 0 || -n ${NO_COLOR:-} || ${TERM:-} == dumb ]] || (( ! UI_ERR && ! UI_OUT )); then UI_DEPTH=0
    elif [[ ${COLORTERM:-} == *truecolor* || ${COLORTERM:-} == *24bit* || -n ${WT_SESSION:-} || ${TERM_PROGRAM:-} =~ ^(mintty|iTerm.app|vscode|WezTerm)$ ]]; then UI_DEPTH=24
    elif [[ $HOST_OS == windows || ${TERM:-} == *256* ]]; then UI_DEPTH=8
    else UI_DEPTH=4; fi
    [[ ${BFX_COLOR_DEPTH:-} =~ ^(0|4|8|24)$ ]] && UI_DEPTH=$BFX_COLOR_DEPTH
    [[ -n ${WT_SESSION:-} || ${TERM_PROGRAM:-} =~ ^(iTerm.app|WezTerm|vscode|mintty)$ || -n ${VTE_VERSION:-} ]] && UI_LINKS=1
    if (( UI_ERR || UI_OUT )); then
        local c; c=${COLUMNS:-}; [[ $c =~ ^[0-9]+$ ]] || c=$(tput cols 2>/dev/null || echo 100)
        [[ $c =~ ^[0-9]+$ ]] || c=100
        (( c < 64 )) && c=64; (( c > 140 )) && c=140
        UI_COLS=$c
    fi
    ui_palette; ui_glyphs
}
ui_to_stdout() {  # renderers that print human output to stdout
    UI_FD=1
    if (( ! UI_OUT && UI_DEPTH > 0 )); then local d=$UI_DEPTH; UI_DEPTH=0; ui_palette; UI_DEPTH=$d; fi
}

# ---- text metrics (visible width: ANSI stripped, UTF-8 continuation bytes ignored)
ui_vlen() {
    local s=$1
    while [[ $s =~ $UI_ANSI_RE ]]; do s=${s//"${BASH_REMATCH[0]}"/}; done
    s=${s//[$'\x80'-$'\xbf']/}
    UI_N=${#s}
}
ui_rep() { local n=$2; (( n > 0 )) || { REPLY=""; return 0; }; printf -v REPLY '%*s' "$n" ''; REPLY=${REPLY// /$1}; }
ui_pad() { ui_vlen "$1"; ui_rep ' ' $(( $2 - UI_N )); REPLY="$1$REPLY"; }
_ui_fixtail() { while [[ -n $REPLY && ${REPLY: -1} == [$'\x80'-$'\xff'] ]]; do REPLY=${REPLY:0:${#REPLY}-1}; done; }
ui_trunc() {  # plain text, cut on the right
    ui_vlen "$1"
    if (( UI_N <= $2 )); then REPLY=$1; return 0; fi
    REPLY=${1:0:$(( $2 - 1 ))}; _ui_fixtail; REPLY+=$G_ELL
}
ui_ltrunc() {  # plain text, cut on the left (paths)
    ui_vlen "$1"
    if (( UI_N <= $2 )); then REPLY=$1; return 0; fi
    local s=${1: -$(( $2 - 1 ))}
    while [[ -n $s && ${s:0:1} == [$'\x80'-$'\xbf'] ]]; do s=${s:1}; done
    REPLY="$G_ELL$s"
}
ui_bytes() {
    local n=${1:-0}
    if (( n >= 1073741824 )); then printf -v REPLY '%d.%d GB' $((n/1073741824)) $(( (n%1073741824)*10/1073741824 ))
    elif (( n >= 1048576 )); then printf -v REPLY '%d.%d MB' $((n/1048576)) $(( (n%1048576)*10/1048576 ))
    elif (( n >= 1024 )); then printf -v REPLY '%d.%d KB' $((n/1024)) $(( (n%1024)*10/1024 ))
    else REPLY="$n B"; fi
}
ui_dur() { local s=${1:-0}; if (( s >= 3600 )); then printf -v REPLY '%dh %02dm' $((s/3600)) $((s%3600/60)); elif (( s >= 60 )); then printf -v REPLY '%dm %02ds' $((s/60)) $((s%60)); else REPLY="${s}s"; fi; }
ui_link() {  # url text -> OSC 8 hyperlink when the terminal supports it
    if (( UI_LINKS && UI_DEPTH > 0 )); then printf -v REPLY '\e]8;;%s\e\\%s\e]8;;\e\\' "$1" "$2"; else REPLY=$2; fi
}
ui_fileurl() {
    local p=$1
    if [[ $HOST_OS == windows ]] && command -v cygpath >/dev/null 2>&1; then p=$(cygpath -m -- "$p"); REPLY="file:///$p"; else REPLY="file://$p"; fi
}

# ---- components
ui_quiet() { [[ $QUIET == 1 ]]; }
ui_progress_end() { if (( UI_PROG_ACTIVE )); then printf '\r\033[K' >&2; UI_PROG_ACTIVE=0; fi; return 0; }
ui_progress() {  # label cur total [detail]
    (( UI_ERR )) && ! ui_quiet || return 0
    local label=$1 cur=$2 tot=$3 det=${4:-} w=28 i fill pct bar=""
    (( tot > 0 )) || tot=1
    (( cur > tot )) && cur=$tot
    pct=$(( cur * 100 / tot )); fill=$(( cur * w / tot ))
    for ((i = 0; i < fill; i++)); do bar+="${UI_BARG[i]}$BAR_F"; done
    ui_rep "$BAR_E" $(( w - fill )); bar+="$C_R$C_DIM$REPLY$C_R"
    ui_pad "$label" 20; label=$REPLY
    [[ -n $det ]] && { ui_trunc "$det" $(( UI_COLS - 66 > 8 ? UI_COLS - 66 : 8 )); det=$REPLY; }
    printf '\r    %s%s%s %s %s %s%3d%%%s %s%s/%s%s %s%s%s\033[K' "$C_PRI" "$G_DIA" "$C_R" "$label" "$bar" "$C_B" "$pct" "$C_R" \
        "$C_DIM" "$cur" "$tot" "$C_R" "$C_DIM" "$det" "$C_R" >&2
    UI_PROG_ACTIVE=1
}
ui_banner() {  # [fd]
    local fd=${1:-2}
    local -a L R
    if (( UI_UNI )); then
        L=(' ██████╗ ███████╗██╗  ██╗' ' ██╔══██╗██╔════╝╚██╗██╔╝' ' ██████╔╝█████╗   ╚███╔╝ ' ' ██╔══██╗██╔══╝   ██╔██╗ ' ' ██████╔╝██║     ██╔╝ ██╗' ' ╚═════╝ ╚═╝     ╚═╝  ╚═╝')
    else
        L=(' ____  _____ __  __ ' '| __ )|  ___|\ \/ / ' '|  _ \| |_   \  /  ' '| |_) |  _|  /  \  ' '|____/|_|   /_/\_\ ' '                    ')
    fi
    R=("" "${C_B}${C_TXT}BrowserForensics${C_ACC}-X${C_R}  ${C_DIM}v$BFX_VERSION${C_R}"
       "${C_SEC}${C_I}evidence-grade browser forensics${C_R}"
       "${C_MUT}discover $G_SEP acquire $G_SEP recover $G_SEP correlate $G_SEP report${C_R}"
       "${C_DIM}${HOST_OS:-?} $G_SEP bash ${BASH_VERSION%%(*} $G_SEP offline $G_SEP sources read-only${C_R}" "")
    local i
    printf '\n' >&"$fd"
    for i in 0 1 2 3 4 5; do printf '  %s%s%s   %s\n' "${UI_GRAD[i]}" "${L[i]}" "$C_R" "${R[i]}" >&"$fd"; done
    printf '\n' >&"$fd"
}
ui_banner_maybe() { (( UI_ERR )) && ! ui_quiet && [[ ${BFX_NO_BANNER:-0} != 1 ]] && ui_banner 2; return 0; }
ui_step() {  # n title [subtitle]
    ui_quiet && return 0
    ui_progress_end
    local n=$1 t=$2 sub=${3:-}
    if (( UI_DEPTH > 0 )); then
        printf '\n  %s%s%s %s/%s %s  %s%s%s%s  %s%s%s\n' "$B_PRI" "$C_INK" "$C_B" "$n" "$STEP_TOTAL" "$C_R" "$C_B" "$C_TXT" "$t" "$C_R" "$C_DIM" "$sub" "$C_R" >&"$UI_FD"
    else
        printf '\n  [%s/%s] %s  %s\n' "$n" "$STEP_TOTAL" "$t" "$sub" >&"$UI_FD"
    fi
}
STEP_N=0 STEP_TOTAL=1 RUN_T0=0
ui_next() { STEP_N=$((STEP_N + 1)); ui_step "$STEP_N" "$@"; }
ui_section() {  # title [right-text]
    ui_quiet && return 0
    local t=$1 r=${2:-} w
    ui_vlen "$t $r"; w=$(( UI_COLS - UI_N - 9 )); (( w < 4 )) && w=4
    ui_rep "$BX_H" "$w"
    printf '\n  %s%s%s %s%s%s %s%s%s %s%s%s\n' "$C_SEC" "$G_DIA" "$C_R" "$C_B$C_TXT" "$t" "$C_R" "$C_DIM" "$REPLY" "$C_R" "$C_MUT" "$r" "$C_R" >&"$UI_FD"
}
ui_ok()   { ui_quiet && return 0; ui_progress_end; printf '    %s%s%s %s\n' "$C_OK" "$G_OK" "$C_R" "$*" >&"$UI_FD"; }
ui_bad()  { ui_progress_end; printf '    %s%s%s %s\n' "$C_ERR" "$G_ERR" "$C_R" "$*" >&"$UI_FD"; }
ui_warnl(){ ui_progress_end; printf '    %s%s%s %s\n' "$C_WARN" "$G_WARN" "$C_R" "$*" >&"$UI_FD"; }
ui_info() { ui_quiet && return 0; ui_progress_end; printf '    %s%s%s %s\n' "$C_PRI" "$G_INFO" "$C_R" "$*" >&"$UI_FD"; }
ui_note() { ui_quiet && return 0; printf '      %s%s%s\n' "$C_DIM" "$*" "$C_R" >&"$UI_FD"; }
ui_kv()   { ui_quiet && return 0; ui_pad "$1" 14; printf '    %s%s%s %s\n' "$C_MUT" "$REPLY" "$C_R" "$2" >&"$UI_FD"; }
ui_box() {  # colour title line...  (rounded panel, auto width)
    local col=$1 title=$2; shift 2
    local l w=0 inner
    for l in "$@"; do ui_vlen "$l"; (( UI_N > w )) && w=$UI_N; done
    ui_vlen "$title"; (( UI_N + 4 > w )) && w=$(( UI_N + 4 ))
    (( w > UI_COLS - 8 )) && w=$(( UI_COLS - 8 ))
    inner=$(( w + 2 ))
    ui_vlen "$title"; ui_rep "$BX_H" $(( inner - UI_N - 3 ))
    printf '  %s%s%s %s%s%s%s %s%s%s\n' "$col" "$BX_TL$BX_H" "$C_R" "$C_B$col" "$title" "$C_R" "$col" "$REPLY" "$BX_TR" "$C_R" >&"$UI_FD"
    for l in "$@"; do
        ui_vlen "$l"
        if (( UI_N > w )); then ui_trunc "$l" "$w"; l=$REPLY; fi
        ui_pad "$l" "$w"
        printf '  %s%s%s %s %s%s%s\n' "$col" "$BX_V" "$C_R" "$REPLY" "$col" "$BX_V" "$C_R" >&"$UI_FD"
    done
    ui_rep "$BX_H" "$inner"
    printf '  %s%s%s%s%s\n' "$col" "$BX_BL" "$REPLY" "$BX_BR" "$C_R" >&"$UI_FD"
}
ui_badge() {  # level -> coloured fixed-width chip in REPLY
    local t=$1 bg fg=$C_INK
    case $t in FULL) bg=$B_OK ;; PARTIAL) bg=$B_WARN ;; CARVE) bg=$B_SEC ;; DETECT) bg=$B_MUT; fg=$C_TXT ;; NONE) bg=$B_ERR ;; *) bg=$B_MUT; fg=$C_TXT ;; esac
    if (( UI_DEPTH > 0 )); then ui_pad " $t" 9; REPLY="$bg$fg$C_B$REPLY$C_R"; else ui_pad "[$t]" 9; fi
}
ui_famcol() {  # family -> colour in REPLY
    case $1 in chromium) REPLY=$C_PRI ;; firefox) REPLY=$C_ORG ;; safari) REPLY=$C_BLU ;; os) REPLY=$C_MUT ;; ese) REPLY=$C_DIM ;; *) REPLY=$C_SEC ;; esac
}
ui_table() {  # flexcol header-tsv row-tsv...  (cells may contain ANSI except the flexible column)
    local flex=$1 hdr=$2; shift 2
    local -a H W
    local IFS=$'\t' row c i n total
    read -r -a H <<< "$hdr"; n=${#H[@]}
    for ((i = 0; i < n; i++)); do ui_vlen "${H[i]}"; W[i]=$UI_N; done
    for row in "$@"; do
        local -a C=(); read -r -a C <<< "$row"
        for ((i = 0; i < n; i++)); do ui_vlen "${C[i]:-}"; (( UI_N > W[i] )) && W[i]=$UI_N; done
    done
    total=$(( 3 * n + 1 + 4 )); for ((i = 0; i < n; i++)); do total=$(( total + W[i] )); done
    if (( total > UI_COLS )); then W[flex]=$(( W[flex] - (total - UI_COLS) )); (( W[flex] < 10 )) && W[flex]=10; fi
    local top="$BX_TL" mid="$BX_LT" bot="$BX_BL"
    for ((i = 0; i < n; i++)); do
        ui_rep "$BX_H" $(( W[i] + 2 ))
        top+=$REPLY; mid+=$REPLY; bot+=$REPLY
        if (( i < n - 1 )); then top+=$BX_TT; mid+=$BX_X; bot+=$BX_BT; fi
    done
    top+=$BX_TR; mid+=$BX_RT; bot+=$BX_BR
    printf '  %s%s%s\n' "$C_DIM" "$top" "$C_R" >&"$UI_FD"
    local line="$C_DIM$BX_V$C_R"
    for ((i = 0; i < n; i++)); do ui_pad "${H[i]}" "${W[i]}"; line+=" $C_B$C_MUT$REPLY$C_R $C_DIM$BX_V$C_R"; done
    printf '  %s\n  %s%s%s\n' "$line" "$C_DIM" "$mid" "$C_R" >&"$UI_FD"
    for row in "$@"; do
        local -a C=(); read -r -a C <<< "$row"
        line="$C_DIM$BX_V$C_R"
        for ((i = 0; i < n; i++)); do
            c=${C[i]:-}
            if (( i == flex )); then ui_ltrunc "$c" "${W[i]}"; c="$C_DIM$REPLY$C_R"; fi
            ui_pad "$c" "${W[i]}"; line+=" $REPLY $C_DIM$BX_V$C_R"
        done
        printf '  %s\n' "$line" >&"$UI_FD"
    done
    printf '  %s%s%s\n' "$C_DIM" "$bot" "$C_R" >&"$UI_FD"
}

# ------------------------------------------------------------------ embedded analysis engine (Python 3, stdlib only)
engine_source() {
cat <<'__BFX_ENGINE_EOF__'
# -*- coding: utf-8 -*-
# BrowserForensics-X analysis engine. Embedded in BrowserForensics-X.sh and
# written to a private temporary directory at runtime. It only READS evidence
# copies; it never executes, imports or evaluates content found in evidence.
import sys, os, io, re, csv, json, html, glob, time, zlib, struct, shutil, sqlite3
import hashlib, hmac, plistlib, argparse, datetime, traceback, urllib.parse, collections
import email.utils
import xml.etree.ElementTree as ET

VERSION = os.environ.get("BFX_VERSION", "dev")
TOOL = "BrowserForensics-X"
UTC = datetime.timezone.utc
E1601 = datetime.datetime(1601, 1, 1, tzinfo=UTC)
E1970 = datetime.datetime(1970, 1, 1, tzinfo=UTC)
E2001 = datetime.datetime(2001, 1, 1, tzinfo=UTC)
PLAUSIBLE_MIN = datetime.datetime(1995, 1, 1, tzinfo=UTC)
PLAUSIBLE_MAX = datetime.datetime(2100, 1, 1, tzinfo=UTC)
MAX_TEXT_FILE = 256 * 1024 * 1024

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    except Exception:
        pass


def utcnow():
    return datetime.datetime.now(UTC)


def iso(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else None


def parse_iso(s):
    s = str(s).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        s += "T00:00:00"
    s = s.replace("Z", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


TIME_FORMATS = {
    "webkit_us": "microseconds since 1601-01-01 UTC (Chromium/WebKit)",
    "filetime": "100-ns intervals since 1601-01-01 UTC (Windows FILETIME)",
    "unix_s": "seconds since 1970-01-01 UTC",
    "unix_ms": "milliseconds since 1970-01-01 UTC",
    "unix_us": "microseconds since 1970-01-01 UTC (Mozilla PRTime)",
    "mac_s": "seconds since 2001-01-01 UTC (Cocoa/CFAbsoluteTime)",
    "unix_auto": "Unix epoch, unit inferred from magnitude (s/ms/us/ns)",
    "datetime": "native datetime (plist), assumed UTC",
    "iso": "ISO-8601 / RFC timestamp string",
    "http_date": "RFC 7231 HTTP-date",
}


def conv_time(raw, fmt):
    """Convert a raw timestamp to an aware UTC datetime, or None if unset/invalid."""
    if raw is None:
        return None
    try:
        if fmt == "datetime":
            if not isinstance(raw, datetime.datetime):
                return None
            return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
        if fmt == "iso":
            return parse_iso(raw) if str(raw).strip() else None
        if fmt == "http_date":
            dt = email.utils.parsedate_to_datetime(str(raw))
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        if isinstance(raw, (bytes, bytearray, bool)):
            return None
        if isinstance(raw, str):
            raw = raw.strip()
            if not raw:
                return None
            raw = float(raw) if ("." in raw or "e" in raw.lower()) else int(raw)
        v = raw
        if v == 0:
            return None
        if fmt == "webkit_us":
            return E1601 + datetime.timedelta(microseconds=int(v))
        if fmt == "filetime":
            return E1601 + datetime.timedelta(microseconds=int(v) // 10)
        if fmt == "unix_s":
            return E1970 + datetime.timedelta(seconds=float(v))
        if fmt == "unix_ms":
            return E1970 + datetime.timedelta(milliseconds=float(v))
        if fmt == "unix_us":
            return E1970 + datetime.timedelta(microseconds=int(v))
        if fmt == "mac_s":
            return E2001 + datetime.timedelta(seconds=float(v))
        if fmt == "unix_auto":
            a = abs(float(v))
            if a < 1e11:
                return conv_time(v, "unix_s")
            if a < 1e14:
                return conv_time(v, "unix_ms")
            if a < 1e17:
                return conv_time(v, "unix_us")
            return E1970 + datetime.timedelta(microseconds=int(v) // 1000)
    except (ValueError, OverflowError, TypeError, IndexError):
        return None
    raise ValueError("unknown time format " + fmt)


def guess_int_timestamp(v):
    """For carved integers: return (fmt, dt) when v falls in a distinctive range."""
    if not isinstance(v, int) or v <= 0:
        return None
    for fmt, lo, hi in (("webkit_us", 12_600_000_000_000_000, 14_200_000_000_000_000),
                        ("unix_us", 800_000_000_000_000, 4_100_000_000_000_000)):
        if lo <= v <= hi:
            dt = conv_time(v, fmt)
            if dt and PLAUSIBLE_MIN <= dt <= PLAUSIBLE_MAX:
                return fmt, dt
    return None


# ---------------------------------------------------------------- redaction
SENSITIVE_PARAM = re.compile(
    r"(?i)^(.*token.*|.*passw.*|pwd|pass|.*secret.*|.*session.*|sid|ssid|auth.*|.*apikey.*|api_key|"
    r"key|code|state|nonce|sig|signature|.*credential.*|e-?mail|mail|user(name)?|login|phone|otp|"
    r"ticket|saml.*|x-amz-.*|jwt|hash|client_secret|assertion)$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


class Redactor:
    def __init__(self, enabled, key):
        self.on = bool(enabled)
        self.key = key or b"bfx"

    def tag(self, b):
        return hmac.new(self.key, b, hashlib.sha256).hexdigest()[:16]

    def secret(self, v, kind="secret"):
        """Replace a secret/personal value by length + keyed HMAC (case key, not in reports)."""
        if v is None:
            return None
        if isinstance(v, (bytes, bytearray)):
            b = bytes(v)
        else:
            b = str(v).encode("utf-8", "replace")
        if not self.on:
            return v if not isinstance(v, (bytes, bytearray)) else "base64:" + __import__("base64").b64encode(b).decode()
        if not b:
            return ""
        return "[REDACTED %s len=%d hmac=%s]" % (kind, len(b), self.tag(b))

    def text(self, s):
        """Free text: mask e-mail addresses."""
        if s is None or not self.on:
            return s
        return EMAIL_RE.sub(lambda m: self.secret(m.group(0), "email"), str(s))

    def url(self, u):
        if u is None or not self.on or not isinstance(u, str):
            return u
        try:
            sp = urllib.parse.urlsplit(u)
        except ValueError:
            return u
        netloc = sp.netloc
        if "@" in netloc:
            netloc = "[REDACTED userinfo]@" + netloc.rsplit("@", 1)[1]

        def red_q(q):
            if not q:
                return q
            parts = []
            for kv in q.split("&"):
                k, sep, val = kv.partition("=")
                if sep and val and SENSITIVE_PARAM.match(urllib.parse.unquote(k)):
                    val = "[REDACTED]"
                parts.append(k + sep + val)
            return "&".join(parts)
        try:
            return urllib.parse.urlunsplit((sp.scheme, netloc, sp.path, red_q(sp.query), red_q(sp.fragment)))
        except ValueError:
            return u


def domain_of(url):
    if not url or not isinstance(url, str):
        return None
    try:
        h = urllib.parse.urlsplit(url).hostname
        return h.lower() if h else None
    except ValueError:
        return None


# ---------------------------------------------------------------- binary helpers
def varint(b, i):
    """LevelDB/protobuf little-endian base-128 varint."""
    r = 0
    s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        if c < 0x80:
            return r, i
        s += 7
        if s > 63:
            raise ValueError("varint too long")


def svarint(b, i):
    """SQLite big-endian varint (1..9 bytes)."""
    v = 0
    for k in range(8):
        c = b[i + k]
        v = (v << 7) | (c & 0x7F)
        if c < 0x80:
            return v, i + k + 1
    return (v << 8) | b[i + 8], i + 9


def snappy_decompress(buf):
    n, pos = varint(buf, 0)
    if n > 512 * 1024 * 1024:
        raise ValueError("snappy: implausible length")
    out = bytearray()
    L = len(buf)
    while pos < L:
        tag = buf[pos]
        pos += 1
        t = tag & 3
        if t == 0:
            ln = tag >> 2
            if ln < 60:
                ln += 1
            else:
                nb = ln - 59
                ln = int.from_bytes(buf[pos:pos + nb], "little") + 1
                pos += nb
            out += buf[pos:pos + ln]
            pos += ln
            continue
        if t == 1:
            ln = ((tag >> 2) & 7) + 4
            off = ((tag >> 5) << 8) | buf[pos]
            pos += 1
        elif t == 2:
            ln = (tag >> 2) + 1
            off = int.from_bytes(buf[pos:pos + 2], "little")
            pos += 2
        else:
            ln = (tag >> 2) + 1
            off = int.from_bytes(buf[pos:pos + 4], "little")
            pos += 4
        if off == 0 or off > len(out):
            raise ValueError("snappy: bad offset")
        start = len(out) - off
        if off >= ln:
            out += out[start:start + ln]
        else:
            for k in range(ln):
                out.append(out[start + k])
    if len(out) != n:
        raise ValueError("snappy: length mismatch %d != %d" % (len(out), n))
    return bytes(out)


def lz4_block_decompress(src, expected=None):
    dst = bytearray()
    i = 0
    L = len(src)
    while i < L:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        dst += src[i:i + lit]
        i += lit
        if i >= L:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        ml = token & 15
        if ml == 15:
            while True:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        if off == 0 or off > len(dst):
            raise ValueError("lz4: bad offset")
        start = len(dst) - off
        if off >= ml:
            dst += dst[start:start + ml]
        else:
            for k in range(ml):
                dst.append(dst[start + k])
    if expected is not None and len(dst) != expected:
        raise ValueError("lz4: size mismatch")
    return bytes(dst)


def mozlz4_decode(data):
    if data[:8] != b"mozLz40\0":
        raise ValueError("not a mozLz4 file")
    size = struct.unpack("<I", data[8:12])[0]
    return lz4_block_decompress(data[12:], size)


_CRC32C = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC32C.append(_c)


def crc32c(data):
    c = 0xFFFFFFFF
    t = _CRC32C
    for b in data:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def crc_mask(c):
    return (((c >> 15) | (c << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def pb_decode(b):
    """Minimal protobuf wire decoder -> {field: [values]} (no schema)."""
    out = collections.defaultdict(list)
    p = 0
    while p < len(b):
        key, p = varint(b, p)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, p = varint(b, p)
        elif wt == 1:
            v = b[p:p + 8]
            p += 8
        elif wt == 2:
            ln, p = varint(b, p)
            v = b[p:p + ln]
            p += ln
        elif wt == 5:
            v = b[p:p + 4]
            p += 4
        else:
            raise ValueError("protobuf wire type %d" % wt)
        if p > len(b) or f == 0:
            raise ValueError("protobuf overrun")
        out[f].append(v)
    return out


URL_CARVE = re.compile(rb"(?:https?|ftp|file|chrome-extension|moz-extension|edge|chrome)://[\x21\x23-\x3b\x3d\x3f-\x5b\x5d\x5f\x61-\x7a\x7e]{3,2048}")
URL_CARVE_U16 = re.compile(rb"(?:h\x00t\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00)(?:[\x21\x23-\x3b\x3d\x3f-\x5b\x5d\x5f\x61-\x7a\x7e]\x00){3,1024}")
URL_CARVE_U16BE = re.compile(rb"(?:\x00h\x00t\x00t\x00p(?:\x00s)?\x00:\x00/\x00/)(?:\x00[\x21\x23-\x3b\x3d\x3f-\x5b\x5d\x5f\x61-\x7a\x7e]){3,1024}")


def carve_urls(data, limit=100000):
    out = []
    for m in URL_CARVE.finditer(data):
        out.append((m.start(), m.group(0).decode("ascii", "replace")))
        if len(out) >= limit:
            break
    for m in URL_CARVE_U16.finditer(data):
        out.append((m.start(), m.group(0).decode("utf-16-le", "replace")))
    for m in URL_CARVE_U16BE.finditer(data):
        out.append((m.start(), m.group(0).decode("utf-16-be", "replace")))
    return out


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]")
_TLD = re.compile(r"^(?:[a-z]{2,24}|xn--[a-z0-9\-]{2,59})$")


def plausible_url(u):
    """Reject carving noise: scheme://host with a real-looking host (dotted name with alphabetic TLD,
    IPv4/IPv6 or localhost) and no control characters."""
    if not u or _CTRL.search(u) or " " in u:
        return False
    try:
        sp = urllib.parse.urlsplit(u)
        host = sp.hostname
    except ValueError:
        return False
    if sp.scheme in ("chrome-extension", "moz-extension"):
        return bool(host)
    if sp.scheme == "file":
        return bool(sp.path)
    if not host:
        return False
    if host == "localhost" or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or ":" in host:
        return True
    labels = host.split(".")
    return len(labels) >= 2 and all(labels) and bool(_TLD.match(labels[-1]))


def clean_columns(cols):
    """A rebuilt SQLite record is accepted only if every text column is free of control/replacement chars."""
    return all(not (isinstance(c, str) and _CTRL.search(c)) for c in cols)


def printable_strings(data, minlen=6, limit=200):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append(m.group(0).decode("ascii"))
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- SQLite internals
def sqlite_header(data):
    if data[:16] != b"SQLite format 3\x00":
        return None
    ps = struct.unpack(">H", data[16:18])[0]
    ps = 65536 if ps == 1 else ps
    h = {
        "page_size": ps,
        "write_version": data[18], "read_version": data[19],
        "wal_mode": data[18] == 2 or data[19] == 2,
        "file_change_counter": struct.unpack(">I", data[24:28])[0],
        "db_size_pages": struct.unpack(">I", data[28:32])[0],
        "freelist_trunk": struct.unpack(">I", data[32:36])[0],
        "freelist_pages": struct.unpack(">I", data[36:40])[0],
        "schema_cookie": struct.unpack(">I", data[40:44])[0],
        "text_encoding": {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(struct.unpack(">I", data[56:60])[0], "?"),
        "user_version": struct.unpack(">I", data[60:64])[0],
        "incremental_vacuum": struct.unpack(">I", data[64:68])[0],
        "auto_vacuum_root": struct.unpack(">I", data[52:56])[0],
        "application_id": struct.unpack(">I", data[68:72])[0],
        "version_valid_for": struct.unpack(">I", data[92:96])[0],
        "sqlite_version_number": struct.unpack(">I", data[96:100])[0],
        "file_size": len(data),
    }
    h["size_mismatch"] = bool(h["db_size_pages"]) and h["db_size_pages"] * ps != len(data)
    h["counter_stale"] = h["version_valid_for"] != h["file_change_counter"]
    return h


def sqlite_unallocated(data):
    """Yield (kind, page, abs_offset, bytes) for freelist pages, freeblocks and
    the unallocated gap of every b-tree page."""
    h = sqlite_header(data)
    if not h:
        return
    ps = h["page_size"]
    n = len(data) // ps
    free = set()
    trunk = h["freelist_trunk"]
    seen = set()
    while trunk and trunk not in seen and trunk <= n:
        seen.add(trunk)
        off = (trunk - 1) * ps
        nxt, cnt = struct.unpack(">II", data[off:off + 8])
        free.add(trunk)
        for i in range(min(cnt, (ps - 8) // 4)):
            lp = struct.unpack(">I", data[off + 8 + 4 * i:off + 12 + 4 * i])[0]
            if 0 < lp <= n:
                free.add(lp)
        trunk = nxt
    for p in sorted(free):
        yield "freelist", p, (p - 1) * ps, data[(p - 1) * ps:p * ps]
    for p in range(1, n + 1):
        if p in free:
            continue
        base = (p - 1) * ps
        hdr = base + (100 if p == 1 else 0)
        t = data[hdr]
        if t not in (2, 5, 10, 13):
            continue
        hlen = 12 if t in (2, 5) else 8
        first_fb, ncells, cstart = struct.unpack(">HHH", data[hdr + 1:hdr + 7])
        cstart = 65536 if cstart == 0 else cstart
        ptr_end = hdr + hlen + 2 * ncells
        cs = base + cstart
        if ptr_end < cs <= base + ps:
            gap = data[ptr_end:cs]
            if gap.strip(b"\x00"):
                yield "unallocated", p, ptr_end, gap
        fb = first_fb
        guard = 0
        while fb and guard < 2000:
            guard += 1
            if fb < 4 or fb + 4 > ps:
                break
            nxt, size = struct.unpack(">HH", data[base + fb:base + fb + 4])
            if size < 4 or fb + size > ps:
                break
            yield "freeblock", p, base + fb, data[base + fb:base + fb + size]
            if nxt and nxt <= fb:
                break
            fb = nxt


def wal_frames(wal, page_size_hint=None):
    """Yield dicts for every WAL frame: index, page, commit, salt_valid, data."""
    if len(wal) < 32:
        return
    magic, ver, ps, ckpt, s1, s2 = struct.unpack(">IIIIII", wal[:24])
    if magic not in (0x377F0682, 0x377F0683):
        return
    ps = ps or page_size_hint or 4096
    off = 32
    idx = 0
    while off + 24 + ps <= len(wal):
        pg, commit, fs1, fs2 = struct.unpack(">IIII", wal[off:off + 16])
        yield {"index": idx, "page": pg, "commit": commit, "salt_valid": (fs1, fs2) == (s1, s2),
               "offset": off, "data": wal[off + 24:off + 24 + ps], "checkpoint_seq": ckpt}
        off += 24 + ps
        idx += 1


def serial_len(t):
    if t in (0, 8, 9):
        return 0
    if 1 <= t <= 4:
        return t
    if t == 5:
        return 6
    if t in (6, 7):
        return 8
    if t >= 12:
        return (t - 12) // 2
    return None


def decode_serial(t, b):
    if t == 0:
        return None
    if t == 8:
        return 0
    if t == 9:
        return 1
    if 1 <= t <= 6:
        return int.from_bytes(b, "big", signed=True)
    if t == 7:
        return struct.unpack(">d", b)[0]
    if t >= 13 and t % 2:
        return b.decode("utf-8", "replace")
    return bytes(b)


def try_record_at_url(R, upos):
    """Try to rebuild an SQLite record whose text column starts at upos.
    Returns list of decoded column values or None."""
    for s in range(max(0, upos - 80), upos):
        try:
            hlen, p = svarint(R, s)
            if hlen < 2 or hlen > 80 or s + hlen > upos:
                continue
            types = []
            q = p
            while q < s + hlen:
                t, q = svarint(R, q)
                types.append(t)
            if q != s + hlen or not types or any(t in (10, 11) for t in types):
                continue
            off = s + hlen
            hit = False
            cols = []
            for t in types:
                ln = serial_len(t)
                if ln is None:
                    break
                if off == upos and t >= 13 and t % 2 == 1:
                    hit = True
                if off + ln > len(R):
                    break
                cols.append(decode_serial(t, R[off:off + ln]))
                off += ln
            else:
                if hit:
                    return cols
        except (IndexError, struct.error):
            continue
    return None


# ---------------------------------------------------------------- LevelDB
def leveldb_log_records(data):
    BLOCK = 32768
    pos = 0
    buf = None
    start = 0
    ok = True
    verify = len(data) <= 64 * 1024 * 1024
    while pos + 7 <= len(data):
        left = BLOCK - (pos % BLOCK)
        if left < 7:
            pos += left
            continue
        crc, ln, typ = struct.unpack("<IHB", data[pos:pos + 7])
        if typ == 0 and ln == 0:
            pos += left
            continue
        payload = data[pos + 7:pos + 7 + ln]
        good = (crc_mask(crc32c(bytes([typ]) + payload)) == crc) if verify else None
        if typ == 1:
            yield pos, payload, good
        elif typ == 2:
            buf, start, ok = bytearray(payload), pos, good
        elif typ == 3 and buf is not None:
            buf += payload
            ok = ok and good
        elif typ == 4 and buf is not None:
            buf += payload
            yield start, bytes(buf), (ok and good)
            buf = None
        elif typ > 4:
            pos += left
            continue
        pos += 7 + ln


def leveldb_batch(rec):
    seq, cnt = struct.unpack("<QI", rec[:12])
    p = 12
    for i in range(cnt):
        t = rec[p]
        p += 1
        kl, p = varint(rec, p)
        k = rec[p:p + kl]
        p += kl
        v = None
        if t == 1:
            vl, p = varint(rec, p)
            v = rec[p:p + vl]
            p += vl
        elif t != 0:
            raise ValueError("leveldb batch: bad tag")
        yield seq + i, t, bytes(k), (bytes(v) if v is not None else None)


def _ldb_block(data, off, sz):
    raw = data[off:off + sz]
    typ = data[off + sz] if off + sz < len(data) else 0
    if typ == 0:
        return raw
    if typ == 1:
        return snappy_decompress(raw)
    raise ValueError("unsupported LevelDB block compression %d" % typ)


def _ldb_block_entries(blk):
    if len(blk) < 4:
        return
    nrest = struct.unpack("<I", blk[-4:])[0]
    limit = len(blk) - 4 - 4 * nrest
    p = 0
    last = b""
    while 0 <= p < limit:
        shared, p = varint(blk, p)
        nons, p = varint(blk, p)
        vlen, p = varint(blk, p)
        key = last[:shared] + blk[p:p + nons]
        p += nons
        val = blk[p:p + vlen]
        p += vlen
        last = key
        yield key, val


def sstable_entries(data):
    if len(data) < 48 or struct.unpack("<Q", data[-8:])[0] != 0xDB4775248B80FB57:
        raise ValueError("not a LevelDB table (bad magic)")
    f = data[-48:]
    p = 0
    _, p = varint(f, p)
    _, p = varint(f, p)
    ix_off, p = varint(f, p)
    ix_sz, p = varint(f, p)
    for _, hv in _ldb_block_entries(_ldb_block(data, ix_off, ix_sz)):
        off, q = varint(hv, 0)
        sz, q = varint(hv, q)
        for ik, val in _ldb_block_entries(_ldb_block(data, off, sz)):
            if len(ik) < 8:
                continue
            tag = struct.unpack("<Q", ik[-8:])[0]
            yield tag >> 8, tag & 0xFF, bytes(ik[:-8]), bytes(val), off


def read_leveldb(d, errors):
    """Read every .log/.ldb/.sst in a LevelDB directory.
    Returns (live, historical, stats). Each entry: dict(seq,type,key,value,file,offset,crc_ok)."""
    entries = []
    stats = {"log_files": 0, "table_files": 0, "records": 0, "crc_errors": 0}
    for fn in sorted(os.listdir(d)):
        path = os.path.join(d, fn)
        if not os.path.isfile(path):
            continue
        low = fn.lower()
        try:
            if low.endswith(".log"):
                stats["log_files"] += 1
                data = open(path, "rb").read()
                for off, rec, good in leveldb_log_records(data):
                    if good is False:
                        stats["crc_errors"] += 1
                    try:
                        for seq, t, k, v in leveldb_batch(rec):
                            entries.append({"seq": seq, "type": t, "key": k, "value": v, "file": path,
                                            "offset": off, "crc_ok": good})
                    except (IndexError, ValueError, struct.error) as e:
                        errors.append("%s@%d: corrupt batch (%s)" % (fn, off, e))
            elif low.endswith(".ldb") or low.endswith(".sst"):
                stats["table_files"] += 1
                data = open(path, "rb").read()
                for seq, t, k, v, off in sstable_entries(data):
                    entries.append({"seq": seq, "type": t, "key": k, "value": v if t == 1 else None,
                                    "file": path, "offset": off, "crc_ok": None})
        except (OSError, ValueError, IndexError, struct.error) as e:
            errors.append("%s: %s" % (fn, e))
    stats["records"] = len(entries)
    by = collections.defaultdict(list)
    for e in entries:
        by[e["key"]].append(e)
    live, hist = [], []
    for k, lst in by.items():
        lst.sort(key=lambda e: e["seq"])
        newest = lst[-1]
        if newest["type"] == 1:
            live.append(newest)
            older = lst[:-1]
        else:
            older = lst
        for e in older:
            if e["type"] == 1:
                e = dict(e)
                e["state"] = "deleted" if newest["type"] == 0 else "superseded"
                hist.append(e)
    stats["live"] = len(live)
    stats["historical"] = len(hist)
    return live, hist, stats


# ---------------------------------------------------------------- Chromium SNSS
class Pickle:
    def __init__(self, b):
        self.b = b
        self.p = 4
        self.end = 4 + struct.unpack("<I", b[:4])[0]
        if self.end > len(b):
            raise ValueError("pickle overrun")

    def _take(self, n):
        if n < 0 or self.p + n > self.end:
            raise ValueError("pickle read past end")
        v = self.b[self.p:self.p + n]
        self.p += (n + 3) & ~3
        return v

    def i32(self):
        return struct.unpack("<i", self._take(4))[0]

    def i64(self):
        v = self.b[self.p:self.p + 8]
        if len(v) < 8 or self.p + 8 > self.end:
            raise ValueError("pickle read past end")
        self.p += 8
        return struct.unpack("<q", v)[0]

    def string(self):
        return self._take(self.i32())

    def string16(self):
        return self._take(self.i32() * 2).decode("utf-16-le", "replace")


def parse_snss(data):
    if data[:4] != b"SNSS":
        raise ValueError("not an SNSS file")
    ver = struct.unpack("<i", data[4:8])[0]
    pos = 8
    cmds = []
    while pos + 2 <= len(data):
        size = struct.unpack("<H", data[pos:pos + 2])[0]
        pos += 2
        if size == 0 or pos + size > len(data):
            break
        cmds.append((data[pos], data[pos + 1:pos + size]))
        pos += size
    return ver, cmds


SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]{1,20}:")


def snss_navigation(payload):
    pk = Pickle(payload)
    tab = pk.i32()
    index = pk.i32()
    url = pk.string().decode("utf-8", "replace")
    if not SCHEME_RE.match(url):
        raise ValueError("not a navigation")
    title = pk.string16()
    nav = {"tab_id": tab, "index": index, "url": url, "title": title}
    try:
        pk.string()                      # encoded page state
        nav["transition"] = pk.i32() & 0xFFFFFFFF
        pk.i32()                         # type mask
        ref = pk.string().decode("utf-8", "replace")
        if ref:
            nav["referrer"] = ref
        pk.i32()                         # referrer policy (obsolete)
        orig = pk.string().decode("utf-8", "replace")
        if orig:
            nav["original_request_url"] = orig
        pk.i32()                         # is_overriding_user_agent
        ts = pk.i64()
        dt = conv_time(ts, "webkit_us")
        if dt and PLAUSIBLE_MIN <= dt <= PLAUSIBLE_MAX:
            nav["timestamp_raw"] = ts
        pk.string16()                    # search terms
        st = pk.i32()
        if 0 < st < 1000:
            nav["http_status"] = st
    except (ValueError, struct.error):
        pass
    return nav


# ---------------------------------------------------------------- misc decoders
CHROME_TRANSITION = {0: "LINK", 1: "TYPED", 2: "AUTO_BOOKMARK", 3: "AUTO_SUBFRAME", 4: "MANUAL_SUBFRAME",
                     5: "GENERATED", 6: "AUTO_TOPLEVEL", 7: "FORM_SUBMIT", 8: "RELOAD", 9: "KEYWORD",
                     10: "KEYWORD_GENERATED"}
CHROME_QUAL = [(0x00800000, "BLOCKED"), (0x01000000, "FORWARD_BACK"), (0x02000000, "FROM_ADDRESS_BAR"),
               (0x04000000, "HOME_PAGE"), (0x08000000, "FROM_API"), (0x10000000, "CHAIN_START"),
               (0x20000000, "CHAIN_END"), (0x40000000, "CLIENT_REDIRECT"), (0x80000000, "SERVER_REDIRECT")]


def chrome_transition(t):
    if t is None:
        return None
    t = int(t) & 0xFFFFFFFF
    s = CHROME_TRANSITION.get(t & 0xFF, "CORE_%d" % (t & 0xFF))
    q = [n for bit, n in CHROME_QUAL if t & bit]
    return "|".join([s] + q)


FF_VISIT = {1: "LINK", 2: "TYPED", 3: "BOOKMARK", 4: "EMBED", 5: "REDIRECT_PERMANENT", 6: "REDIRECT_TEMPORARY",
            7: "DOWNLOAD", 8: "FRAMED_LINK", 9: "RELOAD"}
CHROME_DL_STATE = {0: "IN_PROGRESS", 1: "COMPLETE", 2: "CANCELLED", 3: "BUG_140687", 4: "INTERRUPTED"}
CHROME_DANGER = {0: "NOT_DANGEROUS", 1: "DANGEROUS_FILE", 2: "DANGEROUS_URL", 3: "DANGEROUS_CONTENT",
                 4: "MAYBE_DANGEROUS_CONTENT", 5: "UNCOMMON_CONTENT", 6: "USER_VALIDATED", 7: "DANGEROUS_HOST",
                 8: "POTENTIALLY_UNWANTED", 9: "ALLOWLISTED_BY_POLICY", 10: "ASYNC_SCANNING",
                 11: "BLOCKED_PASSWORD_PROTECTED", 12: "BLOCKED_TOO_LARGE", 13: "SENSITIVE_CONTENT_WARNING",
                 14: "SENSITIVE_CONTENT_BLOCK", 15: "DEEP_SCANNED_SAFE", 16: "DEEP_SCANNED_OPENED_DANGEROUS",
                 17: "PROMPT_FOR_SCANNING", 18: "BLOCKED_UNSUPPORTED_FILETYPE", 19: "DANGEROUS_ACCOUNT_COMPROMISE"}
RISKY_PERMS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "webRequest", "webRequestBlocking",
               "cookies", "history", "tabs", "nativeMessaging", "debugger", "proxy", "management",
               "downloads", "clipboardRead", "declarativeNetRequest", "declarativeNetRequestWithHostAccess",
               "webNavigation", "scripting", "privacy", "browsingData", "content_settings", "contentSettings"}


def encryption_scheme(blob):
    if not blob:
        return None
    b = bytes(blob)
    if b[:3] in (b"v10", b"v11", b"v20"):
        return b[:3].decode()
    if b[:4] == b"\x01\x00\x00\x00" and len(b) > 20:
        return "dpapi"
    return "unknown"


def safe_json_load(path, max_size=MAX_TEXT_FILE):
    if os.path.getsize(path) > max_size:
        raise ValueError("file too large for JSON parsing")
    with open(path, "rb") as f:
        raw = f.read()
    return json.loads(raw.decode("utf-8-sig", "replace"))


def safe_plist_load(path, max_size=MAX_TEXT_FILE):
    if os.path.getsize(path) > max_size:
        raise ValueError("file too large")
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:6] != b"bplist" and re.search(rb"<!ENTITY", raw[:4096]):
        raise ValueError("XML plist with ENTITY declarations refused (XXE protection)")
    return plistlib.loads(raw)


def safe_xml_parse(path, max_size=64 * 1024 * 1024):
    if os.path.getsize(path) > max_size:
        raise ValueError("file too large")
    raw = open(path, "rb").read()
    if re.search(rb"<!DOCTYPE|<!ENTITY", raw[:8192]):
        raise ValueError("XML with DOCTYPE/ENTITY refused (XXE protection)")
    return ET.fromstring(raw)


def file_magic(path):
    try:
        with open(path, "rb") as f:
            h = f.read(16)
    except OSError:
        return "unreadable"
    if h.startswith(b"SQLite format 3"):
        return "sqlite"
    if h.startswith(b"SNSS"):
        return "snss"
    if h.startswith(b"mozLz40"):
        return "mozlz4"
    if h.startswith(b"bplist"):
        return "bplist"
    if h.startswith(b"cook"):
        return "binarycookies"
    if h[:8] == struct.pack("<Q", 0xFCFB6D1BA7725C30):
        return "chromium-simple-cache"
    if h[:4] == b"\xef\xcd\xab\x89" or h[4:8] == b"\xef\xcd\xab\x89":
        return "ese"
    if h[:4] == b"MAM\x04":
        return "prefetch-mam"
    if h[:4] == b"L\x00\x00\x00":
        return "lnk"
    if h[:1] in (b"{", b"["):
        return "json"
    if h.startswith(b"<?xml"):
        return "xml"
    return "other"


# ================================================================ case model
def read_tsv(path, fields):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            parts += [""] * (len(fields) - len(parts))
            rows.append(dict(zip(fields, parts)))
    return rows


PROFILE_FIELDS = ["id", "family", "browser", "os", "user", "profile", "detection", "path"]
SOURCE_FIELDS = ["id", "role", "mode", "path"]


def read_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def load_manifest(case):
    m = {}
    for e in read_jsonl(os.path.join(case, "evidence", "manifest.jsonl")):
        if e.get("copy"):
            m[e["copy"]] = e
    return m


def redaction_key(case):
    p = os.path.join(case, ".redaction.key")
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    except FileExistsError:
        pass
    for _ in range(50):
        data = open(p, "rb").read()
        if len(data) == 32:
            return data
        time.sleep(0.05)
    return data


class Ctx:
    def __init__(self, case, prof, sources, opts):
        self.case = case
        self.prof = prof
        self.pid = prof["id"]
        self.opts = opts
        self.ev = os.path.join(case, "evidence", self.pid)
        self.out = os.path.join(case, "analysis", self.pid)
        self.work = os.path.join(case, "work", self.pid)
        os.makedirs(self.out, exist_ok=True)
        os.makedirs(self.work, exist_ok=True)
        self.roles = {s["role"]: os.path.join(self.ev, s["role"]) for s in sources}
        self.manifest = load_manifest(case)
        self.red = Redactor(opts.redact, redaction_key(case))
        self.fh = open(os.path.join(self.out, "records.jsonl"), "w", encoding="utf-8", newline="\n")
        self.n = 0
        self.counts = collections.Counter()
        self.parsers = []
        self.errors = []
        self.findings = []
        self.limitations = []
        self.dbinfo = []
        self.live_urls = set()
        self.history_urls = set()
        self._wseq = 0
        self.max_ts = None
        self.carve_rejected = 0

    # ---- paths
    def rel(self, path):
        return os.path.relpath(path, self.case).replace(os.sep, "/")

    def sha(self, path):
        e = self.manifest.get(self.rel(path))
        return e.get("sha256_copy") if e else None

    def mtime(self, path):
        e = self.manifest.get(self.rel(path))
        return e.get("mtime_utc") if e else None

    def role_dir(self, role):
        d = self.roles.get(role)
        return d if d and os.path.isdir(d) else None

    def files(self, role, pattern):
        d = self.role_dir(role)
        if not d:
            return []
        return sorted({p for p in glob.glob(os.path.join(d, pattern), recursive=True) if os.path.isfile(p)})

    def dirs(self, role, pattern):
        d = self.role_dir(role)
        if not d:
            return []
        return sorted({p for p in glob.glob(os.path.join(d, pattern), recursive=True) if os.path.isdir(p)})

    def walk(self, role=None):
        roots = [self.role_dir(role)] if role else [d for d in self.roles.values() if os.path.isdir(d)]
        for r in roots:
            if not r:
                continue
            for dp, dn, fn in os.walk(r):
                for f in fn:
                    yield os.path.join(dp, f)

    # ---- sqlite working copies (evidence copies are never opened by SQLite)
    def open_db(self, path):
        with open(path, "rb") as f:
            if f.read(16) != b"SQLite format 3\x00":
                raise ValueError("not an SQLite database: " + self.rel(path))
        self._wseq += 1
        wd = os.path.join(self.work, "db%04d" % self._wseq)
        os.makedirs(wd, exist_ok=True)
        dst = os.path.join(wd, os.path.basename(path))
        shutil.copyfile(path, dst)
        for suf in ("-wal", "-journal"):
            if os.path.exists(path + suf):
                shutil.copyfile(path + suf, dst + suf)
        con = sqlite3.connect(dst, timeout=1)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA query_only=ON")
        except sqlite3.Error:
            pass
        return con

    # ---- emit
    def emit(self, artifact, url=None, title=None, value=None, times=(), details=None, cls="observed",
             src=None, loc=None, redact_url=True, domain=None):
        tdict = {}
        raw = {}
        anomalies = []
        for label, rv, fmt in times:
            dt = conv_time(rv, fmt)
            if dt is None:
                continue
            tdict[label] = iso(dt)
            raw[label] = [rv if not isinstance(rv, datetime.datetime) else iso(dt), fmt]
            if not (PLAUSIBLE_MIN <= dt <= PLAUSIBLE_MAX):
                anomalies.append("%s outside plausible range (%s)" % (label, iso(dt)))
            elif self.max_ts is None or dt > self.max_ts:
                self.max_ts = dt
        u = self.red.url(url) if (redact_url and url) else url
        rec = {
            "rid": "%s-%06d" % (self.pid, self.n + 1),
            "profile_id": self.pid, "browser": self.prof["browser"], "family": self.prof["family"],
            "profile": self.prof["profile"], "user": self.prof["user"], "os": self.prof["os"],
            "artifact": artifact, "class": cls,
            "ts": next(iter(tdict.values()), None), "times": tdict, "raw_times": raw,
            "url": u, "domain": domain or domain_of(url), "title": title, "value": value,
            "details": details or {},
            "src": {"file": self.rel(src) if src else None, "sha256": self.sha(src) if src else None,
                    "loc": loc},
        }
        if anomalies:
            rec["anomalies"] = anomalies
        self.fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self.n += 1
        self.counts[artifact] += 1
        if url and cls == "observed":
            self.live_urls.add(url)
        return rec

    def finding(self, severity, kind, message, src=None, details=None, cls="inferred"):
        self.findings.append({"profile_id": self.pid, "browser": self.prof["browser"],
                              "profile": self.prof["profile"], "severity": severity, "kind": kind,
                              "class": cls, "message": message,
                              "src": self.rel(src) if src else None, "details": details or {}})

    def limit(self, msg):
        if msg not in self.limitations:
            self.limitations.append(msg)

    def close(self):
        self.fh.close()


def q(con, sql, args=()):
    return con.execute(sql, args).fetchall()


def tables(con):
    return {r[0] for r in q(con, "SELECT name FROM sqlite_master WHERE type IN ('table','view')")}


def columns(con, table):
    return [r[1] for r in q(con, 'PRAGMA table_info("%s")' % table.replace('"', '""'))]


def rowd(r):
    return {k: r[k] for k in r.keys()}


def sel(con, table, wanted, extra=""):
    """SELECT only the columns that exist (schemas differ across versions)."""
    have = set(columns(con, table))
    cols = [c for c in wanted if c in have]
    if not cols:
        return []
    return [rowd(r) for r in q(con, 'SELECT %s FROM "%s" %s' % (",".join('"%s"' % c for c in cols), table, extra))]


# ================================================================ generic SQLite / recovery
def analyze_sqlite_file(ctx, path, recover=True):
    data = open(path, "rb").read()
    h = sqlite_header(data)
    if not h:
        return
    info = {"file": ctx.rel(path), "sha256": ctx.sha(path), "header": h, "tables": {}, "wal": None,
            "journal": os.path.exists(path + "-journal"), "integrity": None, "recovered_urls": 0}
    wal = None
    if os.path.exists(path + "-wal"):
        wal = open(path + "-wal", "rb").read()
        frames = list(wal_frames(wal, h["page_size"]))
        info["wal"] = {"size": len(wal), "frames": len(frames),
                       "valid_salt_frames": sum(1 for f in frames if f["salt_valid"]),
                       "commit_frames": sum(1 for f in frames if f["commit"] and f["salt_valid"])}
        if info["wal"]["commit_frames"]:
            ctx.finding("info", "sqlite_wal_pending",
                        "%s: %d committed WAL frame(s) not checkpointed; parsed through a working copy (main file alone is incomplete)"
                        % (os.path.basename(path), info["wal"]["commit_frames"]), src=path, cls="observed")
    if info["journal"] and os.path.getsize(path + "-journal") > 0:
        ctx.finding("info", "sqlite_hot_journal", "%s: rollback journal present (may hold pre-transaction pages)"
                    % os.path.basename(path), src=path, cls="observed")
    if h["freelist_pages"]:
        info["freelist_note"] = "%d free page(s) — deleted content may persist" % h["freelist_pages"]
    if h["counter_stale"]:
        ctx.finding("low", "sqlite_header_inconsistent",
                    "%s: header change counter (%d) != version-valid-for (%d): file modified by a non-conforming writer or legacy SQLite"
                    % (os.path.basename(path), h["file_change_counter"], h["version_valid_for"]), src=path)
    live_strings = set()
    try:
        con = ctx.open_db(path)
        try:
            ic = q(con, "PRAGMA quick_check")
            info["integrity"] = ic[0][0] if ic else None
            if info["integrity"] != "ok":
                ctx.finding("medium", "sqlite_corruption", "%s: quick_check reported: %s"
                            % (os.path.basename(path), info["integrity"]), src=path, cls="observed")
        except sqlite3.Error as e:
            info["integrity"] = "error: %s" % e
        for t in sorted(tables(con)):
            try:
                info["tables"][t] = q(con, 'SELECT count(*) FROM "%s"' % t.replace('"', '""'))[0][0]
            except sqlite3.Error as e:
                info["tables"][t] = "error: %s" % e
                continue
            if not recover:
                continue
            try:
                for r in con.execute('SELECT * FROM "%s"' % t.replace('"', '""')):
                    for v in tuple(r):
                        if isinstance(v, str) and "://" in v:
                            live_strings.add(v)
                            for _, u in carve_urls(v.encode("utf-8", "replace")):
                                live_strings.add(u)
            except sqlite3.Error:
                pass
        con.close()
    except (sqlite3.Error, ValueError, OSError) as e:
        info["open_error"] = str(e)
        ctx.errors.append({"parser": "sqlite_inventory", "file": ctx.rel(path), "error": str(e)})
    if recover and data and len(data) <= ctx.opts.max_recover_bytes:
        info["recovered_urls"] = recover_sqlite(ctx, path, data, h, wal, live_strings)
    elif recover:
        ctx.limit("Deleted-record carving skipped for %s (size above --max-recover-mb)" % ctx.rel(path))
    ctx.dbinfo.append(info)


def _recovered_record(ctx, url, cols, path, region, loc, seen):
    key = (url, region)
    if key in seen:
        return 0
    if not plausible_url(url):
        ctx.carve_rejected += 1
        return 0
    seen.add(key)
    details = {"region": region, "database": os.path.basename(path)}
    times = []
    if cols is not None:
        details["reconstruction"] = "sqlite-record"
        details["columns"] = len(cols)
        texts = [c for c in cols if isinstance(c, str) and c != url]
        title = texts[0] if texts else None
        for c in cols:
            g = guess_int_timestamp(c)
            if g:
                times.append(("timestamp_inferred", c, g[0]))
                details["timestamp_format_inferred"] = g[0]
                break
    else:
        details["reconstruction"] = "string-carve (length may be imprecise)"
        title = None
    if ctx.red.on:
        title = ctx.red.text(title)
    ctx.emit("recovered_url", url=url, title=title, times=times, details=details, cls="recovered",
             src=path, loc=loc)
    return 1


def try_record_headerless(R, upos):
    """Freeblocks lose their first 4 bytes (payload length, rowid, header length).
    Rebuild from the surviving serial-type varints that end right where the URL
    starts (columns before the URL must be zero-length, e.g. INTEGER PRIMARY KEY)."""
    best = None
    for j in range(upos - 1, max(-1, upos - 40), -1):
        try:
            types = []
            q = j
            while q < upos:
                t, q = svarint(R, q)
                types.append(t)
            if q != upos:
                continue
            k = next((i for i, t in enumerate(types) if t >= 13 and t % 2 == 1), None)
            if k is None or any(serial_len(t) != 0 for t in types[:k]) or any(t in (10, 11) for t in types):
                continue
            off = upos
            cols = [None] * k
            for t in types[k:]:
                ln = serial_len(t)
                if off + ln > len(R):
                    raise IndexError
                cols.append(decode_serial(t, R[off:off + ln]))
                off += ln
            if any(isinstance(c, str) and "�" in c for c in cols):
                continue
            best = cols
        except (IndexError, struct.error):
            continue
    return best


def _resolve_carved(blob, upos, url):
    """Use SQLite record reconstruction to get the exact column value when possible."""
    cols = try_record_at_url(blob, upos)
    if cols is not None and not clean_columns(cols):
        cols = None
    if cols is None:
        cols = try_record_headerless(blob, upos)
        if cols is not None and not clean_columns(cols):
            cols = None
    if cols:
        for c in cols:
            if isinstance(c, str) and c and url.startswith(c[:24]) and len(c) <= len(url):
                return c, cols
    return url, cols


def recover_sqlite(ctx, path, data, h, wal, live):
    n = 0
    seen = set()
    for kind, page, off, blob in sqlite_unallocated(data):
        for upos, url in carve_urls(blob):
            url, cols = _resolve_carved(blob, upos, url)
            if url in live:
                continue
            n += _recovered_record(ctx, url, cols, path, kind, "page %d offset 0x%x" % (page, off + upos), seen)
    if wal:
        for fr in wal_frames(wal, h["page_size"]):
            for upos, url in carve_urls(fr["data"]):
                url, cols = _resolve_carved(fr["data"], upos, url)
                if url in live:
                    continue
                n += _recovered_record(ctx, url, cols, path + "-wal",
                                       "wal-frame(%s)" % ("current" if fr["salt_valid"] else "stale"),
                                       "frame %d page %d" % (fr["index"], fr["page"]), seen)
    jp = path + "-journal"
    if os.path.exists(jp) and os.path.getsize(jp) <= ctx.opts.max_recover_bytes:
        jd = open(jp, "rb").read()
        for upos, url in carve_urls(jd):
            url, cols = _resolve_carved(jd, upos, url)
            if url in live:
                continue
            n += _recovered_record(ctx, url, cols, jp, "rollback-journal", "offset 0x%x" % upos, seen)
    if n:
        ctx.finding("medium", "deleted_records_recovered",
                    "%s: %d URL(s) recovered from unallocated SQLite space/WAL/journal that are absent from live records"
                    % (os.path.basename(path), n), src=path, cls="recovered")
    return n


def emit_leveldb_hist(ctx, artifact, hist, decode, origin_hint=None):
    for e in hist:
        try:
            k, v = decode(e["key"], e["value"])
        except Exception:
            k, v = repr(e["key"][:64]), e["value"]
        ctx.emit(artifact, url=origin_hint, title=k, value=ctx.red.secret(v, "storage-value") if v is not None else None,
                 details={"leveldb_state": e["state"], "seq": e["seq"]}, cls="recovered", src=e["file"],
                 loc="offset 0x%x seq %d" % (e["offset"], e["seq"]))


# ================================================================ Chromium family
def cr_history(ctx):
    for path in ctx.files("profile", "History"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if "urls" not in tb:
                ctx.limit("History without 'urls' table: " + ctx.rel(path))
                continue
            vcols = set(columns(con, "visits")) if "visits" in tb else set()
            visited = set()
            if vcols:
                extra = [c for c in ("from_visit", "transition", "visit_duration", "segment_id", "opener_visit",
                                     "external_referrer_url", "app_id", "originator_cache_guid", "incremented_omnibox_typed_score")
                         if c in vcols]
                sql = ("SELECT v.id AS visit_id, v.url AS url_id, v.visit_time, %s u.url, u.title, u.visit_count, "
                       "u.typed_count, u.hidden, u.last_visit_time FROM visits v LEFT JOIN urls u ON u.id = v.url ORDER BY v.visit_time"
                       % "".join("v.%s AS %s, " % (c, c) for c in extra))
                orphans = 0
                for r in con.execute(sql):
                    r = rowd(r)
                    visited.add(r["url_id"])
                    if r["url"] is None:
                        orphans += 1
                    d = {"visit_id": r["visit_id"], "url_id": r["url_id"], "visit_count": r["visit_count"],
                         "typed_count": r["typed_count"], "hidden": r["hidden"],
                         "transition": chrome_transition(r.get("transition")), "from_visit": r.get("from_visit")}
                    if r.get("visit_duration"):
                        d["visit_duration_s"] = round(r["visit_duration"] / 1e6, 3)
                    for c in ("external_referrer_url", "app_id", "opener_visit"):
                        if r.get(c):
                            d[c] = ctx.red.url(r[c]) if c.endswith("url") else r[c]
                    ctx.emit("history", url=r["url"], title=r["title"], times=[("visited", r["visit_time"], "webkit_us")],
                             details=d, src=path, loc="visits.id=%s" % r["visit_id"])
                    if r["url"]:
                        ctx.history_urls.add(r["url"])
                if orphans:
                    ctx.finding("medium", "orphan_visits", "%d visit row(s) reference URL ids missing from 'urls' (rows deleted or DB tampered)"
                                % orphans, src=path)
                ids = [r[0] for r in q(con, "SELECT id FROM visits ORDER BY id")]
                if ids:
                    gaps = (ids[-1] - ids[0] + 1) - len(ids)
                    if gaps > 0:
                        ctx.finding("info", "visit_id_gaps",
                                    "visits.id range %d..%d has %d missing id(s): visits were deleted (user deletion, expiry or sync)"
                                    % (ids[0], ids[-1], gaps), src=path, details={"gaps": gaps})
            novisit = 0
            for r in con.execute("SELECT id, url, title, visit_count, typed_count, last_visit_time, hidden FROM urls"):
                r = rowd(r)
                if r["id"] in visited:
                    continue
                novisit += 1
                ctx.history_urls.add(r["url"])
                ctx.emit("history_url", url=r["url"], title=r["title"],
                         times=[("last_visit", r["last_visit_time"], "webkit_us")],
                         details={"url_id": r["id"], "visit_count": r["visit_count"], "typed_count": r["typed_count"],
                                  "note": "URL row without surviving visit rows"}, src=path, loc="urls.id=%s" % r["id"])
            if novisit and vcols:
                ctx.finding("info", "urls_without_visits",
                            "%d URL row(s) have no visit rows (visits expired/deleted; url rows kept for bookmarks/typed counts)"
                            % novisit, src=path)
            if "keyword_search_terms" in tb:
                for r in con.execute("SELECT k.keyword_id, k.term, k.url_id, u.url, u.last_visit_time FROM keyword_search_terms k "
                                     "LEFT JOIN urls u ON u.id = k.url_id"):
                    r = rowd(r)
                    ctx.emit("search", url=r["url"], title=r["term"], value=r["term"],
                             times=[("searched_approx", r["last_visit_time"], "webkit_us")],
                             details={"keyword_id": r["keyword_id"], "ts_basis": "urls.last_visit_time (approximate)"},
                             src=path, loc="keyword_search_terms.url_id=%s" % r["url_id"])
            if "downloads" in tb:
                chains = collections.defaultdict(list)
                if "downloads_url_chains" in tb:
                    for r in con.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
                        chains[r[0]].append(r[2])
                for r in sel(con, "downloads", ["id", "guid", "current_path", "target_path", "start_time", "end_time",
                                                "received_bytes", "total_bytes", "state", "danger_type", "interrupt_reason",
                                                "opened", "last_access_time", "referrer", "site_url", "tab_url",
                                                "tab_referrer_url", "mime_type", "original_mime_type", "by_ext_id",
                                                "by_ext_name", "hash", "transient"]):
                    ch = chains.get(r["id"], [])
                    url = ch[-1] if ch else r.get("tab_url")
                    tp = r.get("target_path") or r.get("current_path") or ""
                    d = {k: r.get(k) for k in ("guid", "received_bytes", "total_bytes", "interrupt_reason", "opened",
                                               "mime_type", "original_mime_type", "by_ext_id", "by_ext_name") if r.get(k) not in (None, "")}
                    d["target_path"] = tp
                    d["current_path"] = r.get("current_path")
                    d["state"] = CHROME_DL_STATE.get(r.get("state"), r.get("state"))
                    d["danger_type"] = CHROME_DANGER.get(r.get("danger_type"), r.get("danger_type"))
                    d["url_chain"] = [ctx.red.url(u) for u in ch]
                    for k in ("referrer", "site_url", "tab_url", "tab_referrer_url"):
                        if r.get(k):
                            d[k] = ctx.red.url(r[k])
                    if isinstance(r.get("hash"), (bytes, bytearray)) and r["hash"]:
                        d["sha256_reported_by_browser"] = bytes(r["hash"]).hex()
                    ctx.emit("download", url=url, title=os.path.basename(tp.replace("\\", "/")), value=tp,
                             times=[("started", r.get("start_time"), "webkit_us"), ("ended", r.get("end_time"), "webkit_us"),
                                    ("last_access", r.get("last_access_time"), "webkit_us")],
                             details=d, src=path, loc="downloads.id=%s" % r["id"])
                    if r.get("end_time") and r.get("start_time") and r["end_time"] > 0 and r["end_time"] < r["start_time"]:
                        ctx.finding("medium", "download_time_inversion", "download id %s ends before it starts" % r["id"], src=path)
                    if r.get("danger_type") not in (None, 0, 6, 9, 15):
                        ctx.finding("medium", "dangerous_download",
                                    "download flagged %s: %s" % (d["danger_type"], os.path.basename(tp.replace("\\", "/"))),
                                    src=path, cls="observed")
        finally:
            con.close()


def cr_cookies(ctx):
    for path in ctx.files("profile", "Cookies") + ctx.files("profile", "Network/Cookies"):
        con = ctx.open_db(path)
        try:
            if "cookies" not in tables(con):
                continue
            enc_seen = collections.Counter()
            for r in sel(con, "cookies", ["rowid", "host_key", "name", "path", "value", "encrypted_value", "creation_utc",
                                          "expires_utc", "last_access_utc", "last_update_utc", "is_secure", "is_httponly",
                                          "has_expires", "is_persistent", "priority", "samesite", "source_scheme",
                                          "source_port", "top_frame_site_key"]):
                enc = r.get("encrypted_value")
                scheme = encryption_scheme(enc)
                if scheme:
                    enc_seen[scheme] += 1
                host = r.get("host_key") or ""
                d = {"host": host, "path": r.get("path"), "secure": r.get("is_secure"), "httponly": r.get("is_httponly"),
                     "persistent": r.get("is_persistent"), "samesite": r.get("samesite"),
                     "encrypted_value": ({"scheme": scheme, "length": len(enc)} if enc else None),
                     "partition_key": r.get("top_frame_site_key") or None}
                ctx.emit("cookie", url="https://%s%s" % (host.lstrip("."), r.get("path") or "/"), title=r.get("name"),
                         value=ctx.red.secret(r.get("value"), "cookie") if r.get("value") else None,
                         times=[("created", r.get("creation_utc"), "webkit_us"), ("last_access", r.get("last_access_utc"), "webkit_us"),
                                ("last_update", r.get("last_update_utc"), "webkit_us"), ("expires", r.get("expires_utc"), "webkit_us")],
                         details=d, src=path, loc="cookies.rowid=%s" % r.get("rowid"), domain=host.lstrip(".").lower())
                if (r.get("last_access_utc") or 0) and (r.get("creation_utc") or 0) > (r.get("last_access_utc") or 0) > 0:
                    ctx.finding("low", "cookie_time_inversion", "cookie %s@%s created after last access" % (r.get("name"), host), src=path)
            if enc_seen:
                ctx.limit("Chromium cookie values are encrypted (%s); not decrypted by design (requires OS key material: DPAPI/Keychain/libsecret/app-bound key)"
                          % ", ".join("%s=%d" % kv for kv in sorted(enc_seen.items())))
        finally:
            con.close()


def cr_logins(ctx):
    for path in ctx.files("profile", "Login Data") + ctx.files("profile", "Login Data For Account"):
        con = ctx.open_db(path)
        try:
            if "logins" not in tables(con):
                continue
            for r in sel(con, "logins", ["rowid", "origin_url", "action_url", "username_element", "username_value",
                                         "password_element", "password_value", "signon_realm", "date_created",
                                         "blacklisted_by_user", "scheme", "times_used", "date_last_used",
                                         "date_password_modified", "display_name"]):
                pw = r.get("password_value")
                ctx.emit("credential", url=r.get("origin_url"), title=r.get("username_element"),
                         value=ctx.red.secret(r.get("username_value"), "username") if r.get("username_value") else None,
                         times=[("created", r.get("date_created"), "webkit_us"), ("last_used", r.get("date_last_used"), "webkit_us"),
                                ("password_modified", r.get("date_password_modified"), "webkit_us")],
                         details={"signon_realm": r.get("signon_realm"), "action_url": ctx.red.url(r.get("action_url")),
                                  "times_used": r.get("times_used"), "never_save": bool(r.get("blacklisted_by_user")),
                                  "password": ({"stored": True, "encryption": encryption_scheme(pw), "length": len(pw)} if pw else {"stored": False}),
                                  "store": os.path.basename(path)},
                         src=path, loc="logins.rowid=%s" % r.get("rowid"))
        finally:
            con.close()
    if ctx.files("profile", "Login Data"):
        ctx.limit("Stored passwords are inventoried only; they are never decrypted by this tool.")


def cr_webdata(ctx):
    for path in ctx.files("profile", "Web Data"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if "autofill" in tb:
                for r in sel(con, "autofill", ["rowid", "name", "value", "date_created", "date_last_used", "count"]):
                    ctx.emit("form", title=r.get("name"), value=ctx.red.secret(r.get("value"), "form-value"),
                             times=[("first_used", r.get("date_created"), "unix_s"), ("last_used", r.get("date_last_used"), "unix_s")],
                             details={"field": r.get("name"), "count": r.get("count")}, src=path, loc="autofill.rowid=%s" % r.get("rowid"))
            for t in ("autofill_profiles", "local_addresses", "contact_info"):
                if t in tb:
                    for r in sel(con, t, ["guid", "date_modified", "use_count", "use_date", "origin"]):
                        ctx.emit("autofill_profile", value=ctx.red.secret(r.get("guid"), "guid"),
                                 times=[("modified", r.get("date_modified"), "unix_s"), ("last_used", r.get("use_date"), "unix_s")],
                                 details={"table": t, "use_count": r.get("use_count"), "origin": r.get("origin"),
                                          "note": "address/contact fields not exported (personal data)"}, src=path, loc=t)
            for t in ("credit_cards", "local_stored_cards", "masked_credit_cards"):
                if t in tb:
                    for r in sel(con, t, ["guid", "id", "date_modified", "use_count", "use_date", "origin", "network", "nickname"]):
                        ctx.emit("payment_card", value=ctx.red.secret(r.get("guid") or r.get("id"), "card-id"),
                                 times=[("modified", r.get("date_modified"), "unix_s"), ("last_used", r.get("use_date"), "unix_s")],
                                 details={"table": t, "use_count": r.get("use_count"), "network": r.get("network"),
                                          "note": "card number/name never exported; card numbers are encrypted at rest"},
                                 src=path, loc=t)
            if "keywords" in tb:
                for r in sel(con, "keywords", ["id", "short_name", "keyword", "url", "date_created", "last_modified",
                                               "last_visited", "usage_count", "created_by_policy"]):
                    ctx.emit("search_engine", url=r.get("url"), title=r.get("short_name"), value=r.get("keyword"),
                             times=[("created", r.get("date_created"), "webkit_us"), ("modified", r.get("last_modified"), "webkit_us"),
                                    ("last_visited", r.get("last_visited"), "webkit_us")],
                             details={"usage_count": r.get("usage_count"), "by_policy": r.get("created_by_policy")},
                             src=path, loc="keywords.id=%s" % r.get("id"))
        finally:
            con.close()


def cr_misc_sqlite(ctx):
    for path in ctx.files("profile", "Favicons"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if {"icon_mapping", "favicons"} <= tb:
                has_bm = "favicon_bitmaps" in tb
                sql = ("SELECT m.page_url, f.url AS icon_url, %s FROM icon_mapping m LEFT JOIN favicons f ON f.id = m.icon_id %s"
                       % (("max(b.last_updated) AS last_updated, max(b.last_requested) AS last_requested" if has_bm else "NULL AS last_updated, NULL AS last_requested"),
                          ("LEFT JOIN favicon_bitmaps b ON b.icon_id = f.id GROUP BY m.id" if has_bm else "")))
                try:
                    rows = q(con, sql)
                except sqlite3.Error:
                    rows = q(con, sql.replace(", max(b.last_requested) AS last_requested", ", NULL AS last_requested"))
                for r in rows:
                    r = rowd(r)
                    ctx.emit("favicon", url=r["page_url"], times=[("icon_updated", r["last_updated"], "webkit_us"),
                                                                    ("icon_requested", r["last_requested"], "webkit_us")],
                             details={"icon_url": ctx.red.url(r["icon_url"])}, src=path, loc="icon_mapping")
        finally:
            con.close()
    for path in ctx.files("profile", "Top Sites"):
        con = ctx.open_db(path)
        try:
            if "top_sites" in tables(con):
                for r in sel(con, "top_sites", ["url", "url_rank", "title"]):
                    ctx.emit("top_site", url=r.get("url"), title=r.get("title"), details={"rank": r.get("url_rank")}, src=path, loc="top_sites")
        finally:
            con.close()
    for path in ctx.files("profile", "Shortcuts"):
        con = ctx.open_db(path)
        try:
            if "omni_box_shortcuts" in tables(con):
                for r in sel(con, "omni_box_shortcuts", ["id", "text", "fill_into_edit", "url", "contents", "description",
                                                        "last_access_time", "number_of_hits"]):
                    ctx.emit("omnibox_shortcut", url=r.get("url"), title=r.get("contents") or r.get("description"),
                             value=r.get("text"), times=[("last_access", r.get("last_access_time"), "webkit_us")],
                             details={"typed_text": r.get("text"), "hits": r.get("number_of_hits")}, src=path,
                             loc="omni_box_shortcuts.id=%s" % r.get("id"))
        finally:
            con.close()
    for path in ctx.files("profile", "Network Action Predictor"):
        con = ctx.open_db(path)
        try:
            if "network_action_predictor" in tables(con):
                for r in sel(con, "network_action_predictor", ["id", "user_text", "url", "number_of_hits", "number_of_misses"]):
                    ctx.emit("omnibox_predictor", url=r.get("url"), value=r.get("user_text"),
                             details={"typed_text": r.get("user_text"), "hits": r.get("number_of_hits"),
                                      "misses": r.get("number_of_misses")}, src=path, loc="network_action_predictor")
        finally:
            con.close()
    for path in ctx.files("profile", "Media History"):
        con = ctx.open_db(path)
        try:
            if "playback" in tables(con):
                for r in sel(con, "playback", ["id", "url", "watch_time_s", "has_video", "has_audio", "last_updated_time_s"]):
                    ctx.emit("media_playback", url=r.get("url"), times=[("last_updated", r.get("last_updated_time_s"), "unix_s")],
                             details={"watch_time_s": r.get("watch_time_s"), "video": r.get("has_video"), "audio": r.get("has_audio")},
                             src=path, loc="playback.id=%s" % r.get("id"))
        finally:
            con.close()
    if ctx.files("profile", "Visited Links"):
        ctx.limit("'Visited Links' is a salted hash table; it is hashed/inventoried but cannot be reversed to URLs.")


def _walk_bookmarks(node, folder, out):
    if not isinstance(node, dict):
        return
    t = node.get("type")
    if t == "url":
        out.append((folder, node))
    for c in node.get("children", []) or []:
        _walk_bookmarks(c, folder + [node.get("name", "")] if t == "folder" else folder, out)


def cr_bookmarks(ctx):
    current_guids = set()
    for name in ("Bookmarks", "Bookmarks.bak"):
        for path in ctx.files("profile", name):
            data = safe_json_load(path)
            items = []
            for rk, rv in (data.get("roots") or {}).items():
                if isinstance(rv, dict):
                    for c in rv.get("children", []) or []:
                        _walk_bookmarks(c, [rk], items)
            for folder, n in items:
                g = n.get("guid") or n.get("id")
                if name == "Bookmarks":
                    current_guids.add(g)
                elif g in current_guids:
                    continue
                ctx.emit("bookmark", url=n.get("url"), title=n.get("name"),
                         times=[("added", n.get("date_added"), "webkit_us"), ("last_used", n.get("date_last_used"), "webkit_us")],
                         details={"folder": "/".join(folder), "guid": g, "source": name,
                                  "only_in_backup": name != "Bookmarks"}, src=path, loc="guid=%s" % g)


PREF_KEYS = [
    "profile.name", "profile.created_by_version", "profile.exit_type", "profile.exited_cleanly",
    "download.default_directory", "download.prompt_for_download", "savefile.default_directory",
    "homepage", "homepage_is_newtabpage", "session.restore_on_startup", "session.startup_urls",
    "intl.accept_languages", "credentials_enable_service", "profile.password_manager_enabled",
    "default_search_provider_data.template_url_data.url", "browser.last_clear_browsing_data_time",
    "browser.clear_data.browsing_history", "browser.clear_data.cookies", "browser.clear_data.cache",
    "browser.clear_data.time_period", "net.network_prediction_options", "signin.allowed",
    "sync.has_setup_completed", "google.services.last_username", "google.services.last_account_id",
    "proxy", "extensions.ui.developer_mode", "safebrowsing.enabled", "safebrowsing.enhanced",
    "browser.has_seen_welcome_page", "profile.creation_time", "profile.last_engagement_time",
]
PREF_TIME_KEYS = {"browser.last_clear_browsing_data_time": "cleared_browsing_data",
                  "profile.creation_time": "profile_created"}
PREF_SENSITIVE = re.compile(r"(?i)(username|account|email|gaia|token|password)")


def _jget(d, dotted):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def cr_preferences(ctx):
    ext_settings = {}
    for name in ("Preferences", "Secure Preferences"):
        for path in ctx.files("profile", name):
            data = safe_json_load(path)
            for k in PREF_KEYS:
                v = _jget(data, k)
                if v is None:
                    continue
                times = []
                if k in PREF_TIME_KEYS:
                    times = [(PREF_TIME_KEYS[k], v, "webkit_us")]
                vv = ctx.red.secret(v, "account") if (PREF_SENSITIVE.search(k) and ctx.red.on) else v
                ctx.emit("setting", title=k, value=json.dumps(vv, ensure_ascii=False) if not isinstance(vv, str) else vv,
                         times=times, details={"file": name}, src=path, loc=k)
            if _jget(data, "browser.last_clear_browsing_data_time"):
                ctx.finding("medium", "browsing_data_cleared", "Chromium records that 'Clear browsing data' was used",
                            src=path, details={"raw": _jget(data, "browser.last_clear_browsing_data_time")}, cls="observed")
            if _jget(data, "profile.exit_type") == "Crashed":
                ctx.finding("info", "unclean_shutdown", "Last browser session did not exit cleanly (exit_type=Crashed)", src=path, cls="observed")
            for acct in _jget(data, "account_info") or []:
                if isinstance(acct, dict):
                    ctx.emit("account", title=ctx.red.text(acct.get("full_name")) if ctx.red.on else acct.get("full_name"),
                             value=ctx.red.secret(acct.get("email"), "email"),
                             details={"hosted_domain": acct.get("hd"), "gaia": ctx.red.secret(acct.get("gaia"), "gaia-id")},
                             src=path, loc="account_info")
            exc = _jget(data, "profile.content_settings.exceptions") or {}
            if isinstance(exc, dict):
                for typ, entries in exc.items():
                    if not isinstance(entries, dict):
                        continue
                    for pattern, val in entries.items():
                        if not isinstance(val, dict):
                            continue
                        site = pattern.split(",")[0]
                        ctx.emit("permission", url=site if "://" in site else None, title=typ,
                                 value=json.dumps(val.get("setting")) if val.get("setting") is not None else None,
                                 times=[("modified", val.get("last_modified"), "webkit_us"), ("last_visit", val.get("last_visit"), "webkit_us")],
                                 details={"pattern": pattern}, src=path, loc="content_settings.%s" % typ,
                                 domain=domain_of(site) if "://" in site else site)
            es = _jget(data, "extensions.settings")
            if isinstance(es, dict):
                for eid, v in es.items():
                    if isinstance(v, dict):
                        ext_settings.setdefault(eid, {}).update(v)
                        ext_settings[eid]["__src"] = path
    for path in ctx.files("root", "Local State") or ctx.files("profile", "Local State"):
        data = safe_json_load(path)
        cache = _jget(data, "profile.info_cache") or {}
        for pdir, info in cache.items():
            if not isinstance(info, dict):
                continue
            ctx.emit("browser_profile", title=pdir, value=info.get("name"),
                     times=[("last_active", info.get("active_time"), "unix_s")],
                     details={"user_name": ctx.red.secret(info.get("user_name"), "email") if info.get("user_name") else None,
                              "gaia_name": ctx.red.text(info.get("gaia_name")) if ctx.red.on else info.get("gaia_name"),
                              "is_ephemeral": info.get("is_ephemeral"), "managed": info.get("is_managed")},
                     src=path, loc="profile.info_cache.%s" % pdir)
        oc = data.get("os_crypt") or {}
        ctx.emit("setting", title="os_crypt", value=json.dumps({"encrypted_key_present": bool(oc.get("encrypted_key")),
                                                               "app_bound_key_present": bool(oc.get("app_bound_encrypted_key")),
                                                               "audit_enabled": oc.get("audit_enabled")}),
                 details={"note": "key material not exported"}, src=path, loc="os_crypt")
        labs = _jget(data, "browser.enabled_labs_experiments")
        if labs:
            ctx.emit("setting", title="browser.enabled_labs_experiments", value=json.dumps(labs), src=path, loc="labs")
    return ext_settings


def _resolve_msg(name, ext_dir, default_locale):
    if not isinstance(name, str) or not name.startswith("__MSG_"):
        return name
    key = name[6:-2].lower()
    for loc in [default_locale, "en", "en_US"]:
        if not loc:
            continue
        p = os.path.join(ext_dir, "_locales", loc, "messages.json")
        if os.path.isfile(p):
            try:
                msgs = {k.lower(): v for k, v in safe_json_load(p, 4 * 1024 * 1024).items()}
                if key in msgs and isinstance(msgs[key], dict):
                    return msgs[key].get("message", name)
            except (ValueError, OSError):
                pass
    return name


EXT_LOCATIONS = {1: "INTERNAL(store)", 2: "EXTERNAL_PREF", 3: "EXTERNAL_REGISTRY", 4: "UNPACKED(dev)", 5: "COMPONENT",
                 6: "EXTERNAL_PREF_DOWNLOAD", 7: "EXTERNAL_POLICY_DOWNLOAD", 8: "COMMAND_LINE", 9: "EXTERNAL_POLICY",
                 10: "EXTERNAL_COMPONENT"}


def cr_extensions(ctx, ext_settings):
    seen = set()
    for mpath in ctx.files("profile", "Extensions/*/*/manifest.json"):
        vdir = os.path.dirname(mpath)
        eid = os.path.basename(os.path.dirname(vdir))
        try:
            m = safe_json_load(mpath, 8 * 1024 * 1024)
        except ValueError as e:
            ctx.errors.append({"parser": "extensions", "file": ctx.rel(mpath), "error": str(e)})
            continue
        seen.add(eid)
        s = ext_settings.get(eid, {})
        perms = [p for p in (m.get("permissions") or []) if isinstance(p, str)]
        perms += [p for p in (m.get("host_permissions") or []) if isinstance(p, str)]
        for cs in m.get("content_scripts") or []:
            if isinstance(cs, dict):
                perms += [p for p in cs.get("matches") or [] if isinstance(p, str)]
        risky = sorted(set(perms) & RISKY_PERMS)
        loc = s.get("location")
        upd = m.get("update_url")
        d = {"id": eid, "version": m.get("version"), "manifest_version": m.get("manifest_version"),
             "description": _resolve_msg(m.get("description"), vdir, m.get("default_locale")),
             "permissions": sorted(set(perms)), "risky_permissions": risky, "update_url": upd,
             "location": EXT_LOCATIONS.get(loc, loc), "state": s.get("state"),
             "from_webstore": s.get("from_webstore"), "disable_reasons": s.get("disable_reasons"),
             "manifest_sha256": ctx.sha(mpath)}
        name = _resolve_msg(m.get("name"), vdir, m.get("default_locale"))
        ctx.emit("extension", url="chrome-extension://%s/" % eid, title=name, value=m.get("version"),
                 times=[("installed", s.get("install_time") or s.get("first_install_time"), "webkit_us")],
                 details=d, src=mpath, loc=eid)
        if risky:
            ctx.finding("low" if s.get("from_webstore") else "medium", "extension_broad_permissions",
                        "Extension '%s' (%s) requests sensitive permissions: %s" % (name, eid, ", ".join(risky)),
                        src=mpath, details={"id": eid})
        if loc in (4, 8) or (upd and "google.com" not in upd and "microsoft.com" not in upd and "edge" not in upd):
            ctx.finding("medium", "extension_sideloaded",
                        "Extension '%s' (%s) is unpacked/command-line or updates from a non-store URL (%s)" % (name, eid, upd),
                        src=mpath, details={"id": eid})
    for eid, s in ext_settings.items():
        if eid in seen:
            continue
        m = s.get("manifest") if isinstance(s.get("manifest"), dict) else {}
        if s.get("location") == 5 and not m:
            continue
        ctx.emit("extension", url="chrome-extension://%s/" % eid, title=m.get("name") or s.get("path"),
                 value=m.get("version"), times=[("installed", s.get("install_time") or s.get("first_install_time"), "webkit_us")],
                 details={"id": eid, "location": EXT_LOCATIONS.get(s.get("location"), s.get("location")),
                          "state": s.get("state"), "note": "present in Preferences only (component, external or removed extension)"},
                 src=s.get("__src"), loc="extensions.settings.%s" % eid)


def cr_sessions(ctx):
    paths = ctx.files("profile", "Sessions/*") + [p for n in ("Current Session", "Last Session", "Current Tabs", "Last Tabs")
                                                  for p in ctx.files("profile", n)]
    for path in paths:
        base = os.path.basename(path)
        try:
            data = open(path, "rb").read()
            ver, cmds = parse_snss(data)
        except (ValueError, OSError) as e:
            ctx.errors.append({"parser": "sessions", "file": ctx.rel(path), "error": str(e)})
            continue
        kind = "tab_restore" if "Tabs" in base else "session"
        file_ts = []
        m = re.search(r"_(\d{17})$", base)
        if m:
            file_ts = [("session_file_created", int(m.group(1)), "webkit_us")]
        seen = set()
        parsed = 0
        for cid, payload in cmds:
            try:
                nav = snss_navigation(payload)
            except (ValueError, struct.error, IndexError):
                continue
            parsed += 1
            key = (nav["tab_id"], nav["index"], nav["url"])
            if key in seen:
                continue
            seen.add(key)
            times = [("navigated", nav.get("timestamp_raw"), "webkit_us")] if nav.get("timestamp_raw") else []
            d = {"file_kind": kind, "snss_version": ver, "command_id": cid, "tab_id": nav["tab_id"],
                 "nav_index": nav["index"], "transition": chrome_transition(nav.get("transition")),
                 "http_status": nav.get("http_status")}
            if nav.get("referrer"):
                d["referrer"] = ctx.red.url(nav["referrer"])
            ctx.emit("session_tab" if kind == "session" else "closed_tab", url=nav["url"], title=nav["title"],
                     times=times + file_ts, details=d, src=path, loc="command %d" % cid)
        if cmds and not parsed:
            for off, u in carve_urls(data)[:500]:
                ctx.emit("session_tab", url=u, details={"file_kind": kind, "reconstruction": "string-carve"},
                         cls="recovered", src=path, loc="offset 0x%x" % off)
            ctx.limit("SNSS file %s: no navigation commands decoded; URLs carved instead" % base)
    if paths:
        ctx.limit("SNSS sessions: navigation entries decoded; window/tab layout, groups and closed-window structure are not reconstructed.")


def _ls_str(b):
    if not b:
        return ""
    if b[0] == 0:
        return b[1:].decode("utf-16-le", "replace")
    if b[0] == 1:
        return b[1:].decode("latin-1")
    return b.decode("utf-8", "replace")


def cr_local_storage(ctx):
    for d in ctx.dirs("profile", "Local Storage/leveldb"):
        errs = []
        live, hist, st = read_leveldb(d, errs)
        for e in errs:
            ctx.errors.append({"parser": "local_storage", "file": ctx.rel(d), "error": e})

        def dec(k, v):
            if k.startswith(b"_"):
                origin, _, rest = k[1:].partition(b"\x00")
                return origin.decode("utf-8", "replace"), _ls_str(rest), v
            return None, k.decode("utf-8", "replace"), v
        for e in live:
            k = e["key"]
            if k.startswith(b"META:") or k.startswith(b"METAACCESS:"):
                origin = k.split(b":", 1)[1].decode("utf-8", "replace")
                ts = None
                try:
                    pb = pb_decode(e["value"] or b"")
                    ts = pb.get(1, [None])[0]
                except (ValueError, IndexError):
                    pass
                ctx.emit("storage_origin", url=origin, times=[("last_modified" if k.startswith(b"META:") else "last_accessed", ts, "webkit_us")],
                         details={"store": "localStorage"}, src=e["file"], loc="seq %d" % e["seq"])
                continue
            origin, key, val = dec(k, e["value"])
            if origin is None:
                continue
            sval = _ls_str(val) if val else ""
            ctx.emit("local_storage", url=origin, title=key, value=ctx.red.secret(sval, "storage-value"),
                     details={"value_length": len(sval), "seq": e["seq"]}, src=e["file"], loc="seq %d" % e["seq"])
        for e in hist:
            origin, key, val = dec(e["key"], e["value"])
            if origin is None:
                continue
            sval = _ls_str(val) if val else ""
            ctx.emit("local_storage", url=origin, title=key, value=ctx.red.secret(sval, "storage-value"),
                     details={"leveldb_state": e["state"], "seq": e["seq"], "value_length": len(sval)},
                     cls="recovered", src=e["file"], loc="seq %d" % e["seq"])
        if hist:
            ctx.finding("info", "leveldb_deleted_values", "Local Storage: %d deleted/superseded value(s) recovered from LevelDB logs/tables" % len(hist),
                        src=None, cls="recovered")


def _u16_or_latin(b):
    if len(b) >= 2 and len(b) % 2 == 0 and b[1::2].count(0) >= len(b) // 4:
        return b.decode("utf-16-le", "replace")
    return b.decode("latin-1")


def cr_session_storage(ctx):
    for d in ctx.dirs("profile", "Session Storage"):
        errs = []
        live, hist, st = read_leveldb(d, errs)
        ns = {}
        for e in live:
            k = e["key"]
            if k.startswith(b"namespace-"):
                parts = k.decode("utf-8", "replace").split("-", 2)
                if len(parts) == 3 and e["value"]:
                    ns[e["value"].decode("latin-1")] = parts[2]
        for coll, cls in ((live, "observed"), (hist, "recovered")):
            for e in coll:
                k = e["key"]
                if not k.startswith(b"map-"):
                    continue
                _, mapid, rest = k.split(b"-", 2) if k.count(b"-") >= 2 else (None, b"", b"")
                key = _u16_or_latin(rest)
                val = _u16_or_latin(e["value"] or b"")
                origin = ns.get(mapid.decode("latin-1"))
                d2 = {"map_id": mapid.decode("latin-1"), "value_length": len(val)}
                if cls == "recovered":
                    d2["leveldb_state"] = e["state"]
                ctx.emit("session_storage", url=origin, title=key, value=ctx.red.secret(val, "storage-value"),
                         details=d2, cls=cls, src=e["file"], loc="seq %d" % e["seq"])


def _idb_prefix(k):
    b0 = k[0]
    dl, ol, il = (b0 >> 5) + 1, ((b0 >> 2) & 7) + 1, (b0 & 3) + 1
    p = 1
    db = int.from_bytes(k[p:p + dl], "little")
    p += dl
    os_ = int.from_bytes(k[p:p + ol], "little")
    p += ol
    ix = int.from_bytes(k[p:p + il], "little")
    p += il
    return db, os_, ix, p


def _idb_string_with_len(k, p):
    n, p = varint(k, p)
    s = k[p:p + 2 * n].decode("utf-16-be", "replace")
    return s, p + 2 * n


def origin_from_dirname(name):
    base = re.sub(r"\.(indexeddb\.(leveldb|blob))$", "", name)
    m = re.match(r"^(https?|chrome-extension|file)_(.+)_(\d+)$", base)
    if not m:
        return base
    port = m.group(3)
    host = m.group(2)
    return "%s://%s%s" % (m.group(1), host, "" if port in ("0", "80", "443") else ":" + port)


def cr_indexeddb(ctx):
    for d in ctx.dirs("profile", "IndexedDB/*.indexeddb.leveldb"):
        origin = origin_from_dirname(os.path.basename(d))
        errs = []
        live, hist, st = read_leveldb(d, errs)
        dbs = {}
        stores = {}
        counts = collections.Counter()
        where = {}
        urls = set()
        for e in live:
            k = e["key"]
            try:
                db, os_, ix, p = _idb_prefix(k)
            except IndexError:
                continue
            if db == 0 and os_ == 0 and ix == 0 and p < len(k) and k[p] == 201:
                try:
                    o, p2 = _idb_string_with_len(k, p + 1)
                    name, _ = _idb_string_with_len(k, p2)
                    dbid, _ = varint(e["value"], 0)
                    dbs[dbid] = name
                except (IndexError, ValueError):
                    pass
            elif db and os_ == 0 and ix == 0 and p < len(k) and k[p] == 50:
                try:
                    sid, p2 = varint(k, p + 1)
                    if p2 < len(k) and k[p2] == 0:
                        stores[(db, sid)] = (e["value"] or b"").decode("utf-16-be", "replace")
                except (IndexError, ValueError):
                    pass
            elif db and os_ and ix == 1:
                counts[(db, os_)] += 1
                where.setdefault((db, os_), e["file"])
                for _, u in carve_urls(e["value"] or b"")[:20]:
                    urls.add(u)
        for key in stores:
            counts.setdefault(key, 0)
        for (db, os_), n in sorted(counts.items()):
            ctx.emit("indexeddb", url=origin, title="%s/%s" % (dbs.get(db, "db%d" % db), stores.get((db, os_), "store%d" % os_)),
                     value="%d record(s)" % n, details={"database": dbs.get(db), "object_store": stores.get((db, os_)),
                                                        "records": n, "urls_in_values": sorted(ctx.red.url(u) for u in urls)[:50],
                                                        "leveldb": st}, src=where.get((db, os_), live[0]["file"] if live else d), loc="db %d store %d" % (db, os_))
        if not counts and (dbs or live):
            ctx.emit("indexeddb", url=origin, title=", ".join(dbs.values()) or None, value="%d key(s)" % len(live),
                     details={"leveldb": st}, src=(live[0]["file"] if live else d), loc="metadata")
        if hist:
            ctx.emit("indexeddb", url=origin, title="deleted/superseded entries", value="%d" % len(hist),
                     details={"note": "values not decoded (V8 serialization)"}, cls="recovered", src=hist[0]["file"], loc="leveldb history")
    if ctx.dirs("profile", "IndexedDB/*.indexeddb.leveldb"):
        ctx.limit("Chromium IndexedDB: database/object-store names and record counts decoded; values (V8 serialized) are only carved for URLs.")


def cr_service_workers(ctx):
    for d in ctx.dirs("profile", "Service Worker/Database"):
        errs = []
        live, hist, st = read_leveldb(d, errs)
        for coll, cls in ((live, "observed"), (hist, "recovered")):
            for e in coll:
                if not e["key"].startswith(b"REG:"):
                    continue
                try:
                    pb = pb_decode(e["value"] or b"")
                except (ValueError, IndexError):
                    pb = {}
                scope = (pb.get(2) or [b""])[0]
                script = (pb.get(3) or [b""])[0]
                scope = scope.decode("utf-8", "replace") if isinstance(scope, bytes) else None
                script = script.decode("utf-8", "replace") if isinstance(script, bytes) else None
                luc = (pb.get(7) or [None])[0]
                if not scope:
                    scope = e["key"][4:].split(b"\x00")[0].decode("utf-8", "replace")
                d2 = {"script_url": ctx.red.url(script), "registration_id": (pb.get(1) or [None])[0]}
                if cls == "recovered":
                    d2["leveldb_state"] = e["state"]
                ctx.emit("service_worker", url=scope, title=script,
                         times=[("last_update_check", luc if isinstance(luc, int) else None, "webkit_us")],
                         details=d2, cls=cls, src=e["file"], loc="seq %d" % e["seq"])
    for d in ctx.dirs("profile", "Service Worker/CacheStorage") + ctx.dirs("profile", "Service Worker/ScriptCache"):
        cache_simple_dir(ctx, d, "service_worker_cache")


def cr_extension_storage(ctx):
    for kind in ("Local Extension Settings", "Sync Extension Settings", "Managed Extension Settings"):
        for d in ctx.dirs("profile", kind + "/*"):
            eid = os.path.basename(d)
            errs = []
            live, hist, st = read_leveldb(d, errs)
            for coll, cls in ((live, "observed"), (hist, "recovered")):
                for e in coll:
                    v = (e["value"] or b"").decode("utf-8", "replace")
                    ctx.emit("extension_storage", url="chrome-extension://%s/" % eid, title=e["key"].decode("utf-8", "replace"),
                             value=ctx.red.secret(v, "storage-value"), details={"store": kind, "value_length": len(v),
                                                                                "leveldb_state": e.get("state")},
                             cls=cls, src=e["file"], loc="seq %d" % e["seq"])


# ---- Chromium HTTP caches
SIMPLE_MAGIC = 0xFCFB6D1BA7725C30
HDR_RE = re.compile(rb"HTTP/\d(?:\.\d)? \d{3}[^\x00]*(?:\x00[^\x00]+)*")


def _parse_http_head(blob):
    m = HDR_RE.search(blob)
    if not m:
        return {}
    lines = [x.decode("latin-1", "replace") for x in m.group(0).split(b"\x00") if x]
    out = {"status": lines[0][:80]}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            k = k.strip().lower()
            if k in ("content-type", "content-length", "date", "last-modified", "server", "location", "etag", "expires"):
                out[k] = v.strip()[:300]
    return out


def _cache_key_url(key):
    key = key.strip("\x00 ")
    toks = key.split(" ")
    u = toks[-1]
    u = re.sub(r"^(?:\d+/\d+/)?(?:_dk_)?", "", u)
    return u


def cache_simple_dir(ctx, d, artifact="cache"):
    n = 0
    for root, _, files in os.walk(d):
        for fn in files:
            if not re.fullmatch(r"[0-9a-f]{16}_[01s]", fn):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "rb") as f:
                    head = f.read(24 + 8192)
                    if len(head) < 24 or struct.unpack("<Q", head[:8])[0] != SIMPLE_MAGIC:
                        continue
                    ver, klen = struct.unpack("<II", head[8:16])
                    key = None
                    for off in (24, 20):
                        cand = head[off:off + klen]
                        if cand[:1] and (cand[:1].isalnum() or cand[:1] == b"_"):
                            key = cand.decode("utf-8", "replace")
                            break
                    if key is None:
                        continue
                    size = os.path.getsize(path)
                    f.seek(max(0, size - 65536))
                    tail = f.read()
            except OSError as e:
                ctx.errors.append({"parser": artifact, "file": ctx.rel(path), "error": str(e)})
                continue
            hdr = _parse_http_head(tail)
            kurl = _cache_key_url(key)
            if "://" not in kurl:   # e.g. Service Worker ScriptCache keys are numeric resource ids
                kurl = None
            ctx.emit(artifact, url=kurl, title=hdr.get("content-type"),
                     times=[("server_date", hdr.get("date"), "http_date"), ("last_modified", hdr.get("last-modified"), "http_date"),
                            ("file_mtime", ctx.mtime(path), "iso")],
                     details={"format": "simple-cache v%d" % ver, "key": ctx.red.url(key) if len(key) < 4096 else key[:200],
                              "size": size, "http": hdr}, src=path, loc="entry")
            n += 1
    return n


def cache_blockfile(ctx, d, artifact="cache"):
    p = os.path.join(d, "data_1")
    if not os.path.isfile(p):
        return 0
    data = open(p, "rb").read()
    if len(data) < 8192 or struct.unpack("<I", data[:4])[0] != 0xC104CAC3:
        return 0
    n = 0
    for off in range(8192, len(data) - 256 + 1, 256):
        blk = data[off:off + 256]
        klen = struct.unpack("<i", blk[32:36])[0]
        if not (4 <= klen <= 4096):
            continue
        key = data[off + 96:off + 96 + klen]
        if not re.match(rb"^(?:\d+/\d+/)?(?:_dk_)?[a-z][a-z0-9+.\-]*:", key) or b"\x00" in key:
            continue
        ctime = struct.unpack("<Q", blk[24:32])[0]
        k = key.decode("utf-8", "replace")
        ctx.emit(artifact, url=_cache_key_url(k), times=[("created", ctime, "webkit_us")],
                 details={"format": "blockfile", "key": ctx.red.url(k), "reuse_count": struct.unpack("<i", blk[12:16])[0]},
                 src=p, loc="block offset 0x%x" % off)
        n += 1
    ctx.limit("Chromium blockfile cache parsed heuristically (entry keys/creation time from data_1); bodies and headers not extracted.")
    return n


def cr_cache(ctx):
    for role in ("profile", "cache"):
        base = ctx.role_dir(role)
        if not base:
            continue
        for sub in ("Cache/Cache_Data", "Cache", "Media Cache", "Application Cache/Cache"):
            d = os.path.join(base, sub)
            if not os.path.isdir(d):
                continue
            if sub == "Cache" and os.path.isdir(os.path.join(base, "Cache", "Cache_Data")):
                continue
            if os.path.isfile(os.path.join(d, "index")) and os.path.isfile(os.path.join(d, "data_1")):
                cache_blockfile(ctx, d)
            else:
                cache_simple_dir(ctx, d)


def parse_chromium(ctx):
    run_parser(ctx, "history+downloads+searches", cr_history)
    run_parser(ctx, "cookies", cr_cookies)
    run_parser(ctx, "credentials", cr_logins)
    run_parser(ctx, "web_data(autofill)", cr_webdata)
    run_parser(ctx, "favicons/top_sites/shortcuts/predictor/media", cr_misc_sqlite)
    run_parser(ctx, "bookmarks", cr_bookmarks)
    es = run_parser(ctx, "preferences/local_state/permissions", cr_preferences) or {}
    run_parser(ctx, "extensions", lambda c: cr_extensions(c, es))
    run_parser(ctx, "sessions(SNSS)", cr_sessions)
    run_parser(ctx, "local_storage(LevelDB)", cr_local_storage)
    run_parser(ctx, "session_storage(LevelDB)", cr_session_storage)
    run_parser(ctx, "indexeddb(LevelDB)", cr_indexeddb)
    run_parser(ctx, "service_workers", cr_service_workers)
    run_parser(ctx, "extension_storage", cr_extension_storage)
    run_parser(ctx, "http_cache", cr_cache)


# ================================================================ Firefox / Gecko family
def ff_places(ctx):
    for path in ctx.files("profile", "places.sqlite"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if "moz_places" not in tb:
                continue
            visited = set()
            if "moz_historyvisits" in tb:
                vc = set(columns(con, "moz_historyvisits"))
                extra = ", v.source AS source" if "source" in vc else ""
                orphans = 0
                for r in con.execute("SELECT v.id AS vid, v.from_visit, v.place_id, v.visit_date, v.visit_type%s, p.url, p.title, "
                                     "p.visit_count, p.typed, p.hidden, p.frecency FROM moz_historyvisits v "
                                     "LEFT JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date" % extra):
                    r = rowd(r)
                    visited.add(r["place_id"])
                    if r["url"] is None:
                        orphans += 1
                    ctx.history_urls.add(r["url"])
                    ctx.emit("history", url=r["url"], title=r["title"], times=[("visited", r["visit_date"], "unix_us")],
                             details={"visit_id": r["vid"], "place_id": r["place_id"], "from_visit": r["from_visit"],
                                      "visit_type": FF_VISIT.get(r["visit_type"], r["visit_type"]), "visit_count": r["visit_count"],
                                      "typed": r["typed"], "hidden": r["hidden"], "frecency": r["frecency"], "source": r.get("source")},
                             src=path, loc="moz_historyvisits.id=%s" % r["vid"])
                if orphans:
                    ctx.finding("medium", "orphan_visits", "%d visit(s) reference missing moz_places rows" % orphans, src=path)
                ids = [r[0] for r in q(con, "SELECT id FROM moz_historyvisits ORDER BY id")]
                if ids and (ids[-1] - ids[0] + 1) - len(ids) > 0:
                    ctx.finding("info", "visit_id_gaps", "moz_historyvisits.id has %d gap(s): visits were deleted or expired"
                                % ((ids[-1] - ids[0] + 1) - len(ids)), src=path)
            nov = 0
            for r in sel(con, "moz_places", ["id", "url", "title", "visit_count", "last_visit_date", "frecency", "description"],
                         "WHERE last_visit_date IS NOT NULL"):
                if r["id"] in visited:
                    continue
                nov += 1
                ctx.history_urls.add(r["url"])
                ctx.emit("history_url", url=r["url"], title=r.get("title"), times=[("last_visit", r.get("last_visit_date"), "unix_us")],
                         details={"place_id": r["id"], "visit_count": r.get("visit_count"),
                                  "note": "place with last_visit_date but no surviving visit rows"}, src=path, loc="moz_places.id=%s" % r["id"])
            if nov:
                ctx.finding("info", "urls_without_visits", "%d place(s) carry last_visit_date without visit rows (visits deleted/expired)" % nov, src=path)
            if "moz_bookmarks" in tb:
                rows = [rowd(r) for r in q(con, "SELECT b.id, b.type, b.parent, b.title, b.dateAdded, b.lastModified, b.guid, p.url "
                                                "FROM moz_bookmarks b LEFT JOIN moz_places p ON p.id = b.fk")]
                byid = {r["id"]: r for r in rows}

                def fpath(r):
                    out, cur, g = [], byid.get(r["parent"]), 0
                    while cur and g < 64:
                        out.append(cur["title"] or cur["guid"] or "")
                        cur, g = byid.get(cur["parent"]), g + 1
                    return "/".join(reversed(out))
                for r in rows:
                    if r["type"] != 1:
                        continue
                    ctx.emit("bookmark", url=r["url"], title=r["title"],
                             times=[("added", r["dateAdded"], "unix_us"), ("modified", r["lastModified"], "unix_us")],
                             details={"folder": fpath(r), "guid": r["guid"]}, src=path, loc="moz_bookmarks.id=%s" % r["id"])
            if {"moz_annos", "moz_anno_attributes"} <= tb:
                rows = q(con, "SELECT a.place_id, n.name, a.content, a.dateAdded, a.lastModified, p.url FROM moz_annos a "
                              "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id "
                              "WHERE n.name LIKE 'downloads/%'")
                dl = collections.defaultdict(dict)
                for r in rows:
                    r = rowd(r)
                    e = dl[r["place_id"]]
                    e["url"] = r["url"]
                    e[r["name"]] = r["content"]
                    e["added"] = min(e.get("added") or r["dateAdded"], r["dateAdded"])
                for pid_, e in dl.items():
                    dest = e.get("downloads/destinationFileURI") or ""
                    meta = {}
                    try:
                        meta = json.loads(e.get("downloads/metaData") or "{}")
                    except ValueError:
                        pass
                    target = urllib.parse.unquote(dest[7:]) if dest.startswith("file://") else dest
                    if re.match(r"^/[A-Za-z]:/", target):
                        target = target[1:].replace("/", "\\")
                    ctx.emit("download", url=e["url"], title=os.path.basename(target.replace("\\", "/")), value=target,
                             times=[("started", e["added"], "unix_us"), ("ended", meta.get("endTime"), "unix_ms")],
                             details={"target_path": target, "destination_uri": dest, "state": meta.get("state"),
                                      "total_bytes": meta.get("fileSize"), "deleted": meta.get("deleted")},
                             src=path, loc="moz_annos.place_id=%s" % pid_)
            if "moz_inputhistory" in tb:
                for r in q(con, "SELECT i.input, i.use_count, p.url, p.last_visit_date FROM moz_inputhistory i "
                                "LEFT JOIN moz_places p ON p.id = i.place_id"):
                    r = rowd(r)
                    ctx.emit("omnibox_input", url=r["url"], value=r["input"], title=r["input"],
                             times=[("last_visit_of_target", r["last_visit_date"], "unix_us")],
                             details={"typed_text": r["input"], "use_count": r["use_count"]}, src=path, loc="moz_inputhistory")
            if "moz_places_metadata" in tb:
                for r in q(con, "SELECT m.*, p.url FROM moz_places_metadata m LEFT JOIN moz_places p ON p.id = m.place_id"):
                    r = rowd(r)
                    ctx.emit("page_interaction", url=r.get("url"),
                             times=[("created", r.get("created_at"), "unix_ms"), ("updated", r.get("updated_at"), "unix_ms")],
                             details={k: r.get(k) for k in ("total_view_time", "typing_time", "key_presses", "scrolling_time",
                                                            "scrolling_distance", "document_type")},
                             src=path, loc="moz_places_metadata.id=%s" % r.get("id"))
        finally:
            con.close()


def ff_cookies(ctx):
    for path in ctx.files("profile", "cookies.sqlite"):
        con = ctx.open_db(path)
        try:
            if "moz_cookies" not in tables(con):
                continue
            for r in sel(con, "moz_cookies", ["id", "originAttributes", "name", "value", "host", "path", "expiry",
                                              "lastAccessed", "creationTime", "isSecure", "isHttpOnly", "sameSite"]):
                host = r.get("host") or ""
                ctx.emit("cookie", url="https://%s%s" % (host.lstrip("."), r.get("path") or "/"), title=r.get("name"),
                         value=ctx.red.secret(r.get("value"), "cookie"),
                         times=[("created", r.get("creationTime"), "unix_us"), ("last_access", r.get("lastAccessed"), "unix_us"),
                                ("expires", r.get("expiry"), "unix_auto")],
                         details={"host": host, "secure": r.get("isSecure"), "httponly": r.get("isHttpOnly"),
                                  "samesite": r.get("sameSite"), "origin_attributes": r.get("originAttributes")},
                         src=path, loc="moz_cookies.id=%s" % r.get("id"), domain=host.lstrip(".").lower())
        finally:
            con.close()


def ff_formhistory(ctx):
    for path in ctx.files("profile", "formhistory.sqlite"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if "moz_formhistory" in tb:
                for r in sel(con, "moz_formhistory", ["id", "fieldname", "value", "timesUsed", "firstUsed", "lastUsed", "guid"]):
                    ctx.emit("form", title=r.get("fieldname"), value=ctx.red.secret(r.get("value"), "form-value"),
                             times=[("first_used", r.get("firstUsed"), "unix_us"), ("last_used", r.get("lastUsed"), "unix_us")],
                             details={"field": r.get("fieldname"), "count": r.get("timesUsed"), "guid": r.get("guid")},
                             src=path, loc="moz_formhistory.id=%s" % r.get("id"))
            if "moz_deleted_formhistory" in tb:
                rows = sel(con, "moz_deleted_formhistory", ["id", "timeDeleted", "guid"])
                for r in rows:
                    ctx.emit("form_deleted", value=r.get("guid"), times=[("deleted", r.get("timeDeleted"), "unix_us")],
                             details={"note": "tombstone of a deleted form-history entry"}, src=path,
                             loc="moz_deleted_formhistory.id=%s" % r.get("id"))
                if rows:
                    ctx.finding("low", "form_history_deleted", "%d form-history deletion tombstone(s)" % len(rows), src=path, cls="observed")
        finally:
            con.close()


def ff_logins(ctx):
    for path in ctx.files("profile", "logins.json"):
        data = safe_json_load(path)
        for lg in data.get("logins") or []:
            ctx.emit("credential", url=lg.get("hostname"), title=lg.get("usernameField"),
                     value="[encrypted: NSS/key4.db]" if lg.get("encryptedUsername") else None,
                     times=[("created", lg.get("timeCreated"), "unix_ms"), ("last_used", lg.get("timeLastUsed"), "unix_ms"),
                            ("password_changed", lg.get("timePasswordChanged"), "unix_ms")],
                     details={"form_submit_url": ctx.red.url(lg.get("formSubmitURL")), "http_realm": lg.get("httpRealm"),
                              "times_used": lg.get("timesUsed"), "guid": lg.get("guid"),
                              "password": {"stored": bool(lg.get("encryptedPassword")), "encryption": "NSS (key4.db)"}},
                     src=path, loc="guid=%s" % lg.get("guid"))
        ctx.limit("Firefox logins.json usernames/passwords are NSS-encrypted (key4.db, optional primary password); not decrypted by design.")
    for path in ctx.files("profile", "signedInUser.json"):
        try:
            d = safe_json_load(path).get("accountData", {})
            ctx.emit("account", value=ctx.red.secret(d.get("email"), "email"),
                     details={"verified": d.get("verified"), "uid": ctx.red.secret(d.get("uid"), "uid")}, src=path, loc="accountData")
        except (ValueError, AttributeError):
            pass


def ff_favicons(ctx):
    for path in ctx.files("profile", "favicons.sqlite"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if {"moz_pages_w_icons", "moz_icons_to_pages", "moz_icons"} <= tb:
                for r in q(con, "SELECT p.page_url, i.icon_url, i.expire_ms FROM moz_pages_w_icons p "
                                "JOIN moz_icons_to_pages ip ON ip.page_id = p.id JOIN moz_icons i ON i.id = ip.icon_id"):
                    r = rowd(r)
                    ctx.emit("favicon", url=r["page_url"], times=[("icon_expires", r["expire_ms"], "unix_ms")],
                             details={"icon_url": ctx.red.url(r["icon_url"])}, src=path, loc="moz_pages_w_icons")
        finally:
            con.close()


def _ff_session(ctx, path, data):
    sess = data.get("session") or {}
    common = [("session_last_update", sess.get("lastUpdate"), "unix_ms"), ("session_start", sess.get("startTime"), "unix_ms")]
    seen = set()

    def tab_entries(tab, state, widx, tidx, closed_at=None, wclosed=False):
        entries = tab.get("entries") or []
        cur = (tab.get("index") or len(entries)) - 1
        for eidx, e in enumerate(entries):
            url = e.get("url")
            if not url:
                continue
            key = (state, widx, tidx, eidx, url)
            if key in seen:
                continue
            seen.add(key)
            times = []
            if eidx == cur and tab.get("lastAccessed"):
                times.append(("tab_last_accessed", tab.get("lastAccessed"), "unix_ms"))
            if closed_at:
                times.append(("closed", closed_at, "unix_ms"))
            d = {"state": state, "window": widx, "tab": tidx, "entry": eidx, "current_entry": eidx == cur,
                 "pinned": tab.get("pinned"), "hidden": tab.get("hidden"), "window_closed": wclosed,
                 "file": os.path.basename(path)}
            if e.get("referrer"):
                d["referrer"] = ctx.red.url(e.get("referrer"))
            if e.get("formdata"):
                d["formdata"] = ctx.red.secret(json.dumps(e["formdata"]), "formdata")
            ctx.emit("session_tab" if state == "open" else "closed_tab", url=url, title=e.get("title"),
                     times=times + common, details=d, src=path, loc="w%d/t%d/e%d" % (widx, tidx, eidx))
    for widx, w in enumerate(data.get("windows") or []):
        for tidx, t in enumerate(w.get("tabs") or []):
            tab_entries(t, "open", widx, tidx)
        for tidx, ct in enumerate(w.get("_closedTabs") or []):
            tab_entries(ct.get("state") or {}, "closed", widx, tidx, ct.get("closedAt"))
    for widx, w in enumerate(data.get("_closedWindows") or []):
        for tidx, t in enumerate(w.get("tabs") or []):
            tab_entries(t, "closed", 1000 + widx, tidx, w.get("closedAt"), True)
    for c in data.get("cookies") or []:
        ctx.emit("cookie", url="https://%s%s" % ((c.get("host") or "").lstrip("."), c.get("path") or "/"), title=c.get("name"),
                 value=ctx.red.secret(c.get("value"), "cookie"), details={"session_cookie": True, "file": os.path.basename(path)},
                 src=path, loc="session cookies")


def ff_sessions(ctx):
    paths = ctx.files("profile", "sessionstore.jsonlz4") + ctx.files("profile", "sessionstore-backups/*lz4*") + \
        ctx.files("profile", "sessionstore.js")
    for path in paths:
        try:
            raw = open(path, "rb").read()
            data = json.loads(mozlz4_decode(raw) if raw[:8] == b"mozLz40\0" else raw)
        except (ValueError, OSError, IndexError) as e:
            ctx.errors.append({"parser": "sessionstore", "file": ctx.rel(path), "error": str(e)})
            continue
        _ff_session(ctx, path, data)


def ff_extensions(ctx):
    for path in ctx.files("profile", "extensions.json"):
        data = safe_json_load(path)
        for a in data.get("addons") or []:
            loc = a.get("location")
            builtin = loc in ("app-builtin", "app-system-defaults", "app-system-addons", "app-builtin-addons")
            perms = (a.get("userPermissions") or {}).get("permissions", []) + (a.get("userPermissions") or {}).get("origins", [])
            risky = sorted(set(perms) & RISKY_PERMS)
            name = (a.get("defaultLocale") or {}).get("name")
            ctx.emit("extension", url="moz-extension://%s/" % a.get("id"), title=name, value=a.get("version"),
                     times=[("installed", a.get("installDate"), "unix_ms"), ("updated", a.get("updateDate"), "unix_ms")],
                     details={"id": a.get("id"), "type": a.get("type"), "active": a.get("active"),
                              "user_disabled": a.get("userDisabled"), "location": loc, "builtin": builtin,
                              "source_uri": ctx.red.url(a.get("sourceURI")), "signed_state": a.get("signedState"),
                              "permissions": perms, "risky_permissions": risky, "path": a.get("path")},
                     src=path, loc="addon %s" % a.get("id"))
            if risky and not builtin:
                ctx.finding("low", "extension_broad_permissions", "Add-on '%s' (%s) requests: %s" % (name, a.get("id"), ", ".join(risky)), src=path)
            if not builtin and a.get("signedState") is not None and a.get("signedState") <= 0:
                ctx.finding("medium", "extension_unsigned", "Add-on '%s' is unsigned/unverified (signedState=%s)" % (name, a.get("signedState")), src=path)


PREF_RE = re.compile(r'^\s*user_pref\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*(.*?)\s*\)\s*;\s*$')
FF_PRIVACY_FLAGS = {
    "privacy.sanitize.sanitizeOnShutdown": (True, "History is cleared on shutdown"),
    "privacy.clearOnShutdown.history": (True, "clearOnShutdown.history enabled"),
    "privacy.clearOnShutdown_v2.historyFormDataAndDownloads": (True, "clearOnShutdown_v2 history enabled"),
    "places.history.enabled": (False, "History recording disabled"),
    "browser.privatebrowsing.autostart": (True, "Permanent private browsing mode"),
}


def ff_prefs(ctx):
    for path in ctx.files("profile", "prefs.js") + ctx.files("profile", "user.js"):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = PREF_RE.match(line)
                if not m:
                    continue
                k, raw = m.group(1), m.group(2)
                try:
                    v = json.loads(raw)
                except ValueError:
                    v = raw
                times = []
                if isinstance(v, int) and re.search(r"(?i)(time|date|lastUpdate|last_success|Created)", k):
                    for fmt in ("unix_s", "unix_ms"):
                        dt = conv_time(v, fmt)
                        if dt and PLAUSIBLE_MIN <= dt <= PLAUSIBLE_MAX:
                            times = [("pref_time", v, fmt)]
                            break
                vv = ctx.red.secret(v, "pref") if (ctx.red.on and PREF_SENSITIVE.search(k)) else v
                ctx.emit("setting", title=k, value=vv if isinstance(vv, str) else json.dumps(vv), times=times,
                         details={"file": os.path.basename(path)}, src=path, loc=k)
                if k in FF_PRIVACY_FLAGS and v == FF_PRIVACY_FLAGS[k][0]:
                    ctx.finding("medium", "privacy_anti_forensic_setting", "%s (%s=%s)" % (FF_PRIVACY_FLAGS[k][1], k, v), src=path, cls="observed")
    for path in ctx.files("profile", "times.json"):
        try:
            d = safe_json_load(path)
            ctx.emit("browser_profile", title="times.json", times=[("profile_created", d.get("created"), "unix_ms"),
                                                                  ("first_use", d.get("firstUse"), "unix_ms")],
                     details=d, src=path, loc="times.json")
        except ValueError:
            pass
    for path in ctx.files("profile", "compatibility.ini"):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            kv = dict(l.strip().split("=", 1) for l in f if "=" in l)
        ctx.emit("setting", title="compatibility.ini", value=kv.get("LastVersion"), details=kv, src=path, loc="Compatibility")
    for path in ctx.files("profile", "search.json.mozlz4"):
        try:
            d = json.loads(mozlz4_decode(open(path, "rb").read()))
            for e in d.get("engines") or []:
                ctx.emit("search_engine", title=e.get("_name") or e.get("name"), value=e.get("_loadPath"),
                         details={"hidden": (e.get("_metaData") or {}).get("hidden")}, src=path, loc="engines")
        except (ValueError, OSError, IndexError) as e:
            ctx.errors.append({"parser": "search.json.mozlz4", "file": ctx.rel(path), "error": str(e)})
    for path in ctx.files("profile", "permissions.sqlite"):
        con = ctx.open_db(path)
        try:
            if "moz_perms" in tables(con):
                for r in sel(con, "moz_perms", ["id", "origin", "type", "permission", "expireType", "expireTime", "modificationTime"]):
                    ctx.emit("permission", url=r.get("origin"), title=r.get("type"), value=str(r.get("permission")),
                             times=[("modified", r.get("modificationTime"), "unix_ms"), ("expires", r.get("expireTime"), "unix_ms")],
                             details={"expire_type": r.get("expireType")}, src=path, loc="moz_perms.id=%s" % r.get("id"))
        finally:
            con.close()
    for path in ctx.files("profile", "containers.json"):
        try:
            for ident in safe_json_load(path).get("identities") or []:
                ctx.emit("setting", title="container", value=ident.get("name") or ident.get("l10nID"),
                         details={"userContextId": ident.get("userContextId"), "public": ident.get("public")}, src=path, loc="identities")
        except (ValueError, AttributeError):
            pass


def _ff_origin(dirname):
    s = dirname.replace("+++", "://")
    m = re.match(r"^(.*://[^+^]+)\+(\d+)$", s)
    if m:
        s = "%s:%s" % (m.group(1), m.group(2))
    return s.split("^")[0]


def ff_storage(ctx):
    for odir in ctx.dirs("profile", "storage/default/*"):
        origin = _ff_origin(os.path.basename(odir))
        md = os.path.join(odir, ".metadata-v2")
        if os.path.isfile(md):
            raw = open(md, "rb").read(8)
            if len(raw) == 8:
                ctx.emit("storage_origin", url=origin, times=[("origin_last_access", struct.unpack(">q", raw)[0], "unix_us")],
                         details={"store": "storage/default"}, src=md, loc=".metadata-v2")
        for path in glob.glob(os.path.join(odir, "ls", "data.sqlite")):
            con = ctx.open_db(path)
            try:
                if "data" in tables(con):
                    for r in sel(con, "data", ["key", "utf16_length", "conversion_type", "compression_type", "value"]):
                        v = r.get("value")
                        if isinstance(v, (bytes, bytearray)) and r.get("compression_type") == 1:
                            try:
                                v = snappy_decompress(bytes(v))
                            except (ValueError, IndexError):
                                pass
                        if isinstance(v, (bytes, bytearray)):
                            v = bytes(v).decode("utf-8", "replace")
                        ctx.emit("local_storage", url=origin, title=r.get("key"), value=ctx.red.secret(v, "storage-value"),
                                 details={"value_length": len(v or ""), "store": "LSNG"}, src=path, loc="data")
            finally:
                con.close()
        for path in glob.glob(os.path.join(odir, "idb", "*.sqlite")):
            con = ctx.open_db(path)
            try:
                tb = tables(con)
                dbname = None
                if "database" in tb:
                    r = q(con, "SELECT name FROM database LIMIT 1")
                    dbname = r[0][0] if r else None
                if {"object_store", "object_data"} <= tb:
                    for st in q(con, "SELECT s.id, s.name, count(d.key) FROM object_store s LEFT JOIN object_data d "
                                     "ON d.object_store_id = s.id GROUP BY s.id"):
                        urls = set()
                        for (blob,) in q(con, "SELECT data FROM object_data WHERE object_store_id = ? LIMIT 500", (st[0],)):
                            if isinstance(blob, (bytes, bytearray)):
                                try:
                                    blob = snappy_decompress(bytes(blob))
                                except (ValueError, IndexError):
                                    pass
                                for _, u in carve_urls(bytes(blob))[:10]:
                                    urls.add(u)
                        ctx.emit("indexeddb", url=origin, title="%s/%s" % (dbname, st[1]), value="%d record(s)" % st[2],
                                 details={"database": dbname, "object_store": st[1], "records": st[2],
                                          "urls_in_values": sorted(ctx.red.url(u) for u in urls)[:50]}, src=path, loc="object_store.id=%s" % st[0])
            finally:
                con.close()
    for path in ctx.files("profile", "webappsstore.sqlite"):
        con = ctx.open_db(path)
        try:
            if "webappsstore2" in tables(con):
                for r in sel(con, "webappsstore2", ["originKey", "scope", "key", "value"]):
                    ok = r.get("originKey") or r.get("scope") or ""
                    parts = ok.split(":")
                    host = parts[0][::-1].strip(".") if parts else ok
                    origin = "%s://%s" % (parts[1], host) if len(parts) > 1 else host
                    ctx.emit("local_storage", url=origin, title=r.get("key"), value=ctx.red.secret(r.get("value"), "storage-value"),
                             details={"store": "webappsstore (legacy)", "origin_key": ok}, src=path, loc="webappsstore2")
        finally:
            con.close()
    for path in ctx.files("profile", "serviceworker.txt"):
        lines = open(path, "r", encoding="utf-8", errors="replace").read().splitlines()
        block = []
        for ln in lines[1:] + ["#"]:
            if ln.strip() == "#":
                urls = [x for x in block if re.match(r"^https?://", x)]
                nums = [int(x) for x in block if re.fullmatch(r"\d{12,17}", x)]
                if urls:
                    ctx.emit("service_worker", url=urls[0], title=urls[1] if len(urls) > 1 else None,
                             times=[("worker_time_%d" % i, n, "unix_auto") for i, n in enumerate(nums[:3])],
                             details={"script_url": ctx.red.url(urls[1]) if len(urls) > 1 else None, "fields": len(block)},
                             src=path, loc="serviceworker.txt")
                block = []
            else:
                block.append(ln.strip())
        ctx.limit("Firefox serviceworker.txt parsed heuristically (URLs and epoch-like fields).")


def ff_cache2(ctx):
    for role in ("cache", "profile"):
        for d in ctx.dirs(role, "cache2/entries"):
            for fn in os.listdir(d):
                path = os.path.join(d, fn)
                try:
                    size = os.path.getsize(path)
                    if size < 40:
                        continue
                    with open(path, "rb") as f:
                        f.seek(size - 4)
                        moff = struct.unpack(">I", f.read(4))[0]
                        if moff >= size - 4:
                            continue
                        f.seek(moff)
                        meta = f.read(size - 4 - moff)
                except OSError as e:
                    ctx.errors.append({"parser": "cache2", "file": ctx.rel(path), "error": str(e)})
                    continue
                nchunks = (moff + 262143) // 262144
                p = 4 + 2 * nchunks
                if len(meta) < p + 28:
                    continue
                ver, fetch, lastf, lastm, frec, exp, ksz = struct.unpack(">IIIIIII", meta[p:p + 28])
                p += 28
                if ver >= 2:
                    p += 4
                if ver > 10 or ksz > 65536:
                    continue
                key = meta[p:p + ksz].decode("utf-8", "replace")
                elems = meta[p + ksz + 1:].split(b"\x00")
                el = {}
                for i in range(0, len(elems) - 1, 2):
                    el[elems[i].decode("latin-1", "replace")] = elems[i + 1].decode("latin-1", "replace")
                head = el.get("response-head", "")
                hdr = {}
                if head:
                    hl = head.split("\r\n")
                    hdr["status"] = hl[0][:80]
                    for ln in hl[1:]:
                        if ":" in ln:
                            k, v = ln.split(":", 1)
                            if k.strip().lower() in ("content-type", "content-length", "date", "last-modified", "server", "location"):
                                hdr[k.strip().lower()] = v.strip()[:300]
                m = re.search(r":((?:https?|ftp|moz-extension)://.*)$", key)
                url = m.group(1) if m else key
                ctx.emit("cache", url=url, title=hdr.get("content-type"),
                         times=[("last_fetched", lastf, "unix_s"), ("last_modified", lastm, "unix_s"),
                                ("expires", exp if exp != 0xFFFFFFFF else None, "unix_s"), ("server_date", hdr.get("date"), "http_date")],
                         details={"format": "cache2 v%d" % ver, "fetch_count": fetch, "key": ctx.red.url(key), "size": moff,
                                  "http": hdr, "request_method": el.get("request-method")}, src=path, loc="metadata@0x%x" % moff)


def parse_firefox(ctx):
    run_parser(ctx, "places(history/bookmarks/downloads)", ff_places)
    run_parser(ctx, "cookies", ff_cookies)
    run_parser(ctx, "formhistory", ff_formhistory)
    run_parser(ctx, "logins/accounts", ff_logins)
    run_parser(ctx, "favicons", ff_favicons)
    run_parser(ctx, "sessionstore(mozLz4)", ff_sessions)
    run_parser(ctx, "extensions", ff_extensions)
    run_parser(ctx, "prefs/permissions/profile", ff_prefs)
    run_parser(ctx, "storage(LSNG/IDB/SW)", ff_storage)
    run_parser(ctx, "cache2", ff_cache2)


# ================================================================ Safari / WebKit
def sf_history(ctx):
    for path in ctx.files("safari", "History.db"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if {"history_items", "history_visits"} <= tb:
                for r in q(con, "SELECT v.id, v.visit_time, v.title, v.load_successful, v.redirect_source, v.redirect_destination, "
                                "i.url, i.visit_count, i.domain_expansion FROM history_visits v LEFT JOIN history_items i "
                                "ON i.id = v.history_item ORDER BY v.visit_time"):
                    r = rowd(r)
                    ctx.history_urls.add(r["url"])
                    ctx.emit("history", url=r["url"], title=r["title"], times=[("visited", r["visit_time"], "mac_s")],
                             details={"visit_id": r["id"], "visit_count": r["visit_count"], "load_successful": r["load_successful"],
                                      "redirect_source": r["redirect_source"], "redirect_destination": r["redirect_destination"]},
                             src=path, loc="history_visits.id=%s" % r["id"])
            if "history_tombstones" in tb:
                rows = sel(con, "history_tombstones", ["id", "start_time", "end_time", "url", "generation"])
                for r in rows:
                    ctx.emit("history_deleted", url=r.get("url"), times=[("deleted_range_start", r.get("start_time"), "mac_s"),
                                                                        ("deleted_range_end", r.get("end_time"), "mac_s")],
                             details={"note": "Safari history tombstone (deletion record)", "generation": r.get("generation")},
                             src=path, loc="history_tombstones.id=%s" % r.get("id"))
                if rows:
                    ctx.finding("medium", "history_deleted", "Safari: %d history deletion tombstone(s)" % len(rows), src=path, cls="observed")
        finally:
            con.close()


def _plist_walk(o, fn, depth=0):
    if depth > 40:
        return
    if isinstance(o, dict):
        fn(o)
        for v in o.values():
            _plist_walk(v, fn, depth + 1)
    elif isinstance(o, list):
        for v in o:
            _plist_walk(v, fn, depth + 1)


def sf_plists(ctx):
    for path in ctx.files("safari", "Downloads.plist"):
        d = safe_plist_load(path)
        for e in d.get("DownloadHistory") or []:
            tp = e.get("DownloadEntryPath") or ""
            ctx.emit("download", url=e.get("DownloadEntryURL"), title=os.path.basename(tp), value=tp,
                     times=[("started", e.get("DownloadEntryDateAddedKey"), "datetime"),
                            ("ended", e.get("DownloadEntryDateFinishedKey"), "datetime")],
                     details={"target_path": tp, "received_bytes": e.get("DownloadEntryProgressBytesSoFar"),
                              "total_bytes": e.get("DownloadEntryProgressTotalToLoad"),
                              "identifier": e.get("DownloadEntryIdentifier"),
                              "remove_when_done": e.get("DownloadEntryRemoveWhenDoneKey")}, src=path, loc="DownloadHistory")
    for path in ctx.files("safari", "Bookmarks.plist"):
        d = safe_plist_load(path)

        def walk(n, folder):
            t = n.get("WebBookmarkType")
            if t == "WebBookmarkTypeLeaf":
                rl = n.get("ReadingList")
                ctx.emit("reading_list" if rl is not None else "bookmark", url=n.get("URLString"),
                         title=(n.get("URIDictionary") or {}).get("title"),
                         times=[("added", (rl or {}).get("DateAdded"), "datetime"), ("last_viewed", (rl or {}).get("DateLastViewed"), "datetime")],
                         details={"folder": "/".join(folder), "uuid": n.get("WebBookmarkUUID"),
                                  "preview": (rl or {}).get("PreviewText")}, src=path, loc="uuid=%s" % n.get("WebBookmarkUUID"))
            for c in n.get("Children") or []:
                if isinstance(c, dict):
                    walk(c, folder + [n.get("Title") or ""] if t == "WebBookmarkTypeList" else folder)
        walk(d, [])
    for name in ("LastSession.plist", "RecentlyClosedTabs.plist"):
        for path in ctx.files("safari", name):
            d = safe_plist_load(path)
            found = []
            _plist_walk(d, lambda o: found.append(o) if "TabURL" in o else None)
            for o in found:
                ctx.emit("session_tab" if name.startswith("Last") else "closed_tab", url=o.get("TabURL"), title=o.get("TabTitle"),
                         times=[("closed", o.get("DateClosed"), "datetime"), ("last_visit", o.get("LastVisitTime"), "mac_s")],
                         details={"file": name, "tab_uuid": o.get("TabUUID"),
                                  "session_state_blob": bool(o.get("SessionState"))}, src=path, loc=name)
            if any(o.get("SessionState") for o in found):
                ctx.limit("Safari SessionState blobs (back/forward lists) are not decoded.")
    for path in ctx.files("safari", "TopSites.plist"):
        d = safe_plist_load(path)
        for e in d.get("TopSites") or []:
            ctx.emit("top_site", url=e.get("TopSiteURLString"), title=e.get("TopSiteTitle"), src=path, loc="TopSites")
    for path in ctx.files("safari", "*Extensions/Extensions.plist"):
        d = safe_plist_load(path)
        items = d.get("Installed Extensions") if isinstance(d, dict) and "Installed Extensions" in d else d
        if isinstance(items, dict):
            items = [dict(v, __id=k) for k, v in items.items() if isinstance(v, dict)]
        for e in items or []:
            ctx.emit("extension", title=e.get("Archive File Name") or e.get("__id"), value=str(e.get("Enabled")),
                     times=[("added", e.get("AddedDate"), "datetime")], details={"raw_keys": sorted(e.keys())[:30]},
                     src=path, loc="Extensions.plist")


def sf_dbs(ctx):
    for path in ctx.files("safari", "CloudTabs.db"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if "cloud_tabs" in tb:
                devs = {}
                if "cloud_tab_devices" in tb:
                    devs = {r[0]: r[1] for r in q(con, "SELECT device_uuid, device_name FROM cloud_tab_devices")}
                for r in sel(con, "cloud_tabs", ["tab_uuid", "device_uuid", "url", "title", "is_pinned"]):
                    ctx.emit("cloud_tab", url=r.get("url"), title=r.get("title"),
                             details={"device": devs.get(r.get("device_uuid")), "pinned": r.get("is_pinned")}, src=path, loc="cloud_tabs")
        finally:
            con.close()
    for path in ctx.files("safari", "Favicon Cache/favicons.db"):
        con = ctx.open_db(path)
        try:
            tb = tables(con)
            if {"page_url", "icon_info"} <= tb:
                for r in q(con, "SELECT p.url, i.url, i.timestamp FROM page_url p LEFT JOIN icon_info i ON i.uuid = p.uuid"):
                    ctx.emit("favicon", url=r[0], times=[("icon_timestamp", r[2], "mac_s")], details={"icon_url": ctx.red.url(r[1])},
                             src=path, loc="page_url")
        finally:
            con.close()
    for path in ctx.files("safari", "PerSitePreferences.db"):
        con = ctx.open_db(path)
        try:
            if "preference_values" in tables(con):
                for r in sel(con, "preference_values", ["domain", "preference", "preference_value", "timestamp"]):
                    ctx.emit("permission", title=r.get("preference"), value=str(r.get("preference_value")),
                             times=[("set", r.get("timestamp"), "mac_s")], details={"domain": r.get("domain")},
                             src=path, loc="preference_values", domain=r.get("domain"))
        finally:
            con.close()
    for role in ("cache", "safari"):
        for path in ctx.files(role, "Cache.db"):
            con = ctx.open_db(path)
            try:
                if "cfurl_cache_response" in tables(con):
                    for r in sel(con, "cfurl_cache_response", ["entry_ID", "request_key", "time_stamp", "partition", "storage_policy"]):
                        ctx.emit("cache", url=r.get("request_key"), times=[("cached", r.get("time_stamp"), "iso")],
                                 details={"partition": r.get("partition"), "format": "CFNetwork Cache.db"}, src=path,
                                 loc="cfurl_cache_response.entry_ID=%s" % r.get("entry_ID"))
            finally:
                con.close()
    for role in ("safari", "webkit"):
        for path in ctx.files(role, "**/LocalStorage/*.localstorage"):
            con = ctx.open_db(path)
            try:
                if "ItemTable" in tables(con):
                    origin = origin_from_dirname(os.path.basename(path).replace(".localstorage", ""))
                    for r in sel(con, "ItemTable", ["key", "value"]):
                        v = r.get("value")
                        if isinstance(v, (bytes, bytearray)):
                            v = bytes(v).decode("utf-16-le", "replace")
                        ctx.emit("local_storage", url=origin, title=r.get("key"), value=ctx.red.secret(v, "storage-value"),
                                 details={"store": "WebKit LocalStorage", "value_length": len(v or "")}, src=path, loc="ItemTable")
            finally:
                con.close()


def binarycookies_parse(data):
    if data[:4] != b"cook":
        raise ValueError("not a binarycookies file")
    n = struct.unpack(">I", data[4:8])[0]
    sizes = struct.unpack(">%dI" % n, data[8:8 + 4 * n])
    off = 8 + 4 * n
    out = []
    for ps in sizes:
        page = data[off:off + ps]
        off += ps
        if page[:4] != b"\x00\x00\x01\x00":
            continue
        nc = struct.unpack("<I", page[4:8])[0]
        offs = struct.unpack("<%dI" % nc, page[8:8 + 4 * nc])
        for co in offs:
            c = page[co:]
            size, _, flags, _, uo, no, po, vo = struct.unpack("<8I", c[:32])
            exp, cre = struct.unpack("<dd", c[40:56])

            def cs(o):
                e = c.find(b"\x00", o)
                return c[o:e if e >= 0 else None].decode("utf-8", "replace")
            out.append({"domain": cs(uo), "name": cs(no), "path": cs(po), "value": cs(vo), "flags": flags,
                        "expires": exp, "created": cre})
    return out


def sf_cookies(ctx):
    for role in ("cookies", "cookies_container", "safari"):
        for path in ctx.files(role, "*.binarycookies"):
            try:
                cookies = binarycookies_parse(open(path, "rb").read())
            except (ValueError, struct.error) as e:
                ctx.errors.append({"parser": "binarycookies", "file": ctx.rel(path), "error": str(e)})
                continue
            for c in cookies:
                ctx.emit("cookie", url="https://%s%s" % (c["domain"].lstrip("."), c["path"] or "/"), title=c["name"],
                         value=ctx.red.secret(c["value"], "cookie"),
                         times=[("created", c["created"], "mac_s"), ("expires", c["expires"], "mac_s")],
                         details={"host": c["domain"], "secure": bool(c["flags"] & 1), "httponly": bool(c["flags"] & 4)},
                         src=path, loc="binarycookies", domain=c["domain"].lstrip(".").lower())


def parse_safari(ctx):
    run_parser(ctx, "History.db", sf_history)
    run_parser(ctx, "plists(downloads/bookmarks/sessions/topsites/extensions)", sf_plists)
    run_parser(ctx, "cloudtabs/favicons/permissions/cache/localstorage", sf_dbs)
    run_parser(ctx, "binarycookies", sf_cookies)
    if ctx.dirs("webkit", "**/IndexedDB") or ctx.dirs("safari", "Databases"):
        ctx.limit("WebKit IndexedDB/WebSQL databases are inventoried (SQLite inventory/carving) but not decoded.")
    ctx.limit("Safari credentials live in the macOS Keychain (out of scope; not collected).")


# ================================================================ other WebKit/Qt browsers
def parse_epiphany(ctx):
    def run(c):
        for path in ctx.files("profile", "ephy-history.db"):
            con = ctx.open_db(path)
            try:
                tb = tables(con)
                if {"visits", "urls"} <= tb:
                    for r in q(con, "SELECT v.id, v.visit_time, v.visit_type, u.url, u.title, u.visit_count FROM visits v "
                                    "LEFT JOIN urls u ON u.id = v.url"):
                        r = rowd(r)
                        ctx.history_urls.add(r["url"])
                        ctx.emit("history", url=r["url"], title=r["title"], times=[("visited", r["visit_time"], "unix_auto")],
                                 details={"visit_type": r["visit_type"], "visit_count": r["visit_count"]}, src=path,
                                 loc="visits.id=%s" % r["id"])
            finally:
                con.close()
        if ctx.files("profile", "bookmarks.gvdb"):
            ctx.limit("Epiphany bookmarks.gvdb (GVariant DB) is inventoried only.")
    run_parser(ctx, "epiphany history", run)


def parse_qutebrowser(ctx):
    def run(c):
        for path in ctx.files("profile", "history.sqlite"):
            con = ctx.open_db(path)
            try:
                if "History" in tables(con):
                    for r in sel(con, "History", ["rowid", "url", "title", "atime", "redirect"]):
                        ctx.history_urls.add(r.get("url"))
                        ctx.emit("history", url=r.get("url"), title=r.get("title"), times=[("visited", r.get("atime"), "unix_s")],
                                 details={"redirect": r.get("redirect")}, src=path, loc="History.rowid=%s" % r.get("rowid"))
            finally:
                con.close()
    run_parser(ctx, "qutebrowser history", run)


def parse_ese(ctx):
    def run(c):
        for path in ctx.walk():
            if file_magic(path) == "ese":
                ctx.emit("ese_database", title=os.path.basename(path), value="ESE database detected",
                         times=[("file_mtime", ctx.mtime(path), "iso")],
                         details={"note": "Extensible Storage Engine DB (IE/Edge Legacy WebCache). Parsing NOT implemented; "
                                          "export with libesedb/esedbexport and analyze separately."},
                         src=path, loc="header")
        ctx.limit("IE / Edge Legacy WebCacheV01.dat (ESE) is acquired and hashed but NOT parsed by this tool.")
    run_parser(ctx, "ese detection", run)


# ================================================================ operating-system artifacts
def lnk_parse(data):
    if len(data) < 76 or data[:4] != b"L\x00\x00\x00":
        raise ValueError("not a shell link")
    flags = struct.unpack("<I", data[20:24])[0]
    ct, at, wt = struct.unpack("<QQQ", data[28:52])
    size = struct.unpack("<I", data[52:56])[0]
    p = 76
    if flags & 1:
        p += 2 + struct.unpack("<H", data[p:p + 2])[0]
    target = None
    if flags & 2:
        li = data[p:]
        lsz, hsz, lflags, vol_off, lbp_off, cnr_off, cps_off = struct.unpack("<7I", li[:28])

        def cstr(o):
            e = li.find(b"\x00", o)
            return li[o:e].decode("mbcs" if os.name == "nt" else "latin-1", "replace")
        if lflags & 1 and lbp_off:
            target = cstr(lbp_off) + (cstr(cps_off) if cps_off else "")
        p += lsz
    return {"flags": flags, "target_created": ct, "target_accessed": at, "target_written": wt, "target_size": size,
            "target_path": target}


def parse_os(ctx):
    def xbel(c):
        for path in ctx.files("os", "recently-used.xbel"):
            root = safe_xml_parse(path)
            for bm in root.iter("bookmark"):
                href = bm.get("href")
                apps = [a.get("name") for a in bm.iter() if a.tag.endswith("application")]
                ctx.emit("os_recent_file", url=href, title=urllib.parse.unquote(href.rsplit("/", 1)[-1]) if href else None,
                         times=[("added", bm.get("added"), "iso"), ("modified", bm.get("modified"), "iso"),
                                ("visited", bm.get("visited"), "iso")],
                         details={"applications": apps, "source": "GTK recently-used.xbel"}, src=path, loc="bookmark")

    def quarantine(c):
        for path in ctx.files("os", "com.apple.LaunchServices.QuarantineEventsV2"):
            con = ctx.open_db(path)
            try:
                if "LSQuarantineEvent" in tables(con):
                    for r in sel(con, "LSQuarantineEvent", ["LSQuarantineEventIdentifier", "LSQuarantineTimeStamp",
                                                            "LSQuarantineAgentBundleIdentifier", "LSQuarantineAgentName",
                                                            "LSQuarantineDataURLString", "LSQuarantineOriginURLString",
                                                            "LSQuarantineOriginTitle", "LSQuarantineTypeNumber"]):
                        ctx.emit("os_quarantine_event", url=r.get("LSQuarantineDataURLString"), title=r.get("LSQuarantineAgentName"),
                                 times=[("quarantined", r.get("LSQuarantineTimeStamp"), "mac_s")],
                                 details={"agent_bundle": r.get("LSQuarantineAgentBundleIdentifier"),
                                          "origin_url": ctx.red.url(r.get("LSQuarantineOriginURLString")),
                                          "origin_title": r.get("LSQuarantineOriginTitle"), "type": r.get("LSQuarantineTypeNumber")},
                                 src=path, loc="LSQuarantineEvent %s" % r.get("LSQuarantineEventIdentifier"))
            finally:
                con.close()

    def lnks(c):
        for path in ctx.files("recent", "*.lnk"):
            try:
                info = lnk_parse(open(path, "rb").read(65536))
            except (ValueError, struct.error) as e:
                ctx.errors.append({"parser": "lnk", "file": ctx.rel(path), "error": str(e)})
                continue
            ctx.emit("os_recent_file", title=os.path.basename(path), value=info["target_path"],
                     times=[("lnk_file_mtime", ctx.mtime(path), "iso"), ("target_created", info["target_created"], "filetime"),
                            ("target_written", info["target_written"], "filetime"), ("target_accessed", info["target_accessed"], "filetime")],
                     details={"target_path": info["target_path"], "target_size": info["target_size"], "source": "Windows Recent LNK"},
                     src=path, loc="ShellLinkHeader")

    def prefetch(c):
        for path in ctx.files("prefetch", "*.pf"):
            mag = file_magic(path)
            ctx.emit("os_prefetch", title=os.path.basename(path), value=os.path.basename(path).split("-")[0],
                     times=[("pf_file_mtime", ctx.mtime(path), "iso")],
                     details={"format": mag, "note": "file mtime approximates last execution; MAM-compressed content not decoded"},
                     cls="inferred", src=path, loc="file")
        if ctx.files("prefetch", "*.pf"):
            ctx.limit("Windows Prefetch content (MAM/Xpress-Huffman) is not decompressed; only file timestamps are used (inferred execution).")
    run_parser(ctx, "recently-used.xbel", xbel)
    run_parser(ctx, "QuarantineEventsV2", quarantine)
    run_parser(ctx, "Recent LNK", lnks)
    run_parser(ctx, "Prefetch(inventory)", prefetch)


# ================================================================ driver
def run_parser(ctx, name, fn):
    before = ctx.n
    t0 = time.time()
    st = {"parser": name, "status": "ok", "records": 0}
    try:
        res = fn(ctx)
    except Exception as e:  # never abort the profile on one parser
        res = None
        st["status"] = "error"
        st["error"] = "%s: %s" % (type(e).__name__, e)
        ctx.errors.append({"parser": name, "file": None, "error": st["error"],
                           "trace": traceback.format_exc(limit=4)})
    st["records"] = ctx.n - before
    st["seconds"] = round(time.time() - t0, 3)
    if st["status"] == "ok" and st["records"] == 0:
        st["status"] = "no_data"
    ctx.parsers.append(st)
    return res


FAMILY_PARSERS = {"chromium": parse_chromium, "firefox": parse_firefox, "safari": parse_safari,
                  "epiphany": parse_epiphany, "qutebrowser": parse_qutebrowser, "ese": parse_ese, "os": parse_os}
KNOWN_DBS = {"History", "Cookies", "Web Data", "Login Data", "Login Data For Account", "Favicons", "Top Sites", "Shortcuts",
             "Network Action Predictor", "Media History", "places.sqlite", "cookies.sqlite", "formhistory.sqlite",
             "favicons.sqlite", "permissions.sqlite", "webappsstore.sqlite", "History.db", "CloudTabs.db", "Cache.db",
             "ephy-history.db", "history.sqlite", "data.sqlite"}


def cmd_analyze(a):
    case = a.case
    profs = {p["id"]: p for p in read_tsv(os.path.join(case, "profiles.tsv"), PROFILE_FIELDS)}
    if a.profile not in profs:
        print("unknown profile id %s" % a.profile, file=sys.stderr)
        return 2
    prof = profs[a.profile]
    sources = [s for s in read_tsv(os.path.join(case, "sources.tsv"), SOURCE_FIELDS) if s["id"] == a.profile]
    ctx = Ctx(case, prof, sources, a)
    t0 = time.time()
    fam = FAMILY_PARSERS.get(prof["family"])
    if fam:
        fam(ctx)
    else:
        ctx.limit("No parser for family '%s'; files were acquired and hashed only." % prof["family"])

    def sqlite_scan(c):
        files = collections.Counter()
        size = 0
        for path in ctx.walk():
            if path.endswith(("-wal", "-shm", "-journal")):
                continue
            try:
                size += os.path.getsize(path)
            except OSError:
                pass
            mg = file_magic(path)
            files[mg] += 1
            if mg == "sqlite":
                analyze_sqlite_file(ctx, path, recover=not a.no_recover)
        ctx.file_types = dict(files)
        ctx.total_bytes = size
    ctx.file_types, ctx.total_bytes = {}, 0
    run_parser(ctx, "sqlite_inventory+deleted_record_carving", sqlite_scan)
    # file timestamps vs record timestamps
    if ctx.max_ts:
        latest = None
        for p in ctx.walk():
            m = ctx.mtime(p)
            if m:
                try:
                    dt = parse_iso(m)
                    latest = dt if latest is None or dt > latest else latest
                except ValueError:
                    pass
        if latest and ctx.max_ts > latest + datetime.timedelta(days=1):
            ctx.finding("medium", "record_after_file_mtime",
                        "Newest record timestamp %s is >1 day after the newest evidence file mtime %s (clock skew, copied/restored profile or timestamp manipulation)"
                        % (iso(ctx.max_ts), iso(latest)))
    ctx.close()
    inv = {"profile": prof, "sources": sources, "parsers": ctx.parsers, "counts": dict(ctx.counts), "records": ctx.n,
           "errors": ctx.errors, "limitations": ctx.limitations, "sqlite": ctx.dbinfo, "file_types": ctx.file_types,
           "total_bytes": ctx.total_bytes, "history_urls": len(ctx.history_urls), "carve_rejected_as_noise": ctx.carve_rejected,
           "newest_record": iso(ctx.max_ts), "seconds": round(time.time() - t0, 2), "redacted": ctx.red.on,
           "engine_version": VERSION}
    with open(os.path.join(ctx.out, "inventory.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(inv, f, ensure_ascii=False, indent=1, default=str)
    with open(os.path.join(ctx.out, "findings.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(ctx.findings, f, ensure_ascii=False, indent=1, default=str)
    if not a.keep_work:
        shutil.rmtree(ctx.work, ignore_errors=True)
    errs = sum(1 for p in ctx.parsers if p["status"] == "error")
    print(json.dumps({"profile": a.profile, "records": ctx.n, "parser_errors": errs, "seconds": inv["seconds"]}))
    return 5 if errs else 0


# ================================================================ merge / correlation
def load_case(case):
    try:
        return safe_json_load(os.path.join(case, "case.json"))
    except (OSError, ValueError):
        return {}


def iter_records(case):
    base = os.path.join(case, "analysis")
    if not os.path.isdir(base):
        return
    for pid in sorted(os.listdir(base)):
        p = os.path.join(base, pid, "records.jsonl")
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip():
                        try:
                            yield json.loads(line)
                        except ValueError:
                            continue


def map_to_root(p, root, live):
    if not p or not root:
        return None
    p2 = p.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p2)
    if m:
        if live and os.name == "nt":
            return "%s:/%s" % (m.group(1), m.group(2))
        return os.path.join(root, m.group(2))
    if p2.startswith("file://"):
        p2 = urllib.parse.unquote(urllib.parse.urlsplit(p2).path)
        if re.match(r"^/[A-Za-z]:/", p2):
            return map_to_root(p2[1:], root, live)
    if p2.startswith("/"):
        return os.path.join(root, p2.lstrip("/"))
    return None


def file_observation(path, max_hash):
    st = os.stat(path)
    o = {"exists": True, "size": st.st_size, "mtime_utc": iso(conv_time(st.st_mtime, "unix_s"))}
    if st.st_size <= max_hash:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        o["sha256"] = h.hexdigest()
    if os.name == "nt":
        try:
            with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
                zi = f.read(4096)
            o["zone_identifier"] = {k.strip(): v.strip() for k, v in (l.split("=", 1) for l in zi.splitlines() if "=" in l)}
        except OSError:
            pass
    if hasattr(os, "getxattr"):
        for xa in ("user.xdg.origin.url", "user.xdg.referrer.url"):
            try:
                o.setdefault("xattrs", {})[xa] = os.getxattr(path, xa).decode("utf-8", "replace")
            except OSError:
                pass
    return o


def cmd_merge(a):
    case = a.case
    meta = load_case(case)
    acq = meta.get("acquired_utc") or meta.get("created_utc")
    try:
        acq_dt = parse_iso(acq) if acq else utcnow()
    except ValueError:
        acq_dt = utcnow()
    findings = []
    inventories = []
    for pid in sorted(os.listdir(os.path.join(case, "analysis"))) if os.path.isdir(os.path.join(case, "analysis")) else []:
        d = os.path.join(case, "analysis", pid)
        if not os.path.isdir(d):
            continue
        for name, target in (("findings.json", findings), ("inventory.json", inventories)):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                try:
                    v = safe_json_load(p)
                    target.extend(v) if isinstance(v, list) else target.append(v)
                except ValueError:
                    pass
    events = []
    downloads, recents, quarantine = [], [], []
    hist_by_prof = collections.defaultdict(set)
    cache_html = collections.defaultdict(dict)
    favicons = collections.defaultdict(dict)
    tabs = collections.defaultdict(dict)
    future = []
    counts = collections.Counter()
    by_class = collections.Counter()
    by_prof = collections.Counter()
    for r in iter_records(case):
        counts[r["artifact"]] += 1
        by_class[r["class"]] += 1
        by_prof[r["profile_id"]] += 1
        for label, t in (r.get("times") or {}).items():
            events.append({"ts": t, "event": "%s:%s" % (r["artifact"], label), "artifact": r["artifact"], "class": r["class"],
                           "profile_id": r["profile_id"], "browser": r["browser"], "profile": r["profile"], "user": r.get("user"),
                           "url": r.get("url"), "domain": r.get("domain"), "title": r.get("title"), "rid": r["rid"],
                           "src": (r.get("src") or {}).get("file")})
            if label not in ("expires", "icon_expires") and t > iso(acq_dt + datetime.timedelta(days=1)):
                future.append((r["rid"], label, t))
        a_ = r["artifact"]
        if a_ in ("history", "history_url"):
            hist_by_prof[r["profile_id"]].add(r.get("url"))
        elif a_ == "download":
            downloads.append(r)
        elif a_ == "os_recent_file":
            recents.append(r)
        elif a_ == "os_quarantine_event":
            quarantine.append(r)
        elif a_ == "cache" and "html" in str(r.get("title") or "").lower():
            cache_html[r["profile_id"]].setdefault(r.get("url"), r["rid"])
        elif a_ == "favicon":
            favicons[r["profile_id"]].setdefault(r.get("url"), r["rid"])
        elif a_ in ("session_tab", "closed_tab"):
            tabs[r["profile_id"]].setdefault(r.get("url"), r["rid"])
    events.sort(key=lambda e: (e["ts"], e["profile_id"], e["rid"]))
    with open(os.path.join(case, "analysis", "timeline.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    def fnd(sev, kind, msg, details=None, profile_id=None, cls="inferred"):
        findings.append({"profile_id": profile_id, "severity": sev, "kind": kind, "class": cls, "message": msg,
                         "details": details or {}})
    if future:
        fnd("medium", "future_timestamps", "%d timestamp(s) are more than 1 day after acquisition time (%s): clock skew or manipulation"
            % (len(future), iso(acq_dt)), {"examples": future[:20]})
    for pid, urls in cache_html.items():
        missing = [u for u in urls if u not in hist_by_prof.get(pid, set())]
        if missing and hist_by_prof.get(pid):
            fnd("low", "cache_without_history", "%d cached HTML document(s) have no matching history entry (history deleted, private/incognito "
                "spill-over, or non-navigation fetch)" % len(missing), {"examples": missing[:25]}, pid)
    for pid, urls in favicons.items():
        missing = [u for u in urls if u and u.startswith("http") and u not in hist_by_prof.get(pid, set())]
        if missing and hist_by_prof.get(pid):
            fnd("low", "favicon_without_history", "%d page(s) have favicons but no history entry (history deleted/expired)"
                % len(missing), {"examples": missing[:25]}, pid)
    for pid, urls in tabs.items():
        missing = [u for u in urls if u and u.startswith("http") and u not in hist_by_prof.get(pid, set())]
        if missing and hist_by_prof.get(pid):
            fnd("low", "tabs_without_history", "%d session/closed-tab URL(s) are absent from history" % len(missing),
                {"examples": missing[:25]}, pid)
    # downloads <-> OS artifacts <-> file system
    root = meta.get("root_native")
    live = bool(meta.get("live"))
    correlations = []
    rec_by_path = {}
    for r in recents:
        p = (r.get("details") or {}).get("target_path") or r.get("url") or ""
        p = urllib.parse.unquote(p[7:]) if p.startswith("file://") else p
        rec_by_path.setdefault(os.path.basename(p.replace("\\", "/")).lower(), []).append(r)
    q_by_url = collections.defaultdict(list)
    for r in quarantine:
        q_by_url[r.get("url")].append(r)
    for d in downloads:
        tp = (d.get("details") or {}).get("target_path") or d.get("value") or ""
        c = {"download_rid": d["rid"], "profile_id": d["profile_id"], "target_path": tp, "url": d.get("url"), "links": []}
        base = os.path.basename(tp.replace("\\", "/")).lower()
        for r in rec_by_path.get(base, []):
            c["links"].append({"type": r["details"].get("source"), "rid": r["rid"], "times": r.get("times")})
        for r in q_by_url.get(d.get("url"), []):
            c["links"].append({"type": "macOS quarantine event", "rid": r["rid"], "times": r.get("times")})
        if not a.no_fs_correlation and root and tp:
            mp = map_to_root(tp, root, live)
            try:
                if mp and os.path.isfile(mp):
                    c["file"] = file_observation(mp, a.max_hash_bytes)
                    c["file"]["path_checked"] = mp
                    tb = (d.get("details") or {}).get("total_bytes")
                    if tb and c["file"]["size"] != tb:
                        c["file"]["size_mismatch_with_browser"] = tb
                    bh = (d.get("details") or {}).get("sha256_reported_by_browser")
                    if bh and c["file"].get("sha256"):
                        c["file"]["browser_hash_match"] = bh.lower() == c["file"]["sha256"]
                elif mp:
                    c["file"] = {"exists": False, "path_checked": mp}
            except OSError as e:
                c["file"] = {"error": str(e)}
        if c["links"] or c.get("file"):
            correlations.append(c)
    for c in correlations:
        f = c.get("file") or {}
        if f.get("exists") and f.get("zone_identifier"):
            c["mark_of_the_web"] = True
        if f.get("exists") is False:
            fnd("info", "download_target_missing", "Downloaded file no longer present at recorded path: %s" % c["target_path"],
                {"download_rid": c["download_rid"]}, c["profile_id"])
        if f.get("size_mismatch_with_browser"):
            fnd("low", "download_size_mismatch", "File at %s differs in size from browser record" % c["target_path"],
                {"download_rid": c["download_rid"]}, c["profile_id"])
        if f.get("browser_hash_match") is False:
            fnd("medium", "download_hash_mismatch", "File at %s does not match the SHA-256 recorded by the browser (modified after download)"
                % c["target_path"], {"download_rid": c["download_rid"]}, c["profile_id"])
    if correlations:
        fnd("info", "download_correlations", "%d download(s) correlated with OS artifacts and/or the file system" % len(correlations),
            {"count": len(correlations)})
    with open(os.path.join(case, "analysis", "correlations.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(correlations, f, ensure_ascii=False, indent=1, default=str)
    sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: (sev_rank.get(x.get("severity"), 9), x.get("kind", "")))
    with open(os.path.join(case, "analysis", "findings.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(findings, f, ensure_ascii=False, indent=1, default=str)
    parser_errors = sum(1 for inv in inventories for p in inv.get("parsers", []) if p.get("status") == "error")
    summary = {"generated_utc": iso(utcnow()), "engine_version": VERSION, "profiles_analyzed": len(inventories),
               "records": sum(counts.values()), "timeline_events": len(events), "by_artifact": dict(counts.most_common()),
               "by_class": dict(by_class), "by_profile": dict(by_prof), "findings": len(findings),
               "correlations": len(correlations), "parser_errors": parser_errors,
               "time_range": [events[0]["ts"], events[-1]["ts"]] if events else None}
    with open(os.path.join(case, "analysis", "summary.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(json.dumps({"records": summary["records"], "events": len(events), "findings": len(findings)}))
    return 0


# ================================================================ filters
class Filters:
    def __init__(self, a):
        self.since = parse_iso(a.since) if getattr(a, "since", None) else None
        self.until = parse_iso(a.until) if getattr(a, "until", None) else None
        if self.until and re.fullmatch(r"\d{4}-\d{2}-\d{2}", a.until.strip()):
            self.until += datetime.timedelta(days=1) - datetime.timedelta(microseconds=1)
        self.domains = [d.strip().lower() for d in (getattr(a, "domain", None) or "").split(",") if d.strip()]
        self.types = {t.strip() for t in (getattr(a, "type", None) or "").split(",") if t.strip()}
        self.browsers = [b.strip().lower() for b in (getattr(a, "browser", None) or "").split(",") if b.strip()]
        self.profile = re.compile(a.profile_filter, re.I) if getattr(a, "profile_filter", None) else None
        self.classes = {c.strip() for c in (getattr(a, "evidence_class", None) or "").split(",") if c.strip()}
        self.s_since = iso(self.since) if self.since else None
        self.s_until = iso(self.until) if self.until else None

    def active(self):
        return any([self.since, self.until, self.domains, self.types, self.browsers, self.profile, self.classes])

    def describe(self):
        d = {}
        if self.s_since: d["since"] = self.s_since
        if self.s_until: d["until"] = self.s_until
        if self.domains: d["domain"] = self.domains
        if self.types: d["type"] = sorted(self.types)
        if self.browsers: d["browser"] = self.browsers
        if self.profile: d["profile"] = self.profile.pattern
        if self.classes: d["class"] = sorted(self.classes)
        return d

    def match_common(self, r):
        if self.types and r.get("artifact") not in self.types:
            return False
        if self.classes and r.get("class") not in self.classes:
            return False
        if self.browsers and not any(b in (r.get("browser") or "").lower() or b == (r.get("family") or "") for b in self.browsers):
            return False
        if self.profile and not (self.profile.search(r.get("profile_id") or "") or self.profile.search(r.get("profile") or "")
                                 or self.profile.search(r.get("user") or "")):
            return False
        if self.domains:
            dom = (r.get("domain") or "").lower()
            ok = False
            for d in self.domains:
                if d.startswith("~"):
                    ok = ok or d[1:] in (r.get("url") or "").lower() or d[1:] in dom
                else:
                    ok = ok or dom == d or dom.endswith("." + d)
            if not ok:
                return False
        return True

    def match_event(self, e):
        if self.s_since and e["ts"] < self.s_since:
            return False
        if self.s_until and e["ts"] > self.s_until:
            return False
        return self.match_common(e)

    def match_record(self, r):
        if not self.match_common(r):
            return False
        if self.s_since or self.s_until:
            ts = list((r.get("times") or {}).values())
            if not ts:
                return False
            return any((not self.s_since or t >= self.s_since) and (not self.s_until or t <= self.s_until) for t in ts)
        return True


def iter_timeline(case):
    p = os.path.join(case, "analysis", "timeline.jsonl")
    if not os.path.isfile(p):
        return
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def csv_safe(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False)
    s = str(v)
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    return s


TL_COLS = ["ts", "event", "artifact", "class", "browser", "profile", "user", "profile_id", "domain", "url", "title", "rid", "src"]


def cmd_stats(a):
    """key=value summary consumed by the CLI summary panel."""
    case = a.case
    s = {}
    try:
        s = safe_json_load(os.path.join(case, "analysis", "summary.json"))
    except (OSError, ValueError):
        pass
    try:
        f = safe_json_load(os.path.join(case, "analysis", "findings.json"))
    except (OSError, ValueError):
        f = []
    sev = collections.Counter(x.get("severity") for x in f)
    fam = collections.Counter(p["family"] for p in read_tsv(os.path.join(case, "profiles.tsv"), PROFILE_FIELDS))
    cls = s.get("by_class") or {}
    tr = s.get("time_range") or ["", ""]
    out = {"profiles_browser": sum(v for k, v in fam.items() if k != "os"), "profiles_os": fam.get("os", 0),
           "records": s.get("records", 0), "events": s.get("timeline_events", 0), "findings": len(f),
           "high": sev.get("high", 0), "medium": sev.get("medium", 0), "low": sev.get("low", 0), "info": sev.get("info", 0),
           "observed": cls.get("observed", 0), "recovered": cls.get("recovered", 0), "inferred": cls.get("inferred", 0),
           "time_from": (tr[0] or "").replace("T", " "), "time_to": (tr[1] or "").replace("T", " "),
           "parser_errors": s.get("parser_errors", 0)}
    for k, v in out.items():
        print("%s=%s" % (k, v))
    return 0


def cmd_timeline(a):
    flt = Filters(a)
    out = sys.stdout
    n = 0
    color = os.environ.get("BFX_COLOR") == "1"
    E = "\033["
    pal = {"observed": E + "38;5;79m", "recovered": E + "38;5;220m", "inferred": E + "38;5;141m"} if color else {}
    R0, DIM, PRI, BLD = (E + "0m", E + "2m", E + "38;5;45m", E + "1m") if color else ("", "", "", "")
    if a.format == "table":
        try:
            cols = max(80, min(220, int(os.environ.get("BFX_COLS", "120"))))
        except ValueError:
            cols = 120
        rest = max(20, cols - 4 - 19 - 2 - 26 - 1 - 9 - 1 - 16 - 1)
        out.write("%s  %-19s  %-26s %-9s %-16s %s%s\n" % (BLD + DIM, "UTC", "EVENT", "CLASS", "BROWSER", "URL  TITLE", R0))

        def cut(s, n):
            s = s or ""
            return s if len(s) <= n else s[:n - 1] + "\u2026"
    w = csv.writer(out, lineterminator="\n") if a.format == "csv" else None
    if w:
        w.writerow(TL_COLS)
    for e in iter_timeline(a.case):
        if not flt.match_event(e):
            continue
        n += 1
        if a.limit and n > a.limit:
            break
        if w:
            w.writerow([csv_safe(e.get(c)) for c in TL_COLS])
        elif a.format == "jsonl":
            out.write(json.dumps(e, ensure_ascii=False) + "\n")
        else:
            url = cut(e.get("url") or "", rest)
            title = cut(e.get("title") or "", max(0, rest - len(url) - 2)) if len(url) < rest - 6 else ""
            out.write("  %s%s%s  %s%-26s%s %s%-9s%s %-16s %s%s%s%s\n" % (
                DIM, e["ts"][:19].replace("T", " "), R0, PRI, cut(e["event"], 26), R0, pal.get(e["class"], ""), e["class"][:9], R0,
                cut(e["browser"] or "", 16), url, DIM, ("  " + title) if title else "", R0))
    return 0


# ================================================================ reports
def load_support_matrix(case):
    return read_tsv(os.path.join(case, "support_matrix.tsv"), ["family", "artifact", "level", "source", "notes"])


def h(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False, default=str)
    return html.escape(str(v), quote=True)


REPORT_CSS = """
:root{--bg:#f6f7f9;--fg:#1d2330;--muted:#5d6678;--card:#fff;--line:#d9dee7;--acc:#2456c9;--hi:#b42318;--me:#b54708;--lo:#3b7a57;--in:#475467;--code:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#11141a;--fg:#e6e9ef;--muted:#9aa4b5;--card:#191d25;--line:#2b313d;--acc:#7aa2ff;--hi:#ff7a6e;--me:#f5a35c;--lo:#6fcf97;--in:#a0aec0;--code:#222835}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:24px 28px;border-bottom:1px solid var(--line);background:var(--card)}h1{margin:0 0 4px;font-size:22px}h2{font-size:18px;margin:28px 0 10px}
.sub{color:var(--muted)}main{padding:8px 28px 60px;max-width:1500px;margin:0 auto}nav{position:sticky;top:0;background:var(--bg);padding:8px 0;border-bottom:1px solid var(--line);z-index:5;display:flex;flex-wrap:wrap;gap:12px}
nav a{color:var(--acc);text-decoration:none;font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.card b{display:block;font-size:22px}.card span{color:var(--muted);font-size:12px}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{position:sticky;top:0;background:var(--card);font-weight:600}
td.u{max-width:520px;word-break:break-all}td.m{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;word-break:break-all}
.sev{font-weight:700;text-transform:uppercase;font-size:11px}.high{color:var(--hi)}.medium{color:var(--me)}.low{color:var(--lo)}.info{color:var(--in)}
.pill{display:inline-block;padding:0 6px;border-radius:9px;font-size:11px;border:1px solid var(--line)}.observed{color:var(--lo)}.recovered{color:var(--me)}.inferred{color:var(--acc)}
input.f{width:100%;max-width:420px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);margin:6px 0}
.note{background:var(--code);border-radius:6px;padding:8px 12px;color:var(--muted);font-size:12.5px}details summary{cursor:pointer;color:var(--acc)}
.FULL{color:var(--lo)}.PARTIAL{color:var(--me)}.CARVE{color:var(--me)}.DETECT{color:var(--in)}.NONE{color:var(--hi)}
"""


def build_report(a):
    case = a.case
    flt = Filters(a)
    meta = load_case(case)
    summary = {}
    try:
        summary = safe_json_load(os.path.join(case, "analysis", "summary.json"))
    except (OSError, ValueError):
        pass
    inventories = []
    for pid in sorted(os.listdir(os.path.join(case, "analysis"))) if os.path.isdir(os.path.join(case, "analysis")) else []:
        p = os.path.join(case, "analysis", pid, "inventory.json")
        if os.path.isfile(p):
            inventories.append(safe_json_load(p))
    try:
        findings = safe_json_load(os.path.join(case, "analysis", "findings.json"))
    except (OSError, ValueError):
        findings = []
    try:
        correlations = safe_json_load(os.path.join(case, "analysis", "correlations.json"))
    except (OSError, ValueError):
        correlations = []
    manifest = read_jsonl(os.path.join(case, "evidence", "manifest.jsonl"))
    matrix = load_support_matrix(case)
    acq_errors = read_jsonl(os.path.join(case, "errors.jsonl"))
    profiles = read_tsv(os.path.join(case, "profiles.tsv"), PROFILE_FIELDS)
    events = [e for e in iter_timeline(case) if flt.match_event(e)]
    records = collections.defaultdict(list)
    for r in iter_records(case):
        if flt.match_record(r):
            records[r["artifact"]].append(r)
    if flt.profile or flt.browsers:
        keep = {r["profile_id"] for lst in records.values() for r in lst} | {e["profile_id"] for e in events}
        findings = [f for f in findings if f.get("profile_id") in keep or f.get("profile_id") is None]
    limitations = []
    for inv in inventories:
        for l in inv.get("limitations", []):
            if l not in limitations:
                limitations.append(l)
    for l in meta.get("limitations", []):
        if l not in limitations:
            limitations.append(l)
    parse_errors = [dict(e, profile_id=inv["profile"]["id"]) for inv in inventories for e in inv.get("errors", [])]
    acq_failed = [m for m in manifest if m.get("status") not in ("ok",)]
    partial = bool(parse_errors or acq_failed or acq_errors or any(p.get("status") == "error" for inv in inventories
                                                                    for p in inv.get("parsers", [])))
    os.makedirs(a.out, exist_ok=True)
    formats = {f.strip() for f in a.formats.split(",")}
    gen = iso(utcnow())
    by_cls = collections.Counter(r["class"] for lst in records.values() for r in lst)
    ctx = dict(case=case, meta=meta, summary=summary, inventories=inventories, findings=findings, correlations=correlations,
               manifest=manifest, matrix=matrix, acq_errors=acq_errors, profiles=profiles, events=events, records=records,
               limitations=limitations, parse_errors=parse_errors, acq_failed=acq_failed, partial=partial, generated=gen,
               filters=flt.describe(), by_cls=by_cls)
    written = []
    if "json" in formats:
        p = os.path.join(a.out, "report.json")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"tool": TOOL, "version": VERSION, "generated_utc": gen, "case": meta, "filters": ctx["filters"],
                       "partial_results": partial, "summary": summary,
                       "inventory": [{k: v for k, v in inv.items() if k != "sqlite"} for inv in inventories],
                       "sqlite_databases": [dict(d, profile_id=inv["profile"]["id"]) for inv in inventories for d in inv.get("sqlite", [])],
                       "findings": findings, "correlations": correlations, "timeline": events,
                       "artifacts": records, "evidence_manifest": manifest, "support_matrix": matrix,
                       "limitations": limitations, "errors": {"acquisition": acq_errors + acq_failed, "parsing": parse_errors}},
                      f, ensure_ascii=False, indent=1, default=str)
        written.append(p)
    if "csv" in formats:
        cd = os.path.join(a.out, "csv")
        os.makedirs(cd, exist_ok=True)

        def wcsv(name, cols, rows):
            p = os.path.join(cd, name)
            with open(p, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f, lineterminator="\r\n")
                w.writerow(cols)
                for r in rows:
                    w.writerow([csv_safe(r.get(c)) for c in cols])
            written.append(p)
        wcsv("timeline.csv", TL_COLS, events)
        rc = ["rid", "artifact", "class", "browser", "profile", "user", "profile_id", "ts", "times", "domain", "url", "title",
              "value", "details", "anomalies"]
        for art, lst in sorted(records.items()):
            wcsv("artifact_%s.csv" % re.sub(r"[^a-z0-9_]", "_", art), rc + ["src_file", "src_sha256", "src_loc"],
                 [dict(r, src_file=r["src"]["file"], src_sha256=r["src"]["sha256"], src_loc=r["src"]["loc"]) for r in lst])
        wcsv("findings.csv", ["severity", "kind", "class", "profile_id", "message", "src", "details"], findings)
        wcsv("evidence_manifest.csv", ["evidence_id", "profile_id", "role", "source", "copy", "size", "mtime_utc", "atime_utc",
                                       "ctime_utc", "sha256_source", "sha256_copy", "status", "error", "acquired_utc"], manifest)
        wcsv("inventory.csv", ["id", "family", "browser", "os", "user", "profile", "detection", "path", "records", "parser_errors"],
             [dict(inv["profile"], records=inv.get("records"),
                   parser_errors=sum(1 for p in inv.get("parsers", []) if p["status"] == "error")) for inv in inventories])
        wcsv("errors.csv", ["profile_id", "parser", "file", "error"], parse_errors + [
            {"profile_id": m.get("profile_id"), "parser": "acquisition", "file": m.get("source"), "error": m.get("status") + ": " + (m.get("error") or "")}
            for m in acq_failed])
        wcsv("support_matrix.csv", ["family", "artifact", "level", "source", "notes"], matrix)
    if "md" in formats:
        p = os.path.join(a.out, "report.md")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_md(ctx, a))
        written.append(p)
    if "html" in formats:
        p = os.path.join(a.out, "report.html")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_html(ctx, a))
        written.append(p)
    print(json.dumps({"written": [os.path.relpath(w, case).replace(os.sep, "/") for w in written], "partial": partial,
                      "events": len(events)}))
    return 0


def _exec_summary(ctx):
    s = ctx["summary"]
    inv = ctx["inventories"]
    browsers = sorted({i["profile"]["browser"] for i in inv if i["profile"]["family"] != "os"})
    lines = []
    lines.append("%d browser profile(s) across %d browser(s) were acquired and analyzed (%s)."
                 % (sum(1 for i in inv if i["profile"]["family"] != "os"), len(browsers), ", ".join(browsers) or "none"))
    tr = s.get("time_range")
    if tr:
        lines.append("Recorded activity spans %s to %s (UTC)." % (tr[0], tr[1]))
    lines.append("%d artifact record(s) and %d timeline event(s) in scope; classification: %s."
                 % (sum(len(v) for v in ctx["records"].values()), len(ctx["events"]),
                    ", ".join("%s=%d" % kv for kv in sorted(ctx["by_cls"].items())) or "n/a"))
    sev = collections.Counter(f.get("severity") for f in ctx["findings"])
    lines.append("%d finding(s): %s." % (len(ctx["findings"]), ", ".join("%s=%d" % (k, sev[k]) for k in ("high", "medium", "low", "info") if sev[k]) or "none"))
    ok = sum(1 for m in ctx["manifest"] if m.get("status") == "ok")
    lines.append("%d evidence file(s) acquired with SHA-256 verification; %d file(s) not acquired or altered during acquisition."
                 % (ok, len(ctx["acq_failed"])))
    if ctx["partial"]:
        lines.append("RESULTS ARE PARTIAL: see the Errors and Limitations sections.")
    if ctx["filters"]:
        lines.append("Filters applied: %s." % json.dumps(ctx["filters"]))
    return lines


def render_md(ctx, a):
    m = ctx["meta"]
    o = io.StringIO()
    o.write("# %s — Browser Forensics Report\n\n" % TOOL)
    o.write("| Field | Value |\n|---|---|\n")
    for k in ("case_id", "examiner", "created_utc", "acquired_utc", "root", "host", "tool_version", "redaction"):
        o.write("| %s | %s |\n" % (k, str(m.get(k, "")).replace("|", "\\|")))
    o.write("| generated_utc | %s |\n\n" % ctx["generated"])
    o.write("## Executive summary\n\n")
    for l in _exec_summary(ctx):
        o.write("- %s\n" % l)
    o.write("\n## Inventory\n\n| ID | Browser | OS | User | Profile | Records | Parser errors |\n|---|---|---|---|---|---|---|\n")
    for inv in ctx["inventories"]:
        p = inv["profile"]
        o.write("| %s | %s | %s | %s | %s | %s | %s |\n" % (p["id"], p["browser"], p["os"], p["user"], p["profile"], inv.get("records"),
                                                       sum(1 for x in inv.get("parsers", []) if x["status"] == "error")))
    o.write("\n## Artifacts (in scope)\n\n| Artifact | Records |\n|---|---|\n")
    for art, lst in sorted(ctx["records"].items(), key=lambda kv: -len(kv[1])):
        o.write("| %s | %d |\n" % (art, len(lst)))
    o.write("\n## Findings\n\n")
    for f in ctx["findings"]:
        o.write("- **[%s]** `%s` (%s) %s%s\n" % (f.get("severity", "").upper(), f.get("kind"), f.get("class"),
                                                 str(f.get("message")).replace("\n", " "),
                                                 (" — profile %s" % f["profile_id"]) if f.get("profile_id") else ""))
    o.write("\n## Timeline (first %d events)\n\n| UTC | Event | Class | Browser/Profile | URL | Title |\n|---|---|---|---|---|---|\n" % a.md_rows)
    for e in ctx["events"][:a.md_rows]:
        o.write("| %s | %s | %s | %s/%s | %s | %s |\n" % (e["ts"], e["event"], e["class"], e["browser"], e["profile"],
                                                       str(e.get("url") or "").replace("|", "%7C")[:160],
                                                       str(e.get("title") or "").replace("|", "\\|").replace("\n", " ")[:100]))
    if len(ctx["events"]) > a.md_rows:
        o.write("\n_%d more events in csv/timeline.csv and report.json._\n" % (len(ctx["events"]) - a.md_rows))
    o.write("\n## Integrity\n\nEvidence manifest: `evidence/manifest.jsonl` (%d entries). Hashes: SHA-256. "
            "Verify with `BrowserForensics-X.sh verify --case <dir>`.\n" % len(ctx["manifest"]))
    o.write("\n## Limitations\n\n")
    for l in ctx["limitations"]:
        o.write("- %s\n" % l)
    o.write("\n## Errors / partial results\n\n")
    if not (ctx["parse_errors"] or ctx["acq_failed"] or ctx["acq_errors"]):
        o.write("None recorded.\n")
    for e in ctx["parse_errors"]:
        o.write("- parse [%s] %s %s: %s\n" % (e.get("profile_id"), e.get("parser"), e.get("file") or "", e.get("error")))
    for e in ctx["acq_failed"]:
        o.write("- acquisition %s: %s %s\n" % (e.get("status"), e.get("source"), e.get("error") or ""))
    for e in ctx["acq_errors"]:
        o.write("- %s: %s\n" % (e.get("stage"), e.get("message")))
    o.write("\n## Support matrix\n\n| Family | Artifact | Level | Source | Notes |\n|---|---|---|---|---|\n")
    for r in ctx["matrix"]:
        o.write("| %s | %s | %s | %s | %s |\n" % (r["family"], r["artifact"], r["level"], r["source"], r["notes"]))
    return o.getvalue()


def _table(cols, rows, cls_map=None, tid=None, filt=False):
    o = io.StringIO()
    if filt and tid:
        o.write('<input class="f" type="search" placeholder="Filter rows…" data-target="%s">' % tid)
    o.write('<div class="tw"><table%s><thead><tr>%s</tr></thead><tbody>' % (' id="%s"' % tid if tid else "",
                                                                               "".join("<th>%s</th>" % h(c) for c in cols)))
    for r in rows:
        o.write("<tr>")
        for c in cols:
            v = r.get(c)
            cl = (cls_map or {}).get(c, "")
            if c in ("severity",):
                cl = "sev %s" % h(v)
            if c == "class" or c == "level":
                cl = h(v)
            o.write('<td class="%s">%s</td>' % (cl, h(v)))
        o.write("</tr>")
    o.write("</tbody></table></div>")
    return o.getvalue()


def render_html(ctx, a):
    nonce = hashlib.sha256(os.urandom(16)).hexdigest()[:24]
    m = ctx["meta"]
    s = ctx["summary"]
    o = io.StringIO()
    o.write('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    o.write('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; script-src \'nonce-%s\'; img-src \'none\'; connect-src \'none\'; form-action \'none\'; base-uri \'none\'">' % nonce)
    o.write('<meta name="referrer" content="no-referrer"><title>%s Report</title><style>%s</style></head><body>' % (h(TOOL), REPORT_CSS))
    o.write("<header><h1>%s — Browser Forensics Report</h1><div class='sub'>Case <b>%s</b> · examiner %s · generated %s · tool %s</div></header><main>"
            % (h(TOOL), h(m.get("case_id")), h(m.get("examiner")), h(ctx["generated"]), h(m.get("tool_version") or VERSION)))
    o.write("<nav>%s</nav>" % "".join('<a href="#%s">%s</a>' % (k, v) for k, v in (
        ("sum", "Summary"), ("case", "Case"), ("inv", "Inventory"), ("find", "Findings"), ("tl", "Timeline"), ("art", "Artifacts"),
        ("corr", "Correlations"), ("db", "SQLite"), ("hash", "Evidence & hashes"), ("lim", "Limitations"), ("err", "Errors"),
        ("mx", "Support matrix"))))
    o.write('<h2 id="sum">Executive summary</h2>')
    if ctx["partial"]:
        o.write('<p class="note"><b class="sev high">Partial results</b> — some evidence could not be acquired or parsed; see Errors.</p>')
    o.write("<ul>%s</ul>" % "".join("<li>%s</li>" % h(l) for l in _exec_summary(ctx)))
    cards = [("Profiles", len(ctx["inventories"])), ("Records", sum(len(v) for v in ctx["records"].values())),
             ("Timeline events", len(ctx["events"])), ("Observed", ctx["by_cls"].get("observed", 0)),
             ("Recovered", ctx["by_cls"].get("recovered", 0)), ("Inferred", ctx["by_cls"].get("inferred", 0)),
             ("Findings", len(ctx["findings"])), ("Evidence files", len(ctx["manifest"])),
             ("Acquisition issues", len(ctx["acq_failed"])), ("Parser errors", len(ctx["parse_errors"]))]
    o.write('<div class="cards">%s</div>' % "".join('<div class="card"><b>%s</b><span>%s</span></div>' % (h(v), h(k)) for k, v in cards))
    o.write('<h2 id="case">Case information</h2>')
    o.write(_table(["field", "value"], [{"field": k, "value": v} for k, v in m.items() if k not in ("limitations",)]
                   + [{"field": "filters", "value": ctx["filters"] or "none"}], {"value": "m"}))
    o.write('<h2 id="inv">Inventory by browser / profile</h2>')
    rows = []
    for inv in ctx["inventories"]:
        p = inv["profile"]
        rows.append({"id": p["id"], "browser": p["browser"], "family": p["family"], "os": p["os"], "user": p["user"],
                     "profile": p["profile"], "detection": p["detection"], "source path": p["path"], "records": inv.get("records"),
                     "artifacts": ", ".join("%s:%d" % kv for kv in sorted(inv.get("counts", {}).items())),
                     "parsers ok/no-data/error": "%d/%d/%d" % tuple(sum(1 for x in inv.get("parsers", []) if x["status"] == st)
                                                                   for st in ("ok", "no_data", "error"))})
    o.write(_table(list(rows[0].keys()) if rows else ["id"], rows, {"source path": "m"}, "t_inv", True))
    o.write('<h2 id="find">Findings & inconsistencies</h2>')
    o.write(_table(["severity", "kind", "class", "profile_id", "message", "src"], ctx["findings"], {"src": "m"}, "t_find", True))
    lim = a.html_rows
    o.write('<h2 id="tl">Unified timeline (UTC)</h2>')
    if len(ctx["events"]) > lim:
        o.write('<p class="note">Showing first %d of %d events. Full timeline: csv/timeline.csv, report.json.</p>' % (lim, len(ctx["events"])))
    o.write(_table(["ts", "event", "class", "browser", "profile", "url", "title", "rid"], ctx["events"][:lim], {"url": "u", "rid": "m"}, "t_tl", True))
    o.write('<h2 id="art">Artifacts</h2>')
    for art, lst in sorted(ctx["records"].items(), key=lambda kv: -len(kv[1])):
        o.write("<details><summary>%s — %d record(s)</summary>" % (h(art), len(lst)))
        rows = [{"ts": r.get("ts"), "class": r["class"], "browser": r["browser"], "profile": r["profile"], "url": r.get("url"),
                 "title": r.get("title"), "value": r.get("value"), "details": r.get("details"),
                 "source": "%s [%s]" % (r["src"]["file"], r["src"]["loc"]), "sha256": (r["src"]["sha256"] or "")[:16]} for r in lst[:lim]]
        if len(lst) > lim:
            o.write('<p class="note">First %d shown; full data in csv/artifact_%s.csv.</p>' % (lim, h(art)))
        o.write(_table(["ts", "class", "browser", "profile", "url", "title", "value", "details", "source", "sha256"], rows,
                       {"url": "u", "details": "m", "source": "m", "sha256": "m", "value": "m"}, "t_a_" + re.sub(r"\W", "_", art), True))
        o.write("</details>")
    o.write('<h2 id="corr">Correlations (downloads ↔ OS ↔ file system)</h2>')
    o.write(_table(["profile_id", "download_rid", "target_path", "url", "links", "file"], ctx["correlations"],
                   {"links": "m", "file": "m", "target_path": "m"}))
    o.write('<h2 id="db">SQLite databases</h2>')
    dbrows = []
    for inv in ctx["inventories"]:
        for d in inv.get("sqlite", []):
            hd = d.get("header") or {}
            dbrows.append({"profile": inv["profile"]["id"], "file": d["file"], "integrity": d.get("integrity"),
                           "pages": hd.get("db_size_pages"), "freelist pages": hd.get("freelist_pages"),
                           "WAL": d.get("wal"), "recovered URLs": d.get("recovered_urls"),
                           "tables": ", ".join("%s(%s)" % kv for kv in sorted((d.get("tables") or {}).items()))})
    o.write(_table(["profile", "file", "integrity", "pages", "freelist pages", "WAL", "recovered URLs", "tables"], dbrows,
                   {"file": "m", "WAL": "m", "tables": "m"}, "t_db", True))
    o.write('<h2 id="hash">Evidence manifest & hashes (SHA-256)</h2>')
    o.write('<p class="note">Manifest: evidence/manifest.jsonl · Checksums: evidence/SHA256SUMS · Manifest hash: %s</p>' % h(m.get("manifest_sha256", "see evidence/manifest.sha256")))
    o.write(_table(["evidence_id", "profile_id", "role", "copy", "size", "mtime_utc", "sha256_copy", "status"],
                   ctx["manifest"][:max(lim, 5000)], {"copy": "m", "sha256_copy": "m"}, "t_hash", True))
    o.write('<h2 id="lim">Limitations</h2><ul>%s</ul>' % "".join("<li>%s</li>" % h(l) for l in ctx["limitations"]))
    o.write('<h2 id="err">Errors & partial results</h2>')
    errs = [{"stage": "parse", "profile_id": e.get("profile_id"), "item": "%s %s" % (e.get("parser"), e.get("file") or ""),
             "error": e.get("error")} for e in ctx["parse_errors"]]
    errs += [{"stage": "acquisition", "profile_id": e.get("profile_id"), "item": e.get("source"),
              "error": "%s %s" % (e.get("status"), e.get("error") or "")} for e in ctx["acq_failed"]]
    errs += [{"stage": e.get("stage"), "profile_id": e.get("profile_id"), "item": e.get("item"), "error": e.get("message")}
             for e in ctx["acq_errors"]]
    o.write(_table(["stage", "profile_id", "item", "error"], errs, {"item": "m"}, "t_err", True) if errs else "<p>None recorded.</p>")
    o.write('<h2 id="mx">Support matrix</h2>')
    o.write(_table(["family", "artifact", "level", "source", "notes"], ctx["matrix"], None, "t_mx", True))
    o.write("<p class='sub'>Values marked [REDACTED …] are replaced by length + keyed HMAC (key kept in the case directory). "
            "URLs are displayed as text and are never fetched.</p>")
    o.write("""</main><script nonce="%s">
document.querySelectorAll('input.f').forEach(function(i){i.addEventListener('input',function(){var q=i.value.toLowerCase();
var t=document.getElementById(i.getAttribute('data-target'));if(!t)return;t.querySelectorAll('tbody tr').forEach(function(r){
r.style.display=(!q||r.textContent.toLowerCase().indexOf(q)>=0)?'':'none';});});});
</script></body></html>""" % nonce)
    return o.getvalue()


# ================================================================ laboratory artifact generator (self-test)
def _wk(s):
    return int((parse_iso(s) - E1601).total_seconds() * 1_000_000)


def _us(s):
    return int((parse_iso(s) - E1970).total_seconds() * 1_000_000)


def _ms(s):
    return int((parse_iso(s) - E1970).total_seconds() * 1000)


def _mac(s):
    return (parse_iso(s) - E2001).total_seconds()


def enc_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def snappy_compress_literal(raw):
    out = bytearray(enc_varint(len(raw)))
    i = 0
    while i < len(raw):
        chunk = raw[i:i + 65536]
        n = len(chunk) - 1
        if n < 60:
            out.append(n << 2)
        elif n < 256:
            out += bytes([60 << 2, n])
        else:
            out += bytes([61 << 2]) + struct.pack("<H", n)
        out += chunk
        i += len(chunk)
    return bytes(out)


def lz4_literal(raw):
    n = len(raw)
    if n < 15:
        return bytes([n << 4]) + raw
    out = bytearray([0xF0])
    r = n - 15
    while r >= 255:
        out.append(255)
        r -= 255
    out.append(r)
    return bytes(out) + raw


def mozlz4_encode(raw):
    return b"mozLz40\0" + struct.pack("<I", len(raw)) + lz4_literal(raw)


def ldb_log(batches):
    out = bytearray()
    for seq, ops in batches:
        rec = bytearray(struct.pack("<QI", seq, len(ops)))
        for t, k, v in ops:
            rec += bytes([t]) + enc_varint(len(k)) + k
            if t == 1:
                rec += enc_varint(len(v)) + v
        left = 32768 - (len(out) % 32768)
        if left < 7 + len(rec):
            raise ValueError("lab log too large for single block")
        out += struct.pack("<IHB", crc_mask(crc32c(bytes([1]) + bytes(rec))), len(rec), 1) + rec
    return bytes(out)


def ldb_table(entries):
    def block(kvs):
        b = bytearray()
        for k, v in kvs:
            b += enc_varint(0) + enc_varint(len(k)) + enc_varint(len(v)) + k + v
        return bytes(b) + struct.pack("<II", 0, 1)
    kvs = [(uk + struct.pack("<Q", (seq << 8) | t), v) for uk, seq, t, v in sorted(entries)]
    comp = snappy_compress_literal(block(kvs))
    out = bytearray(comp + b"\x01" + b"\0" * 4)
    meta = block([])
    mo = len(out)
    out += meta + b"\x00" + b"\0" * 4
    idx = block([(kvs[-1][0], enc_varint(0) + enc_varint(len(comp)))])
    io_ = len(out)
    out += idx + b"\x00" + b"\0" * 4
    footer = enc_varint(mo) + enc_varint(len(meta)) + enc_varint(io_) + enc_varint(len(idx))
    out += footer + b"\0" * (40 - len(footer)) + struct.pack("<Q", 0xDB4775248B80FB57)
    return bytes(out)


def _pk_str(b):
    return struct.pack("<i", len(b)) + b + b"\0" * ((4 - len(b) % 4) % 4)


def _pk_str16(s):
    e = s.encode("utf-16-le")
    return struct.pack("<i", len(s)) + e + b"\0" * ((4 - len(e) % 4) % 4)


def snss_nav_cmd(cid, tab, idx, url, title, ts):
    f = struct.pack("<ii", tab, idx) + _pk_str(url.encode()) + _pk_str16(title) + _pk_str(b"") + struct.pack("<ii", 1, 0) + \
        _pk_str(b"") + struct.pack("<i", 0) + _pk_str(b"") + struct.pack("<i", 0) + struct.pack("<q", ts) + _pk_str16("") + \
        struct.pack("<i", 200)
    pk = struct.pack("<I", len(f)) + f
    return struct.pack("<H", len(pk) + 1) + bytes([cid]) + pk


def _mk(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def _db(path, script, rows=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(script)
    for sql, vals in rows or []:
        con.executemany(sql, vals)
    con.commit()
    con.close()


CHROME_HISTORY_SCHEMA = """
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,
 typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,transition INTEGER DEFAULT 0 NOT NULL,
 segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,opener_visit INTEGER,
 originator_cache_guid TEXT,originator_visit_id INTEGER,originator_from_visit INTEGER,originator_opener_visit INTEGER,is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,
 consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL,external_referrer_url TEXT,visited_link_id INTEGER DEFAULT 0 NOT NULL,app_id TEXT);
CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL,url_id INTEGER NOT NULL,term LONGVARCHAR NOT NULL,normalized_term LONGVARCHAR NOT NULL);
CREATE TABLE downloads(id INTEGER PRIMARY KEY,guid VARCHAR NOT NULL,current_path LONGVARCHAR NOT NULL,target_path LONGVARCHAR NOT NULL,
 start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,danger_type INTEGER NOT NULL,
 interrupt_reason INTEGER NOT NULL,hash BLOB NOT NULL,end_time INTEGER NOT NULL,opened INTEGER NOT NULL,last_access_time INTEGER NOT NULL,
 transient INTEGER NOT NULL,referrer VARCHAR NOT NULL,site_url VARCHAR NOT NULL,embedder_download_data VARCHAR NOT NULL,tab_url VARCHAR NOT NULL,
 tab_referrer_url VARCHAR NOT NULL,http_method VARCHAR NOT NULL,by_ext_id VARCHAR NOT NULL,by_ext_name VARCHAR NOT NULL,by_web_app_id VARCHAR NOT NULL,
 etag VARCHAR NOT NULL,last_modified VARCHAR NOT NULL,mime_type VARCHAR(255) NOT NULL,original_mime_type VARCHAR(255) NOT NULL);
CREATE TABLE downloads_url_chains(id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL,PRIMARY KEY(id,chain_index));
"""


def _chrome_download(i, target, url, start, end, size, digest=b"", danger=0):
    return (i, "guid-%d" % i, target, target, _wk(start), size, size, 1, danger, 0, digest, _wk(end), 0, _wk(end), 0,
            "https://www.example.com/", "https://www.example.com/", "", "https://www.example.com/downloads", "", "GET", "", "", "",
            "", "", "application/octet-stream", "application/octet-stream")


DL_SQL = "INSERT INTO downloads VALUES(%s)" % ",".join("?" * 28)


def lab_chrome_profile(udd, prof, variant, extra_cache=None):
    P = os.path.join(udd, prof)
    os.makedirs(P, exist_ok=True)
    hist = os.path.join(P, "History")
    if variant == "full":
        report = b"%PDF-1.4 lab report\n" * 20
        tmp = hist + ".tmp"
        con = sqlite3.connect(tmp)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.executescript(CHROME_HISTORY_SCHEMA)
        urls = [(1, "https://www.example.com/", "Example Domain", 2, 1, _wk("2024-03-15T10:30:00Z"), 0),
                (2, "https://www.google.com/search?q=forensic+tools", "forensic tools - Google Search", 1, 0, _wk("2024-03-15T10:31:00Z"), 0),
                (3, "https://login.example/cb?token=TOKENSECRET123&lang=en", "Login callback", 1, 0, _wk("2024-03-15T10:32:00Z"), 0),
                (4, "https://xss.example/", "<script>alert('xss')</script><img src=x onerror=alert(1)>", 1, 0, _wk("2024-03-15T10:33:00Z"), 0),
                (5, "https://deleted-evidence.example/secret-page", "Secret Page Title", 1, 0, _wk("2024-03-15T09:00:00Z"), 0),
                (6, "https://files.example/report.pdf", "", 1, 0, _wk("2024-03-15T10:34:00Z"), 0),
                (7, "https://expired.example/", "Expired visit", 3, 0, _wk("2024-01-01T00:00:00Z"), 0)]
        con.executemany("INSERT INTO urls VALUES(?,?,?,?,?,?,?)", urls)
        vis = [(1, 1, _wk("2024-03-15T10:30:00Z"), 0, 0x30000001), (2, 1, _wk("2024-03-15T10:30:30Z"), 0, 0x30000000),
               (3, 2, _wk("2024-03-15T10:31:00Z"), 1, 0x30000005), (4, 3, _wk("2024-03-15T10:32:00Z"), 0, 0x30000000),
               (5, 4, _wk("2024-03-15T10:33:00Z"), 0, 0x30000000), (6, 5, _wk("2024-03-15T09:00:00Z"), 0, 0x30000001),
               (9, 6, _wk("2024-03-15T10:34:00Z"), 0, 0x30000000)]
        con.executemany("INSERT INTO visits(id,url,visit_time,from_visit,transition,visit_duration) VALUES(?,?,?,?,?,1500000)", vis)
        con.execute("INSERT INTO keyword_search_terms VALUES(2,2,'forensic tools','forensic tools')")
        con.execute(DL_SQL, _chrome_download(1, "/home/alice/Downloads/report.pdf", "https://files.example/report.pdf",
                                             "2024-03-15T10:34:00Z", "2024-03-15T10:34:05Z", len(report),
                                             hashlib.sha256(report).digest()))
        con.execute("INSERT INTO downloads_url_chains VALUES(1,0,'https://files.example/report.pdf')")
        con.commit()
        con.execute("DELETE FROM visits WHERE url=5")
        con.execute("DELETE FROM urls WHERE id=5")
        con.commit()
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        con.execute("INSERT INTO urls VALUES(8,'https://wal-only.example/old','WAL old',1,0,%d,0)" % _wk("2024-03-15T11:00:00Z"))
        con.commit()
        con.execute("DELETE FROM urls WHERE id=8")
        con.execute("INSERT INTO urls VALUES(9,'https://wal-new.example/','WAL new',1,0,%d,0)" % _wk("2024-03-15T11:05:00Z"))
        con.commit()
        shutil.copyfile(tmp, hist)
        shutil.copyfile(tmp + "-wal", hist + "-wal")
        con.close()
        for s in ("", "-wal", "-shm"):
            if os.path.exists(tmp + s):
                os.remove(tmp + s)
        return report
    if variant == "edge":
        _db(hist, CHROME_HISTORY_SCHEMA, [
            ("INSERT INTO urls VALUES(?,?,?,?,?,?,?)", [(1, "https://www.microsoft.com/", "Microsoft", 1, 1, _wk("2024-04-01T09:00:00Z"), 0),
                                                         (2, "https://download.example/setup.exe", "", 1, 0, _wk("2024-04-01T09:05:00Z"), 0)]),
            ("INSERT INTO visits(id,url,visit_time,from_visit,transition) VALUES(?,?,?,?,?)",
             [(1, 1, _wk("2024-04-01T09:00:00Z"), 0, 1), (2, 2, _wk("2024-04-01T09:05:00Z"), 1, 0), (3, 999, _wk("2024-04-01T09:06:00Z"), 0, 0)]),
            (DL_SQL, [_chrome_download(1, "C:\\Users\\bob\\Downloads\\setup.exe", "https://download.example/setup.exe",
                                       "2024-04-01T09:05:00Z", "2024-04-01T09:05:10Z", 4096, danger=3)]),
            ("INSERT INTO downloads_url_chains VALUES(?,?,?)", [(1, 0, "https://download.example/setup.exe")])])
        return None
    if variant == "opera":
        _db(hist, CHROME_HISTORY_SCHEMA, [
            ("INSERT INTO urls VALUES(?,?,?,?,?,?,?)", [(1, "https://www.opera.com/", "Opera", 1, 1, _wk("2024-04-02T09:00:00Z"), 0)]),
            ("INSERT INTO visits(id,url,visit_time,from_visit,transition) VALUES(?,?,?,?,?)", [(1, 1, _wk("2024-04-02T09:00:00Z"), 0, 1)])])
        return None
    if variant == "mac":
        _db(hist, CHROME_HISTORY_SCHEMA, [
            ("INSERT INTO urls VALUES(?,?,?,?,?,?,?)", [(1, "https://www.apple.com/", "Apple", 1, 1, _wk("2024-05-01T09:00:00Z"), 0)]),
            ("INSERT INTO visits(id,url,visit_time,from_visit,transition) VALUES(?,?,?,?,?)", [(1, 1, _wk("2024-05-01T09:00:00Z"), 0, 1)])])
        return None


def lab_chrome_extras(udd, P, extra_cache=None):
    _mk(os.path.join(udd, "Local State"), json.dumps({
        "profile": {"info_cache": {"Default": {"name": "Alice", "user_name": "alice@example.org", "active_time": 1710500000.5,
                                               "gaia_name": "Alice Lab"}}},
        "os_crypt": {"encrypted_key": "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAA="}}))
    ext = "abcdefghijklmnopabcdefghijklmnop"
    _mk(os.path.join(P, "Preferences"), json.dumps({
        "profile": {"name": "Person 1", "exit_type": "Crashed", "creation_time": str(_wk("2024-01-10T08:00:00Z")),
                    "content_settings": {"exceptions": {"notifications": {"https://push.example:443,*": {
                        "last_modified": str(_wk("2024-03-15T10:40:00Z")), "setting": 1}}}}},
        "download": {"default_directory": "/home/alice/Downloads"},
        "browser": {"last_clear_browsing_data_time": str(_wk("2024-03-20T18:00:00Z"))},
        "account_info": [{"email": "alice@example.org", "full_name": "Alice Lab", "gaia": "1234567890"}],
        "extensions": {"settings": {ext: {"install_time": str(_wk("2024-02-01T12:00:00Z")), "location": 4, "state": 1,
                                          "from_webstore": False}}}}))
    _mk(os.path.join(P, "Secure Preferences"), json.dumps({"extensions": {"settings": {}}}))
    xd = os.path.join(P, "Extensions", ext, "1.0_0")
    _mk(os.path.join(xd, "manifest.json"), json.dumps({"name": "__MSG_appName__", "version": "1.0", "manifest_version": 3,
                                                       "default_locale": "en", "permissions": ["cookies", "history", "tabs"],
                                                       "host_permissions": ["<all_urls>"], "update_url": "https://evil.example/update.xml"}))
    _mk(os.path.join(xd, "_locales", "en", "messages.json"), json.dumps({"appName": {"message": "Lab Helper"}}))
    _mk(os.path.join(xd, "background.js"), "/* lab: must never be executed */ console.log('x');")
    bm = {"roots": {"bookmark_bar": {"type": "folder", "name": "Bookmarks bar", "children": [
        {"type": "url", "name": "Example", "url": "https://www.example.com/", "date_added": str(_wk("2024-03-01T10:00:00Z")), "guid": "g1"},
        {"type": "folder", "name": "Work", "children": [
            {"type": "url", "name": "Intranet", "url": "https://intranet.example/", "date_added": str(_wk("2024-03-02T10:00:00Z")), "guid": "g2"}]}]},
        "other": {"type": "folder", "name": "Other", "children": []}}}
    _mk(os.path.join(P, "Bookmarks"), json.dumps(bm))
    bm["roots"]["other"]["children"].append({"type": "url", "name": "Removed bookmark", "url": "https://removed-bookmark.example/",
                                             "date_added": str(_wk("2024-02-20T10:00:00Z")), "guid": "g3"})
    _mk(os.path.join(P, "Bookmarks.bak"), json.dumps(bm))
    _db(os.path.join(P, "Network", "Cookies"), """CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,
        name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,
        is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,
        samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL);""",
        [("INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          [(_wk("2024-03-15T10:30:01Z"), ".example.com", "", "sid", "", b"v10" + b"\x11" * 40, "/", _wk("2025-03-15T10:30:01Z"), 1, 1,
            _wk("2024-03-15T10:35:00Z"), 1, 1, 1, 0, 2, 443, _wk("2024-03-15T10:30:01Z")),
           (_wk("2024-03-15T10:31:00Z"), "www.google.com", "", "pref", "PLAINCOOKIEVALUE", b"", "/", _wk("2025-03-15T10:30:01Z"), 0, 0,
            _wk("2024-03-15T10:31:00Z"), 1, 1, 1, 0, 2, 443, _wk("2024-03-15T10:31:00Z"))])])
    _db(os.path.join(P, "Login Data"), """CREATE TABLE logins(origin_url VARCHAR NOT NULL,action_url VARCHAR,username_element VARCHAR,username_value VARCHAR,
        password_element VARCHAR,password_value BLOB,submit_element VARCHAR,signon_realm VARCHAR NOT NULL,date_created INTEGER NOT NULL,
        blacklisted_by_user INTEGER NOT NULL,scheme INTEGER NOT NULL,password_type INTEGER,times_used INTEGER,form_data BLOB,display_name VARCHAR,
        icon_url VARCHAR,federation_url VARCHAR,skip_zero_click INTEGER,generation_upload_status INTEGER,possible_username_pairs BLOB,
        id INTEGER PRIMARY KEY AUTOINCREMENT,date_last_used INTEGER NOT NULL DEFAULT 0,moving_blocked_for BLOB,date_password_modified INTEGER NOT NULL DEFAULT 0);""",
        [("INSERT INTO logins(origin_url,action_url,username_element,username_value,password_element,password_value,signon_realm,date_created,"
          "blacklisted_by_user,scheme,times_used,date_last_used,date_password_modified) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
          [("https://login.example/", "https://login.example/post", "user", "alice.login@example.org", "pass", b"v10" + b"\x22" * 32,
            "https://login.example/", _wk("2024-03-10T10:00:00Z"), 0, 0, 3, _wk("2024-03-15T10:32:00Z"), _wk("2024-03-10T10:00:00Z"))])])
    _db(os.path.join(P, "Web Data"), """CREATE TABLE autofill(name VARCHAR,value VARCHAR,value_lower VARCHAR,date_created INTEGER DEFAULT 0,
        date_last_used INTEGER DEFAULT 0,count INTEGER DEFAULT 1,PRIMARY KEY(name,value));
        CREATE TABLE keywords(id INTEGER PRIMARY KEY,short_name VARCHAR NOT NULL,keyword VARCHAR NOT NULL,favicon_url VARCHAR NOT NULL,url VARCHAR NOT NULL,
        safe_for_autoreplace INTEGER,originating_url VARCHAR,date_created INTEGER DEFAULT 0,usage_count INTEGER DEFAULT 0,input_encodings VARCHAR,
        suggest_url VARCHAR,prepopulate_id INTEGER DEFAULT 0,created_by_policy INTEGER DEFAULT 0,last_modified INTEGER DEFAULT 0,sync_guid VARCHAR,
        alternate_urls VARCHAR,image_url VARCHAR,search_url_post_params VARCHAR,suggest_url_post_params VARCHAR,image_url_post_params VARCHAR,
        new_tab_url VARCHAR,last_visited INTEGER DEFAULT 0);""",
        [("INSERT INTO autofill VALUES(?,?,?,?,?,?)", [("email", "alice.form@example.org", "alice.form@example.org", 1710496800, 1710500000, 4)]),
         ("INSERT INTO keywords(id,short_name,keyword,favicon_url,url,date_created) VALUES(?,?,?,?,?,?)",
          [(2, "Google", "google.com", "", "{google:baseURL}search?q={searchTerms}", _wk("2024-01-10T08:00:00Z"))])])
    _db(os.path.join(P, "Favicons"), """CREATE TABLE favicons(id INTEGER PRIMARY KEY,url LONGVARCHAR NOT NULL,icon_type INTEGER DEFAULT 1);
        CREATE TABLE icon_mapping(id INTEGER PRIMARY KEY,page_url LONGVARCHAR NOT NULL,icon_id INTEGER,page_url_type INTEGER DEFAULT 0);
        CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY,icon_id INTEGER NOT NULL,last_updated INTEGER DEFAULT 0,image_data BLOB,width INTEGER DEFAULT 0,
        height INTEGER DEFAULT 0,last_requested INTEGER DEFAULT 0);""",
        [("INSERT INTO favicons VALUES(?,?,?)", [(1, "https://hidden-site.example/favicon.ico", 1)]),
         ("INSERT INTO icon_mapping VALUES(?,?,?,?)", [(1, "https://hidden-site.example/", 1, 0)]),
         ("INSERT INTO favicon_bitmaps VALUES(?,?,?,?,?,?,?)", [(1, 1, _wk("2024-03-14T22:00:00Z"), b"\x89PNG", 16, 16, 0)])])
    _db(os.path.join(P, "Top Sites"), "CREATE TABLE top_sites(url LONGVARCHAR NOT NULL,url_rank INTEGER NOT NULL,title LONGVARCHAR NOT NULL);",
        [("INSERT INTO top_sites VALUES(?,?,?)", [("https://www.example.com/", 0, "Example Domain")])])
    _db(os.path.join(P, "Shortcuts"), """CREATE TABLE omni_box_shortcuts(id VARCHAR PRIMARY KEY,text VARCHAR,fill_into_edit VARCHAR,url VARCHAR,
        document_type INTEGER,contents VARCHAR,contents_class VARCHAR,description VARCHAR,description_class VARCHAR,transition INTEGER,type INTEGER,
        keyword VARCHAR,last_access_time INTEGER,number_of_hits INTEGER);""",
        [("INSERT INTO omni_box_shortcuts(id,text,url,contents,last_access_time,number_of_hits) VALUES(?,?,?,?,?,?)",
          [("s1", "exam", "https://www.example.com/", "Example Domain", _wk("2024-03-15T10:30:00Z"), 2)])])
    sess = b"SNSS" + struct.pack("<i", 3) + snss_nav_cmd(6, 7, 0, "https://news.example/article", "News Article", _wk("2024-03-15T10:36:00Z")) + \
        snss_nav_cmd(0, 7, 0, "https://not-a-nav.example/", "x", 0)
    _mk(os.path.join(P, "Sessions", "Session_%d" % _wk("2024-03-15T10:29:00Z")), sess)
    _mk(os.path.join(P, "Sessions", "Tabs_%d" % _wk("2024-03-15T10:29:00Z")),
        b"SNSS" + struct.pack("<i", 3) + snss_nav_cmd(1, 3, 0, "https://closed-tab.example/", "Closed Tab", _wk("2024-03-15T10:37:00Z")))
    o = b"https://app.example"
    _mk(os.path.join(P, "Local Storage", "leveldb", "000003.log"), ldb_log([
        (1, [(1, b"VERSION", b"1")]),
        (2, [(1, b"META:" + o, b"\x08" + enc_varint(_wk("2024-03-15T10:38:00Z")) + b"\x10\x10")]),
        (3, [(1, b"_" + o + b"\x00\x01theme", b"\x01dark")]),
        (4, [(1, b"_" + o + b"\x00\x01deleted_key", b"\x01DELETEDLSVALUE")]),
        (5, [(0, b"_" + o + b"\x00\x01deleted_key", None)]),
        (6, [(1, b"_" + o + b"\x00\x01secret", b"\x00" + "LSSECRETVALUE".encode("utf-16-le"))])]))
    _mk(os.path.join(P, "Local Storage", "leveldb", "000005.ldb"), ldb_table([(b"_" + o + b"\x00\x01ldbkey", 0, 1, b"\x01fromtable")]))
    _mk(os.path.join(P, "Local Storage", "leveldb", "CURRENT"), b"MANIFEST-000001\n")
    _mk(os.path.join(P, "Session Storage", "000003.log"), ldb_log([
        (1, [(1, b"namespace-1111-https://app.example/", b"7")]),
        (2, [(1, b"map-7-" + "sskey".encode("utf-16-le"), "ssvalue".encode("utf-16-le"))])]))
    idb = os.path.join(P, "IndexedDB", "https_app.example_0.indexeddb.leveldb")

    def sw(s):
        return enc_varint(len(s)) + s.encode("utf-16-be")
    _mk(os.path.join(idb, "000003.log"), ldb_log([
        (1, [(1, b"\x00\x00\x00\x00\xc9" + sw("https_app.example_0@1") + sw("labdb"), enc_varint(1))]),
        (2, [(1, b"\x00\x01\x00\x00\x32" + enc_varint(1) + b"\x00", "notes".encode("utf-16-be"))]),
        (3, [(1, b"\x00\x01\x01\x01" + b"\x03key1", b"\xff\x0fo\"\x04noteI\x02https://note-link.example/a")]),
        (4, [(1, b"\x00\x01\x01\x01" + b"\x03key2", b"\xff\x0fo\"\x04body")])]))
    swpb = b"\x08\x05" + b"\x12" + enc_varint(len(b"https://app.example/")) + b"https://app.example/" + \
        b"\x1a" + enc_varint(len(b"https://app.example/sw.js")) + b"https://app.example/sw.js" + b"\x38" + enc_varint(_wk("2024-03-15T10:39:00Z"))
    _mk(os.path.join(P, "Service Worker", "Database", "000003.log"), ldb_log([(1, [(1, b"REG:https://app.example/\x005", swpb)])]))
    _mk(os.path.join(P, "Local Extension Settings", ext, "000003.log"), ldb_log([(1, [(1, b"config", b'{"c2":"https://evil.example/"}')])]))

    def simple_entry(d, key, body, headers):
        k = key.encode()
        data = struct.pack("<QIII", SIMPLE_MAGIC, 5, len(k), 0x1234) + b"\0" * 4 + k + body + b"\0" * 16 + headers + b"\0" * 24
        _mk(os.path.join(d, "%s_0" % hashlib.sha1(key.encode()).hexdigest()[:16]), data)
    simple_entry(os.path.join(P, "Cache", "Cache_Data"), "1/0/_dk_https://cdn.example https://cdn.example https://cdn.example/app.js",
                 b"console.log('lab');", b"HTTP/1.1 200\x00content-type:application/javascript\x00date:Fri, 15 Mar 2024 10:31:00 GMT\x00\x00")
    simple_entry(os.path.join(P, "Cache", "Cache_Data"), "1/0/_dk_https://cache-only.example https://cache-only.example https://cache-only.example/page.html",
                 b"<html>cached</html>", b"HTTP/1.1 200\x00content-type:text/html; charset=utf-8\x00date:Fri, 15 Mar 2024 08:00:00 GMT\x00\x00")
    _mk(os.path.join(P, "Cache", "Cache_Data", "index"), b"\0" * 32)
    if extra_cache:
        simple_entry(os.path.join(extra_cache, "Cache", "Cache_Data"), "1/0/_dk_https://ext-cache.example https://ext-cache.example https://ext-cache.example/index.html",
                     b"<html>x</html>", b"HTTP/1.1 200\x00content-type:text/html\x00\x00")
    _mk(os.path.join(P, "Code Cache", "js", "deadbeef_0"), b"jit cache must be excluded by default")
    _mk(os.path.join(P, "Visited Links"), b"VLnk" + b"\0" * 60)


def lab_firefox(home, profdir, cachedir):
    P = profdir
    _db(os.path.join(P, "places.sqlite"), """
    CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url LONGVARCHAR,title LONGVARCHAR,rev_host LONGVARCHAR,visit_count INTEGER DEFAULT 0,
     hidden INTEGER DEFAULT 0 NOT NULL,typed INTEGER DEFAULT 0 NOT NULL,frecency INTEGER DEFAULT -1 NOT NULL,last_visit_date INTEGER,guid TEXT,
     foreign_count INTEGER DEFAULT 0 NOT NULL,url_hash INTEGER DEFAULT 0 NOT NULL,description TEXT,preview_image_url TEXT,origin_id INTEGER);
    CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,from_visit INTEGER,place_id INTEGER,visit_date INTEGER,visit_type INTEGER,session INTEGER,
     source INTEGER DEFAULT 0 NOT NULL,triggeringPlaceId INTEGER);
    CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY,type INTEGER,fk INTEGER DEFAULT NULL,parent INTEGER,position INTEGER,title LONGVARCHAR,
     keyword_id INTEGER,folder_type TEXT,dateAdded INTEGER,lastModified INTEGER,guid TEXT,syncStatus INTEGER NOT NULL DEFAULT 0,syncChangeCounter INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY,name VARCHAR(32) UNIQUE NOT NULL);
    CREATE TABLE moz_annos(id INTEGER PRIMARY KEY,place_id INTEGER NOT NULL,anno_attribute_id INTEGER,content LONGVARCHAR,flags INTEGER DEFAULT 0,
     expiration INTEGER DEFAULT 0,type INTEGER DEFAULT 0,dateAdded INTEGER DEFAULT 0,lastModified INTEGER DEFAULT 0);
    CREATE TABLE moz_inputhistory(place_id INTEGER NOT NULL,input LONGVARCHAR NOT NULL,use_count INTEGER,PRIMARY KEY(place_id,input));
    CREATE TABLE moz_places_metadata(id INTEGER PRIMARY KEY,place_id INTEGER NOT NULL,referrer_place_id INTEGER,created_at INTEGER NOT NULL DEFAULT 0,
     updated_at INTEGER NOT NULL DEFAULT 0,total_view_time INTEGER NOT NULL DEFAULT 0,typing_time INTEGER NOT NULL DEFAULT 0,key_presses INTEGER NOT NULL DEFAULT 0,
     scrolling_time INTEGER NOT NULL DEFAULT 0,scrolling_distance INTEGER NOT NULL DEFAULT 0,document_type INTEGER NOT NULL DEFAULT 0,search_query_id INTEGER);
    """, [
        ("INSERT INTO moz_places(id,url,title,visit_count,last_visit_date,guid) VALUES(?,?,?,?,?,?)",
         [(1, "https://www.mozilla.org/", "Mozilla", 1, _us("2024-03-16T12:00:00Z"), "p1"),
          (2, "https://ff-download.example/tool.zip", None, 0, _us("2024-03-16T12:05:00Z"), "p2"),
          (3, "https://bookmarked.example/", "Bookmarked", 0, None, "p3")]),
        ("INSERT INTO moz_historyvisits(id,from_visit,place_id,visit_date,visit_type) VALUES(?,?,?,?,?)",
         [(1, 0, 1, _us("2024-03-16T12:00:00Z"), 2), (2, 1, 2, _us("2024-03-16T12:05:00Z"), 7)]),
        ("INSERT INTO moz_bookmarks(id,type,fk,parent,position,title,dateAdded,lastModified,guid) VALUES(?,?,?,?,?,?,?,?,?)",
         [(1, 2, None, 0, 0, "", 0, 0, "root________"), (2, 2, None, 1, 0, "toolbar", 0, 0, "toolbar_____"),
          (3, 1, 3, 2, 0, "Bookmarked site", _us("2024-03-10T10:00:00Z"), _us("2024-03-10T10:00:00Z"), "bm3")]),
        ("INSERT INTO moz_anno_attributes VALUES(?,?)", [(1, "downloads/destinationFileURI"), (2, "downloads/metaData")]),
        ("INSERT INTO moz_annos(place_id,anno_attribute_id,content,dateAdded,lastModified) VALUES(?,?,?,?,?)",
         [(2, 1, "file:///home/alice/Downloads/tool.zip", _us("2024-03-16T12:05:00Z"), _us("2024-03-16T12:05:00Z")),
          (2, 2, json.dumps({"state": 1, "endTime": _ms("2024-03-16T12:05:30Z"), "fileSize": 1234}), _us("2024-03-16T12:05:00Z"), 0)]),
        ("INSERT INTO moz_inputhistory VALUES(?,?,?)", [(1, "mozi", 1)]),
        ("INSERT INTO moz_places_metadata(place_id,created_at,updated_at,total_view_time) VALUES(?,?,?,?)",
         [(1, _ms("2024-03-16T12:00:01Z"), _ms("2024-03-16T12:02:00Z"), 119000)])])
    _db(os.path.join(P, "cookies.sqlite"), """CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY,originAttributes TEXT NOT NULL DEFAULT '',name TEXT,value TEXT,
        host TEXT,path TEXT,expiry INTEGER,lastAccessed INTEGER,creationTime INTEGER,isSecure INTEGER,isHttpOnly INTEGER,inBrowserElement INTEGER DEFAULT 0,
        sameSite INTEGER DEFAULT 0,rawSameSite INTEGER DEFAULT 0,schemeMap INTEGER DEFAULT 0);""",
        [("INSERT INTO moz_cookies(id,name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly) VALUES(?,?,?,?,?,?,?,?,?,?)",
          [(1, "session", "SUPERSECRETCOOKIE", ".mozilla.org", "/", 1742126400, _us("2024-03-16T12:00:05Z"), _us("2024-03-16T12:00:02Z"), 1, 1)])])
    _db(os.path.join(P, "formhistory.sqlite"), """CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY,fieldname TEXT NOT NULL,value TEXT NOT NULL,
        timesUsed INTEGER,firstUsed INTEGER,lastUsed INTEGER,guid TEXT);
        CREATE TABLE moz_deleted_formhistory(id INTEGER PRIMARY KEY,timeDeleted INTEGER,guid TEXT);""",
        [("INSERT INTO moz_formhistory VALUES(?,?,?,?,?,?,?)", [(1, "searchbar-history", "FORMSECRETVALUE", 2, _us("2024-03-16T12:01:00Z"),
                                                                 _us("2024-03-16T12:03:00Z"), "f1")]),
         ("INSERT INTO moz_deleted_formhistory VALUES(?,?,?)", [(1, _us("2024-03-18T09:00:00Z"), "f0")])])
    _mk(os.path.join(P, "logins.json"), json.dumps({"nextId": 2, "logins": [{"id": 1, "hostname": "https://accounts.example",
        "httpRealm": None, "formSubmitURL": "https://accounts.example", "usernameField": "user", "passwordField": "pw",
        "encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECAAAAAAAAAAABAhJVU5LTk9XTg==",
        "encryptedPassword": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECAAAAAAAAAAABAhJVU5LTk9XTg==", "guid": "{g-1}",
        "timeCreated": _ms("2024-03-05T10:00:00Z"), "timeLastUsed": _ms("2024-03-16T12:04:00Z"), "timePasswordChanged": _ms("2024-03-05T10:00:00Z"),
        "timesUsed": 5}]}))
    _db(os.path.join(P, "key4.db"), "CREATE TABLE metaData(id PRIMARY KEY UNIQUE ON CONFLICT REPLACE, item1, item2);")
    _db(os.path.join(P, "favicons.sqlite"), """CREATE TABLE moz_icons(id INTEGER PRIMARY KEY,icon_url TEXT NOT NULL,fixed_icon_url_hash INTEGER NOT NULL DEFAULT 0,
        width INTEGER NOT NULL DEFAULT 0,root INTEGER NOT NULL DEFAULT 0,color INTEGER,expire_ms INTEGER NOT NULL DEFAULT 0,data BLOB);
        CREATE TABLE moz_pages_w_icons(id INTEGER PRIMARY KEY,page_url TEXT NOT NULL,page_url_hash INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE moz_icons_to_pages(page_id INTEGER NOT NULL,icon_id INTEGER NOT NULL,expire_ms INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(page_id,icon_id));""",
        [("INSERT INTO moz_icons(id,icon_url,expire_ms) VALUES(?,?,?)", [(1, "https://www.mozilla.org/favicon.ico", _ms("2024-03-23T12:00:00Z"))]),
         ("INSERT INTO moz_pages_w_icons(id,page_url) VALUES(?,?)", [(1, "https://www.mozilla.org/")]),
         ("INSERT INTO moz_icons_to_pages(page_id,icon_id) VALUES(?,?)", [(1, 1)])])
    sess = {"version": ["sessionrestore", 1], "session": {"lastUpdate": _ms("2024-03-16T12:10:00Z"), "startTime": _ms("2024-03-16T11:59:00Z")},
            "windows": [{"tabs": [{"entries": [{"url": "https://www.mozilla.org/", "title": "Mozilla"},
                                               {"url": "https://open-tab.example/", "title": "Open Tab",
                                                "formdata": {"id": {"q": "FORMDATASECRET"}}}],
                                   "index": 2, "lastAccessed": _ms("2024-03-16T12:09:00Z")}],
                         "_closedTabs": [{"state": {"entries": [{"url": "https://ff-closed.example/", "title": "FF Closed"}], "index": 1},
                                          "closedAt": _ms("2024-03-16T12:08:00Z"), "title": "FF Closed"}]}],
            "_closedWindows": [], "cookies": [{"host": ".open-tab.example", "name": "s", "value": "SESSIONCOOKIESECRET", "path": "/"}]}
    _mk(os.path.join(P, "sessionstore-backups", "recovery.jsonlz4"), mozlz4_encode(json.dumps(sess).encode()))
    _mk(os.path.join(P, "extensions.json"), json.dumps({"schemaVersion": 35, "addons": [
        {"id": "spy@lab.example", "version": "2.0", "type": "extension", "defaultLocale": {"name": "Lab Spy"}, "active": True,
         "userDisabled": False, "location": "app-profile", "installDate": _ms("2024-03-01T09:00:00Z"), "updateDate": _ms("2024-03-01T09:00:00Z"),
         "sourceURI": "https://addons.example/spy.xpi", "signedState": 0,
         "userPermissions": {"permissions": ["webRequest", "cookies"], "origins": ["<all_urls>"]}}]}))
    _mk(os.path.join(P, "prefs.js"), "// Mozilla User Preferences\n"
        'user_pref("browser.download.dir", "/home/alice/Downloads");\n'
        'user_pref("privacy.sanitize.sanitizeOnShutdown", true);\n'
        'user_pref("toolkit.startup.last_success", %d);\n'
        'user_pref("services.sync.username", "alice.sync@example.org");\n' % 1710590340)
    _db(os.path.join(P, "permissions.sqlite"), """CREATE TABLE moz_perms(id INTEGER PRIMARY KEY,origin TEXT,type TEXT,permission INTEGER,expireType INTEGER,
        expireTime INTEGER,modificationTime INTEGER);""",
        [("INSERT INTO moz_perms VALUES(?,?,?,?,?,?,?)", [(1, "https://www.mozilla.org", "desktop-notification", 1, 0, 0, _ms("2024-03-16T12:00:30Z"))])])
    _mk(os.path.join(P, "times.json"), json.dumps({"created": _ms("2024-01-05T09:00:00Z"), "firstUse": None}))
    _mk(os.path.join(P, "compatibility.ini"), "[Compatibility]\nLastVersion=123.0_20240311000000/20240311000000\nLastOSABI=Linux_x86_64-gcc3\n")
    _mk(os.path.join(P, "search.json.mozlz4"), mozlz4_encode(json.dumps({"engines": [{"_name": "DuckDuckGo", "_loadPath": "[app]ddg"}]}).encode()))
    od = os.path.join(P, "storage", "default", "https+++app.example")
    _mk(os.path.join(od, ".metadata-v2"), struct.pack(">q", _us("2024-03-16T12:06:00Z")) + b"\x00" * 8)
    _db(os.path.join(od, "ls", "data.sqlite"), """CREATE TABLE data(key TEXT PRIMARY KEY,utf16_length INTEGER NOT NULL,conversion_type INTEGER NOT NULL,
        compression_type INTEGER NOT NULL,last_access_time INTEGER NOT NULL DEFAULT 0,value BLOB NOT NULL);""",
        [("INSERT INTO data VALUES(?,?,?,?,?,?)", [("fflskey", 10, 1, 1, 0, snappy_compress_literal(b"FFLSSECRET"))])])
    _db(os.path.join(od, "idb", "1234567890abcdef.sqlite"), """CREATE TABLE database(name TEXT PRIMARY KEY,origin TEXT,version INTEGER);
        CREATE TABLE object_store(id INTEGER PRIMARY KEY,auto_increment INTEGER,name TEXT,key_path TEXT);
        CREATE TABLE object_data(object_store_id INTEGER,key BLOB,index_data_values BLOB,file_ids TEXT,data BLOB,PRIMARY KEY(object_store_id,key));""",
        [("INSERT INTO database VALUES(?,?,?)", [("ffdb", "https://app.example", 1)]),
         ("INSERT INTO object_store VALUES(?,?,?,?)", [(1, 0, "items", None)]),
         ("INSERT INTO object_data VALUES(?,?,?,?,?)", [(1, b"k1", None, None, snappy_compress_literal(b"\x00https://ff-idb-link.example/x\x00"))])])
    _mk(os.path.join(P, "serviceworker.txt"), "9\n^\nhttps://app.example/\nhttps://app.example/sw.js\ntrue\nsw-cache\n0\n%d\n%d\n%d\n#\n"
        % (_ms("2024-03-16T12:07:00Z"), _ms("2024-03-16T12:07:01Z"), _ms("2024-03-16T12:07:02Z")))
    content = b"<html>ff cache</html>"
    key = b"a,:https://ff-cache.example/page.html"
    elems = b"request-method\0GET\0response-head\0HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Sat, 16 Mar 2024 12:01:00 GMT\r\n\0"
    meta = struct.pack(">I", 0) + b"\0\0" + struct.pack(">IIIIIIII", 3, 2, 1710590460, 1710590400, 0, 0xFFFFFFFF, len(key), 0) + key + b"\0" + elems
    _mk(os.path.join(cachedir, "cache2", "entries", "A" * 40), content + meta + struct.pack(">I", len(content)))


def lab_safari(home):
    S = os.path.join(home, "Library", "Safari")
    _db(os.path.join(S, "History.db"), """CREATE TABLE history_items(id INTEGER PRIMARY KEY AUTOINCREMENT,url TEXT NOT NULL UNIQUE,domain_expansion TEXT NULL,
        visit_count INTEGER NOT NULL,daily_visit_counts BLOB NOT NULL,weekly_visit_counts BLOB NULL,autocomplete_triggers BLOB NULL,
        should_recompute_derived_visit_counts INTEGER NOT NULL,visit_count_score INTEGER NOT NULL,status_code INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE history_visits(id INTEGER PRIMARY KEY AUTOINCREMENT,history_item INTEGER NOT NULL,visit_time REAL NOT NULL,title TEXT NULL,
        load_successful BOOLEAN NOT NULL DEFAULT 1,http_non_get BOOLEAN NOT NULL DEFAULT 0,synthesized BOOLEAN NOT NULL DEFAULT 0,
        redirect_source INTEGER NULL UNIQUE,redirect_destination INTEGER NULL UNIQUE,origin INTEGER NOT NULL DEFAULT 0,generation INTEGER NOT NULL DEFAULT 0,
        attributes INTEGER NOT NULL DEFAULT 0,score INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE history_tombstones(id INTEGER PRIMARY KEY AUTOINCREMENT,start_time REAL NOT NULL,end_time REAL NOT NULL,url TEXT,
        generation INTEGER NOT NULL DEFAULT 0);""",
        [("INSERT INTO history_items(id,url,visit_count,daily_visit_counts,should_recompute_derived_visit_counts,visit_count_score) VALUES(?,?,?,?,?,?)",
          [(1, "https://www.apple.com/", 1, b"", 0, 100), (2, "https://safari-download.example/tool.dmg", 1, b"", 0, 100)]),
         ("INSERT INTO history_visits(id,history_item,visit_time,title) VALUES(?,?,?,?)",
          [(1, 1, _mac("2024-03-17T08:00:00Z"), "Apple"), (2, 2, _mac("2024-03-17T08:05:00Z"), "tool.dmg")]),
         ("INSERT INTO history_tombstones(start_time,end_time,url) VALUES(?,?,?)",
          [(_mac("2024-03-17T07:00:00Z"), _mac("2024-03-17T07:30:00Z"), "https://wiped.example/")])])
    def bp(path, obj):
        _mk(path, plistlib.dumps(obj, fmt=plistlib.FMT_BINARY))
    bp(os.path.join(S, "Downloads.plist"), {"DownloadHistory": [{
        "DownloadEntryURL": "https://safari-download.example/tool.dmg", "DownloadEntryPath": "/Users/carol/Downloads/tool.dmg",
        "DownloadEntryProgressBytesSoFar": 2048, "DownloadEntryProgressTotalToLoad": 2048, "DownloadEntryIdentifier": "D-1",
        "DownloadEntryDateAddedKey": parse_iso("2024-03-17T08:05:00Z").replace(tzinfo=None),
        "DownloadEntryDateFinishedKey": parse_iso("2024-03-17T08:05:20Z").replace(tzinfo=None)}]})
    bp(os.path.join(S, "Bookmarks.plist"), {"WebBookmarkType": "WebBookmarkTypeList", "Title": "", "Children": [
        {"WebBookmarkType": "WebBookmarkTypeList", "Title": "BookmarksBar", "Children": [
            {"WebBookmarkType": "WebBookmarkTypeLeaf", "URLString": "https://www.apple.com/", "URIDictionary": {"title": "Apple"}, "WebBookmarkUUID": "u1"}]},
        {"WebBookmarkType": "WebBookmarkTypeList", "Title": "com.apple.ReadingList", "Children": [
            {"WebBookmarkType": "WebBookmarkTypeLeaf", "URLString": "https://read-later.example/", "URIDictionary": {"title": "Read later"},
             "WebBookmarkUUID": "u2", "ReadingList": {"DateAdded": parse_iso("2024-03-17T08:10:00Z").replace(tzinfo=None), "PreviewText": "preview"}}]}]})
    bp(os.path.join(S, "LastSession.plist"), {"SessionVersion": "1.0", "SessionWindows": [{"TabStates": [
        {"TabURL": "https://safari-open.example/", "TabTitle": "Safari Open", "TabUUID": "t1"}]}]})
    bp(os.path.join(S, "RecentlyClosedTabs.plist"), {"ClosedTabOrWindowPersistentStates": [{"PersistentState": {
        "TabURL": "https://safari-closed.example/", "TabTitle": "Safari Closed", "DateClosed": parse_iso("2024-03-17T08:20:00Z").replace(tzinfo=None)}}]})
    bp(os.path.join(S, "TopSites.plist"), {"TopSites": [{"TopSiteURLString": "https://www.apple.com/", "TopSiteTitle": "Apple"}]})
    _db(os.path.join(S, "CloudTabs.db"), """CREATE TABLE cloud_tabs(tab_uuid TEXT PRIMARY KEY,system_fields BLOB,device_uuid TEXT,position BLOB,title TEXT,
        url TEXT,is_showing_reader BOOLEAN,is_pinned BOOLEAN,reader_scroll_position_page_index INTEGER,scene_id TEXT);
        CREATE TABLE cloud_tab_devices(device_uuid TEXT PRIMARY KEY,system_fields BLOB,device_name TEXT,has_duplicate_device_name BOOLEAN,
        is_ephemeral_device BOOLEAN,last_modified REAL);""",
        [("INSERT INTO cloud_tabs(tab_uuid,device_uuid,title,url,is_pinned) VALUES(?,?,?,?,?)", [("c1", "d1", "iPhone tab", "https://iphone-tab.example/", 0)]),
         ("INSERT INTO cloud_tab_devices(device_uuid,device_name) VALUES(?,?)", [("d1", "Carol's iPhone")])])
    _db(os.path.join(S, "LocalStorage", "https_app.example_0.localstorage"), "CREATE TABLE ItemTable(key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB NOT NULL ON CONFLICT FAIL);",
        [("INSERT INTO ItemTable VALUES(?,?)", [("sfkey", "SAFARILSSECRET".encode("utf-16-le"))])])

    def ck(domain, name, path, value, flags, exp, cre):
        d, n, p, v = [x.encode() + b"\0" for x in (domain, name, path, value)]
        uo = 56
        no = uo + len(d)
        po = no + len(n)
        vo = po + len(p)
        size = vo + len(v)
        return struct.pack("<8I", size, 0, flags, 0, uo, no, po, vo) + b"\0" * 8 + struct.pack("<dd", exp, cre) + d + n + p + v
    recs = [ck(".apple.com", "sess", "/", "SAFARICOOKIESECRET", 5, _mac("2025-03-17T08:00:00Z"), _mac("2024-03-17T08:00:01Z"))]
    hdr_len = 8 + 4 * len(recs) + 4
    offs = []
    o = hdr_len
    for r in recs:
        offs.append(o)
        o += len(r)
    page = b"\x00\x00\x01\x00" + struct.pack("<I", len(recs)) + b"".join(struct.pack("<I", x) for x in offs) + b"\0\0\0\0" + b"".join(recs)
    _mk(os.path.join(home, "Library", "Cookies", "Cookies.binarycookies"), b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page)) + page + b"\0" * 8)
    _db(os.path.join(home, "Library", "Caches", "com.apple.Safari", "Cache.db"), """CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
        version INTEGER,hash_value INTEGER,storage_policy INTEGER,request_key TEXT UNIQUE,time_stamp NOT NULL DEFAULT CURRENT_TIMESTAMP,partition TEXT);""",
        [("INSERT INTO cfurl_cache_response(version,hash_value,storage_policy,request_key,time_stamp) VALUES(?,?,?,?,?)",
          [(0, 1, 0, "https://www.apple.com/main.css", "2024-03-17 08:00:02")])])
    _db(os.path.join(home, "Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2"), """CREATE TABLE LSQuarantineEvent(
        LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL,LSQuarantineTimeStamp REAL,LSQuarantineAgentBundleIdentifier TEXT,LSQuarantineAgentName TEXT,
        LSQuarantineDataURLString TEXT,LSQuarantineSenderName TEXT,LSQuarantineSenderAddress TEXT,LSQuarantineTypeNumber INTEGER,
        LSQuarantineOriginTitle TEXT,LSQuarantineOriginURLString TEXT,LSQuarantineOriginAlias BLOB);""",
        [("INSERT INTO LSQuarantineEvent(LSQuarantineEventIdentifier,LSQuarantineTimeStamp,LSQuarantineAgentBundleIdentifier,LSQuarantineAgentName,"
          "LSQuarantineDataURLString,LSQuarantineTypeNumber,LSQuarantineOriginURLString) VALUES(?,?,?,?,?,?,?)",
          [("Q-1", _mac("2024-03-17T08:05:21Z"), "com.apple.Safari", "Safari", "https://safari-download.example/tool.dmg", 0,
            "https://safari-download.example/")])])
    _mk(os.path.join(home, "Downloads", "tool.dmg"), b"\x00" * 2048)


def lab_lnk(target):
    t = target.encode("latin-1") + b"\0"
    vol = struct.pack("<IIII", 0x11, 3, 0xABCD1234, 0x10) + b"\0"
    li_hdr = 0x1C
    lbp = li_hdr + len(vol)
    cps = lbp + len(t)
    body = vol + t + b"\0"
    li = struct.pack("<7I", li_hdr + len(body), li_hdr, 1, li_hdr, lbp, 0, cps) + body
    ft = lambda s: int((parse_iso(s) - E1601).total_seconds() * 10_000_000)
    hdr = struct.pack("<I16sIIQQQIiIHHII", 0x4C, b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46", 0x2, 0x20,
                      ft("2024-04-01T09:05:10Z"), ft("2024-04-01T09:06:00Z"), ft("2024-04-01T09:05:10Z"), 4096, 0, 1, 0, 0, 0, 0)
    return hdr + li + b"\0\0\0\0"


def cmd_labgen(a):
    R = a.root
    if os.path.exists(R) and os.listdir(R):
        print("lab root must be empty: %s" % R, file=sys.stderr)
        return 2
    alice = os.path.join(R, "home", "alice")
    udd = os.path.join(alice, ".config", "google-chrome")
    ext_cache = os.path.join(alice, ".cache", "google-chrome", "Default")
    report = lab_chrome_profile(udd, "Default", "full")
    lab_chrome_extras(udd, os.path.join(udd, "Default"), extra_cache=ext_cache)
    _mk(os.path.join(alice, "Downloads", "report.pdf"), report)
    ffroot = os.path.join(alice, ".mozilla", "firefox")
    _mk(os.path.join(ffroot, "profiles.ini"), "[Profile0]\nName=default-release\nIsRelative=1\nPath=abcd1234.default-release\nDefault=1\n")
    lab_firefox(alice, os.path.join(ffroot, "abcd1234.default-release"),
                os.path.join(alice, ".cache", "mozilla", "firefox", "abcd1234.default-release"))
    _db(os.path.join(alice, ".local", "share", "epiphany", "ephy-history.db"), """CREATE TABLE hosts(id INTEGER PRIMARY KEY,url LONGVARCAR,title LONGVARCAR,
        visit_count INTEGER DEFAULT 0 NOT NULL,zoom_level REAL DEFAULT 0.0);
        CREATE TABLE urls(id INTEGER PRIMARY KEY,host INTEGER NOT NULL REFERENCES hosts(id),url LONGVARCAR,title LONGVARCAR,sync_id LONGVARCAR,
        visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER,thumbnail_update_time INTEGER DEFAULT 0,
        hidden_from_overview INTEGER DEFAULT 0);
        CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER NOT NULL REFERENCES urls(id),visit_time INTEGER NOT NULL,visit_type INTEGER NOT NULL,
        referring_visit INTEGER);""",
        [("INSERT INTO urls(id,host,url,title,visit_count,last_visit_time) VALUES(?,?,?,?,?,?)",
          [(1, 1, "https://gnome.example/", "GNOME", 1, _us("2024-03-18T10:00:00Z"))]),
         ("INSERT INTO visits(id,url,visit_time,visit_type) VALUES(?,?,?,?)", [(1, 1, _us("2024-03-18T10:00:00Z"), 1)])])
    _db(os.path.join(alice, ".local", "share", "qutebrowser", "history.sqlite"), """CREATE TABLE History(url TEXT,title TEXT,atime INTEGER,redirect INTEGER);""",
        [("INSERT INTO History VALUES(?,?,?,?)", [("https://qute.example/", "Qute", 1710756000, 0),
                                                 ("https://future.example/", "Future", int((parse_iso("2099-01-01T00:00:00Z") - E1970).total_seconds()), 0)])])
    _mk(os.path.join(alice, ".local", "share", "recently-used.xbel"),
        '<?xml version="1.0" encoding="UTF-8"?>\n<xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks" '
        'xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">\n'
        '<bookmark href="file:///home/alice/Downloads/report.pdf" added="2024-03-15T10:34:06.000000Z" modified="2024-03-15T10:34:06.000000Z" '
        'visited="2024-03-15T10:40:00.000000Z"><info><metadata owner="http://freedesktop.org"><mime:mime-type type="application/pdf"/>'
        '<bookmark:applications><bookmark:application name="Document Viewer" exec="&apos;evince %u&apos;" modified="2024-03-15T10:40:00Z" count="1"/>'
        '</bookmark:applications></metadata></info></bookmark>\n</xbel>\n')
    bob = os.path.join(R, "Users", "bob")
    eudd = os.path.join(bob, "AppData", "Local", "Microsoft", "Edge", "User Data")
    lab_chrome_profile(eudd, "Default", "edge")
    _mk(os.path.join(eudd, "Local State"), json.dumps({"profile": {"info_cache": {"Default": {"name": "Bob"}}}}))
    _mk(os.path.join(eudd, "Default", "Preferences"), json.dumps({"profile": {"name": "Bob"},
                                                                    "browser": {"last_clear_browsing_data_time": str(_wk("2024-04-01T10:00:00Z"))}}))
    oudd = os.path.join(bob, "AppData", "Roaming", "Opera Software", "Opera Stable")
    os.makedirs(oudd, exist_ok=True)
    lab_chrome_profile(os.path.dirname(oudd), os.path.basename(oudd), "opera")
    _mk(os.path.join(oudd, "Preferences"), json.dumps({"profile": {"name": "Opera"}}))
    ocache = os.path.join(bob, "AppData", "Local", "Opera Software", "Opera Stable", "Cache", "Cache_Data")
    _mk(os.path.join(ocache, "index"), b"\xc3\xca\x03\xc1" + b"\0" * 252)
    blk = bytearray(256)
    key = b"https://opera-cache.example/logo.png"
    struct.pack_into("<IIIiiiQiI", blk, 0, 0x1234, 0, 0, 1, 0, 0, _wk("2024-04-02T09:00:05Z"), len(key), 0)
    blk[96:96 + len(key)] = key
    _mk(os.path.join(ocache, "data_1"), struct.pack("<IIhh", 0xC104CAC3, 0x20000, 1, 0) + b"\0" * (8192 - 12) + bytes(blk))
    _mk(os.path.join(bob, "AppData", "Local", "Microsoft", "Windows", "WebCache", "WebCacheV01.dat"),
        b"\x00\x00\x00\x00\xef\xcd\xab\x89" + b"\0" * 4088)
    _mk(os.path.join(bob, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "setup.exe.lnk"), lab_lnk("C:\\Users\\bob\\Downloads\\setup.exe"))
    _mk(os.path.join(bob, "Downloads", "setup.exe"), b"MZ lab placeholder - not a real executable\n" + b"\0" * 4053)
    _mk(os.path.join(R, "Windows", "Prefetch", "MSEDGE.EXE-1A2B3C4D.pf"), b"MAM\x04" + b"\0" * 60)
    _mk(os.path.join(R, "Windows", "Prefetch", "NOTEPAD.EXE-11111111.pf"), b"MAM\x04" + b"\0" * 60)
    carol = os.path.join(R, "Users", "carol")
    lab_safari(carol)
    cudd = os.path.join(carol, "Library", "Application Support", "Google", "Chrome")
    lab_chrome_profile(cudd, "Default", "mac")
    _mk(os.path.join(cudd, "Default", "Preferences"), json.dumps({"profile": {"name": "Carol"}}))
    print(json.dumps({"lab_root": R}))
    return 0


# ================================================================ unit tests (pure decoders)
def cmd_unit(a):
    results = []

    def t(name, fn):
        try:
            ok = fn()
            results.append((name, bool(ok), ""))
        except Exception as e:
            results.append((name, False, "%s: %s" % (type(e).__name__, e)))
    t("time.webkit", lambda: iso(conv_time(13354972200000000, "webkit_us")) == "2024-03-15T10:30:00.000000Z")
    t("time.prtime", lambda: iso(conv_time(1710590400000000, "unix_us")) == "2024-03-16T12:00:00.000000Z")
    t("time.mac", lambda: iso(conv_time(732355200.0, "mac_s")) == "2024-03-17T08:00:00.000000Z")
    t("time.filetime", lambda: iso(conv_time(133549722000000000, "filetime")) == "2024-03-15T10:30:00.000000Z")
    t("time.unix_auto", lambda: conv_time(1710590400, "unix_auto") == conv_time(1710590400000, "unix_auto") == conv_time(1710590400000000, "unix_auto"))
    t("time.zero_is_null", lambda: conv_time(0, "webkit_us") is None and conv_time("", "unix_s") is None)
    t("time.overflow_is_null", lambda: conv_time(10 ** 30, "webkit_us") is None)
    t("time.http_date", lambda: iso(conv_time("Fri, 15 Mar 2024 10:31:00 GMT", "http_date")) == "2024-03-15T10:31:00.000000Z")
    t("snappy.copy", lambda: snappy_decompress(bytes.fromhex("1208616263" "1d03" "0103")) == b"abc" * 6)
    t("snappy.literal_roundtrip", lambda: snappy_decompress(snappy_compress_literal(b"x" * 1000 + b"yz")) == b"x" * 1000 + b"yz")
    t("lz4.match", lambda: lz4_block_decompress(bytes.fromhex("4861626364" "0400")) == b"abcd" * 4)
    t("lz4.long_literal", lambda: lz4_block_decompress(lz4_literal(b"q" * 600)) == b"q" * 600)
    t("mozlz4.roundtrip", lambda: mozlz4_decode(mozlz4_encode(b'{"a":1}')) == b'{"a":1}')
    t("crc32c.vector", lambda: crc32c(b"123456789") == 0xE3069283)
    t("varint.leveldb", lambda: varint(enc_varint(300), 0) == (300, 2))
    t("varint.sqlite", lambda: svarint(bytes([0x81, 0x00]), 0) == (128, 2))
    t("protobuf.decode", lambda: pb_decode(b"\x08\x96\x01\x12\x03abc")[1] == [150] and pb_decode(b"\x08\x96\x01\x12\x03abc")[2] == [b"abc"])
    t("leveldb.log_roundtrip", lambda: [(s, ty, k, v) for _, rec, ok in leveldb_log_records(ldb_log([(5, [(1, b"k", b"v"), (0, b"k", None)])]))
                                        for s, ty, k, v in leveldb_batch(rec)] == [(5, 1, b"k", b"v"), (6, 0, b"k", None)])
    t("leveldb.crc_detects_corruption", lambda: [ok for _, _, ok in leveldb_log_records(
        (lambda b: b[:-1] + bytes([b[-1] ^ 0xFF]))(ldb_log([(1, [(1, b"key", b"value")])])))] == [False])
    t("leveldb.table_roundtrip", lambda: [(s, ty, k, v) for s, ty, k, v, _ in sstable_entries(ldb_table([(b"a", 3, 1, b"1"), (b"b", 4, 1, b"2")]))]
      == [(3, 1, b"a", b"1"), (4, 1, b"b", b"2")])
    t("snss.navigation", lambda: snss_navigation(snss_nav_cmd(6, 9, 2, "https://x.example/", "Título", _wk("2024-03-15T10:36:00Z"))[3:])["title"] == "Título")
    t("binarycookies.reject", lambda: _raises(lambda: binarycookies_parse(b"nope")))
    t("transition.decode", lambda: chrome_transition(0x30000001) == "TYPED|CHAIN_START|CHAIN_END")
    rd = Redactor(True, b"k")
    t("redact.url_token", lambda: rd.url("https://a.example/cb?token=SECRET&x=1") == "https://a.example/cb?token=[REDACTED]&x=1")
    t("redact.url_userinfo", lambda: "pw" not in rd.url("https://user:pw@a.example/"))
    t("redact.secret_hmac_stable", lambda: rd.secret("abc") == rd.secret("abc") and "abc" not in rd.secret("abc"))
    t("redact.email", lambda: "bob@example.com" not in rd.text("contact bob@example.com"))
    t("redact.off", lambda: Redactor(False, b"k").secret("abc") == "abc")
    t("csv.formula_injection", lambda: csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)")
    t("html.escape", lambda: "<script>" not in h("<script>alert(1)</script>"))
    t("xml.xxe_refused", lambda: _raises_xml())
    t("sqlite.record_rebuild", _test_record_rebuild)
    t("carve.plausible_url", lambda: plausible_url("https://a.example/x") and not plausible_url("https://deleted-3")
      and not plausible_url("https://x.example/\x01") and plausible_url("http://127.0.0.1:8080/"))
    t("origin.dirname", lambda: origin_from_dirname("https_app.example_0.indexeddb.leveldb") == "https://app.example")
    t("map_to_root.windows", lambda: map_to_root("C:\\Users\\bob\\x.exe", "/img", False).replace("\\", "/") == "/img/Users/bob/x.exe")
    fails = [r for r in results if not r[1]]
    for name, ok, err in results:
        print("%s  unit:%s%s" % ("PASS" if ok else "FAIL", name, (" — " + err) if err else ""))
    print("UNIT %d/%d passed" % (len(results) - len(fails), len(results)))
    return 1 if fails else 0


def _raises(fn):
    try:
        fn()
    except Exception:
        return True
    return False


def _raises_xml():
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, "x.xml")
    _mk(p, '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>')
    try:
        return _raises(lambda: safe_xml_parse(p))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _test_record_rebuild():
    rec = b"\x05\x00\x45\x21\x01" + b"https://deleted.example/page" + b"Deleted pg" + b"\x07"
    blob = b"\x00" * 10 + rec + b"\x00" * 10
    upos = blob.find(b"https://")
    cols = try_record_at_url(blob, upos)
    return cols is not None and cols[1] == "https://deleted.example/page" and cols[2] == "Deleted pg"


# ================================================================ self-test assertions on a lab case
def cmd_selfcheck(a):
    case = a.case
    recs = list(iter_records(case))
    events = list(iter_timeline(case))
    findings = safe_json_load(os.path.join(case, "analysis", "findings.json"))
    corr = safe_json_load(os.path.join(case, "analysis", "correlations.json"))
    profs = read_tsv(os.path.join(case, "profiles.tsv"), PROFILE_FIELDS)
    res = []

    def t(name, cond, info=""):
        res.append((name, bool(cond), info))

    def find(art=None, url=None, cls=None, browser=None, title=None, pred=None):
        out = []
        for r in recs:
            if art and r["artifact"] != art: continue
            if url and r.get("url") != url: continue
            if cls and r["class"] != cls: continue
            if browser and browser not in r["browser"]: continue
            if title and r.get("title") != title: continue
            if pred and not pred(r): continue
            out.append(r)
        return out
    fk = {f["kind"] for f in findings}
    bset = {(p["browser"], p["family"]) for p in profs}
    for b in ("Google Chrome", "Mozilla Firefox", "Microsoft Edge", "Opera", "Safari", "GNOME Web (Epiphany)", "qutebrowser"):
        t("discovery: %s" % b, any(x[0] == b for x in bset), sorted(bset))
    t("discovery: Chrome on macOS layout", any(p["browser"] == "Google Chrome" and p["os"] == "macos" for p in profs))
    t("discovery: Opera single-profile layout", any(p["browser"] == "Opera" and p["profile"] == "Opera Stable" for p in profs))
    t("discovery: ESE legacy cache detected", any(p["family"] == "ese" for p in profs))
    t("discovery: OS artifacts (linux/windows/macos)", {p["os"] for p in profs if p["family"] == "os"} >= {"linux", "windows", "macos"})
    t("chrome: visits parsed", len(find("history", browser="Google Chrome", pred=lambda r: r["os"] == "linux")) == 6)
    t("chrome: UTC conversion exact", any(r["ts"] == "2024-03-15T10:30:00.000000Z" for r in find("history", url="https://www.example.com/")))
    t("chrome: transition decoded", any(r["details"].get("transition") == "TYPED|CHAIN_START|CHAIN_END" for r in find("history", url="https://www.example.com/")))
    t("chrome: search term", len(find("search", title="forensic tools")) == 1)
    t("chrome: download + url chain", any(r["details"].get("state") == "COMPLETE" for r in find("download", url="https://files.example/report.pdf")))
    t("chrome: deleted URL recovered from freeblock/freelist",
      any(r["details"].get("region") in ("freeblock", "freelist", "unallocated") for r in find("recovered_url", url="https://deleted-evidence.example/secret-page")))
    t("chrome: recovered record title rebuilt", any(r.get("title") == "Secret Page Title" for r in find("recovered_url", url="https://deleted-evidence.example/secret-page")))
    t("recovery: no carving noise accepted", all(plausible_url(r["url"]) for r in find("recovered_url")) and len(find("recovered_url")) == 2,
      [r["url"] for r in find("recovered_url")])
    t("chrome: WAL-only deleted URL recovered", any("wal-frame" in r["details"].get("region", "") for r in find("recovered_url", url="https://wal-only.example/old")))
    t("chrome: WAL committed row visible (working copy)", len(find("history_url", url="https://wal-new.example/")) == 1)
    t("chrome: bookmark folders", any(r["details"].get("folder") == "bookmark_bar/Work" for r in find("bookmark", url="https://intranet.example/")))
    t("chrome: bookmark only in .bak flagged", any(r["details"].get("only_in_backup") for r in find("bookmark", url="https://removed-bookmark.example/")))
    t("chrome: cookie encrypted metadata only", any((r["details"].get("encrypted_value") or {}).get("scheme") == "v10" for r in find("cookie", browser="Google Chrome")))
    t("chrome: credential inventoried, password not exported",
      any(r["details"]["password"]["stored"] and r["details"]["password"]["encryption"] == "v10" for r in find("credential", browser="Google Chrome")))
    t("chrome: autofill", len(find("form", browser="Google Chrome")) == 1)
    t("chrome: favicon", len(find("favicon", url="https://hidden-site.example/")) == 1)
    t("chrome: top site + shortcut", find("top_site", url="https://www.example.com/") and find("omnibox_shortcut", url="https://www.example.com/"))
    t("chrome: extension name resolved from _locales", any(r.get("title") == "Lab Helper" for r in find("extension")))
    t("chrome: SNSS session navigation", any(r.get("title") == "News Article" for r in find("session_tab", url="https://news.example/article")))
    t("chrome: SNSS tab-restore entry", len(find("closed_tab", url="https://closed-tab.example/")) == 1)
    t("chrome: localStorage live key (log)", any(r.get("title") == "theme" for r in find("local_storage", url="https://app.example", cls="observed")))
    t("chrome: localStorage key from .ldb (snappy table)", any(r.get("title") == "ldbkey" for r in find("local_storage", url="https://app.example")))
    t("chrome: localStorage deleted value recovered", any(r.get("title") == "deleted_key" for r in find("local_storage", cls="recovered")))
    t("chrome: sessionStorage", any(r.get("title") == "sskey" and r.get("url") == "https://app.example/" for r in find("session_storage")))
    t("chrome: IndexedDB names + counts", any(r.get("title") == "labdb/notes" and r["details"].get("records") == 2 for r in find("indexeddb")))
    t("chrome: IndexedDB value URL carving", any("https://note-link.example/a" in r["details"].get("urls_in_values", []) for r in find("indexeddb")))
    t("chrome: service worker registration", any(r.get("title") == "https://app.example/sw.js" for r in find("service_worker", url="https://app.example/")))
    t("chrome: extension storage", len(find("extension_storage")) == 1)
    t("chrome: simple cache entry", len(find("cache", url="https://cdn.example/app.js")) == 1)
    t("chrome: external cache dir (role=cache)", len(find("cache", url="https://ext-cache.example/index.html")) == 1)
    t("chrome: Code Cache excluded by default", not any("Code Cache" in str((r.get("src") or {}).get("file")) for r in recs))
    t("chrome: Local State profile + os_crypt presence only", find("browser_profile", title="Default") and
      not any("RFBBUEkB" in json.dumps(r) for r in recs))
    t("chrome: clear-browsing-data finding", "browsing_data_cleared" in fk)
    t("chrome: sideloaded extension finding", "extension_sideloaded" in fk)
    t("edge: orphan visit finding", "orphan_visits" in fk)
    t("edge: dangerous download finding", "dangerous_download" in fk)
    t("opera: history (profile == user-data dir)", len(find("history", browser="Opera")) == 1)
    t("opera: blockfile cache (external cache dir)", len(find("cache", url="https://opera-cache.example/logo.png")) == 1)
    t("firefox: visits PRTime", any(r["ts"] == "2024-03-16T12:00:00.000000Z" for r in find("history", url="https://www.mozilla.org/")))
    t("firefox: visit type", any(r["details"].get("visit_type") == "DOWNLOAD" for r in find("history", browser="Firefox")))
    t("firefox: bookmark", any(r["details"].get("folder") == "/toolbar" or r["details"].get("folder", "").endswith("toolbar")
                               for r in find("bookmark", url="https://bookmarked.example/")))
    t("firefox: download (annotations)", any(r.get("value") == "/home/alice/Downloads/tool.zip" for r in find("download", browser="Firefox")))
    t("firefox: cookie", len(find("cookie", browser="Firefox", title="session")) == 1)
    t("firefox: form history + deletion tombstone", find("form", browser="Firefox") and find("form_deleted"))
    t("firefox: logins inventoried", len(find("credential", url="https://accounts.example")) == 1)
    t("firefox: session (mozLz4) open + closed tabs", find("session_tab", url="https://open-tab.example/") and find("closed_tab", url="https://ff-closed.example/"))
    t("firefox: extension + unsigned finding", find("extension", title="Lab Spy") and "extension_unsigned" in fk)
    t("firefox: anti-forensic pref finding", "privacy_anti_forensic_setting" in fk)
    t("firefox: LSNG local storage (snappy)", any(r.get("title") == "fflskey" for r in find("local_storage", url="https://app.example", browser="Firefox")))
    t("firefox: IndexedDB sqlite", any("https://ff-idb-link.example/x" in r["details"].get("urls_in_values", []) for r in find("indexeddb", browser="Firefox")))
    t("firefox: serviceworker.txt", len(find("service_worker", browser="Firefox")) == 1)
    t("firefox: cache2 entry (local profile dir)", len(find("cache", url="https://ff-cache.example/page.html")) == 1)
    t("firefox: page metadata", len(find("page_interaction")) == 1)
    t("firefox: permissions", len(find("permission", browser="Firefox")) == 1)
    t("epiphany: history", len(find("history", url="https://gnome.example/")) == 1)
    t("qutebrowser: history", len(find("history", url="https://qute.example/")) == 1)
    t("safari: history (Cocoa time)", any(r["ts"] == "2024-03-17T08:00:00.000000Z" for r in find("history", url="https://www.apple.com/", browser="Safari")))
    t("safari: tombstone finding", "history_deleted" in fk)
    t("safari: downloads.plist", len(find("download", browser="Safari")) == 1)
    t("safari: bookmark + reading list", find("bookmark", browser="Safari") and find("reading_list", url="https://read-later.example/"))
    t("safari: last session + closed tab", find("session_tab", url="https://safari-open.example/") and find("closed_tab", url="https://safari-closed.example/"))
    t("safari: cloud tabs", any(r["details"].get("device") == "Carol's iPhone" for r in find("cloud_tab")))
    t("safari: binarycookies", len(find("cookie", browser="Safari")) == 1)
    t("safari: Cache.db", len(find("cache", url="https://www.apple.com/main.css")) == 1)
    t("safari: LocalStorage", any(r.get("title") == "sfkey" for r in find("local_storage", browser="Safari")))
    t("os: recently-used.xbel", len(find("os_recent_file", url="file:///home/alice/Downloads/report.pdf")) == 1)
    t("os: LNK target", any(r.get("value") == "C:\\Users\\bob\\Downloads\\setup.exe" for r in find("os_recent_file")))
    t("os: prefetch (inferred)", any(r["class"] == "inferred" for r in find("os_prefetch")))
    t("os: macOS quarantine", len(find("os_quarantine_event")) == 1)
    t("ese: detected, not parsed", len(find("ese_database")) == 1)
    cmap = {c["target_path"]: c for c in corr}
    rp = cmap.get("/home/alice/Downloads/report.pdf", {})
    t("correlation: chrome download file present + hash matches browser",
      (rp.get("file") or {}).get("exists") and (rp.get("file") or {}).get("browser_hash_match") is True, rp.get("file"))
    t("correlation: chrome download <-> recently-used.xbel", any(l["type"] == "GTK recently-used.xbel" for l in rp.get("links", [])))
    t("correlation: edge download <-> LNK", any(l["type"] == "Windows Recent LNK" for l in cmap.get("C:\\Users\\bob\\Downloads\\setup.exe", {}).get("links", [])))
    t("correlation: safari download <-> quarantine", any(l["type"] == "macOS quarantine event" for l in cmap.get("/Users/carol/Downloads/tool.dmg", {}).get("links", [])))
    t("correlation: missing downloaded file reported", "download_target_missing" in fk)
    t("finding: future timestamp", "future_timestamps" in fk)
    t("finding: cache without history", "cache_without_history" in fk)
    t("finding: favicon without history", "favicon_without_history" in fk)
    t("finding: WAL pending", "sqlite_wal_pending" in fk)
    t("finding: deleted records recovered", "deleted_records_recovered" in fk)
    t("timeline: sorted", all(events[i]["ts"] <= events[i + 1]["ts"] for i in range(len(events) - 1)) and len(events) > 100, len(events))
    t("timeline: every event links a record", all(e.get("rid") for e in events))
    t("provenance: every record has source file + sha256",
      all((r.get("src") or {}).get("file") and (r.get("src") or {}).get("sha256") for r in recs if r["artifact"] not in ("extension",) or r["src"]["file"]),
      [r["rid"] for r in recs if not ((r.get("src") or {}).get("file") and (r.get("src") or {}).get("sha256"))][:5])
    secrets_ = ["SUPERSECRETCOOKIE", "TOKENSECRET123", "LSSECRETVALUE", "FFLSSECRET", "FORMSECRETVALUE", "alice.form@example.org",
                "alice.login@example.org", "SAFARICOOKIESECRET", "SAFARILSSECRET", "FORMDATASECRET", "SESSIONCOOKIESECRET",
                "PLAINCOOKIEVALUE", "DELETEDLSVALUE", "alice.sync@example.org", "alice@example.org"]
    leaks = []
    for sub in ("analysis", "reports"):
        for dp, _, fns in os.walk(os.path.join(case, sub)):
            for fn in fns:
                blob = open(os.path.join(dp, fn), "rb").read().decode("utf-8", "replace")
                for s in secrets_:
                    if s in blob:
                        leaks.append("%s in %s" % (s, fn))
    t("redaction: no lab secret appears in analysis/ or reports/", not leaks, leaks[:10])
    rep = os.path.join(case, "reports", "report.html")
    if os.path.isfile(rep):
        hb = open(rep, "r", encoding="utf-8").read()
        t("html: hostile title escaped", "<script>alert('xss')" not in hb and "&lt;script&gt;alert(" in hb)
        t("html: CSP + no external resources", "Content-Security-Policy" in hb and not re.search(r'(?i)<(?:script|link|img)[^>]+(?:src|href)=["\']?https?:', hb))
    for f in ("report.json", "report.md", "csv/timeline.csv", "csv/evidence_manifest.csv"):
        t("report: %s exists" % f, os.path.isfile(os.path.join(case, "reports", f)))
    fails = [r for r in res if not r[1]]
    for name, ok, info in res:
        print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("" if ok else "  -> %s" % (info,))))
    print("SELFCHECK %d/%d passed" % (len(res) - len(fails), len(res)))
    return 1 if fails else 0


# ================================================================ main
def main(argv):
    ap = argparse.ArgumentParser(prog="bfx-engine")
    sp = ap.add_subparsers(dest="cmd", required=True)

    def flt(p):
        p.add_argument("--since")
        p.add_argument("--until")
        p.add_argument("--domain")
        p.add_argument("--type")
        p.add_argument("--browser")
        p.add_argument("--profile-filter")
        p.add_argument("--evidence-class")
    p = sp.add_parser("analyze")
    p.add_argument("--case", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--redact", type=int, default=1)
    p.add_argument("--no-recover", action="store_true")
    p.add_argument("--keep-work", action="store_true")
    p.add_argument("--max-recover-bytes", type=int, default=512 * 1024 * 1024)
    p = sp.add_parser("merge")
    p.add_argument("--case", required=True)
    p.add_argument("--no-fs-correlation", action="store_true")
    p.add_argument("--max-hash-bytes", type=int, default=512 * 1024 * 1024)
    p = sp.add_parser("report")
    p.add_argument("--case", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--formats", default="html,json,csv,md")
    p.add_argument("--html-rows", type=int, default=20000)
    p.add_argument("--md-rows", type=int, default=500)
    flt(p)
    p = sp.add_parser("timeline")
    p.add_argument("--case", required=True)
    p.add_argument("--format", choices=["table", "csv", "jsonl"], default="table")
    p.add_argument("--limit", type=int, default=0)
    flt(p)
    p = sp.add_parser("stats")
    p.add_argument("--case", required=True)
    p = sp.add_parser("labgen")
    p.add_argument("--root", required=True)
    sp.add_parser("unit")
    p = sp.add_parser("selfcheck")
    p.add_argument("--case", required=True)
    p = sp.add_parser("validate-date")
    p.add_argument("value")
    a = ap.parse_args(argv)
    if a.cmd == "analyze":
        return cmd_analyze(a)
    if a.cmd == "merge":
        return cmd_merge(a)
    if a.cmd == "report":
        Filters(a)
        return build_report(a)
    if a.cmd == "timeline":
        return cmd_timeline(a)
    if a.cmd == "stats":
        return cmd_stats(a)
    if a.cmd == "labgen":
        return cmd_labgen(a)
    if a.cmd == "unit":
        return cmd_unit(a)
    if a.cmd == "selfcheck":
        return cmd_selfcheck(a)
    if a.cmd == "validate-date":
        try:
            print(iso(parse_iso(a.value)))
            return 0
        except ValueError:
            return 2
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(0)
__BFX_ENGINE_EOF__
}

# ------------------------------------------------------------------ support matrix (single source of truth)
support_matrix() {
cat <<'EOF'
# family	artifact	level	source	notes
chromium	history	FULL	History: urls, visits	visit time, transition decoded, duration, orphan/gap checks
chromium	search_terms	FULL	History: keyword_search_terms	time approximated by urls.last_visit_time
chromium	downloads	FULL	History: downloads, downloads_url_chains	state, danger type, URL chain, browser-reported hash
chromium	bookmarks	FULL	Bookmarks, Bookmarks.bak	backup-only entries flagged
chromium	cookies	PARTIAL	Cookies / Network/Cookies	metadata and times only; values encrypted (DPAPI/AES-GCM v10/v11/v20, Keychain, libsecret) and never decrypted
chromium	credentials	PARTIAL	Login Data, Login Data For Account	origin, username (redacted), times; passwords never decrypted
chromium	autofill/forms	FULL	Web Data: autofill	values redacted; address/card tables summarised only
chromium	search_engines	FULL	Web Data: keywords
chromium	favicons/top_sites/shortcuts/predictor	FULL	Favicons, Top Sites, Shortcuts, Network Action Predictor
chromium	media_history	FULL	Media History: playback
chromium	sessions/tabs	PARTIAL	Sessions/Session_*, Tabs_*, legacy Current/Last Session	SNSS navigation commands; window/group layout not rebuilt
chromium	extensions	FULL	Extensions/*/manifest.json + Preferences	_locales names, permissions, install time, risk flags; code never executed
chromium	preferences/permissions	PARTIAL	Preferences, Secure Preferences, Local State	selected keys, content-setting exceptions, clear-data marker
chromium	local_storage	PARTIAL	Local Storage/leveldb (.log + .ldb, snappy)	keys decoded, values redacted; deleted/superseded values recovered
chromium	session_storage	PARTIAL	Session Storage (LevelDB)
chromium	indexeddb	PARTIAL	IndexedDB/*.indexeddb.leveldb	DB/object-store names + counts; V8 values only carved for URLs
chromium	service_workers	PARTIAL	Service Worker/Database (protobuf)	scope, script, last update check
chromium	extension_storage	PARTIAL	Local/Sync/Managed Extension Settings (LevelDB)	values redacted
chromium	http_cache	PARTIAL	Cache/Cache_Data (simple cache), blockfile data_1	URL keys + HTTP headers; bodies not exported; blockfile heuristic
chromium	visited_links	DETECT	Visited Links	salted hash table, irreversible
chromium	code_cache/gpu_cache	NONE	Code Cache, GPUCache, ShaderCache	excluded by default (use --full to acquire)
firefox	history	FULL	places.sqlite: moz_places, moz_historyvisits	visit types, orphan/gap checks
firefox	bookmarks	FULL	places.sqlite: moz_bookmarks	folder paths
firefox	downloads	PARTIAL	places.sqlite: moz_annos	modern downloads only; legacy downloads.sqlite inventoried
firefox	input_history/page_metadata	FULL	moz_inputhistory, moz_places_metadata
firefox	cookies	FULL	cookies.sqlite	values redacted
firefox	form_history	FULL	formhistory.sqlite (+ moz_deleted_formhistory)	deletion tombstones reported
firefox	credentials	PARTIAL	logins.json, key4.db	NSS-encrypted; never decrypted
firefox	favicons	FULL	favicons.sqlite
firefox	sessions/tabs	PARTIAL	sessionstore.jsonlz4, sessionstore-backups/*	open/closed tabs and windows, form data redacted
firefox	extensions	FULL	extensions.json	signing state, permissions
firefox	preferences/permissions	FULL	prefs.js, user.js, permissions.sqlite, times.json, compatibility.ini, containers.json	anti-forensic settings flagged
firefox	local_storage	FULL	storage/default/*/ls/data.sqlite (snappy), webappsstore.sqlite	values redacted
firefox	indexeddb	PARTIAL	storage/default/*/idb/*.sqlite	names + counts; structured-clone values carved for URLs
firefox	service_workers	PARTIAL	serviceworker.txt	heuristic line parser
firefox	http_cache	PARTIAL	cache2/entries	key, fetch count, times, response head
firefox	search_engines	PARTIAL	search.json.mozlz4
safari	history	FULL	History.db	Cocoa timestamps; history_tombstones reported as deletions
safari	downloads	FULL	Downloads.plist
safari	bookmarks/reading_list	FULL	Bookmarks.plist
safari	sessions/tabs	PARTIAL	LastSession.plist, RecentlyClosedTabs.plist	SessionState blobs not decoded
safari	cloud_tabs	FULL	CloudTabs.db
safari	top_sites	FULL	TopSites.plist
safari	cookies	FULL	Cookies.binarycookies	values redacted
safari	http_cache	PARTIAL	Caches/com.apple.Safari/Cache.db	metadata only
safari	local_storage	PARTIAL	LocalStorage/*.localstorage
safari	favicons/permissions/extensions	PARTIAL	Favicon Cache, PerSitePreferences.db, Extensions.plist
safari	credentials	NONE	macOS Keychain	out of scope
safari	indexeddb/websql	DETECT	WebKit databases	SQLite inventory + carving only
epiphany	history	PARTIAL	ephy-history.db	epoch unit inferred
qutebrowser	history	FULL	history.sqlite
ese	ie/edge_legacy	DETECT	WebCacheV01.dat	ESE not parsed (export with libesedb separately)
all	deleted_records	CARVE	SQLite freelist/freeblocks/unallocated, WAL frames, rollback journals	URL carving + SQLite record reconstruction; no completeness guarantee
all	leveldb_deleted	CARVE	LevelDB .log/.ldb	deleted/superseded entries until compaction
all	sqlite_inventory	FULL	every SQLite file acquired	tables, row counts, header, WAL, freelist, quick_check
os	recently_used	FULL	~/.local/share/recently-used.xbel	Linux (GTK)
os	quarantine	FULL	QuarantineEventsV2	macOS
os	recent_lnk	PARTIAL	Windows Recent *.lnk	header times + LinkInfo path
os	prefetch	DETECT	Windows Prefetch (browser executables)	MAM content not decoded; file mtime as inferred execution
os	download_file_correlation	PARTIAL	file system under --root	existence, size, SHA-256, Zone.Identifier (native Windows Python on NTFS), Linux xattrs
EOF
}

# ------------------------------------------------------------------ browser path templates
# family|browser|os|base|udd_rel|cache_base|cache_rel   (H=home, L=AppData/Local, R=AppData/Roaming, A=Library/Application Support, C=Library/Caches)
browser_templates() {
cat <<'EOF'
chromium|Google Chrome|linux|H|.config/google-chrome|H|.cache/google-chrome
chromium|Google Chrome Beta|linux|H|.config/google-chrome-beta|H|.cache/google-chrome-beta
chromium|Google Chrome Dev|linux|H|.config/google-chrome-unstable|H|.cache/google-chrome-unstable
chromium|Google Chrome (flatpak)|linux|H|.var/app/com.google.Chrome/config/google-chrome|H|.var/app/com.google.Chrome/cache/google-chrome
chromium|Chromium|linux|H|.config/chromium|H|.cache/chromium
chromium|Chromium (snap)|linux|H|snap/chromium/common/chromium|H|snap/chromium/common/.cache/chromium
chromium|Chromium (flatpak)|linux|H|.var/app/org.chromium.Chromium/config/chromium|H|.var/app/org.chromium.Chromium/cache/chromium
chromium|Microsoft Edge|linux|H|.config/microsoft-edge|H|.cache/microsoft-edge
chromium|Microsoft Edge Beta|linux|H|.config/microsoft-edge-beta|H|.cache/microsoft-edge-beta
chromium|Microsoft Edge Dev|linux|H|.config/microsoft-edge-dev|H|.cache/microsoft-edge-dev
chromium|Brave|linux|H|.config/BraveSoftware/Brave-Browser|H|.cache/BraveSoftware/Brave-Browser
chromium|Brave (flatpak)|linux|H|.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser|-|-
chromium|Vivaldi|linux|H|.config/vivaldi|H|.cache/vivaldi
chromium|Opera|linux|H|.config/opera|H|.cache/opera
chromium|Opera Beta|linux|H|.config/opera-beta|H|.cache/opera-beta
chromium|Yandex Browser|linux|H|.config/yandex-browser|H|.cache/yandex-browser
chromium|Thorium|linux|H|.config/thorium|H|.cache/thorium
chromium|Google Chrome|windows|L|Google/Chrome/User Data|-|-
chromium|Google Chrome Beta|windows|L|Google/Chrome Beta/User Data|-|-
chromium|Google Chrome Dev|windows|L|Google/Chrome Dev/User Data|-|-
chromium|Google Chrome Canary|windows|L|Google/Chrome SxS/User Data|-|-
chromium|Chromium|windows|L|Chromium/User Data|-|-
chromium|Microsoft Edge|windows|L|Microsoft/Edge/User Data|-|-
chromium|Microsoft Edge Beta|windows|L|Microsoft/Edge Beta/User Data|-|-
chromium|Microsoft Edge Dev|windows|L|Microsoft/Edge Dev/User Data|-|-
chromium|Microsoft Edge Canary|windows|L|Microsoft/Edge SxS/User Data|-|-
chromium|Brave|windows|L|BraveSoftware/Brave-Browser/User Data|-|-
chromium|Brave Beta|windows|L|BraveSoftware/Brave-Browser-Beta/User Data|-|-
chromium|Brave Nightly|windows|L|BraveSoftware/Brave-Browser-Nightly/User Data|-|-
chromium|Vivaldi|windows|L|Vivaldi/User Data|-|-
chromium|Opera|windows|R|Opera Software/Opera Stable|L|Opera Software/Opera Stable
chromium|Opera GX|windows|R|Opera Software/Opera GX Stable|L|Opera Software/Opera GX Stable
chromium|Opera Beta|windows|R|Opera Software/Opera Next|L|Opera Software/Opera Next
chromium|Yandex Browser|windows|L|Yandex/YandexBrowser/User Data|-|-
chromium|Thorium|windows|L|Thorium/User Data|-|-
chromium|Naver Whale|windows|L|Naver/Naver Whale/User Data|-|-
chromium|Coc Coc|windows|L|CocCoc/Browser/User Data|-|-
chromium|Epic Privacy Browser|windows|L|Epic Privacy Browser/User Data|-|-
chromium|Cent Browser|windows|L|CentBrowser/User Data|-|-
chromium|Comodo Dragon|windows|L|Comodo/Dragon/User Data|-|-
chromium|Iridium|windows|L|Iridium/User Data|-|-
chromium|Arc|windows|L|Packages/TheBrowserCompany.Arc_*/LocalCache/Local/Arc/User Data|-|-
chromium|Google Chrome|macos|A|Google/Chrome|C|Google/Chrome
chromium|Google Chrome Beta|macos|A|Google/Chrome Beta|C|Google/Chrome Beta
chromium|Google Chrome Canary|macos|A|Google/Chrome Canary|C|Google/Chrome Canary
chromium|Chromium|macos|A|Chromium|C|Chromium
chromium|Microsoft Edge|macos|A|Microsoft Edge|C|Microsoft Edge
chromium|Brave|macos|A|BraveSoftware/Brave-Browser|C|BraveSoftware/Brave-Browser
chromium|Vivaldi|macos|A|Vivaldi|C|Vivaldi
chromium|Opera|macos|A|com.operasoftware.Opera|C|com.operasoftware.Opera
chromium|Opera GX|macos|A|com.operasoftware.OperaGX|C|com.operasoftware.OperaGX
chromium|Yandex Browser|macos|A|Yandex/YandexBrowser|-|-
chromium|Arc|macos|A|Arc/User Data|C|Arc/User Data
chromium|Thorium|macos|A|Thorium|-|-
firefox|Mozilla Firefox|linux|H|.mozilla/firefox|H|.cache/mozilla/firefox
firefox|Mozilla Firefox (snap)|linux|H|snap/firefox/common/.mozilla/firefox|H|snap/firefox/common/.cache/mozilla/firefox
firefox|Mozilla Firefox (flatpak)|linux|H|.var/app/org.mozilla.firefox/.mozilla/firefox|H|.var/app/org.mozilla.firefox/cache/mozilla/firefox
firefox|LibreWolf|linux|H|.librewolf|H|.cache/librewolf
firefox|Waterfox|linux|H|.waterfox|H|.cache/waterfox
firefox|Pale Moon|linux|H|.moonchild productions/pale moon|H|.cache/moonchild productions/pale moon
firefox|SeaMonkey|linux|H|.mozilla/seamonkey|-|-
firefox|Floorp|linux|H|.floorp|H|.cache/floorp
firefox|Zen Browser|linux|H|.zen|H|.cache/zen
firefox|Tor Browser|linux|H|.local/share/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Browser|-|-
firefox|Tor Browser|linux|H|tor-browser/Browser/TorBrowser/Data/Browser|-|-
firefox|Mozilla Firefox|windows|R|Mozilla/Firefox/Profiles|L|Mozilla/Firefox/Profiles
firefox|LibreWolf|windows|R|librewolf/Profiles|L|librewolf/Profiles
firefox|Waterfox|windows|R|Waterfox/Profiles|L|Waterfox/Profiles
firefox|Pale Moon|windows|R|Moonchild Productions/Pale Moon/Profiles|L|Moonchild Productions/Pale Moon/Profiles
firefox|SeaMonkey|windows|R|Mozilla/SeaMonkey/Profiles|L|Mozilla/SeaMonkey/Profiles
firefox|Floorp|windows|R|Floorp/Profiles|L|Floorp/Profiles
firefox|Zen Browser|windows|R|zen/Profiles|L|zen/Profiles
firefox|Tor Browser|windows|H|Desktop/Tor Browser/Browser/TorBrowser/Data/Browser|-|-
firefox|Mozilla Firefox|macos|A|Firefox/Profiles|C|Firefox/Profiles
firefox|LibreWolf|macos|A|librewolf/Profiles|C|librewolf/Profiles
firefox|Waterfox|macos|A|Waterfox/Profiles|C|Waterfox/Profiles
firefox|Floorp|macos|A|Floorp/Profiles|C|Floorp/Profiles
firefox|Zen Browser|macos|A|zen/Profiles|C|zen/Profiles
firefox|Tor Browser|macos|A|TorBrowser-Data/Browser|-|-
epiphany|GNOME Web (Epiphany)|linux|H|.local/share/epiphany|-|-
epiphany|GNOME Web (Epiphany)|linux|H|.var/app/org.gnome.Epiphany/data/epiphany|-|-
qutebrowser|qutebrowser|linux|H|.local/share/qutebrowser|-|-
qutebrowser|qutebrowser|macos|A|qutebrowser|-|-
qutebrowser|qutebrowser|windows|R|qutebrowser/data|-|-
EOF
}

# ------------------------------------------------------------------ discovery
base_dir() {  # home base-code -> directory
    case $2 in
        H) printf '%s' "$1" ;; L) printf '%s/AppData/Local' "$1" ;; R) printf '%s/AppData/Roaming' "$1" ;;
        A) printf '%s/Library/Application Support' "$1" ;; C) printf '%s/Library/Caches' "$1" ;; *) return 1 ;;
    esac
}
browser_selected() {  # family browser
    [[ -z $BROWSER_SEL ]] && return 0
    local s low=${2,,}; local IFS=,
    for s in $BROWSER_SEL; do
        s=${s,,}; s=${s// /}
        [[ $s == "$1" || ${low// /} == *"$s"* ]] && return 0
    done
    return 1
}
add_profile() {  # family browser os user profile detection path -> sets NEWID ("" if duplicate)
    local key
    key=$(cd -- "$7" 2>/dev/null && pwd -P || printf '%s' "$7")
    NEWID=""
    [[ -n ${SEEN_PROFILE[$key]:-} ]] && return 0
    PCOUNT=$((PCOUNT+1)); printf -v NEWID 'P%03d' "$PCOUNT"
    SEEN_PROFILE[$key]=$NEWID
    local f; for f in "$1" "$2" "$3" "$4" "$5" "$6" "$7"; do
        if [[ $f == *$'\t'* || $f == *$'\n'* ]]; then { log warn "skipping profile path with control characters: $7"; PCOUNT=$((PCOUNT-1)); NEWID=""; return 0; }; fi
    done
    PROFILE_ROWS+=("$NEWID"$'\t'"$1"$'\t'"$2"$'\t'"$3"$'\t'"$4"$'\t'"$5"$'\t'"$6"$'\t'"$7")
}
add_source() { [[ -n $1 ]] && SOURCE_ROWS+=("$1"$'\t'"$2"$'\t'"$3"$'\t'"$4"); return 0; }

scan_chromium_udd() {  # browser os user udd cacheroot detection
    local browser=$1 os=$2 user=$3 udd=$4 croot=$5 det=$6 p name
    [[ -d $udd ]] || return 0
    if [[ -f $udd/History || -f $udd/Preferences ]] && [[ ! -d $udd/Default ]]; then
        add_profile chromium "$browser" "$os" "$user" "${udd##*/}" "$det" "$udd"
        add_source "$NEWID" profile tree "$udd"
        if [[ -n $croot && -d $croot ]]; then add_source "$NEWID" cache tree "$croot"; fi
        return 0
    fi
    for p in "$udd"/*/; do
        p=${p%/}; name=${p##*/}
        [[ -f $p/History || -f $p/Preferences || -f $p/Cookies || -f $p/Network/Cookies || -f $p/Bookmarks ]] || continue
        add_profile chromium "$browser" "$os" "$user" "$name" "$det" "$p"
        [[ -n $NEWID ]] || continue
        add_source "$NEWID" profile tree "$p"
        add_source "$NEWID" root files1 "$udd"
        if [[ -n $croot && -d $croot/$name ]]; then add_source "$NEWID" cache tree "$croot/$name"; fi
    done
}
scan_firefox_dir() {  # browser os user profilesdir cacheroot detection
    local browser=$1 os=$2 user=$3 pd=$4 croot=$5 det=$6 p name ini line base
    [[ -d $pd ]] || return 0
    local -a cands=("$pd"/*/)
    for ini in "$pd/profiles.ini" "${pd%/*}/profiles.ini"; do
        [[ -f $ini ]] || continue
        while IFS= read -r line || [[ -n $line ]]; do
            line=${line%$'\r'}
            if [[ $line == Path=* ]]; then
                base=${line#Path=}
                if [[ $base == /* || $base =~ ^[A-Za-z]:[\\/] ]]; then
                    if [[ $base =~ ^[A-Za-z]: ]]; then { (( LIVE )) && command -v cygpath >/dev/null && base=$(cygpath -u "$base") || continue; }; fi
                    if [[ -d $base ]]; then cands+=("$base/"); fi
                fi
            fi
        done < "$ini"
    done
    for p in "${cands[@]}"; do
        p=${p%/}; name=${p##*/}
        [[ -f $p/prefs.js || -f $p/places.sqlite ]] || continue
        add_profile firefox "$browser" "$os" "$user" "$name" "$det" "$p"
        [[ -n $NEWID ]] || continue
        add_source "$NEWID" profile tree "$p"
        if [[ -n $croot && -d $croot/$name ]]; then add_source "$NEWID" cache tree "$croot/$name"; fi
    done
}
scan_home() {  # os user home
    local os=$1 user=$2 home=$3 fam br tos b rel cb crel bd udd croot g
    local -A BASES=([H]="$home" [L]="$home/AppData/Local" [R]="$home/AppData/Roaming" [A]="$home/Library/Application Support" [C]="$home/Library/Caches")
    while IFS='|' read -r fam br tos b rel cb crel; do
        if [[ -z $fam || $fam == \#* || $tos != "$os" ]]; then continue; fi
        browser_selected "$fam" "$br" || continue
        bd=${BASES[$b]:-}; [[ -n $bd ]] || continue
        croot=""
        if [[ $cb != - ]]; then croot="${BASES[$cb]}/$crel"; fi
        local -a udds=() ; local oifs=$IFS; IFS=   # rel may contain spaces and a glob (Arc)
        udds=( "$bd"/$rel ); IFS=$oifs
        for udd in "${udds[@]+"${udds[@]}"}"; do
            [[ -d $udd ]] || continue
            case $fam in
                chromium) scan_chromium_udd "$br" "$os" "$user" "$udd" "$croot" known-path ;;
                firefox) scan_firefox_dir "$br" "$os" "$user" "$udd" "$croot" known-path ;;
                epiphany|qutebrowser)
                    add_profile "$fam" "$br" "$os" "$user" "${udd##*/}" known-path "$udd"
                    add_source "$NEWID" profile tree "$udd" ;;
            esac
        done
    done < <(browser_templates)
    if [[ $os == macos ]] && browser_selected safari Safari && [[ -d $home/Library/Safari ]]; then
        add_profile safari Safari macos "$user" Safari known-path "$home/Library/Safari"
        if [[ -n $NEWID ]]; then
            add_source "$NEWID" safari tree "$home/Library/Safari"
            if [[ -d $home/Library/Cookies ]]; then add_source "$NEWID" cookies tree "$home/Library/Cookies"; fi
            g="$home/Library/Containers/com.apple.Safari/Data/Library/Cookies"
            if [[ -d $g ]]; then add_source "$NEWID" cookies_container tree "$g"; fi
            if [[ -d $home/Library/Caches/com.apple.Safari ]]; then add_source "$NEWID" cache tree "$home/Library/Caches/com.apple.Safari"; fi
            if [[ -d $home/Library/WebKit/com.apple.Safari ]]; then add_source "$NEWID" webkit tree "$home/Library/WebKit/com.apple.Safari"; fi
        fi
    fi
    if [[ $os == windows ]] && browser_selected ese "Internet Explorer / Edge Legacy" && [[ -d $home/AppData/Local/Microsoft/Windows/WebCache ]]; then
        add_profile ese "Internet Explorer / Edge Legacy (WebCache)" windows "$user" WebCache known-path "$home/AppData/Local/Microsoft/Windows/WebCache"
        add_source "$NEWID" profile tree "$home/AppData/Local/Microsoft/Windows/WebCache"
    fi
    (( OS_ARTIFACTS )) || return 0
    browser_selected os "os" || [[ -z $BROWSER_SEL ]] || return 0
    case $os in
        linux) if [[ -f $home/.local/share/recently-used.xbel ]]; then
                   add_profile os "Operating System (Linux)" linux "$user" os-artifacts known-path "$home/.local/share/recently-used.xbel"
                   add_source "$NEWID" os file "$home/.local/share/recently-used.xbel"; fi ;;
        macos) g="$home/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
               if [[ -f $g ]]; then
                   add_profile os "Operating System (macOS)" macos "$user" os-artifacts known-path "$g"
                   add_source "$NEWID" os file "$g"; fi ;;
        windows) g="$home/AppData/Roaming/Microsoft/Windows/Recent"
                 if [[ -d $g ]]; then
                     add_profile os "Operating System (Windows)" windows "$user" os-artifacts known-path "$g"
                     add_source "$NEWID" recent files1 "$g"; fi ;;
    esac
}
list_homes() {  # root -> "os<TAB>user<TAB>home"
    local r=${1%/} h u
    for h in "$r"/home/* "$r"/root; do
        [[ -d $h && ! -L $h ]] || continue
        printf 'linux\t%s\t%s\n' "${h##*/}" "$h"
    done
    for h in "$r"/Users/*; do
        [[ -d $h && ! -L $h ]] || continue
        u=${h##*/}
        case $u in Public|Default|"Default User"|"All Users"|Shared|Guest|.localized|defaultuser0|WDAGUtilityAccount) continue ;; esac
        if [[ -d $h/AppData ]]; then printf 'windows\t%s\t%s\n' "$u" "$h"
        elif [[ -d $h/Library ]]; then printf 'macos\t%s\t%s\n' "$u" "$h"; fi
    done
}
deep_scan() {  # signature-based discovery of profiles outside known paths
    local r=$1 f d
    log info "deep signature scan under ${r:-/} (maxdepth $DEPTH)"
    while IFS= read -r -d '' f; do
        d=${f%/*}
        case ${f##*/} in
            History) [[ -f $d/Preferences || -d $d/Network || -f $d/Bookmarks ]] || continue
                     browser_selected chromium "Chromium-based (signature)" || continue
                     add_profile chromium "Chromium-based (signature)" unknown "?" "${d##*/}" signature "$d"
                     if [[ -n $NEWID ]]; then add_source "$NEWID" profile tree "$d" && add_source "$NEWID" root files1 "${d%/*}"; fi ;;
            places.sqlite) browser_selected firefox "Gecko-based (signature)" || continue
                     add_profile firefox "Gecko-based (signature)" unknown "?" "${d##*/}" signature "$d"
                     if [[ -n $NEWID ]]; then add_source "$NEWID" profile tree "$d"; fi ;;
            History.db) [[ -f $d/Bookmarks.plist || -f $d/Downloads.plist || ${d##*/} == Safari ]] || continue
                     browser_selected safari "Safari (signature)" || continue
                     add_profile safari "Safari/WebKit (signature)" unknown "?" "${d##*/}" signature "$d"
                     if [[ -n $NEWID ]]; then add_source "$NEWID" safari tree "$d"; fi ;;
            ephy-history.db) add_profile epiphany "GNOME Web (signature)" unknown "?" "${d##*/}" signature "$d"
                     if [[ -n $NEWID ]]; then add_source "$NEWID" profile tree "$d"; fi ;;
        esac
    done < <(find "${r:-/}" -maxdepth "$DEPTH" \( -path '*/proc' -o -path '*/sys' -o -path '*/dev' -o -path '*/$Recycle.Bin' \) -prune -o \
               -type f \( -name History -o -name places.sqlite -o -name History.db -o -name ephy-history.db \) -print0 2>/dev/null)
}
detect_source_dir() {  # explicit --source directory: infer family
    local d=${1%/} fam="" br=""
    if [[ -f $d/History && ( -f $d/Preferences || -d $d/Network || -f $d/Bookmarks || -f $d/Login\ Data ) ]]; then fam=chromium br="Chromium-based (--source)"
    elif [[ -f $d/places.sqlite || -f $d/prefs.js ]]; then fam=firefox br="Gecko-based (--source)"
    elif [[ -f $d/History.db || -f $d/Bookmarks.plist ]]; then fam=safari br="Safari/WebKit (--source)"
    elif [[ -f $d/ephy-history.db ]]; then fam=epiphany br="GNOME Web (--source)"
    elif [[ -f $d/history.sqlite ]]; then fam=qutebrowser br="qutebrowser (--source)"
    fi
    if [[ -n $FAMILY_HINT ]]; then fam=$FAMILY_HINT && br="${br:-$FAMILY_HINT (--source)}"; fi
    [[ -n $fam ]] || { log warn "cannot identify browser family of $d (use --family)"; record_error discovery "" "$d" "unidentified source directory"; return 0; }
    add_profile "$fam" "$br" unknown "?" "${d##*/}" explicit-source "$d"
    [[ -n $NEWID ]] || return 0
    case $fam in safari) add_source "$NEWID" safari tree "$d" ;; *) add_source "$NEWID" profile tree "$d" ;; esac
    if [[ $fam == chromium && -f ${d%/*}/Local\ State ]]; then add_source "$NEWID" root files1 "${d%/*}"; fi
    return 0
}
discover() {
    PROFILE_ROWS=(); SOURCE_ROWS=(); SEEN_PROFILE=(); PCOUNT=0
    local r os user home
    if (( ${#SOURCES_ARG[@]} )); then
        for r in "${SOURCES_ARG[@]}"; do [[ -d $r ]] || die $E_USAGE "--source is not a directory: $r"; detect_source_dir "$r"; done
        return 0
    fi
    for r in "${ROOTS[@]}"; do
        r=${r%/}
        while IFS=$'\t' read -r os user home; do
            log debug "scanning $os home $home"
            scan_home "$os" "$user" "$home"
        done < <(list_homes "$r")
        if (( OS_ARTIFACTS )) && [[ -z $BROWSER_SEL || ,${BROWSER_SEL,,}, == *,os,* ]] && [[ -d $r/Windows/Prefetch ]]; then
            add_profile os "Operating System (Windows)" windows SYSTEM prefetch known-path "$r/Windows/Prefetch"
            add_source "$NEWID" prefetch pfglob "$r/Windows/Prefetch"
        fi
        (( DEEP )) && deep_scan "$r"
    done
    if (( LIVE )) && [[ $HOST_OS != windows && -n ${HOME:-} && -d $HOME ]]; then
        case "$HOME" in /home/*|/root|/Users/*) ;; *) scan_home "$([[ $HOST_OS == macos ]] && echo macos || echo linux)" "${USER:-user}" "$HOME" ;; esac
    fi
    return 0
}
print_profiles() {
    local -a rows=()
    local row id fam br os user prof det path col nb=0 ns=0 sig=0
    local -A users=() browsers=()
    for row in "${PROFILE_ROWS[@]+"${PROFILE_ROWS[@]}"}"; do
        IFS=$'\t' read -r id fam br os user prof det path <<< "$row"
        ui_famcol "$fam"; col=$REPLY
        [[ $fam == os ]] && ns=$((ns+1)) || { nb=$((nb+1)); browsers[$br]=1; }
        users["$user@$os"]=1
        ui_trunc "$br" 28; br=$REPLY; ui_trunc "$prof" 18; prof=$REPLY
        local mark=""; [[ $det == known-path ]] || { mark=" ${C_SEC}${G_DIA}${C_R}"; sig=1; }
        rows+=("${C_DIM}$id${C_R}"$'\t'"${col}${G_INFO}${C_R} ${C_B}$br${C_R}$mark"$'\t'"$prof"$'\t'"${C_MUT}${user:--}${C_R}"$'\t'"$os"$'\t'"$path")
    done
    if (( ${#rows[@]} == 0 )); then ui_warnl "No browser profiles found ${C_DIM}(try --root, --source or --deep)${C_R}"; return 0; fi
    ui_table 5 "ID"$'\t'"BROWSER"$'\t'"PROFILE"$'\t'"USER"$'\t'"OS"$'\t'"PATH" "${rows[@]}"
    (( sig )) && printf '  %s%s%s %sfound by signature / explicit --source (not a known install path)%s\n' "$C_SEC" "$G_DIA" "$C_R" "$C_DIM" "$C_R" >&"$UI_FD"
    printf '  %s%d browser profile(s) %s %d browser(s) %s %d user context(s) %s %d OS artifact set(s)%s\n' "$C_MUT" "$nb" "$G_SEP" \
        "${#browsers[@]}" "$G_SEP" "${#users[@]}" "$G_SEP" "$ns" "$C_R" >&"$UI_FD"
}
default_roots() {
    (( ${#ROOTS[@]} )) && { LIVE=0; return 0; }
    LIVE=1
    case $HOST_OS in
        windows) local sd="${SYSTEMDRIVE:-C:}"; ROOTS=("$(cygpath -u "$sd\\" 2>/dev/null || echo /c)") ;;
        wsl) ROOTS=(""); [[ -d /mnt/c/Users ]] && ROOTS+=("/mnt/c") ;;
        *) ROOTS=("") ;;
    esac
}

# ------------------------------------------------------------------ case management
case_lock() {
    LOCK_DIR="$CASE_DIR/.lock"
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        LOCK_DIR=""
        die $E_ERR "case is locked by another BrowserForensics-X process ($(cat "$CASE_DIR/.lock/pid" 2>/dev/null || echo '?')); remove $CASE_DIR/.lock if stale"
    fi
    echo "$$" > "$LOCK_DIR/pid"
}
require_case() {
    [[ -n $CASE_DIR ]] || die $E_USAGE "--case DIR is required for '$CMD'"
    [[ -d $CASE_DIR ]] || die $E_USAGE "case directory not found: $CASE_DIR"
    CASE_DIR=$(abspath "$CASE_DIR")
    [[ -f $CASE_DIR/case.json && -f $CASE_DIR/profiles.tsv ]] || die $E_USAGE "$CASE_DIR is not a BrowserForensics-X case (missing case.json/profiles.tsv)"
    mkdir -p "$CASE_DIR/logs"
}
write_case_json() {  # status
    local roots="" r lim=""
    for r in "${ROOTS[@]+"${ROOTS[@]}"}"; do roots+="${roots:+,}$(jstr "${r:-/}")"; done
    for r in "${LIMITATIONS[@]+"${LIMITATIONS[@]}"}"; do lim+="${lim:+,}$(jstr "$r")"; done
    local rn=""; [[ ${#ROOTS[@]} -gt 0 ]] && rn=$(native_path "${ROOTS[0]:-/}")
    local mh=""; [[ -f $CASE_DIR/evidence/manifest.sha256 ]] && mh=$(cut -c1-64 "$CASE_DIR/evidence/manifest.sha256")
    {
        printf '{\n "tool": %s,\n "tool_version": %s,\n "case_id": %s,\n "examiner": %s,\n "notes": %s,\n' \
            "$(jstr "$BFX_NAME")" "$(jstr "$BFX_VERSION")" "$(jstr "$CASE_ID")" "$(jstr "$EXAMINER")" "$(jstr "$NOTES")"
        printf ' "status": %s,\n "created_utc": %s,\n "acquired_utc": %s,\n "host": %s,\n "host_os": %s,\n "run_user": %s,\n' \
            "$(jstr "$1")" "$(jstr "$CASE_CREATED")" "$(jstr "${ACQUIRED_UTC:-}")" "$(jstr "$(hostname 2>/dev/null || echo unknown)")" \
            "$(jstr "$HOST_OS")" "$(jstr "$RUN_USER")"
        printf ' "command_line": %s,\n "roots": [%s],\n "root": %s,\n "root_native": %s,\n "live": %s,\n' \
            "$(jstr "$CMDLINE")" "$roots" "$(jstr "${ROOTS[0]:-/}")" "$(jstr "$rn")" "$([[ $LIVE == 1 ]] && echo true || echo false)"
        printf ' "redaction": %s,\n "options": {"deep": %s, "no_cache": %s, "full": %s, "max_file_size": %s, "os_artifacts": %s, "browsers": %s},\n' \
            "$([[ $REDACT == 1 ]] && echo '"enabled"' || echo '"DISABLED"')" "$DEEP" "$NO_CACHE" "$FULL" "$MAX_FILE_SIZE" "$OS_ARTIFACTS" "$(jstr "$BROWSER_SEL")"
        printf ' "environment": {"bash": %s, "python": %s, "sqlite": %s, "hash_tool": %s, "gnu_find": %s},\n' \
            "$(jstr "$BASH_VERSION")" "$(jstr "${PY_VERSION:-absent}")" "$(jstr "${PY_SQLITE:-absent}")" "$(jstr "$HASH_TOOL")" "$GNU_FIND"
        printf ' "acquisition": {"files_ok": %s, "files_failed": %s, "files_skipped": %s, "bytes": %s},\n' "$ACQ_OK" "$ACQ_FAIL" "$ACQ_SKIP" "$ACQ_BYTES"
        printf ' "manifest_sha256": %s,\n "limitations": [%s]\n}\n' "$(jstr "$mh")" "$lim"
    } > "$CASE_DIR/case.json.tmp"
    mv -f "$CASE_DIR/case.json.tmp" "$CASE_DIR/case.json"
}
running_browsers() {
    local out=""
    case $HOST_OS in
        windows) out=$(tasklist //fo csv //nh 2>/dev/null | tr 'A-Z' 'a-z' | grep -oE '"(chrome|msedge|firefox|brave|opera|vivaldi|browser|thorium|librewolf|waterfox|iexplore)\.exe"' | sort -u | tr -d '"' | tr '\n' ' ') || true ;;
        *) out=$(ps -A -o comm= 2>/dev/null | grep -oiE '(chrome|chromium|msedge|microsoft-edge|firefox|brave|opera|vivaldi|safari|epiphany|qutebrowser)' | sort -u | tr '\n' ' ') || true ;;
    esac
    printf '%s' "$out"
}

# ------------------------------------------------------------------ acquisition
default_excludes() {
    EXCLUDES=()
    (( FULL )) && return 0
    EXCLUDES=("Code Cache" GPUCache ShaderCache GrShaderCache GraphiteDawnCache DawnCache DawnGraphiteCache DawnWebGPUCache
              component_crx_cache optimization_guide_model_store OnDeviceHeadSuggestModel screen_ai WidevineCdm SODA
              startupCache safebrowsing "Safe Browsing" BrowserMetrics)
    (( NO_CACHE )) && EXCLUDES+=(Cache cache2 CacheStorage ScriptCache "Media Cache" "Application Cache")
    return 0
}
PF_BROWSERS='^(CHROME|MSEDGE|FIREFOX|BRAVE|OPERA|LAUNCHER|VIVALDI|BROWSER|IEXPLORE|THORIUM|LIBREWOLF|WATERFOX|ARC|TOR|FLOORP|ZEN|WHALE|DRAGON)\.EXE-[0-9A-F]{8}\.pf$'

list_source_files() {  # src mode listfile  -> NUL list of "size\tmtime\tatime\tctime\tpath"
    local src=$1 mode=$2 out=$3
    local -a prune=() depth=()
    local n
    if [[ $mode == tree ]] && (( ${#EXCLUDES[@]} )); then
        prune=( \( -type d \( )
        for n in "${EXCLUDES[@]}"; do prune+=( -name "$n" -o ); done
        prune=( "${prune[@]:0:${#prune[@]}-1}" \) -prune \) -o )
    fi
    if [[ $mode == files1 || $mode == pfglob ]]; then depth=( -maxdepth 1 ); fi
    if [[ $mode == file ]]; then
        local f
        for f in "$src" "$src-wal" "$src-shm" "$src-journal"; do
            [[ -f $f ]] || continue
            if (( GNU_FIND )); then find "$f" -maxdepth 0 -printf '%s\t%T@\t%A@\t%C@\t%p\0'
            else printf '%s\t%s\t%s\t%s\t%s\0' "$(stat -f %z "$f")" "$(stat -f %m "$f")" "$(stat -f %a "$f")" "$(stat -f %c "$f")" "$f"; fi
        done > "$out"
        return 0
    fi
    if (( GNU_FIND )); then
        find "$src" "${depth[@]}" "${prune[@]}" \( -type f -o -type l \) -printf '%s\t%T@\t%A@\t%C@\t%p\0' 2>>"$TMP_DIR/find.err" > "$out" || true
    else
        find "$src" "${depth[@]}" "${prune[@]}" \( -type f -o -type l \) -print0 2>>"$TMP_DIR/find.err" | while IFS= read -r -d '' n; do
            printf '%s\t%s\t%s\t%s\t%s\0' "$(stat -f %z "$n")" "$(stat -f %m "$n")" "$(stat -f %a "$n")" "$(stat -f %c "$n")" "$n"
        done > "$out" || true
    fi
}
epoch_set() {  # epoch_set VAR "1700000000.123" -> ISO-8601 UTC (no fork)
    local e=${2%%.*} frac="" t
    if [[ $2 == *.* ]]; then frac=${2#*.}; frac=".${frac:0:6}"; fi
    if [[ $e =~ ^-?[0-9]+$ ]]; then printf -v t '%(%Y-%m-%dT%H:%M:%S)T' "$e"; printf -v "$1" '%s%sZ' "$t" "$frac"
    else printf -v "$1" '%s' ""; fi
}
sums_line() {  # hash relpath -> coreutils-compatible checksum line
    local h=$1 p=$2
    if [[ $p == *\* || $p == *$'\n'* ]]; then p=${p//\/\\}; p=${p//$'\n'/\n}; printf '\%s  %s\n' "$h" "$p"
    else printf '%s  %s\n' "$h" "$p"; fi
}
GNU_CP=-1
acquire_all() {  # acquire every row of SOURCE_ROWS with global batched hashing
    local all="$TMP_DIR/acq.paths" lst="$TMP_DIR/acq.list" pre="$TMP_DIR/acq.pre" post="$TMP_DIR/acq.post" cpl="$TMP_DIR/acq.copies"
    local -a EP=() EX=() ESZ=() EMT=() EAT=() ECT=() EC=() EST=() EERR=() SRC_ID=() SRC_ROLE=() SRC_MODE=() SRC_PATH=()
    local -A PRE=() POST=() CPERR=()
    local row id role mode src rec size mt at ct p rel n=0 i=0 k line
    local -a DSTDIRS=()
    if (( GNU_CP < 0 )); then if cp --version 2>/dev/null | grep -q GNU; then GNU_CP=1; else GNU_CP=0; fi; fi
    : > "$all"
    for row in "${SOURCE_ROWS[@]+"${SOURCE_ROWS[@]}"}"; do
        IFS=$'\t' read -r id role mode src <<< "$row"; src=${src%/}
        SRC_ID[i]=$id SRC_ROLE[i]=$role SRC_MODE[i]=$mode SRC_PATH[i]=$src
        if [[ ! -e $src ]]; then record_error acquisition "$id" "$src" "source vanished before acquisition"; i=$((i+1)); continue; fi
        log debug "listing $id [$role] $src"
        ui_progress "Scanning sources" $((i + 1)) "${#SOURCE_ROWS[@]}" "$id/$role"
        DSTDIRS+=("$CASE_DIR/evidence/$id/$role")
        list_source_files "$src" "$mode" "$lst"
        while IFS= read -r -d '' rec; do
            IFS=$'\t' read -r size mt at ct p <<< "$rec"
            [[ -n $p ]] || continue
            if [[ $mode == pfglob ]]; then [[ ${p##*/} =~ $PF_BROWSERS ]] || continue; fi
            if [[ $mode == file ]]; then rel=${p##*/}; else rel=${p#"$src"/}; fi
            EP[n]=$p EX[n]=$i ESZ[n]=$size EMT[n]=$mt EAT[n]=$at ECT[n]=$ct EC[n]="$CASE_DIR/evidence/$id/$role/$rel"
            printf '%s\0' "$p" >> "$all"; n=$((n+1))
        done < "$lst"
        i=$((i+1))
    done
    (( ${#DSTDIRS[@]} )) && mkdir -p -- "${DSTDIRS[@]}"
    ui_progress_end
    ui_ok "Inventoried ${C_B}$n${C_R} file(s) in ${#SOURCE_ROWS[@]} source location(s)"
    ui_progress "Hashing sources" 0 1 "SHA-256 $G_SEP $n file(s)"
    hash_nul_list "$all" "$pre"
    while IFS= read -r -d '' line; do PRE[${line#*$'\t'}]=${line%%$'\t'*}; done < "$pre"
    for ((k = 0; k < i; k++)); do : > "$TMP_DIR/acq.rel.$k"; done
    for ((k = 0; k < n; k++)); do
        p=${EP[k]}; EST[k]=ok; EERR[k]=""
        if [[ -L $p ]]; then
            EST[k]="skipped-symlink"; EERR[k]="target: $(readlink -- "$p" 2>/dev/null || echo '?')"; ACQ_SKIP=$((ACQ_SKIP+1))
        elif (( ${ESZ[k]:-0} > MAX_FILE_SIZE )); then
            EST[k]="skipped-size"; EERR[k]="size ${ESZ[k]} > --max-file-size $MAX_FILE_SIZE"; ACQ_SKIP=$((ACQ_SKIP+1))
        elif [[ -z ${PRE[$p]:-} ]]; then
            EST[k]="unreadable"; EERR[k]=$( (exec < "$p") 2>&1 ) || true
            EERR[k]=${EERR[k]:-"source could not be read (locked by another process or permission denied)"}; ACQ_FAIL=$((ACQ_FAIL+1))
        elif [[ ${SRC_MODE[EX[k]]} != file && $GNU_CP == 1 ]]; then
            rel=${p#"${SRC_PATH[EX[k]]}"/}; printf '%s\0' "$rel" >> "$TMP_DIR/acq.rel.${EX[k]}"
        else
            mkdir -p -- "${EC[k]%/*}"
            if ! EERR[k]=$(cp -p -- "$p" "${EC[k]}" 2>&1); then EST[k]="copy-failed"; ACQ_FAIL=$((ACQ_FAIL+1)); rm -f -- "${EC[k]}"; else EERR[k]=""; fi
        fi
    done
    for ((k = 0; k < i; k++)); do
        [[ -s $TMP_DIR/acq.rel.$k ]] || continue
        log debug "copying ${SRC_ID[k]} [${SRC_ROLE[k]}]"
        ui_progress "Copying" $((k + 1)) "$i" "${SRC_ID[k]}/${SRC_ROLE[k]}"
        ( cd -- "${SRC_PATH[k]}" && xargs -0 cp -p --parents -t "$CASE_DIR/evidence/${SRC_ID[k]}/${SRC_ROLE[k]}" -- < "$TMP_DIR/acq.rel.$k" ) 2> "$TMP_DIR/acq.cperr" || true
        while IFS= read -r line; do
            if [[ $line =~ ^cp:\ cannot\ [a-z\ ]+\ \'(.+)\'(\ for\ reading)?:\ (.*)$ ]]; then CPERR["$k|${BASH_REMATCH[1]}"]=${BASH_REMATCH[3]}; fi
        done < "$TMP_DIR/acq.cperr"
    done
    : > "$cpl"
    for ((k = 0; k < n; k++)); do
        [[ ${EST[k]} == ok ]] || continue
        if [[ -f ${EC[k]} ]]; then printf '%s\0' "${EC[k]}" >> "$cpl"
        else rel=${EP[k]#"${SRC_PATH[EX[k]]}"/}; EST[k]="copy-failed"; EERR[k]=${CPERR["${EX[k]}|$rel"]:-"copy missing after cp"}; ACQ_FAIL=$((ACQ_FAIL+1)); fi
    done
    ui_progress "Verifying copies" 0 1 "re-hashing every copy"
    hash_nul_list "$cpl" "$post"
    while IFS= read -r -d '' line; do POST[${line#*$'\t'}]=${line%%$'\t'*}; done < "$post"
    local hs hc relcase evid st err again j_ev j_id j_role j_src j_copy j_mt j_at j_ct j_hs j_hc j_st j_err j_now t1 t2 t3
    jset j_now "$(now_utc)"
    local pstep=$(( n / 60 + 1 ))
    for ((k = 0; k < n; k++)); do
        (( k % pstep == 0 )) && ui_progress "Sealing manifest" "$k" "$n"
        p=${EP[k]}; st=${EST[k]}; err=${EERR[k]}; hs=${PRE[$p]:-}; hc=""
        if [[ $st == ok ]]; then
            hc=${POST[${EC[k]}]:-}
            if [[ -z $hc ]]; then st="copy-unreadable"; ACQ_FAIL=$((ACQ_FAIL+1))
            elif [[ $hc != "$hs" ]]; then
                again=$(sha256_file "$p" 2>/dev/null || true)
                if [[ $again == "$hc" ]]; then st="source-changed-during-acquisition"; err="source hash before copy $hs; copy matches current source"
                else st="hash-mismatch"; err="source $hs / copy $hc / source-now ${again:-unreadable}"; fi
                ACQ_FAIL=$((ACQ_FAIL+1))
            else ACQ_OK=$((ACQ_OK+1)); ACQ_BYTES=$((ACQ_BYTES+${ESZ[k]:-0})); fi
        fi
        if [[ $st != ok ]]; then record_error acquisition "${SRC_ID[EX[k]]}" "$p" "$st $err"; fi
        EVSEQ=$((EVSEQ+1)); printf -v evid 'E%06d' "$EVSEQ"
        relcase=${EC[k]#"$CASE_DIR"/}
        epoch_set t1 "${EMT[k]}"; epoch_set t2 "${EAT[k]}"; epoch_set t3 "${ECT[k]}"
        jset j_ev "$evid"; jset j_id "${SRC_ID[EX[k]]}"; jset j_role "${SRC_ROLE[EX[k]]}"; jset j_src "$p"; jset j_copy "${hc:+$relcase}"
        jset j_mt "$t1"; jset j_at "$t2"; jset j_ct "$t3"; jset j_hs "$hs"; jset j_hc "$hc"; jset j_st "$st"; jset j_err "$err"
        printf '{"evidence_id":%s,"profile_id":%s,"role":%s,"source":%s,"copy":%s,"size":%s,"mtime_utc":%s,"atime_utc":%s,"ctime_utc":%s,"sha256_source":%s,"sha256_copy":%s,"status":%s,"error":%s,"acquired_utc":%s}\n' \
            "$j_ev" "$j_id" "$j_role" "$j_src" "$j_copy" "${ESZ[k]:-0}" "$j_mt" "$j_at" "$j_ct" "$j_hs" "$j_hc" "$j_st" "$j_err" "$j_now" >> "$CASE_DIR/evidence/manifest.jsonl"
        if [[ -n $hc ]]; then sums_line "$hc" "$relcase" >> "$CASE_DIR/evidence/SHA256SUMS"; fi
    done
    ui_progress_end
    rm -f -- "$all" "$lst" "$pre" "$post" "$cpl" "$TMP_DIR"/acq.rel.* "$TMP_DIR/acq.cperr"
}
print_profiles_compact() {  # step view inside acquire/run (stderr)
    ui_quiet && return 0
    local row id fam br os user prof det path n=0 total=${#PROFILE_ROWS[@]}
    for row in "${PROFILE_ROWS[@]+"${PROFILE_ROWS[@]}"}"; do
        n=$((n+1))
        if (( n > 14 )); then ui_note "$G_ELL and $((total - 14)) more (see profiles.tsv)"; break; fi
        IFS=$'\t' read -r id fam br os user prof det path <<< "$row"
        ui_famcol "$fam"; local col=$REPLY
        ui_trunc "$br" 32; ui_pad "$REPLY" 32; local b=$REPLY
        ui_trunc "$prof" 22; ui_pad "$REPLY" 22; local p=$REPLY
        printf '    %s%s%s %s%s%s  %s%s%s %s %s%s@%s%s\n' "$col" "$G_INFO" "$C_R" "$C_DIM" "$id" "$C_R" "$C_B" "$b" "$C_R" "$p" \
            "$C_MUT" "${user:--}" "$os" "$C_R" >&2
    done
}
cmd_acquire_impl() {
    [[ -n $CASE_DIR ]] || die $E_USAGE "--case DIR is required"
    [[ -n $HASH_TOOL ]] || die $E_DEPS "a SHA-256 tool is required (sha256sum, shasum or openssl)"
    if [[ -e $CASE_DIR ]]; then
        [[ -d $CASE_DIR ]] || die $E_USAGE "--case exists and is not a directory: $CASE_DIR"
        [[ -z $(ls -A -- "$CASE_DIR" 2>/dev/null) ]] || die $E_USAGE "case directory must be new or empty (refusing to mix evidence): $CASE_DIR"
    fi
    mkdir -p "$CASE_DIR"/{evidence,analysis,reports,logs} || die $E_ERR "cannot create case directory"
    CASE_DIR=$(abspath "$CASE_DIR")
    case_lock
    find_python || true
    ensure_tmp
    CASE_CREATED=$(now_utc)
    [[ -n $CASE_ID ]] || CASE_ID="BFX-$(date -u +%Y%m%d-%H%M%S)"
    default_roots
    local r; for r in "${ROOTS[@]}"; do [[ -z $r || -d $r ]] || die $E_USAGE "--root is not a directory: $r"; done
    write_case_json created
    audit "case_created" "case_id=$CASE_ID examiner=$EXAMINER tool=$BFX_NAME/$BFX_VERSION cmd=$CMDLINE"
    support_matrix > "$CASE_DIR/support_matrix.tsv"
    if (( LIVE )); then
        add_limitation "Live-system acquisition: files in use by running browsers may be locked, inconsistent or change during copy."
        local rb; rb=$(running_browsers)
        if [[ -n $rb ]]; then
            log warn "browser processes running on this host: $rb — databases may be locked or change during acquisition"
            add_limitation "Browsers were running during acquisition: $rb"
            audit "warning" "running browsers: $rb"
        fi
        if [[ $HOST_OS == macos ]]; then add_limitation "macOS TCC: Safari/Library data requires Full Disk Access for the terminal; unreadable files are listed as acquisition errors."; fi
        if [[ $HOST_OS == windows ]]; then add_limitation "Windows live acquisition does not use VSS; files locked by running processes cannot be copied (close browsers or acquire from an image/VSS snapshot)."; fi
    fi
    local rshow="${ROOTS[*]:-/}"; [[ -z ${ROOTS[0]:-x} ]] && rshow="/ (live system)"
    (( ${#SOURCES_ARG[@]} )) && rshow="${#SOURCES_ARG[@]} explicit source(s)"
    ui_next "Discovery" "$rshow"
    log debug "discovering browser profiles (roots: ${ROOTS[*]:-/})"
    discover
    if (( ${#PROFILE_ROWS[@]} )); then
        print_profiles_compact
        ui_ok "${C_B}${#PROFILE_ROWS[@]}${C_R} profile / artifact set(s) ${C_DIM}${G_SEP} ${#SOURCE_ROWS[@]} source location(s)${C_R}"
    else
        ui_warnl "No browser profiles found ${C_DIM}(try --root, --source or --deep)${C_R}"
    fi
    { printf '# id\tfamily\tbrowser\tos\tuser\tprofile\tdetection\tpath\n'; printf '%s\n' "${PROFILE_ROWS[@]+"${PROFILE_ROWS[@]}"}"; } > "$CASE_DIR/profiles.tsv"
    { printf '# id\trole\tmode\tpath\n'; printf '%s\n' "${SOURCE_ROWS[@]+"${SOURCE_ROWS[@]}"}"; } > "$CASE_DIR/sources.tsv"
    audit "discovery" "profiles=${#PROFILE_ROWS[@]} sources=${#SOURCE_ROWS[@]}"
    default_excludes
    (( ${#EXCLUDES[@]} )) && add_limitation "Excluded from acquisition by default (low evidentiary value / binary caches): ${EXCLUDES[*]} (use --full to include)."
    : > "$CASE_DIR/evidence/manifest.jsonl"; : > "$CASE_DIR/evidence/SHA256SUMS"
    ui_next "Acquisition" "SHA-256 source ${G_ARR} copy ${G_SEP} manifest ${G_SEP} read-only evidence"
    acquire_all
    ACQUIRED_UTC=$(now_utc)
    sha256_file "$CASE_DIR/evidence/manifest.jsonl" | sed 's|$|  evidence/manifest.jsonl|' > "$CASE_DIR/evidence/manifest.sha256"
    sha256_file "$CASE_DIR/evidence/SHA256SUMS" | sed 's|$|  evidence/SHA256SUMS|' >> "$CASE_DIR/evidence/manifest.sha256"
    (( ACQ_FAIL )) && add_limitation "$ACQ_FAIL file(s) could not be acquired or changed during acquisition (see errors.jsonl / manifest status)."
    chmod -R a-w "$CASE_DIR/evidence" 2>/dev/null || true
    write_case_json acquired
    audit "acquisition_complete" "ok=$ACQ_OK failed=$ACQ_FAIL skipped=$ACQ_SKIP bytes=$ACQ_BYTES manifest_sha256=$(cut -c1-64 "$CASE_DIR/evidence/manifest.sha256" | head -n1)"
    log debug "acquisition: $ACQ_OK file(s) OK, $ACQ_FAIL failed, $ACQ_SKIP skipped, $ACQ_BYTES bytes"
    ui_bytes "$ACQ_BYTES"
    ui_ok "${C_B}$ACQ_OK${C_R} file(s) acquired and verified ${C_DIM}${G_SEP} $REPLY ${G_SEP} copies match source hashes${C_R}"
    (( ACQ_SKIP )) && ui_info "$ACQ_SKIP file(s) skipped and recorded ${C_DIM}(symlinks / --max-file-size)${C_R}"
    (( ACQ_FAIL )) && ui_warnl "${C_B}$ACQ_FAIL${C_R} file(s) not acquired or changed during copy ${C_DIM}(locked / unreadable — see errors.jsonl)${C_R}"
    ui_ok "Manifest sealed ${C_DIM}${G_SEP} sha256 $(cut -c1-16 "$CASE_DIR/evidence/manifest.sha256" | head -n1)${G_ELL} ${G_SEP} evidence set read-only${C_R}"
}

# ------------------------------------------------------------------ analysis
cmd_analyze_impl() {
    require_case; require_python
    if [[ -z ${LOCK_DIR:-} ]]; then case_lock; fi
    [[ -s $CASE_DIR/evidence/manifest.jsonl ]] || die $E_USAGE "case has no acquired evidence"
    mkdir -p "$CASE_DIR/analysis" "$CASE_DIR/work"
    chmod u+w "$CASE_DIR/analysis" 2>/dev/null || true
    local -a ids=()
    local line
    while IFS=$'\t' read -r line _; do [[ -z $line || $line == \#* ]] || ids+=("$line"); done < "$CASE_DIR/profiles.tsv"
    local jobs=$JOBS
    (( jobs > 0 )) || jobs=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
    (( jobs > 8 )) && jobs=8
    audit "analysis_start" "profiles=${#ids[@]} jobs=$jobs redaction=$REDACT recover=$RECOVER"
    (( REDACT )) || { log warn "REDACTION DISABLED: secrets and personal data will appear in analysis output and reports"; audit "warning" "redaction disabled by examiner"; }
    log debug "analyzing ${#ids[@]} profile(s) with up to $jobs parallel job(s)"
    ui_next "Analysis" "${#ids[@]} profile(s) ${G_SEP} $jobs parallel worker(s) ${G_SEP} redaction $([[ $REDACT == 1 ]] && echo on || echo OFF)"
    rm -f "$CASE_DIR"/logs/analyze_*.rc
    local total=${#ids[@]}
    _ap() { local f=("$CASE_DIR"/logs/analyze_*.rc); ui_progress "Parsing profiles" "${#f[@]}" "$total" "parsers ${G_SEP} carving ${G_SEP} LevelDB ${G_SEP} SNSS"; }
    local id
    local -a extra=()
    (( RECOVER )) || extra+=(--no-recover)
    (( KEEP_WORK )) && extra+=(--keep-work)
    for id in "${ids[@]+"${ids[@]}"}"; do
        while (( $(jobs -rp | wc -l) >= jobs )); do wait -n 2>/dev/null || true; _ap; done
        (
            rc=0
            engine analyze --case "$(native_path "$CASE_DIR")" --profile "$id" --redact "$REDACT" "${extra[@]+"${extra[@]}"}" \
                > "$CASE_DIR/logs/analyze_$id.out" 2> "$CASE_DIR/logs/analyze_$id.err" || rc=$?
            echo "$rc" > "$CASE_DIR/logs/analyze_$id.rc"
        ) &
        _ap
    done
    while (( $(jobs -rp | wc -l) > 0 )); do wait -n 2>/dev/null || true; _ap; done
    _ap; ui_progress_end
    local failed=0 partial=0 rc
    for id in "${ids[@]+"${ids[@]}"}"; do
        rc=$(cat "$CASE_DIR/logs/analyze_$id.rc" 2>/dev/null || echo 99)
        case $rc in
            0) log debug "$id analyzed: $(cat "$CASE_DIR/logs/analyze_$id.out" 2>/dev/null)" ;;
            5) partial=$((partial+1)); log warn "$id analyzed with parser errors (partial): $(cat "$CASE_DIR/logs/analyze_$id.out" 2>/dev/null)" ;;
            *) failed=$((failed+1)); log error "$id analysis failed (rc=$rc): $(tail -n 3 "$CASE_DIR/logs/analyze_$id.err" 2>/dev/null | tr '\n' ' ')"
               record_error analysis "$id" "engine" "analysis failed rc=$rc" ;;
        esac
    done
    local -a mextra=()
    (( FS_CORR )) || mextra+=(--no-fs-correlation)
    if (( failed == 0 && partial == 0 )); then ui_ok "${C_B}${#ids[@]}${C_R} profile(s) parsed without parser errors"
    else ui_warnl "${#ids[@]} profile(s) parsed ${G_SEP} $partial partial ${G_SEP} $failed failed ${C_DIM}(see report Errors section)${C_R}"; fi
    ui_progress "Correlating" 0 1 "timeline ${G_SEP} downloads ${G_SEP} OS artifacts ${G_SEP} findings"
    engine merge --case "$(native_path "$CASE_DIR")" "${mextra[@]+"${mextra[@]}"}" > "$CASE_DIR/logs/merge.out" 2> "$CASE_DIR/logs/merge.err" \
        || { record_error analysis "" merge "merge failed: $(tail -n 2 "$CASE_DIR/logs/merge.err" | tr '\n' ' ')"; die $E_ERR "merge failed (see logs/merge.err)"; }
    audit "analysis_complete" "profiles=${#ids[@]} partial=$partial failed=$failed summary=$(cat "$CASE_DIR/logs/merge.out")"
    ui_progress_end
    local mo; mo=$(cat "$CASE_DIR/logs/merge.out")
    local mr=0 me=0 mf=0
    [[ $mo =~ \"records\":\ ([0-9]+) ]] && mr=${BASH_REMATCH[1]}
    [[ $mo =~ \"events\":\ ([0-9]+) ]] && me=${BASH_REMATCH[1]}
    [[ $mo =~ \"findings\":\ ([0-9]+) ]] && mf=${BASH_REMATCH[1]}
    ui_ok "Unified UTC timeline ${C_DIM}${G_SEP}${C_R} ${C_B}$me${C_R} events from ${C_B}$mr${C_R} records"
    ui_ok "Correlation and consistency checks ${C_DIM}${G_SEP}${C_R} ${C_B}$mf${C_R} finding(s)"
    ANALYSIS_PARTIAL=$((partial+failed))
}
filter_args() {
    FARGS=()
    [[ -n $F_SINCE ]] && FARGS+=(--since "$F_SINCE"); [[ -n $F_UNTIL ]] && FARGS+=(--until "$F_UNTIL")
    [[ -n $F_DOMAIN ]] && FARGS+=(--domain "$F_DOMAIN"); [[ -n $F_TYPE ]] && FARGS+=(--type "$F_TYPE")
    [[ -n $F_BROWSER ]] && FARGS+=(--browser "$F_BROWSER"); [[ -n $F_PROFILE ]] && FARGS+=(--profile-filter "$F_PROFILE")
    if [[ -n $F_CLASS ]]; then FARGS+=(--evidence-class "$F_CLASS"); fi
    return 0
}
cmd_report_impl() {
    require_case; require_python
    if [[ -z ${LOCK_DIR:-} ]]; then case_lock; fi
    [[ -f $CASE_DIR/analysis/summary.json ]] || die $E_USAGE "case not analyzed yet (run: analyze --case $CASE_DIR)"
    filter_args
    local out=$OUT_DIR
    if [[ -z $out ]]; then
        out="$CASE_DIR/reports"
        (( ${#FARGS[@]} )) && out="$CASE_DIR/reports/filtered_$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    mkdir -p "$out"; out=$(abspath "$out")
    ui_next "Reporting" "${FORMATS//,/ $G_SEP } ${G_SEP} SHA-256 sealed"
    ui_progress "Rendering" 0 1 "${FORMATS}"
    engine report --case "$(native_path "$CASE_DIR")" --out "$(native_path "$out")" --formats "$FORMATS" "${FARGS[@]+"${FARGS[@]}"}" \
        > "$CASE_DIR/logs/report.out" 2> "$CASE_DIR/logs/report.err" || die $E_ERR "report generation failed: $(tail -n 3 "$CASE_DIR/logs/report.err")"
    ( cd "$out" && find . -type f ! -name SHA256SUMS -print0 | sort -z | while IFS= read -r -d '' f; do
        sums_line "$(sha256_file "$f")" "${f#./}"; done > SHA256SUMS )
    audit "report" "out=${out#"$CASE_DIR"/} formats=$FORMATS filters=${FARGS[*]:-none} sha256sums=$(sha256_file "$out/SHA256SUMS")"
    ui_progress_end
    local f lab sz
    for f in report.html report.json report.md csv; do
        [[ -e $out/$f ]] || continue
        case $f in report.html) lab="HTML" ;; report.json) lab="JSON" ;; report.md) lab="Markdown" ;; csv) lab="CSV" ;; esac
        if [[ -f $out/$f ]]; then ui_bytes "$(wc -c < "$out/$f")"; sz=$REPLY; else local cf=("$out"/csv/*.csv); sz="${#cf[@]} files"; fi
        ui_pad "$lab" 9; local l9=$REPLY
        ui_fileurl "$out/$f"; local u=$REPLY; ui_link "$u" "${out#"$CASE_DIR"/}/$f"
        ui_ok "${C_B}$l9${C_R} $REPLY ${C_DIM}${G_SEP} $sz${C_R}"
    done
    REPORT_OUT=$out
    [[ $QUIET == 1 || $CMD == run ]] || printf '%s\n' "$out"
    return 0
}
cmd_timeline_impl() {
    require_case; require_python
    [[ -f $CASE_DIR/analysis/timeline.jsonl ]] || die $E_USAGE "case not analyzed yet"
    filter_args
    BFX_COLS=$UI_COLS BFX_COLOR=$(( UI_OUT && UI_DEPTH > 0 ? 1 : 0 )) engine timeline --case "$(native_path "$CASE_DIR")" --format "$TL_FORMAT" --limit "$TL_LIMIT" "${FARGS[@]+"${FARGS[@]}"}"
}

ui_run_summary() {
    ui_quiet && return 0
    local -A S=()
    local k v
    while IFS='=' read -r k v; do [[ -n $k ]] && S[$k]=$v; done < <(engine stats --case "$(native_path "$CASE_DIR")" 2>/dev/null || true)
    ui_bytes "$ACQ_BYTES"; local by=$REPLY
    ui_dur $(( SECONDS - RUN_T0 )); local dur=$REPLY
    bk() { ui_pad "$1" 11; REPLY="${C_MUT}$REPLY${C_R} $2"; }
    local -a L=()
    bk "Examiner" "$EXAMINER"; L+=("$REPLY")
    bk "Sources" "${C_B}${S[profiles_browser]:-0}${C_R} browser profile(s) ${C_DIM}${G_SEP}${C_R} ${S[profiles_os]:-0} OS artifact set(s)"; L+=("$REPLY")
    local fc=$C_OK; (( ACQ_FAIL )) && fc=$C_WARN
    bk "Evidence" "${C_B}$ACQ_OK${C_R} files ${C_DIM}${G_SEP}${C_R} $by ${C_DIM}${G_SEP}${C_R} ${fc}$ACQ_FAIL failed${C_R} ${C_DIM}${G_SEP} $ACQ_SKIP skipped${C_R}"; L+=("$REPLY")
    if [[ -n ${S[time_from]:-} ]]; then bk "Activity" "${S[time_from]:0:16} ${C_DIM}${G_ARR}${C_R} ${S[time_to]:0:16} ${C_DIM}UTC${C_R}"; L+=("$REPLY"); fi
    bk "Timeline" "${C_B}${S[events]:-0}${C_R} events ${C_DIM}${G_SEP}${C_R} ${S[records]:-0} records"; L+=("$REPLY")
    bk "Classes" "${C_OK}${G_INFO}${C_R} ${S[observed]:-0} observed  ${C_WARN}${G_INFO}${C_R} ${S[recovered]:-0} recovered  ${C_SEC}${G_INFO}${C_R} ${S[inferred]:-0} inferred"; L+=("$REPLY")
    bk "Findings" "${C_ERR}${G_INFO}${C_R} ${S[high]:-0} high  ${C_WARN}${G_INFO}${C_R} ${S[medium]:-0} medium  ${C_OK}${G_INFO}${C_R} ${S[low]:-0} low  ${C_MUT}${G_INFO}${C_R} ${S[info]:-0} info"; L+=("$REPLY")
    bk "Duration" "$dur"; L+=("$REPLY")
    printf '\n' >&2
    ui_box "$C_PRI" "CASE ${CASE_ID}" "${L[@]}" >&2
    local self=${BFX_SELF##*/}
    printf '\n' >&2
    if (( ACQ_FAIL || ANALYSIS_PARTIAL )); then printf '  %s%s Completed with partial results%s %sin %s%s\n' "$C_WARN$C_B" "$G_WARN" "$C_R" "$C_DIM" "$dur" "$C_R" >&2
    else printf '  %s%s Case ready%s %sin %s%s\n' "$C_OK$C_B" "$G_OK" "$C_R" "$C_DIM" "$dur" "$C_R" >&2; fi
    if [[ -n ${REPORT_OUT:-} && -f $REPORT_OUT/report.html ]]; then
        ui_fileurl "$REPORT_OUT/report.html"; local u=$REPLY; ui_link "$u" "$REPORT_OUT/report.html"
        printf '    %s%s%s %sOpen%s     %s\n' "$C_PRI" "$G_ARR" "$C_R" "$C_MUT" "$C_R" "$REPLY" >&2
    fi
    printf '    %s%s%s %sVerify%s   %s verify -c %s\n' "$C_PRI" "$G_ARR" "$C_R" "$C_MUT" "$C_R" "$self" "$CASE_DIR" >&2
    printf '    %s%s%s %sExplore%s  %s timeline -c %s --since %s\n\n' "$C_PRI" "$G_ARR" "$C_R" "$C_MUT" "$C_R" "$self" "$CASE_DIR" "${S[time_from]:0:10}" >&2
}

# ------------------------------------------------------------------ verification
sums_check() {  # file (run inside case dir)
    case $HASH_TOOL in
        sha256sum) sha256sum -c --quiet -- "$1" ;;
        shasum) shasum -a 256 -c --quiet -- "$1" ;;
        *) local h p bad=0; while IFS= read -r l; do h=${l:0:64}; p=${l:66}; [[ $(sha256_file "$p") == "$h" ]] || { echo "$p: FAILED"; bad=1; }; done < "$1"; return $bad ;;
    esac
}
cmd_verify_impl() {
    [[ -n $CASE_DIR && -d $CASE_DIR ]] || die $E_USAGE "--case DIR is required"
    CASE_DIR=$(abspath "$CASE_DIR")
    [[ -n $HASH_TOOL ]] || die $E_DEPS "no SHA-256 tool"
    ui_to_stdout
    local bad=0 out n
    STEP_TOTAL=1
    ui_section "Integrity verification" "${CASE_DIR}"
    if [[ -f $CASE_DIR/evidence/manifest.sha256 ]]; then
        if out=$(cd "$CASE_DIR" && sums_check evidence/manifest.sha256 2>&1); then ui_ok "Manifest and checksum list unchanged ${C_DIM}evidence/manifest.jsonl ${G_SEP} SHA256SUMS${C_R}"
        else ui_bad "Manifest / checksum list altered: $out"; bad=1; fi
    else ui_bad "evidence/manifest.sha256 missing"; bad=1; fi
    if [[ -f $CASE_DIR/evidence/SHA256SUMS ]]; then
        n=$(grep -c . "$CASE_DIR/evidence/SHA256SUMS" || true)
        if out=$(cd "$CASE_DIR" && sums_check evidence/SHA256SUMS 2>&1); then ui_ok "${C_B}$n${C_R} evidence file(s) match their recorded SHA-256"
        else ui_bad "Evidence hash mismatch:"; printf '%s\n' "$out" | head -n 20 | sed "s/^/        ${C_ERR}${G_ARR}${C_R} /" >&"$UI_FD"; bad=1; fi
        local extra
        extra=$(cd "$CASE_DIR" && comm -13 <(sed -E 's/^\\?[0-9a-f]{64}  //' evidence/SHA256SUMS | sort) \
                <(find evidence -type f ! -name SHA256SUMS ! -name manifest.jsonl ! -name manifest.sha256 | sort) | head -n 20)
        if [[ -n $extra ]]; then ui_bad "Files present in evidence/ but not in the manifest:"; printf '%s\n' "$extra" | sed "s/^/        ${C_ERR}${G_ARR}${C_R} /" >&"$UI_FD"; bad=1
        else ui_ok "No unregistered files in evidence/"; fi
    fi
    if out=$(verify_audit_chain "$CASE_DIR/audit.log"); then ui_ok "Audit log: $out"; else ui_bad "Audit log: $out"; bad=1; fi
    local d
    for d in "$CASE_DIR"/reports "$CASE_DIR"/reports/filtered_*; do
        [[ -f $d/SHA256SUMS ]] || continue
        if out=$(cd "$d" && sums_check SHA256SUMS 2>&1); then ui_ok "Reports unchanged ${C_DIM}${d#"$CASE_DIR"/}${C_R}"
        else ui_bad "Report files altered in ${d#"$CASE_DIR"/}: $out"; bad=1; fi
    done
    if [[ -n ${LOCK_DIR:-} || -w $CASE_DIR ]]; then audit "verify" "result=$([[ $bad == 0 ]] && echo PASS || echo FAIL)"; fi
    printf '\n' >&"$UI_FD"
    if (( bad )); then
        ui_box "$C_ERR" "INTEGRITY FAILURE" "${C_ERR}${G_ERR}${C_R} ${C_B}RESULT: FAIL${C_R}  evidence, manifest, audit log or reports differ from what was recorded"
        return $E_INTEGRITY
    fi
    ui_box "$C_OK" "INTEGRITY VERIFIED" "${C_OK}${G_OK}${C_R} ${C_B}RESULT: PASS${C_R}  every hash, the manifest and the audit chain match"
}

# ------------------------------------------------------------------ self-test
tree_snapshot() {  # dir -> sorted "sha256  size  mtime  path" lines (detects any change to lab sources)
    ( cd "$1" && find . -type f -print0 | sort -z | while IFS= read -r -d '' f; do
        if (( GNU_FIND )); then printf '%s  %s\n' "$(sha256_file "$f")" "$(find "$f" -maxdepth 0 -printf '%s %T@ %p')"
        else printf '%s  %s %s %s\n' "$(sha256_file "$f")" "$(stat -f %z "$f")" "$(stat -f %m "$f")" "$f"; fi
    done )
}
cmd_selftest_impl() {
    require_python
    ui_to_stdout
    local st="$TMP_DIR/selftest" lab case2 rc out t0=$SECONDS
    mkdir -p "$st"; lab="$st/lab"; local case="$st/case"; case2="$st/case_nopy"
    local pass=0 fail=0 gname="" gp=0 gf=0 gi=0
    local -a gfails=()
    STEP_TOTAL=5
    _st_flush() {
        [[ -n $gname ]] || return 0
        (( UI_OUT )) && printf '\r\033[K' >&"$UI_FD"
        local tot=$((gp + gf)) dots
        ui_vlen "$gname"; local lw=$(( UI_COLS < 84 ? UI_COLS : 84 )); ui_rep "$G_SEP" $(( lw - UI_N - 22 > 3 ? lw - UI_N - 22 : 3 )); dots=$REPLY
        if (( gf == 0 )); then printf '    %s%s%s %s %s%s%s %s%d/%d%s\n' "$C_OK" "$G_OK" "$C_R" "$gname" "$C_DIM" "$dots" "$C_R" "$C_OK" "$gp" "$tot" "$C_R" >&"$UI_FD"
        else
            printf '    %s%s%s %s %s%s%s %s%d/%d%s\n' "$C_ERR" "$G_ERR" "$C_R" "$gname" "$C_DIM" "$dots" "$C_R" "$C_ERR" "$gp" "$tot" "$C_R" >&"$UI_FD"
            local f; for f in "${gfails[@]}"; do printf '        %s%s %s%s\n' "$C_ERR" "$G_ARR" "$f" "$C_R" >&"$UI_FD"; done
        fi
        gname=""
    }
    grp() {
        _st_flush; gi=$((gi + 1)); gname=$1; gp=0; gf=0; gfails=()
        ui_step "$gi" "$1" "${2:-}"
        (( UI_OUT )) && printf '    %s%s%s %srunning%s %s' "$C_PRI" "$G_HALF" "$C_R" "$C_DIM" "$C_R" "$1" >&"$UI_FD"
        return 0
    }
    _res() {  # ok name [info]
        if (( $1 )); then pass=$((pass+1)); gp=$((gp+1)); [[ $LOG_LEVEL == debug ]] && { (( UI_OUT )) && printf '\r\033[K' >&"$UI_FD"; printf '      %s%s%s %s%s%s\n' "$C_OK" "$G_OK" "$C_R" "$C_DIM" "$2" "$C_R" >&"$UI_FD"; }
        else fail=$((fail+1)); gf=$((gf+1)); gfails+=("$2${3:+  ${C_DIM}$3${C_R}}"); fi
        return 0
    }
    t() {  # name, command...
        local name=$1; shift
        if "$@" >/dev/null 2>&1; then _res 1 "$name"; else _res 0 "$name"; fi
    }
    count_engine() {  # parse PASS/FAIL lines of engine output
        local l n
        while IFS= read -r l; do
            case $l in
                PASS*) n=${l#PASS  }; _res 1 "${n#unit:}" ;;
                FAIL*) n=${l#FAIL  }; _res 0 "${n%%  -> *}" "$([[ $n == *"  -> "* ]] && printf '%s' "${n#*  -> }")" ;;
            esac
        done <<< "$1"
    }
    grp "Unit tests" "decoders · time conversion · redaction · escaping"
    out=$(engine unit 2>&1) || true
    count_engine "$out"
    grp "Laboratory" "synthetic Linux / Windows / macOS layouts · 7 browsers"
    if engine labgen --root "$(native_path "$lab")" >/dev/null; then _res 1 "lab artifacts generated"; else _res 0 "lab generation"; _st_flush; die $E_ERR "lab generation failed"; fi
    local before after; before=$(tree_snapshot "$lab")
    grp "Pipeline" "run --root <lab> — acquire · analyze · report"
    rc=0
    BFX_NO_BANNER=1 "$BASH" "$BFX_SELF" run --root "$lab" --case "$case" --examiner selftest --case-id SELFTEST --jobs 4 --quiet > "$st/run.out" 2>&1 || rc=$?
    t "pipeline completes (exit 0)" test "$rc" -eq 0
    after=$(tree_snapshot "$lab")
    t "sources unchanged by acquisition/analysis (content + mtime)" test "$before" == "$after"
    if (( rc != 0 )); then _st_flush; sed 's/^/        /' "$st/run.out" | tail -n 25 >&"$UI_FD"; fi
    grp "Engine assertions" "parsers · recovery · correlation · redaction · reports"
    out=$(engine selfcheck --case "$(native_path "$case")" 2>&1) || true
    count_engine "$out"
    grp "CLI & integrity" "filters · validation · locking · tamper detection · preservation"
    t "verify passes on intact case" "$BASH" "$BFX_SELF" verify --case "$case"
    t "Code Cache excluded from acquisition" bash -c '! find "$1/evidence" -path "*Code Cache*" | grep -q .' _ "$case"
    t "only browser prefetch files acquired" bash -c 'find "$1/evidence" -name "*.pf" | grep -q MSEDGE && ! find "$1/evidence" -name "NOTEPAD*" | grep -q .' _ "$case"
    t "evidence copies preserve source mtime" bash -c 'a=$(find "$1" -path "*google-chrome/Default/History" -newer "$2/case.json" | wc -l); [ "$a" -eq 0 ]' _ "$case/evidence" "$case"
    t "manifest records source+copy SHA-256 for every acquired file" bash -c '! grep -q "\"status\":\"ok\"" "$1" || ! grep "\"status\":\"ok\"" "$1" | grep -q "\"sha256_copy\":\"\""' _ "$case/evidence/manifest.jsonl"
    out=$("$BASH" "$BFX_SELF" timeline --case "$case" --domain example.com --format csv 2>/dev/null) || true
    t "timeline --domain filter" bash -c '[ "$(printf "%s\n" "$1" | tail -n +2 | wc -l)" -gt 0 ] && ! printf "%s\n" "$1" | tail -n +2 | cut -d, -f9 | grep -vqE "(^|\.)example\.com$"' _ "$out"
    out=$("$BASH" "$BFX_SELF" timeline --case "$case" --since 2024-03-16 --until 2024-03-16 --format csv 2>/dev/null) || true
    t "timeline --since/--until filter (UTC day)" bash -c '[ "$(printf "%s\n" "$1" | tail -n +2 | wc -l)" -gt 0 ] && ! printf "%s\n" "$1" | tail -n +2 | grep -vq "^2024-03-16T"' _ "$out"
    "$BASH" "$BFX_SELF" report --case "$case" --type history --browser firefox --formats json --out "$st/rep_hist" --quiet >/dev/null 2>&1 || true
    t "filtered report (--type/--browser)" "$PY" -I -c 'import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
a=d["artifacts"]
assert list(a)==["history"] and all("Firefox" in r["browser"] for r in a["history"]) and d["filters"]["type"]==["history"]' "$(native_path "$st/rep_hist/report.json")"
    t "CLI: unknown option -> exit 2" bash -c '"$1" "$2" analyze --bogus >/dev/null 2>&1; [ $? -eq 2 ]' _ "$BASH" "$BFX_SELF"
    t "CLI: invalid date -> exit 2" bash -c '"$1" "$2" timeline --case "$3" --since 2024-13-40 >/dev/null 2>&1; [ $? -eq 2 ]' _ "$BASH" "$BFX_SELF" "$case"
    t "CLI: invalid --jobs -> exit 2" bash -c '"$1" "$2" analyze --case "$3" --jobs abc >/dev/null 2>&1; [ $? -eq 2 ]' _ "$BASH" "$BFX_SELF" "$case"
    t "CLI: missing --case -> exit 2" bash -c '"$1" "$2" analyze >/dev/null 2>&1; [ $? -eq 2 ]' _ "$BASH" "$BFX_SELF"
    t "CLI: refuses non-empty case dir for acquisition" bash -c '"$1" "$2" acquire --root "$3" --case "$4" >/dev/null 2>&1; [ $? -eq 2 ]' _ "$BASH" "$BFX_SELF" "$lab" "$case"
    t "CLI: plain output when piped (no ANSI escapes)" bash -c '! env -u BFX_FORCE_TTY -u BFX_COLOR_DEPTH "$1" "$2" matrix 2>&1 | grep -q $'"'"'\033'"'"'' _ "$BASH" "$BFX_SELF"
    t "CLI: ASCII fallback (BFX_ASCII=1)" bash -c '! env -u BFX_FORCE_TTY -u BFX_COLOR_DEPTH BFX_ASCII=1 "$1" "$2" help 2>&1 | LC_ALL=C grep -q "[^[:print:][:space:]]"' _ "$BASH" "$BFX_SELF"
    mkdir "$case/.lock"; echo 99999 > "$case/.lock/pid"
    t "case lock prevents concurrent analysis" bash -c '"$1" "$2" analyze --case "$3" >/dev/null 2>&1; [ $? -eq 1 ]' _ "$BASH" "$BFX_SELF" "$case"
    rm -rf "$case/.lock"
    rc=0; BFX_NO_PYTHON=1 "$BASH" "$BFX_SELF" acquire --root "$lab" --case "$case2" --quiet >/dev/null 2>&1 || rc=$?
    t "acquisition works without Python (pure Bash + coreutils)" test "$rc" -eq 0
    t "verify passes on Python-less acquisition" "$BASH" "$BFX_SELF" verify --case "$case2"
    t "analysis refuses to run without Python (exit 3)" bash -c 'BFX_NO_PYTHON=1 "$1" "$2" analyze --case "$3" >/dev/null 2>&1; [ $? -eq 3 ]' _ "$BASH" "$BFX_SELF" "$case2"
    local victim; victim=$(find "$case2/evidence" -type f -name History | head -n 1); [[ -n $victim ]] || victim="$case2/evidence/manifest.jsonl"
    chmod u+w "$victim" "${victim%/*}" 2>/dev/null || true; printf 'X' >> "$victim"
    t "verify detects modified evidence (exit 4)" bash -c '"$1" "$2" verify --case "$3" >/dev/null 2>&1; [ $? -eq 4 ]' _ "$BASH" "$BFX_SELF" "$case2"
    sed -i.bak '2s/acquisition/ACQUISITION/' "$case/audit.log" 2>/dev/null || true; rm -f "$case/audit.log.bak"
    sed -i.bak '1s/case_created/case_CREATED/' "$case/audit.log" 2>/dev/null || true; rm -f "$case/audit.log.bak"
    t "verify detects altered audit log (exit 4)" bash -c '"$1" "$2" verify --case "$3" >/dev/null 2>&1; [ $? -eq 4 ]' _ "$BASH" "$BFX_SELF" "$case"
    _st_flush
    chmod -R u+w "$st" 2>/dev/null || true
    local tot=$((pass + fail)) w=40 fill bar i
    ui_dur $(( SECONDS - t0 )); local dur=$REPLY
    fill=$(( tot ? pass * w / tot : 0 )); bar=""
    for ((i = 0; i < w; i++)); do if (( i < fill )); then bar+="${UI_BARG[i*28/w]}$G_BLK"; else bar+="$C_ERR$G_BLK"; fi; done
    printf '\n' >&"$UI_FD"
    if (( fail == 0 )); then
        ui_box "$C_OK" "SELFTEST PASSED" "${C_OK}${G_OK}${C_R} ${C_B}$pass${C_R}/${tot} checks passed  ${C_DIM}${G_SEP} $dur${C_R}" "$bar$C_R"
    else
        ui_box "$C_ERR" "SELFTEST FAILED" "${C_ERR}${G_ERR}${C_R} ${C_B}$fail${C_R} of $tot checks failed  ${C_DIM}${G_SEP} $dur${C_R}" "$bar$C_R"
    fi
    printf '  %sSELFTEST SUMMARY: %d passed, %d failed%s\n' "$C_DIM" "$pass" "$fail" "$C_R" >&"$UI_FD"
    if (( KEEP_TMP )); then ui_note "artifacts kept in $st"; fi
    (( fail == 0 )) || return $E_ERR
}

# ------------------------------------------------------------------ help
usage() {
    ui_to_stdout
    local fd=$UI_FD
    h() { printf '\n  %s%s%s\n' "$C_B$C_SEC" "$1" "$C_R" >&"$fd"; }
    c() { ui_pad "$C_PRI$C_B$1$C_R" 13; printf '    %s %s%s%s %s\n' "$REPLY" "$C_DIM" "$G_ARR" "$C_R" "$2" >&"$fd"; }
    o() { ui_pad "$C_PRI$1$C_R ${C_SEC}${2}$C_R" 30; printf '    %s %s\n' "$REPLY" "$3" >&"$fd"; }
    x() { printf '    %s%s\n' "$C_DIM#" " $1$C_R" >&"$fd"; printf '    %s$%s %s\n\n' "$C_ACC" "$C_R" "$2" >&"$fd"; }
    ui_banner "$fd"
    printf '  %sUsage%s  %s%s%s %s<command>%s %s[options]%s\n' "$C_MUT" "$C_R" "$C_B" "${BFX_SELF##*/}" "$C_R" "$C_PRI" "$C_R" "$C_SEC" "$C_R" >&"$fd"
    h "INVESTIGATE"
    c run "discover + acquire + analyze + report, end to end"
    c discover "detect installed browsers and profiles ${C_DIM}(read-only)${C_R}"
    c acquire "controlled acquisition into a new case ${C_DIM}(SHA-256, manifest, audit chain)${C_R}"
    c analyze "parse copies in parallel, recover deleted data, correlate, build the timeline"
    c report "HTML ${G_SEP} JSON ${G_SEP} CSV ${G_SEP} Markdown, optionally filtered"
    c timeline "query the unified UTC timeline ${C_DIM}(table, csv, jsonl)${C_R}"
    h "ASSURE"
    c verify "re-hash evidence, manifest, unregistered files, audit chain, reports"
    c selftest "build laboratory artifacts, run the full pipeline, assert every subsystem"
    c matrix "exact support level of every artifact and browser family"
    c deps "check host capabilities and dependencies"
    c help "this screen ${C_DIM}${G_SEP}${C_R} ${C_PRI}${C_B}version${C_R} prints the release"
    h "SOURCES"
    o "-r, --root" "<dir>" "mounted image / exported tree instead of the live system"
    o "-s, --source" "<dir>" "explicit profile directory, family auto-detected"
    o "    --family" "<name>" "chromium | firefox | safari | epiphany | qutebrowser"
    o "-b, --browsers" "<list>" "restrict discovery, e.g. chrome,edge,firefox,safari,os,ese"
    o "    --deep" "" "also hunt signature files (History, places.sqlite, History.db)"
    o "    --depth" "<n>" "max depth for --deep ${C_DIM}(default 8)${C_R}"
    o "    --no-os-artifacts" "" "skip recently-used.xbel, LNK, Prefetch, QuarantineEventsV2"
    h "ACQUISITION"
    o "-c, --case" "<dir>" "case directory ${C_DIM}(new or empty for acquire/run)${C_R}"
    o "    --case-id" "<id>" "case identifier ${C_DIM}(default BFX-<UTC timestamp>)${C_R}"
    o "-e, --examiner" "<name>" "examiner recorded in case.json and the audit log"
    o "    --notes" "<text>" "free-text case notes"
    o "    --no-cache" "" "skip HTTP caches (Cache, cache2, CacheStorage ${G_ELL})"
    o "    --full" "" "acquire everything, incl. JIT/GPU caches skipped by default"
    o "    --max-file-size" "<size>" "skip but record larger files ${C_DIM}(default 2G; K M G T)${C_R}"
    h "ANALYSIS"
    o "-j, --jobs" "<n>" "parallel profile analyses ${C_DIM}(default: CPUs, max 8)${C_R}"
    o "    --no-redact" "" "${C_WARN}disable${C_R} redaction of secrets and personal data"
    o "    --no-recover" "" "skip deleted-record carving (SQLite, WAL, journal)"
    o "    --no-fs-correlation" "" "do not stat/hash downloaded files under the root"
    o "    --keep-work" "" "keep SQLite working copies for manual review"
    h "FILTERS  ${C_DIM}report ${G_SEP} timeline${C_R}"
    o "    --since / --until" "<date>" "ISO-8601, UTC unless offset; bare date = whole day"
    o "    --domain" "<list>" "domain and subdomains; prefix ~ for substring match"
    o "    --profile" "<regex>" "profile id, name or user"
    o "    --browser" "<list>" "browser name substring or family"
    o "    --type" "<list>" "history,download,cookie,cache,recovered_url,${G_ELL}"
    o "    --class" "<list>" "observed,recovered,inferred"
    o "    --formats" "<list>" "html,json,csv,md ${C_DIM}(default all)${C_R}"
    o "-o, --out" "<dir>" "report output directory"
    o "    --format" "<fmt>" "timeline: table|csv|jsonl ${G_SEP} discover: table|tsv"
    o "    --limit" "<n>" "timeline: stop after n events"
    h "GENERAL"
    o "-v, --verbose" "" "debug logging, list every self-test check"
    o "-q, --quiet" "" "only warnings and errors"
    o "    --no-color" "" "plain output ${C_DIM}(also NO_COLOR=1 / BFX_ASCII=1)${C_R}"
    o "    --keep-tmp" "" "keep temporary files (self-test artifacts)"
    h "EXAMPLES"
    x "what is on this machine (read-only)" "${BFX_SELF##*/} discover"
    x "full live triage into a new case" "${BFX_SELF##*/} run -c ./cases/HOST01 -e \"J. Doe\" --case-id INC-2024-17"
    x "mounted Windows image, Chromium browsers + OS artifacts, 4 workers" "${BFX_SELF##*/} run -r /mnt/evidence/C -c ./cases/IMG01 -b chrome,edge,brave,os -j 4"
    x "one exported profile directory" "${BFX_SELF##*/} run -s ./export/Default -c ./cases/EXP01"
    x "activity on one domain since a date" "${BFX_SELF##*/} timeline -c ./cases/IMG01 --since 2024-03-15 --domain example.com"
    x "downloads and recovered URLs only" "${BFX_SELF##*/} report -c ./cases/IMG01 --type download,recovered_url --formats html,csv"
    x "integrity check before hand-over" "${BFX_SELF##*/} verify -c ./cases/IMG01"
    h "EXIT CODES"
    printf '    %s0%s ok   %s1%s error   %s2%s usage   %s3%s missing dependency   %s4%s integrity failure   %s5%s partial results\n' \
        "$C_OK" "$C_R" "$C_ERR" "$C_R" "$C_WARN" "$C_R" "$C_WARN" "$C_R" "$C_ERR" "$C_R" "$C_WARN" "$C_R" >&"$fd"
    h "GUARANTEES"
    printf '    %s%s%s sources are only read; SQLite opens disposable copies of hashed evidence\n' "$C_OK" "$G_OK" "$C_R" >&"$fd"
    printf '    %s%s%s encrypted secrets are inventoried, never decrypted; evidence is never executed\n' "$C_OK" "$G_OK" "$C_R" >&"$fd"
    printf '    %s%s%s no network access of any kind; Python >= 3.8 (stdlib) only for analysis\n\n' "$C_OK" "$G_OK" "$C_R" >&"$fd"
}

print_matrix() {
    ui_to_stdout
    local fam art lvl src notes cur="" w aw=34
    local -A cnt=()
    while IFS=$'\t' read -r fam art lvl src notes; do [[ -z $fam || $fam == \#* ]] || cnt[$fam]=$(( ${cnt[$fam]:-0} + 1 )); done < <(support_matrix)
    while IFS=$'\t' read -r fam art lvl src notes; do
        [[ -z $fam || $fam == \#* ]] && continue
        if [[ $fam != "$cur" ]]; then
            cur=$fam
            local title
            case $fam in chromium) title="Chromium family  ${C_DIM}Chrome, Edge, Brave, Opera, Vivaldi, Yandex, Arc …${C_R}" ;;
                firefox) title="Gecko family  ${C_DIM}Firefox, ESR, LibreWolf, Waterfox, Tor, Floorp, Zen …${C_R}" ;;
                safari) title="Safari / WebKit  ${C_DIM}macOS${C_R}" ;; epiphany) title="GNOME Web (Epiphany)" ;; qutebrowser) title="qutebrowser" ;;
                ese) title="IE / Edge Legacy  ${C_DIM}ESE WebCache${C_R}" ;; all) title="Cross-cutting engines" ;; os) title="Operating-system correlation" ;; *) title=$fam ;; esac
            ui_section "$title" "${cnt[$fam]} artifact(s)"
        fi
        ui_badge "$lvl"; local bdg=$REPLY
        ui_pad "${C_TXT}${art}${C_R}" "$aw"; local a=$REPLY
        w=$(( UI_COLS - aw - 18 )); ui_trunc "$src" "$w"
        printf '    %s %s %s%s%s\n' "$bdg" "$a" "$C_MUT" "$REPLY" "$C_R" >&"$UI_FD"
        if [[ -n $notes ]]; then ui_trunc "$notes" $(( UI_COLS - 18 )); printf '    %9s %s%s%s%s\n' "" "$C_DIM" "$G_ARR " "$REPLY" "$C_R" >&"$UI_FD"; fi
    done < <(support_matrix)
    printf '\n' >&"$UI_FD"
    local b1 b2 b3 b4 b5
    ui_badge FULL; b1=$REPLY; ui_badge PARTIAL; b2=$REPLY; ui_badge CARVE; b3=$REPLY; ui_badge DETECT; b4=$REPLY; ui_badge NONE; b5=$REPLY
    ui_box "$C_SEC" "LEGEND" \
        "$b1 structured parse of the documented fields" \
        "$b2 structured, but some fields/structures are not decoded" \
        "$b3 recovery by carving ${C_DIM}— no completeness guarantee${C_R}" \
        "$b4 acquired, hashed and inventoried only" \
        "$b5 not supported" \
        "" \
        "${C_B}Validation${C_R} every parser runs in ${C_PRI}selftest${C_R} on schema-faithful synthetic lab artifacts." \
        "Also validated on profiles produced by real Chrome/Edge (Windows): history, cookies," \
        "SNSS sessions, localStorage, blockfile cache, service workers, IndexedDB names." \
        "${C_WARN}Not yet validated on real-browser output:${C_R} Firefox, Safari, Epiphany, qutebrowser," \
        "Chromium simple-cache, IndexedDB record counts. Schema drift => parser errors, never silence."
}

# ------------------------------------------------------------------ CLI
main() {
    local a; CMDLINE=$(printf '%q ' "$BFX_SELF" "$@"); CMDLINE=${CMDLINE% }
    [[ $# -ge 1 ]] || { detect_os; ui_init; usage; exit $E_USAGE; }
    CMD=$1; shift
    case $CMD in
        -h|--help|help) detect_os; ui_init; usage; exit 0 ;;
        -V|--version|version) printf '%s %s\n' "$BFX_NAME" "$BFX_VERSION"; exit 0 ;;
        deps|discover|acquire|analyze|report|run|timeline|verify|matrix|selftest) ;;
        *) detect_os; ui_init; die $E_USAGE "unknown command: $CMD" ;;
    esac
    local -a args=()
    for a in "$@"; do
        if [[ $a == --*=* ]]; then args+=("${a%%=*}" "${a#*=}"); else args+=("$a"); fi
    done
    set -- "${args[@]+"${args[@]}"}"
    local fmt_set=""
    while (( $# )); do
        case $1 in
            -c|--case) need_arg "$@"; CASE_DIR=$2; shift 2 ;;
            -r|--root) need_arg "$@"; ROOTS+=("$2"); shift 2 ;;
            -s|--source) need_arg "$@"; SOURCES_ARG+=("$2"); shift 2 ;;
            --family) need_arg "$@"; FAMILY_HINT=$2; shift 2 ;;
            -b|--browsers) need_arg "$@"; BROWSER_SEL=$2; shift 2 ;;
            --deep) DEEP=1; shift ;;
            --depth) need_arg "$@"; DEPTH=$2; shift 2 ;;
            --no-os-artifacts) OS_ARTIFACTS=0; shift ;;
            --case-id) need_arg "$@"; CASE_ID=$2; shift 2 ;;
            -e|--examiner) need_arg "$@"; EXAMINER=$2; shift 2 ;;
            --notes) need_arg "$@"; NOTES=$2; shift 2 ;;
            --no-cache) NO_CACHE=1; shift ;;
            --full) FULL=1; shift ;;
            --max-file-size) need_arg "$@"; MAX_FILE_SIZE=$(parse_size "$2") || die $E_USAGE "invalid size: $2"; shift 2 ;;
            -j|--jobs) need_arg "$@"; JOBS=$2; shift 2 ;;
            --no-redact) REDACT=0; shift ;;
            --no-recover) RECOVER=0; shift ;;
            --no-fs-correlation) FS_CORR=0; shift ;;
            --keep-work) KEEP_WORK=1; shift ;;
            --since) need_arg "$@"; F_SINCE=$2; shift 2 ;;
            --until) need_arg "$@"; F_UNTIL=$2; shift 2 ;;
            --domain) need_arg "$@"; F_DOMAIN=$2; shift 2 ;;
            --profile) need_arg "$@"; F_PROFILE=$2; shift 2 ;;
            --browser) need_arg "$@"; F_BROWSER=$2; shift 2 ;;
            --type) need_arg "$@"; F_TYPE=$2; shift 2 ;;
            --class) need_arg "$@"; F_CLASS=$2; shift 2 ;;
            --formats) need_arg "$@"; FORMATS=$2; shift 2 ;;
            -o|--out) need_arg "$@"; OUT_DIR=$2; shift 2 ;;
            --format) need_arg "$@"; TL_FORMAT=$2; fmt_set=1; shift 2 ;;
            --limit) need_arg "$@"; TL_LIMIT=$2; shift 2 ;;
            -v|--verbose) LOG_LEVEL=debug; shift ;;
            -q|--quiet) QUIET=1; shift ;;
            --log-level) need_arg "$@"; LOG_LEVEL=$2; shift 2 ;;
            --no-color) USE_COLOR=0; shift ;;
            --offline) OFFLINE=1; shift ;;
            --keep-tmp) KEEP_TMP=1; shift ;;
            -h|--help) detect_os; ui_init; usage; exit 0 ;;
            *) die $E_USAGE "unknown option: $1 (see --help)" ;;
        esac
    done
    # ---- validation
    [[ $JOBS =~ ^[0-9]+$ ]] && (( JOBS <= 64 )) || die $E_USAGE "--jobs must be an integer 0..64"
    [[ $DEPTH =~ ^[0-9]+$ ]] && (( DEPTH >= 1 && DEPTH <= 64 )) || die $E_USAGE "--depth must be 1..64"
    [[ $TL_LIMIT =~ ^[0-9]+$ ]] || die $E_USAGE "--limit must be a non-negative integer"
    [[ $LOG_LEVEL =~ ^(debug|info|warn|error)$ ]] || die $E_USAGE "--log-level must be debug|info|warn|error"
    [[ -z $F_SINCE ]] || valid_date "$F_SINCE" || die $E_USAGE "invalid --since date: $F_SINCE"
    [[ -z $F_UNTIL ]] || valid_date "$F_UNTIL" || die $E_USAGE "invalid --until date: $F_UNTIL"
    [[ -z $F_CLASS || $F_CLASS =~ ^(observed|recovered|inferred)(,(observed|recovered|inferred))*$ ]] || die $E_USAGE "--class accepts observed,recovered,inferred"
    [[ $FORMATS =~ ^(html|json|csv|md)(,(html|json|csv|md))*$ ]] || die $E_USAGE "--formats accepts html,json,csv,md"
    [[ -z $FAMILY_HINT || $FAMILY_HINT =~ ^(chromium|firefox|safari|epiphany|qutebrowser)$ ]] || die $E_USAGE "invalid --family"
    if [[ $CMD == discover ]]; then [[ -z $fmt_set || $TL_FORMAT =~ ^(table|tsv)$ ]] || die $E_USAGE "discover --format: table|tsv"
    else [[ $TL_FORMAT =~ ^(table|csv|jsonl)$ ]] || die $E_USAGE "--format must be table|csv|jsonl"; fi
    if [[ -n $F_PROFILE ]]; then local grc=0; echo x | grep -E -- "$F_PROFILE" >/dev/null 2>&1 || grc=$?; (( grc <= 1 )) || die $E_USAGE "invalid --profile regex"; fi
    local r i
    for i in "${!ROOTS[@]}"; do r=${ROOTS[i]}; [[ -d $r ]] || die $E_USAGE "--root is not a directory: $r"; ROOTS[i]=$(abspath "$r"); done
    for i in "${!SOURCES_ARG[@]}"; do r=${SOURCES_ARG[i]}; [[ -d $r ]] || die $E_USAGE "--source is not a directory: $r"; SOURCES_ARG[i]=$(abspath "$r"); done
    detect_os; detect_hash; ui_init
    RUN_T0=$SECONDS
    case $CMD in
        run) STEP_TOTAL=4 ;; acquire) STEP_TOTAL=2 ;; analyze|report) STEP_TOTAL=1 ;;
    esac
    case $CMD in run|acquire|analyze|report|deps|discover|verify|matrix|selftest) ui_banner_maybe ;; esac
    case $CMD in
        deps) cmd_deps ;;
        matrix) print_matrix ;;
        discover)
            default_roots; discover
            if [[ $TL_FORMAT == tsv ]]; then printf '%s\n' "${PROFILE_ROWS[@]+"${PROFILE_ROWS[@]}"}"
            else
                ui_to_stdout
                local rs="${ROOTS[*]:-/}"; [[ -z ${ROOTS[0]:-x} ]] && rs="/ (live system)"
                ui_section "Discovered browser profiles" "read-only $G_SEP $rs"
                print_profiles
            fi
            if (( LIVE )); then local rb; rb=$(running_browsers); [[ -z $rb ]] || log warn "running browser processes: $rb"; fi ;;
        acquire) cmd_acquire_impl; (( ACQ_FAIL == 0 )) || exit $E_PARTIAL ;;
        analyze) ANALYSIS_PARTIAL=0; cmd_analyze_impl; (( ANALYSIS_PARTIAL == 0 )) || exit $E_PARTIAL ;;
        report) cmd_report_impl ;;
        run)
            ANALYSIS_PARTIAL=0
            cmd_acquire_impl
            if find_python; then
                cmd_analyze_impl; cmd_report_impl; ui_run_summary
            else
                log warn "Python not available: acquisition completed; run 'analyze' and 'report' on a workstation with Python 3"
                exit $E_DEPS
            fi
            (( ACQ_FAIL == 0 && ANALYSIS_PARTIAL == 0 )) || { log warn "completed with partial results (see errors section of the report)"; exit $E_PARTIAL; } ;;
        timeline) cmd_timeline_impl ;;
        verify) cmd_verify_impl ;;
        selftest) ensure_tmp; cmd_selftest_impl ;;
    esac
}

main "$@"
