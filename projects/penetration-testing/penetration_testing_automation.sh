#!/bin/bash

set -u
set -o pipefail

SCRIPT_NAME="$(basename "$0")"
RUN_ID="$(date +%Y%m%d_%H%M%S)"

TARGET_SCOPE=""
OUTPUT_DIR=""
SCAN_MODE=""
PASSWORD_LIST=""
USER_LIST=""
PASSWORD_LIST_COUNT=0
USER_LIST_COUNT=0
LARGE_WORDLIST_STATUS="Not triggered."
CREDENTIAL_WORDLISTS_ALLOWED=1

LOG_FILE=""
SUMMARY_FILE=""
COMMAND_LOG=""
TOOL_REPORT=""
README_RESULTS_FILE=""
SERVICE_SUMMARY_FILE=""
HOSTS_SUMMARY_FILE=""
LOGIN_SERVICES_FILE=""
CREDENTIAL_PLAN_FILE=""
CREDENTIAL_RESULTS_DIR=""
VULNERABILITY_SUMMARY_FILE=""
CVE_SUMMARY_FILE=""
SEARCHSPLOIT_FILE=""
NMAP_DIR=""
PARSED_DIR=""
CREDENTIALS_DIR=""
REPORT_DIR=""
REPORT_MD=""
REPORT_HTML=""

ZIP_ARCHIVE_PATH="Not created."
CREDENTIAL_STATUS="[SKIP] Not requested."
VULNERABILITY_STATUS="[SKIP] Basic mode selected."
SERVICE_COUNT=0
TCP_SERVICE_COUNT=0
UDP_SERVICE_COUNT=0
HOST_COUNT=0
LOGIN_SERVICE_COUNT=0
CVE_COUNT=0
MISSING_TOOLS=()
_CRED_HOSTS=()
_CRED_ROLES=()
_CRED_SVCS=()
_SVC_NAMES=()
_SVC_PORTS=()

REQUIRED_TOOLS=(nmap hydra medusa searchsploit zip grep awk sed)

declare -A TOOL_PACKAGES=(
    [nmap]="nmap"
    [hydra]="hydra"
    [medusa]="medusa"
    [searchsploit]="exploitdb"
    [zip]="zip"
    [grep]="grep"
    [awk]="gawk"
    [sed]="sed"
)

# Initializes terminal colors, with NO_COLOR=1 support.
init_colors() {
    if [[ "${NO_COLOR:-}" == "1" ]]; then
        GREEN=""
        RED=""
        YELLOW=""
        CYAN=""
        BLUE=""
        BOLD=""
        RESET=""
    else
        GREEN=$'\033[0;32m'
        RED=$'\033[0;31m'
        YELLOW=$'\033[0;33m'
        CYAN=$'\033[0;36m'
        BLUE=$'\033[0;34m'
        BOLD=$'\033[1m'
        RESET=$'\033[0m'
    fi
}

# Prints the script title.
show_banner() {
    cat <<EOF
${CYAN}${BOLD}============================================================
  VULNER
  Network Service and Vulnerability Mapper
============================================================${RESET}
EOF
}

# Prints a visual separator.
separator() {
    echo "${BLUE}------------------------------------------------------------${RESET}"
}

# Prints a numbered stage header.
stage() {
    local number="$1"
    local title="$2"
    echo
    separator
    echo "${CYAN}${BOLD}[$number/9] $title${RESET}"
    separator
}

# Writes a status message to terminal and run.log when available.
log_status() {
    local level="$1"
    local message="$2"
    local color="$RESET"
    local timestamp
    local display_message

    case "$level" in
        OK) color="$GREEN" ;;
        WARN|SKIP) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        INFO) color="$CYAN" ;;
    esac

    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    display_message="$message"
    if [[ "$display_message" == "[$level] "* ]]; then
        display_message="${display_message#\[$level\] }"
    fi
    echo "${color}[$level]${RESET} $display_message"
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[$timestamp] [$level] $display_message" >> "$LOG_FILE"
    fi
}

# Stops the script with a clear error message.
fail() {
    log_status "ERROR" "$1"
    exit 1
}

# Validates that a value is a normal IPv4 address.
is_valid_ipv4() {
    local ip="$1"
    local IFS=.
    local -a octets

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

# Checks whether an IPv4 address is inside common private network ranges.
is_private_ipv4() {
    local ip="$1"
    local IFS=.
    local -a o

    is_valid_ipv4 "$ip" || return 1
    read -r -a o <<< "$ip"

    if (( o[0] == 10 )); then
        return 0
    fi
    if (( o[0] == 172 && o[1] >= 16 && o[1] <= 31 )); then
        return 0
    fi
    if (( o[0] == 192 && o[1] == 168 )); then
        return 0
    fi
    return 1
}

# Accepts only private single IPs or CIDRs that start in a private range.
validate_private_scope() {
    local scope="$1"
    local ip cidr

    if [[ "$scope" == */* ]]; then
        ip="${scope%/*}"
        cidr="${scope#*/}"
        [[ "$cidr" =~ ^[0-9]+$ ]] || return 1
        (( cidr >= 8 && cidr <= 32 )) || return 1
        is_private_ipv4 "$ip" || return 1
        return 0
    fi

    is_private_ipv4 "$scope"
}

# Returns true when the target is a CIDR/subnet.
is_cidr_scope() {
    [[ "$1" == */* ]]
}

# Creates the requested result folder structure.
prepare_output_dir() {
    local base_dir="$1"

    [[ -n "$base_dir" ]] || fail "Output directory cannot be empty."
    OUTPUT_DIR="${base_dir%/}/vulner_${RUN_ID}"
    NMAP_DIR="$OUTPUT_DIR/nmap"
    PARSED_DIR="$OUTPUT_DIR/parsed"
    CREDENTIALS_DIR="$OUTPUT_DIR/credentials"
    REPORT_DIR="$OUTPUT_DIR/report"
    CREDENTIAL_RESULTS_DIR="$CREDENTIALS_DIR/credential_results"

    mkdir -p "$NMAP_DIR" "$PARSED_DIR" "$CREDENTIAL_RESULTS_DIR" "$REPORT_DIR" || fail "Could not create output directories."

    README_RESULTS_FILE="$OUTPUT_DIR/README_RESULTS.txt"
    LOG_FILE="$OUTPUT_DIR/run.log"
    COMMAND_LOG="$OUTPUT_DIR/commands.txt"
    TOOL_REPORT="$OUTPUT_DIR/tool_check.txt"
    SERVICE_SUMMARY_FILE="$PARSED_DIR/services_summary.txt"
    HOSTS_SUMMARY_FILE="$PARSED_DIR/hosts_summary.txt"
    LOGIN_SERVICES_FILE="$PARSED_DIR/login_services.txt"
    CREDENTIAL_PLAN_FILE="$CREDENTIALS_DIR/credential_testing_plan.txt"
    VULNERABILITY_SUMMARY_FILE="$PARSED_DIR/vulnerability_summary.txt"
    CVE_SUMMARY_FILE="$PARSED_DIR/cve_summary.txt"
    SEARCHSPLOIT_FILE="$PARSED_DIR/searchsploit_mapping.txt"
    SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
    REPORT_MD="$REPORT_DIR/report.md"
    REPORT_HTML="$REPORT_DIR/report.html"

    : > "$README_RESULTS_FILE"
    : > "$LOG_FILE"
    : > "$COMMAND_LOG"
    : > "$TOOL_REPORT"
    : > "$SERVICE_SUMMARY_FILE"
    : > "$HOSTS_SUMMARY_FILE"
    : > "$LOGIN_SERVICES_FILE"
    : > "$CREDENTIAL_PLAN_FILE"
    : > "$VULNERABILITY_SUMMARY_FILE"
    : > "$CVE_SUMMARY_FILE"
    : > "$SEARCHSPLOIT_FILE"
    : > "$SUMMARY_FILE"
}

# Collects the target scope and output directory before numbered stages begin.
collect_initial_inputs() {
    local default_output
    default_output="./results"

    echo
    separator
    echo "${CYAN}${BOLD}Target Scope Setup${RESET}"
    separator
    read -r -p "Enter private network target scope (single IP or CIDR): " TARGET_SCOPE
    validate_private_scope "$TARGET_SCOPE" || fail "Only private IPv4 ranges are allowed: 10/8, 172.16/12, 192.168/16."

    read -r -p "Enter output directory [${default_output}]: " OUTPUT_DIR
    OUTPUT_DIR="${OUTPUT_DIR:-$default_output}"
    prepare_output_dir "$OUTPUT_DIR"
    log_status "OK" "Output directory prepared: $OUTPUT_DIR"
}

# Writes a command preview to commands.txt and terminal.
log_command() {
    local printable
    printable="$(printf '%q ' "$@")"
    echo "$printable" >> "$COMMAND_LOG"
    log_status "INFO" "Command: $printable"
}

# Checks expected tools and records OK/MISSING status.
check_tools() {
    local tool

    MISSING_TOOLS=()
    : > "$TOOL_REPORT"
    echo "Tool check generated: $(date '+%Y-%m-%d %H:%M:%S')" >> "$TOOL_REPORT"

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "[OK] $tool: $(command -v "$tool")" | tee -a "$TOOL_REPORT"
            log_status "OK" "$tool is installed."
        else
            echo "[MISSING] $tool" | tee -a "$TOOL_REPORT"
            log_status "WARN" "$tool is missing."
            MISSING_TOOLS+=("$tool")
        fi
    done
}

# Offers to install missing tools on Kali-style systems.
install_missing_tools_if_requested() {
    local choice tool package
    local -a packages=()

    if (( ${#MISSING_TOOLS[@]} == 0 )); then
        return 0
    fi

    read -r -p "Do you want to install missing tools now? [y/N]: " choice
    choice="${choice:-N}"
    case "$choice" in
        y|Y|yes|YES) ;;
        n|N|no|NO)
            log_status "SKIP" "Missing tool installation skipped by user."
            return 0
            ;;
        *)
            log_status "SKIP" "Invalid install choice; skipping installation."
            return 0
            ;;
    esac

    for tool in "${MISSING_TOOLS[@]}"; do
        package="${TOOL_PACKAGES[$tool]}"
        packages+=("$package")
    done

    log_command sudo apt update
    sudo apt update >> "$LOG_FILE" 2>&1
    log_command sudo apt install "${packages[@]}" -y
    sudo apt install "${packages[@]}" -y >> "$LOG_FILE" 2>&1
    check_tools
}

# Runs the startup tool check and optional installation.
tool_check_workflow() {
    stage 1 "Environment and tool check"
    check_tools
    install_missing_tools_if_requested
    if ! command -v medusa >/dev/null 2>&1; then
        log_status "WARN" "Medusa is missing; credential testing can continue with Hydra only."
    fi
}

# Shows validated user inputs.
input_validation_summary() {
    stage 2 "Input and scope validation"
    log_status "OK" "Target scope accepted: $TARGET_SCOPE"
    log_status "OK" "Output directory: $OUTPUT_DIR"
    log_status "OK" "Target scope validated."
}

# Confirms network scans and wide CIDRs.
scope_confirmation() {
    if is_cidr_scope "$TARGET_SCOPE"; then
        log_status "INFO" "Network scan target: $TARGET_SCOPE"
        read -r -p "Continue? [y/N]: " confirm
        confirm="${confirm:-N}"

        case "$confirm" in
            y|Y|yes|YES)
                log_status "OK" "Network scan confirmed."
                ;;
            *)
                fail "Network scan cancelled by user."
                ;;
        esac
    fi
}

# Lets the user choose Basic or Full scan mode.
select_scan_mode() {
    local choice

    echo
    echo "Choose scan mode:"
    echo "  1) Basic - TCP/UDP scans, service/version detection, and controlled weak-password testing"
    echo "  2) Full  - Basic plus NSE vulnerability scripts and Searchsploit mapping"
    read -r -p "Selection [1]: " choice
    choice="${choice:-1}"

    case "$choice" in
        1) SCAN_MODE="Basic" ;;
        2) SCAN_MODE="Full" ;;
        *) fail "Invalid scan mode selection." ;;
    esac
    log_status "OK" "Scan mode selected: $SCAN_MODE"
}

# Counts non-empty entries in a wordlist.
count_wordlist_entries() {
    grep -cve '^[[:space:]]*$' "$1" || true
}

# Prompts until a usable wordlist path is selected.
select_one_wordlist() {
    local label="$1"
    local default_path="$2"
    local compressed_path="${3:-}"
    local path count

    while true; do
        read -r -p "${label} list path [${default_path}]: " path
        path="${path:-$default_path}"

        if [[ ! -f "$path" ]]; then
            if [[ "$label" == "Username" && "$path" == "$default_path" ]]; then
                echo "SecLists username list not found."
                echo "Install SecLists with:"
                echo "sudo apt install seclists"
            elif [[ "$label" == "Password" && "$path" == "$default_path" && -f "$compressed_path" ]]; then
                echo "rockyou.txt is compressed."
                echo "Extract it with:"
                echo "sudo gzip -d /usr/share/wordlists/rockyou.txt.gz"
            else
                log_status "WARN" "$label list not found: $path"
            fi
            continue
        fi

        if [[ ! -r "$path" ]]; then
            log_status "WARN" "$label list is not readable: $path"
            continue
        fi

        count="$(count_wordlist_entries "$path")"
        if (( count == 0 )); then
            log_status "WARN" "$label list is empty: $path"
            continue
        fi

        SELECTED_WORDLIST_PATH="$path"
        SELECTED_WORDLIST_COUNT="$count"
        return 0
    done
}

# Selects and validates real assessment username/password wordlists.
select_password_list() {
    local default_users default_password compressed_rockyou choice

    default_users="${VULNER_DEFAULT_USERNAME_LIST:-/usr/share/seclists/Usernames/top-usernames-shortlist.txt}"
    default_password="${VULNER_DEFAULT_PASSWORD_LIST:-/usr/share/wordlists/rockyou.txt}"
    compressed_rockyou="${VULNER_DEFAULT_PASSWORD_GZ:-/usr/share/wordlists/rockyou.txt.gz}"

    select_one_wordlist "Username" "$default_users"
    USER_LIST="$SELECTED_WORDLIST_PATH"
    USER_LIST_COUNT="$SELECTED_WORDLIST_COUNT"

    select_one_wordlist "Password" "$default_password" "$compressed_rockyou"
    PASSWORD_LIST="$SELECTED_WORDLIST_PATH"
    PASSWORD_LIST_COUNT="$SELECTED_WORDLIST_COUNT"

    LARGE_WORDLIST_STATUS="Not triggered."
    CREDENTIAL_WORDLISTS_ALLOWED=1
    if (( USER_LIST_COUNT > 1000 || PASSWORD_LIST_COUNT > 1000 )); then
        log_status "WARN" "Large wordlists selected. Credential testing may take a long time."
        read -r -p "Continue with these wordlists? [y/N]: " choice
        choice="${choice:-N}"
        case "$choice" in
            y|Y|yes|YES)
                LARGE_WORDLIST_STATUS="[OK] large wordlist confirmation accepted"
                ;;
            *)
                LARGE_WORDLIST_STATUS="[SKIP] user declined large wordlist confirmation"
                CREDENTIAL_WORDLISTS_ALLOWED=0
                CREDENTIAL_STATUS="[SKIP] user declined large wordlist confirmation"
                ;;
        esac
    fi

    log_status "OK" "Username list: $USER_LIST"
    log_status "INFO" "Username entries: $USER_LIST_COUNT"
    log_status "OK" "Password list: $PASSWORD_LIST"
    log_status "INFO" "Password entries: $PASSWORD_LIST_COUNT"
}

# Checks one tool before a live command uses it.
requires_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        log_status "SKIP" "Skipping because required tool is missing: $tool"
        return 1
    fi
    return 0
}

# Executes a command after logging it and records the exit code.
run_command() {
    local label="$1"
    local required_tool="$2"
    shift 2
    local status

    log_status "INFO" "$label"
    log_command "$@"
    requires_tool "$required_tool" || return 127
    "$@" >> "$LOG_FILE" 2>&1
    status=$?
    log_status "INFO" "$label finished with exit code $status"
    return "$status"
}

# Runs the TCP Nmap service/version scan.
run_tcp_scan() {
    stage 4 "TCP service/version scan"
    run_command "Running TCP service/version scan" nmap \
        nmap -sS -sV -T3 --reason -oA "$NMAP_DIR/tcp_services" "$TARGET_SCOPE"
}

# Runs the UDP Nmap top ports scan.
run_udp_scan() {
    stage 5 "UDP top ports scan"
    run_command "Running UDP top ports scan" nmap \
        nmap -sU --top-ports 20 -T3 --reason -oA "$NMAP_DIR/udp_top" "$TARGET_SCOPE"
}

# Parses Nmap grepable output into a service table.
parse_nmap_services() {
    local tcp_input udp_input file line host ports entry
    local port state proto owner service sunrpc version rest
    local -a entries hosts_order
    declare -A host_seen host_tcp_count host_udp_count host_services
    tcp_input="$NMAP_DIR/tcp_services.gnmap"
    udp_input="$NMAP_DIR/udp_top.gnmap"

    stage 6 "Service parsing"
    {
        printf '%-15s | %-5s | %-8s | %-12s | %s\n' "Host" "Port" "Protocol" "Service" "Version"
        printf '%-15s-+-%-5s-+-%-8s-+-%-12s-+-%s\n' "---------------" "-----" "--------" "------------" "----------------"
    } > "$SERVICE_SUMMARY_FILE"

    if [[ ! -f "$tcp_input" && ! -f "$udp_input" ]]; then
        echo "No Nmap service output found." >> "$SERVICE_SUMMARY_FILE"
        log_status "WARN" "No Nmap grepable output found to parse."
        return 0
    fi

    SERVICE_COUNT=0
    TCP_SERVICE_COUNT=0
    UDP_SERVICE_COUNT=0
    HOST_COUNT=0
    hosts_order=()
    for file in "$tcp_input" "$udp_input"; do
        [[ -f "$file" ]] || continue
        while IFS= read -r line; do
            [[ "$line" == *"Ports:"* ]] || continue
            set -- $line
            host="$2"
            ports="${line#*Ports: }"
            IFS=',' read -r -a entries <<< "$ports"
            for entry in "${entries[@]}"; do
                entry="${entry#"${entry%%[![:space:]]*}"}"
                IFS='/' read -r port state proto owner service sunrpc version rest <<< "$entry"
                [[ "$state" == "open" ]] || continue
                if [[ -z "${host_seen[$host]:-}" ]]; then
                    host_seen["$host"]=1
                    host_tcp_count["$host"]=0
                    host_udp_count["$host"]=0
                    host_services["$host"]=""
                    hosts_order+=("$host")
                    HOST_COUNT=$((HOST_COUNT + 1))
                fi
                service="${service:-unknown}"
                version="${version:-"-"}"
                printf '%-15s | %-5s | %-8s | %-12s | %s\n' "$host" "$port" "$proto" "$service" "$version" >> "$SERVICE_SUMMARY_FILE"
                host_services["$host"]+="${port}/${proto} ${service} ${version}"$'\n'
                SERVICE_COUNT=$((SERVICE_COUNT + 1))
                case "$proto" in
                    tcp)
                        TCP_SERVICE_COUNT=$((TCP_SERVICE_COUNT + 1))
                        host_tcp_count["$host"]=$((host_tcp_count["$host"] + 1))
                        ;;
                    udp)
                        UDP_SERVICE_COUNT=$((UDP_SERVICE_COUNT + 1))
                        host_udp_count["$host"]=$((host_udp_count["$host"] + 1))
                        ;;
                esac
            done
        done < "$file"
    done

    {
        echo "Hosts summary"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo
        if (( HOST_COUNT == 0 )); then
            echo "No hosts with open TCP/UDP services were parsed from Nmap output."
        else
            for host in "${hosts_order[@]}"; do
                echo "Host: $host"
                echo "  TCP services: ${host_tcp_count[$host]}"
                echo "  UDP services: ${host_udp_count[$host]}"
                echo "  Open services:"
                while IFS= read -r line; do
                    [[ -n "$line" ]] || continue
                    echo "    - $line"
                done <<< "${host_services[$host]}"
                echo
            done
        fi
    } > "$HOSTS_SUMMARY_FILE"

    if (( SERVICE_COUNT == 0 )); then
        echo "No open TCP/UDP services were parsed from Nmap output." >> "$SERVICE_SUMMARY_FILE"
        log_status "WARN" "No open services parsed."
    else
        log_status "OK" "Parsed $SERVICE_COUNT open service entries across $HOST_COUNT host(s)."
    fi

    echo
    echo "${CYAN}${BOLD}Discovered Services${RESET}"
    cat "$SERVICE_SUMMARY_FILE"
}

# Extracts login services from TCP Nmap output for credential testing.
discover_login_services() {
    local tcp_input line host ports entry
    local port state proto owner service sunrpc version rest login_service
    local -a entries
    tcp_input="$NMAP_DIR/tcp_services.gnmap"

    : > "$LOGIN_SERVICES_FILE"
    if [[ ! -f "$tcp_input" ]]; then
        log_status "WARN" "No TCP grepable output found for login service detection."
        LOGIN_SERVICE_COUNT=0
        return 0
    fi

    while IFS= read -r line; do
        [[ "$line" == *"Ports:"* ]] || continue
        set -- $line
        host="$2"
        ports="${line#*Ports: }"
        IFS=',' read -r -a entries <<< "$ports"
        for entry in "${entries[@]}"; do
            entry="${entry#"${entry%%[![:space:]]*}"}"
            IFS='/' read -r port state proto owner service sunrpc version rest <<< "$entry"
            [[ "$state" == "open" && "$proto" == "tcp" ]] || continue
            login_service=""
            case "$port" in
                22) login_service="ssh" ;;
                21) login_service="ftp" ;;
                23) login_service="telnet" ;;
                3389) login_service="rdp" ;;
            esac
            [[ -n "$login_service" ]] || continue
            echo "$host $login_service $port tcp" >> "$LOGIN_SERVICES_FILE"
        done
    done < "$tcp_input"

    if [[ -s "$LOGIN_SERVICES_FILE" ]]; then
        sort -u "$LOGIN_SERVICES_FILE" -o "$LOGIN_SERVICES_FILE"
    fi

    LOGIN_SERVICE_COUNT=0
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        LOGIN_SERVICE_COUNT=$((LOGIN_SERVICE_COUNT + 1))
    done < "$LOGIN_SERVICES_FILE"

    if (( LOGIN_SERVICE_COUNT == 0 )); then
        log_status "SKIP" "No SSH, FTP, Telnet, or RDP login services discovered."
    else
        log_status "OK" "Discovered $LOGIN_SERVICE_COUNT login service entries."
        cat "$LOGIN_SERVICES_FILE"
    fi
}

# Writes safe credential testing plan commands for discovered services.
write_credential_plan() {
    {
        echo "Credential testing plan"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Username list: $USER_LIST"
        echo "Username entries: $USER_LIST_COUNT"
        echo "Password list: $PASSWORD_LIST"
        echo "Password entries: $PASSWORD_LIST_COUNT"
        echo "Large wordlist warning status: $LARGE_WORDLIST_STATUS"
        echo
        echo "Hydra/Medusa are never run automatically."
        echo "A single discovered private host/service must be selected and confirmed before execution."
        echo
    } > "$CREDENTIAL_PLAN_FILE"

    if [[ ! -s "$LOGIN_SERVICES_FILE" ]]; then
        echo "No discovered login services are available." >> "$CREDENTIAL_PLAN_FILE"
        return 0
    fi

    while read -r host service port proto; do
        [[ -n "$host" && -n "$service" && -n "$port" && -n "$proto" ]] || continue
        {
            echo "Host: $host Service: $service Port: $port Protocol: $proto"
            echo "  Hydra: hydra -L \"$USER_LIST\" -P \"$PASSWORD_LIST\" -s $port ${service}://$host"
            echo "  Medusa: medusa -h $host -U \"$USER_LIST\" -P \"$PASSWORD_LIST\" -M $service -n $port"
            echo
        } >> "$CREDENTIAL_PLAN_FILE"
    done < "$LOGIN_SERVICES_FILE"
}

# Finds a discovered host/service pair and returns its port.
find_discovered_login_port() {
    local target="$1"
    local service="$2"
    local host listed_service port proto

    while read -r host listed_service port proto; do
        if [[ "$host" == "$target" && "$listed_service" == "$service" && "$proto" == "tcp" ]]; then
            echo "$port"
            return 0
        fi
    done < "$LOGIN_SERVICES_FILE"
    return 1
}

# Returns a role label inferred from a space-separated list of service names.
infer_host_role() {
    local svcs="$1"
    case " $svcs " in
        *" rdp "*|*"rdp"*) echo "Windows host (inferred)" ;;
        *" ssh "*|*" ftp "*|*" telnet "*|*"ssh"*|*"ftp"*|*"telnet"*) echo "Linux host (inferred)" ;;
        *) echo "Unknown" ;;
    esac
}

# Reads LOGIN_SERVICES_FILE and prints a numbered host pick-list.
# Sets globals: _CRED_HOSTS _CRED_ROLES _CRED_SVCS
build_credential_host_menu() {
    _CRED_HOSTS=()
    _CRED_ROLES=()
    _CRED_SVCS=()

    local host service port proto found i
    while read -r host service port proto; do
        [[ -n "$host" && -n "$service" ]] || continue
        found=0
        for i in "${!_CRED_HOSTS[@]}"; do
            if [[ "${_CRED_HOSTS[$i]}" == "$host" ]]; then
                _CRED_SVCS[$i]="${_CRED_SVCS[$i]} $service"
                found=1
                break
            fi
        done
        if (( found == 0 )); then
            _CRED_HOSTS+=("$host")
            _CRED_SVCS+=("$service")
            _CRED_ROLES+=("")
        fi
    done < "$LOGIN_SERVICES_FILE"

    for i in "${!_CRED_HOSTS[@]}"; do
        _CRED_ROLES[$i]="$(infer_host_role "${_CRED_SVCS[$i]}")"
    done

    echo
    echo "  Available login targets:"
    printf "  %-3s  %-16s  %-26s  %s\n" "#" "Host" "Role" "Login services"
    local idx=1
    for i in "${!_CRED_HOSTS[@]}"; do
        printf "  %-3s  %-16s  %-26s  %s\n" "$idx" "${_CRED_HOSTS[$i]}" "${_CRED_ROLES[$i]}" "${_CRED_SVCS[$i]}"
        idx=$((idx + 1))
    done
    printf "  %-3s  %s\n" "q" "Skip"
    echo
}

# Prints a numbered service pick-list for HOST_IP in stable order (ftp ssh telnet rdp).
# Sets globals: _SVC_NAMES _SVC_PORTS
show_credential_service_menu() {
    local host_ip="$1"
    _SVC_NAMES=()
    _SVC_PORTS=()

    local host service port proto svc
    declare -A _svc_port_map
    _svc_port_map=()

    while read -r host service port proto; do
        [[ "$host" == "$host_ip" && "$proto" == "tcp" ]] || continue
        _svc_port_map["$service"]="$port"
    done < "$LOGIN_SERVICES_FILE"

    local -a preferred_order=(ftp ssh telnet rdp)
    for svc in "${preferred_order[@]}"; do
        if [[ -n "${_svc_port_map[$svc]:-}" ]]; then
            _SVC_NAMES+=("$svc")
            _SVC_PORTS+=("${_svc_port_map[$svc]}")
        fi
    done

    echo
    echo "  Target:   $host_ip"
    echo "  Services:"
    local idx=1
    for i in "${!_SVC_NAMES[@]}"; do
        printf "    %s) %s  %s/tcp\n" "$idx" "${_SVC_NAMES[$i]}" "${_SVC_PORTS[$i]}"
        idx=$((idx + 1))
    done
    printf "    %s) %s\n" "q" "cancel"
    echo
}

# Asks whether to run one controlled weak credential test.
credential_workflow() {
    local choice target service port tool confirm output_file status timestamp command_text pick

    stage 7 "Controlled weak credential testing"
    discover_login_services
    write_credential_plan

    if (( CREDENTIAL_WORDLISTS_ALLOWED == 0 )); then
        CREDENTIAL_STATUS="[SKIP] user declined large wordlist confirmation"
        log_status "SKIP" "Credential testing skipped because user declined large wordlist confirmation."
        return 0
    fi

    if (( LOGIN_SERVICE_COUNT == 0 )); then
        CREDENTIAL_STATUS="[SKIP] No discovered login services."
        return 0
    fi

    read -r -p "Do you want to run controlled weak credential testing against a specific discovered host? [y/N]: " choice
    choice="${choice:-N}"
    case "$choice" in
        y|Y|yes|YES) ;;
        n|N|no|NO)
            CREDENTIAL_STATUS="[SKIP] User skipped credential testing."
            log_status "SKIP" "Credential testing skipped by user."
            return 0
            ;;
        *)
            CREDENTIAL_STATUS="[SKIP] Invalid credential testing choice."
            log_status "SKIP" "Invalid credential testing choice; skipping."
            return 0
            ;;
    esac

    build_credential_host_menu
    read -r -p "  Pick a host to test [q]: " pick
    pick="${pick:-q}"
    if [[ "$pick" == "q" || "$pick" == "Q" ]]; then
        CREDENTIAL_STATUS="[SKIP] User skipped host selection."
        log_status "SKIP" "Credential testing skipped at host selection."
        return 0
    fi
    if ! [[ "$pick" =~ ^[0-9]+$ ]] || (( pick < 1 || pick > ${#_CRED_HOSTS[@]} )); then
        CREDENTIAL_STATUS="[SKIP] Invalid host selection."
        log_status "SKIP" "Invalid host number entered at credential menu."
        return 0
    fi
    target="${_CRED_HOSTS[$((pick - 1))]}"

    show_credential_service_menu "$target"
    read -r -p "  Pick a service [q]: " pick
    pick="${pick:-q}"
    if [[ "$pick" == "q" || "$pick" == "Q" ]]; then
        CREDENTIAL_STATUS="[SKIP] User cancelled service selection."
        log_status "SKIP" "Credential testing cancelled at service selection."
        return 0
    fi
    if ! [[ "$pick" =~ ^[0-9]+$ ]] || (( pick < 1 || pick > ${#_SVC_NAMES[@]} )); then
        CREDENTIAL_STATUS="[SKIP] Invalid service selection."
        log_status "SKIP" "Invalid service number entered at credential menu."
        return 0
    fi
    service="${_SVC_NAMES[$((pick - 1))]}"
    port="${_SVC_PORTS[$((pick - 1))]}"

    # Defense-in-depth: verify source data integrity
    is_private_ipv4 "$target" || fail "Credential testing target must be one private IPv4 address."
    case "$service" in
        ssh|ftp|telnet|rdp) ;;
        *) fail "Unsupported credential testing service: $service" ;;
    esac
    find_discovered_login_port "$target" "$service" > /dev/null || fail "Selected host/service was not discovered as open."

    if command -v hydra >/dev/null 2>&1 && command -v medusa >/dev/null 2>&1; then
        read -r -p "Use hydra or medusa? [hydra]: " tool
        tool="${tool:-hydra}"
    elif command -v hydra >/dev/null 2>&1; then
        log_status "WARN" "Medusa is missing. Hydra is the only available option."
        tool="hydra"
    elif command -v medusa >/dev/null 2>&1; then
        log_status "WARN" "Hydra is missing. Medusa is the only available option."
        tool="medusa"
    else
        CREDENTIAL_STATUS="[SKIP] Hydra and Medusa are missing."
        log_status "SKIP" "No credential testing tool is available."
        return 0
    fi

    if [[ "$tool" == "medusa" ]] && ! command -v medusa >/dev/null 2>&1; then
        log_status "WARN" "Medusa is unavailable; falling back to Hydra."
        tool="hydra"
    fi
    if [[ "$tool" == "hydra" ]] && ! command -v hydra >/dev/null 2>&1; then
        log_status "WARN" "Hydra is unavailable; falling back to Medusa."
        tool="medusa"
    fi
    [[ "$tool" == "hydra" || "$tool" == "medusa" ]] || fail "Invalid credential testing tool selection."

    echo
    if [[ "$tool" == "hydra" ]]; then
        command_text="hydra -L \"$USER_LIST\" -P \"$PASSWORD_LIST\" -s $port ${service}://$target"
    else
        command_text="medusa -h $target -U \"$USER_LIST\" -P \"$PASSWORD_LIST\" -M $service -n $port"
    fi
    echo "${YELLOW}Exact command:${RESET} $command_text"
    read -r -p "Run this credential test against this single discovered service? [y/N]: " confirm
    confirm="${confirm:-N}"
    case "$confirm" in
        y|Y|yes|YES) ;;
        *)
            CREDENTIAL_STATUS="[SKIP] Prepared but not executed; user did not approve credential test."
            log_status "SKIP" "Credential test skipped by user."
            return 0
            ;;
    esac

    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    output_file="$CREDENTIAL_RESULTS_DIR/${tool}_${target}_${service}_${port}.txt"
    {
        echo "Credential test timestamp: $timestamp"
        echo "Tool: $tool"
        echo "Target: $target"
        echo "Service: $service"
        echo "Port: $port"
        echo "Command: $command_text"
        echo
    } > "$output_file"

    if [[ "$tool" == "hydra" ]]; then
        log_command hydra -L "$USER_LIST" -P "$PASSWORD_LIST" -s "$port" "${service}://$target"
        hydra -L "$USER_LIST" -P "$PASSWORD_LIST" -s "$port" "${service}://$target" >> "$output_file" 2>> "$LOG_FILE"
    else
        log_command medusa -h "$target" -U "$USER_LIST" -P "$PASSWORD_LIST" -M "$service" -n "$port"
        medusa -h "$target" -U "$USER_LIST" -P "$PASSWORD_LIST" -M "$service" -n "$port" >> "$output_file" 2>> "$LOG_FILE"
    fi
    status=$?
    echo "Exit code: $status" >> "$output_file"
    if (( status == 0 )); then
        CREDENTIAL_STATUS="[OK] Credential test completed. Output: $output_file Exit code: $status"
        log_status "OK" "$CREDENTIAL_STATUS"
    else
        CREDENTIAL_STATUS="[WARN] Credential test completed with non-zero exit code: $status. Review raw output manually. Output: $output_file"
        log_status "WARN" "$CREDENTIAL_STATUS"
    fi
}

# Extracts deduplicated CVE identifiers from NSE output.
write_cve_summary() {
    local nse_file="$1"

    CVE_COUNT=0
    {
        echo "CVE summary"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Source: $nse_file"
        echo
    } > "$CVE_SUMMARY_FILE"

    if [[ ! -f "$nse_file" ]]; then
        echo "No NSE output was available for CVE extraction." >> "$CVE_SUMMARY_FILE"
        return 0
    fi

    grep -Eio 'CVE-[0-9]{4}-[0-9]+' "$nse_file" | sort -u >> "$CVE_SUMMARY_FILE" || true
    CVE_COUNT="$(grep -Ec '^CVE-[0-9]{4}-[0-9]+' "$CVE_SUMMARY_FILE" || true)"

    if (( CVE_COUNT == 0 )); then
        echo "No CVE identifiers were extracted from NSE output." >> "$CVE_SUMMARY_FILE"
    fi
}

# Runs Nmap NSE vulnerability scan and optional Searchsploit mapping.
run_vulnerability_mapping() {
    local nse_base nmap_xml search_status

    stage 8 "Vulnerability mapping, Full mode only"
    if [[ "$SCAN_MODE" != "Full" ]]; then
        VULNERABILITY_STATUS="[SKIP] Basic mode selected."
        CVE_COUNT=0
        {
            echo "Vulnerability summary"
            echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "Status: Basic mode selected; NSE vulnerability mapping was not run."
            echo "Potential findings require manual validation."
        } > "$VULNERABILITY_SUMMARY_FILE"
        {
            echo "CVE summary"
            echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
            echo
            echo "Basic mode selected; no NSE output was available for CVE extraction."
        } > "$CVE_SUMMARY_FILE"
        log_status "SKIP" "Vulnerability mapping is only run in Full mode."
        return 0
    fi

    nse_base="$NMAP_DIR/vuln_nse"
    nmap_xml="$NMAP_DIR/tcp_services.xml"
    run_command "Running Nmap NSE vulnerability scan" nmap \
        nmap -sV --script vuln -T3 --reason -oA "$nse_base" "$TARGET_SCOPE"

    {
        echo "Vulnerability summary"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "NSE output base: $nse_base"
        echo "NSE nmap output: $nse_base.nmap"
        echo "NSE XML output: $nse_base.xml"
        echo
    } > "$VULNERABILITY_SUMMARY_FILE"

    if [[ -f "$nmap_xml" ]]; then
        log_command searchsploit --nmap "$nmap_xml"
        if requires_tool searchsploit; then
            searchsploit --nmap "$nmap_xml" > "$SEARCHSPLOIT_FILE" 2>> "$LOG_FILE"
            search_status=$?
            echo "Searchsploit output: $SEARCHSPLOIT_FILE" >> "$VULNERABILITY_SUMMARY_FILE"
            echo "Searchsploit exit code: $search_status" >> "$VULNERABILITY_SUMMARY_FILE"
        else
            echo "Searchsploit skipped because the tool is missing." >> "$VULNERABILITY_SUMMARY_FILE"
        fi
    else
        echo "Searchsploit skipped because TCP XML output is missing: $nmap_xml" >> "$VULNERABILITY_SUMMARY_FILE"
    fi

    write_cve_summary "$nse_base.nmap"
    echo "CVE summary: $CVE_SUMMARY_FILE" >> "$VULNERABILITY_SUMMARY_FILE"
    echo "CVE count: $CVE_COUNT" >> "$VULNERABILITY_SUMMARY_FILE"
    echo "Potential findings require manual validation." >> "$VULNERABILITY_SUMMARY_FILE"

    VULNERABILITY_STATUS="[OK] Vulnerability outputs created: $VULNERABILITY_SUMMARY_FILE"
    log_status "OK" "$VULNERABILITY_STATUS"
    echo
    cat "$VULNERABILITY_SUMMARY_FILE"
}

# Escapes a markdown file for safe embedding in HTML.
html_escape_file() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$1"
}

# Prints escaped file content for HTML report sections.
html_pre_file() {
    local file="$1"
    if [[ -s "$file" ]]; then
        html_escape_file "$file"
    else
        echo "No data recorded."
    fi
}

# Prints login services as escaped text for the HTML report.
html_login_services() {
    if [[ -s "$LOGIN_SERVICES_FILE" ]]; then
        html_escape_file "$LOGIN_SERVICES_FILE"
    else
        echo "None"
    fi
}

# Prints known network infrastructure notices for summaries and reports.
print_lab_infrastructure_notes() {
    local found="no"

    if [[ -f "$SERVICE_SUMMARY_FILE" ]] && grep -q '^192\.168\.72\.2[[:space:]]' "$SERVICE_SUMMARY_FILE"; then
        echo "- 192.168.72.2: Network infrastructure / non-target"
        found="yes"
    fi

    if [[ "$found" == "no" ]]; then
        echo "None detected from the current parsed service summary."
    fi
}

# Writes a short guide for the generated run folder.
write_results_readme() {
    {
        echo "VULNER Results Folder"
        echo "====================="
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Target scope: $TARGET_SCOPE"
        echo "Scan mode: $SCAN_MODE"
        echo "Username list: $USER_LIST"
        echo "Username entries: $USER_LIST_COUNT"
        echo "Password list: $PASSWORD_LIST"
        echo "Password entries: $PASSWORD_LIST_COUNT"
        echo "Large wordlist warning status: $LARGE_WORDLIST_STATUS"
        echo
        echo "Top-level files:"
        echo "- README_RESULTS.txt: this guide"
        echo "- summary.txt: final run summary and counts"
        echo "- commands.txt: commands previewed or executed by the script"
        echo "- run.log: stage log and redirected command output"
        echo "- tool_check.txt: startup tool availability"
        echo
        echo "Directories:"
        echo "- nmap/: raw Nmap outputs"
        echo "- parsed/: parsed services, hosts, login services, CVEs, and Searchsploit mapping"
        echo "- credentials/: credential testing plan and approved credential test results"
        echo "- report/: Markdown and HTML reports"
        echo
        echo "Important parsed files:"
        echo "- $HOSTS_SUMMARY_FILE"
        echo "- $SERVICE_SUMMARY_FILE"
        echo "- $LOGIN_SERVICES_FILE"
        echo "- $VULNERABILITY_SUMMARY_FILE"
        echo "- $CVE_SUMMARY_FILE"
        echo "- $SEARCHSPLOIT_FILE"
        echo
        echo "Safety:"
        echo "- Use only on authorized private networks."
        echo "- Public targets, exploitation, and destructive actions are outside scope."
        echo "- Credential testing requires explicit approval for one discovered private host/service."
    } > "$README_RESULTS_FILE"
}

# Writes the final summary file.
write_summary() {
    {
        echo "Final Assessment Summary"
        echo "========================"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Script: $SCRIPT_NAME"
        echo "Target scope: $TARGET_SCOPE"
        echo "Scan mode: $SCAN_MODE"
        echo "Output directory: $OUTPUT_DIR"
        echo
        echo "Counts:"
        echo "- Hosts discovered: $HOST_COUNT"
        echo "- TCP services: $TCP_SERVICE_COUNT"
        echo "- UDP services: $UDP_SERVICE_COUNT"
        echo "- Total services: $SERVICE_COUNT"
        echo "- Login services: $LOGIN_SERVICE_COUNT"
        echo "- CVE count: $CVE_COUNT"
        echo
        echo "Wordlists:"
        echo "- Username list: $USER_LIST"
        echo "- Username entries: $USER_LIST_COUNT"
        echo "- Password list: $PASSWORD_LIST"
        echo "- Password entries: $PASSWORD_LIST_COUNT"
        echo "- Large wordlist warning status: $LARGE_WORDLIST_STATUS"
        echo
        echo "Statuses:"
        echo "- Credential status: $CREDENTIAL_STATUS"
        echo "- Vulnerability status: $VULNERABILITY_STATUS"
        echo "- Zip status: $ZIP_ARCHIVE_PATH"
        echo
        echo "Tool status:"
        cat "$TOOL_REPORT"
        echo
        echo "Discovered hosts:"
        cat "$HOSTS_SUMMARY_FILE"
        echo
        echo "Services discovered:"
        cat "$SERVICE_SUMMARY_FILE"
        echo
        echo "Login services discovered: $LOGIN_SERVICE_COUNT"
        if [[ -s "$LOGIN_SERVICES_FILE" ]]; then
            cat "$LOGIN_SERVICES_FILE"
        else
            echo "None"
        fi
        echo
        echo "Network infrastructure / non-target notes:"
        print_lab_infrastructure_notes
        echo
        echo "Important output paths:"
        echo "- Results README: $README_RESULTS_FILE"
        echo "- Run log: $LOG_FILE"
        echo "- Commands: $COMMAND_LOG"
        echo "- Tool check: $TOOL_REPORT"
        echo "- Hosts summary: $HOSTS_SUMMARY_FILE"
        echo "- Services summary: $SERVICE_SUMMARY_FILE"
        echo "- Login services: $LOGIN_SERVICES_FILE"
        echo "- Credential plan: $CREDENTIAL_PLAN_FILE"
        echo "- Credential results: $CREDENTIAL_RESULTS_DIR"
        echo "- Vulnerability summary: $VULNERABILITY_SUMMARY_FILE"
        echo "- CVE summary: $CVE_SUMMARY_FILE"
        echo "- Searchsploit mapping: $SEARCHSPLOIT_FILE"
        echo "- Nmap directory: $NMAP_DIR"
        echo "- Markdown report: $REPORT_MD"
        echo "- HTML report: $REPORT_HTML"
        echo
        echo "Next recommended manual steps:"
        echo "- Review parsed/hosts_summary.txt and parsed/services_summary.txt and confirm host ownership."
        echo "- Review credentials/credential_results only if a controlled credential test was approved."
        echo "- In Full mode, review parsed/vulnerability_summary.txt, parsed/cve_summary.txt, and raw Nmap/Searchsploit outputs."
        echo "- Use report/report.html, parsed summaries, and screenshots as evidence for the manually designed PDF."
        echo "- Do not run exploitation; document findings and remediation guidance."
    } > "$SUMMARY_FILE"
}

# Generates Markdown and HTML reports for the assessment run.
generate_reports() {
    {
        echo "# VULNER Network Assessment Report"
        echo
        echo "## Executive Summary"
        echo
        echo "This report summarizes an authorized private-network assessment run. Potential findings require manual validation."
        echo
        echo "- **Hosts discovered:** $HOST_COUNT"
        echo "- **TCP services:** $TCP_SERVICE_COUNT"
        echo "- **UDP services:** $UDP_SERVICE_COUNT"
        echo "- **Total services:** $SERVICE_COUNT"
        echo "- **Login services:** $LOGIN_SERVICE_COUNT"
        echo "- **CVE count:** $CVE_COUNT"
        echo "- **Credential status:** $CREDENTIAL_STATUS"
        echo "- **Username list:** $USER_LIST"
        echo "- **Username entries:** $USER_LIST_COUNT"
        echo "- **Password list:** $PASSWORD_LIST"
        echo "- **Password entries:** $PASSWORD_LIST_COUNT"
        echo "- **Large wordlist warning status:** $LARGE_WORDLIST_STATUS"
        echo
        echo "## Scope and Method"
        echo
        echo "- **Generated:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo "- **Target scope:** $TARGET_SCOPE"
        echo "- **Scan mode:** $SCAN_MODE"
        echo "- **Output directory:** $OUTPUT_DIR"
        echo
        echo "## Tool Status"
        echo
        echo '```text'
        cat "$TOOL_REPORT"
        echo '```'
        echo
        echo "## Discovered Hosts"
        echo
        echo '```text'
        cat "$HOSTS_SUMMARY_FILE"
        echo '```'
        echo
        echo "## Services by Host"
        echo
        echo '```text'
        cat "$SERVICE_SUMMARY_FILE"
        echo '```'
        echo
        echo "## Login Services"
        echo
        echo '```text'
        if [[ -s "$LOGIN_SERVICES_FILE" ]]; then
            cat "$LOGIN_SERVICES_FILE"
        else
            echo "None"
        fi
        echo '```'
        echo
        echo "## Credential Testing"
        echo
        echo "$CREDENTIAL_STATUS"
        echo
        echo '```text'
        cat "$CREDENTIAL_PLAN_FILE"
        echo '```'
        echo
        echo "## Vulnerability Mapping"
        echo
        echo '```text'
        cat "$VULNERABILITY_SUMMARY_FILE"
        echo '```'
        echo
        echo '```text'
        cat "$CVE_SUMMARY_FILE"
        echo '```'
        echo
        echo "## Evidence Files"
        echo
        echo "- Results README: $README_RESULTS_FILE"
        echo "- Run log: $LOG_FILE"
        echo "- Commands: $COMMAND_LOG"
        echo "- Tool check: $TOOL_REPORT"
        echo "- Nmap outputs: $NMAP_DIR"
        echo "- Hosts summary: $HOSTS_SUMMARY_FILE"
        echo "- Services summary: $SERVICE_SUMMARY_FILE"
        echo "- Login services: $LOGIN_SERVICES_FILE"
        echo "- Credential plan: $CREDENTIAL_PLAN_FILE"
        echo "- Credential results: $CREDENTIAL_RESULTS_DIR"
        echo "- Vulnerability summary: $VULNERABILITY_SUMMARY_FILE"
        echo "- CVE summary: $CVE_SUMMARY_FILE"
        echo "- Searchsploit mapping: $SEARCHSPLOIT_FILE"
        echo "- Summary: $SUMMARY_FILE"
        echo "- Markdown report: $REPORT_MD"
        echo "- HTML report: $REPORT_HTML"
        echo
        echo "## Safety and Limitations"
        echo
        echo "This report is for an authorized private network only. Public targets, exploitation, and destructive actions are outside scope. Credential testing is controlled and requires approval against a discovered private host/service. Potential findings require manual validation."
        echo
        echo "## Recommended Next Steps"
        echo
        echo "- Verify each finding manually in the authorized local network."
        echo "- Prioritize weak credentials, outdated services, and exposed remote login services."
        echo "- Patch vulnerable services, disable unused services, and enforce strong passwords."
        echo "- Keep evidence paths with the final submission PDF."
    } > "$REPORT_MD"

    {
        cat <<'HTML_HEAD'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VULNER Network Assessment Report</title>
  <style>
    :root {
      --ink: #17212b;
      --muted: #52606d;
      --line: #d9e2ec;
      --soft: #f5f7fa;
      --accent: #0f4c81;
      --accent-soft: #e6f0f8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      background: #ffffff;
      font-family: Arial, Helvetica, sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }
    main {
      max-width: 1040px;
      margin: 0 auto;
      padding: 34px 42px;
      background: #ffffff;
    }
    header {
      border-bottom: 3px solid var(--accent);
      margin-bottom: 26px;
      padding-bottom: 18px;
    }
    h1 {
      margin: 0 0 8px;
      color: var(--accent);
      font-size: 30px;
      line-height: 1.15;
    }
    .subtitle {
      color: var(--muted);
      margin: 0;
      font-size: 15px;
    }
    nav {
      border: 1px solid var(--line);
      background: var(--soft);
      padding: 12px 14px;
      margin: 18px 0 24px;
    }
    nav a {
      display: inline-block;
      color: var(--accent);
      margin: 3px 14px 3px 0;
      text-decoration: none;
      font-weight: 700;
    }
    h2 {
      break-after: avoid;
      page-break-after: avoid;
      color: var(--accent);
      font-size: 18px;
      margin: 28px 0 10px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--line);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px 18px;
    }
    .item {
      border: 1px solid var(--line);
      background: var(--soft);
      padding: 10px 12px;
      border-radius: 4px;
      min-width: 0;
    }
    .label {
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .03em;
      margin-bottom: 3px;
    }
    .value {
      font-family: Consolas, Menlo, monospace;
      overflow-wrap: anywhere;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 10px 0 14px;
      font-size: 13px;
    }
    th, td {
      border: 1px solid var(--line);
      padding: 8px 9px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      background: var(--accent-soft);
      color: #12344d;
      font-weight: 700;
    }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #f7f9fb;
      color: var(--ink);
      border: 1px solid var(--line);
      border-left: 4px solid var(--accent);
      padding: 12px;
      border-radius: 4px;
      font-family: Consolas, Menlo, monospace;
      font-size: 12px;
    }
    .status {
      border: 1px solid var(--line);
      background: #fbfcfd;
      padding: 12px;
      border-radius: 4px;
      font-weight: 700;
    }
    .safety {
      border: 1px solid #f0c36d;
      background: #fff8e6;
      padding: 12px;
      border-radius: 4px;
    }
    ul { margin-top: 8px; padding-left: 21px; }
    footer {
      border-top: 1px solid var(--line);
      margin-top: 30px;
      padding-top: 12px;
      color: var(--muted);
      font-size: 12px;
    }
    @media print {
      @page {
        size: A4;
        margin: 14mm 12mm;
      }
      html, body {
        background: #fff;
      }
      body {
        color: #000;
        font-size: 10.5pt;
        line-height: 1.35;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      main {
        max-width: none;
        margin: 0;
        padding: 0;
        border: 0;
        box-shadow: none;
      }
      header {
        border-bottom: 2px solid #000;
        margin-bottom: 12mm;
        padding-bottom: 5mm;
      }
      h1 {
        color: #000;
        font-size: 22pt;
      }
      h2 {
        color: #000;
        font-size: 13.5pt;
        margin-top: 8mm;
        break-after: avoid;
        page-break-after: avoid;
      }
      section, table, pre, .item, .status, .safety {
        break-inside: avoid;
        page-break-inside: avoid;
      }
      .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 6px 10px;
      }
      nav {
        display: none;
      }
      .item, pre, th, td, .status, .safety {
        background: #fff !important;
        color: #000 !important;
        border-color: #777 !important;
      }
      table {
        font-size: 9.5pt;
      }
      th {
        font-weight: 700;
      }
      pre {
        border-left: 2px solid #000;
        font-size: 9pt;
        white-space: pre-wrap;
      }
      .subtitle, .label, footer {
        color: #333 !important;
      }
      a { color: #000; text-decoration: none; }
    }
  </style>
</head>
<body>
<main>
HTML_HEAD
        cat <<HTML_BODY
  <header>
    <h1>VULNER Network Assessment Report</h1>
    <p class="subtitle">Authorized private-network scan results</p>
  </header>

  <nav>
    <a href="#executive-summary">Executive Summary</a>
    <a href="#scope-method">Scope and Method</a>
    <a href="#tool-status">Tool Status</a>
    <a href="#discovered-hosts">Discovered Hosts</a>
    <a href="#services-by-host">Services by Host</a>
    <a href="#login-services">Login Services</a>
    <a href="#credential-testing">Credential Testing</a>
    <a href="#vulnerability-mapping">Vulnerability Mapping</a>
    <a href="#evidence-files">Evidence Files</a>
    <a href="#safety-limitations">Safety and Limitations</a>
    <a href="#next-steps">Recommended Next Steps</a>
  </nav>

  <section id="executive-summary">
    <h2>Executive Summary</h2>
    <div class="grid">
      <div class="item"><span class="label">Hosts discovered</span><span class="value">$HOST_COUNT</span></div>
      <div class="item"><span class="label">TCP services</span><span class="value">$TCP_SERVICE_COUNT</span></div>
      <div class="item"><span class="label">UDP services</span><span class="value">$UDP_SERVICE_COUNT</span></div>
      <div class="item"><span class="label">Total services</span><span class="value">$SERVICE_COUNT</span></div>
      <div class="item"><span class="label">Login services</span><span class="value">$LOGIN_SERVICE_COUNT</span></div>
      <div class="item"><span class="label">CVE count</span><span class="value">$CVE_COUNT</span></div>
    </div>
    <p>Potential findings require manual validation.</p>
  </section>

  <section id="scope-method">
    <h2>Scope and Method</h2>
    <div class="grid">
      <div class="item"><span class="label">Generated</span><span class="value">$(date '+%Y-%m-%d %H:%M:%S')</span></div>
      <div class="item"><span class="label">Script</span><span class="value">$SCRIPT_NAME</span></div>
      <div class="item"><span class="label">Scan mode</span><span class="value">$SCAN_MODE</span></div>
      <div class="item"><span class="label">Target scope</span><span class="value">$TARGET_SCOPE</span></div>
      <div class="item"><span class="label">Output directory</span><span class="value">$OUTPUT_DIR</span></div>
      <div class="item"><span class="label">Username list</span><span class="value">$USER_LIST</span></div>
      <div class="item"><span class="label">Username entries</span><span class="value">$USER_LIST_COUNT</span></div>
      <div class="item"><span class="label">Password list</span><span class="value">$PASSWORD_LIST</span></div>
      <div class="item"><span class="label">Password entries</span><span class="value">$PASSWORD_LIST_COUNT</span></div>
      <div class="item"><span class="label">Large wordlist warning status</span><span class="value">$LARGE_WORDLIST_STATUS</span></div>
    </div>
  </section>

  <section id="tool-status">
    <h2>Tool Status</h2>
    <pre>
HTML_BODY
        html_pre_file "$TOOL_REPORT"
        cat <<HTML_BODY
</pre>
  </section>

  <section id="discovered-hosts">
    <h2>Discovered Hosts</h2>
    <pre>
HTML_BODY
        html_pre_file "$HOSTS_SUMMARY_FILE"
        cat <<HTML_BODY
</pre>
  </section>

  <section id="services-by-host">
    <h2>Services by Host</h2>
    <pre>
HTML_BODY
        html_pre_file "$SERVICE_SUMMARY_FILE"
        cat <<HTML_BODY
</pre>
  </section>

  <section id="login-services">
    <h2>Login Services</h2>
    <pre>
HTML_BODY
        html_login_services
        cat <<HTML_BODY
</pre>
  </section>

  <section id="credential-testing">
    <h2>Credential Testing</h2>
    <div class="status">$CREDENTIAL_STATUS</div>
    <pre>
HTML_BODY
        html_pre_file "$CREDENTIAL_PLAN_FILE"
        cat <<HTML_BODY
</pre>
  </section>

  <section id="vulnerability-mapping">
    <h2>Vulnerability Mapping</h2>
    <pre>
HTML_BODY
        html_pre_file "$VULNERABILITY_SUMMARY_FILE"
        cat <<HTML_BODY
</pre>
    <pre>
HTML_BODY
        html_pre_file "$CVE_SUMMARY_FILE"
        cat <<HTML_BODY
</pre>
  </section>

  <section id="evidence-files">
    <h2>Evidence Files</h2>
    <table>
      <thead><tr><th>Evidence</th><th>Path</th></tr></thead>
      <tbody>
        <tr><td>Results README</td><td>$README_RESULTS_FILE</td></tr>
        <tr><td>Run log</td><td>$LOG_FILE</td></tr>
        <tr><td>Commands</td><td>$COMMAND_LOG</td></tr>
        <tr><td>Tool check</td><td>$TOOL_REPORT</td></tr>
        <tr><td>Nmap outputs</td><td>$NMAP_DIR</td></tr>
        <tr><td>Hosts summary</td><td>$HOSTS_SUMMARY_FILE</td></tr>
        <tr><td>Services summary</td><td>$SERVICE_SUMMARY_FILE</td></tr>
        <tr><td>Login services</td><td>$LOGIN_SERVICES_FILE</td></tr>
        <tr><td>Credential plan</td><td>$CREDENTIAL_PLAN_FILE</td></tr>
        <tr><td>Credential results</td><td>$CREDENTIAL_RESULTS_DIR</td></tr>
        <tr><td>Vulnerability summary</td><td>$VULNERABILITY_SUMMARY_FILE</td></tr>
        <tr><td>CVE summary</td><td>$CVE_SUMMARY_FILE</td></tr>
        <tr><td>Searchsploit mapping</td><td>$SEARCHSPLOIT_FILE</td></tr>
        <tr><td>Summary</td><td>$SUMMARY_FILE</td></tr>
        <tr><td>Markdown report</td><td>$REPORT_MD</td></tr>
        <tr><td>HTML report</td><td>$REPORT_HTML</td></tr>
        <tr><td>Zip archive</td><td>$ZIP_ARCHIVE_PATH</td></tr>
      </tbody>
    </table>
  </section>

  <section id="safety-limitations">
    <h2>Safety and Limitations</h2>
    <div class="safety">Use only on authorized private networks. Public targets, exploitation, and destructive actions are outside scope. Credential testing is controlled and requires approval against a discovered private host/service. Potential findings require manual validation.</div>
  </section>

  <section id="next-steps">
    <h2>Recommended Next Steps</h2>
    <ul>
      <li>Review the discovered services and verify each finding manually in the authorized local network.</li>
      <li>Prioritize weak credentials, outdated services, and exposed remote login services.</li>
      <li>Patch vulnerable services, disable unused services, and enforce strong passwords.</li>
      <li>Keep this report and the evidence files with the final submission PDF.</li>
    </ul>
  </section>

  <footer>Generated by $SCRIPT_NAME - VULNER Network Service and Vulnerability Mapper. Authorized private-network use only.</footer>
HTML_BODY
        cat <<'HTML_TAIL'
</main>
</body>
</html>
HTML_TAIL
    } > "$REPORT_HTML"

    log_status "OK" "Reports generated: $REPORT_MD and $REPORT_HTML"
}

# Lets the user search saved result files.
search_results() {
    local choice term

    read -r -p "Search inside saved results now? [y/N]: " choice
    choice="${choice:-N}"
    case "$choice" in
        y|Y|yes|YES)
            read -r -p "Enter search term: " term
            [[ -n "$term" ]] || {
                log_status "SKIP" "Empty search term; search skipped."
                return 0
            }
            log_status "INFO" "Searching results for: $term"
            grep -Rni -- "$term" "$OUTPUT_DIR" | tee "$OUTPUT_DIR/search_results.txt" || true
            ;;
        n|N|no|NO)
            log_status "SKIP" "Result search skipped by user."
            ;;
        *)
            log_status "SKIP" "Invalid search choice; skipping."
            ;;
    esac
}

# Creates a zip archive if the user approves.
zip_results() {
    local choice zip_file status

    read -r -p "Save all results into a Zip archive? [Y/n]: " choice
    choice="${choice:-Y}"
    case "$choice" in
        y|Y|yes|YES) ;;
        n|N|no|NO)
            ZIP_ARCHIVE_PATH="Not created; user skipped zip."
            log_status "SKIP" "Zip archive skipped by user."
            return 0
            ;;
        *)
            ZIP_ARCHIVE_PATH="Not created; invalid zip choice."
            log_status "SKIP" "Invalid zip choice; skipping archive."
            return 0
            ;;
    esac

    zip_file="${OUTPUT_DIR}.zip"
    log_command zip -r "$zip_file" "$OUTPUT_DIR"
    requires_tool zip || {
        ZIP_ARCHIVE_PATH="Not created; zip is missing."
        return 0
    }
    zip -r "$zip_file" "$OUTPUT_DIR" >> "$LOG_FILE" 2>&1
    status=$?
    ZIP_ARCHIVE_PATH="$zip_file (exit code $status)"
    log_status "OK" "Zip archive result: $ZIP_ARCHIVE_PATH"
}

# Prints the final summary box to the terminal.
print_final_summary() {
    echo
    separator
    echo "${CYAN}${BOLD}Final Summary${RESET}"
    separator
    cat "$SUMMARY_FILE"
}

# Runs the main guided workflow.
main() {
    init_colors
    show_banner
    collect_initial_inputs
    tool_check_workflow
    input_validation_summary
    scope_confirmation
    select_scan_mode
    select_password_list
    run_tcp_scan
    run_udp_scan
    parse_nmap_services
    credential_workflow
    run_vulnerability_mapping
    stage 9 "Summary, search, archive, and report"
    search_results
    zip_results
    write_results_readme
    write_summary
    generate_reports
    print_final_summary
    log_status "OK" "Done. Review output in: $OUTPUT_DIR"
}

main "$@"
