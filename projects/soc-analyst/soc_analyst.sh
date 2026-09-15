#!/usr/bin/env bash

# SOC Analyst Checker for authorized training labs. The tool discovers the local
# network and offers three bounded Nmap attacks. Logs are written to
# /var/log/soc_checker.log, so root is required. Dependencies: nmap, ip, awk,
# grep, and date.

set -u
set -o pipefail

readonly LOG_FILE="/var/log/soc_checker.log"
readonly SCRIPT_VERSION="1.0"

ACTIVE_INTERFACE=""
LOCAL_IP=""
SUBNET_CIDR=""
DEFAULT_GATEWAY=""
SELECTED_ATTACK=""
SELECTED_TARGET=""
SESSION_ID=""
LOG_READY=false
PROGRAM_END_LOGGED=false
PROGRAM_EXIT_CODE=0
declare -a DISCOVERED_HOSTS=()
declare -a ELIGIBLE_TARGETS=()

print_banner() {
    printf '%s\n' \
        '========================================' \
        "      SOC Analyst Checker v${SCRIPT_VERSION}" \
        '      Authorized SOC Lab Use Only' \
        '========================================'
}

show_usage() {
    printf '%s\n' \
        "Usage: ./checker.sh [--help|--version]" \
        '' \
        '  --help     Show this command-line help and exit' \
        '  --version  Show the script version and exit'
}

parse_arguments() {
    if (( $# > 1 )); then
        printf 'Error: use at most one command-line option.\n' >&2
        show_usage >&2
        exit 1
    fi

    case "${1:-}" in
        '') ;;
        --help)
            show_usage
            exit 0
            ;;
        --version)
            printf 'SOC Analyst Checker v%s\n' "$SCRIPT_VERSION"
            exit 0
            ;;
        *)
            printf 'Error: unknown option: %s\n' "$1" >&2
            show_usage >&2
            exit 1
            ;;
    esac
}

check_root() {
    if (( EUID != 0 )); then
        printf 'Error: root privileges are required to write %s.\n' "$LOG_FILE" >&2
        printf 'Run this script with: sudo ./checker.sh\n' >&2
        exit 1
    fi
}

check_dependencies() {
    local dependency
    local -a missing=()
    local -a required=(nmap ip awk grep date)

    for dependency in "${required[@]}"; do
        if ! command -v "$dependency" >/dev/null 2>&1; then
            missing+=("$dependency")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        printf 'Error: missing required dependencies: %s\n' "${missing[*]}" >&2
        printf 'On Debian/Kali, install the corresponding packages with apt.\n' >&2
        printf 'Example: sudo apt install nmap iproute2 gawk grep coreutils\n' >&2
        exit 1
    fi
}

confirm_authorization() {
    local response

    printf '\nThis tool is restricted to systems you are authorized to test.\n'
    read -r -p 'Do you confirm this is an authorized SOC lab? [y/N] ' response
    case "$response" in
        [yY]|[yY][eE][sS]) ;;
        *)
            printf 'Authorization was not confirmed. Exiting safely.\n'
            exit 0
            ;;
    esac
}

detect_network() {
    local address_cidr

    # Use the default route to identify the active interface and gateway.
    ACTIVE_INTERFACE=$(ip route show default 2>/dev/null | awk 'NR == 1 { for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }')
    DEFAULT_GATEWAY=$(ip route show default 2>/dev/null | awk 'NR == 1 { for (i=1; i<=NF; i++) if ($i == "via") { print $(i+1); exit } }')

    if [[ -z "$ACTIVE_INTERFACE" ]]; then
        printf 'Error: no default-route interface was detected. Check the lab network connection.\n' >&2
        exit 1
    fi

    address_cidr=$(ip -o -4 addr show dev "$ACTIVE_INTERFACE" scope global 2>/dev/null | awk 'NR == 1 { print $4 }')
    if [[ -z "$address_cidr" ]]; then
        printf 'Error: no global IPv4 address found on interface %s.\n' "$ACTIVE_INTERFACE" >&2
        exit 1
    fi

    LOCAL_IP=${address_cidr%/*}
    SUBNET_CIDR=$(ip -4 route show dev "$ACTIVE_INTERFACE" proto kernel scope link 2>/dev/null \
        | awk -v ip="$LOCAL_IP" '{ for (i=1; i<NF; i++) if ($i == "src" && $(i+1) == ip) { print $1; exit } }')
    if [[ -z "$SUBNET_CIDR" ]]; then
        # Nmap accepts an interface address with its prefix when no network route is listed.
        SUBNET_CIDR=$address_cidr
    fi
}

discover_hosts() {
    local scan_output line candidate subnet_address prefix
    local -A seen_hosts=()

    # Ping-scan only the automatically detected local subnet, then parse both
    # "IP" and "hostname (IP)" Nmap report formats.
    if [[ "$SUBNET_CIDR" != */* ]]; then
        printf 'Error: detected subnet %s is not valid IPv4 CIDR notation.\n' "$SUBNET_CIDR" >&2
        exit 1
    fi
    subnet_address=${SUBNET_CIDR%/*}
    prefix=${SUBNET_CIDR##*/}
    if ! is_valid_ipv4 "$subnet_address" || [[ ! "$prefix" =~ ^(0|[1-9][0-9]?)$ ]] \
        || (( 10#$prefix > 32 )); then
        printf 'Error: detected subnet %s is not valid IPv4 CIDR notation.\n' "$SUBNET_CIDR" >&2
        exit 1
    fi
    if (( 10#$prefix < 24 )); then
        printf 'Error: detected subnet %s is broader than /24.\n' "$SUBNET_CIDR" >&2
        printf 'Automatic discovery is limited to /24 or smaller networks for safety.\n' >&2
        exit 1
    fi

    printf '\nDiscovering live hosts with a safe Nmap ping scan...\n'
    if ! scan_output=$(nmap -sn "$SUBNET_CIDR" 2>&1); then
        printf 'Error: host discovery failed. Nmap reported:\n%s\n' "$scan_output" >&2
        exit 1
    fi

    DISCOVERED_HOSTS=()
    ELIGIBLE_TARGETS=()
    while IFS= read -r line; do
        candidate=$(awk '{ print $NF }' <<< "$line")
        candidate=${candidate#(}
        candidate=${candidate%)}

        if is_valid_ipv4 "$candidate" && [[ -z ${seen_hosts[$candidate]+present} ]]; then
            DISCOVERED_HOSTS+=("$candidate")
            seen_hosts["$candidate"]=1
            if is_private_ipv4 "$candidate" && [[ "$candidate" != "$LOCAL_IP" ]]; then
                ELIGIBLE_TARGETS+=("$candidate")
            fi
        fi
    done < <(grep '^Nmap scan report for ' <<< "$scan_output")
}

display_hosts() {
    local host host_note

    printf '\n%s\n' \
        '========================================' \
        ' Network Information' \
        '========================================'
    printf 'Interface : %s\n' "$ACTIVE_INTERFACE"
    printf 'Local IP  : %s\n' "$LOCAL_IP"
    printf 'Network   : %s\n' "$SUBNET_CIDR"
    printf 'Gateway   : %s\n' "${DEFAULT_GATEWAY:-Not detected}"
    printf '\nDiscovered hosts:\n'

    if (( ${#DISCOVERED_HOSTS[@]} == 0 )); then
        printf 'No live IPv4 hosts were reported by discovery.\n'
    else
        for host in "${DISCOVERED_HOSTS[@]}"; do
            host_note=""
            [[ "$host" == "$LOCAL_IP" ]] && host_note=" (local host; not eligible)"
            if ! is_private_ipv4 "$host"; then
                host_note=" (non-RFC1918; not eligible)"
            fi
            printf '  %s%s\n' "$host" "$host_note"
        done
    fi
}

is_valid_ipv4() {
    local ip=${1:-}
    local octet
    local -a octets

    # Validate structure first, then force base-10 octet arithmetic.
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$ip"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        [[ ${#octet} -eq 1 || ${octet:0:1} != 0 ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

is_private_ipv4() {
    local ip=${1:-}
    local first second _third _fourth

    is_valid_ipv4 "$ip" || return 1
    IFS='.' read -r first second _third _fourth <<< "$ip"
    first=$((10#$first))
    second=$((10#$second))

    if (( first == 10 )); then
        return 0
    fi
    if (( first == 172 && second >= 16 && second <= 31 )); then
        return 0
    fi
    if (( first == 192 && second == 168 )); then
        return 0
    fi
    return 1
}

select_target() {
    local choice host_number manual_ip candidate target_note
    local -a random_hosts=()

    printf '\n%s\n' \
        '========================================' \
        ' Select Target' \
        '========================================'
    printf 'Discovered targets:\n'
    if (( ${#ELIGIBLE_TARGETS[@]} == 0 )); then
        printf 'No eligible discovered targets.\n'
    else
        for host_number in "${!ELIGIBLE_TARGETS[@]}"; do
            target_note=""
            [[ "${ELIGIBLE_TARGETS[$host_number]}" == "$DEFAULT_GATEWAY" ]] \
                && target_note=" (default gateway; explicit selection only)"
            printf '[%d] %s%s\n' "$((host_number + 1))" "${ELIGIBLE_TARGETS[$host_number]}" "$target_note"
        done
    fi
    printf '\n[M] Enter IP manually\n[R] Random target\n[Q] Quit\n\n'
    read -r -p 'Select target: ' choice

    case "${choice,,}" in
        [0-9]*)
            if (( ${#ELIGIBLE_TARGETS[@]} == 0 )); then
                printf 'Error: no discovered private targets are available.\n' >&2
                exit 1
            fi
            host_number=$choice
            if [[ ! "$host_number" =~ ^[0-9]+$ ]]; then
                printf 'Error: target selection must be a displayed number.\n' >&2
                exit 1
            fi
            if (( ${#host_number} > 6 )); then
                printf 'Error: target selection number is too long.\n' >&2
                exit 1
            fi
            host_number=$((10#$host_number))
            if (( host_number < 1 || host_number > ${#ELIGIBLE_TARGETS[@]} )); then
                printf 'Error: host number is outside the displayed range.\n' >&2
                exit 1
            fi
            SELECTED_TARGET=${ELIGIBLE_TARGETS[$((host_number - 1))]}
            ;;
        r)
            # Never choose the default gateway implicitly; it remains available
            # when the user explicitly chooses or enters it.
            for candidate in "${ELIGIBLE_TARGETS[@]}"; do
                [[ "$candidate" != "$DEFAULT_GATEWAY" ]] && random_hosts+=("$candidate")
            done
            if (( ${#random_hosts[@]} == 0 )); then
                printf 'Error: no non-gateway discovered host is available for random selection.\n' >&2
                exit 1
            fi
            SELECTED_TARGET=${random_hosts[$((RANDOM % ${#random_hosts[@]}))]}
            ;;
        m)
            read -r -p 'Enter an RFC1918 private IPv4 address: ' manual_ip
            if ! is_valid_ipv4 "$manual_ip"; then
                printf 'Error: invalid IPv4 address syntax.\n' >&2
                exit 1
            fi
            if ! is_private_ipv4 "$manual_ip"; then
                printf 'Error: only RFC1918 private IPv4 targets are allowed.\n' >&2
                exit 1
            fi
            if [[ "$manual_ip" == "$LOCAL_IP" ]]; then
                printf 'Error: the local host cannot be selected as a target.\n' >&2
                exit 1
            fi
            SELECTED_TARGET=$manual_ip
            ;;
        q)
            printf 'No target selected. Exiting.\n'
            exit 0
            ;;
        *)
            printf 'Error: invalid target selection.\n' >&2
            exit 1
            ;;
    esac

    printf 'Selected target: %s\n' "$SELECTED_TARGET"
}

show_attack_menu() {
    printf '\n%s\n' \
        '========================================' \
        ' Select Attack' \
        '========================================' \
        '[1] TCP SYN Scan' \
        '    Limited scan of the 100 most common TCP ports.' \
        '' \
        '[2] UDP Scan' \
        '    Limited scan of the 20 most common UDP ports.' \
        '' \
        '[3] Service Detection Scan' \
        '    Detects services and versions on 20 common TCP ports.' \
        '' \
        '[R] Random Attack' \
        '[H] Help' \
        '[Q] Quit'
}

show_attack_help() {
    printf '\n%s\n' \
        '========================================' \
        ' Checker Help' \
        '========================================' \
        'Purpose : Generate controlled telemetry for an authorized SOC lab.' \
        'Activity: Each attack sends bounded Nmap traffic to the confirmed target.' \
        'Targets : Choose a discovered host, a random non-gateway host, or enter' \
        '          an RFC1918 private IPv4 address.' \
        "Logs    : ${LOG_FILE}" \
        'Safety  : Use only on lab systems you are explicitly authorized to test.'
}

get_attack_name() {
    case "$1" in
        TCP_SYN_SCAN) printf 'TCP SYN Scan\n' ;;
        UDP_SCAN) printf 'UDP Scan\n' ;;
        SERVICE_DETECTION) printf 'Service Detection Scan\n' ;;
        *) return 1 ;;
    esac
}

get_attack_type() {
    case "$1" in
        TCP_SYN_SCAN|UDP_SCAN|SERVICE_DETECTION) printf 'REAL NETWORK ACTIVITY\n' ;;
        *) return 1 ;;
    esac
}

get_attack_description() {
    case "$1" in
        TCP_SYN_SCAN)
            printf 'Performs a limited SYN scan against the 100 most common TCP ports.\n'
            ;;
        UDP_SCAN)
            printf 'Performs a limited UDP scan against the 20 most common UDP ports.\n'
            ;;
        SERVICE_DETECTION)
            printf 'Performs service and version detection against 20 common TCP ports.\n'
            ;;
        *) return 1 ;;
    esac
}

select_attack() {
    local choice attack_name

    while true; do
        printf '\n'
        read -r -p 'Select attack: ' choice
        case "${choice,,}" in
            1) SELECTED_ATTACK="TCP_SYN_SCAN" ;;
            2) SELECTED_ATTACK="UDP_SCAN" ;;
            3) SELECTED_ATTACK="SERVICE_DETECTION" ;;
            r)
                case $((RANDOM % 3 + 1)) in
                    1) SELECTED_ATTACK="TCP_SYN_SCAN" ;;
                    2) SELECTED_ATTACK="UDP_SCAN" ;;
                    3) SELECTED_ATTACK="SERVICE_DETECTION" ;;
                esac
                attack_name=$(get_attack_name "$SELECTED_ATTACK")
                printf 'Random selection: %s\n' "$attack_name"
                ;;
            h|-h|help)
                show_attack_help
                printf '\n'
                show_attack_menu
                continue
                ;;
            q)
                printf 'No attack selected. Exiting.\n'
                exit 0
                ;;
            *)
                printf 'Error: invalid attack selection. Choose 1, 2, 3, R, H, or Q.\n' >&2
                exit 1
                ;;
        esac
        return 0
    done
}

write_log() {
    local attack_type=$1
    local target=$2
    local status=$3
    local extra=${4:-}
    local timestamp

    if ! timestamp=$(date --iso-8601=seconds); then
        printf 'Error: unable to generate an audit timestamp.\n' >&2
        return 1
    fi
    # Audit records are structured for easy SIEM parsing and session correlation.
    if [[ -n "$extra" ]]; then
        printf '%s | SESSION=%s | ATTACK=%s | TARGET=%s | STATUS=%s | %s\n' \
            "$timestamp" "$SESSION_ID" "$attack_type" "$target" "$status" "$extra" >> "$LOG_FILE"
    else
        printf '%s | SESSION=%s | ATTACK=%s | TARGET=%s | STATUS=%s\n' \
            "$timestamp" "$SESSION_ID" "$attack_type" "$target" "$status" >> "$LOG_FILE"
    fi
}

write_program_log() {
    local event=$1
    local extra=${2:-}
    local timestamp

    [[ "$LOG_READY" == true ]] || return 0
    if ! timestamp=$(date --iso-8601=seconds); then
        printf 'Warning: unable to generate a program-event timestamp.\n' >&2
        return 1
    fi
    if [[ -n "$extra" ]]; then
        printf '%s | SESSION=%s | EVENT=%s | %s\n' \
            "$timestamp" "$SESSION_ID" "$event" "$extra" >> "$LOG_FILE"
    else
        printf '%s | SESSION=%s | EVENT=%s\n' "$timestamp" "$SESSION_ID" "$event" >> "$LOG_FILE"
    fi
}

attack_syn_scan() {
    local target=$1
    local exit_code

    printf 'Running TCP SYN Scan against %s...\n' "$target"
    printf 'Command: nmap -Pn -sS --top-ports 100 %s\n\n' "$target"
    write_log "TCP_SYN_SCAN" "$target" "STARTED" || return 1

    # Keep reconnaissance bounded to the 100 most common TCP ports.
    nmap -Pn -sS --top-ports 100 "$target"
    exit_code=$?

    if (( exit_code == 0 )); then
        write_log "TCP_SYN_SCAN" "$target" "COMPLETED" "EXIT_CODE=0" || return 1
    else
        write_log "TCP_SYN_SCAN" "$target" "FAILED" "EXIT_CODE=$exit_code" || return "$exit_code"
    fi
    return "$exit_code"
}

attack_udp_scan() {
    local target=$1
    local exit_code

    printf 'Running UDP Scan against %s...\n' "$target"
    printf 'Command: nmap -Pn -sU --top-ports 20 %s\n\n' "$target"
    write_log "UDP_SCAN" "$target" "STARTED" || return 1

    # Limit UDP reconnaissance to a small set of common ports.
    nmap -Pn -sU --top-ports 20 "$target"
    exit_code=$?

    if (( exit_code == 0 )); then
        write_log "UDP_SCAN" "$target" "COMPLETED" "EXIT_CODE=0" || return 1
    else
        write_log "UDP_SCAN" "$target" "FAILED" "EXIT_CODE=$exit_code" || return "$exit_code"
    fi
    return "$exit_code"
}

attack_service_detection() {
    local target=$1
    local exit_code

    printf 'Running Service Detection Scan against %s...\n' "$target"
    printf 'Command: nmap -Pn -sV --top-ports 20 %s\n\n' "$target"
    write_log "SERVICE_DETECTION" "$target" "STARTED" || return 1

    # Bound active version enumeration to 20 common TCP ports.
    nmap -Pn -sV --top-ports 20 "$target"
    exit_code=$?

    if (( exit_code == 0 )); then
        write_log "SERVICE_DETECTION" "$target" "COMPLETED" "EXIT_CODE=0" || return 1
    else
        write_log "SERVICE_DETECTION" "$target" "FAILED" "EXIT_CODE=$exit_code" || return "$exit_code"
    fi
    return "$exit_code"
}

cleanup() {
    local exit_code=${1:-0}

    # Record a normal end once; no temporary resources currently need removal.
    if (( exit_code != 0 )); then
        PROGRAM_EXIT_CODE=$exit_code
    fi
    if [[ "$LOG_READY" == true && "$PROGRAM_END_LOGGED" == false ]]; then
        PROGRAM_END_LOGGED=true
        if ! write_program_log "PROGRAM_END" "EXIT_CODE=$PROGRAM_EXIT_CODE"; then
            printf 'Warning: unable to write the program-end record to %s.\n' "$LOG_FILE" >&2
        fi
    fi
}

handle_interrupt() {
    printf '\nInterrupted. Cleaning up and exiting safely.\n' >&2
    if [[ "$LOG_READY" == true && "$PROGRAM_END_LOGGED" == false ]]; then
        PROGRAM_END_LOGGED=true
        if ! write_program_log "PROGRAM_INTERRUPTED"; then
            printf 'Warning: unable to write the interruption record to %s.\n' "$LOG_FILE" >&2
        fi
    fi
    exit 130
}

initialize_session() {
    # Timestamp plus process ID is unique enough for a single training host.
    printf -v SESSION_ID '%(%Y%m%d_%H%M%S)T_%d' -1 "$$"
}

display_execution_summary() {
    local attack_name attack_type description

    attack_name=$(get_attack_name "$SELECTED_ATTACK") || return 1
    attack_type=$(get_attack_type "$SELECTED_ATTACK") || return 1
    description=$(get_attack_description "$SELECTED_ATTACK") || return 1
    printf '\n%s\n' \
        '========================================' \
        ' Execution Summary' \
        '========================================'
    printf 'Attack    : %s\n' "$attack_name"
    printf 'Type      : %s\n' "$attack_type"
    printf 'Target    : %s\n' "$SELECTED_TARGET"
    printf 'Interface : %s\n' "$ACTIVE_INTERFACE"
    printf 'Network   : %s\n' "$SUBNET_CIDR"
    printf 'Log       : %s\n' "$LOG_FILE"
    printf '\nDescription: %s\n' "$description"
}

main() {
    local confirmation attack_exit attack_name

    trap handle_interrupt INT
    trap 'cleanup $?' EXIT

    parse_arguments "$@"
    initialize_session
    print_banner
    confirm_authorization

    check_root
    check_dependencies

    # Keep the log root-only. A SIEM collector may need lab-specific group
    # ownership or read permissions, which this script deliberately does not set.
    umask 077
    touch "$LOG_FILE" || {
        printf 'Error: unable to create log file %s. Check root permissions and disk space.\n' "$LOG_FILE" >&2
        exit 1
    }
    chmod 600 "$LOG_FILE" || {
        printf 'Error: unable to set secure permissions on %s.\n' "$LOG_FILE" >&2
        exit 1
    }
    LOG_READY=true
    write_program_log "PROGRAM_START" || {
        printf 'Error: unable to write the program-start record to %s.\n' "$LOG_FILE" >&2
        PROGRAM_END_LOGGED=true
        exit 1
    }

    detect_network
    discover_hosts

    display_hosts
    show_attack_menu
    select_attack
    select_target

    attack_name=$(get_attack_name "$SELECTED_ATTACK") || {
        printf 'Error: internal attack selection failure.\n' >&2
        exit 1
    }
    printf '\nSelected attack: %s\n' "$attack_name"
    display_execution_summary || {
        printf 'Error: unable to build the execution summary.\n' >&2
        exit 1
    }
    write_log "$SELECTED_ATTACK" "$SELECTED_TARGET" "SELECTED" || {
            printf 'Error: unable to record the selected attack.\n' >&2
        exit 1
    }
    printf '\n'
    read -r -p 'Proceed? [y/N] ' confirmation
    case "$confirmation" in
        [yY]|[yY][eE][sS]) ;;
        *)
            write_log "$SELECTED_ATTACK" "$SELECTED_TARGET" "CANCELLED" || {
                printf 'Error: unable to record attack cancellation.\n' >&2
                exit 1
            }
            printf 'Attack cancelled. No attack was performed.\n'
            exit 0
            ;;
    esac

    attack_exit=0
    case "$SELECTED_ATTACK" in
        TCP_SYN_SCAN) attack_syn_scan "$SELECTED_TARGET" || attack_exit=$? ;;
        UDP_SCAN) attack_udp_scan "$SELECTED_TARGET" || attack_exit=$? ;;
        SERVICE_DETECTION) attack_service_detection "$SELECTED_TARGET" || attack_exit=$? ;;
    esac

    if (( attack_exit == 0 )); then
        printf '[+] Attack completed successfully.\n[+] Audit log: %s\n' "$LOG_FILE"
    else
        printf '[-] Attack failed with exit code: %d\n[-] Check audit log: %s\n' \
            "$attack_exit" "$LOG_FILE" >&2
        return "$attack_exit"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
