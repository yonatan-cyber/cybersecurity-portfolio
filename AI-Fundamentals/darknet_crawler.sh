#!/bin/bash

set -uo pipefail
umask 077

# --- Configuration ----------------------------------------------------------
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DATA_DIR="${DARKCRAWL_DATA_DIR:-$SCRIPT_DIR/data}"
readonly INPUT_FILE="${1:-$SCRIPT_DIR/onion_sites.txt}"
readonly QUEUE_FILE="$DATA_DIR/queue.txt"
readonly VISITED_FILE="$DATA_DIR/visited.txt"
readonly ALERT_FILE="$DATA_DIR/alert_words.txt"
readonly LOG_FILE="$DATA_DIR/crawler.log"
readonly STATE_FILE="$DATA_DIR/state.env"
readonly TMP_DIR="$DATA_DIR/tmp"

readonly TOR_HOST="${TOR_HOST:-127.0.0.1}"
readonly TOR_PORT="${TOR_PORT:-9050}"
readonly CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-20}"
readonly MAX_TIME="${MAX_TIME:-60}"
readonly MAX_PAGE_BYTES="${MAX_PAGE_BYTES:-2097152}"
readonly USER_AGENT="Research-Crawler/1.0"

# curl's socks5h mode sends DNS resolution through Tor. Set TRANSPORT to
# "proxychains" only if that command is installed and configured for Tor.
readonly TRANSPORT="${TRANSPORT:-tor}"

# --- Small helpers -----------------------------------------------------------
timestamp() { date '+%Y-%m-%d %H:%M:%S'; }
trim() { sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
pause() { read -r -p "Press Enter to continue..." _; }

log_event() {
    # Format: date | time | status | URL | title/comment
    printf '%s | %-10s | %s | %s\n' "$(timestamp)" "$1" "$2" "$3" >> "$LOG_FILE"
}

is_onion_url() {
    # Accept a bare host or http(s) URL. Onion v3 names contain 56 base32 chars;
    # 16-char legacy names are accepted for coursework input/status reporting.
    [[ "${1,,}" =~ ^(https?://)?[a-z2-7]{16}([a-z2-7]{40})?\.onion(/[^[:space:]]*)?$ ]]
}

normalise_url() {
    local url
    url="$(printf '%s' "$1" | trim)"
    url="${url%%#*}"
    [[ "$url" =~ ^https?:// ]] || url="http://$url"
    printf '%s\n' "$url"
}

contains_line() { grep -Fqx -- "$1" "$2" 2>/dev/null; }

append_unique() {
    local value="$1" file="$2"
    contains_line "$value" "$file" || printf '%s\n' "$value" >> "$file"
}

# --- Environment setup and input handling ----------------------------------
check_dependencies() {
    local missing=() command
    for command in curl grep sed awk sort date; do
        command -v "$command" >/dev/null 2>&1 || missing+=("$command")
    done
    if ((${#missing[@]})); then
        printf 'Missing required commands: %s\n' "${missing[*]}" >&2
        printf 'Debian/Ubuntu example: sudo apt install curl grep sed gawk coreutils tor\n' >&2
        return 1
    fi
    if [[ "$TRANSPORT" == proxychains ]] && ! command -v proxychains4 >/dev/null 2>&1; then
        printf 'TRANSPORT=proxychains, but proxychains4 is unavailable.\n' >&2
        return 1
    fi
}

initialise_storage() {
    mkdir -p -- "$DATA_DIR" "$TMP_DIR"
    touch -- "$QUEUE_FILE" "$VISITED_FILE" "$ALERT_FILE" "$LOG_FILE"
    chmod 700 "$DATA_DIR" "$TMP_DIR" 2>/dev/null || true
    chmod 600 "$QUEUE_FILE" "$VISITED_FILE" "$ALERT_FILE" "$LOG_FILE" 2>/dev/null || true
}

load_initial_input() {
    local raw url valid=0
    [[ -f "$INPUT_FILE" ]] || {
        printf 'Input file not found: %s\n' "$INPUT_FILE" >&2
        printf 'Create it with one .onion address per line (comments may start with #).\n' >&2
        return 1
    }
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        raw="${raw%%#*}"
        raw="$(printf '%s' "$raw" | trim)"
        [[ -z "$raw" ]] && continue
        if is_onion_url "$raw"; then
            url="$(normalise_url "$raw")"
            append_unique "$url" "$QUEUE_FILE"
            ((valid += 1))
        else
            printf 'Ignoring invalid onion address: %s\n' "$raw" >&2
        fi
    done < "$INPUT_FILE"
    if ((valid != 10)); then
        printf 'Warning: expected 10 valid initial sites; found %d.\n' "$valid" >&2
    fi
}

# --- Tor access and HTTP retrieval ------------------------------------------
tor_status() {
    # A TCP check alone does not prove Tor routing, so request Tor's check page.
    local reply
    reply="$(curl --silent --show-error --max-time 15 \
        --socks5-hostname "$TOR_HOST:$TOR_PORT" \
        'https://check.torproject.org/api/ip' 2>/dev/null || true)"
    grep -q '"IsTor"[[:space:]]*:[[:space:]]*true' <<< "$reply"
}

fetch_page() {
    local url="$1" output="$2"
    local common=(--fail --silent --show-error --location
        --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME"
        --max-filesize "$MAX_PAGE_BYTES" --user-agent "$USER_AGENT"
        --proto '=http,https' --proto-redir '=http,https' --output "$output")
    if [[ "$TRANSPORT" == proxychains ]]; then
        proxychains4 -q curl "${common[@]}" -- "$url"
    else
        curl "${common[@]}" --socks5-hostname "$TOR_HOST:$TOR_PORT" -- "$url"
    fi
}

# --- Extraction and persistent crawl state ---------------------------------
extract_title() {
    local file="$1" title
    title="$(tr '\r\n' '  ' < "$file" | sed -n 's:.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\([^<]*\)</[Tt][Ii][Tt][Ll][Ee]>.*:\1:p' | head -n 1)"
    title="$(printf '%s' "$title" | sed 's/&amp;/\&/g;s/&lt;/</g;s/&gt;/>/g;s/[[:space:]]\+/ /g' | trim)"
    printf '%.200s' "${title:-[NO TITLE]}"
}

discover_onion_links() {
    local file="$1" found url count=0
    # Extract absolute public onion URLs only; remove punctuation/HTML suffixes.
    while IFS= read -r found; do
        url="$(normalise_url "$found")"
        if is_onion_url "$url" && ! contains_line "$url" "$VISITED_FILE"; then
            if ! contains_line "$url" "$QUEUE_FILE"; then
                printf '%s\n' "$url" >> "$QUEUE_FILE"
                ((count += 1))
            fi
        fi
    done < <(grep -Eio 'https?://[a-z2-7]{56}\.onion(/[^"'"'"'<>[:space:]]*)?' "$file" | sort -u || true)
    printf '%d' "$count"
}

check_alerts() {
    local file="$1" url="$2" word
    while IFS= read -r word || [[ -n "$word" ]]; do
        word="$(printf '%s' "$word" | trim)"
        [[ -z "$word" ]] && continue
        if grep -Fqi -- "$word" "$file"; then
            log_event 'ALERT' "$url" "Search word matched: $word"
            printf '  ALERT: matched "%s"\n' "$word"
        fi
    done < "$ALERT_FILE"
}

save_state() {
    local url="$1"
    {
        printf 'LAST_URL=%q\n' "$url"
        printf 'UPDATED_AT=%q\n' "$(timestamp)"
    } > "$STATE_FILE"
}

crawl_site() {
    local url="$1" page title new_links
    page="$(mktemp "$TMP_DIR/page.XXXXXX")" || return 1
    printf 'Crawling: %s\n' "$url"
    if fetch_page "$url" "$page"; then
        title="$(extract_title "$page")"
        new_links="$(discover_onion_links "$page")"
        log_event 'ACCESSIBLE' "$url" "$title | new links: $new_links"
        check_alerts "$page" "$url"
        printf '  Title: %s; discovered: %s\n' "$title" "$new_links"
    else
        log_event 'NO ACCESS' "$url" '[NO ACCESS]'
        printf '  [NO ACCESS]\n'
    fi
    append_unique "$url" "$VISITED_FILE"
    save_state "$url"
    rm -f -- "$page"
}

crawl_pending() {
    local limit="${1:-0}" url processed=0
    if ! tor_status; then
        printf 'Tor status is Non-Active. Start Tor/check port %s and try again.\n' "$TOR_PORT" >&2
        return 1
    fi
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        contains_line "$url" "$VISITED_FILE" && continue
        crawl_site "$url"
        ((processed += 1))
        ((limit > 0 && processed >= limit)) && break
    done < "$QUEUE_FILE"
    printf 'Processed %d pending site(s).\n' "$processed"
}

refresh_indexed_status() {
    local url page
    tor_status || { printf 'Tor status is Non-Active.\n' >&2; return 1; }
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        page="$(mktemp "$TMP_DIR/status.XXXXXX")" || return 1
        if fetch_page "$url" "$page"; then
            log_event 'STATUS OK' "$url" "$(extract_title "$page")"
        else
            log_event 'NO ACCESS' "$url" '[NO ACCESS] (status refresh)'
        fi
        rm -f -- "$page"
    done < "$VISITED_FILE"
    printf 'Indexed-site status refresh complete.\n'
}

# --- Alert management and admin UI ------------------------------------------
manage_alerts() {
    local choice word
    while true; do
        printf '\nAlert words:\n'; nl -ba "$ALERT_FILE" 2>/dev/null || true
        printf '\n1) Add  2) Remove  3) Return\n'
        read -r -p '> ' choice || return
        case "$choice" in
            1) read -r -p 'Word/phrase to add: ' word
               word="$(printf '%s' "$word" | tr '\r\n' '  ' | trim)"
               [[ -n "$word" ]] && append_unique "$word" "$ALERT_FILE" ;;
            2) read -r -p 'Exact word/phrase to remove: ' word
               grep -Fvx -- "$word" "$ALERT_FILE" > "$ALERT_FILE.tmp" || true
               mv -- "$ALERT_FILE.tmp" "$ALERT_FILE" ;;
            3) return ;;
            *) printf 'Invalid option.\n' ;;
        esac
    done
}

show_dashboard() {
    local crawled queued access
    crawled="$(grep -cve '^$' "$VISITED_FILE" || true)"
    queued="$(grep -cve '^$' "$QUEUE_FILE" || true)"
    if tor_status; then access='Active'; else access='Non-Active'; fi
    printf '\n=== Darknet Crawler ===\n'
    printf 'Sites crawled : %s\nIndexed/queued: %s\nDarknet access: %s\nLog file      : %s\n' \
        "$crawled" "$queued" "$access" "$LOG_FILE"
}

main_menu() {
    local choice
    while true; do
        show_dashboard
        printf '\n1) Crawl next pending site\n2) Crawl all pending sites\n'
        printf '3) Recheck indexed-site status\n4) Manage alert words\n'
        printf '5) View log\n6) Exit\n'
        read -r -p '> ' choice || {
            printf '\nInput closed; state remains saved in %s\n' "$DATA_DIR"
            return
        }
        case "$choice" in
            1) crawl_pending 1; pause ;;
            2) crawl_pending 0; pause ;;
            3) refresh_indexed_status; pause ;;
            4) manage_alerts ;;
            5) ${PAGER:-less} "$LOG_FILE" 2>/dev/null || sed -n '1,200p' "$LOG_FILE"; pause ;;
            6) printf 'State saved in %s\n' "$DATA_DIR"; return ;;
            *) printf 'Invalid option.\n' ;;
        esac
    done
}

main() {
    check_dependencies || exit 1
    initialise_storage
    load_initial_input || exit 1
    main_menu
}

main "$@"
