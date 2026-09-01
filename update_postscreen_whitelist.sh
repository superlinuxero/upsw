#!/bin/bash
#
# update_postscreen_whitelist.sh
#
# Generates /etc/postfix/postscreen_whitelist.cidr containing the outbound
# networks of selected major email providers. These networks can then bypass
# Postscreen tests through postscreen_access_list.
#
# Sources:
#   - Google: SPF
#   - Microsoft 365 / Outlook: SPF
#   - Apple / iCloud: SPF, including redirect= support
#   - Amazon SES: SPF
#   - Yahoo: official Yahoo outbound mail server list
#
# Yahoo entries are sanitized individually:
#   - Invalid IPv4 addresses are ignored with a WARNING
#   - CIDR prefixes greater than 32 are ignored with a WARNING
#   - Individual invalid entries do NOT abort generation
#
# Requirements:
#   dig
#   curl
#   flock
#
# Run as root, manually or through cron/systemd timer.

set -euo pipefail

OUT="/etc/postfix/postscreen_whitelist.cidr"
LOCK="/var/lock/update_postscreen_whitelist.lock"

YAHOO_URL="https://senders.yahooinc.com/outbound-mail-servers/"

# If Yahoo returns fewer valid entries than this value, assume that either
# the page structure has changed or the parser has failed. In that situation
# the existing allowlist is preserved.
YAHOO_MIN_VALID_ENTRIES=20


# ----------------------------------------------------------------------
# Lock
# ----------------------------------------------------------------------

exec 200>"$LOCK"

flock -n 200 || {
    echo "Another instance is already running. Exiting."
    exit 1
}


# ----------------------------------------------------------------------
# Temporary files
# ----------------------------------------------------------------------

TMP=$(mktemp)

cleanup() {
    rm -f "$TMP"
}

trap cleanup EXIT


# ----------------------------------------------------------------------
# Providers resolved through SPF
# ----------------------------------------------------------------------

SPF_DOMAINS=(
    "_spf.google.com"
    "spf.protection.outlook.com"
    "icloud.com"
    "amazonses.com"
)


# ----------------------------------------------------------------------
# Return the SPF mechanisms/modifiers relevant to static network
# extraction.
#
# Supported:
#   ip4:
#   ip6:
#   include:
#   redirect=
# ----------------------------------------------------------------------

resolve_spf_entries() {
    local domain="$1"

    dig +short TXT "$domain" 2>/dev/null \
        | tr -d '"' \
        | tr ' ' '\n' \
        | grep -E '^(ip4|ip6|include):|^redirect=' \
        || true
}


# ----------------------------------------------------------------------
# Recursively flatten an SPF record.
#
# Domains that have already been visited are stored in a temporary file
# to prevent include/redirect loops.
# ----------------------------------------------------------------------

flatten_spf() {
    local root_domain="$1"

    local seen_file
    seen_file=$(mktemp)

    local -a queue=("$root_domain")
    local count=0

    while [ ${#queue[@]} -gt 0 ]; do

        local current="${queue[0]}"

        if [ ${#queue[@]} -eq 1 ]; then
            queue=()
        else
            queue=("${queue[@]:1}")
        fi

        if grep -qxF "$current" "$seen_file" 2>/dev/null; then
            continue
        fi

        echo "$current" >> "$seen_file"

        local entry

        while read -r entry; do

            [ -z "$entry" ] && continue

            case "$entry" in

                ip4:*|ip6:*)
                    echo "${entry#*:} permit" >> "$TMP"
                    ((count+=1))
                    ;;

                include:*)
                    queue+=("${entry#*:}")
                    ;;

                redirect=*)
                    queue+=("${entry#*=}")
                    ;;

            esac

        done < <(resolve_spf_entries "$current")

    done

    rm -f "$seen_file"

    if [ "$count" -eq 0 ]; then
        echo "ERROR: $root_domain produced no SPF networks." >&2
        return 1
    fi

    echo "     $count networks found"
}


# ----------------------------------------------------------------------
# Validate an IPv4 address.
#
# Returns 0 for a valid IPv4 address and 1 otherwise.
#
# 10# forces decimal interpretation so that values containing leading
# zeroes are not interpreted as octal by Bash arithmetic.
# ----------------------------------------------------------------------

valid_ipv4() {
    local ip="$1"
    local o1 o2 o3 o4

    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    [[ -n "${o1:-}" && -n "${o2:-}" &&
       -n "${o3:-}" && -n "${o4:-}" ]] || return 1

    [[ "$o1" =~ ^[0-9]{1,3}$ ]] || return 1
    [[ "$o2" =~ ^[0-9]{1,3}$ ]] || return 1
    [[ "$o3" =~ ^[0-9]{1,3}$ ]] || return 1
    [[ "$o4" =~ ^[0-9]{1,3}$ ]] || return 1

    (( 10#$o1 <= 255 )) || return 1
    (( 10#$o2 <= 255 )) || return 1
    (( 10#$o3 <= 255 )) || return 1
    (( 10#$o4 <= 255 )) || return 1

    return 0
}


# ----------------------------------------------------------------------
# Retrieve and sanitize Yahoo outbound networks.
# ----------------------------------------------------------------------

fetch_yahoo_entries() {

    local yahoo_tmp
    local yahoo_raw
    local yahoo_entries

    yahoo_tmp=$(mktemp)
    yahoo_raw=$(mktemp)
    yahoo_entries=$(mktemp)

    echo "  -> Yahoo (official outbound server list)"

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --max-time 30 \
        --connect-timeout 10 \
        --user-agent "Postscreen-Whitelist-Updater/3.0" \
        "$YAHOO_URL" \
        > "$yahoo_tmp"
    then
        echo "ERROR: unable to download Yahoo's official outbound server list." >&2
        rm -f "$yahoo_tmp" "$yahoo_raw" "$yahoo_entries"
        return 1
    fi


    # Extract IPv4/CIDR-shaped candidates.
    #
    # This regular expression is intentionally used only to locate
    # candidates. Actual IPv4 and prefix validation is performed below.
    grep -Eo \
        '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
        "$yahoo_tmp" \
        | sort -u \
        > "$yahoo_raw" \
        || true


    local invalid_count=0
    local valid_count=0

    while read -r candidate; do

        [ -z "$candidate" ] && continue

        local ip
        local prefix

        if [[ "$candidate" == */* ]]; then
            ip="${candidate%/*}"
            prefix="${candidate#*/}"
        else
            ip="$candidate"
            prefix="32"
        fi


        # Validate IPv4 address.
        if ! valid_ipv4 "$ip"; then
            echo "     WARNING: ignoring invalid Yahoo IPv4 address: $candidate" >&2
            ((invalid_count+=1))
            continue
        fi


        # Validate CIDR prefix.
        if ! [[ "$prefix" =~ ^[0-9]{1,2}$ ]]; then
            echo "     WARNING: ignoring invalid Yahoo CIDR prefix: $candidate" >&2
            ((invalid_count+=1))
            continue
        fi

        if (( 10#$prefix > 32 )); then
            echo "     WARNING: ignoring invalid Yahoo CIDR prefix: $candidate" >&2
            ((invalid_count+=1))
            continue
        fi


        echo "$ip/$prefix" >> "$yahoo_entries"
        ((valid_count+=1))

    done < "$yahoo_raw"


    sort -u "$yahoo_entries" -o "$yahoo_entries"

    valid_count=$(wc -l < "$yahoo_entries")


    # Individual malformed candidates are harmless and have already been
    # ignored. A very small result set, however, most likely indicates that
    # Yahoo changed the page structure or that parsing failed. Preserve the
    # existing allowlist rather than installing a suspiciously incomplete one.
    if [ "$valid_count" -lt "$YAHOO_MIN_VALID_ENTRIES" ]; then
        echo "ERROR: Yahoo produced only $valid_count valid entries." >&2
        echo "The official page may have changed or parsing may have failed." >&2
        rm -f "$yahoo_tmp" "$yahoo_raw" "$yahoo_entries"
        return 1
    fi


    while read -r network; do
        [ -z "$network" ] && continue
        echo "$network permit" >> "$TMP"
    done < "$yahoo_entries"


    echo "     $valid_count valid networks/addresses found"

    if [ "$invalid_count" -gt 0 ]; then
        echo "     WARNING: $invalid_count invalid candidate(s) ignored"
    fi


    rm -f "$yahoo_tmp" "$yahoo_raw" "$yahoo_entries"
}


# ----------------------------------------------------------------------
# Build the allowlist.
# ----------------------------------------------------------------------

echo "Resolving SPF providers..."

for domain in "${SPF_DOMAINS[@]}"; do
    echo "  -> $domain"
    flatten_spf "$domain"
done


echo
echo "Retrieving Yahoo infrastructure..."

fetch_yahoo_entries


# ----------------------------------------------------------------------
# General sanity checks.
# ----------------------------------------------------------------------

if [ ! -s "$TMP" ]; then
    echo "ERROR: no entries were resolved." >&2
    echo "$OUT will not be modified." >&2
    exit 1
fi


sort -u "$TMP" -o "$TMP"

ENTRY_COUNT=$(wc -l < "$TMP")

echo
echo "Total valid entries: $ENTRY_COUNT"


# ----------------------------------------------------------------------
# Install the new allowlist only when its contents have changed.
# ----------------------------------------------------------------------

if [ -f "$OUT" ] && cmp -s "$TMP" "$OUT"; then

    echo "No changes detected."
    echo "Postfix will not be reloaded."

else

    install \
        -o root \
        -g root \
        -m 644 \
        "$TMP" \
        "$OUT"

    echo "Allowlist updated:"
    echo "  $OUT"

    systemctl reload postfix

    echo "Postfix reloaded."

fi


# ----------------------------------------------------------------------
# Usage example.
# ----------------------------------------------------------------------

echo
echo "Test an address with:"
echo
echo "  postmap -q IP cidr:$OUT"
echo
echo "Example Yahoo address:"
echo
echo "  postmap -q 77.238.179.82 cidr:$OUT"
