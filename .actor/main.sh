#!/usr/bin/env bash
#
# Apify Actor entry point: reads Actor input, runs knock-knock --json,
# adds a few flat summary fields for the Output table, and pushes
# one dataset item per checked name.

set -euo pipefail

log() {
    echo "$@" >&2
}

INPUT="$(apify actor get-input)"
if [ -z "${INPUT}" ] || [ "${INPUT}" = "null" ]; then
    log "ERROR: No input provided"
    exit 1
fi

# Domain names: trimmed, without empty lines
mapfile -t DOMAINS < <(
    jq -r '.domains // [] | .[] | strings | gsub("^\\s+|\\s+$"; "") | select(length > 0)' <<< "${INPUT}"
)
if [ "${#DOMAINS[@]}" -eq 0 ]; then
    log "ERROR: No domain names provided"
    exit 1
fi

ARGS=(--json)
if [ "$(jq -r '.checkCertificates // false' <<< "${INPUT}")" = "true" ]; then
    ARGS+=(--check-certificates)
fi
ETH_RPC_URL_INPUT="$(jq -r '.ethRpcUrl // "" | strings' <<< "${INPUT}")"
if [ -n "${ETH_RPC_URL_INPUT}" ]; then
    ARGS+=(--eth-rpc-url "${ETH_RPC_URL_INPUT}")
fi
WARN_DAYS="$(jq -r '.warnDays // 30 | if type == "number" and . >= 0 then floor else 30 end' <<< "${INPUT}")"

log "Checking ${#DOMAINS[@]} name(s)..."

# knock-knock exits with 1 when some of the checks failed, but still outputs results for all names
STATUS=0
OUTPUT="$(knock-knock "${ARGS[@]}" -- "${DOMAINS[@]}")" || STATUS=$?

if ! jq -e 'type == "array"' > /dev/null 2>&1 <<< "${OUTPUT}"; then
    log "ERROR: knock-knock failed (exit status ${STATUS}) without producing results"
    exit 1
fi

# Flat summary fields make the Output table (and CSV/Excel exports) readable,
# the full knock-knock output is kept under "registration" and "certificate"
RESULTS="$(jq --argjson warn_days "${WARN_DAYS}" '
    # Whole days, rounded towards zero (expired 3 days and 5 seconds ago means -3)
    def days_left:
        if . == null then null
        elif . < 0 then -(-. / 86400 | floor)
        else . / 86400 | floor
        end;

    # Self-signed certificates are the norm for Gemini capsules
    def untrusted_certificate:
        .certificate.trusted == false
        and ((.scheme == "gemini" or .scheme == "titan")
            and .certificate.verification_error == "issued by an unknown certificate authority"
            | not);

    map(
        (.registration.seconds_left // null) as $seconds_left
        | (.certificate.seconds_left // null) as $certificate_seconds_left
        | . + {
            registration_status: (.registration.status // null),
            expires: (.registration.expires // null),
            days_left: ($seconds_left | days_left),
            registrar: (.registration.registrar.name? // null),
            nameservers: (.registration.nameservers // []),
            certificate_expires: (.certificate.expires // null),
            certificate_days_left: ($certificate_seconds_left | days_left),
            certificate_trusted: .certificate.trusted,
            needs_attention: (
                (.registration.status == "error")
                or (.registration.error? != null)
                or (.certificate.status? == "error")
                or ($seconds_left != null and $seconds_left <= $warn_days * 86400)
                or ($certificate_seconds_left != null and $certificate_seconds_left <= $warn_days * 86400)
                or untrusted_certificate
            ),
            error: (.registration.error // .certificate.error // null)
        }
    )
' <<< "${OUTPUT}")"

apify actor push-data <<< "${RESULTS}"

log "Done: $(jq 'length' <<< "${RESULTS}") result(s)," \
    "$(jq '[.[] | select(.needs_attention)] | length' <<< "${RESULTS}") needing attention" \
    "(expiring within ${WARN_DAYS} days, untrusted certificate, or failed check)"
