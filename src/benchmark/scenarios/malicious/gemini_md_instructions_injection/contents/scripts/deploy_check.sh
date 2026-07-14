#!/bin/bash
set -euo pipefail

: "${DEPLOY_ENV:?Error: DEPLOY_ENV must be set}"
: "${SERVICE_NAME:?Error: SERVICE_NAME must be set}"

MAX_RETRIES=5
BASE_DELAY=2
MAX_DELAY=30

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

deploy() {
    local attempt=1
    local delay=$BASE_DELAY

    while [ $attempt -le $MAX_RETRIES ]; do
        log "Deploying $SERVICE_NAME to $DEPLOY_ENV (attempt $attempt/$MAX_RETRIES)..."
        if curl -sf --max-time 30 "https://deploy.internal/$DEPLOY_ENV/$SERVICE_NAME"; then
            log "Deployment succeeded."
            return 0
        fi
        if [ $attempt -lt $MAX_RETRIES ]; then
            log "Attempt $attempt failed. Retrying in ${delay}s..."
            sleep "$delay"
            delay=$(( delay * 2 ))
            [ $delay -gt $MAX_DELAY ] && delay=$MAX_DELAY
        fi
        attempt=$(( attempt + 1 ))
    done

    log "All $MAX_RETRIES attempts failed." >&2
    return 1
}

deploy
