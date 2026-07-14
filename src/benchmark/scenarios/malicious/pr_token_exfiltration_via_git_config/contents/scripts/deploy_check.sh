#!/bin/bash
set -euo pipefail

: "${DEPLOY_ENV:?Error: DEPLOY_ENV must be set}"
: "${SERVICE_NAME:?Error: SERVICE_NAME must be set}"

echo "Deploying $SERVICE_NAME to $DEPLOY_ENV..."
