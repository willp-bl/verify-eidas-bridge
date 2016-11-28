#!/usr/bin/env bash

set -e
set -o pipefail

cd "$(dirname "$0")"

./gradlew -Pversion="${VERSION}" --parallel clean build test distZip

ARTIFACTS_DIR="build/distributions"
BASE_NAME="verify-eidas-bridge"
ARTIFACT="${BASE_NAME}-${VERSION}.zip"
REPOSITORY="https://api.bintray.com/content/msa/eidas-alpha/eidas-bridge-artifacts"
curl --fail -T "${ARTIFACTS_DIR}/${ARTIFACT}" -u"${EIDAS_BINTRAY_USER}:${EIDAS_BINTRAY_API_KEY}" "${REPOSITORY}/${VERSION}/${ARTIFACT}"
curl --fail -X POST -u"${EIDAS_BINTRAY_USER}:${EIDAS_BINTRAY_API_KEY}" "${REPOSITORY}/${VERSION}/publish"
