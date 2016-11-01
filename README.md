# verify-eidas-bridge

This repository contains the Verify Eidas Bridge Codes

## Getting Started

To run this bridge locally
java -jar build/libs/verify-eidas-bridge-standalone.jar server src/dist/config/eidasbridge.yml


To deploy on CF

cf push niyi-bridge-test -b "https://github.com/cloudfoundry/java-buildpack.git" -p build/libs/verify-eidas-bridge-standalone.jar

