# verify-eidas-bridge

This repository contains the Verify Eidas Bridge Codes

## Getting Started

To run this bridge locally:
```
./gradlew run
```

To deploy on CF:
```

./gradlew distZip
cf push eidas-bridge -p build/distributions/verify-eidas-bridge.zip -f bridge-manifest.yml

```
