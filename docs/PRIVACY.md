# Privacy Policy

SimpleCipher is a peer-to-peer encrypted chat program. It is designed to collect nothing and store nothing.

## Data collection

SimpleCipher collects no data. There are no analytics, no telemetry, no crash reporting, and no usage tracking of any kind.

## Network communication

All communication is direct peer-to-peer over TCP. No data is transmitted to any server operated by the project or any third party. There is no central server, no relay, and no signaling service.

## Data storage

By default, nothing is written to disk. All keys and messages exist only in memory and are wiped when the session ends.

The optional `keygen` command saves a passphrase-protected identity key file to a location you specify. This happens only at your explicit request. No other data is ever persisted.

## IP addresses

IP addresses are used solely to establish direct TCP connections between peers. They are not logged, stored, or transmitted to third parties.

## Android app permissions

The Android app requests the following permissions:

- **INTERNET** -- required for TCP connections (all flavors)
- **CAMERA** -- used for QR code scanning (full flavor only, not requested in the minimal flavor)

No other permissions are requested. No data leaves the device except the encrypted peer-to-peer connection you initiate.

## Cookies, tracking, and advertising

There are none. No cookies, no tracking pixels, no advertising, no fingerprinting, no third-party SDKs.

## Changes

If this policy changes, the change will be visible in the project's version control history.
