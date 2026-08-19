# Laneway Desktop

Standalone endpoint UI for the protected local Laneway daemon.

See [the desktop foundation guide](../docs/desktop-client.md) and
[local daemon contract](../spec/local-daemon-api-v1.md) before extending the
read-only command surface. The webview must never receive controller administrator
credentials, profile private keys, raw local requests, or privileged helper
access.
