# Laneway Desktop

Standalone endpoint UI for the protected local Laneway daemon.

See [the desktop foundation guide](../docs/desktop-client.md), the
[desktop endpoint contract](../spec/desktop-client-v1.md), and the normative
[local daemon API](../docs/local-daemon-api-v1.md) before extending the
read-only command surface. The webview must never receive controller administrator
credentials, profile private keys, raw local requests, or privileged helper
access.
