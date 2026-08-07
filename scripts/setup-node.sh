#!/bin/sh
set -eu

# Compatibility entry point retained for release packages. Discovery,
# enrollment, strict configuration, ownership checks, systemd activation, and
# rollback now live in the single binary so this wrapper cannot drift from the
# supported managed-node workflow.
exec /usr/local/bin/laneway node install "$@"
