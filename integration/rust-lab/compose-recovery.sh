# Sourced only by the marked disposable Compose cutover fixture.
check_compose_recovery() {
  local bundle_name=rust-rehearsal.age native_admin controller_container controller_pid compose_bundle
  local restored="$work/restored" restored_project="$project-restore" recipient
  for utility in age age-keygen nsenter; do command -v "$utility" >/dev/null; done
  for file in laneway-control recovery.sh validate.sh; do
    install -m 0755 "$root/deploy/compose/$file" "$base/$file"
  done
  age-keygen -o "$work/identity" 2>"$work/age-keygen.out"
  recipient=$(age-keygen -y "$work/identity")
  printf 'LANEWAY_CONNECTOR_IMAGE_DIGEST=%s\nLANEWAY_BACKUP_RECIPIENT=%s\nLANEWAY_NETWORK_NAME=baseline\nLANEWAY_IPV4_POOL=100.115.18.0/24\n' \
    "$digest" "$recipient" >> "$base/.env"

  # Seed the fixture renewal cache with a later, CA-signed certificate for
  # exactly the same relay identity; it must survive as the restored seed.
  laneway pki relay --ca-cert "$base/generated/pki/intermediate-chain.crt" \
    --ca-key "$base/generated/pki/intermediate.key" --network-id "$network" \
    --service-id "$relay" --dns "$name" --validity 1440h \
    --out-cert "$work/renewed-relay.crt" --out-key "$work/renewed-relay.key" >/dev/null
  cat "$work/renewed-relay.crt" "$work/renewed-relay.key" > "$base/generated/rust-relay-workload/relay-service.pem"
  chmod 0600 "$base/generated/rust-relay-workload/relay-service.pem"
  chown 65532:65532 "$base/generated/rust-relay-workload/relay-service.pem"

  # On the fixture only, embed the resolved local-image and isolated-volume
  # overrides so the production wrapper itself needs no testing switch.
  rust_compose --profile '*' config --no-path-resolution > "$work/maint.yaml"
  mv compose.yaml go-base.yaml
  mv compose.rust.yaml rust-overlay.yaml
  cp "$work/maint.yaml" compose.yaml
  printf 'services: {}\n' > compose.rust.yaml
  native_admin=$(docker create laneway-go-admin:compose-cutover-lab)
  docker cp "$native_admin:/usr/local/bin/laneway" "$work/bin/laneway-native"
  docker rm "$native_admin" >/dev/null
  controller_container=$(rust_compose ps -q controller)
  controller_pid=$(docker inspect --format '{{.State.Pid}}' "$controller_container")
  laneway pki controller --ca-cert "$base/generated/pki/intermediate-chain.crt" \
    --ca-key "$base/generated/pki/intermediate.key" --network-id "$network" \
    --service-id "$controller" --dns "$name" --validity 1440h \
    --out-cert "$work/renewed-controller.crt" --out-key "$work/renewed-controller.key" >/dev/null
  cat "$work/renewed-controller.crt" "$work/renewed-controller.key" > "$work/controller-service.pem"
  chmod 0600 "$work/controller-service.pem"
  chown 65532:65532 "$work/controller-service.pem"
  docker cp -a "$work/controller-service.pem" "$controller_container:/var/lib/laneway-controller/rust-tls/"

  echo '==> read authenticated inventory with the real Rust maintenance wrapper'
  nsenter -t "$controller_pid" -n env COMPOSE_PROJECT_NAME="$project" \
    LANEWAY_COMMAND="$work/bin/laneway-native" "$base/laneway-control" --rust status > "$work/maintenance-status"
  grep -Fx 'controller=healthy' "$work/maintenance-status"
  grep -Fx 'relay=healthy' "$work/maintenance-status"
  if env COMPOSE_PROJECT_NAME="$project" "$base/laneway-control" --rust upgrade ignored.env > "$work/unsupported" 2>&1; then
    echo "Rust mode allowed the legacy upgrade path" >&2
    return 1
  fi
  grep -F 'refusing the Go lifecycle workflow' "$work/unsupported"

  echo '==> take an encrypted live Rust backup and restore a separate database'
  printf 'services:\n  controller:\n    image: laneway-go-controller:compose-cutover-lab\n' > compose.rust.yaml
  if env COMPOSE_PROJECT_NAME="$project" "$base/laneway-control" --rust backup mismatched.age > "$work/mismatched-image" 2>&1; then
    echo "Rust backup accepted a different running image" >&2
    return 1
  fi
  grep -F 'running controller image does not match' "$work/mismatched-image"
  test ! -e "$base/generated/recovery/mismatched.age"
  printf 'services: {}\n' > compose.rust.yaml
  env COMPOSE_PROJECT_NAME="$project" "$base/laneway-control" --rust backup "$bundle_name"
  compose_bundle="$base/generated/recovery/$bundle_name"
  test -s "$compose_bundle"
  [[ -z $(find "$base/generated/backups" -mindepth 1 -maxdepth 1 -print -quit) ]]
  age --decrypt -i "$work/identity" -o "$work/verified-backup.tar" "$compose_bundle"
  test "$(tar -xOf "$work/verified-backup.tar" FORMAT)" = LANEWAY_RECOVERY_VERSION=2
  cmp -s "$work/renewed-controller.crt" <(tar -xOf "$work/verified-backup.tar" generated/pki/controller.crt)
  cmp -s "$work/renewed-relay.crt" <(tar -xOf "$work/verified-backup.tar" generated/pki/relay.crt)
  if cmp -s "$work/renewed-relay.crt" "$base/generated/pki/relay.crt"; then
    echo 'backup replaced the running deployment relay seed' >&2
    return 1
  fi
  mkdir -m 0700 "$restored"
  sed -e "s|$base|$restored|g" -e "s|$project|$restored_project|g" "$work/maint.yaml" > "$restored/compose.yaml"
  cp compose.rust.yaml laneway-control recovery.sh validate.sh "$restored/"
  # Register cleanup before starting the restored project. The parent only
  # ever removes these two uniquely named fixture projects.
  recovery_project_dir=$restored
  recovery_project_name=$restored_project
  if env COMPOSE_PROJECT_NAME="$restored_project" "$restored/laneway-control" restore \
      "$compose_bundle" --identity "$work/identity" >"$work/wrong-runtime" 2>&1; then
    echo 'Legacy restore accepted a Rust recovery bundle' >&2
    return 1
  fi
  test ! -e "$restored/.env"
  env COMPOSE_PROJECT_NAME="$restored_project" "$restored/laneway-control" --rust restore \
    "$compose_bundle" --identity "$work/identity"
  # The offline fixture's public HTTPS key is not a standard recovery input.
  # Start only the restored controller to prove that its state is bootable.
  (
    cd "$restored"
    docker compose -p "$restored_project" up --pull never -d controller --wait --wait-timeout 35
    docker compose -p "$restored_project" --profile tools run --rm --no-deps --pull never -T \
      admin controller network list --limit 100 "${auth[@]}" |
      jq -e --arg original "$network" --arg changed "$added" \
        'any(.networks[]; .network_id == $original and .name == "baseline")
         and any(.networks[]; .network_id == $changed and .name == "added-in-rust")' >/dev/null
  )
  assert_network "$added" added-in-rust
  mv go-base.yaml compose.yaml
  mv rust-overlay.yaml compose.rust.yaml
  echo 'PASS: Rust encrypted recovery restored both networks to a fresh Compose controller without replacing the live volume.'
}
