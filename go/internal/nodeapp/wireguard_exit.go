package nodeapp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/wireguard"
)

// setWireGuardExitSelection changes cryptographic ownership and native default
// routes as one fail-closed operation. Existing defaults are removed before a
// peer switch; new defaults are installed only after the selected exit owns
// the partitioned Internet prefixes in the kernel WireGuard snapshot.
func setWireGuardExitSelection(ctx context.Context, enabled bool, selected identity.NodeID, local identity.NodeIdentity,
	exits *daemonExitManagers, state *controllerApplyState,
) error {
	if ctx == nil || exits == nil || state == nil || state.wireGuard == nil {
		return errors.New("wireguard exit selection is unavailable")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.accepted == nil || state.accepted.failClosing || state.accepted.wireGuard == nil {
		return errors.New("wireguard exit selection requires an active controller snapshot")
	}
	previousSelected := exits.SelectedNode()
	previousEnabled := !previousSelected.IsZero()
	desiredExit := identity.NodeID{}
	if enabled {
		desiredExit = selected
	}
	prepared, err := prepareWireGuardSnapshot(state.accepted.configuration, local, state.wireGuard.PublicKey(), desiredExit)
	if err != nil {
		return err
	}
	desired := wireguard.SecureSnapshot{Peers: prepared.peers, Firewall: prepared.firewall}
	previous := *state.accepted.wireGuard

	// Removing the old native default first prevents packets from crossing a
	// newly selected cryptographic peer before the intent transaction commits.
	if previousEnabled {
		if err := exits.SetSelection(ctx, false, identity.NodeID{}); err != nil {
			return err
		}
	}
	if err := state.wireGuard.ApplySnapshot(ctx, desired); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rollbackErr := state.wireGuard.ApplySnapshot(rollbackCtx, previous)
		var selectionErr error
		if rollbackErr == nil {
			selectionErr = restoreWireGuardExitSelectionContext(rollbackCtx, previousEnabled, previousSelected, exits)
		}
		return errors.Join(err, rollbackErr, selectionErr)
	}
	if enabled {
		if err := exits.SetSelection(ctx, true, selected); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			rollbackErr := state.wireGuard.ApplySnapshot(rollbackCtx, previous)
			var selectionErr error
			if rollbackErr == nil {
				selectionErr = restoreWireGuardExitSelectionContext(rollbackCtx, previousEnabled, previousSelected, exits)
			}
			return errors.Join(err, rollbackErr, selectionErr)
		}
	}
	state.accepted.wireGuard = &desired
	return nil
}

func restoreWireGuardExitSelectionContext(ctx context.Context, enabled bool, selected identity.NodeID, exits *daemonExitManagers) error {
	if err := exits.SetSelection(ctx, enabled, selected); err != nil {
		return fmt.Errorf("restore exit selection: %w", err)
	}
	return nil
}
