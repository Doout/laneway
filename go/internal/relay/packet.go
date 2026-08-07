package relay

import (
	"errors"
	"net/netip"

	"laneway.dev/laneway/internal/protocol"
)

// Forward validates and queues a single Laneway packet frame received from the
// exact authenticated sender session. It performs no I/O and never blocks on a
// full outbound queue. The frame is copied only after all validation succeeds.
func (r *Registry) Forward(sender *Session, frame []byte) error {
	header, payload, err := protocol.DecodePacket(frame)
	if err != nil {
		r.metrics.droppedMalformed.Add(1)
		return err
	}
	source, destination, ok := packetAddresses(payload)
	if !ok {
		// DecodePacket currently catches this, but retain a fail-closed boundary
		// if its structural validation evolves.
		r.metrics.droppedMalformed.Add(1)
		return protocol.ErrInvalidIPPacket
	}

	if sender == nil || sender.registry != r {
		r.metrics.droppedClosed.Add(1)
		return ErrUnknownSession
	}
	snapshot := r.forwarding.Load()
	table := snapshot.bySession[sender]
	if table == nil {
		r.metrics.droppedClosed.Add(1)
		return ErrUnknownSession
	}
	route, ok := table.byHandle[header.RouteHandle]
	recipient := route.recipient
	if recipient == nil {
		r.metrics.droppedUnknownHandle.Add(1)
		return ErrUnknownHandle
	}
	if !ok {
		r.metrics.droppedUnknownHandle.Add(1)
		return ErrUnknownHandle
	}
	if _, current := snapshot.bySession[recipient]; !current {
		r.metrics.droppedUnknownHandle.Add(1)
		return ErrUnknownHandle
	}
	if !route.hasReturn {
		r.metrics.droppedNoReturn.Add(1)
		return ErrNoReturnHandle
	}
	if len(payload) > route.maxPayload {
		r.metrics.droppedTooLarge.Add(1)
		return ErrPacketTooLarge
	}
	if source.Is6() && (!sender.allowIPv6 || !recipient.allowIPv6) {
		r.metrics.droppedCapability.Add(1)
		return ErrCapabilityNotNegotiated
	}
	if !sender.prefixes.contains(source) {
		r.metrics.droppedSource.Add(1)
		return ErrSourceUnauthorized
	}
	if !recipient.prefixes.contains(destination) {
		r.metrics.droppedDestination.Add(1)
		return ErrDestinationUnauthorized
	}

	out := r.frames.Acquire(len(frame))
	forwardedBytes := len(frame)
	copy(out.Bytes(), frame)
	if err := protocol.EncodePacketHeader(out.Bytes(), protocol.PacketHeader{
		Version: protocol.PacketVersion1, RouteHandle: route.returnHandle,
	}); err != nil {
		out.Release()
		r.metrics.droppedMalformed.Add(1)
		return err
	}
	if err := recipient.outbound.enqueue(out); err != nil {
		out.Release()
		if errors.Is(err, ErrQueueFull) {
			r.metrics.droppedQueueFull.Add(1)
		} else {
			r.metrics.droppedClosed.Add(1)
		}
		return err
	}
	r.metrics.forwardedPackets.Add(1)
	r.metrics.forwardedBytes.Add(uint64(forwardedBytes))
	return nil
}

func packetAddresses(payload []byte) (source, destination netip.Addr, ok bool) {
	switch payload[0] >> 4 {
	case 4:
		var src, dst [4]byte
		copy(src[:], payload[12:16])
		copy(dst[:], payload[16:20])
		return netip.AddrFrom4(src), netip.AddrFrom4(dst), true
	case 6:
		var src, dst [16]byte
		copy(src[:], payload[8:24])
		copy(dst[:], payload[24:40])
		return netip.AddrFrom16(src), netip.AddrFrom16(dst), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}
