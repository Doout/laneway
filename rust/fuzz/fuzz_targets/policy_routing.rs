#![no_main]

use laneway_protocol::{
    Id,
    policy::{CompiledPolicy, prefix_from_wire},
    v1,
};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(prefix) = v1::IpPrefix::decode(data)
        && let Ok(parsed) = prefix_from_wire(prefix)
    {
        assert_eq!(parsed, parsed.trunc());
        if let std::net::IpAddr::V6(address) = parsed.addr() {
            assert!(address.to_ipv4_mapped().is_none());
        }
    }
    let Ok(snapshot) = v1::PolicySnapshot::decode(data) else {
        return;
    };
    let Ok(network) = Id::from_slice(&snapshot.network_id) else {
        return;
    };
    let epoch = snapshot.configuration_epoch;
    if let Ok(policy) = CompiledPolicy::compile(snapshot, network, epoch) {
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 100, 96, 0, 1, 100, 96, 0, 2,
        ];
        let first = policy.allows(network, network, &packet);
        assert_eq!(first, policy.allows(network, network, &packet));
    }
});
