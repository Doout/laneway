#![no_main]

use laneway_protocol::{certificate_serial_from_der, identity_from_certificate_der};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(identity) = identity_from_certificate_der(data) {
        assert_eq!(identity.network_id.as_bytes().len(), 16);
        assert_eq!(identity.subject_id.as_bytes().len(), 16);
    }
    if let Ok(serial) = certificate_serial_from_der(data) {
        assert!(!serial.is_empty());
        assert!(serial.len() <= 32);
        assert_ne!(serial.first(), Some(&0));
    }
});
