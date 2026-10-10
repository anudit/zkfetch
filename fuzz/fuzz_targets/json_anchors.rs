#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(members) = zkf_ir::json::members(data) {
        for member in members {
            assert!(member.key_range.start < member.key_range.end);
            assert!(member.value_range.start < member.value_range.end);
            assert!(member.key_range.end <= member.value_range.start);
            assert!(member.value_range.end <= data.len());
        }
    }
});
