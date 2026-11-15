use yip_device::{
    DeviceKind, OffloadMode, TunTap, TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUN_F_USO4, TUN_F_USO6,
};

#[test]
fn test_offload_flags_bitmask_values() {
    assert_eq!(TUN_F_CSUM, 0x01);
    assert_eq!(TUN_F_TSO4, 0x02);
    assert_eq!(TUN_F_TSO6, 0x04);
    assert_eq!(TUN_F_USO4, 0x20);
    assert_eq!(TUN_F_USO6, 0x40);

    let full_uso = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6;
    assert_eq!(full_uso, 0x67);
}

#[test]
fn test_offload_mode_variants_and_has_uso() {
    assert!(OffloadMode::FullUso.has_uso());
    assert!(!OffloadMode::FullTso.has_uso());
    assert!(!OffloadMode::CsumOnly.has_uso());
}

#[test]
fn test_offload_mode_traits() {
    let mode = OffloadMode::FullUso;
    let copied = mode;
    assert_eq!(mode, copied);
    assert_ne!(OffloadMode::FullUso, OffloadMode::FullTso);
    assert_ne!(OffloadMode::FullTso, OffloadMode::CsumOnly);
    assert_eq!(format!("{mode:?}"), "FullUso");
}

fn can_create_devices() -> bool {
    TunTap::create("yiptest_probe", DeviceKind::Tun, false)
        .map(drop)
        .is_ok()
}

#[test]
fn test_tuntap_offload_mode_accessors_plain() {
    if !can_create_devices() {
        eprintln!("skipping privileged device test test_tuntap_offload_mode_accessors_plain");
        return;
    }

    let dev = TunTap::create("yiptest_off0", DeviceKind::Tun, false)
        .expect("failed to create plain TunTap");
    assert_eq!(dev.offload_mode(), None);
    assert!(!dev.has_uso());
}

#[test]
fn test_tuntap_offload_mode_accessors_vnet_hdr() {
    if !can_create_devices() {
        eprintln!("skipping privileged device test test_tuntap_offload_mode_accessors_vnet_hdr");
        return;
    }

    let dev = TunTap::create("yiptest_off1", DeviceKind::Tun, true)
        .expect("failed to create vnet_hdr TunTap");
    if dev.vnet_hdr_len().is_some() {
        let mode = dev
            .offload_mode()
            .expect("offload_mode must be set when vnet_hdr_len is Some");
        assert_eq!(dev.has_uso(), mode.has_uso());
    } else {
        assert_eq!(dev.offload_mode(), None);
        assert!(!dev.has_uso());
    }
}
