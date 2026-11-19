//! Emulator detection (light flag `emulator`). Only signals that real phones never have:
//! - `emulator.props`: QEMU kernel/boot props, goldfish/ranchu/vbox86 hardware names, SDK and Genymotion product
//!   names, Nox / LDPlayer / BlueStacks props;
//! - `emulator.files`: QEMU pipes and daemons, VirtualBox guest devices, Nox / LDPlayer binaries.
//!
//! x86 ABIs alone are not a signal (Chromebooks, some tablets).

use obfstr::obfstring as s;

/// `emulator.props`
pub fn property_trace(prop: &dyn Fn(&str) -> String) -> bool {
    if prop(&s!("ro.kernel.qemu")) == "1" || prop(&s!("ro.boot.qemu")) == "1" {
        return true;
    }
    let virtual_hardware = [s!("goldfish"), s!("ranchu"), s!("vbox86"), s!("nox"), s!("ttvm"), s!("cutf_cvm")];
    for name in [s!("ro.hardware"), s!("ro.boot.hardware"), s!("ro.product.board")] {
        let value = prop(&name).to_ascii_lowercase();
        if virtual_hardware.iter().any(|hw| value == *hw || value.starts_with(hw.as_str())) {
            return true;
        }
    }
    let model = prop(&s!("ro.product.model"));
    let product = prop(&s!("ro.product.name"));
    let device = prop(&s!("ro.product.device"));
    let model_tokens = [s!("sdk_gphone"), s!("Android SDK built for"), s!("google_sdk"), s!("Emulator")];
    let product_tokens = [s!("sdk_gphone"), s!("sdk_google"), s!("generic_x86"), s!("vbox86p"), s!("emulator")];
    if model_tokens.iter().any(|token| model.contains(token.as_str()))
        || product_tokens.iter().any(|token| product.contains(token.as_str()) || device.contains(token.as_str()))
    {
        return true;
    }
    if prop(&s!("ro.product.manufacturer")) == obfstr::obfstr!("Genymotion") {
        return true;
    }
    // Vendor-specific props set only by those emulators.
    [
        s!("ro.genymotion.version"),
        s!("ro.nox.version"),
        s!("ro.ldplayer.version"),
        s!("ro.bst.version"),
        s!("init.svc.qemu-props"),
    ]
    .iter()
    .any(|name| !prop(name).is_empty())
}

/// `emulator.files`
pub fn file_trace(exists: &dyn Fn(&str) -> bool) -> bool {
    [
        s!("/dev/qemu_pipe"),
        s!("/dev/goldfish_pipe"),
        s!("/dev/socket/qemud"),
        s!("/system/bin/qemu-props"),
        s!("/system/lib/libc_malloc_debug_qemu.so"),
        s!("/sys/qemu_trace"),
        s!("/dev/vboxguest"),
        s!("/dev/vboxuser"),
        s!("/system/bin/nox-prop"),
        s!("/system/bin/noxd"),
        s!("/system/bin/ldinit"),
        s!("/system/bin/ldmountsf"),
    ]
    .iter()
    .any(|path| exists(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::props_from;

    #[test]
    fn real_phones_are_not_emulators() {
        let pixel = props_from(
            "ro.hardware=husky\nro.boot.hardware=husky\nro.product.board=husky\nro.product.model=Pixel 8 Pro\n\
             ro.product.name=husky\nro.product.device=husky\nro.product.manufacturer=Google",
        );
        assert!(!property_trace(&pixel));
        let samsung =
            props_from("ro.hardware=qcom\nro.product.model=SM-A155F\nro.product.name=a15nsxx\nro.product.device=a15");
        assert!(!property_trace(&samsung));
        assert!(!file_trace(&|_| false));
    }

    #[test]
    fn emulators_are_found() {
        assert!(property_trace(&props_from("ro.kernel.qemu=1")));
        assert!(property_trace(&props_from("ro.hardware=ranchu\nro.product.model=sdk_gphone64_arm64")));
        assert!(property_trace(&props_from("ro.product.manufacturer=Genymotion")));
        assert!(property_trace(&props_from("ro.boot.hardware=vbox86")));
        assert!(property_trace(&props_from("ro.product.model=Android SDK built for x86")));
        assert!(file_trace(&|path| path == "/dev/qemu_pipe"));
    }
}
