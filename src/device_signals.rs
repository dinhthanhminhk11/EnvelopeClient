//! Device signals for `POST /api/v1/devices/register` (`deviceSignals`, theme-x plan §4.1), ported from ai-car
//! `cpp/device/hw_fingerprint_encode.cpp` + `device_identity.cpp` with standard SHA-256, byte-identical to its vectors.
//!
//! Output: lowercase hex SHA-256 digests (the server accepts `^(?:[0-9a-fA-F]{2}){16,64}$` and stores
//! `HMAC(pepper, kind|hex)`), plus `drmStatus` (`^[a-z0-9_-]{1,32}$`). An unreadable signal is omitted, never sent as
//! `sha256("")`, which every failing device would share.
//!
//! Inputs from Kotlin (only Java can read them reliably): ANDROID_ID (`Settings.Secure.ANDROID_ID`), the Widevine
//! `deviceUniqueId` (`MediaDrm.getPropertyByteArray`) or the reason it failed, and the sensor list
//! (`SensorManager.getSensorList(Sensor.TYPE_ALL)`). Read natively: `ro.product.manufacturer`, `ro.product.model`,
//! `ro.product.cpu.abilist` (fallback `ro.product.cpu.abi`), processor count, total RAM and `/data` size.

use obfstr::obfstr;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::codec::{hex_encode, unframe, Frame};
use crate::error::{Error, Result};

const MIB: i64 = 1 << 20;
const GIB: i64 = 1 << 30;
const FIRST_RAM_BUCKET_MIB: i64 = 512;
/// accelerometer, magnetic field, gyroscope, light, pressure, proximity, relative humidity, ambient temperature.
const FINGERPRINT_SENSOR_TYPES: [i32; 8] = [1, 2, 4, 5, 6, 8, 12, 13];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HwSensor {
    pub sensor_type: i32,
    pub vendor: String,
    pub name: String,
}

/// Raw hardware signals; an unreadable value is "" / 0.
#[derive(Clone, Debug, Default)]
pub struct HwSignals {
    pub manufacturer: String,
    pub model: String,
    pub primary_abi: String,
    pub processors: i64,
    pub total_mem_bytes: i64,
    pub data_bytes: i64,
    pub sensors: Vec<HwSensor>,
}

/// Outcome of the Widevine read done in Kotlin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrmFailure {
    /// `UnsupportedSchemeException` / scheme not supported.
    Unsupported,
    /// `NotProvisionedException`.
    NotProvisioned,
    /// Any other failure.
    Error,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

/// `androidIdHash = sha256Hex(utf8(ANDROID_ID))`, absent when ANDROID_ID is empty.
pub fn android_id_hash(android_id_utf8: &[u8]) -> Option<String> {
    (!android_id_utf8.is_empty()).then(|| sha256_hex(android_id_utf8))
}

/// False for an empty id or one where every byte is identical (junk id).
pub fn drm_id_is_valid(id: &[u8]) -> bool {
    id.first().is_some_and(|first| id.iter().any(|byte| byte != first))
}

/// `sha256Hex(lowerHex(id) + "|" + model)`, absent when the id is junk.
pub fn drm_id_hash(id: &[u8], model: &str) -> Option<String> {
    if !drm_id_is_valid(id) {
        return None;
    }
    let mut material = hex_encode(id);
    material.push('|');
    material.push_str(model);
    let hash = sha256_hex(material.as_bytes());
    material.zeroize();
    Some(hash)
}

pub fn is_fingerprint_sensor_type(sensor_type: i32) -> bool {
    FINGERPRINT_SENSOR_TYPES.contains(&sensor_type)
}

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Runs of ASCII whitespace become one space, the result is trimmed, only A–Z are lowered. Works on UTF-8 bytes
/// (the bytes it touches never occur inside a multi-byte sequence).
pub fn normalize(value: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(value.len());
    let mut pending_space = false;
    for &byte in value.as_bytes() {
        if is_ascii_whitespace(byte) {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(b' ');
        }
        pending_space = false;
        out.push(byte.to_ascii_lowercase());
    }
    // Only ASCII bytes were changed, so the bytes are still valid UTF-8.
    String::from_utf8(out).unwrap_or_default()
}

pub fn processor_count(processors: i64) -> i64 {
    if processors <= 1 {
        0
    } else {
        processors
    }
}

fn ceil_div(value: i64, unit: i64) -> i64 {
    value / unit + i64::from(value % unit != 0)
}

/// Ceiling into 512, 768, 1024, 1536, 2048, 3072, … MiB; 0 when `total_bytes <= 0`.
pub fn ram_bucket_mib(total_bytes: i64) -> i64 {
    if total_bytes <= 0 {
        return 0;
    }
    let needed = ceil_div(total_bytes, MIB);
    let mut bucket = FIRST_RAM_BUCKET_MIB;
    while bucket < needed {
        bucket = if bucket & (bucket - 1) == 0 { bucket / 2 * 3 } else { bucket / 3 * 4 };
    }
    bucket
}

/// Ceiling to a power of two GiB; 0 when `total_bytes <= 0`.
pub fn data_bucket_gib(total_bytes: i64) -> i64 {
    if total_bytes <= 0 {
        return 0;
    }
    let needed = ceil_div(total_bytes, GIB);
    let mut bucket = 1;
    while bucket < needed {
        bucket *= 2;
    }
    bucket
}

/// Filter by type, normalize vendor/name, sort by (type, vendor bytes, name bytes), dedupe.
pub fn canonical_sensors(sensors: &[HwSensor]) -> Vec<HwSensor> {
    let mut out: Vec<HwSensor> = sensors
        .iter()
        .filter(|sensor| is_fingerprint_sensor_type(sensor.sensor_type))
        .map(|sensor| HwSensor {
            sensor_type: sensor.sensor_type,
            vendor: normalize(&sensor.vendor),
            name: normalize(&sensor.name),
        })
        .collect();
    // String's Ord is byte-wise, like std::string::compare in the C++ reference.
    out.sort();
    out.dedup();
    out
}

/// Length-prefixed CNHW1 encoding.
pub fn encode_hw_fingerprint(signals: &HwSignals) -> Vec<u8> {
    let sensors = canonical_sensors(&signals.sensors);
    let mut frame = Frame::with_capacity(128 + sensors.len() * 64)
        .text(obfstr!("CNHW1"))
        .text(&normalize(&signals.manufacturer))
        .text(&normalize(&signals.model))
        .text(&normalize(&signals.primary_abi))
        .text(&processor_count(signals.processors).to_string())
        .text(&ram_bucket_mib(signals.total_mem_bytes).to_string())
        .text(&data_bucket_gib(signals.data_bytes).to_string())
        .text(&sensors.len().to_string());
    for sensor in &sensors {
        frame = frame.text(&sensor.sensor_type.to_string()).text(&sensor.vendor).text(&sensor.name);
    }
    frame.finish()
}

/// `sha256Hex(CNHW1 encoding)`, absent when the normalized model is empty or the RAM or /data bucket is 0.
pub fn hw_fingerprint_hash(signals: &HwSignals) -> Option<String> {
    if normalize(&signals.model).is_empty()
        || ram_bucket_mib(signals.total_mem_bytes) == 0
        || data_bucket_gib(signals.data_bytes) == 0
    {
        return None;
    }
    Some(sha256_hex(&encode_hw_fingerprint(signals)))
}

/// Sensor list from Kotlin: a frame of triples `(i32be type as a 4-byte field, vendor UTF-8, name UTF-8)`.
pub fn parse_sensors(input: &[u8]) -> Result<Vec<HwSensor>> {
    let fields = unframe(input).ok_or(Error::InvalidArgument)?;
    if fields.len() % 3 != 0 || fields.len() / 3 > 1024 {
        return Err(Error::InvalidArgument);
    }
    fields
        .chunks_exact(3)
        .map(|triple| {
            let sensor_type = i32::from_be_bytes(<[u8; 4]>::try_from(triple[0]).map_err(|_| Error::InvalidArgument)?);
            Ok(HwSensor {
                sensor_type,
                vendor: String::from_utf8_lossy(triple[1]).into_owned(),
                name: String::from_utf8_lossy(triple[2]).into_owned(),
            })
        })
        .collect()
}

/// Encodes sensors the way Kotlin must (used by tests and documented in the JNI API).
pub fn encode_sensors(sensors: &[HwSensor]) -> Vec<u8> {
    let mut frame = Frame::new();
    for sensor in sensors {
        frame = frame.bytes(&sensor.sensor_type.to_be_bytes()).text(&sensor.vendor).text(&sensor.name);
    }
    frame.finish()
}

pub struct SignalInputs<'a> {
    pub android_id: Option<&'a [u8]>,
    pub drm_id: Option<&'a [u8]>,
    pub drm_failure: Option<DrmFailure>,
    pub hw: HwSignals,
}

/// The `deviceSignals` JSON object of the register body; absent signals are left out.
pub fn device_signals_json(inputs: &SignalInputs<'_>) -> Vec<u8> {
    let mut object = Map::new();
    if let Some(hash) = inputs.android_id.and_then(android_id_hash) {
        object.insert("androidIdHash".into(), Value::from(hash));
    }
    let drm_status = match (inputs.drm_id, inputs.drm_failure) {
        (Some(id), _) => match drm_id_hash(id, &inputs.hw.model) {
            Some(hash) => {
                object.insert("drmIdHash".into(), Value::from(hash));
                "ok"
            }
            None => "invalid",
        },
        (None, Some(DrmFailure::Unsupported)) => "unsupported",
        (None, Some(DrmFailure::NotProvisioned)) => "not_provisioned",
        (None, _) => "error",
    };
    object.insert("drmStatus".into(), Value::from(drm_status));
    if let Some(hash) = hw_fingerprint_hash(&inputs.hw) {
        object.insert("hwFpHash".into(), Value::from(hash));
    }
    serde_json::to_vec(&Value::Object(object)).unwrap_or_else(|_| b"{}".to_vec())
}

pub fn parse_drm_failure(value: &[u8]) -> DrmFailure {
    match value {
        b"unsupported" => DrmFailure::Unsupported,
        b"not_provisioned" => DrmFailure::NotProvisioned,
        _ => DrmFailure::Error,
    }
}

/// Hardware signals read in-process (everything except the sensor list).
#[cfg(target_os = "android")]
pub fn read_native_hw(sensors: Vec<HwSensor>) -> HwSignals {
    use crate::sys::property;

    let abi_list = property(obfstr!("ro.product.cpu.abilist"));
    let mut primary_abi = abi_list.split(',').next().unwrap_or("").to_owned();
    if primary_abi.is_empty() {
        primary_abi = property(obfstr!("ro.product.cpu.abi"));
    }
    HwSignals {
        manufacturer: property(obfstr!("ro.product.manufacturer")),
        model: property(obfstr!("ro.product.model")),
        primary_abi,
        processors: read_processors(),
        total_mem_bytes: read_total_memory(),
        data_bytes: read_data_bytes(),
        sensors,
    }
}

#[cfg(not(target_os = "android"))]
pub fn read_native_hw(sensors: Vec<HwSensor>) -> HwSignals {
    HwSignals { sensors, ..HwSignals::default() }
}

/// `Runtime.availableProcessors()` on Android is `sysconf(_SC_NPROCESSORS_CONF)`.
#[cfg(target_os = "android")]
fn read_processors() -> i64 {
    // SAFETY: sysconf has no memory side effects.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    count.max(0) as i64
}

/// Same value as `ActivityManager.MemoryInfo.totalMem` (MemTotal).
#[cfg(target_os = "android")]
#[allow(clippy::useless_conversion)] // c_ulong is u32 on armeabi-v7a
fn read_total_memory() -> i64 {
    // SAFETY: sysinfo writes into the zeroed struct we own.
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } != 0 {
        return 0;
    }
    let unit = if info.mem_unit == 0 { 1 } else { u64::from(info.mem_unit) };
    clamp_i64(u64::from(info.totalram).saturating_mul(unit))
}

/// Same value as `StatFs(Environment.getDataDirectory()).totalBytes`.
#[cfg(target_os = "android")]
#[allow(clippy::useless_conversion)] // fsblkcnt_t / c_ulong are u32 on armeabi-v7a
fn read_data_bytes() -> i64 {
    let path = std::ffi::CString::new(obfstr!("/data")).unwrap_or_default();
    // SAFETY: statvfs writes into the zeroed struct we own; path is NUL-terminated.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return 0;
    }
    clamp_i64(u64::from(stat.f_blocks).saturating_mul(u64::from(stat.f_frsize)))
}

#[cfg(target_os = "android")]
fn clamp_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    //! Vectors of ai-car `cpp/tests/hw_fingerprint_encode_test.cpp` (shared with its server tests).
    use super::*;

    fn sensor(sensor_type: i32, vendor: &str, name: &str) -> HwSensor {
        HwSensor { sensor_type, vendor: vendor.into(), name: name.into() }
    }

    fn vector_one() -> HwSignals {
        HwSignals {
            manufacturer: " Samsung ".into(),
            model: "SM-A155F".into(),
            primary_abi: "arm64-v8a".into(),
            processors: 8,
            total_mem_bytes: 3_872_000_000,
            data_bytes: 110_317_191_168,
            sensors: vec![
                sensor(1, "STMicroelectronics", "LSM6DSO  Accelerometer"),
                sensor(4, "STMicroelectronics", "LSM6DSO Gyroscope"),
                sensor(2, "AKM", "AK09918 Magnetometer"),
                sensor(8, "Sensortek", "STK3A5X Proximity Sensor"),
                sensor(5, "Sensortek", "STK3A5X Light Sensor"),
                sensor(1, "STMICROELECTRONICS", "lsm6dso\taccelerometer "),
                sensor(9, "Samsung", "Gravity Sensor"),
                sensor(65601, "Samsung", "Vendor Private Sensor"),
            ],
        }
    }

    fn unreadable() -> HwSignals {
        HwSignals { processors: 1, ..HwSignals::default() }
    }

    #[test]
    fn vector_one_matches() {
        let bytes = encode_hw_fingerprint(&vector_one());
        assert_eq!(bytes.len(), 294);
        let expected = "762648282cb1943fe3ad01c5d92dd924d31dee50b31103d9cb2d6d52c7ab2ccc";
        assert_eq!(sha256_hex(&bytes), expected);
        assert_eq!(hw_fingerprint_hash(&vector_one()).as_deref(), Some(expected));
    }

    #[test]
    fn all_unreadable() {
        let mut signals = unreadable();
        let bytes = encode_hw_fingerprint(&signals);
        assert_eq!(bytes.len(), 41);
        let expected = "9d1641521a8681dd25c729d10004b2a76649d7828197650948533c366a17751c";
        assert_eq!(sha256_hex(&bytes), expected);
        signals.processors = 0;
        assert_eq!(sha256_hex(&encode_hw_fingerprint(&signals)), expected);
    }

    #[test]
    fn sensor_filter_dedupe_sort() {
        let expected = vec![
            sensor(1, "stmicroelectronics", "lsm6dso accelerometer"),
            sensor(2, "akm", "ak09918 magnetometer"),
            sensor(4, "stmicroelectronics", "lsm6dso gyroscope"),
            sensor(5, "sensortek", "stk3a5x light sensor"),
            sensor(8, "sensortek", "stk3a5x proximity sensor"),
        ];
        assert_eq!(canonical_sensors(&vector_one().sensors), expected);

        let input = vec![
            sensor(13, "b", "a"),
            sensor(12, "z", "z"),
            sensor(13, "a", "b"),
            sensor(13, "a", "a"),
            sensor(6, "", ""),
            sensor(3, "a", "a"),
        ];
        let sorted = vec![
            sensor(6, "", ""),
            sensor(12, "z", "z"),
            sensor(13, "a", "a"),
            sensor(13, "a", "b"),
            sensor(13, "b", "a"),
        ];
        assert_eq!(canonical_sensors(&input), sorted);
        assert!(!is_fingerprint_sensor_type(9));
        assert!(!is_fingerprint_sensor_type(65601));
        assert!(is_fingerprint_sensor_type(13));
    }

    #[test]
    fn ram_buckets() {
        let cases: [(i64, i64); 15] = [
            (0, 0),
            (-1, 0),
            (1, 512),
            (512 * MIB, 512),
            (512 * MIB + 1, 768),
            (768 * MIB + 1, 1024),
            (1_900_000_000, 2048),
            (2_800_000_000, 3072),
            (3_872_000_000, 4096),
            (5_900_000_000, 6144),
            (7_700_000_000, 8192),
            (11_800_000_000, 12288),
            (12 * GIB, 12288),
            (12 * GIB + 1, 16384),
            (16 * GIB + 1, 24576),
        ];
        for (input, expected) in cases {
            assert_eq!(ram_bucket_mib(input), expected, "{input}");
        }
    }

    #[test]
    fn data_buckets() {
        let cases: [(i64, i64); 10] = [
            (0, 0),
            (-1, 0),
            (1, 1),
            (10_000_000_000, 16),
            (24_000_000_000, 32),
            (52_000_000_000, 64),
            (64 * GIB, 64),
            (64 * GIB + 1, 128),
            (110_317_191_168, 128),
            (240_000_000_000, 256),
        ];
        for (input, expected) in cases {
            assert_eq!(data_bucket_gib(input), expected, "{input}");
        }
    }

    #[test]
    fn processors() {
        for (input, expected) in [(-1, 0), (0, 0), (1, 0), (2, 2), (8, 8)] {
            assert_eq!(processor_count(input), expected);
        }
    }

    #[test]
    fn normalize_cases() {
        assert_eq!(normalize(""), "");
        assert_eq!(normalize(" \t\r\n "), "");
        assert_eq!(normalize(" Samsung "), "samsung");
        assert_eq!(normalize("LSM6DSO  Accelerometer"), "lsm6dso accelerometer");
        assert_eq!(normalize("lsm6dso\taccelerometer "), "lsm6dso accelerometer");
        assert_eq!(normalize("\x0b\x0cA\r\nB "), "a b");
        assert_eq!(normalize("\u{c9}CLAIR \u{c4} I"), "\u{c9}clair \u{c4} i");
        assert_eq!(normalize("A B"), "a b");
    }

    #[test]
    fn omit_rules() {
        assert_eq!(hw_fingerprint_hash(&unreadable()), None);
        let mut blank_model = vector_one();
        blank_model.model = " \t ".into();
        assert_eq!(hw_fingerprint_hash(&blank_model), None);
        let mut no_ram = vector_one();
        no_ram.total_mem_bytes = 0;
        assert_eq!(hw_fingerprint_hash(&no_ram), None);
        let mut no_data = vector_one();
        no_data.data_bytes = 0;
        assert_eq!(hw_fingerprint_hash(&no_data), None);
    }

    #[test]
    fn sha256_and_android_id() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        assert_eq!(android_id_hash(b""), None);
        assert_eq!(
            android_id_hash(b"abc").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex_encode(&[]), "");
    }

    /// ai-car converts the Java UTF-16 string itself; here Kotlin passes `toByteArray(UTF_8)`, which produces the same
    /// bytes (unpaired surrogates become '?'), so the hash of a non-ASCII id still matches the C++ path.
    #[test]
    fn utf8_bytes_like_java() {
        let java_utf8 = "\u{111}\u{20ac}\u{1f600}".as_bytes();
        assert_eq!(java_utf8, b"\xC4\x91\xE2\x82\xAC\xF0\x9F\x98\x80");
    }

    #[test]
    fn drm_hashes() {
        let id = [0x01, 0xab, 0x00, 0xff];
        assert_eq!(
            drm_id_hash(&id, "SM-A155F").as_deref(),
            Some("af45bf257c4d36217e369b67aa32f95440b34493cfcf7f028c1c0707aa4ef32b")
        );
        assert_eq!(
            drm_id_hash(&id, "").as_deref(),
            Some("f26024c61fe637c096a474c215e23ef5226f059ac8d0927aeed08088c7a15584")
        );
        assert_eq!(drm_id_hash(&[], "SM-A155F"), None);
        assert_eq!(drm_id_hash(&[0u8; 32], "SM-A155F"), None);
        assert_eq!(drm_id_hash(&[0x7f; 16], "SM-A155F"), None);
        assert!(!drm_id_is_valid(&[0x42]));
    }

    /// The JSON is the `deviceSignals` object of theme-x registration (the doodle-art server does not read it yet).
    #[test]
    fn json_matches_backend_validation() {
        let hex_digest = |value: &Value| {
            let text = value.as_str().unwrap();
            (32..=128).contains(&text.len()) && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit())
        };
        let drm_id = [0x01, 0xab, 0x00, 0xff];
        let inputs = SignalInputs {
            android_id: Some(b"9774d56d682e549c"),
            drm_id: Some(&drm_id),
            drm_failure: None,
            hw: vector_one(),
        };
        let json: Value = serde_json::from_slice(&device_signals_json(&inputs)).unwrap();
        assert!(hex_digest(&json["androidIdHash"]) && hex_digest(&json["drmIdHash"]) && hex_digest(&json["hwFpHash"]));
        assert_eq!(json["drmStatus"], "ok");
        assert_eq!(json["hwFpHash"], "762648282cb1943fe3ad01c5d92dd924d31dee50b31103d9cb2d6d52c7ab2ccc");
        assert_eq!(json["drmIdHash"], "af45bf257c4d36217e369b67aa32f95440b34493cfcf7f028c1c0707aa4ef32b");

        let empty = SignalInputs {
            android_id: Some(b""),
            drm_id: None,
            drm_failure: Some(DrmFailure::NotProvisioned),
            hw: unreadable(),
        };
        let json: Value = serde_json::from_slice(&device_signals_json(&empty)).unwrap();
        assert_eq!(json, serde_json::json!({ "drmStatus": "not_provisioned" }));

        let junk = SignalInputs { android_id: None, drm_id: Some(&[0u8; 16]), drm_failure: None, hw: unreadable() };
        let json: Value = serde_json::from_slice(&device_signals_json(&junk)).unwrap();
        assert_eq!(json, serde_json::json!({ "drmStatus": "invalid" }));
        for status in ["ok", "invalid", "unsupported", "not_provisioned", "error"] {
            assert!(crate::envelope::validate::risk_flag(status));
        }
    }

    #[test]
    fn sensors_round_trip() {
        let sensors = vector_one().sensors;
        assert_eq!(parse_sensors(&encode_sensors(&sensors)).unwrap(), sensors);
        assert_eq!(parse_sensors(&[]).unwrap(), vec![]);
        assert!(parse_sensors(&Frame::new().text("x").finish()).is_err());
    }
}
