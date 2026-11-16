#[deny(clippy::indexing_slicing)]
mod cpp_string;
mod loader;
mod aasset;
mod jniopts;
mod plthook;
use std::{
    fs,
    sync::{LockResult, Mutex},
};
use crate::{loader::ResourcePackManager, plthook::replace_plt_functions};
use bhook::hook_fn;
use bstr::ByteSlice;
use atoi::FromRadix16;
use plt_rs::DynamicLibrary;
use tinypatscan::Pattern;

const RPMC_PATTERNS: [Pattern; 9] = [
    // 1.26.60+ (exact - byte 9 = 0x67)
    Pattern::from_str("FF C3 07 D1 FD 7B 1A A9 FC 67 1B A9 F8 5F 1C A9 F6 57 1D A9 F4 4F 1E A9 FD 83 06 91 58 D0 3B D5 F4 03 02 AA F3 03 00 AA"),
    // 1.26.60+ (exact - byte 9 = 0x6F)
    Pattern::from_str("FF C3 07 D1 FD 7B 1A A9 FC 6F 1B A9 F8 5F 1C A9 F6 57 1D A9 F4 4F 1E A9 FD 83 06 91 58 D0 3B D5 F4 03 02 AA F3 03 00 AA"),
    // 1.26.60+ (wildcard fallback from PixelBoy mtbinloader2)
    Pattern::from_str("?? ?? ?? D1 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? 91 ?? ?? ?? D5 F4 03 02 AA F3 03 00 AA"),
    // 1.26.60+ (wildcard fallback with canary store A8 83 1F F8)
    Pattern::from_str("?? ?? ?? D1 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? 91 ?? ?? ?? D5 F4 03 02 AA F3 03 00 AA ?? ?? ?? F9 A8 83 1F F8 ?? ?? ?? AA"),
    // v26.50
    Pattern::from_str("?? ?? ?? D1 ?? ?? ?? A9 ?? ?? ?? F9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? 91 ?? ?? ?? D5 F6 03 03 2A F5 03 02 AA ?? ?? ?? F9 F3 03 00 AA"),
    // v26.40
    Pattern::from_str("?? ?? ?? D1 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? 91 ?? ?? ?? D5 F6 03 03 2A F5 03 02 AA ?? ?? ?? F9 F3 03 00 AA"),
    // 1.21.120.4
    Pattern::from_str("FF ?? 02 D1 FD 7B ?? A9 ?? ?? ?? ?? FA 67 ?? A9 F8 5F ?? A9 F6 57 ?? A9 F4 4F ?? A9 FD ?? 01 91 ?? D0 3B D5 ?? 03 03 2A ?? 03 02 AA ?? 17 40 F9 F3 03 00 AA A8 83 1F F8"),
    // 1.21.60.21
    Pattern::from_str("FF 83 02 D1 FD 7B 06 A9 FD 83 01 91 F8 5F 07 A9 F6 57 08 A9 F4 4F 09 A9 58 D0 3B D5 F6 03 03 2A 08 17 40 F9 F5 03 02 AA F3 03 00 AA A8 83 1F F8 28 10 40 F9 28 01 00 B4"),
    // 1.19.50 – 1.21.50
    Pattern::from_str("FF 03 03 D1 FD 7B 07 A9 FD C3 01 91 F9 43 00 F9 F8 5F 09 A9 F6 57 0A A9 F4 4F 0B A9 59 D0 3B D5 F6 03 03 2A 28 17 40 F9 F5 03 02 AA F3 03 00 AA A8 83 1F F8 28 10 40 F9"),
];

pub fn setup_logging() {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Trace),
    );
}

#[ctor::ctor]
fn safe_setup() {
    setup_logging();
    std::panic::set_hook(Box::new(|panic_info| {
        log::error!("Thread crashed: {}", panic_info);
    }));
    main();
}

fn main() {
    log::info!("Starting mbl2 v0.1.12");
    let mcmaps = match find_minecraft_library_manually() {
        Ok(m) => m,
        Err(e) => {
            log::error!("Cannot find libminecraftpe.so in memory maps: {e}");
            return;
        }
    };
    let Some(addr) = find_signatures(&RPMC_PATTERNS, &mcmaps) else {
        log::error!("No RPM signature matched — unsupported MC version, bailing out");
        return;
    };
    log::info!("Hooking ResourcePackManager constructor");
    unsafe { rpm_ctor::hook_address(addr as *mut u8) };
    log::info!("Hooking AssetManager functions");
    hook_aasset();
    log::info!("Checking for 4DSkin module");
    load_4dskin_if_present();
}

/// Dynamically load and activate lib4DSkin.so if present in the APK's library directory.
fn load_4dskin_if_present() {
    let candidate_names = [
        b"lib4DSkin.so\0".as_ptr() as *const libc::c_char,
        b"lib4dskin.so\0".as_ptr() as *const libc::c_char,
    ];

    for &name in &candidate_names {
        unsafe {
            let handle = libc::dlopen(name, libc::RTLD_NOW | libc::RTLD_GLOBAL);
            if handle.is_null() {
                continue;
            }
            log::info!("Found 4DSkin library, initializing hooks");
            let sym = libc::dlsym(handle, b"PLMod_Enable\0".as_ptr() as *const libc::c_char);
            if sym.is_null() {
                log::error!("PLMod_Enable symbol not found in 4DSkin library");
                return;
            }

            // In lib4DSkin.so, PLMod_Enable export stub is at 0x45944.
            // The mod state variable is at offset 0xd4958 in .bss.
            // Setting state = 1 satisfies the check:
            //   0x49220: LDR W8, [X19, #0x958]; CMP W8, #1; B.EQ 0x4923c;
            let base = (sym as usize).wrapping_sub(0x45944);
            let state_ptr = (base + 0xd4958) as *mut u32;
            *state_ptr = 1;
            log::info!("Set lib4DSkin state to 1 (LOADED)");

            // Also patch 0x49220 with "B 0x4923c" (0x14000007) so the guard passes unconditionally
            let patch_addr = (base + 0x49220) as *mut u32;
            if let Ok(_guard) = region::protect_with_handle(
                patch_addr as *const (),
                4,
                region::Protection::READ_WRITE_EXECUTE,
            ) {
                *patch_addr = 0x14000007;
                log::info!("Patched lib4DSkin state guard instruction");
            }

            let enable_fn: extern "C" fn() -> bool = std::mem::transmute(sym);
            let res = enable_fn();
            log::info!("PLMod_Enable executed with result: {}", res);
            return;
        }
    }
    log::info!("lib4DSkin.so not present, skipping 4D skin activation");
}

// ── /proc/self/maps parsing ──────────────────────────────────────────────────

/// Minimal memory map range (start addr + size).
struct SimpleMapRange {
    start: usize,
    size: usize,
}

fn find_minecraft_library_manually() -> Result<Vec<SimpleMapRange>, Box<dyn std::error::Error>> {
    let contents = fs::read("/proc/self/maps")?;
    let ranges: Vec<SimpleMapRange> = contents
        .lines()
        .filter_map(|line| {
            if line.trim_ascii().is_empty() {
                return None;
            }
            let (addr_start, addr_end) = parse_range(line)?;
            let start = usize::from_radix_16(addr_start).0;
            let end = usize::from_radix_16(addr_end).0;
            log::debug!("Found libminecraftpe.so region: {:x}-{:x}", start, end);
            Some(SimpleMapRange { start, size: end - start })
        })
        .collect();

    if ranges.is_empty() {
        Err("libminecraftpe.so not found in memory maps".into())
    } else {
        Ok(ranges)
    }
}

/// Parse one line from /proc/self/maps, returning `(start_hex, end_hex)` bytes
/// only for executable regions belonging to libminecraftpe.so.
#[inline]
fn parse_range(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut fields = buf.split(|b| b.is_ascii_whitespace());
    let addr_range = fields.next()?;
    let perms = fields.next()?;
    let pathname = fields.next_back()?;
    if perms.contains(&b'x') && (pathname.ends_with(b"libminecraftpe.so") || pathname.contains_str(b"libminecraftpe.so")) {
        return addr_range.split_once_str(b"-");
    }
    None
}

// ── signature scanning ───────────────────────────────────────────────────────

fn find_signatures(signatures: &[Pattern], ranges: &[SimpleMapRange]) -> Option<*const u8> {
    for sig in signatures {
        for range in ranges {
            let lib_bytes =
                unsafe { core::slice::from_raw_parts(range.start as *const u8, range.size) };
            if let Some(offset) = sig.search(lib_bytes, tinypatscan::Algorithm::Simd) {
                let addr = unsafe { lib_bytes.as_ptr().byte_add(offset) };
                log::info!(
                    "Signature matched in {:x}-{:x} at offset {:x}",
                    range.start,
                    range.start + range.size,
                    offset
                );
                return Some(addr);
            }
        }
        log::error!("Signature not found in any region");
    }
    None
}

// ── PLT hooking ──────────────────────────────────────────────────────────────

macro_rules! cast_array {
    ($($func_name:literal -> $hook:expr),* $(,)?) => {
        [$(($func_name, $hook as *const u8)),*]
    }
}

/// Hook all AAsset* PLT entries in libminecraftpe.so.
fn hook_aasset() {
    let lib_entry = match find_lib("libminecraftpe") {
        Some(e) => e,
        None => {
            log::error!("Cannot find libminecraftpe in loaded modules — PLT hooks skipped");
            return;
        }
    };
    let dyn_lib = match DynamicLibrary::initialize(lib_entry) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Failed to parse libminecraftpe ELF: {e:?} — PLT hooks skipped");
            return;
        }
    };
    let asset_fn_list = cast_array! {
        "AAssetManager_open"         -> aasset::open,
        "AAsset_read"                -> aasset::read,
        "AAsset_close"               -> aasset::close,
        "AAsset_seek"                -> aasset::seek,
        "AAsset_seek64"              -> aasset::seek64,
        "AAsset_getLength"           -> aasset::len,
        "AAsset_getLength64"         -> aasset::len64,
        "AAsset_getRemainingLength"  -> aasset::rem,
        "AAsset_getRemainingLength64"-> aasset::rem64,
        "AAsset_openFileDescriptor"  -> aasset::fd_dummy,
        "AAsset_openFileDescriptor64"-> aasset::fd_dummy64,
        "AAsset_getBuffer"           -> aasset::get_buffer,
        "AAsset_isAllocated"         -> aasset::is_alloc,
    };
    replace_plt_functions(&dyn_lib, asset_fn_list);
}

fn find_lib<'a>(target_name: &str) -> Option<plt_rs::LoadedLibrary<'a>> {
    plt_rs::collect_modules()
        .into_iter()
        .find(|lib| lib.name().contains(target_name))
}

// ── Global state ─────────────────────────────────────────────────────────────

/// The current ResourcePackManager instance, updated each time MC creates a new one.
pub static PACKM_OBJ: Mutex<Option<ResourcePackManager>> = Mutex::new(None);

hook_fn! {
    fn rpm_ctor(this: *mut libc::c_void, unk1: usize, unk2: usize, needs_init: bool) -> *mut libc::c_void = {
        use crate::loader::ResourcePackManager;
        use crate::LockResultExt;
        log::info!("rpm_ctor called (this={:?}, needs_init={})", this, needs_init);
        let result = call_original(this, unk1, unk2, needs_init);
        log::info!("RPM pointer has been obtained");
        *crate::PACKM_OBJ.lock().ignore_poison() = Some(ResourcePackManager::wrap(this));
        self_disable();
        log::info!("rpm_ctor hook disabled, captured ResourcePackManager pointer ({:?})", this);
        result
    }
}

// ── Utilities ────────────────────────────────────────────────────────────────

pub trait LockResultExt {
    type Guard;
    fn ignore_poison(self) -> Self::Guard;
}

impl<Guard> LockResultExt for LockResult<Guard> {
    type Guard = Guard;
    fn ignore_poison(self) -> Guard {
        self.unwrap_or_else(|e| e.into_inner())
    }
}
