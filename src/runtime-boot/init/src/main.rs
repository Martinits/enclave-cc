extern crate libc;

use libc::syscall;

use nix::mount::MsFlags;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;

use anyhow::Result;
use std::ffi::CString;
use std::mem::size_of;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let agent_boot = matches!(env::var("ENCLAVE_AGENT"), Ok(val) if val == "true" || val == "TRUE" || val == "1");

    // Mount the image
    const SYS_MOUNT_FS: i64 = 363;
    const KEY_FILE: &str = "/tmp/key.txt";

    let ret = match agent_boot {
        true => {
            let root_config_ptr: *const i8 = std::ptr::null();
            unsafe { syscall(SYS_MOUNT_FS, root_config_ptr) }
        }
        false => {
            let rootfs_base = "/eccfs";
            let rootfs_entry = "/";

            let mount_path = Path::new("/tmp");
            let flags = MsFlags::empty();

            nix::mount::mount(
                Some("sefs"),
                mount_path,
                Some("sefs"),
                flags,
                Some("dir=/keys/sefs/lower"),
            ).unwrap_or_else(|err| {
                eprintln!("Error mounting keys: {}", err);
            });

            // Get the key of FS image
            let key_str = load_key(KEY_FILE)?;
            let nr_layer = key_str.as_str().split(":").collect::<Vec<_>>().len();
            let key_str = CString::new(key_str)?;

            nix::mount::umount(mount_path)?;

            // Example envs. must end with null
            let env1 = CString::new("TEST=1234").unwrap();
            let envp = [env1.as_ptr(), std::ptr::null()];

            // Set rootfs parameters
            let lower_path = (0..nr_layer-1).map(
                |n| format!("{rootfs_base}/{:04}.roimage", n)
            ).collect::<Vec<_>>().join(":");
            let upper_layer_path = CString::new(format!("{rootfs_base}/run.rwimage"))?;
            let lower_layer_path = CString::new(lower_path)?;

            let entry_point = CString::new(rootfs_entry).expect("CString::new failed");
            let hostfs_source = CString::new("/tmp").expect("CString::new failed");

            let rootfs_config: user_rootfs_config = user_rootfs_config {
                len: size_of::<user_rootfs_config>(),
                eccfs_key_str: key_str.as_ptr(),
                upper_layer_path: upper_layer_path.as_ptr(),
                lower_layer_path: lower_layer_path.as_ptr(),
                entry_point: entry_point.as_ptr(),
                hostfs_source: hostfs_source.as_ptr(),
                hostfs_target: std::ptr::null(),
                envp: envp.as_ptr(),
            };
            unsafe { syscall(SYS_MOUNT_FS, std::ptr::null() as *const i8, &rootfs_config) }
        }
    };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
struct user_rootfs_config {
    // length of the struct
    len: usize,
    eccfs_key_str: *const i8,
    // UnionFS type rootfs upper layer, read-write layer
    upper_layer_path: *const i8,
    // UnionFS type rootfs lower layer, read-only layer
    lower_layer_path: *const i8,
    entry_point: *const i8,
    // HostFS source path
    hostfs_source: *const i8,
    // HostFS target path, default value is "/host"
    hostfs_target: *const i8,
    // An array of pointers to null-terminated strings
    // and must be terminated by a null pointer
    envp: *const *const i8,
}

fn load_key(key_path: &str) -> Result<String, Box<dyn Error>> {
    let mut key_file = File::open(key_path)?;
    let mut key = String::new();
    key_file.read_to_string(&mut key)?;
    Ok(key.trim_end_matches(|c| c == '\r' || c == '\n').to_string())
}
