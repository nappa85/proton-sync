#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod auth;
pub mod bridge;
mod ffi_utils;

pub use auth::proton_signon_process;
pub use bridge::{
    proton_string_free, proton_sync_free, proton_sync_new, proton_sync_step, ProtonSync,
};
