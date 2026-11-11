//! Phone-side sync logic behind the Buteo plugin shim.
//!
//! The C++ shim is an I/O adapter: it dumps raw local data (QtContacts,
//! mKCal), applies write plans, stores settings and shows notifications.
//! Every decision — what changed, what to upload, what to write, what to
//! remember — is made here and driven through [`session::Session`].

pub mod calendar;
pub mod calendar_identity;
pub mod caltime;
pub mod contacts;
pub mod reconcile;
pub mod session;
pub mod settings;

pub(crate) use proton_api::diag::verbose;
