//! Núcleo do SentinelStack.
//!
//! Esta crate não conhece Tauri, não conhece interface e não sabe que existe
//! um frontend. Ela recebe configuração e devolve dados por canal. Essa é a
//! fronteira inteira.

pub mod diff;
pub mod evidence;
pub mod identity;
pub mod model;
pub mod net;
pub mod rules;
pub mod scan;
pub mod service_diff;
pub mod store;

pub use model::{Capabilities, Device, Observation, ScanConfig, ScanEvent};