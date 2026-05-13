//! `signing/` module — canonicalize + steward_sign for detection events.
//! See MISSION.md §2 signing/.

pub mod event;

pub use event::{sign_detection, DetectionInputs, SigningError};
