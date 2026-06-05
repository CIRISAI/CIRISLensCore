//! `scoring/` module — N_eff (Kish), capacity band, LC-AV-18
//! assembly gate, and the `ManifoldConformity` result enum.
//! See MISSION.md §2 scoring/.

pub mod assembly;
pub mod capacity;
pub mod n_eff;
pub mod result;

pub use assembly::{assemble, AssemblyInput};
pub use capacity::capacity;
pub use n_eff::kish_n_eff;
pub use result::{
    AxisFamily, DetectionEvent, IndeterminateReason, ManifoldConformity, Score, Severity,
    UnavailableReason,
};
