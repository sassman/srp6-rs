// The facade is named for the type and re-exported below; the nesting never
// reaches call sites.
#[allow(clippy::module_inception)]
pub(crate) mod big_number;
pub(crate) mod crypto;

pub use big_number::*;
