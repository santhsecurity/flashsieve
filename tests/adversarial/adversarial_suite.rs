#![allow(warnings)]
#![allow(clippy::pedantic)]
#![allow(clippy::cast_precision_loss, clippy::doc_markdown, clippy::explicit_iter_loop, clippy::uninlined_format_args, clippy::unreadable_literal)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[path = "mod.rs"]
mod adversarial;

#[path = "resource/mod.rs"]
pub mod resource;

#[path = "unicode/mod.rs"]
pub mod unicode;

#[path = "boundary/mod.rs"]
pub mod boundary;

#[path = "malformed/mod.rs"]
pub mod malformed;

#[path = "overflow/mod.rs"]
pub mod overflow;
