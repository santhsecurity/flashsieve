#![allow(warnings)]
#![allow(clippy::pedantic)]
#![allow(clippy::cast_precision_loss, clippy::doc_markdown, clippy::explicit_iter_loop, clippy::uninlined_format_args, clippy::unreadable_literal)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod adversarial;

#[path = "adversarial/resource/mod.rs"]
pub mod resource;

#[path = "adversarial/unicode/mod.rs"]
pub mod unicode;

#[path = "adversarial/boundary/mod.rs"]
pub mod boundary;

#[path = "adversarial/malformed/mod.rs"]
pub mod malformed;

#[path = "adversarial/overflow/mod.rs"]
pub mod overflow;
