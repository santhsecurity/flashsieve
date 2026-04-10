#![allow(clippy::pedantic)]
#![allow(clippy::cast_precision_loss, clippy::doc_markdown, clippy::explicit_iter_loop, clippy::uninlined_format_args, clippy::unreadable_literal)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[path = "../concurrent/mod.rs"]
mod concurrent;

#[path = "../concurrent/multi_writer/mod.rs"]
pub mod multi_writer;

#[path = "../concurrent/reader_writer/mod.rs"]
pub mod reader_writer;

#[path = "../concurrent/stress/mod.rs"]
pub mod stress;
