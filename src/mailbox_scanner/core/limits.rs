//! Shared byte limits for downloading, scanning and preserving messages.

/// Maximum original EML size and maximum decoded MIME leaf size (200 MiB).
pub const MESSAGE_BYTES: usize = 200 * 1024 * 1024;

/// Maximum aggregate decoded MIME material per message (400 MiB).
pub const DECODED_BYTES: usize = 2 * MESSAGE_BYTES;
