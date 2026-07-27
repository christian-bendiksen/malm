use kdl::KdlDocument;

use crate::{
    MAX_CONFIG_COMMENT_NESTING_DEPTH, MAX_CONFIG_DOCUMENT_BYTES, MAX_CONFIG_NESTING_DEPTH,
};

/// Bounded lexical or KDL failure before rich grammar validation.
#[derive(Debug, thiserror::Error)]
pub enum RichSyntaxErrorV1 {
    #[error("rich config document is {actual} bytes; limit is {limit}")]
    TooLarge { limit: usize, actual: usize },
    #[error("rich config document is not UTF-8")]
    InvalidUtf8,
    #[error("rich config KDL nesting exceeds limit {limit}")]
    NestingTooDeep { limit: usize },
    #[error("rich config KDL block-comment nesting exceeds limit {limit}")]
    CommentNestingTooDeep { limit: usize },
    #[error("malformed rich config KDL: {0}")]
    MalformedKdl(String),
}

pub(crate) fn parse_document(bytes: &[u8]) -> Result<KdlDocument, RichSyntaxErrorV1> {
    if bytes.len() > MAX_CONFIG_DOCUMENT_BYTES {
        return Err(RichSyntaxErrorV1::TooLarge {
            limit: MAX_CONFIG_DOCUMENT_BYTES,
            actual: bytes.len(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RichSyntaxErrorV1::InvalidUtf8)?;
    enforce_nesting_limit(text)?;
    KdlDocument::parse_v2(text).map_err(|error| RichSyntaxErrorV1::MalformedKdl(error.to_string()))
}

#[derive(Clone, Copy)]
enum ScanState {
    Normal,
    LineComment,
    BlockComment(usize),
    Quoted { multiline: bool },
    Raw { hashes: usize, multiline: bool },
}

fn enforce_nesting_limit(text: &str) -> Result<(), RichSyntaxErrorV1> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut depth = 0;
    let mut state = ScanState::Normal;
    while index < bytes.len() {
        match state {
            ScanState::Normal => {
                if bytes[index..].starts_with(b"//") {
                    state = ScanState::LineComment;
                    index += 2;
                } else if bytes[index..].starts_with(b"/*") {
                    state = ScanState::BlockComment(1);
                    index += 2;
                } else if bytes[index] == b'"' {
                    let multiline = bytes[index..].starts_with(b"\"\"\"");
                    state = ScanState::Quoted { multiline };
                    index += if multiline { 3 } else { 1 };
                } else if bytes[index] == b'#' {
                    let start = index;
                    while index < bytes.len() && bytes[index] == b'#' {
                        index += 1;
                    }
                    let hashes = index - start;
                    if index < bytes.len() && bytes[index] == b'"' {
                        let multiline = bytes[index..].starts_with(b"\"\"\"");
                        state = ScanState::Raw { hashes, multiline };
                        index += if multiline { 3 } else { 1 };
                    }
                } else {
                    match bytes[index] {
                        b'{' => {
                            depth += 1;
                            if depth > MAX_CONFIG_NESTING_DEPTH {
                                return Err(RichSyntaxErrorV1::NestingTooDeep {
                                    limit: MAX_CONFIG_NESTING_DEPTH,
                                });
                            }
                        }
                        b'}' => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                    index += 1;
                }
            }
            ScanState::LineComment => {
                if let Some(length) = newline_length(bytes, index) {
                    state = ScanState::Normal;
                    index += length;
                } else {
                    index += 1;
                }
            }
            ScanState::BlockComment(block_depth) => {
                if bytes[index..].starts_with(b"/*") {
                    if block_depth == MAX_CONFIG_COMMENT_NESTING_DEPTH {
                        return Err(RichSyntaxErrorV1::CommentNestingTooDeep {
                            limit: MAX_CONFIG_COMMENT_NESTING_DEPTH,
                        });
                    }
                    state = ScanState::BlockComment(block_depth + 1);
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    state = if block_depth == 1 {
                        ScanState::Normal
                    } else {
                        ScanState::BlockComment(block_depth - 1)
                    };
                    index += 2;
                } else {
                    index += 1;
                }
            }
            ScanState::Quoted { multiline } => {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if multiline && bytes[index..].starts_with(b"\"\"\"") {
                    state = ScanState::Normal;
                    index += 3;
                } else if !multiline && bytes[index] == b'"' {
                    state = ScanState::Normal;
                    index += 1;
                } else {
                    index += 1;
                }
            }
            ScanState::Raw { hashes, multiline } => {
                let quote_count = if multiline { 3 } else { 1 };
                if bytes[index..].starts_with(&b"\"\"\""[..quote_count]) {
                    let hash_start = index + quote_count;
                    let hash_end = hash_start.saturating_add(hashes);
                    if hash_end <= bytes.len()
                        && bytes[hash_start..hash_end].iter().all(|byte| *byte == b'#')
                    {
                        state = ScanState::Normal;
                        index = hash_end;
                        continue;
                    }
                }
                index += 1;
            }
        }
    }
    Ok(())
}

fn newline_length(bytes: &[u8], index: usize) -> Option<usize> {
    match bytes[index] {
        b'\r' => Some(1 + usize::from(bytes.get(index + 1) == Some(&b'\n'))),
        b'\n' | 0x0b | 0x0c => Some(1),
        0xc2 if bytes.get(index + 1) == Some(&0x85) => Some(2),
        0xe2 if bytes.get(index + 1) == Some(&0x80)
            && bytes
                .get(index + 2)
                .is_some_and(|byte| matches!(*byte, 0xa8 | 0xa9)) =>
        {
            Some(3)
        }
        _ => None,
    }
}
