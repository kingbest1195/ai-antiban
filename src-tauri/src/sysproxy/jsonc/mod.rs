//! Point editor for JSONC (`settings.json` of VS Code and its forks, Claude Code, Gemini CLI).
//!
//! It finds the value of one key (also inside a nested object), replaces, inserts or deletes it
//! and leaves every other byte of the document alone: comments (`//`, `/* */`), BOM, CR/LF line
//! ends, indentation, unicode, trailing commas and the order of the keys all stay as they were.
//!
//! The editor refuses (returns `Err`, the caller writes nothing) when the document is damaged or
//! ambiguous: a syntax error anywhere, a root that is not an object, a key that is repeated in the
//! object being edited, or an intermediate value that is not an object. Errors carry no values.

use std::fmt;

/// Why an edit was refused. Never carries document content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsoncError {
    /// Not valid JSONC (including unterminated strings / comments).
    Syntax,
    /// The document holds only whitespace (a BOM is allowed) or only comments.
    NoRoot,
    /// The root, or an intermediate value on the path, is not an object.
    NotObject,
    /// The key being looked up appears more than once in the same object.
    DuplicateKey,
    /// The object that must hold the key does not exist.
    MissingParent,
}

impl fmt::Display for JsoncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JsoncError::Syntax => "settings file is not valid JSON with comments",
            JsoncError::NoRoot => "settings file has no JSON object",
            JsoncError::NotObject => "settings file holds a value that is not an object",
            JsoncError::DuplicateKey => "settings file repeats a key",
            JsoncError::MissingParent => "the parent object does not exist",
        })
    }
}

impl std::error::Error for JsoncError {}

/// The value found at a key path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<'a> {
    /// The exact text of the value token(s), without surrounding whitespace or comments.
    pub raw: &'a str,
    pub is_object: bool,
    /// An object with no members and nothing but whitespace between the braces (no comments).
    pub is_empty_object: bool,
}


mod doc;
mod parser;

use doc::{Located, parse};

pub(super) fn quote(key: &str) -> String {
    serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string())
}

fn apply(text: &str, mut edits: Vec<(usize, usize, String)>) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse((e.0, e.1)));
    let mut out = text.to_string();
    for (s, e, r) in edits {
        out.replace_range(s..e, &r);
    }
    out
}

/// Checks that `text` is a usable JSONC document with an object root.
pub fn validate(text: &str) -> Result<(), JsoncError> {
    parse(text).map(|_| ())
}

/// The value at `path`, `Ok(None)` when it (or its parent object) does not exist.
pub fn get<'a>(text: &'a str, path: &[&str]) -> Result<Option<Found<'a>>, JsoncError> {
    let doc = parse(text)?;
    Ok(match doc.locate(path)? {
        Located::Found { parent, idx } => {
            let m = &parent.members[idx];
            let (is_object, is_empty_object) = match &m.obj {
                Some(o) => (
                    true,
                    o.members.is_empty() && text[o.open + 1..o.close].trim().is_empty(),
                ),
                None => (false, false),
            };
            Some(Found {
                raw: &text[m.val_start..m.val_end],
                is_object,
                is_empty_object,
            })
        }
        Located::Absent { .. } | Located::ParentMissing => None,
    })
}

/// Replaces or inserts the value (`raw` is its JSON text) at `path`. The parent object must exist
/// ([`JsoncError::MissingParent`]). A document with only blanks becomes a new object.
pub fn set(text: &str, path: &[&str], raw: &str) -> Result<String, JsoncError> {
    if path.is_empty() {
        return Err(JsoncError::NotObject);
    }
    let doc = match parse(text) {
        Err(JsoncError::NoRoot) if path.len() == 1 && is_blank(text) => {
            let (bom, rest) = split_bom(text);
            let eol = if rest.contains("\r\n") { "\r\n" } else { "\n" };
            return Ok(format!(
                "{bom}{{{eol}  {}: {raw}{eol}}}{eol}",
                quote(path[0])
            ));
        }
        other => other?,
    };
    match doc.locate(path)? {
        Located::ParentMissing => Err(JsoncError::MissingParent),
        Located::Found { parent, idx } => {
            let m = &parent.members[idx];
            Ok(apply(text, vec![(m.val_start, m.val_end, raw.to_string())]))
        }
        Located::Absent { parent } => {
            let key = path[path.len() - 1];
            Ok(apply(text, doc.insert_member(parent, key, raw)))
        }
    }
}

/// Deletes the key at `path`; a missing key (or parent) leaves the text as it is.
pub fn remove(text: &str, path: &[&str]) -> Result<String, JsoncError> {
    let doc = parse(text)?;
    match doc.locate(path)? {
        Located::Found { parent, idx } => Ok(apply(text, doc.remove_member(parent, idx))),
        Located::Absent { .. } | Located::ParentMissing => Ok(text.to_string()),
    }
}

fn split_bom(text: &str) -> (&str, &str) {
    match text.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", text),
    }
}

/// Only blanks (and an optional BOM).
pub fn is_blank(text: &str) -> bool {
    split_bom(text).1.trim().is_empty()
}


#[cfg(test)]
mod tests;
