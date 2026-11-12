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

const MAX_DEPTH: usize = 64;

#[derive(Debug)]
struct Member {
    key: String,
    key_start: usize,
    val_start: usize,
    val_end: usize,
    /// Position of the comma that follows this member, if any.
    comma: Option<usize>,
    obj: Option<Obj>,
}

#[derive(Debug)]
struct Obj {
    open: usize,
    close: usize,
    members: Vec<Member>,
}

struct Parser<'a> {
    b: &'a [u8],
    s: &'a str,
    i: usize,
}

struct Val {
    start: usize,
    end: usize,
    obj: Option<Obj>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_trivia(&mut self) -> Result<(), JsoncError> {
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                b'/' => match self.b.get(self.i + 1) {
                    Some(b'/') => {
                        while let Some(c) = self.peek() {
                            if c == b'\n' || c == b'\r' {
                                break;
                            }
                            self.i += 1;
                        }
                    }
                    Some(b'*') => {
                        let rest = &self.s[self.i + 2..];
                        let end = rest.find("*/").ok_or(JsoncError::Syntax)?;
                        self.i += 2 + end + 2;
                    }
                    _ => return Err(JsoncError::Syntax),
                },
                _ => break,
            }
        }
        Ok(())
    }

    /// Parses a string literal at the cursor; returns its decoded text.
    fn string(&mut self) -> Result<String, JsoncError> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.i += 1;
        let mut out = String::new();
        let mut run = self.i;
        loop {
            let Some(c) = self.peek() else {
                return Err(JsoncError::Syntax);
            };
            match c {
                b'"' => {
                    out.push_str(&self.s[run..self.i]);
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.s[run..self.i]);
                    self.i += 1;
                    let e = self.peek().ok_or(JsoncError::Syntax)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                // A high surrogate must be followed by `\uXXXX` (low surrogate).
                                if self.peek() == Some(b'\\')
                                    && self.b.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return Err(JsoncError::Syntax);
                                    }
                                    let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    out.push(char::from_u32(cp).ok_or(JsoncError::Syntax)?);
                                } else {
                                    return Err(JsoncError::Syntax);
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(JsoncError::Syntax);
                            } else {
                                out.push(char::from_u32(hi).ok_or(JsoncError::Syntax)?);
                            }
                        }
                        _ => return Err(JsoncError::Syntax),
                    }
                    run = self.i;
                }
                0..=0x1f => return Err(JsoncError::Syntax),
                _ => self.i += 1,
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsoncError> {
        let chunk = self.s.get(self.i..self.i + 4).ok_or(JsoncError::Syntax)?;
        if !chunk.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(JsoncError::Syntax);
        }
        self.i += 4;
        u32::from_str_radix(chunk, 16).map_err(|_| JsoncError::Syntax)
    }

    fn number(&mut self) -> Result<(), JsoncError> {
        let digits = |p: &mut Self| -> usize {
            let st = p.i;
            while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                p.i += 1;
            }
            p.i - st
        };
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                digits(self);
            }
            _ => return Err(JsoncError::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if digits(self) == 0 {
                return Err(JsoncError::Syntax);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                return Err(JsoncError::Syntax);
            }
        }
        Ok(())
    }

    fn literal(&mut self, word: &str) -> Result<(), JsoncError> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(JsoncError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Val, JsoncError> {
        if depth > MAX_DEPTH {
            return Err(JsoncError::Syntax);
        }
        let start = self.i;
        let mut obj = None;
        match self.peek().ok_or(JsoncError::Syntax)? {
            b'{' => obj = Some(self.object(depth)?),
            b'[' => self.array(depth)?,
            b'"' => {
                self.string()?;
            }
            b'-' | b'0'..=b'9' => self.number()?,
            b't' => self.literal("true")?,
            b'f' => self.literal("false")?,
            b'n' => self.literal("null")?,
            _ => return Err(JsoncError::Syntax),
        }
        Ok(Val {
            start,
            end: self.i,
            obj,
        })
    }

    fn array(&mut self, depth: usize) -> Result<(), JsoncError> {
        self.i += 1; // [
        loop {
            self.skip_trivia()?;
            if self.peek() == Some(b']') {
                self.i += 1;
                return Ok(());
            }
            self.value(depth + 1)?;
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(JsoncError::Syntax),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Obj, JsoncError> {
        let open = self.i;
        self.i += 1; // {
        let mut members = Vec::new();
        loop {
            self.skip_trivia()?;
            match self.peek() {
                Some(b'}') => {
                    let close = self.i;
                    self.i += 1;
                    return Ok(Obj {
                        open,
                        close,
                        members,
                    });
                }
                Some(b'"') => {}
                _ => return Err(JsoncError::Syntax),
            }
            let key_start = self.i;
            let key = self.string()?;
            self.skip_trivia()?;
            if self.peek() != Some(b':') {
                return Err(JsoncError::Syntax);
            }
            self.i += 1;
            self.skip_trivia()?;
            let v = self.value(depth + 1)?;
            self.skip_trivia()?;
            let mut member = Member {
                key,
                key_start,
                val_start: v.start,
                val_end: v.end,
                comma: None,
                obj: v.obj,
            };
            match self.peek() {
                Some(b',') => {
                    member.comma = Some(self.i);
                    self.i += 1;
                    members.push(member);
                }
                Some(b'}') => {
                    members.push(member);
                }
                _ => return Err(JsoncError::Syntax),
            }
        }
    }
}

/// A parsed, validated document.
struct Doc<'a> {
    text: &'a str,
    root: Obj,
}

fn parse(text: &str) -> Result<Doc<'_>, JsoncError> {
    let mut p = Parser {
        b: text.as_bytes(),
        s: text,
        i: if text.starts_with('\u{feff}') { 3 } else { 0 },
    };
    p.skip_trivia()?;
    if p.peek().is_none() {
        return Err(JsoncError::NoRoot);
    }
    let v = p.value(0)?;
    p.skip_trivia()?;
    if p.peek().is_some() {
        return Err(JsoncError::Syntax);
    }
    let root = v.obj.ok_or(JsoncError::NotObject)?;
    Ok(Doc { text, root })
}

/// Result of walking a key path.
enum Located<'a> {
    /// An intermediate object on the path does not exist.
    ParentMissing,
    /// The key is absent from the (existing) parent object.
    Absent {
        parent: &'a Obj,
    },
    Found {
        parent: &'a Obj,
        idx: usize,
    },
}

fn find(obj: &Obj, key: &str) -> Result<Option<usize>, JsoncError> {
    let mut hits = obj.members.iter().enumerate().filter(|(_, m)| m.key == key);
    let first = hits.next().map(|(i, _)| i);
    if hits.next().is_some() {
        return Err(JsoncError::DuplicateKey);
    }
    Ok(first)
}

impl<'a> Doc<'a> {
    fn locate(&self, path: &[&str]) -> Result<Located<'_>, JsoncError> {
        let (last, inner) = path.split_last().ok_or(JsoncError::NotObject)?;
        let mut cur = &self.root;
        for k in inner {
            match find(cur, k)? {
                None => return Ok(Located::ParentMissing),
                Some(i) => cur = cur.members[i].obj.as_ref().ok_or(JsoncError::NotObject)?,
            }
        }
        Ok(match find(cur, last)? {
            Some(idx) => Located::Found { parent: cur, idx },
            None => Located::Absent { parent: cur },
        })
    }

    fn line_start(&self, pos: usize) -> usize {
        self.text[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0)
    }

    /// Leading blanks of the line that contains `pos`.
    fn line_indent(&self, pos: usize) -> &'a str {
        let ls = self.line_start(pos);
        let rest = &self.text[ls..];
        let n = rest
            .bytes()
            .take_while(|c| *c == b' ' || *c == b'\t')
            .count();
        &rest[..n]
    }

    fn eol(&self) -> &'static str {
        match self.text.find('\n') {
            Some(i) if i > 0 && self.text.as_bytes()[i - 1] == b'\r' => "\r\n",
            _ => "\n",
        }
    }

    /// Whether only blanks precede `pos` on its line.
    fn first_on_line(&self, pos: usize) -> bool {
        let ls = self.line_start(pos);
        self.text[ls..pos].bytes().all(|c| c == b' ' || c == b'\t')
    }

    /// End of the member's own tokens: after its comma if it has one.
    fn tail_end(m: &Member) -> usize {
        m.comma.map(|c| c + 1).unwrap_or(m.val_end)
    }

    /// The member sits on its own line(s): nothing but blanks before the key and nothing but
    /// blanks (or the end of the text) after its value and comma.
    fn alone_on_line(&self, m: &Member) -> bool {
        if !self.first_on_line(m.key_start) {
            return false;
        }
        let rest = &self.text.as_bytes()[Self::tail_end(m)..];
        for c in rest {
            match c {
                b' ' | b'\t' => {}
                b'\n' | b'\r' => return true,
                _ => return false,
            }
        }
        true
    }

    /// One level of indentation, learned from the first member that sits on its own line.
    fn indent_unit(&self) -> String {
        let base = self.line_indent(self.root.open);
        for m in &self.root.members {
            if self.first_on_line(m.key_start) {
                let ind = self.line_indent(m.key_start);
                if ind.len() > base.len() && ind.starts_with(base) {
                    return ind[base.len()..].to_string();
                }
            }
        }
        "  ".to_string()
    }

    /// Where a trailing same-line comment of the member ends (or `from` when there is none).
    fn end_of_trailing_comment(&self, from: usize) -> usize {
        let b = self.text.as_bytes();
        let mut i = from;
        let mut end = from;
        while i < b.len() {
            match b[i] {
                b' ' | b'\t' => i += 1,
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                        i += 1;
                    }
                    return i;
                }
                b'/' if b.get(i + 1) == Some(&b'*') => match self.text[i + 2..].find("*/") {
                    Some(e) => {
                        let close = i + 2 + e + 2;
                        if self.text[i..close].contains(['\n', '\r']) {
                            return end;
                        }
                        i = close;
                        end = close;
                    }
                    None => return end,
                },
                b'\n' | b'\r' => return i,
                _ => return end,
            }
        }
        i
    }

    fn insert_member(&self, parent: &Obj, key: &str, raw: &str) -> Vec<(usize, usize, String)> {
        let member = format!("{}: {}", quote(key), raw);
        let eol = self.eol();
        let base = self.line_indent(parent.open);
        let unit = self.indent_unit();
        let Some(last) = parent.members.last() else {
            let inner = &self.text[parent.open + 1..parent.close];
            if inner.trim().is_empty() {
                let mi = format!("{base}{unit}");
                return vec![(
                    parent.open + 1,
                    parent.close,
                    format!("{eol}{mi}{member}{eol}{base}"),
                )];
            }
            let mi = format!("{base}{unit}");
            return vec![(
                parent.open + 1,
                parent.open + 1,
                format!("{eol}{mi}{member}"),
            )];
        };
        let multiline = self.first_on_line(last.key_start);
        let indent = if multiline {
            self.line_indent(last.key_start).to_string()
        } else {
            String::new()
        };
        match last.comma {
            Some(cp) => {
                let text = if multiline {
                    format!("{eol}{indent}{member},")
                } else {
                    format!(" {member},")
                };
                vec![(cp + 1, cp + 1, text)]
            }
            None if multiline => {
                let p2 = self.end_of_trailing_comment(last.val_end);
                if p2 == last.val_end {
                    vec![(
                        last.val_end,
                        last.val_end,
                        format!(",{eol}{indent}{member}"),
                    )]
                } else {
                    vec![
                        (last.val_end, last.val_end, ",".to_string()),
                        (p2, p2, format!("{eol}{indent}{member}")),
                    ]
                }
            }
            None => vec![(last.val_end, last.val_end, format!(", {member}"))],
        }
    }

    fn remove_member(&self, parent: &Obj, idx: usize) -> Vec<(usize, usize, String)> {
        let m = &parent.members[idx];
        let alone = self.alone_on_line(m);
        let (rm_start, rm_end) = if alone {
            let ls = self.line_start(m.key_start);
            let mut e = Self::tail_end(m);
            let b = self.text.as_bytes();
            while e < b.len() && (b[e] == b' ' || b[e] == b'\t') {
                e += 1;
            }
            if e < b.len() && b[e] == b'\r' {
                e += 1;
            }
            if e < b.len() && b[e] == b'\n' {
                e += 1;
            }
            (ls, e)
        } else if m.comma.is_some() {
            // Inline: the member, its comma and the blanks after it.
            let b = self.text.as_bytes();
            let mut e = Self::tail_end(m);
            while e < b.len() && (b[e] == b' ' || b[e] == b'\t') {
                e += 1;
            }
            (m.key_start, e)
        } else if idx > 0 && parent.members[idx - 1].comma.is_some() {
            // Inline, last member without a comma: take the previous comma with it.
            (
                parent.members[idx - 1].comma.unwrap_or(m.key_start),
                m.val_end,
            )
        } else {
            (m.key_start, m.val_end)
        };
        // The only member and nothing else inside the braces: collapse to `{}`.
        if parent.members.len() == 1 {
            let left = &self.text[parent.open + 1..rm_start];
            let right = &self.text[rm_end..parent.close];
            if left.trim().is_empty() && right.trim().is_empty() {
                return vec![(parent.open + 1, parent.close, String::new())];
            }
        }
        let mut edits = vec![(rm_start, rm_end, String::new())];
        // The member was the last one and has no comma of its own: the comma of the previous
        // member would become a stray separator (the inverse of the insertion).
        if alone
            && m.comma.is_none()
            && idx > 0
            && let Some(pc) = parent.members[idx - 1].comma
        {
            edits.push((pc, pc + 1, String::new()));
        }
        edits
    }
}

fn quote(key: &str) -> String {
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
mod tests {
    use super::*;

    fn raw<'a>(t: &'a str, p: &[&str]) -> Option<&'a str> {
        get(t, p).unwrap().map(|f| f.raw)
    }

    #[test]
    fn finds_top_level_and_nested_values() {
        let t = "{\n  \"a\": 1,\n  \"terminal.integrated.env.osx\": {\n    \"HTTP_PROXY\": \"x\"\n  }\n}\n";
        assert_eq!(raw(t, &["a"]), Some("1"));
        assert_eq!(
            raw(t, &["terminal.integrated.env.osx", "HTTP_PROXY"]),
            Some("\"x\"")
        );
        assert_eq!(raw(t, &["terminal.integrated.env.osx", "NOPE"]), None);
        assert_eq!(raw(t, &["missing", "x"]), None);
        assert!(
            get(t, &["terminal.integrated.env.osx"])
                .unwrap()
                .unwrap()
                .is_object
        );
    }

    #[test]
    fn replace_touches_only_the_value_bytes() {
        let t =
            "{\n  // keep me\n  \"http.proxy\": \"http://old\", /* tail */\n  \"b\": [1, 2]\n}\n";
        let out = set(t, &["http.proxy"], "\"http://new\"").unwrap();
        assert_eq!(
            out,
            "{\n  // keep me\n  \"http.proxy\": \"http://new\", /* tail */\n  \"b\": [1, 2]\n}\n"
        );
    }

    #[test]
    fn insert_into_empty_object_and_remove_is_exact() {
        let t = "{}\n";
        let out = set(t, &["a"], "1").unwrap();
        assert_eq!(out, "{\n  \"a\": 1\n}\n");
        assert_eq!(remove(&out, &["a"]).unwrap(), t);
    }

    #[test]
    fn insert_after_last_member_and_remove_round_trips() {
        let t = "{\n  \"x\": 1,\n  \"y\": \"two\"\n}\n";
        let out = set(t, &["k"], "true").unwrap();
        assert_eq!(out, "{\n  \"x\": 1,\n  \"y\": \"two\",\n  \"k\": true\n}\n");
        assert_eq!(remove(&out, &["k"]).unwrap(), t);
    }

    #[test]
    fn trailing_comma_style_is_kept_and_round_trips() {
        let t = "{\n  \"x\": 1,\n  \"y\": 2,\n}\n";
        let out = set(t, &["k"], "3").unwrap();
        assert_eq!(out, "{\n  \"x\": 1,\n  \"y\": 2,\n  \"k\": 3,\n}\n");
        assert_eq!(remove(&out, &["k"]).unwrap(), t);
        validate(&out).unwrap();
    }

    #[test]
    fn crlf_and_tabs_are_used_for_new_lines_and_nothing_else_changes() {
        let t = "{\r\n\t\"x\": 1\r\n}\r\n";
        let out = set(t, &["k"], "\"v\"").unwrap();
        assert_eq!(out, "{\r\n\t\"x\": 1,\r\n\t\"k\": \"v\"\r\n}\r\n");
        assert_eq!(remove(&out, &["k"]).unwrap(), t);
    }

    #[test]
    fn bom_is_preserved_in_every_edit() {
        let t = "\u{feff}{\n  \"x\": 1\n}\n";
        let out = set(t, &["k"], "2").unwrap();
        assert!(out.starts_with('\u{feff}'));
        assert_eq!(remove(&out, &["k"]).unwrap(), t);
        let blank = set("\u{feff}", &["k"], "2").unwrap();
        assert!(blank.starts_with("\u{feff}{"));
        validate(&blank).unwrap();
    }

    #[test]
    fn comments_of_both_kinds_survive_and_a_trailing_comment_stays_in_place() {
        let t = "{\n  // top\n  \"x\": 1 // about x\n  /* block */\n}\n";
        let out = set(t, &["k"], "2").unwrap();
        assert!(
            out.contains("// top") && out.contains("// about x") && out.contains("/* block */")
        );
        validate(&out).unwrap();
        assert_eq!(raw(&out, &["x"]), Some("1"));
        assert_eq!(raw(&out, &["k"]), Some("2"));
        assert_eq!(remove(&out, &["k"]).unwrap(), t);
    }

    #[test]
    fn unicode_in_strings_and_urls_is_untouched() {
        let t =
            "{\n  \"路径\": \"http://пример.рф/a?b=ü\",\n  \"e\": \"\\u00e9\\ud83d\\ude00\"\n}\n";
        let out = set(t, &["k"], "1").unwrap();
        assert!(out.contains("http://пример.рф/a?b=ü") && out.contains("\\ud83d\\ude00"));
        assert_eq!(raw(&out, &["路径"]), Some("\"http://пример.рф/a?b=ü\""));
        assert_eq!(remove(&out, &["k"]).unwrap(), t);
        // A key written with escapes is the same key.
        assert_eq!(raw("{\"\\u0061b\": 1}", &["ab"]), Some("1"));
    }

    #[test]
    fn inline_objects_round_trip() {
        let t = "{\"a\": 1, \"b\": 2}";
        let out = set(t, &["k"], "3").unwrap();
        assert_eq!(out, "{\"a\": 1, \"b\": 2, \"k\": 3}");
        assert_eq!(remove(&out, &["k"]).unwrap(), t);
        assert_eq!(remove(t, &["a"]).unwrap(), "{\"b\": 2}");
    }

    #[test]
    fn removing_the_first_and_middle_members_keeps_the_commas_valid() {
        let t = "{\n  \"a\": 1,\n  \"b\": 2,\n  \"c\": 3\n}\n";
        let no_a = remove(t, &["a"]).unwrap();
        assert_eq!(no_a, "{\n  \"b\": 2,\n  \"c\": 3\n}\n");
        let no_b = remove(t, &["b"]).unwrap();
        assert_eq!(no_b, "{\n  \"a\": 1,\n  \"c\": 3\n}\n");
        let no_c = remove(t, &["c"]).unwrap();
        assert_eq!(no_c, "{\n  \"a\": 1,\n  \"b\": 2\n}\n");
        for s in [no_a, no_b, no_c] {
            validate(&s).unwrap();
        }
    }

    #[test]
    fn nested_insert_and_remove_use_the_indent_of_the_container() {
        let t = "{\n  \"a\": 1,\n  \"env\": {\n    \"X\": \"1\"\n  }\n}\n";
        let out = set(t, &["env", "Y"], "\"2\"").unwrap();
        assert_eq!(
            out,
            "{\n  \"a\": 1,\n  \"env\": {\n    \"X\": \"1\",\n    \"Y\": \"2\"\n  }\n}\n"
        );
        assert_eq!(remove(&out, &["env", "Y"]).unwrap(), t);
    }

    #[test]
    fn a_created_container_is_filled_and_removed_back_to_the_original_bytes() {
        let t = "{\n  \"a\": 1\n}\n";
        let with_env = set(t, &["env"], "{}").unwrap();
        validate(&with_env).unwrap();
        let filled = set(&with_env, &["env", "K"], "\"v\"").unwrap();
        validate(&filled).unwrap();
        assert_eq!(raw(&filled, &["env", "K"]), Some("\"v\""));
        let emptied = remove(&filled, &["env", "K"]).unwrap();
        assert!(get(&emptied, &["env"]).unwrap().unwrap().is_empty_object);
        assert_eq!(remove(&emptied, &["env"]).unwrap(), t);
    }

    #[test]
    fn a_comment_inside_an_empty_object_is_not_an_empty_object() {
        let t = "{\n  \"env\": {\n    // note\n  }\n}\n";
        let f = get(t, &["env"]).unwrap().unwrap();
        assert!(f.is_object && !f.is_empty_object);
        let t2 = "{\n  \"env\": { /* x */ }\n}\n";
        assert!(!get(t2, &["env"]).unwrap().unwrap().is_empty_object);
        // Inserting into it keeps the comment.
        let out = set(t, &["env", "K"], "1").unwrap();
        assert!(out.contains("// note"));
        validate(&out).unwrap();
        // Removing the only member does not swallow the comment either.
        assert_eq!(remove(&out, &["env", "K"]).unwrap(), t);
    }

    #[test]
    fn refuses_damaged_documents() {
        for bad in [
            "{\"a\": 1",
            "{\"a\" 1}",
            "{\"a\": 1,, \"b\": 2}",
            "{\"a\": 1} trailing",
            "{\"a\": \"unterminated}",
            "{\"a\": /* open }",
            "{\"a\": 01}",
            "{a: 1}",
            "{\"a\": tru}",
            "{\"a\": \"\\x\"}",
            "{\"a\": 1}}",
        ] {
            assert_eq!(validate(bad), Err(JsoncError::Syntax), "{bad}");
            assert!(set(bad, &["k"], "1").is_err(), "{bad}");
            assert!(remove(bad, &["a"]).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_a_root_that_is_not_an_object() {
        for t in ["[1, 2]", "\"s\"", "42", "null", "true"] {
            assert_eq!(validate(t), Err(JsoncError::NotObject), "{t}");
        }
        assert_eq!(validate(""), Err(JsoncError::NoRoot));
        assert_eq!(validate("// only a comment\n"), Err(JsoncError::NoRoot));
        assert!(set("// only a comment\n", &["k"], "1").is_err());
    }

    #[test]
    fn refuses_duplicate_keys_in_the_object_being_edited() {
        let t = "{\n  \"http.proxy\": \"a\",\n  \"x\": 1,\n  \"http.proxy\": \"b\"\n}\n";
        assert_eq!(get(t, &["http.proxy"]), Err(JsoncError::DuplicateKey));
        assert_eq!(
            set(t, &["http.proxy"], "\"c\""),
            Err(JsoncError::DuplicateKey)
        );
        assert_eq!(remove(t, &["http.proxy"]), Err(JsoncError::DuplicateKey));
        // A repeated key that is not the one being edited is not in the way.
        let u = "{\n  \"x\": 1,\n  \"x\": 2\n}\n";
        assert_eq!(raw(u, &["other"]), None);
        assert!(set(u, &["other"], "1").is_ok());
        // Same inside a nested object.
        let n = "{\"env\": {\"A\": 1, \"A\": 2}}";
        assert_eq!(get(n, &["env", "A"]), Err(JsoncError::DuplicateKey));
    }

    #[test]
    fn an_intermediate_value_that_is_not_an_object_is_refused() {
        let t = "{\"env\": \"text\"}";
        assert_eq!(get(t, &["env", "K"]), Err(JsoncError::NotObject));
        assert_eq!(set(t, &["env", "K"], "1"), Err(JsoncError::NotObject));
        let t2 = "{\"a\": 1}";
        assert_eq!(set(t2, &["env", "K"], "1"), Err(JsoncError::MissingParent));
        assert_eq!(remove(t2, &["env", "K"]).unwrap(), t2);
    }

    #[test]
    fn a_missing_key_is_a_no_op_for_remove() {
        let t = "{\n  // c\n  \"a\": 1\n}\n";
        assert_eq!(remove(t, &["nope"]).unwrap(), t);
    }

    #[test]
    fn deeply_nested_input_is_refused_not_a_stack_overflow() {
        let deep = format!("{}1{}", "[".repeat(1000), "]".repeat(1000));
        assert_eq!(
            validate(&format!("{{\"a\": {deep}}}")),
            Err(JsoncError::Syntax)
        );
    }

    #[test]
    fn keys_with_special_characters_are_quoted() {
        let out = set("{}", &["we\"ird\\key"], "1").unwrap();
        validate(&out).unwrap();
        assert_eq!(raw(&out, &["we\"ird\\key"]), Some("1"));
    }
}
