use super::JsoncError;
use super::parser::{Member, Obj, Parser};
use super::quote;

/// A parsed, validated document.
pub(super) struct Doc<'a> {
    text: &'a str,
    root: Obj,
}

pub(super) fn parse(text: &str) -> Result<Doc<'_>, JsoncError> {
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
pub(super) enum Located<'a> {
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
    pub(super) fn locate(&self, path: &[&str]) -> Result<Located<'_>, JsoncError> {
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

    /// End of the comment that trails the comma at `from` on the same line, `from` when there is
    /// none. Unlike `end_of_trailing_comment` it also takes a block comment that spans lines as
    /// long as the line ends right after it.
    fn end_of_comment_after_comma(&self, from: usize) -> usize {
        let end = self.end_of_trailing_comment(from);
        if end != from {
            return end;
        }
        let rest = &self.text[from..];
        let blanks = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let Some(body) = rest[blanks..].strip_prefix("/*") else {
            return from;
        };
        let Some(e) = body.find("*/") else {
            return from;
        };
        let close = from + blanks + 2 + e + 2;
        let tail = &self.text[close..];
        let line_rest = tail.split(['\n', '\r']).next().unwrap_or("");
        if line_rest.trim_matches([' ', '\t']).is_empty() {
            close
        } else {
            from
        }
    }

    pub(super) fn insert_member(&self, parent: &Obj, key: &str, raw: &str) -> Vec<(usize, usize, String)> {
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
            Some(cp) if multiline => {
                // A comment after the last member's comma belongs to that member: our line goes
                // after it, so removing our line gives the original bytes back.
                let at = self.end_of_comment_after_comma(cp + 1);
                vec![(at, at, format!("{eol}{indent}{member},"))]
            }
            Some(cp) => vec![(cp + 1, cp + 1, format!(" {member},"))],
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

    pub(super) fn remove_member(&self, parent: &Obj, idx: usize) -> Vec<(usize, usize, String)> {
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

