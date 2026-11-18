use super::JsoncError;

pub(super) const MAX_DEPTH: usize = 64;

#[derive(Debug)]
pub(super) struct Member {
    pub(super) key: String,
    pub(super) key_start: usize,
    pub(super) val_start: usize,
    pub(super) val_end: usize,
    /// Position of the comma that follows this member, if any.
    pub(super) comma: Option<usize>,
    pub(super) obj: Option<Obj>,
}

#[derive(Debug)]
pub(super) struct Obj {
    pub(super) open: usize,
    pub(super) close: usize,
    pub(super) members: Vec<Member>,
}

pub(super) struct Parser<'a> {
    pub(super) b: &'a [u8],
    pub(super) s: &'a str,
    pub(super) i: usize,
}

pub(super) struct Val {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) obj: Option<Obj>,
}

impl<'a> Parser<'a> {
    pub(super) fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    pub(super) fn skip_trivia(&mut self) -> Result<(), JsoncError> {
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

    pub(super) fn value(&mut self, depth: usize) -> Result<Val, JsoncError> {
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
