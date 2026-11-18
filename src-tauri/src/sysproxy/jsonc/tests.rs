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
fn a_comment_after_the_last_comma_stays_with_its_member_and_the_bytes_come_back() {
    // Each fixture: the last member has a trailing comma followed by a comment.
    let fixtures = [
        "{\n  \"a\": 1, // note\n}\n",
        "{\n  \"a\": 1, /* note */\n}\n",
        "{\n  \"a\": 1,   // note\n}\n",
        "{\n  \"a\": 1, /* two\n  lines */\n}\n",
        "{\r\n  \"a\": 1, // note\r\n}\r\n",
        "{\n  \"b\": 0,\n  \"a\": 1, // note\n  // after\n}",
        "\u{feff}{\n\t\"a\": 1, // note\n}\n",
    ];
    for t in fixtures {
        let out = set(t, &["k"], "true").unwrap();
        validate(&out).unwrap();
        assert_eq!(raw(&out, &["k"]), Some("true"), "{t:?}");
        // The comment is still on the line of "a".
        let a_line = out.lines().find(|l| l.contains("\"a\"")).unwrap();
        assert!(
            a_line.contains("note") || a_line.contains("/* two"),
            "{out:?}"
        );
        assert_eq!(remove(&out, &["k"]).unwrap(), t, "{t:?}");
    }
    // Nested object.
    let t = "{\n  \"env\": {\n    \"X\": \"1\", // why\n  }\n}\n";
    let out = set(t, &["env", "Y"], "\"2\"").unwrap();
    validate(&out).unwrap();
    assert_eq!(remove(&out, &["env", "Y"]).unwrap(), t);
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
