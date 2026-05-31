//! Clipboard content classifier.
//!
//! Two surfaces:
//!
//! 1. [`kind_of`] — picks one of [`Kind::Text`] / [`Kind::Url`] /
//!    [`Kind::Code`] for a freshly-copied string. The UI uses this to
//!    render the right glyph in the history list.
//! 2. [`is_sensitive`] — flags strings that look like secrets so the
//!    daemon can mark `ClipboardItem.sensitive = true` and skip persisting
//!    them in the 50-item ring buffer.
//!
//! The exact rules — copied here so the README can quote them:
//!
//! ```text
//! url    : matches /^https?:\/\//   (strict — `www.x.y` is text)
//! code   : multi-line AND contains a code-like token from a small list
//!          ({}, ;, =>, fn , def , function , import , class , const ,
//!          public , #include, package , module )
//! text   : default
//!
//! sensitive — any of:
//!   - JWT      :  eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
//!   - Stripe   :  sk_(?:test|live)_[A-Za-z0-9]{24,}
//!   - Generic  :  sk-[A-Za-z0-9]{20,}        (covers OpenAI-style keys)
//!   - GitHub   :  ghp_[A-Za-z0-9]{36}
//!   - AWS      :  AKIA[0-9A-Z]{16}
//!   - Hex 64   :  \b[A-Fa-f0-9]{64}\b        (SHA-256 / private-key shape)
//! ```

use fluxsync_proto::Kind;
use regex::Regex;
use std::sync::OnceLock;

const CODE_TOKENS: &[&str] = &[
    "{",
    "}",
    ";",
    "=>",
    "fn ",
    "def ",
    "function ",
    "function(",
    "import ",
    "class ",
    "const ",
    "public ",
    "#include",
    "package ",
    "module ",
];

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^https?://").expect("url regex literal must compile"))
}

fn jwt_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
            .expect("jwt regex literal must compile")
    })
}

fn stripe_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"sk_(?:test|live)_[A-Za-z0-9]{24,}").expect("stripe regex literal must compile")
    })
}

fn generic_sk_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // L-CORE-03: allow `_`/`-` in the body so modern prefixed keys like
    // `sk-proj-…` and `sk-ant-…` match — the old `[A-Za-z0-9]{20,}` stopped at
    // the first hyphen (`proj` = 4 chars < 20) and let them through.
    R.get_or_init(|| {
        Regex::new(r"sk-[A-Za-z0-9_-]{20,}").expect("generic-sk regex literal must compile")
    })
}

fn github_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // L-CORE-03: classic `ghp_` PATs plus fine-grained `github_pat_…` tokens.
    R.get_or_init(|| {
        Regex::new(r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}")
            .expect("github regex literal must compile")
    })
}

fn aws_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("aws regex literal must compile"))
}

fn hex64_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[A-Fa-f0-9]{64}\b").expect("hex64 regex literal must compile"))
}

/// Classify a clipboard string into one of the three UI categories.
#[must_use]
pub fn kind_of(text: &str) -> Kind {
    if url_re().is_match(text) {
        return Kind::Url;
    }
    if text.contains('\n') && CODE_TOKENS.iter().any(|t| text.contains(t)) {
        return Kind::Code;
    }
    Kind::Text
}

/// Heuristic: does this string look like something we should never persist?
#[must_use]
pub fn is_sensitive(text: &str) -> bool {
    jwt_re().is_match(text)
        || stripe_re().is_match(text)
        || generic_sk_re().is_match(text)
        || github_re().is_match(text)
        || aws_re().is_match(text)
        || hex64_re().is_match(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── kind_of ────────────────────────────────────────────────────────────
    #[test]
    fn url_classified_for_http_and_https() {
        assert_eq!(kind_of("http://example.com"), Kind::Url);
        assert_eq!(kind_of("https://github.com/foo/bar"), Kind::Url);
    }

    #[test]
    fn url_strict_rejects_no_scheme_and_ftp() {
        assert_eq!(kind_of("www.example.com"), Kind::Text);
        assert_eq!(kind_of("ftp://example.com"), Kind::Text);
        assert_eq!(kind_of("github.com/torvalds/linux"), Kind::Text);
    }

    #[test]
    fn code_needs_newline_and_token() {
        assert_eq!(kind_of("fn main() {\n    println!(\"hi\");\n}"), Kind::Code);
        assert_eq!(kind_of("def foo():\n    return 1"), Kind::Code);
        assert_eq!(kind_of("import os\nimport sys\n"), Kind::Code);
    }

    #[test]
    fn single_line_with_braces_is_text_not_code() {
        // "{}" alone on one line is more likely a text snippet than code.
        assert_eq!(kind_of("foo { bar }"), Kind::Text);
    }

    #[test]
    fn multi_line_without_code_token_is_text() {
        assert_eq!(kind_of("Bonjour\nKaolack\nMerci"), Kind::Text);
    }

    #[test]
    fn defaults_to_text() {
        assert_eq!(kind_of(""), Kind::Text);
        assert_eq!(kind_of("Merci frère"), Kind::Text);
    }

    // ── is_sensitive ───────────────────────────────────────────────────────
    #[test]
    fn detects_jwt() {
        let jwt =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(is_sensitive(jwt));
    }

    #[test]
    fn detects_stripe_test_and_live() {
        assert!(is_sensitive("sk_test_4eC39HqLyjWDarjtT1zdp7dc"));
        assert!(is_sensitive("sk_live_aBcDeFgHiJkLmNoPqRsTuVwX"));
    }

    #[test]
    fn detects_generic_sk_dash_keys() {
        // OpenAI-style: sk-AbCdEfGh... long
        assert!(is_sensitive("sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"));
    }

    #[test]
    fn detects_modern_prefixed_sk_keys() {
        // L-CORE-03: hyphen-bodied keys the old regex missed.
        assert!(is_sensitive(
            "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf"
        ));
        assert!(is_sensitive("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz01234"));
    }

    #[test]
    fn detects_github_personal_access_token() {
        assert!(is_sensitive("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"));
    }

    #[test]
    fn detects_github_fine_grained_token() {
        // L-CORE-03: `github_pat_…` fine-grained tokens.
        assert!(is_sensitive(
            "github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789"
        ));
    }

    #[test]
    fn detects_aws_access_key_id() {
        assert!(is_sensitive("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_hex64() {
        assert!(is_sensitive(
            "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn ignores_non_secret_text() {
        assert!(!is_sensitive("Hello, world"));
        assert!(!is_sensitive("https://github.com"));
        assert!(!is_sensitive("sk-too-short"));
        assert!(!is_sensitive("akia_lowercase_not_aws"));
        // 63-char hex (one short of 64): not flagged
        assert!(!is_sensitive(
            "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcde"
        ));
    }

    #[test]
    fn detects_secret_inside_larger_payload() {
        let payload =
            "Hi team,\nhere is the AWS key for the staging account: AKIAIOSFODNN7EXAMPLE\nplease rotate.";
        assert!(is_sensitive(payload));
    }
}
