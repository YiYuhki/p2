//! The DLP text scanner: runs detectors over text, aggregates findings into a
//! report, escalates identity-revealing datasets, and tests a candidate rule.
//! Port of the Go `internal/dlp/scan.go` (text-scanning core; the MIME/OCR
//! extraction side lands with the mimeproc port).

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::Serialize;

use super::detectors::{
    builtin, mask_middle, Detector, Severity, CATEGORY_PII, CONTEXT_WINDOW, SEP_CONTEXT_CHARS,
};

/// Byte ranges of a text.
type Ranges = Vec<(usize, usize)>;

/// A separator-normalized view of a text: (view, lowercased, number tokens).
type View = (String, String, Ranges);

/// A user-defined detector from configuration.
#[derive(Clone, Debug, Default)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
    pub min_count: usize,
    pub context: Vec<String>,
}

/// Scanner options.
#[derive(Default)]
pub struct Options {
    pub disabled: Vec<String>,
    pub min_counts: HashMap<String, usize>,
    pub rules: Vec<Rule>,
    pub combine_pii: bool,
    pub combine_min_pii: usize,
    pub combine_bulk: usize,
}

pub struct Scanner {
    detectors: Vec<Detector>,
    opts: Options,
}

/// One detector's aggregated matches in one location.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub detector: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub location: String,
    pub count: usize,
    pub samples: Vec<String>,
    #[serde(skip)]
    sev: Severity,
}

impl Finding {
    pub fn sev(&self) -> Severity {
        if self.sev != Severity::None {
            self.sev
        } else {
            Severity::parse(&self.severity).unwrap_or(Severity::None)
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uninspectable: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub encrypted: Vec<String>,
}

impl Report {
    pub fn has_encrypted(&self) -> bool {
        !self.encrypted.is_empty()
    }

    pub fn max_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.sev())
            .max()
            .unwrap_or(Severity::None)
    }

    /// Short one-line description, e.g. "주민등록번호 3건, AWS Access Key 1건".
    pub fn summary(&self) -> String {
        let mut tot: HashMap<&str, usize> = HashMap::new();
        let mut names: Vec<&str> = Vec::new();
        for f in &self.findings {
            if !tot.contains_key(f.name.as_str()) {
                names.push(&f.name);
            }
            *tot.entry(&f.name).or_insert(0) += f.count;
        }
        names
            .iter()
            .map(|n| format!("{} {}건", n, tot[n]))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Scanner {
    pub fn new(opts: Options) -> Result<Self, String> {
        let off: HashSet<&str> = opts.disabled.iter().map(|s| s.as_str()).collect();
        let mut ds: Vec<Detector> = Vec::new();
        for mut d in builtin() {
            if off.contains(d.id.as_str()) {
                continue;
            }
            if let Some(&n) = opts.min_counts.get(&d.id) {
                d.min_count = n;
            }
            ds.push(d);
        }
        for r in &opts.rules {
            let re = Regex::new(&r.pattern).map_err(|e| format!("dlp rule {:?}: {e}", r.id))?;
            if re.captures_len() > 2 {
                return Err(format!(
                    "dlp rule {:?}: at most one capture group allowed",
                    r.id
                ));
            }
            let sev = Severity::parse(&r.severity).ok_or_else(|| {
                format!("dlp rule {:?}: severity must be low, medium or high", r.id)
            })?;
            let cat = if r.category.is_empty() {
                CATEGORY_PII.to_string()
            } else {
                r.category.clone()
            };
            let name = if r.name.is_empty() {
                r.id.clone()
            } else {
                r.name.clone()
            };
            ds.push(Detector {
                id: r.id.clone(),
                name,
                category: cat,
                severity: sev,
                re,
                validate: None,
                context: r.context.iter().map(|c| c.to_lowercase()).collect(),
                min_count: r.min_count,
                mask: mask_middle(2, 2),
                needs_context: None,
                digits: false,
                hints: vec![],
                hints_fold: vec![],
                back: 0,
                ahead: 0,
                sep_context: vec![],
            });
        }
        Ok(Scanner {
            detectors: ds,
            opts,
        })
    }

    /// Runs every detector over one piece of text. Number detectors with a
    /// checksum or fixed shape (RRN, card, business/corporate registration,
    /// mobile, driver licence) also run over two separator-normalized views
    /// of the text — separators [-./] with surrounding whitespace (and one
    /// line break) between digit groups become '-', and in the second view
    /// short whitespace-only separators are dropped — so "900101 - 1234567",
    /// "900101.1234567" and "9 0 0 1 0 1 - 1 2 3 4 5 6 7" all match.
    /// Matches are de-duplicated by their digits.
    pub fn scan_text(&self, loc: &str, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let lower = ascii_lower(text);
        let mut num_tokens: Option<Vec<(usize, usize)>> = None;
        // (view, lowercased view, number tokens) for tolerant detectors;
        // `strict_views` only turn a literal dash into '-' (for detectors
        // with `sep_context`).
        let mut views: Option<Vec<View>> = None;
        let mut strict_views: Option<Vec<View>> = None;

        for d in &self.detectors {
            let tolerant = d.digits && is_separator_tolerant(&d.id);
            let windows: Vec<(usize, usize)> = if d.digits {
                num_tokens
                    .get_or_insert_with(|| number_tokens(text))
                    .clone()
            } else if !d.hints.is_empty() || !d.hints_fold.is_empty() {
                let (mut back, mut ahead) = (d.back, d.ahead);
                if ahead == 0 {
                    ahead = 512;
                    if back == 0 {
                        back = 32;
                    }
                }
                hint_windows(text, &lower, &d.hints, &d.hints_fold, back, ahead)
            } else {
                vec![(0, text.len())]
            };
            let strict = !d.sep_context.is_empty();
            let mut sources: Vec<(&str, &str, Ranges)> = vec![(text, &lower, windows)];
            if tolerant {
                let slot = if strict {
                    &mut strict_views
                } else {
                    &mut views
                };
                let vs = slot.get_or_insert_with(|| {
                    [false, true]
                        .iter()
                        .map(|&drop_ws| collapse_numbers(text, drop_ws, strict))
                        .filter(|v| v != text)
                        .map(|v| {
                            let l = ascii_lower(&v);
                            let t = number_tokens(&v);
                            (v, l, t)
                        })
                        .collect()
                });
                for (v, l, t) in vs.iter() {
                    sources.push((v, l, t.clone()));
                }
            }
            let mut seen: HashSet<String> = HashSet::new();
            let mut samples: Vec<String> = Vec::new();
            for (si, (src, src_lower, windows)) in sources.into_iter().enumerate() {
                for (ws, we) in windows {
                    let seg = &src[ws..we];
                    for caps in d.re.captures_iter(seg) {
                        let m = match caps.get(1) {
                            Some(g) => g,
                            None => caps.get(0).unwrap(),
                        };
                        let v = m.as_str();
                        let abs_start = m.start() + ws;
                        let abs_end = m.end() + ws;
                        let key = if tolerant {
                            super::detectors::digits(v)
                        } else {
                            v.to_string()
                        };
                        if seen.contains(&key) {
                            continue;
                        }
                        if let Some(validate) = d.validate {
                            if !validate(v) {
                                continue;
                            }
                        }
                        // Not in its canonical dashed form: a non-dash
                        // separator, or only seen once separators were
                        // collapsed — require a keyword close by.
                        if strict
                            && !v.contains('-')
                            && (si > 0 || v.bytes().any(|c| !c.is_ascii_digit()))
                            && !has_context_chars(
                                src_lower,
                                abs_start,
                                abs_end,
                                &d.sep_context,
                                SEP_CONTEXT_CHARS,
                            )
                        {
                            continue;
                        }
                        if !d.context.is_empty()
                            && d.needs_context.map(|f| f(v)).unwrap_or(true)
                            && !has_context(src_lower, abs_start, abs_end, &d.context)
                        {
                            continue;
                        }
                        seen.insert(key);
                        if samples.len() < 3 {
                            samples.push((d.mask)(v));
                        }
                    }
                }
            }
            let n = seen.len();
            if n >= d.min_count.max(1) {
                out.push(Finding {
                    detector: d.id.clone(),
                    name: d.name.clone(),
                    category: d.category.clone(),
                    severity: d.severity.as_str().to_string(),
                    location: loc.to_string(),
                    count: n,
                    samples,
                    sev: d.severity,
                });
            }
        }
        out
    }
    /// Adds a synthetic high-severity "pii_combination" finding for each location
    /// that holds several distinct personal-data types, or a bulk list of one.
    pub fn escalate(&self, rep: &mut Report) {
        if !self.opts.combine_pii {
            return;
        }
        let min_pii = if self.opts.combine_min_pii == 0 {
            2
        } else {
            self.opts.combine_min_pii
        };
        let bulk = if self.opts.combine_bulk == 0 {
            20
        } else {
            self.opts.combine_bulk
        };

        struct Agg {
            types: HashSet<String>,
            max: usize,
        }
        let mut by_loc: HashMap<String, Agg> = HashMap::new();
        let mut order: Vec<String> = Vec::new();
        for f in &rep.findings {
            if !is_identity_detector(&f.detector) {
                continue;
            }
            let a = by_loc.entry(f.location.clone()).or_insert_with(|| {
                order.push(f.location.clone());
                Agg {
                    types: HashSet::new(),
                    max: 0,
                }
            });
            a.types.insert(f.detector.clone());
            if f.count > a.max {
                a.max = f.count;
            }
        }
        for loc in order {
            let a = &by_loc[&loc];
            let reason = if a.types.len() >= min_pii {
                format!("서로 다른 개인정보 {}종이 함께 있음", a.types.len())
            } else if a.max >= bulk {
                format!("동일 개인정보 {}건 이상 대량", a.max)
            } else {
                continue;
            };
            rep.findings.push(Finding {
                detector: "pii_combination".into(),
                name: "개인정보 결합·대량(신원 식별 가능)".into(),
                category: CATEGORY_PII.into(),
                severity: Severity::High.as_str().into(),
                location: loc,
                count: a.types.len(),
                samples: vec![reason],
                sev: Severity::High,
            });
        }
    }

    /// Scans a flat piece of text and returns a sorted report (helper used until
    /// the MIME scanner lands).
    pub fn scan_text_report(&self, loc: &str, text: &str) -> Report {
        let mut rep = Report {
            findings: self.scan_text(loc, text),
            ..Default::default()
        };
        self.escalate(&mut rep);
        rep.findings.sort_by_key(|f| std::cmp::Reverse(f.sev()));
        rep
    }

    /// Parses a raw message and scans its subject, every text-like leaf (incl.
    /// embedded messages) and text attachments. Port of the Go ScanMessage text
    /// path (OCR/archive extraction is the analysis project's territory).
    /// Structure comes from [`crate::mimetree`], the parser the gateway relays
    /// with, so DLP sees exactly the parts recipients see. HTML is reduced to
    /// its text (tags stripped, entities decoded) and invisible format
    /// characters are removed before matching. Non-text attachments are noted
    /// as uninspectable, opaque encrypted parts as encrypted.
    pub fn scan_message(&self, raw: &[u8]) -> Report {
        let mut rep = Report::default();
        let parsed = match crate::mimeproc::parse(raw) {
            Ok(p) => p,
            Err(_) => {
                rep.uninspectable
                    .push("메일 구조 해석 실패: 원문 전체를 텍스트로 검사".into());
                let text = normalize_text(&String::from_utf8_lossy(raw), false);
                rep.findings = self.scan_text("메일 원문", &text);
                self.escalate(&mut rep);
                rep.findings.sort_by_key(|f| std::cmp::Reverse(f.sev()));
                return rep;
            }
        };
        if !parsed.subject.is_empty() {
            rep.findings
                .extend(self.scan_text("제목", &normalize_text(&parsed.subject, false)));
        }
        for tp in &parsed.text_parts {
            rep.findings
                .extend(self.scan_text(&tp.location, &normalize_text(&tp.text, tp.html)));
        }
        for att in &parsed.attachments {
            let loc = format!("첨부 {}", att.filename);
            let lname = att.filename.to_ascii_lowercase();
            let ext = lname.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
            let rtf = att.content_type.ends_with("/rtf") || ext == "rtf";
            let text_like =
                crate::mimeproc::is_text_like(&att.content_type) || TEXT_EXTS.contains(&ext) || rtf;
            let data: std::borrow::Cow<[u8]> = if rtf {
                std::borrow::Cow::Owned(rtf_unescape(&att.data))
            } else {
                std::borrow::Cow::Borrowed(&att.data)
            };
            let text = match crate::mimeproc::decode_text(&data, att.charset.as_deref()) {
                crate::mimeproc::Decoded::Text(t) => Some(t),
                other if text_like => Some(other.into_string()),
                _ => None,
            };
            match text {
                Some(text) => {
                    let html = att.content_type == "text/html" || ext == "html" || ext == "htm";
                    rep.findings
                        .extend(self.scan_text(&loc, &normalize_text(&text, html)))
                }
                None => rep
                    .uninspectable
                    .push(format!("{loc}: 텍스트로 해석할 수 없는 첨부")),
            }
        }
        rep.uninspectable.extend(parsed.uninspectable);
        rep.encrypted.extend(parsed.encrypted);
        self.escalate(&mut rep);
        rep.findings.sort_by_key(|f| std::cmp::Reverse(f.sev()));
        rep
    }
}

/// File extensions scanned as text whatever their declared type.
const TEXT_EXTS: &[&str] = &[
    "txt",
    "csv",
    "tsv",
    "log",
    "json",
    "xml",
    "html",
    "htm",
    "md",
    "ini",
    "cfg",
    "conf",
    "yaml",
    "yml",
    "sql",
    "eml",
    "vcf",
    "ics",
    "js",
    "sh",
    "properties",
    "env",
];

/// Replaces RTF hex escapes (\'hh) with the bytes they stand for.
fn rtf_unescape(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len());
    let mut i = 0;
    while i < d.len() {
        if d[i] == b'\\' && d.get(i + 1) == Some(&b'\'') && i + 3 < d.len() {
            let h = (d[i + 2] as char).to_digit(16);
            let l = (d[i + 3] as char).to_digit(16);
            if let (Some(h), Some(l)) = (h, l) {
                out.push((h * 16 + l) as u8);
                i += 4;
                continue;
            }
        }
        out.push(d[i]);
        i += 1;
    }
    out
}

/// Prepares text for matching: HTML is reduced to its rendered text (plus its
/// attribute values and hidden content, on their own lines), Unicode format
/// characters (zero-width spaces/joiners, soft hyphens, bidi controls, BOM)
/// that split a number invisibly are removed, full-width forms become ASCII,
/// dash variants become '-' and Unicode spaces (NBSP, ...) become ' '.
pub fn normalize_text(text: &str, html: bool) -> String {
    let s = if html {
        html_to_text(text)
    } else {
        text.to_string()
    };
    s.chars().filter_map(normalize_char).collect()
}

/// Per-character normalization (see [`normalize_text`]).
fn normalize_char(c: char) -> Option<char> {
    if crate::mimeproc::is_format_char(c) {
        return None;
    }
    let u = c as u32;
    Some(match u {
        0xFF0D => '-',
        // Full-width ASCII variants (NFKC).
        0xFF01..=0xFF5E => char::from_u32(u - 0xFEE0).unwrap_or(c),
        0x2010..=0x2015 | 0x2212 | 0xFE58 | 0xFE63 | 0x2043 => '-',
        // Unicode spaces (Zs) incl. NBSP and the ideographic space.
        0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000 => ' ',
        0xFF61 => '.',
        _ => c,
    })
}

/// Block-level elements whose boundaries separate words.
fn is_block_tag(name: &str) -> bool {
    matches!(
        name,
        "br" | "p"
            | "div"
            | "td"
            | "th"
            | "tr"
            | "li"
            | "ul"
            | "ol"
            | "table"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "hr"
            | "blockquote"
            | "pre"
            | "section"
            | "article"
            | "header"
            | "footer"
            | "title"
            | "body"
            | "html"
            | "head"
            | "option"
            | "dt"
            | "dd"
    )
}

/// Strips tags and comments (inline tags vanish so "1234<b></b>567" joins;
/// block tags become line breaks), moves the content of hidden elements
/// (style display:none / visibility:hidden, or the `hidden` attribute) out of
/// the rendered text onto their own lines (so a hidden digit cannot break a
/// number, yet hidden data is still scanned), appends quoted attribute values
/// on their own lines, and decodes character references.
fn html_to_text(html: &str) -> String {
    let b = html.as_bytes();
    let mut text = String::with_capacity(html.len());
    let mut hidden_text = String::new();
    let mut attrs = String::new();
    // The hidden element being skipped: (tag name, nesting depth).
    let mut hidden: Option<(String, usize)> = None;
    let mut i = 0;
    let mut lit = 0; // start of the pending literal run
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if html[i..].starts_with("<!--") {
            let dst = if hidden.is_some() {
                &mut hidden_text
            } else {
                &mut text
            };
            dst.push_str(&html[lit..i]);
            i = match html[i + 4..].find("-->") {
                Some(j) => i + 4 + j + 3,
                None => b.len(),
            };
            lit = i;
            continue;
        }
        let next = b.get(i + 1).copied().unwrap_or(b' ');
        if !(next.is_ascii_alphabetic() || next == b'/' || next == b'!' || next == b'?') {
            i += 1;
            continue;
        }
        // Find the closing '>' outside quotes.
        let mut j = i + 1;
        let mut quote: Option<u8> = None;
        let mut val_start = 0;
        let mut vals: Vec<(usize, usize)> = Vec::new();
        while j < b.len() {
            let c = b[j];
            match quote {
                Some(q) if c == q => {
                    vals.push((val_start, j));
                    quote = None;
                }
                Some(_) => {}
                None if c == b'"' || c == b'\'' => {
                    quote = Some(c);
                    val_start = j + 1;
                }
                None if c == b'>' => break,
                None => {}
            }
            j += 1;
        }
        if j >= b.len() {
            break; // unterminated tag: keep the rest as literal text
        }
        {
            let dst = if hidden.is_some() {
                &mut hidden_text
            } else {
                &mut text
            };
            dst.push_str(&html[lit..i]);
        }
        let raw_inner = &html[i + 1..j];
        let closing = raw_inner.starts_with('/');
        let self_closing = raw_inner.ends_with('/');
        let inner = raw_inner.trim_start_matches('/');
        let name: String = inner
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        match hidden.as_mut() {
            Some((hn, depth)) => {
                if *hn == name {
                    if closing {
                        *depth -= 1;
                        if *depth == 0 {
                            hidden = None;
                            hidden_text.push('\n');
                        }
                    } else if !self_closing {
                        *depth += 1;
                    }
                }
            }
            None => {
                if !closing && !self_closing && !is_void_tag(&name) && is_hidden_tag(inner) {
                    hidden = Some((name.clone(), 1));
                }
            }
        }
        if is_block_tag(&name) {
            let dst = if hidden.is_some() {
                &mut hidden_text
            } else {
                &mut text
            };
            dst.push('\n');
        }
        for (s, e) in vals {
            attrs.push_str(&html[s..e]);
            attrs.push('\n');
        }
        i = j + 1;
        lit = i;
    }
    {
        let dst = if hidden.is_some() {
            &mut hidden_text
        } else {
            &mut text
        };
        dst.push_str(&html[lit..]);
    }
    if !hidden_text.is_empty() {
        text.push('\n');
        text.push_str(&hidden_text);
    }
    if !attrs.is_empty() {
        text.push('\n');
        text.push_str(&attrs);
    }
    decode_entities(&text)
}

/// Elements without content (no closing tag).
fn is_void_tag(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "source"
            | "track"
            | "wbr"
    )
}

/// The tag hides its content: style display:none / visibility:hidden, or a
/// `hidden` attribute.
fn is_hidden_tag(inner: &str) -> bool {
    let l = inner.to_ascii_lowercase();
    let compact: String = l.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("display:none") || compact.contains("visibility:hidden") {
        return true;
    }
    l.split(|c: char| c.is_whitespace() || c == '/')
        .skip(1)
        .any(|t| t == "hidden" || t.starts_with("hidden="))
}

/// Decodes numeric character references (with or without the final ';') and
/// the common named ones.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        if let Some(num) = tail.strip_prefix('#') {
            let (hex, digits) = match num.strip_prefix(['x', 'X']) {
                Some(h) => (true, h),
                None => (false, num),
            };
            let n = digits
                .bytes()
                .take_while(|c| {
                    if hex {
                        c.is_ascii_hexdigit()
                    } else {
                        c.is_ascii_digit()
                    }
                })
                .count();
            if n > 0 {
                let d = digits[..n].trim_start_matches('0');
                let v = if d.is_empty() {
                    Some(0xFFFD)
                } else if d.len() > 8 {
                    None
                } else {
                    u32::from_str_radix(d, if hex { 16 } else { 10 }).ok()
                };
                out.push(v.and_then(char::from_u32).unwrap_or('\u{FFFD}'));
                let used = (num.len() - digits.len()) + n;
                let mut after = &num[used..];
                if let Some(a) = after.strip_prefix(';') {
                    after = a;
                }
                rest = after;
                continue;
            }
        } else if let Some(semi) = tail.find(';').filter(|&k| k > 0 && k <= 32) {
            let rep = match &tail[..semi] {
                "amp" => Some("&"),
                "lt" => Some("<"),
                "gt" => Some(">"),
                "quot" => Some("\""),
                "apos" => Some("'"),
                "nbsp" | "ensp" | "emsp" | "thinsp" => Some(" "),
                "shy" | "ZeroWidthSpace" | "zwnj" | "zwj" | "lrm" | "rlm" | "NoBreak"
                | "InvisibleTimes" | "InvisibleComma" => Some(""),
                "hyphen" | "dash" | "ndash" | "mdash" | "minus" => Some("-"),
                "period" => Some("."),
                "colon" => Some(":"),
                "commat" => Some("@"),
                _ => None,
            };
            if let Some(r) = rep {
                out.push_str(r);
                rest = &tail[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = tail;
    }
    out.push_str(rest);
    out
}

fn is_identity_detector(id: &str) -> bool {
    matches!(
        id,
        "kr_rrn"
            | "kr_passport"
            | "kr_driver_license"
            | "credit_card"
            | "kr_biz_reg"
            | "kr_corp_reg"
            | "bank_account"
            | "iban"
            | "kr_mobile"
            | "email_address"
    )
}

/// Lower-cases ASCII letters only, preserving byte offsets.
fn ascii_lower(s: &str) -> String {
    let mut b = s.as_bytes().to_vec();
    for c in b.iter_mut() {
        if c.is_ascii_uppercase() {
            *c += 32;
        }
    }
    // SAFETY: only ASCII bytes were altered, so UTF-8 validity is preserved.
    String::from_utf8(b).unwrap()
}

fn snap_down(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn snap_up(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Merged [start,end) byte ranges around every hint occurrence.
fn hint_windows(
    text: &str,
    lower: &str,
    hints: &[String],
    fold: &[String],
    back: usize,
    ahead: usize,
) -> Vec<(usize, usize)> {
    let mut pos: Vec<usize> = Vec::new();
    let mut find = |hay: &str, needle: &str| {
        let mut i = 0;
        while let Some(j) = hay[i..].find(needle) {
            pos.push(i + j);
            i += j + needle.len();
        }
    };
    for h in hints {
        find(text, h);
    }
    for h in fold {
        find(lower, h);
    }
    if pos.is_empty() {
        return vec![];
    }
    pos.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for p in pos {
        let lo = snap_down(text, p.saturating_sub(back));
        let hi = snap_up(text, (p + ahead).min(text.len()));
        if let Some(last) = out.last_mut() {
            if lo <= last.1 {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        out.push((lo, hi));
    }
    out
}

/// Runs of digits joined by single '-', ' ' or '.' with at least 10 digits,
/// padded by one byte each side (snapped to char boundaries).
fn number_tokens(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let n = b.len();
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < n {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits_n = 0;
        let mut j = i;
        while j < n {
            let c = b[j];
            if c.is_ascii_digit() {
                digits_n += 1;
                j += 1;
                continue;
            }
            if (c == b'-' || c == b' ' || c == b'.') && j + 1 < n && b[j + 1].is_ascii_digit() {
                j += 1;
                continue;
            }
            break;
        }
        if digits_n >= 10 {
            let lo = snap_down(text, start.saturating_sub(1));
            let hi = snap_up(text, (j + 1).min(n));
            out.push((lo, hi));
        }
        i = j;
    }
    out
}

/// Number detectors that also run over the separator-normalized views (each
/// has a checksum or a fixed group shape, keeping false positives down).
fn is_separator_tolerant(id: &str) -> bool {
    matches!(
        id,
        "kr_rrn" | "credit_card" | "kr_biz_reg" | "kr_corp_reg" | "kr_mobile" | "kr_driver_license"
    )
}

/// Longest separator (in bytes) joining two digit groups in the normalized
/// views.
const MAX_SEP: usize = 6;

/// A copy of `text` where, between two digit groups, a separator made of at
/// most one of [-./] plus whitespace (at most one line break, at most
/// [`MAX_SEP`] bytes) becomes '-' — or, when whitespace only, ' ' (dropped
/// entirely when `drop_ws` and at most 3 bytes long). With `dash_only`, only
/// a literal '-' becomes '-' ('.' and '/' become ' ', never dropped), so a
/// dash in the view always stands for a dash in the text.
fn collapse_numbers(text: &str, drop_ws: bool, dash_only: bool) -> String {
    let b = text.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(n);
    let mut lit = 0;
    let mut i = 0;
    while i < n {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        out.push_str(&text[lit..i]);
        let mut j = i;
        loop {
            let ds = j;
            while j < n && b[j].is_ascii_digit() {
                j += 1;
            }
            out.push_str(&text[ds..j]);
            let (ss, mut k) = (j, j);
            let (mut punct, mut nl, mut dash) = (0, 0, false);
            while k < n && k - ss <= MAX_SEP {
                match b[k] {
                    b'-' => {
                        punct += 1;
                        dash = true;
                    }
                    b'.' | b'/' => punct += 1,
                    b'\n' => nl += 1,
                    b' ' | b'\t' | b'\r' => {}
                    _ => break,
                }
                k += 1;
            }
            if k > ss
                && k - ss <= MAX_SEP
                && k < n
                && b[k].is_ascii_digit()
                && punct <= 1
                && nl <= 1
            {
                if punct == 1 && (dash || !dash_only) {
                    out.push('-');
                } else if punct == 1 || !(drop_ws && k - ss <= 3) {
                    out.push(' ');
                }
                j = k;
                continue;
            }
            break;
        }
        i = j;
        lit = j;
    }
    out.push_str(&text[lit..]);
    out
}
fn has_context(lower: &str, start: usize, end: usize, kws: &[String]) -> bool {
    let lo = snap_down(lower, start.saturating_sub(CONTEXT_WINDOW));
    let hi = snap_up(lower, (end + CONTEXT_WINDOW).min(lower.len()));
    let win = &lower[lo..hi];
    kws.iter().any(|k| win.contains(k.as_str()))
}

/// Whether one of `kws` occurs within `chars` characters of [start,end).
fn has_context_chars(lower: &str, start: usize, end: usize, kws: &[String], chars: usize) -> bool {
    let lo = lower[..start]
        .char_indices()
        .rev()
        .take(chars)
        .last()
        .map(|(i, _)| i)
        .unwrap_or(start);
    let hi = lower[end..]
        .char_indices()
        .nth(chars)
        .map(|(i, _)| end + i)
        .unwrap_or(lower.len());
    let win = &lower[lo..hi];
    kws.iter().any(|k| win.contains(k.as_str()))
}

/// Compiles a candidate rule pattern and returns up to `max` masked matches.
pub fn test_rule(pattern: &str, text: &str, max: usize) -> Result<Vec<String>, String> {
    let re = Regex::new(pattern).map_err(|e| e.to_string())?;
    if re.captures_len() > 2 {
        return Err("at most one capture group allowed".into());
    }
    let max = if max == 0 { 50 } else { max };
    let mask = mask_middle(2, 2);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for caps in re.captures_iter(text) {
        let v = match caps.get(1) {
            Some(g) if !g.as_str().is_empty() => g.as_str(),
            _ => caps.get(0).unwrap().as_str(),
        };
        let mv = mask(v);
        if seen.contains(&mv) {
            continue;
        }
        seen.insert(mv.clone());
        out.push(mv);
        if out.len() >= max {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> Scanner {
        Scanner::new(Options {
            combine_pii: true,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn detects_rrn_with_context() {
        let s = scanner();
        let f = s.scan_text("본문", "제 주민등록번호는 900101-1234567 입니다.");
        assert!(f.iter().any(|x| x.detector == "kr_rrn" && x.count == 1));
        assert!(f.iter().find(|x| x.detector == "kr_rrn").unwrap().samples[0].contains("900101-1"));
    }

    #[test]
    fn detects_credit_card_with_context() {
        let s = scanner();
        let f = s.scan_text("본문", "card: 4111 1111 1111 1111");
        assert!(f.iter().any(|x| x.detector == "credit_card"));
    }

    #[test]
    fn bulk_mobile_threshold() {
        let s = scanner();
        // 4 numbers: below the MinCount of 5 -> no finding.
        let few = "010-1111-2222, 010-3333-4444, 010-5555-6666, 010-7777-8888";
        assert!(!s
            .scan_text("x", few)
            .iter()
            .any(|x| x.detector == "kr_mobile"));
        let many = format!("{few}, 010-9999-0000");
        assert!(s
            .scan_text("x", &many)
            .iter()
            .any(|x| x.detector == "kr_mobile"));
    }

    #[test]
    fn secret_detectors() {
        let s = scanner();
        let f = s.scan_text("코드", "AWS_KEY AKIAIOSFODNN7EXAMPLE end");
        assert!(f.iter().any(|x| x.detector == "aws_access_key"));
    }

    #[test]
    fn escalation_combines_pii() {
        let s = scanner();
        let text = "명단: 홍길동 900101-1234567 card 4111 1111 1111 1111";
        let rep = s.scan_text_report("첨부 a.xlsx", text);
        assert!(rep
            .findings
            .iter()
            .any(|f| f.detector == "pii_combination" && f.sev() == Severity::High));
        assert_eq!(rep.max_severity(), Severity::High);
    }

    #[test]
    fn summary_format() {
        let s = scanner();
        let rep = s.scan_text_report("본문", "주민번호 900101-1234567");
        assert!(rep.summary().contains("건"));
    }

    #[test]
    fn test_rule_masks_and_dedupes() {
        let out = test_rule(
            r"(\d{3}-\d{2}-\d{4})",
            "111-22-3333 and 111-22-3333 and 999-88-7777",
            50,
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].contains('*'));
        assert!(test_rule(r"(\d)(\d)", "12", 50).is_err()); // >1 capture group
    }

    #[test]
    fn scan_message_subject_body_attachment() {
        let s = scanner();
        let raw = b"From: a@ext.org\r\nSubject: card 4111 1111 1111 1111\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
--B\r\nContent-Type: text/plain\r\n\r\n\
\xEC\xA3\xBC\xEB\xAF\xBC 900101-1234567\r\n\
--B\r\nContent-Type: text/csv; name=\"list.csv\"\r\n\
Content-Disposition: attachment; filename=\"list.csv\"\r\n\r\n\
name,ssn\r\nkim,900101-1234567\r\n--B--\r\n";
        let rep = s.scan_message(raw);
        assert!(rep.findings.iter().any(|f| f.detector == "kr_rrn"));
        assert!(rep
            .findings
            .iter()
            .any(|f| f.location == "제목" && f.detector == "credit_card"));
        assert!(rep
            .findings
            .iter()
            .any(|f| f.location.starts_with("첨부 list.csv")));
    }

    #[test]
    fn disabled_and_min_counts() {
        let mut mc = HashMap::new();
        mc.insert("kr_mobile".to_string(), 1usize);
        let s = Scanner::new(Options {
            disabled: vec!["kr_rrn".into()],
            min_counts: mc,
            ..Default::default()
        })
        .unwrap();
        // kr_rrn disabled -> not detected even with a valid RRN.
        assert!(!s
            .scan_text("x", "900101-1234567")
            .iter()
            .any(|f| f.detector == "kr_rrn"));
        // kr_mobile min_count lowered to 1 -> a single number is detected.
        assert!(s
            .scan_text("x", "010-1234-5678")
            .iter()
            .any(|f| f.detector == "kr_mobile"));
    }

    fn has_rrn(rep: &Report) -> bool {
        rep.findings.iter().any(|f| f.detector == "kr_rrn")
    }

    #[test]
    fn nameless_non_text_leaves_are_scanned_or_reported() {
        let s = scanner();
        for ct in [
            "application/octet-stream",
            "message/rfc822",
            "application/json",
            "application/xml",
        ] {
            let raw = format!("From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: {ct}\r\n\r\nSubject: x\r\n\r\nRRN 900101-1234567\r\n--B--\r\n");
            assert!(has_rrn(&s.scan_message(raw.as_bytes())), "{ct}");
        }
        // Binary nameless leaves are reported, never silently skipped.
        let raw = b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream\r\n\r\n\xff\xff\x00\x01\xff\xff\x02\x03\r\n--B--\r\n";
        assert_eq!(s.scan_message(raw).uninspectable.len(), 1);
        // Opaque ciphertext is reported as encrypted.
        let raw = b"From: a@x\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\nMIAG\r\n";
        assert!(s.scan_message(raw).has_encrypted());
    }

    #[test]
    fn dlp_uses_the_relay_parser() {
        // mailparse would split at "--Bx" and hide the PII in a "png"; the
        // gateway relays it as text, so DLP must scan it as text.
        let s = scanner();
        let raw = b"From: a@x\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n--Bx\r\nContent-Type: image/png; name=a.png\r\nContent-Transfer-Encoding: base64\r\n\r\n\xEC\xA3\xBC\xEB\xAF\xBC\xEB\xB2\x88\xED\x98\xB8 900101-1234567\r\n--B--\r\n";
        let rep = s.scan_message(raw);
        assert!(has_rrn(&rep));
        assert!(rep.uninspectable.is_empty());
    }

    #[test]
    fn html_and_invisible_characters_are_normalized() {
        let s = scanner();
        for body in [
            "<p>rrn 900101-<i></i>1234567</p>",
            "<p>rrn &#57;00101-1234567</p>",
            "<p>rrn &#x39;00101&#45;1234567</p>",
            "<p>rrn 900101&shy;-1234567<!-- x --></p>",
            "<p title=\"900101-1234567\">hover</p>",
        ] {
            let raw = format!("Content-Type: text/html\r\n\r\n{body}\r\n");
            assert!(has_rrn(&s.scan_message(raw.as_bytes())), "{body}");
        }
        let raw = "Content-Type: text/plain; charset=utf-8\r\n\r\nrrn 900101-\u{200B}1234567\r\n";
        assert!(has_rrn(&s.scan_message(raw.as_bytes())));
        let raw =
            "Content-Type: text/plain; charset=utf-8\r\n\r\nrrn 9001\u{2060}01-12345\u{FEFF}67\r\n";
        assert!(has_rrn(&s.scan_message(raw.as_bytes())));
        assert_eq!(html_to_text("a<br>b"), "a\nb");
        assert_eq!(html_to_text("1 < 2 & 3"), "1 < 2 & 3");
        assert_eq!(decode_entities("&lt;&amp;&#65;&#x42&zz;"), "<&AB&zz;");
    }

    #[test]
    fn deep_nesting_does_not_crash_the_scanner() {
        let raw = crate::mimetree::tests::deep_message(50_000);
        let h = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || scanner().scan_message(&raw))
            .unwrap();
        let rep = h.join().expect("no stack overflow");
        assert!(!rep.uninspectable.is_empty());
    }
}

/// Round-2 review regressions: number evasions, charsets, hidden HTML.
#[cfg(test)]
mod r2_tests {
    use super::*;

    fn s() -> Scanner {
        Scanner::new(Options {
            combine_pii: true,
            ..Default::default()
        })
        .unwrap()
    }

    fn policy() -> crate::outbound::Policy {
        crate::outbound::Policy {
            high: "hold".into(),
            medium: "notify".into(),
            low: "allow".into(),
            uninspectable: "notify".into(),
            encrypted: "hold".into(),
            exempt_senders: vec![],
            exempt_recipient_domains: vec![],
            dry_run: false,
        }
    }

    fn assert_rrn(label: &str, raw: &[u8]) {
        let r = s().scan_message(raw);
        assert!(
            r.findings.iter().any(|f| f.detector == "kr_rrn"),
            "{label}: findings={:?} unins={:?}",
            r.findings.iter().map(|f| &f.detector).collect::<Vec<_>>(),
            r.uninspectable
        );
        assert_eq!(crate::outbound::decide(&r, &policy()), "hold", "{label}");
    }

    #[test]
    fn number_evasions_are_detected() {
        let base = |body: &str| {
            format!("Content-Type: text/plain; charset=utf-8\r\n\r\n주민등록번호 {body}\r\n")
        };
        for (l, b) in [
            ("plain", "900101-1234567"),
            ("fullwidth", "９００１０１－１２３４５６７"),
            ("endash", "900101–1234567"),
            ("emdash", "900101—1234567"),
            ("minus", "900101−1234567"),
            ("dot", "900101.1234568"),
            ("spaced", "9 0 0 1 0 1 - 1 2 3 4 5 6 7"),
            ("slash", "900101/1234568"),
            ("sp-dash-sp", "900101 - 1234567"),
            ("nbsp", "900101\u{a0}1234568"),
            ("thin-space", "900101\u{2009}-\u{2009}1234567"),
            ("ideographic-space", "900101\u{3000}1234568"),
            ("newline", "900101-\r\n1234567"),
            ("fwhyphen", "900101－1234567"),
        ] {
            assert_rrn(l, base(b).as_bytes());
        }
        // Cards: full-width digits and spaced groups.
        let r = s().scan_text(
            "x",
            &normalize_text("card ４１１１－１１１１－１１１１－１１１１", false),
        );
        assert!(r.iter().any(|f| f.detector == "credit_card"));
        let r = s().scan_text("x", "card 4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1");
        assert!(r.iter().any(|f| f.detector == "credit_card"));
        // The same number written several ways is counted once.
        let r = s().scan_text(
            "x",
            "rrn 900101-1234567 / 900101 - 1234567 / 900101.1234567",
        );
        assert_eq!(r.iter().find(|f| f.detector == "kr_rrn").unwrap().count, 1);
        // No false positive from collapsing unrelated digits: a bare 13-digit
        // run needs the checksum.
        let r = s().scan_text("x", "order 9 0 0 1 0 1 1 2 3 4 5 6 7");
        assert!(!r.iter().any(|f| f.detector == "kr_rrn"));
    }

    #[test]
    fn encodings_and_markup_are_decoded() {
        let cases: &[(&str, &[u8])] = &[
            ("qp-soft", b"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nrrn 900101-12=\r\n34567\r\n"),
            ("b64", b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\ncnJuIDkwMDEwMS0xMjM0NTY3\r\n"),
            ("csv-euc-kr", b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/csv; name=a.csv; charset=euc-kr\r\n\r\n\xc1\xd6\xb9\xce,900101-1234567\r\n--B--\r\n"),
            ("csv-cp949-undeclared", b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream; name=list.csv\r\n\r\n\xc1\xd6\xb9\xce,900101-1234567\r\n--B--\r\n"),
            ("utf16le-declared", b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain; name=a.txt; charset=utf-16le\r\n\r\n9\x000\x000\x001\x000\x001\x00-\x001\x002\x003\x004\x005\x006\x007\x00\r\n--B--\r\n"),
            ("utf16le-undeclared", b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream; name=a.txt\r\n\r\n9\x000\x000\x001\x000\x001\x00-\x001\x002\x003\x004\x005\x006\x007\x00\r\n--B--\r\n"),
            ("utf16be-bom", b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: text/plain; name=a.txt\r\n\r\n\xfe\xff\x009\x000\x000\x001\x000\x001\x00-\x001\x002\x003\x004\x005\x006\x007\r\n--B--\r\n"),
            ("body-euc-kr-undeclared", b"Content-Type: text/plain\r\n\r\n\xc1\xd6\xb9\xce 900101\xa1\xaa1234567\r\n"),
            ("html-split-td", b"Content-Type: text/html\r\n\r\nrrn <span>900101</span><span style=x>-1234567</span>\r\n"),
            ("html-entity-fw", b"Content-Type: text/html\r\n\r\nrrn &#65305;00101-1234567\r\n"),
            ("html-hidden-span", b"Content-Type: text/html\r\n\r\n<div>rrn 900101<span style=\"display: none\">0</span>-1234567</div>\r\n"),
            ("html-hidden-attr", b"Content-Type: text/html\r\n\r\n<div>rrn 900101<b hidden>77</b>-1234567</div>\r\n"),
            ("encrypted-fake", b"Content-Type: multipart/encrypted; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nrrn 900101-1234567\r\n--B\r\nContent-Type: application/octet-stream\r\n\r\nrrn 900101-1234567\r\n--B--\r\n"),
            ("sigpart", b"Content-Type: multipart/signed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/pkcs7-signature; name=a.txt\r\n\r\nrrn 900101-1234567\r\n--B--\r\n"),
            ("uuencode-cte", b"Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 a.txt\r\n2<G)N(#DP,#$P,2TQ,C,T-38W\r\n`\r\nend\r\n"),
            ("uuencode-inline", b"Content-Type: text/plain\r\n\r\nsee\r\nbegin 644 a.txt\r\n2<G)N(#DP,#$P,2TQ,C,T-38W\r\n`\r\nend\r\n"),
            ("charset-utf7", b"Content-Type: text/plain; charset=utf-7\r\n\r\nrrn +ADk-00101-1234567\r\n"),
            ("charset-unknown", b"Content-Type: text/plain; charset=x-foo\r\nContent-Transfer-Encoding: base64\r\n\r\ncnJuIDkwMDEwMS0xMjM0NTY3\r\n"),
            ("rtf-hex", b"Content-Type: application/rtf; name=a.rtf\r\n\r\n{\\rtf1 rrn \\'39\\'30\\'30101-1234567}\r\n"),
        ];
        for (l, raw) in cases {
            assert_rrn(l, raw);
        }
    }

    /// Deterministic xorshift for the synthetic corpora.
    struct Rng(u64);
    impl Rng {
        fn r(&mut self, m: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % m
        }
    }

    /// Accounting-style rows (dates next to amounts, unrelated 6+7 digit
    /// pairs) must never be reported as resident registration numbers:
    /// only a literal dash between the groups is accepted without the
    /// checksum, and any other separator needs the checksum plus an RRN
    /// keyword nearby.
    #[test]
    fn rrn_false_positive_corpus() {
        let sc = s();
        let mut rng = Rng(0x1234567);
        type Gen = Box<dyn Fn(&mut Rng) -> String>;
        let date = |r: &mut Rng| format!("{:02}{:02}{:02}", r.r(26), 1 + r.r(12), 1 + r.r(28));
        let gens: Vec<(&str, Gen)> = vec![
            (
                "date<TAB>amount",
                Box::new(move |r: &mut Rng| {
                    format!("일자\t금액\n{}\t{}\n", date(r), 1_000_000 + r.r(9_000_000))
                }),
            ),
            (
                "(주)name<TAB>date<TAB>amount",
                Box::new(move |r: &mut Rng| {
                    format!("(주)한빛\t{}\t{}\r\n", date(r), 1_000_000 + r.r(9_000_000))
                }),
            ),
            (
                "date amount원",
                Box::new(move |r: &mut Rng| {
                    format!("{} {}원", date(r), 1_000_000 + r.r(9_000_000))
                }),
            ),
            (
                "date / amount",
                Box::new(move |r: &mut Rng| {
                    format!("{} / {}", date(r), 1_000_000 + r.r(9_000_000))
                }),
            ),
            (
                "date.amount",
                Box::new(move |r: &mut Rng| {
                    format!("value={}.{}", date(r), 1_000_000 + r.r(9_000_000))
                }),
            ),
            (
                "date<NL>amount",
                Box::new(move |r: &mut Rng| {
                    format!("{}\n{}\n", date(r), 1_000_000 + r.r(9_000_000))
                }),
            ),
            (
                "date<NBSP>amount",
                Box::new(move |r: &mut Rng| {
                    format!("{}\u{a0}{}", date(r), 1_000_000 + r.r(9_000_000))
                }),
            ),
            (
                "order 6 7",
                Box::new(|r: &mut Rng| {
                    format!("주문번호 {:06} {:07}", r.r(1_000_000), r.r(10_000_000))
                }),
            ),
            (
                "random 6/7",
                Box::new(|r: &mut Rng| format!("{:06}/{:07}", r.r(1_000_000), r.r(10_000_000))),
            ),
        ];
        let mut total = 0;
        let mut report = Vec::new();
        for (label, g) in &gens {
            let mut hits = 0;
            let mut ex = String::new();
            for _ in 0..2000 {
                let t = g(&mut rng);
                let f = sc.scan_text("x", &normalize_text(&t, false));
                if f.iter().any(|f| f.detector == "kr_rrn") {
                    hits += 1;
                    if ex.is_empty() {
                        ex = t;
                    }
                }
            }
            report.push(format!("{label}: {hits}/2000 {ex:?}"));
            total += hits;
        }
        eprintln!("RRN-FP\n{}", report.join("\n"));
        // Non-dash separators still detect with the checksum and a keyword
        // (but not without either).
        let rrn = |t: &str| {
            sc.scan_text("x", &normalize_text(t, false))
                .iter()
                .any(|f| f.detector == "kr_rrn")
        };
        for sep in [" ", "\t", "\n", " / ", ".", "\u{a0}", "\u{3000}"] {
            assert!(rrn(&format!("주민번호: 900101{sep}1234568")), "{sep:?}");
            assert!(
                rrn(&format!("Resident Registration No 900101{sep}1234568")),
                "{sep:?}"
            );
            assert!(!rrn(&format!("주민번호: 900101{sep}1234567")), "{sep:?}");
            assert!(!rrn(&format!("주문번호: 900101{sep}1234568")), "{sep:?}");
        }
        assert!(rrn("JUMIN 900101 1234568"));
        assert!(rrn("생년월일 900101 1234568"));
        // A dash (or dash variant) needs neither.
        assert!(rrn("900101-1234567"));
        assert!(rrn("900101\u{2013}1234567"));
        assert!(rrn("９００１０１－１２３４５６７"));
        assert!(rrn("9 0 0 1 0 1 - 1 2 3 4 5 6 7"));
        assert_eq!(total, 0, "{report:#?}");
        // The whole TSV message does not trigger a hold.
        let mut body = String::from("일자\t거래처\t금액\r\n");
        for i in 0..10 {
            body.push_str(&format!(
                "(주)한빛\t2511{:02}\t{}\r\n",
                10 + i,
                1_250_000 + i * 31_000
            ));
        }
        let raw = format!("From: a@corp.kr\r\nSubject: 11월 정산\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}");
        let rep = sc.scan_message(raw.as_bytes());
        assert!(
            !rep.findings.iter().any(|f| f.detector == "kr_rrn"),
            "{:?}",
            rep.findings
        );
        assert_ne!(crate::outbound::decide(&rep, &policy()), "hold");
    }

    #[test]
    fn decode_text_heuristics() {
        use crate::mimeproc::{decode_text, Decoded};
        assert_eq!(
            decode_text(b"\xc7\xd1\xb1\xdb", None),
            Decoded::Text("한글".into())
        );
        assert_eq!(
            decode_text(b"\xc7\xd1\xb1\xdb", Some("euc-kr")),
            Decoded::Text("한글".into())
        );
        assert_eq!(
            decode_text("한글".as_bytes(), Some("us-ascii")),
            Decoded::Text("한글".into())
        );
        assert_eq!(
            decode_text(b"\xef\xbb\xbfabc", Some("euc-kr")),
            Decoded::Text("abc".into())
        );
        assert_eq!(
            decode_text(b"a\x00b\x00c\x00d\x00", None),
            Decoded::Text("abcd".into())
        );
        assert!(matches!(
            decode_text(b"\xff\xff\x00\x01\xff\xff\x02\x03", None),
            Decoded::Lossy(_)
        ));
    }
}
