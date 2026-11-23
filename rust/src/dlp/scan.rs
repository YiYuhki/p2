//! The DLP text scanner: runs detectors over text, aggregates findings into a
//! report, escalates identity-revealing datasets, and tests a candidate rule.
//! Port of the Go `internal/dlp/scan.go` (text-scanning core; the MIME/OCR
//! extraction side lands with the mimeproc port).

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::Serialize;

use super::detectors::{builtin, mask_middle, Detector, Severity, CATEGORY_PII, CONTEXT_WINDOW};

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
            });
        }
        Ok(Scanner {
            detectors: ds,
            opts,
        })
    }

    /// Runs every detector over one piece of text.
    pub fn scan_text(&self, loc: &str, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let lower = ascii_lower(text);
        let mut num_tokens: Vec<(usize, usize)> = Vec::new();
        let mut num_done = false;

        for d in &self.detectors {
            let windows: Vec<(usize, usize)> = if d.digits {
                if !num_done {
                    num_tokens = number_tokens(text);
                    num_done = true;
                }
                num_tokens.clone()
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
            if windows.is_empty() {
                continue;
            }
            let mut seen: HashSet<String> = HashSet::new();
            let mut samples: Vec<String> = Vec::new();
            for (ws, we) in windows {
                let seg = &text[ws..we];
                for caps in d.re.captures_iter(seg) {
                    let m = match caps.get(1) {
                        Some(g) => g,
                        None => caps.get(0).unwrap(),
                    };
                    let v = m.as_str();
                    let abs_start = m.start() + ws;
                    let abs_end = m.end() + ws;
                    if seen.contains(v) {
                        continue;
                    }
                    if let Some(validate) = d.validate {
                        if !validate(v) {
                            continue;
                        }
                    }
                    if !d.context.is_empty()
                        && d.needs_context.map(|f| f(v)).unwrap_or(true)
                        && !has_context(&lower, abs_start, abs_end, &d.context)
                    {
                        continue;
                    }
                    seen.insert(v.to_string());
                    if samples.len() < 3 {
                        samples.push((d.mask)(v));
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

fn has_context(lower: &str, start: usize, end: usize, kws: &[String]) -> bool {
    let lo = snap_down(lower, start.saturating_sub(CONTEXT_WINDOW));
    let hi = snap_up(lower, (end + CONTEXT_WINDOW).min(lower.len()));
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
}
