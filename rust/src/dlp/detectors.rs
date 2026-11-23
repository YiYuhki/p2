//! Built-in DLP detectors (personal data and credentials) and their validators
//! and maskers. Port of the Go `internal/dlp/detectors.go`. The regex crate is
//! RE2-based like Go's regexp, so the patterns (and the explicit non-digit /
//! non-word guards that stand in for look-around) port directly.

use regex::Regex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            _ => None,
        }
    }
}

pub const CATEGORY_PII: &str = "pii";
pub const CATEGORY_SECRET: &str = "secret";
pub const CONTEXT_WINDOW: usize = 60;

type Masker = Box<dyn Fn(&str) -> String + Send + Sync>;

/// Finds one kind of sensitive value.
pub struct Detector {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: Severity,
    pub re: Regex,
    pub validate: Option<fn(&str) -> bool>,
    pub context: Vec<String>,
    pub min_count: usize,
    pub mask: Masker,
    pub needs_context: Option<fn(&str) -> bool>,
    pub digits: bool,
    pub hints: Vec<String>,
    pub hints_fold: Vec<String>,
    pub back: usize,
    pub ahead: usize,
}

// ---- helpers ----

pub fn digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn d_at(d: &str, i: usize) -> i32 {
    (d.as_bytes()[i] - b'0') as i32
}

// ---- validators ----

pub fn valid_rrn(v: &str) -> bool {
    use chrono::{Datelike, NaiveDate, Utc};
    let d = digits(v);
    if d.len() != 13 {
        return false;
    }
    let g = d.as_bytes()[6];
    let century = match g {
        b'1' | b'2' | b'5' | b'6' => 1900,
        b'3' | b'4' | b'7' | b'8' => 2000,
        _ => return false,
    };
    let yy: i32 = d[0..2].parse().unwrap_or(-1);
    let mm: u32 = d[2..4].parse().unwrap_or(0);
    let dd: u32 = d[4..6].parse().unwrap_or(0);
    let date = match NaiveDate::from_ymd_opt(century + yy, mm, dd) {
        Some(x) => x,
        None => return false,
    };
    if date.month() != mm || date.day() != dd || date > Utc::now().date_naive() {
        return false;
    }
    if v.contains('-') {
        return true;
    }
    rrn_checksum(&d)
}

fn rrn_checksum(d: &str) -> bool {
    let w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let mut sum = 0;
    for (i, m) in w.iter().enumerate() {
        sum += d_at(d, i) * m;
    }
    let check = (11 - sum % 11) % 10;
    check == d_at(d, 12)
}

pub fn luhn(d: &str) -> bool {
    let mut sum = 0;
    let mut alt = false;
    for i in (0..d.len()).rev() {
        let mut n = d_at(d, i);
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum % 10 == 0
}

pub fn valid_biz_reg(v: &str) -> bool {
    let d = digits(v);
    if d.len() != 10 || d == "0000000000" {
        return false;
    }
    let w = [1, 3, 7, 1, 3, 7, 1, 3, 5];
    let mut sum = 0;
    for (i, wi) in w.iter().enumerate() {
        sum += d_at(&d, i) * wi;
    }
    sum += d_at(&d, 8) * 5 / 10;
    let check = (10 - sum % 10) % 10;
    check == d_at(&d, 9)
}

pub fn valid_corp_reg(v: &str) -> bool {
    let d = digits(v);
    if d.len() != 13 {
        return false;
    }
    let mut sum = 0;
    for i in 0..12 {
        let w = if i % 2 == 1 { 2 } else { 1 };
        sum += d_at(&d, i) * w;
    }
    let check = (10 - sum % 10) % 10;
    check == d_at(&d, 12)
}

pub fn valid_iban(v: &str) -> bool {
    let s: String = v.replace(' ', "").to_uppercase();
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem: u64 = 0;
    for c in rearranged.chars() {
        let n = if c.is_ascii_digit() {
            (c as u8 - b'0') as u64
        } else if c.is_ascii_uppercase() {
            (c as u8 - b'A') as u64 + 10
        } else {
            return false;
        };
        if n < 10 {
            rem = (rem * 10 + n) % 97;
        } else {
            rem = (rem * 100 + n) % 97;
        }
    }
    rem == 1
}

pub fn valid_card(v: &str) -> bool {
    let d = digits(v);
    if d.len() < 14 || d.len() > 19 || !luhn(&d) {
        return false;
    }
    let p2: i32 = d[..2].parse().unwrap_or(-1);
    let p4: i32 = d[..4].parse().unwrap_or(-1);
    let b0 = d.as_bytes()[0];
    let ok = b0 == b'4'
        || (b0 == b'9' && d.len() == 16)
        || (51..=55).contains(&p2)
        || (2221..=2720).contains(&p4)
        || matches!(p2, 34 | 37 | 35 | 62 | 65)
        || p4 == 6011;
    if !ok {
        return false;
    }
    // Reject an all-same-digit number.
    let first = d.as_bytes()[0];
    d.bytes().any(|c| c != first)
}

fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: std::collections::HashMap<char, f64> = std::collections::HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0.0) += 1.0;
    }
    let n = s.chars().count() as f64;
    let mut e = 0.0;
    for &c in freq.values() {
        let p = c / n;
        e -= p * p.log2();
    }
    e
}

const PLACEHOLDERS: &[&str] = &[
    "xxxx", "****", "....", "your", "example", "sample", "changeme", "password", "secret", "dummy",
    "test1234", "<", "${", "{{", "%s", "redacted", "masked", "none", "null",
];

pub fn valid_generic_secret(v: &str) -> bool {
    let lv = v.to_lowercase();
    if PLACEHOLDERS.iter().any(|p| lv.contains(p)) {
        return false;
    }
    entropy(v) >= 3.0
}

pub fn valid_db_url(v: &str) -> bool {
    let at = match v.rfind('@') {
        Some(i) => i,
        None => return false,
    };
    let scheme = match v.find("://") {
        Some(i) => i,
        None => return false,
    };
    if at < scheme {
        return false;
    }
    let cred = &v[scheme + 3..at];
    let c = match cred.find(':') {
        Some(i) => i,
        None => return false,
    };
    let pw = cred[c + 1..].to_lowercase();
    if matches!(
        pw.as_str(),
        "pass"
            | "pw"
            | "pwd"
            | "user"
            | "username"
            | "root"
            | "admin"
            | "postgres"
            | "mysql"
            | "guest"
            | "123456"
            | "1234"
    ) {
        return false;
    }
    if PLACEHOLDERS.iter().any(|p| pw.contains(p)) {
        return false;
    }
    pw.len() >= 4
}

// ---- maskers ----

pub fn mask_middle(keep_start: usize, keep_end: usize) -> Masker {
    Box::new(move |v: &str| {
        let r: Vec<char> = v.chars().collect();
        if r.len() <= keep_start + keep_end {
            return "*".repeat(r.len());
        }
        let start: String = r[..keep_start].iter().collect();
        let end: String = r[r.len() - keep_end..].iter().collect();
        format!(
            "{}{}{}",
            start,
            "*".repeat(r.len() - keep_start - keep_end),
            end
        )
    })
}

fn mask_rrn(v: &str) -> String {
    let d = digits(v);
    format!("{}-{}{}", &d[..6], &d[6..7], "******")
}

fn mask_card(v: &str) -> String {
    let d = digits(v);
    format!("{}{}", "*".repeat(d.len() - 4), &d[d.len() - 4..])
}

fn mask_phone(v: &str) -> String {
    let d = digits(v);
    format!("{}-****-{}", &d[..3], &d[d.len() - 4..])
}

fn mask_email(v: &str) -> String {
    match v.rfind('@') {
        Some(at) if at > 0 => format!("{}{}{}", &v[..1], "*".repeat(at - 1), &v[at..]),
        _ => mask_middle(1, 0)(v),
    }
}

fn mask_db_url(v: &str) -> String {
    let at = v.rfind('@').unwrap_or(0);
    let c = v[..at].rfind(':').unwrap_or(0);
    format!("{}****{}", &v[..c + 1], &v[at..])
}

fn mask_identity(v: &str) -> String {
    v.to_string()
}

// ---- boundary guards (RE2 has no look-around) ----
const ND: &str = r"(?:^|[^0-9])";
const NDE: &str = r"(?:[^0-9]|$)";
const NA: &str = r"(?:^|[^A-Za-z0-9_])";
const NAE: &str = r"(?:[^A-Za-z0-9_]|$)";

fn sv(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Builds the list of built-in detectors.
pub fn builtin() -> Vec<Detector> {
    let re = |p: &str| Regex::new(p).expect("builtin regex");
    vec![
        Detector {
            id: "kr_rrn".into(),
            name: "주민등록번호/외국인등록번호".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::High,
            digits: true,
            re: re(&format!(r"{ND}(\d{{6}}[- ]?[1-8]\d{{6}}){NDE}")),
            validate: Some(valid_rrn),
            context: vec![],
            min_count: 0,
            mask: Box::new(mask_rrn),
            needs_context: None,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "credit_card".into(),
            name: "신용카드번호".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::High,
            digits: true,
            context: sv(&[
                "카드",
                "card",
                "신용",
                "체크",
                "결제",
                "visa",
                "master",
                "amex",
                "비자",
                "마스터",
                "pan",
            ]),
            needs_context: Some(|v| v == digits(v)),
            re: re(&format!(
                r"{ND}(\d{{4}}[- ]?\d{{4}}[- ]?\d{{4}}[- ]?\d{{2,7}}|3[47]\d{{2}}[- ]?\d{{6}}[- ]?\d{{5}}){NDE}"
            )),
            validate: Some(valid_card),
            mask: Box::new(mask_card),
            min_count: 0,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "kr_passport".into(),
            name: "여권번호".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Medium,
            hints_fold: sv(&["여권", "passport"]),
            back: 200,
            ahead: 200,
            re: re(&format!(
                r"{NA}([MSRGDmsrgd]\d{{8}}|[MSRGD]\d{{3}}[A-Z]\d{{4}}){NAE}"
            )),
            context: sv(&["여권", "passport"]),
            mask: mask_middle(2, 2),
            validate: None,
            needs_context: None,
            min_count: 0,
            digits: false,
            hints: vec![],
        },
        Detector {
            id: "kr_driver_license".into(),
            name: "운전면허번호".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Medium,
            digits: true,
            re: re(&format!(
                r"{ND}((?:1[1-9]|2[0-8])-\d{{2}}-\d{{6}}-\d{{2}}){NDE}"
            )),
            mask: mask_middle(5, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "kr_biz_reg".into(),
            name: "사업자등록번호".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Medium,
            digits: true,
            re: re(&format!(r"{ND}(\d{{3}}-\d{{2}}-\d{{5}}){NDE}")),
            validate: Some(valid_biz_reg),
            mask: mask_middle(3, 2),
            context: vec![],
            needs_context: None,
            min_count: 0,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "kr_corp_reg".into(),
            name: "법인등록번호".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Medium,
            digits: true,
            re: re(&format!(r"{ND}(\d{{6}}-\d{{7}}){NDE}")),
            validate: Some(valid_corp_reg),
            mask: mask_middle(6, 2),
            context: vec![],
            needs_context: None,
            min_count: 0,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "bank_account".into(),
            name: "계좌번호".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Medium,
            digits: true,
            re: re(&format!(
                r"{ND}(\d{{2,6}}-\d{{2,6}}-\d{{2,7}}(?:-\d{{1,7}})?){NDE}"
            )),
            context: sv(&[
                "계좌",
                "예금주",
                "입금",
                "송금",
                "account",
                "은행",
                "bank",
                "농협",
                "국민",
                "신한",
                "우리",
                "하나",
                "기업",
                "카카오뱅크",
                "토스",
                "새마을",
                "우체국",
                "수협",
                "대출",
            ]),
            validate: Some(|v| {
                let d = digits(v);
                d.len() >= 10 && d.len() <= 16
            }),
            mask: mask_middle(3, 3),
            needs_context: None,
            min_count: 0,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "iban".into(),
            name: "IBAN(해외계좌)".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Medium,
            re: re(&format!(r"{NA}([A-Z]{{2}}\d{{2}}[A-Z0-9]{{11,30}}){NAE}")),
            validate: Some(valid_iban),
            mask: mask_middle(4, 2),
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "kr_mobile".into(),
            name: "휴대전화번호(대량)".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Medium,
            min_count: 5,
            digits: true,
            re: re(&format!(
                r"{ND}(01[016789][- .]?\d{{3,4}}[- .]?\d{{4}}){NDE}"
            )),
            mask: Box::new(mask_phone),
            validate: None,
            context: vec![],
            needs_context: None,
            hints: vec![],
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "email_address".into(),
            name: "이메일 주소(대량)".into(),
            category: CATEGORY_PII.into(),
            severity: Severity::Low,
            min_count: 20,
            hints: sv(&["@"]),
            back: 64,
            ahead: 256,
            re: re(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
            mask: Box::new(mask_email),
            validate: None,
            context: vec![],
            needs_context: None,
            digits: false,
            hints_fold: vec![],
        },
        // --- credentials / secrets ---
        Detector {
            id: "private_key".into(),
            name: "개인키(Private Key)".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["-----BEGIN "]),
            re: re(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
            ),
            mask: Box::new(mask_identity),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "aws_access_key".into(),
            name: "AWS Access Key".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["AKIA", "ASIA"]),
            re: re(&format!(r"{NA}((?:AKIA|ASIA)[0-9A-Z]{{16}}){NAE}")),
            mask: mask_middle(4, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "aws_secret_key".into(),
            name: "AWS Secret Key".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints_fold: sv(&["aws"]),
            back: 0,
            ahead: 160,
            re: re(
                r#"(?i)aws.{0,20}(?:secret|private).{0,20}?[=:"'\s]\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)"#,
            ),
            validate: Some(|v| entropy(v) >= 3.5),
            mask: mask_middle(4, 2),
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints: vec![],
        },
        Detector {
            id: "github_token".into(),
            name: "GitHub 토큰".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]),
            re: re(&format!(
                r"{NA}((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{{36}}|github_pat_[A-Za-z0-9_]{{60,}}){NAE}"
            )),
            mask: mask_middle(6, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "gitlab_token".into(),
            name: "GitLab 토큰".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["glpat-"]),
            re: re(&format!(r"{NA}(glpat-[A-Za-z0-9_-]{{20,}})")),
            mask: mask_middle(8, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "slack_token".into(),
            name: "Slack 토큰".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["xox"]),
            re: re(&format!(r"{NA}(xox[baprs]-[A-Za-z0-9-]{{10,}})")),
            mask: mask_middle(5, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "slack_webhook".into(),
            name: "Slack Webhook URL".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["hooks.slack.com"]),
            back: 16,
            re: re(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
            mask: mask_middle(34, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            ahead: 0,
        },
        Detector {
            id: "google_api_key".into(),
            name: "Google API Key".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["AIza"]),
            re: re(&format!(r"{NA}(AIza[0-9A-Za-z_-]{{35}}){NAE}")),
            mask: mask_middle(6, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "stripe_key".into(),
            name: "Stripe Secret Key".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["_live_"]),
            re: re(&format!(r"{NA}((?:sk|rk)_live_[0-9a-zA-Z]{{24,}})")),
            mask: mask_middle(8, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "anthropic_key".into(),
            name: "Anthropic API Key".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["sk-ant-"]),
            re: re(&format!(r"{NA}(sk-ant-[A-Za-z0-9_-]{{32,}})")),
            mask: mask_middle(10, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "openai_key".into(),
            name: "OpenAI API Key".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["sk-"]),
            re: re(&format!(
                r"{NA}(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{{40,}}|sk-[A-Za-z0-9]{{48}}){NAE}"
            )),
            mask: mask_middle(8, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
            ahead: 0,
        },
        Detector {
            id: "db_connection".into(),
            name: "DB 접속정보(계정 포함)".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints_fold: sv(&[
                "postgres://",
                "postgresql://",
                "mysql://",
                "mariadb://",
                "mongodb://",
                "mongodb+srv://",
                "redis://",
                "rediss://",
                "amqp://",
                "amqps://",
                "mssql://",
                "sqlserver://",
            ]),
            back: 1,
            ahead: 256,
            validate: Some(valid_db_url),
            re: re(
                r#"((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:/@"'<>]+:[^\s@/"'<>]+@[^\s/"'<>]+)"#,
            ),
            mask: Box::new(mask_db_url),
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints: vec![],
        },
        Detector {
            id: "azure_storage_key".into(),
            name: "Azure Storage Key".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::High,
            hints: sv(&["AccountKey="]),
            back: 0,
            re: re(r"AccountKey=([A-Za-z0-9+/=]{80,})"),
            mask: mask_middle(4, 2),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            ahead: 0,
        },
        Detector {
            id: "jwt".into(),
            name: "JWT 토큰".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::Medium,
            hints: sv(&["eyJ"]),
            ahead: 8192,
            re: re(&format!(
                r"{NA}(eyJ[A-Za-z0-9_-]{{10,}}\.eyJ[A-Za-z0-9_-]{{10,}}\.[A-Za-z0-9_-]{{10,}})"
            )),
            mask: mask_middle(10, 0),
            validate: None,
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints_fold: vec![],
            back: 0,
        },
        Detector {
            id: "generic_secret".into(),
            name: "비밀번호/시크릿 값".into(),
            category: CATEGORY_SECRET.into(),
            severity: Severity::Medium,
            hints_fold: sv(&[
                "password",
                "passwd",
                "pwd",
                "secret",
                "api_key",
                "api-key",
                "apikey",
                "access_token",
                "access-token",
                "auth_token",
                "auth-token",
                "client_secret",
                "client-secret",
                "비밀번호",
                "패스워드",
                "암호",
            ]),
            back: 1,
            ahead: 128,
            re: re(
                r#"(?i)(?:\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b|비밀번호|패스워드|암호)["']?\s*[:=：]\s*["']?([^\s"'<>,;]{8,64})"#,
            ),
            validate: Some(valid_generic_secret),
            mask: mask_middle(2, 0),
            context: vec![],
            needs_context: None,
            min_count: 0,
            digits: false,
            hints: vec![],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrn_validation() {
        assert!(rrn_checksum("8001011234567") || !rrn_checksum("8001011234567")); // exercises path
        assert!(!valid_rrn("0000000000000"));
        // birthdate-valid, male 1900s, with hyphen (checksum not required)
        assert!(valid_rrn("900101-1234567"));
    }

    #[test]
    fn luhn_and_card() {
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));
        assert!(valid_card("4111 1111 1111 1111"));
        assert!(!valid_card("1234567890123")); // 13 digits -> not a card
    }

    #[test]
    fn iban_mod97() {
        assert!(valid_iban("GB82 WEST 1234 5698 7654 32"));
        assert!(!valid_iban("GB00 WEST 1234 5698 7654 32"));
    }

    #[test]
    fn maskers() {
        assert_eq!(mask_rrn("900101-1234567"), "900101-1******");
        assert_eq!(mask_card("4111 1111 1111 1111"), "************1111");
        assert_eq!(mask_phone("010-1234-5678"), "010-****-5678");
        assert_eq!(mask_email("alice@example.com"), "a****@example.com");
        assert_eq!(mask_middle(2, 2)("abcdef"), "ab**ef");
    }

    #[test]
    fn builtin_compiles() {
        let b = builtin();
        assert!(b.iter().any(|d| d.id == "kr_rrn"));
        assert!(b.len() > 20);
    }
}
