# 발신 메일 DLP (개인정보·인증정보 유출 방지)

내부 메일 서버가 **외부로 보내는 메일**을 secmail이 먼저 받아 본문과 첨부파일을 검사합니다. 개인정보나 API 키가 있으면 정책에 따라 알리거나, 보류하거나, 차단합니다.

```
사용자 ─→ 내부 메일서버 ──(외부행 메일)──→ secmail :10025 ──검사──→ next_hop ──→ 인터넷
                                               │
                     허용 / 알림 / 보류(관리자 승인) / 차단
                                               │
                         발신자·보안담당자 알림 메일, 감사 로그(dlp_events)
```

## 탐지 항목

| ID | 항목 | 등급 | 오탐 방지 |
|---|---|---|---|
| `kr_rrn` | 주민등록번호 / 외국인등록번호 | high | 생년월일 유효성, 성별자리 1~8. 하이픈 없는 13자리는 체크섬까지 일치해야 함 |
| `credit_card` | 신용카드번호 | high | Luhn 체크섬, 발급사 BIN(Visa/Master/Amex/JCB/UnionPay/국내). 구분자 없는 숫자열은 주변에 '카드·결제·card' 같은 단어가 있어야 인정 |
| `kr_passport` | 여권번호 | medium | 주변 60자 안에 '여권/passport'가 있어야 인정 |
| `kr_driver_license` | 운전면허번호 | medium | 지역코드 11~28 |
| `kr_biz_reg` | 사업자등록번호 | medium | 10자리 검증 숫자(체크섬) 일치 |
| `kr_corp_reg` | 법인등록번호 | medium | 13자리 검증 숫자(체크섬) 일치 |
| `bank_account` | 계좌번호 | medium | 주변에 '계좌·예금주·은행·송금' 또는 은행명이 있어야 인정, 10~16자리 |
| `iban` | IBAN(해외계좌) | medium | ISO 7064 mod-97 체크섬 일치 |
| `kr_mobile` | 휴대전화번호 **대량** | medium | 한 위치에 서로 다른 번호 5개 이상 (서명의 연락처는 제외됨) |
| `email_address` | 이메일 주소 **대량** | low | 20개 이상 |
| `private_key` | 개인키 (RSA/EC/OpenSSH/PGP) | high | PEM 헤더 |
| `aws_access_key` / `aws_secret_key` | AWS 키 | high | 접두어, 엔트로피 |
| `github_token`, `gitlab_token`, `slack_token`, `slack_webhook`, `google_api_key`, `stripe_key`, `anthropic_key`, `openai_key`, `azure_storage_key` | 클라우드·SaaS 키 | high | 서비스별 고정 형식 |
| `db_connection` | 계정이 포함된 DB 접속 URL | high | `user:password@` 형태. `password`, `${...}` 같은 예시·플레이스홀더는 제외 |
| `jwt` | JWT 토큰 | medium | `eyJ…` 3조각 |
| `generic_secret` | `password=`, `api_key:`, `비밀번호:` 뒤의 값 | medium | 엔트로피 3.0 이상, `****`·`your_…`·`example` 등 예시값 제외 |
| `pii_combination` | 신원 항목의 결합·대량 (파생) | high | 아래 [개인정보 결합·대량 탐지](#개인정보-결합대량-탐지-dlpcombine_pii) 참조 |

- 알림과 관리자 화면에는 **마스킹된 값만** 표시하고 저장합니다 (예: `900101-1******`, `AKIA**************LE`).
- 조직 전용 패턴은 `dlp.rules`에 추가합니다 (정규식, 캡처 그룹 1개까지).
- 특정 탐지기를 끄려면 `dlp.disabled`, 대량 판정 기준을 바꾸려면 `dlp.min_counts`를 씁니다.

## 첨부파일 형식

| 형식 | 방식 |
|---|---|
| txt, csv, json, xml, html, log, env, yaml, 소스코드 등 | UTF-8/UTF-16/EUC-KR 자동 판별 |
| docx, xlsx, pptx, odt/ods, **hwpx** | ZIP 안의 XML 추출 (Word의 쪼개진 텍스트 조각 결합, 엑셀 셀 구분) |
| **hwp (한글 5.x)** | OLE → BodyText 섹션 해제 → 문단 텍스트 |
| pdf | 텍스트 레이어 추출 |
| zip, **gzip, tar, tar.gz** | Go 표준 라이브러리로 해제 |
| **7z, RAR, xz, zstd** | 7-Zip CLI로 해제 (`sevenzip_command`, 자동 탐지) |
| 압축파일 공통 | 최대 3단계 중첩, 파일 500개, 해제 200MB 한도 (압축폭탄 방지) |
| doc, xls, ppt (구형) | 스트림에서 문자열 추출 |
| 첨부된 메일(.eml) | 재귀 검사 |
| **이미지** (png/jpg/gif/bmp/tiff/webp) | **OCR** (아래 참고) |
| 동영상·음성·실행파일 | 검사 대상 아님 |

다음 파일은 내용을 볼 수 없으므로 **검사 불가**로 보고되고, `actions.uninspectable` 정책이 적용됩니다.
- 암호화된 zip 항목
- 열람 암호가 걸린 Office·PDF·HWP 문서 (열람 암호 없이 편집·인쇄만 제한된 PDF는 poppler로 검사됨)
- 한글 **배포용 문서**
- OCR 한도(이미지 수·시간·PDF 페이지 수)를 넘긴 이미지
- 변환 도구가 설치되지 않은 환경의 HEIC/AVIF 사진, JBIG2/JPEG2000 스캔 PDF (Docker 이미지에는 모두 포함)

## 이미지 OCR (`dlp.ocr`)

[Tesseract](https://github.com/tesseract-ocr/tesseract)(한국어+영어)로 이미지 속 글자를 읽은 뒤 같은 탐지기로 검사합니다.

| OCR 대상 | 위치 표기 예 |
|---|---|
| 이미지 첨부파일 (스크린샷, 휴대폰 사진) | `첨부 캡처.png (OCR)` |
| 본문에 삽입된 이미지 | `본문 삽입 이미지 (OCR)` |
| 문서에 붙여 넣은 그림 (docx/xlsx/pptx `media/`, hwpx `BinData/`, **hwp BinData**, odt `Pictures/`) | `첨부 가이드.docx > word/media/image1.png (OCR)` |
| **스캔 PDF** 페이지 이미지 | `첨부 scan.pdf > 이미지 1 (OCR)` 또는 `> 페이지 1 (OCR)` |
| **HEIC/AVIF** 사진 (아이폰 기본 형식) | `첨부 IMG_2231.heic (OCR)` |
| zip 안의 위 파일들 | `첨부 a.zip > 신분증.jpg (OCR)` |

### 형식별 처리

Go로 바로 디코딩하는 형식과, 외부 도구로 변환한 뒤 OCR하는 형식이 있습니다.

| 형식 | 처리 |
|---|---|
| PNG, JPEG, GIF, BMP, TIFF(팩스 G3/G4 포함), WebP | Go 디코더 |
| PDF 이미지: DCT(JPEG), Flate 8비트·**1비트**, ASCII85/ASCIIHex 체인, PNG predictor, **CCITT G4 / G3 1D** | Go 디코더 (`x/image/ccitt`) |
| **HEIC / AVIF** | libheif `heif-dec`(또는 `heif-convert`)로 PNG 변환 |
| PDF 이미지: **JBIG2**, **JPEG2000**, CCITT G3 2D | poppler `pdftoppm`으로 **페이지 전체를 렌더링** (최대 `pdf_max_pages`쪽, 긴 변 `pdf_scale_to`px) |
| Go 파서가 못 여는 PDF (AES-256 암호화, 비표준 구조, **열람 암호 없는 사용 제한 PDF**) | poppler `pdftotext`로 텍스트 레이어 추출 + 페이지 렌더링 OCR |

- 페이지를 렌더링하는 PDF는 개별 추출한 이미지를 버리고 페이지 이미지만 OCR합니다. 같은 내용이 두 번 탐지되지 않습니다.
- 변환 도구는 시작할 때 PATH에서 자동으로 찾고 로그에 남깁니다 (`dlp converters`). 없으면 해당 파일만 "검사 불가"로 보고됩니다. `none`으로 끌 수도 있습니다.
- 외부 도구는 신뢰할 수 없는 파일을 처리하는 C 프로그램입니다. 다음과 같이 격리해서 실행합니다.
  - 시간 제한과 동시 실행 수 제한을 적용합니다.
  - 파일마다 전용 임시 디렉터리를 만들고 처리 후 삭제합니다.
  - 컨테이너 안에서 root가 아닌 사용자로 실행합니다.
  - 추가로 격리하려면 게이트웨이를 seccomp·read-only 파일시스템 컨테이너로 실행하세요.

### OCR 전처리
- OCR 전에 흑백 변환, 작은 이미지 확대·큰 이미지 축소, **대비 정규화**, **기울기 보정(deskew, ±8°)** 을 적용합니다. 비뚤게 찍은 사진이나 스캔의 인식률이 올라갑니다. 흑백 반전된 팩스 이미지는 자동으로 뒤집습니다.
- 글자 사이가 벌어진 한글(`주 민 등 록 번 호`)을 붙여서, '여권'·'카드' 같은 문맥 단어 검사가 동작하게 합니다.
- OCR이 자주 헷갈리는 글자를 **숫자 덩어리 안에서만** 보정합니다 (`O→0`, `l/I/|→1`, `900101 - 1234567`의 공백 제거). 일반 단어는 건드리지 않습니다.
- 서명 로고처럼 같은 이미지가 반복되면 한 번만 OCR하고, 아이콘처럼 작은 이미지(`min_pixels` 미만)는 건너뜁니다.
- 부하 제한:
  - 메일당 `max_images`(20개), 이미지당 `timeout`(20초), 메일당 `total_timeout`(60초)
  - 메일당 동시 처리 `concurrency`(2), 서버 전체 동시 tesseract 프로세스 `max_processes`(4)
  - 한도를 넘은 이미지는 **검사 불가**로 보고되어 `actions.uninspectable` 정책을 따릅니다.
- 처리 시간은 A4 한 장 분량 이미지 기준 약 0.3~1초입니다. SMTP 응답이 그만큼 늦어집니다.
- Docker 이미지에는 tesseract(한국어 데이터), libheif, poppler가 모두 포함되어 있습니다. 직접 설치할 때는 다음 패키지를 설치합니다.
  - Debian/Ubuntu: `apt install tesseract-ocr tesseract-ocr-kor libheif-examples libheif-plugin-libde265 libheif-plugin-dav1d poppler-utils`
  - Alpine: `apk add tesseract-ocr tesseract-ocr-data-kor libheif-tools poppler-utils` `ocr.enabled: true`인데 설치되어 있지 않으면 시작 시 오류로 알려줍니다.

정확도 한계:
- 인쇄체·화면 캡처는 잘 읽습니다. 손글씨, 심하게 기울거나 흐린 사진, 배경이 복잡한 신분증 사진은 놓칠 수 있습니다.
- OCR은 보조 수단입니다. 신분증 사본처럼 반드시 막아야 하는 경우에는 `dlp.rules`에 "신분증", "주민등록증" 같은 파일명·제목 규칙을 함께 두기를 권장합니다.

## 정책 (`dlp.actions`)

| 동작 | 메일 | 알림 |
|---|---|---|
| `allow` | 발송 | 없음 (감사 로그만 기록) |
| `notify` | 발송 | 발신자와 보안담당자에게 알림. 인증정보가 포함됐으면 즉시 폐기(재발급) 안내 |
| `hold` | **보류** (발신자에게는 정상 접수로 응답) | 발신자에게 보류 안내, 보안담당자에게 검토 링크 발송 |
| `block` | 거부 (`550 5.7.1 Message blocked by data loss prevention policy (…)`) | 발신자와 보안담당자에게 알림. 내부 메일 서버가 반송 메일도 생성 |

### 암호가 걸린 첨부파일 (`dlp.actions.encrypted`)

암호가 걸린 압축파일(zip/7z/rar)·PDF·Office 문서는 내용을 볼 수 없으므로 별도 정책을 적용합니다. 기본값은 `hold`(보류)입니다. `""`로 두면 `uninspectable`과 같게 동작합니다.

- 게이트웨이는 암호를 추측하거나 우회하지 않습니다. 열 수 없는 파일은 "암호 잠김"으로 보고하고 정책에 따라 처리합니다.
- 발신자에게는 "암호 파일 대신 회사가 승인한 보안 전송 수단을 이용하라"는 안내를 보냅니다.
- 관리자는 검토 화면에서 발신자에게 확인한 뒤 승인·반려합니다.
- HWP 열람 암호·배포용 문서처럼 형식이 비공개라 열 수 없는 것도 이 정책을 따릅니다.

메일 한 통의 최종 동작은 발견 항목들의 등급별 동작 중 **가장 엄격한 것**입니다.

### 개인정보 결합·대량 탐지 (`dlp.combine_pii`)

개별 항목 하나하나는 위험도가 낮아도, 한곳에 여러 종류가 모이면 특정 개인을 식별할 수 있는 데이터셋이 되어 위험도가 급격히 올라갑니다. 게이트웨이는 이런 경우를 별도 항목 `pii_combination`(high)으로 승격합니다.

- **결합**: 같은 위치(본문, 또는 하나의 첨부/이미지)에서 서로 다른 신원 항목이 `combine_min_pii`개(기본 2) 이상 발견되면 high로 승격합니다. 대상은 신원과 직접 연결되는 항목(주민등록번호·여권·운전면허·신용카드·계좌·휴대전화·이메일 등)이며, API 키·비밀번호 같은 인증정보는 결합 계산에서 제외합니다.
- **대량**: 한 종류라도 `combine_bulk`개(기본 20) 이상 나오면(예: 전화번호 200개가 담긴 명단 파일) high로 승격합니다.
- `pii_combination`은 파생 항목이므로 원본 항목은 그대로 함께 보고되고, 탐지 건수 메트릭에는 중복으로 집계되지 않습니다.
- `combine_pii: false`로 끌 수 있습니다.

예외 설정:
- `exempt_senders`: 이 발신자의 메일은 검사하지 않습니다 (예: 급여 명세 발송 시스템).
- `exempt_recipient_domains`: 수신자가 **모두** 이 도메인이면 탐지 내용은 기록하되 `allow`로 처리합니다 (계약된 위탁사 등).
- `scan_internal: false` (기본): 수신자가 모두 사내 도메인인 메일은 검사하지 않습니다.

## 보류 메일 검토

1. 보안담당자(`dlp.admins`)가 알림 메일의 **검토 링크**를 엽니다 (`https://<portal>/dlp/<token>`).
2. `portal.auth`가 `otp`나 `header`면 관리자 본인 확인을 거칩니다. `dlp.admins`에 있는 주소만 통과합니다.
3. 화면에서 탐지 내역(마스킹)을 보고 **승인 후 발송** 또는 **반려(사유 입력)** 를 누릅니다.
   - 승인하면 원본을 `next_hop`으로 그대로 전달합니다. 전달에 실패하면 보류 상태로 되돌아가 다시 시도할 수 있습니다.
   - 반려하면 원본을 삭제하고, 발신자에게 사유를 포함한 결과를 알립니다.
   - `hold_ttl`(기본 72시간)이 지나면 **발송하지 않고 폐기**합니다 (fail-closed).
4. 원본 메일은 결정 즉시 저장소에서 삭제되고, DB에는 마스킹된 탐지 내역만 남습니다.

관리 API (`internal_api.admin_token`, 분석 엔진 토큰과 별도):
```bash
curl -H "Authorization: Bearer $ADMIN" http://secmail:8081/internal/v1/dlp/holds?status=HELD
curl -H "Authorization: Bearer $ADMIN" -d '{"by":"sec@example.com"}' \
     http://secmail:8081/internal/v1/dlp/holds/<id>/release
curl -H "Authorization: Bearer $ADMIN" -d '{"by":"sec@example.com","reason":"마스킹 후 재발송"}' \
     http://secmail:8081/internal/v1/dlp/holds/<id>/reject
curl -H "Authorization: Bearer $ADMIN" http://secmail:8081/internal/v1/dlp/events?limit=100
```

`events` 목록은 `action`(allow/notify/hold/block/exempt)·`severity`(high/medium/low/…)로 서버측 필터링할 수 있습니다(예: `?action=block&severity=high`). `holds`·`events` 목록은 `limit`(최대 500)과 **커서 페이지네이션**을 지원합니다. 응답이 `limit`만큼 가득 차면 `X-Next-Cursor` 헤더에 다음 페이지 커서가 담기며, 이를 `?cursor=` 로 넘겨 이어서 조회합니다(시각·id 복합 키 기준이라 같은 시각의 항목도 누락·중복 없이 페이징됩니다).
```bash
next=$(curl -sD - -H "Authorization: Bearer $ADMIN" \
       "http://secmail:8081/internal/v1/dlp/events?limit=100" | grep -i x-next-cursor | cut -d' ' -f2 | tr -d '\r')
curl -H "Authorization: Bearer $ADMIN" "http://secmail:8081/internal/v1/dlp/events?limit=100&cursor=$next"
```

## 감사 로그

탐지 내역이 있는 모든 발신 메일은 `dlp_events` 테이블에 기록됩니다: 발신자, 수신자, 제목, 동작, 최고 등급, 마스킹된 탐지 내역, 보류 ID.

```sql
-- 최근 7일 발신자별 고위험 발송 시도 건수
SELECT mail_from, count(*) FROM dlp_events
WHERE severity = 'high' AND at > now() - interval '7 days'
GROUP BY 1 ORDER BY 2 DESC;
```

## 메일 서버 연결

아래 설정 예시는 [deployment.md의 발신 메일 절](deployment.md#7-발신-메일-dlp-연동)에 있습니다.
- Postfix: `content_filter` + 재주입 포트
- Exchange: 스마트 호스트 Send Connector
- Microsoft 365 / Google Workspace: 아웃바운드 커넥터 / Outbound gateway

secmail은 발신 메일을 **수정하지 않고** 전달하므로, 내부 서버가 넣은 DKIM 서명이 그대로 유효합니다.

## 성능

- 탐지기는 리터럴 힌트(`AKIA`, `ghp_`, `password` 등)나 숫자 토큰 위치 주변에서만 정규식을 실행합니다. 숫자가 빽빽한 최악 조건에서 약 40MB/s입니다 (`go test -bench ScanText ./internal/dlp`).
- 소스코드·문서 2만여 파일(217MB) 코퍼스 기준 검사 시간은 6초이고, 카드번호 오탐은 2건이었습니다.
- OCR은 이미지당 약 0.3~1초로, 텍스트 검사보다 훨씬 비쌉니다. 위의 한도 설정으로 조절하세요.
