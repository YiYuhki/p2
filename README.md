# secmail — 첨부파일 격리 + 발신 DLP 보안 메일 게이트웨이

메일 서버 앞단의 SMTP 프록시입니다.

- **수신**: 첨부파일을 분리해 오브젝트 스토리지에 격리하고, 본문에는 다운로드 링크 배너를 넣어 실제 메일 서버로 전달합니다. 외부 분석 엔진이 파일을 검사하고, `CLEAN` 판정을 받은 파일만 포털에서 받을 수 있습니다.
- **발신 (DLP)**: 외부로 나가는 메일의 본문과 첨부파일(docx/xlsx/pptx, hwp/hwpx, pdf, zip 등)에서 주민등록번호, 카드번호, API 키, 개인키 같은 민감정보를 찾아냅니다. 정책에 따라 알림, 보류(관리자 승인), 차단 중 하나를 적용합니다 → [docs/dlp.md](docs/dlp.md)

> 정적/동적 분석 엔진은 **별도 프로젝트**입니다. 연동 규격은 [docs/analyzer-contract.md](docs/analyzer-contract.md),
> DNS·내부 메일서버(Postfix/Exchange/M365/Google)·포털 운영 설정은 [docs/deployment.md](docs/deployment.md)에 있습니다.

```
 인터넷 MTA ──SMTP──▶ ┌──────────── secmail ────────────┐ ──SMTP──▶ 내부 메일서버
                      │ SMTP Proxy (go-smtp)            │          (Exchange/Postfix…)
                      │  ├ MIME 파싱 → 첨부 분리         │
                      │  ├ 배너(링크) 삽입 · DKIM 재서명 │
                      │  └ Quarantine ──▶ S3/MinIO      │
                      │                ──▶ PostgreSQL   │
                      │                ──▶ Redis jobs ──┼──▶ [외부 분석 엔진]
                      │ Internal API ◀── verdict ───────┼───┘
                      │ Download Portal ◀── 사용자 클릭  │
                      │ Janitor (재시도 · 만료 삭제)     │
                      └─────────────────────────────────┘
```

## 주요 동작

### 1. SMTP Proxy (`internal/gateway`, `internal/mimeproc`)
- **Before-queue 방식**: MAIL/RCPT를 업스트림에 즉시 전달하므로, 업스트림의 수신자 거부(550 등)가 그대로 발신 MTA에 전달됩니다. 업스트림이 재작성된 메일을 수락해야만 250을 응답하므로 로컬 스풀이 없습니다.
- 스토리지/DB 장애 시 `451` 임시 오류로 응답 → 발신 MTA가 재시도 (메일 유실 없음).
- `accepted_domains` 밖의 수신자는 `550 Relaying denied` (오픈 릴레이 방지).
- 첨부 판별: `Content-Disposition: attachment`, 파일명 있는 파트, 이름 없는 비텍스트 파트, 전달된 메일(`message/rfc822`). HTML에 삽입된 인라인 이미지(`Content-ID`)는 옵션으로 유지.
- 원본 파트는 바이트 단위로 보존하고, 배너가 들어가는 text/plain · text/html 파트만 UTF-8 + QP로 재인코딩 (EUC-KR/`ks_c_5601-1987` 본문 · 파일명 디코딩 지원).
- 첨부만 있는 메일, 단일 파트 첨부 메일은 안내 파트를 새로 만듭니다.
- **파싱 불가 메일은 전체를 `original-message.eml`로 격리** (fail-closed). MIME 구조 제한: 중첩 깊이 32, 전체 파트 수 10,000(초과 시 통째 격리 — 파트 폭탄 증폭 공격 방어).
- SMTP 리스너에 동시 연결 수·IP별 연결 수 제한(초과 시 421), 최대 라인/메시지 크기, 읽기/쓰기 타임아웃(slow-loris 방지).
- S/MIME·PGP 서명 메일: `rewrite`(서명 래퍼 제거 + 안내) / `passthrough`. 암호화 메일: `passthrough` / `reject`.
- 발신자가 넣은 `X-SecMail-*` 헤더는 제거(위조 방지)하고 `X-SecMail-Processed`, `Received`, `Authentication-Results`를 추가.

### 2. 인바운드 인증 (DKIM · SPF · DMARC)
- **DKIM**: 수정 전 원본 서명을 검증해 `Authentication-Results`에 기록 (`dkim.verify_inbound`). 메일을 수정한 경우 깨진 원본 서명은 `X-SecMail-Original-DKIM-Signature`로 이름을 바꿔 보존.
- **SPF** (`spf.verify_inbound`): 접속 IP를 MAIL FROM(널 반송경로는 HELO) 도메인의 SPF 레코드와 대조해 `spf=...`를 기록.
- **DMARC** (`dmarc.verify_inbound`): From 헤더 도메인 기준으로 SPF·DKIM 정렬(relaxed/strict, 조직 도메인 폴백)을 평가해 `dmarc=...`를 기록. 평가만 하며 거부는 내부 서버 정책에 맡깁니다.
- 세 결과는 하나의 `Authentication-Results`로 합쳐지고, **게이트웨이 authserv-id를 사칭한 인바운드 헤더는 제거**합니다(RFC 8601 §5). 결과는 `secmail_inbound_auth_total{method,result}` 메트릭으로도 노출.
- 게이트웨이 키로 재서명 (relaxed/relaxed, RSA 또는 Ed25519). 키 생성: `secmail dkim-keygen -domain example.com -selector secmail`.
- 내부 메일 서버는 게이트웨이 IP와 게이트웨이 DKIM 서명, 그리고 `TrustedAuthservIDs`에 게이트웨이 hostname만 신뢰하도록 설정하세요.

### 3. 비동기 분석 연동 (`internal/service`, `internal/queue`)
- 첨부 저장 → DB `PENDING` 등록 → Redis `secmail:jobs:high` 에 작업 발행 (재시도는 `:normal`).
- 판정 수신 경로 2가지: Internal API `POST .../verdict` 또는 Redis `secmail:results`.
- 동일 SHA-256 파일은 `verdict_reuse_window` 동안 기존 판정 재사용 → 즉시 결과 제공.
- Janitor: `analysis.timeout` 초과 `PENDING` 재큐잉, `max_attempts` 초과 시 `ERROR`(다운로드 차단), `link_ttl` 지난 파일은 오브젝트 삭제 후 `EXPIRED`.

### 4. 다운로드 포털 (`internal/portal`)
| 상태 | 화면 |
|---|---|
| `PENDING` | "보안 검사가 진행 중입니다" + 3초 폴링, 완료 시 자동 갱신 |
| `CLEAN` | "검증이 완료된 안전한 파일입니다" + 다운로드 버튼 |
| `MALICIOUS` | 다운로드 차단, 탐지명 표시 (403) |
| `ERROR` | 검사 실패 → 차단 (403, fail-closed) |
| `EXPIRED` | 링크 만료 (410) |

수신자 인증 (`portal.auth.mode`):
- `otp`: 메일을 받은 주소를 입력하면 6자리 인증 코드를 메일로 보내고, 확인되면 서명된 세션 쿠키를 발급합니다. **해당 메일의 SMTP 수신자만** 파일에 접근할 수 있으므로 링크가 전달·유출되어도 다른 사람은 받을 수 없습니다.
- `header`: oauth2-proxy 등 SSO 리버스 프록시가 넣어준 이메일 헤더로 판단합니다.
- `none`: 링크 소유만으로 접근 (테스트용).
- 배포 그룹 주소로 받은 메일은 `allow_domain_users: true`로 사내 도메인 사용자 전체를 허용할 수 있습니다.
- 모든 다운로드는 `download_events` 테이블에 사용자·IP·User-Agent와 함께 기록됩니다.

보안 설계:
- 링크 토큰은 256-bit 난수, DB에는 **SHA-256 해시만** 저장 (DB 유출 시에도 링크 사용 불가).
- 실제 다운로드는 **POST로만 발급되는 1회용 티켓**(기본 60초)을 거칩니다 → Outlook Safe Links 같은 링크 스캐너가 GET으로 파일을 가져가지 못함.
- 전송 직전 판정 재확인, `application/octet-stream` + RFC 5987 파일명의 `attachment` 강제(인라인 렌더링 차단), `nosniff`, nonce 기반 CSP.
- IP별 rate limit에 더해 **토큰 열거 방어**: 실패한 조회에 별도 per-IP·전역 예산을 두어 분산 추측도 억제(존재 여부는 노출 안 함). 조회 결과는 `secmail_portal_requests_total{outcome}` 메트릭으로 노출.
- `Sec-Fetch-Site`/`Origin` 검사로 교차 사이트 POST(CSRF) 차단, 인증 페이지에서는 파일명도 노출하지 않음.

### 5. 발신 메일 DLP (`internal/dlp`, `internal/outbound`)
- 내부 메일 서버의 외부행 메일을 `outbound.listen`(10025)에서 받아 검사한 뒤 `next_hop`으로 전달합니다. 허용된 내부 서버와 자사 발신 도메인만 릴레이할 수 있습니다.
- 한국 개인정보(주민/외국인등록번호, 여권, 운전면허, 대량 휴대전화)와 카드번호, 클라우드·SaaS API 키, 개인키, DB 접속정보, JWT, 비밀번호를 탐지합니다. 체크섬, 날짜, 문맥 단어, 엔트로피 검사로 오탐을 줄였습니다.
- **이미지 OCR**(Tesseract 한국어+영어): 스크린샷, 사진(HEIC/AVIF 포함), 스캔 PDF(JBIG2·JPEG2000·CCITT 포함), 문서에 붙여 넣은 그림 속 글자도 검사합니다.
- 등급별 동작(`allow / notify / hold / block`), 검사 불가(`uninspectable`)·암호 파일(`encrypted`) 정책을 지정합니다. 발신자와 보안담당자에게 마스킹된 탐지 내역을 메일로 알립니다.
- 한 위치에 신원 정보가 여러 종 모이거나 대량으로 나오면 `pii_combination`(high)으로 **승격**합니다(개별 항목은 낮아도 식별 가능한 데이터셋은 위험).
- 보류된 메일은 포털 검토 화면(`/dlp/<token>`), 관리자 대시보드(`/dlp/admin`, 인증 필요·`dlp.admins` 전용), 또는 관리 API에서 승인·반려합니다. 기한이 지나면 발송하지 않고 폐기합니다.
- 모든 탐지는 `dlp_events` 감사 테이블에 남고, 관리 API의 목록은 커서 페이지네이션과 action·severity 필터를 지원합니다.

## 빠른 시작 (Docker)

```bash
docker compose -f deploy/docker-compose.yml up --build
# 테스트 메일 발송 (수신자는 @example.com)
swaks --server localhost:2525 --to user@example.com --attach @report.pdf
# 내부 메일서버(mailpit)가 받은 메일: http://localhost:8025 → 링크 클릭 → http://localhost:8080/d/...
# 데모는 otp 모드: 포털에 user@example.com 입력 → 인증 코드 메일도 mailpit에 도착
# 발신 DLP: 주민번호가 든 메일을 localhost:10025로 보내면 보류 → security@example.com 앞 검토 링크
swaks --server localhost:10025 --from kim@example.com --to partner@ext.org --body "고객 900101-1234567"
```
S3는 RustFS(MinIO 호환) 컨테이너를 씁니다 (MinIO는 공식 이미지 배포를 중단). 운영에서는 MinIO/AWS S3를 그대로 쓰면 됩니다.
`mock-analyzer`는 EICAR 문자열이 있으면 `MALICIOUS`, 아니면 `CLEAN`을 회신하는 참고 구현입니다.
실제 악성코드 분석은 malengine 엔진([`../p1`](../p1))을 임베드한 [`analyzer/`](analyzer/)로 하며, 두 형태를 지원합니다:
- **독립 워커**(redis): `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.analyzer.yml up --build`
- **secmail 인프로세스**(`-tags malengine`, memory 큐 포함): config `analyzer.enabled: true` — 둘은 같은 `scan` 코드를 공유합니다.

## 직접 실행

```bash
go build -o secmail ./cmd/secmail
cp config.example.yaml config.yaml   # 환경에 맞게 수정
./secmail -config config.yaml                           # 전체
./secmail -config config.yaml -components smtp          # SMTP 프록시만
./secmail -config config.yaml -components portal,api,worker
```
컴포넌트를 분리하면 SMTP·포털을 각각 수평 확장할 수 있습니다 (상태는 PostgreSQL/Redis/S3에 있음).
개발용으로 `database.type: memory`, `queue.type: memory`, `storage.type: fs`를 쓸 수 있습니다.

## 설정
전체 항목은 [config.example.yaml](config.example.yaml) 참고. `${ENV}` 형식으로 비밀값을 환경변수에서 주입합니다.

## 디렉터리

| 경로 | 내용 |
|---|---|
| `cmd/secmail` | 메인 바이너리, `dkim-keygen` 서브커맨드 |
| `cmd/mock-analyzer` | 분석 엔진 대역 (연동 참고용) |
| `analyzer/` | 실제 첨부 분석 워커 — malengine(`../p1`) 임베드 (별도 모듈) |
| `internal/gateway` | SMTP 세션/업스트림 릴레이, 메시지 처리, 배너 |
| `internal/mimeproc` | MIME 트리 파싱 · 첨부 분리 · 배너 삽입 |
| `internal/dkimutil` | DKIM 검증/재서명 |
| `internal/spfutil` | 인바운드 SPF 검증 |
| `internal/dmarc` | 인바운드 DMARC 정렬 평가 |
| `internal/authres` | Authentication-Results 값 sanitize (공용) |
| `internal/metrics` | Prometheus 메트릭 (private registry) |
| `internal/service` | 격리 저장, 판정 반영, janitor |
| `internal/portal` | 다운로드 포털, 수신자 인증(OTP/SSO 헤더), 1회용 티켓, rate limit |
| `internal/internalapi` | 분석 엔진용 인증 API |
| `internal/store` | PostgreSQL(내장 마이그레이션) / 메모리 저장소 |
| `internal/storage` | S3·MinIO / 파일시스템 |
| `internal/dlp` | 민감정보 탐지기, 첨부 텍스트 추출(Office/HWP/PDF/ZIP) |
| `internal/outbound` | 발신 DLP 정책(알림/보류/차단), 보류 승인·반려, 알림 메일 |
| `internal/notify` | 게이트웨이 알림 메일 생성·발송 |
| `internal/smtpclient` | 업스트림 SMTP 연결 (STARTTLS, 사용자 지정 HELO) |
| `internal/queue` | Redis / 메모리 큐 |

## 테스트

```bash
go test ./...          # 단위 + 종단간 (외부 인프라 불필요)

# 실제 인프라 대상 통합 테스트 (환경변수가 있을 때만 실행)
SECMAIL_TEST_PG_DSN="postgres://postgres@127.0.0.1:5432/secmail_test?sslmode=disable" \
SECMAIL_TEST_REDIS=127.0.0.1:6379 \
SECMAIL_TEST_S3_ENDPOINT=127.0.0.1:9000 SECMAIL_TEST_S3_ACCESS_KEY=... SECMAIL_TEST_S3_SECRET_KEY=... \
go test -count=1 ./...
```
- MIME 변환: 서명·암호화·한글 파일명/EUC-KR·인라인 이미지·전달 메일·깊은 중첩
- SMTP 종단간: 릴레이 거부, 업스트림 거부 전달, DKIM 재서명 검증, 파싱 불가 메일 격리
- 포털: 상태별 화면, 1회용 티켓, 만료, rate limit, OTP 로그인·무차별 대입 제한·비수신자 차단·쿠키 위조, SSO 헤더 모드, CSRF
- OCR: 가짜 엔진으로 중복 제거·크기 필터·한도·시간 초과 검증, 실제 tesseract로 PNG·docx 삽입 그림·스캔 PDF 인식 (tesseract가 설치된 경우에만 실행)
- DLP: 탐지기 양성/음성 케이스, 실제 형식(docx·xlsx·중첩 zip·암호화 zip·zip bomb·PDF·HWP 레코드·EUC-KR), 발신 정책 종단간(보류→승인/반려/만료, 차단, 예외, 릴레이 보호), 검토 화면·관리 API
- 실제 HWP 샘플 검증: `SECMAIL_TEST_HWP_DIR=<pyhwp>/tests/hwp5_tests/fixtures go test ./internal/dlp`
- 저장소 적합성: 같은 테스트를 메모리/PostgreSQL, 파일시스템/S3에 각각 실행, Redis 큐 우선순위·dead-letter, Redis 티켓/OTP

## 운영 시 참고
- 포털은 반드시 HTTPS 리버스 프록시 뒤에 두고 `trust_proxy_headers: true`를 설정하세요.
- Internal API는 분석 네트워크에서만 접근 가능하도록 제한하세요. `:8081`에 `/metrics`(Prometheus), `/healthz`(liveness), `/readyz`(DB·스토리지 준비)도 여기 붙습니다.
- 부팅 시 DB·스토리지·Redis가 준비될 때까지 최대 30초(지수 백오프) 기다립니다. PostgreSQL 풀 크기와 Redis 풀·타임아웃은 설정에서 조정합니다.
- 내부 메일 서버가 게이트웨이를 신뢰하도록(SPF/DKIM 재검사 제외, `TrustedAuthservIDs`=게이트웨이 hostname, 우회 차단) 설정해야 합니다 → [docs/deployment.md](docs/deployment.md)
