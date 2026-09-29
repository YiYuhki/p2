# secmail — 첨부파일 격리형 보안 메일 게이트웨이

메일 서버 앞단의 SMTP 프록시입니다. 수신 메일의 첨부파일을 분리해 오브젝트 스토리지에 격리하고,
본문에는 다운로드 링크 배너를 넣어 실제 메일 서버로 전달합니다. 외부 분석 엔진이 파일을 검사하고,
`CLEAN` 판정을 받은 파일만 포털에서 받을 수 있습니다.

> 정적/동적 분석 엔진은 **별도 프로젝트**입니다. 연동 규격은 [docs/analyzer-contract.md](docs/analyzer-contract.md)에 있습니다.

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
- **파싱 불가 메일은 전체를 `original-message.eml`로 격리** (fail-closed). 중첩 깊이 제한 32.
- S/MIME·PGP 서명 메일: `rewrite`(서명 래퍼 제거 + 안내) / `passthrough`. 암호화 메일: `passthrough` / `reject`.
- 발신자가 넣은 `X-SecMail-*` 헤더는 제거(위조 방지)하고 `X-SecMail-Processed`, `Received`, `Authentication-Results`를 추가.

### 2. DKIM
- 수정 전 원본 서명을 검증해 `Authentication-Results`에 기록 (`dkim.verify_inbound`).
- 메일을 수정한 경우 깨진 원본 서명은 `X-SecMail-Original-DKIM-Signature`로 이름을 바꿔 보존.
- 게이트웨이 키로 재서명 (relaxed/relaxed, RSA 또는 Ed25519). 키 생성: `secmail dkim-keygen -domain example.com -selector secmail`.
- 내부 메일 서버는 게이트웨이 IP와 게이트웨이 DKIM 서명을 신뢰하도록 설정하세요.

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

보안 설계:
- 링크 토큰은 256-bit 난수, DB에는 **SHA-256 해시만** 저장 (DB 유출 시에도 링크 사용 불가).
- 실제 다운로드는 **POST로만 발급되는 1회용 티켓**(기본 60초)을 거칩니다 → Outlook Safe Links 같은 링크 스캐너가 GET으로 파일을 가져가지 못함.
- 전송 직전 판정 재확인, `application/octet-stream` + `attachment` 강제, `nosniff`, nonce 기반 CSP, IP별 rate limit.

## 빠른 시작 (Docker)

```bash
docker compose -f deploy/docker-compose.yml up --build
# 테스트 메일 발송 (수신자는 @example.com)
swaks --server localhost:2525 --to user@example.com --attach @report.pdf
# 내부 메일서버(mailpit)가 받은 메일: http://localhost:8025 → 링크 클릭 → http://localhost:8080/d/...
```
`mock-analyzer`는 EICAR 문자열이 있으면 `MALICIOUS`, 아니면 `CLEAN`을 회신하는 참고 구현입니다. 실제 분석 프로젝트로 교체하세요.

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
| `internal/gateway` | SMTP 세션/업스트림 릴레이, 메시지 처리, 배너 |
| `internal/mimeproc` | MIME 트리 파싱 · 첨부 분리 · 배너 삽입 |
| `internal/dkimutil` | DKIM 검증/재서명 |
| `internal/service` | 격리 저장, 판정 반영, janitor |
| `internal/portal` | 다운로드 포털, 1회용 티켓, rate limit |
| `internal/internalapi` | 분석 엔진용 인증 API |
| `internal/store` | PostgreSQL(내장 마이그레이션) / 메모리 저장소 |
| `internal/storage` | S3·MinIO / 파일시스템 |
| `internal/queue` | Redis / 메모리 큐 |

## 테스트

```bash
go test ./...
```
MIME 변환(서명·암호화·한글 파일명/EUC-KR·인라인 이미지·전달 메일·깊은 중첩), SMTP 종단간(릴레이 거부, 업스트림 거부 전달, DKIM 재서명 검증, 파싱 불가 메일 격리), 포털(상태별 화면, 1회용 티켓, 만료, rate limit), 서비스(재시도·만료·판정 재사용), 내부 API를 다룹니다.

## 운영 시 참고
- 포털은 반드시 HTTPS 리버스 프록시 뒤에 두고 `trust_proxy_headers: true`를 설정하세요.
- Internal API는 분석 네트워크에서만 접근 가능하도록 제한하세요.
- 현재 링크는 수신자 구분 없이 동작합니다. 수신자 인증(SSO 등)이 필요하면 포털 앞단에 붙이세요.
