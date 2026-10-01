# 분석 엔진 연동 규격 (Analyzer Contract)

secmail은 정적 분석을 직접 수행하지 않습니다. 첨부파일을 격리 저장한 뒤 **분석 작업(Job)** 을
큐에 넣고, 외부 분석 프로젝트가 **판정(Verdict)** 을 돌려주면 그 결과에 따라 다운로드를 허용/차단합니다.

```
secmail ──LPUSH job──▶ Redis  secmail:jobs:high / secmail:jobs:normal
                                   │ BRPOP (high 우선)
                                   ▼
                          [외부 분석 엔진]
                   파일 획득: ① internal API content_url  또는  ② S3/MinIO 직접 읽기
                   판정 회신: ① POST verdict_url           또는  ② LPUSH secmail:results
```

## 1. 작업 수신

| 키 | 용도 |
|---|---|
| `secmail:jobs:high` | 신규 메일 첨부파일 (사용자가 기다리는 중 → 최우선) |
| `secmail:jobs:normal` | 타임아웃 후 재시도 |

`BRPOP secmail:jobs:high secmail:jobs:normal 0` 으로 소비하면 Redis가 high를 먼저 비웁니다.
작업 유실을 막으려면 `BLMOVE ... secmail:jobs:processing` 패턴을 권장합니다
(유실되더라도 secmail의 janitor가 `analysis.timeout` 후 재큐잉하고, `max_attempts` 초과 시 `ERROR`로 막습니다).

### Job JSON

```json
{
  "version": 1,
  "attachment_id": "5673abe9-4132-44c3-bd9d-c563e4aacad5",
  "message_id": "360317b9-b316-4682-af24-3eb39d4d34ee",
  "filename": "견적서.pdf",
  "content_type": "application/pdf",
  "size": 22,
  "sha256": "9f2c...e1",
  "storage": { "type": "s3", "bucket": "secmail-attachments", "key": "attachments/2026/09/29/5673abe9-..." },
  "content_url": "http://secmail-internal:8081/internal/v1/attachments/5673abe9-.../content",
  "verdict_url": "http://secmail-internal:8081/internal/v1/attachments/5673abe9-.../verdict",
  "attempt": 1,
  "enqueued_at": "2026-09-29T23:55:52Z"
}
```

- `filename`/`content_type` 은 **발신자가 주장한 값**입니다. 신뢰하지 말고 파일 매직으로 재판별하세요.
- `content_url`/`verdict_url` 은 `internal_api.advertise_url` 이 설정된 경우에만 채워집니다.
- 동일 SHA-256 파일이 `analysis.verdict_reuse_window` 안에 이미 판정되었다면 작업이 발행되지 않습니다.

## 2. 파일 획득

**① Internal API** (권장, 분석 엔진에 S3 자격증명 불필요)

```
GET /internal/v1/attachments/{id}/content
Authorization: Bearer <internal_api.token>
→ 200 application/octet-stream  (X-SHA256 헤더 포함)
```

**② 오브젝트 스토리지 직접 접근**: `storage.bucket` + `storage.key` (읽기 전용 권한만 부여).

## 3. 판정 회신

`status` 는 `CLEAN` | `MALICIOUS` | `ERROR` 중 하나. `detail` 은 임의의 JSON(보고서, YARA 룰 목록 등)으로 DB에 그대로 저장됩니다.

- `detail` 은 최대 **64 KiB**입니다. 초과 시 400(HTTP) 또는 dead-list(Redis)로 처리되므로, 대용량 보고서는 오브젝트 스토리지에 두고 링크만 넣으세요.
- `threat_name` 은 최대 256바이트로 잘리고(잘림은 UTF-8 문자 경계에서), 제어문자는 제거됩니다(다운로드 페이지·로그에 노출되므로).
- HTTP 본문은 1 MiB로 제한됩니다.

**① HTTP**

```
POST /internal/v1/attachments/{id}/verdict
Authorization: Bearer <token>
Content-Type: application/json

{"status":"MALICIOUS","threat_name":"Ransom.LockBit","detail":{"yara":["lockbit_note"],"entropy":7.98}}
```

| 응답 | 의미 |
|---|---|
| 200 | 반영됨 |
| 400 | 잘못된 status / JSON |
| 404 | 없는 첨부파일 |
| 409 | 이미 최종 판정됨 (중복 회신 — 무시해도 됨) |

**② Redis**: `LPUSH secmail:results '{"attachment_id":"...","status":"CLEAN","detail":{...}}'`

- 디코딩 불가 메시지, 그리고 반영이 **영구 실패**한 판정(잘못된 payload·없는 첨부·중복)은 `secmail:results:dead` 로 이동합니다. 운영 중 이 리스트가 쌓이면 분석기 payload 오류를 점검하세요.
- 반영이 **일시 실패**(DB·스토리지 순단)한 경우 게이트웨이가 지수 백오프로 몇 차례 재시도하며, 그래도 실패하면 판정을 버리고 stale-job 스윕이 작업을 재발행합니다(분석이 다시 수행됨). 즉 완료된 판정이 순간 장애로 유실되지 않습니다.
- 중복 회신(이미 최종 판정)은 조용히 무시됩니다(멱등).

## 4. 상태 전이

```
PENDING ──CLEAN──────▶ 다운로드 허용
        ──MALICIOUS──▶ 차단 (탐지명 표시)
        ──ERROR──────▶ 차단 (fail-closed)
        ──timeout × max_attempts──▶ ERROR
(any)   ──link_ttl 경과──▶ EXPIRED (오브젝트 삭제)
```

판정은 한 번만 반영됩니다 (`PENDING` 에서만 전이). 참고 구현: `cmd/mock-analyzer`(EICAR 대역).
실제 구현: [`analyzer/`](../analyzer/) — malengine(`../../p1`) 엔진을 라이브러리로 임베드한 분석 워커.
