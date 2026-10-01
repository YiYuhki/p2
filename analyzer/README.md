# secmail analyzer (malengine 연동)

secmail의 **첨부파일 악성코드 분석**을 담당합니다. [`docs/analyzer-contract.md`](../docs/analyzer-contract.md)
규격을 구현하며, 분석 엔진으로 [malengine](../../p1)(`github.com/YiYuhki/p1`)의 공개 라이브러리
API(`analyzer` 패키지)를 임베드합니다.

## 두 가지 배포 형태 — 같은 코드 공유

분석·판정매핑 로직은 전부 **`scan` 패키지**(`github.com/yiyuhki/p2/analyzer/scan`)에 있고,
두 배포 형태가 이걸 **공유**합니다. 전송(transport)만 다릅니다.

| 형태 | 전송 | 큐 | cgo |
|---|---|---|---|
| **① 독립 워커** (이 모듈의 `main`) | Redis + 내부 API(HTTP) | redis 전용 | 워커 바이너리만 |
| **② secmail 인프로세스** (`-tags malengine`) | 인프로세스 함수 호출 | **redis·memory 둘 다** | secmail 바이너리 |

```
① 독립 워커:
secmail ──job──▶ Redis(secmail:jobs:*) ──BRPOP──▶ [워커] ──scan.Scan──▶ verdict_url POST / LPUSH results

② 인프로세스 (secmail -tags malengine):
secmail(ConsumeJobs) ──job──▶ [goroutine] ──스토리지 직접 read──▶ scan.Scan ──▶ ApplyVerdict (인프로세스)
```

①은 트래픽 있는 운영(분석을 메일 경로와 격리, 독립 수평 확장)에, ②는 memory 큐를 쓰는
단일 프로세스 개발/소규모(외부 워커가 붙을 수 없는 환경)에 적합합니다.

## 왜 별도 모듈인가

malengine은 **libyara(cgo)** 를 필수로 링크합니다. 이 워커만 malengine을 임포트하도록
독립 Go 모듈(`github.com/yiyuhki/p2/analyzer`)로 분리해서, secmail 코어(`../`)는 순수
Go(`CGO_ENABLED=0`)로 libyara 의존 없이 그대로 빌드됩니다. malengine은 `replace ../../p1`
로 워크스페이스의 옆 폴더를 참조합니다.

## 빌드 / 실행 (로컬)

빌드 시 `libyara-dev` 와 `pkg-config` 가 필요합니다(Debian/Ubuntu 기준).

```sh
cd p2/analyzer
go build -o analyzer .

# secmail(+Redis)이 떠 있는 상태에서
SECMAIL_INTERNAL_TOKEN=<secmail internal_api.token> \
  ./analyzer -redis localhost:6379 -yara-dir ../../p1/rules/yara
```

여러 개를 띄우면 같은 큐를 BRPOP 하므로 자동으로 부하가 분산됩니다.

## 주요 플래그

| 플래그 | 기본값 | 설명 |
|---|---|---|
| `-redis` | `localhost:6379` | Redis 주소 |
| `-prefix` | `secmail` | 큐 키 프리픽스 |
| `-token` | `$SECMAIL_INTERNAL_TOKEN` | internal API 베어러 토큰 |
| `-yara-dir` | `$MALENGINE_YARA_DIR` | YARA 룰 디렉터리(비우면 YARA 생략, 나머지 정적 탐지는 동작) |
| `-block-level` | `suspicious` | 이 등급 이상이면 MALICIOUS 로 차단: `clean`\|`suspicious`\|`likely`\|`malicious` |
| `-threat-intel` | `false` | abuse.ch·VirusTotal 등 외부 조회 활성화 |
| `-sandbox` | `false` | 동적 샌드박스 단계(Docker/Firecracker 필요) |
| `-max-size` | `0` | 분석 최대 입력 크기(바이트, 0=엔진 기본) |
| `-tmp-dir` | OS temp | AnalyzeBytes 스크래치 디렉터리 |
| `-reply-redis` | `false` | verdict_url POST 대신 `secmail:results` 로 LPUSH |

## 판정 매핑

malengine의 등급(`CLEAN`<`SUSPICIOUS`<`LIKELY_MALICIOUS`<`MALICIOUS`)을 secmail 상태로 변환합니다.

- `-block-level`(기본 `suspicious`) **이상** → `MALICIOUS` (탐지명 = YARA 패밀리/대표 카테고리/등급).
  메일 게이트웨이는 fail-safe 가 기본이라 EICAR 같은 `SUSPICIOUS` 도 차단합니다.
- 그 미만 → `CLEAN`.
- 다운로드 실패·분석 오류 → `ERROR` (secmail은 fail-closed 로 차단).

`detail` 에는 전체 malengine JSON 리포트를 넣되, secmail의 64 KiB 상한을 넘으면 핵심 요약
(등급·점수·상위 근거·ATT&CK 기법·SHA-256, `"truncated": true`)으로 축약합니다.

## Docker

빌드 컨텍스트는 p1·p2를 함께 담은 상위 폴더여야 합니다(`replace ../../p1` 해석).

```sh
cd ..          # …/program (p1/ 와 p2/ 의 부모)
docker build -f p2/analyzer/Dockerfile -t secmail-analyzer .
```

데모 스택에 붙이려면 [`deploy/docker-compose.analyzer.yml`](../deploy/docker-compose.analyzer.yml)
오버레이를 사용합니다(mock-analyzer 를 실제 워커로 교체).

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.analyzer.yml up --build
```

> 이 환경에서는 Docker 빌드를 실행해 검증하지 못했습니다. libyara 런타임 패키지명이 베이스
> 이미지에 따라 다를 수 있으니(`libyara9` 등) 필요 시 조정하세요. Go 바이너리/테스트는 로컬에서 검증했습니다.

## ② secmail 인프로세스 빌드 (`-tags malengine`)

secmail 자체에 분석기를 넣어 **외부 워커 없이** 돌리는 방식입니다. memory 큐에서도 동작합니다.
기본 빌드는 영향받지 않습니다(순수 Go, 분석기 미포함).

```sh
# p2 레포 루트에서 (libyara-dev, pkg-config 필요)
go build -tags malengine -o secmail ./cmd/secmail
```

그리고 secmail 설정에서 `analyzer` 섹션을 켭니다(config.example.yaml 참고):

```yaml
queue:   { type: memory }        # 또는 redis
analyzer:
  enabled: true                  # -tags malengine 빌드에서만 효과
  yara_dir: ../p1/rules/yara
  block_level: suspicious
```

태그 없이 빌드한 secmail에서 `analyzer.enabled: true` 를 켜면 무시되고 경고만 남습니다(외부 워커 사용).

분석·판정 로직은 ①과 **완전히 동일한 `scan` 패키지**를 씁니다(`cmd/secmail/analyzer_malengine.go`).
