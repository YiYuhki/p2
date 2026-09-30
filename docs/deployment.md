# 운영 배포 가이드

secmail을 인터넷과 내부 메일 서버 사이에 넣을 때 필요한 DNS, 내부 메일 서버, 포털 설정입니다.

```
인터넷 ─(MX)→ secmail :25 ─→ 내부 메일서버 :25 ─→ 사용자 메일함
                   │
사용자 브라우저 ─→ HTTPS 리버스 프록시 ─→ secmail 포털 :8080
분석 엔진 ───────────────────────────→ secmail internal API :8081 (내부망 전용)
```

## 1. DNS

| 레코드 | 값 | 설명 |
|---|---|---|
| `MX example.com` | `10 secmail.example.com.` | 외부 메일이 게이트웨이로 들어오게 함 |
| `A secmail.example.com` | 게이트웨이 공인 IP | SMTP 수신 |
| `A sec-mail.example.com` | 리버스 프록시 IP | 다운로드 포털 (`portal.public_base_url`) |
| `TXT secmail._domainkey.example.com` | `v=DKIM1; k=rsa; p=...` | `secmail dkim-keygen` 출력값 |

게이트웨이는 **수신 전용**입니다. 외부로 나가는 메일의 SPF에는 게이트웨이 IP를 넣을 필요가 없습니다.

## 2. 내부 메일 서버 설정 (핵심)

게이트웨이를 거친 메일은 다음 두 가지가 바뀝니다.
- 첨부파일이 링크로 바뀌어 **원래 발신자의 DKIM 서명이 깨집니다** (`X-SecMail-Original-DKIM-Signature`로 보존).
- 연결 IP가 원래 발신 서버가 아니라 **게이트웨이 IP**가 되므로 내부 서버에서 SPF를 다시 검사하면 실패합니다.

그래서 내부 메일 서버는 다음과 같이 설정해야 합니다.
1. 게이트웨이 IP에서 오는 연결을 **신뢰된 릴레이**로 등록하고, 그 연결에서는 SPF/DKIM/DMARC 재검사를 끕니다.
2. 게이트웨이가 남긴 `Authentication-Results: secmail.example.com; dkim=...` 헤더(수정 전 원본 검증 결과)를 신뢰합니다. 게이트웨이는 발신자가 넣은 `X-SecMail-*` 헤더를 항상 지우므로 위조할 수 없습니다.
3. 게이트웨이 IP 외에는 25번 포트를 막아 **게이트웨이 우회를 차단**합니다. 우회가 가능하면 첨부파일 격리가 무력화됩니다.

### Postfix

```ini
# /etc/postfix/main.cf
mynetworks = 127.0.0.0/8 [::1]/128 10.0.5.20/32      # 10.0.5.20 = secmail
smtpd_client_restrictions = permit_mynetworks, reject  # 게이트웨이만 수신 허용 (우회 차단)

# 재검사 milter(opendkim/opendmarc/policyd-spf)가 있다면 게이트웨이 연결에서는 건너뜀
# opendkim: InternalHosts / ExemptDomains 에 10.0.5.20 추가
# opendmarc: IgnoreHosts 에 10.0.5.20 추가, TrustedAuthservIDs secmail.example.com
# policyd-spf: skip_addresses = 127.0.0.0/8,10.0.5.20/32
```

### Microsoft Exchange Server (온프레미스)

```powershell
# 게이트웨이 전용 Receive Connector: 익명 + 외부 보안 인증(신뢰된 릴레이)
New-ReceiveConnector -Name "From secmail" -TransportRole FrontendTransport `
  -Bindings 0.0.0.0:25 -RemoteIPRanges 10.0.5.20 `
  -PermissionGroups AnonymousUsers,ExchangeServers -AuthMechanism ExternalAuthoritative

# 게이트웨이를 내부 SMTP 서버로 등록 → 원래 발신자 IP 기준으로 스팸 판정
Set-TransportConfig -InternalSMTPServers @{Add="10.0.5.20"}
```
기본 수신 커넥터의 `RemoteIPRanges`는 게이트웨이만 허용하도록 줄입니다.

### Microsoft 365 / Google Workspace

- Microsoft 365: MX를 게이트웨이로 바꾸고, 게이트웨이 IP로 **Inbound connector**("Partner organization", IP 제한)를 만든 뒤 **Enhanced Filtering for Connectors**에 게이트웨이 IP를 등록합니다(원래 발신자 IP로 SPF/DMARC 평가). 업스트림 주소는 `<tenant>.mail.protection.outlook.com:25`, `starttls: true`.
- Google Workspace: 관리 콘솔 → Gmail → 스팸, 피싱, 멀웨어 → **Inbound gateway**에 게이트웨이 IP 등록, "Reject all mail not from gateway IPs" 체크. 업스트림 주소는 `aspmx.l.google.com:25`, `starttls: true`.

## 3. 포털

- 반드시 HTTPS 리버스 프록시 뒤에 둡니다 (쿠키 `Secure` 플래그는 `public_base_url`이 `https://`면 자동 적용).
- 프록시 뒤라면 `trust_proxy_headers: true` (IP별 rate limit이 `X-Forwarded-For` 기준으로 동작).

### 토큰 추측·열거 방어

다운로드 링크는 256비트 난수 토큰(해시만 저장)이라 추측이 사실상 불가능하지만, 무차별 대입 시도 자체를 억제하고 탐지할 수 있게 다층 방어를 둡니다.

- **일반 rate limit** (`rate_limit_rps`/`rate_limit_burst`): IP별 전체 요청 상한. 정상적인 페이지 열람·상태 폴링을 포괄합니다.
- **열거 방어** (`enum_per_ip_burst`/`enum_global_rps`): *실패한* 조회(존재하지 않거나 형식이 잘못된 토큰)에만 부과하는 별도 예산입니다. 정상 사용자는 유효한 링크를 따라오므로 거의 실패하지 않습니다. 실패가 몰리면 그 IP는 `enum_per_ip_burst`회(기본 10) 후 `429`로 제한되고, 여러 IP로 분산된 공격도 전체 `enum_global_rps`(기본 20/s) 상한으로 함께 막힙니다. 유효 토큰 요청은 이 예산을 소비하지 않으므로 공격 중에도 정상 다운로드는 영향받지 않습니다.
- 존재하지 않는 토큰은 형식 오류든 미등록이든 **동일하게 404/429**만 반환해, 추측한 토큰의 존재 여부를 노출하지 않습니다.
- 다운로드 파일은 항상 `Content-Disposition: attachment`(제어문자·경로 제거, 원본 파일명은 RFC 5987 `filename*`)로 내려보내 브라우저 인라인 렌더링(HTML/SVG 등)을 차단하고, `Content-Security-Policy: default-src 'none'; sandbox`를 함께 적용합니다.
- 열거 시도는 `secmail_portal_requests_total{outcome="notfound"|"throttled"}` 메트릭과 경고 로그로 드러납니다. `notfound`/`throttled`의 급증에 알림을 걸어 두세요. 성공 다운로드는 `download_events` 테이블에도 감사 기록됩니다.

### 수신자 인증 모드 (`portal.auth.mode`)

| 모드 | 동작 | 적합한 환경 |
|---|---|---|
| `none` | 링크만 있으면 다운로드 (256-bit 토큰) | 테스트, 내부망 전용 |
| `otp` | 메일 수신 주소를 입력 → 인증 코드 메일 → 코드 입력 후 세션 발급 | SSO가 없는 조직 (권장 기본값) |
| `header` | SSO 리버스 프록시가 넣어준 헤더의 이메일로 판단 | oauth2-proxy, Azure AD App Proxy 등 |

- 접근 허용 대상은 해당 메일의 **SMTP 수신자(envelope RCPT)** 입니다.
- 배포 그룹/별칭 주소로 받은 메일은 실제 사용자 주소가 수신자 목록에 없습니다. 이 경우 `allow_domain_users: true`로 `accepted_domains` 소속 사용자 전체를 허용하세요.
- OTP 메일은 업스트림 메일 서버로 직접 보내므로 `otp_from` 주소가 내부 서버에서 거부되지 않아야 합니다.
- OTP는 이메일당 `otp_resend_after`(기본 1분)마다 1회 발송, `otp_max_attempts`(기본 5회) 오입력 시 폐기됩니다.

`header` 모드 예시 (oauth2-proxy):
```yaml
portal:
  auth:
    mode: header
    trusted_header: X-Auth-Request-Email
```
> header 모드에서는 포털 포트(8080)가 **SSO 프록시에서만** 접근 가능해야 합니다. 직접 접근이 가능하면 헤더를 위조할 수 있습니다.

## 4. 분석 엔진 연동

- Internal API(:8081)는 분석 엔진 네트워크에서만 접근 가능하게 방화벽을 설정합니다.
- `internal_api.token`은 32자 이상 난수를 권장합니다 (`openssl rand -hex 32`).
- 연동 규격: [analyzer-contract.md](analyzer-contract.md)

## 5. 확장 / 가용성

- 상태는 PostgreSQL·Redis·S3에만 있으므로 `-components smtp`, `-components portal`을 여러 대 띄워 수평 확장할 수 있습니다.
- `worker`(판정 소비 + janitor)는 여러 대 떠도 안전하지만(판정은 `PENDING`에서 한 번만 반영) 1~2대면 충분합니다.
- MX를 여러 게이트웨이에 걸어 두면 한 대가 죽어도 발신 MTA가 다른 MX로 재시도합니다. 게이트웨이는 업스트림이 수락해야만 250을 응답하므로 메일이 유실되지 않습니다.

## 6. 운영 점검 항목

- [ ] 게이트웨이 외 IP에서 내부 메일 서버 25번 포트 접속 불가
- [ ] `dig TXT secmail._domainkey.example.com` 으로 DKIM 공개키 확인
- [ ] 테스트 메일의 `Authentication-Results` / `X-SecMail-Processed` 헤더 확인
- [ ] EICAR 첨부 메일 → 포털에서 차단 확인
- [ ] 분석 엔진 중지 상태에서 `analysis.timeout × max_attempts` 후 `ERROR`(차단) 전환 확인
- [ ] `download_events` 테이블에 다운로드 감사 기록 확인

### SMTP 연결 보호

- 리스너마다 동시 연결 수(`smtp.max_connections`, 기본 1024)와 수신 리스너의 IP별 동시 연결 수(`smtp.max_connections_per_ip`, 기본 50)를 제한합니다. 초과 연결은 `421`을 받고 즉시 종료됩니다.
- 발신(outbound) 리스너는 IP별 제한을 적용하지 않습니다(허용된 내부 메일 서버가 다수 연결을 열 수 있으므로). 대신 `outbound.allowed_clients` IP 목록으로 접근을 통제합니다.
- 과도하게 긴 SMTP 라인(`smtp.max_line_length`), 메시지 크기(`smtp.max_message_bytes`, SIZE로 광고), 읽기/쓰기 타임아웃(slow-loris 방지)을 적용합니다.
- 부하가 큰 환경에서는 `smtp.max_connections`를 파일 디스크립터 한도(`ulimit -n`)와 함께 조정하세요.

## 7. 발신 메일 DLP 연동

내부 메일 서버가 **외부로 나가는 메일**을 secmail의 outbound 포트(`outbound.listen`, 기본 10025)로 넘기면, secmail이 검사한 뒤 `outbound.next_hop`으로 전달합니다. 정책과 탐지 항목은 [dlp.md](dlp.md)에 있습니다.

- `outbound.allowed_clients`에는 **내부 메일 서버 IP만** 넣으세요. 이 포트는 인증 없이 외부로 릴레이하므로 인터넷에 노출하면 안 됩니다.
- `MAIL FROM` 도메인은 `sender_domains`(기본값 `smtp.accepted_domains`)만 허용합니다.
- `next_hop`은 인터넷으로 배달할 수 있는 MTA여야 합니다. secmail은 자체 발송 큐를 두지 않고, next hop이 수락해야만 250으로 응답합니다.
- 발신 메일은 수정하지 않으므로 내부 서버의 DKIM 서명이 그대로 유지됩니다.

### Postfix (content_filter + 재주입)

```ini
# /etc/postfix/master.cf
# 1) 사용자가 보내는 메일(submission)을 secmail로 넘김
submission inet n - n - - smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o content_filter=smtp:[10.0.5.20]:10025

# 2) secmail이 검사를 마친 메일을 되돌려 받는 재주입 포트 (필터 없음)
10.0.5.10:10026 inet n - n - - smtpd
  -o syslog_name=postfix/dlp-reinject
  -o content_filter=
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks,no_milters
  -o mynetworks=10.0.5.20/32
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
```
secmail 설정: `outbound.next_hop.addr: 10.0.5.10:10026`, `outbound.allowed_clients: [10.0.5.10/32]`.
사내끼리 주고받는 메일도 content_filter를 거치지만, `dlp.scan_internal: false`(기본)면 검사 없이 통과합니다.

### Microsoft Exchange Server

```powershell
# 인터넷행 Send Connector를 secmail 스마트 호스트로 변경
Set-SendConnector "Internet" -SmartHosts 10.0.5.20 -SmartHostAuthMechanism None -DNSRoutingEnabled $false -Port 10025
```
secmail의 `next_hop`에는 인터넷으로 배달하는 릴레이 MTA를 지정합니다 (예: DMZ의 Postfix relay, ISP 스마트 호스트).

### Microsoft 365 / Google Workspace

- Microsoft 365: Exchange admin center → Mail flow → Connectors → **Office 365 → Partner organization** 커넥터를 만들어 모든 외부 도메인을 secmail로 라우팅합니다 (스마트 호스트 `secmail.example.com:10025`, TLS). `allowed_clients`에는 [Microsoft 365 발신 IP 대역](https://learn.microsoft.com/microsoft-365/enterprise/urls-and-ip-address-ranges)을 넣고, `next_hop`은 인터넷 배달용 relay로 지정합니다.
- Google Workspace: 관리 콘솔 → Gmail → 라우팅 → **Outbound gateway**에 `secmail.example.com:10025`를 지정합니다. `allowed_clients`는 Google 발신 대역(`_spf.google.com`)입니다.
- 클라우드 발신 IP 대역은 넓으므로 `sender_domains`를 반드시 좁게 설정하고, 가능하면 상호 TLS 인증을 앞단 프록시에서 적용하세요.

### 점검 항목

- [ ] 내부 서버 외 IP에서 10025 접속 시 `554 Access denied`
- [ ] 외부 도메인 발신자(`MAIL FROM:<x@other.org>`) → `550 Sender domain not allowed`
- [ ] 주민번호가 든 xlsx 첨부 → 보류, 보안담당자 메일에 검토 링크
- [ ] 검토 화면 승인 → 수신자 도착, 반려 → 발신자에게 사유 안내
- [ ] `dlp_events` 테이블 기록 확인

## 8. 관측(Observability)과 헬스체크

Internal API 리스너(`internal_api.listen`, 기본 8081)에서 다음을 인증 없이 제공합니다. 이 포트는 반드시 내부망 전용으로 두세요.

| 경로 | 용도 |
|---|---|
| `/metrics` | Prometheus 텍스트 형식 메트릭 |
| `/healthz` | liveness (프로세스 생존) |
| `/readyz` | readiness — DB·오브젝트 스토리지 ping, 실패 시 503 |

주요 메트릭:

| 메트릭 | 설명 |
|---|---|
| `secmail_inbound_messages_total{result}` | 수신 릴레이 건수 |
| `secmail_attachments_total{status}` | 격리 첨부(pending/reused-*) |
| `secmail_verdicts_total{status}` | 분석 판정 반영(clean/malicious/error) |
| `secmail_outbound_messages_total{action}` | 발신 DLP 동작(allow/notify/hold/block/exempt) |
| `secmail_dlp_findings_total{severity}` | DLP 탐지 건수(high/medium/low) |
| `secmail_dlp_scan_seconds` | 발신 메일 검사 소요시간 히스토그램 |
| `secmail_external_tool_seconds{tool}` | OCR/변환/압축해제 소요시간(ocr/pdf/heif/archive) |
| `secmail_holds_total{event}` | 보류 생성/승인/반려/만료 |
| `secmail_portal_requests_total{outcome}` | 포털 토큰 조회 결과(ok/notfound/throttled/denied/error) — notfound·throttled 급증은 토큰 열거 신호 |

Kubernetes 예: livenessProbe → `/healthz`, readinessProbe → `/readyz`. Prometheus scrape 대상은 `<secmail>:8081/metrics`.
