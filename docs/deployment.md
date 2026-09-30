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
