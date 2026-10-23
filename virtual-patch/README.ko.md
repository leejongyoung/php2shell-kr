# virtual-patch: 가상 패치(임시 완화) 모음

> 경고: PHP 공식 공지는 PHP2Shell(CVE-2026-109618 / CVE-2026-109619)에 완전한 완화책이 없다고 밝힙니다.
> 이 디렉터리의 파일은 일부 공격 경로만 줄이며 우회될 수 있습니다. 패치까지 시간을 버는 용도입니다.
> 근본 조치는 패치 버전(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 / 8.6.0RC4) 적용입니다.

`@@POST_MAX@@`, `@@POST_MAX_BYTES@@`, `@@UPLOAD_MAX@@` 는 도구가 복사할 때 값으로 치환합니다
(업로드 없음 8M/8388608/2M, 업로드 있음 32M/33554432/20M). 직접 쓸 때는 값을 손으로 바꾸세요.

## 파일 목록

| 파일 | 역할 |
|---|---|
| `php/php-mitigation.ini` | php.ini 조각: 업로드 진행률 비활성화, 크기 상한 (memory_limit 없음) |
| `php/php-fpm-pool-mitigation.conf` | pool 조각: php_admin_* 로 고정, memory_limit=-1 은 기본 주석 처리 |
| `apache/php2shell-mitigation.conf` | Apache Limit* 와 mod_php php_admin_* |
| `nginx/php2shell-mitigation.conf` | nginx 크기/헤더/빈도 제한 |
| `nginx/php2shell-block-multipart.conf` | 업로드 없는 사이트 전용 multipart 차단 |
| `modsecurity/php2shell.conf` | ModSecurity 규칙(ID 91001-91010) |
| `iis/web.config.snippet.xml` | IIS 요청 크기 상한만 설정 (미검증: IIS 환경 없음) |
| `iis/web.config.block-multipart.xml` | 업로드 없는 사이트 전용 multipart 차단; 업로드 없음 선택 시에만 생성 (미검증: IIS 환경 없음) |
| `os/systemd-php-fpm-dropin.conf` | 메모리 상한(가용성 경계) |
| `os/docker-compose-hardening.yml` | 컨테이너 하드닝 예시 |
| `os/auditd-php2shell.rules` | 탐지 규칙(noisy) |
| `os/nftables-egress-example.nft` | 외부 연결 차단 예시 |
| `os/selinux-apparmor-notes.ko.md` | SELinux/AppArmor 메모 |

## 적용 순서

1. 노출 줄이기: IP 허용 목록/VPN/점검 페이지(필요시 서비스 중단). 자세한 내용은 `docs/virtual-patching.ko.md`.
2. OS 메모리 상한(systemd MemoryMax/cgroup 또는 컨테이너 --memory/mem_limit)을 먼저 설정하고 적용 여부를 확인합니다.
3. PHP 설정(pool 파일 또는 Apache php_admin). php.ini 조각은 보조입니다. `memory_limit=-1` 은 기본 주석 처리되어 있습니다.
   OS 상한 확인 후에만 pool 의 `;php_admin_value[memory_limit] = -1` 에서 `;` 를,
   Apache 해당 모듈 블록의 `#php_admin_value memory_limit -1` 에서 `#` 를 제거하세요.
   업로드 진행률 비활성화와 크기 제한은 주석 해제 없이도 적용됩니다.
4. 웹서버 요청 크기/헤더 제한(nginx/Apache/IIS).
5. WAF 규칙(ModSecurity): DetectionOnly 로 시작, 로그 확인 후 차단.
6. 침해 후 피해 축소: egress 차단, auditd, SELinux/AppArmor.

## 한계

- memory_limit=-1 은 OS 상한을 먼저 적용한 뒤 선택적으로 켜세요. RLIMIT_AS/RLIMIT_DATA 로 대체하지 마세요.
- session.auto_start=0 은 session_start() 없이 $_SESSION 을 쓰는 페이지를 깨뜨릴 수 있습니다(출처: Xint).
- 요청 형태 규칙은 문자셋 변형, RFC 2231/5987 인코딩, 대용량 본문으로 우회될 수 있습니다.
- 각 파일의 검증 상태는 파일 머리말과 최종 보고를 확인하세요. 미검증 항목은 스테이징 시험이 필수입니다.
