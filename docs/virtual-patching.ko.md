# 가상 패치(임시 완화) 가이드

> PHP 공식 공지는 완전한 완화책이 없다고 밝힙니다. 아래 계층은 일부 경로만 줄이며 우회될 수 있습니다.
> 패치(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 / 8.6.0RC4)가 가능하면 그것이 최우선입니다. 7.4/8.0/8.1 은
> 벤더 패치 또는 PHP 보안팀 소스 백포트 브랜치뿐이고, 5.4-7.3 은 EOL 로 수정이 없습니다.
> 파일은 `virtual-patch/` 에 있습니다.

## 계층

1. 요청 형태 제한: nginx `client_max_body_size`, Apache `LimitRequest*`, IIS `maxAllowedContentLength`.
   Apache 는 chunked 본문도 누적해 제한합니다.
2. 표지/중첩/multipart 규칙(ModSecurity): `PHP_SESSION_UPLOAD_PROGRESS` 필드명, 과도한 대괄호 중첩,
   과다 인자/파일, chunked multipart. 업로드가 없는 사이트는 multipart 전체 차단 가능.
3. PHP 관리자 전용 ini: `php_admin_value/flag`(pool 또는 mod_php)로 고정. `session.upload_progress.enabled=0`,
   크기 상한. memory_limit 은 ini 파일이 아니라 admin 설정에만 둡니다(덮어쓰기 방지). pool/Apache 파일에서
   `memory_limit=-1` 은 기본 주석 처리입니다. OS 메모리 상한을 먼저 설정하고 적용 여부를 확인한 뒤에만 pool 의
   `;php_admin_value[memory_limit] = -1` 앞의 `;` 또는 Apache 해당 모듈 블록의
   `#php_admin_value memory_limit -1` 앞의 `#` 를 제거하세요. 다른 업로드 진행률/크기 제한은 기본 활성입니다.
   `session.auto_start=0` 은 $_SESSION 을 session_start() 없이 쓰는 페이지를 깨뜨릴 수 있습니다(Xint).
4. OS 메모리 상한(가용성 경계): `memory_limit=-1` 은 상한을 없애므로 systemd MemoryMax/cgroup/컨테이너
   mem_limit/--memory 를 먼저 설정해야 합니다. RLIMIT_AS/RLIMIT_DATA 는 취약한 할당 실패를 유발할 수 있어 쓰지 마세요.
   이 상한은 가용성 보호이지 공격 차단이 아닙니다.
5. 노출 줄이기: 점검 페이지, IP 허용 목록/VPN, 다른 방법이 없으면 사이트를 내리는 것(KISA/NSA/CERT-EU 권고).
6. 침해 후 피해 축소: egress 필터링, 읽기 전용/noexec, SELinux/AppArmor, auditd/FIM,
   자격증명 교체(침해 가능성이 있으면 DB/API 키/세션 비밀 포함).

## 어떤 계층을 언제

| 상황 | 권장 |
|---|---|
| 업로드 불필요 | 크기 8M 상한 + multipart 차단(nginx block-multipart, ModSecurity 91010, IIS rewrite) |
| 업로드 필요 | 크기 32M 상한 + ModSecurity 91001-91007, 업로드 경로 제한. multipart 차단 금지 |
| mod_php | Apache 파일의 php_admin_* (pool 파일은 해당 없음) |
| PHP-FPM | pool 파일의 php_admin_* + systemd drop-in |
| nginx | nginx 조각 (+ ModSecurity v3 사용 시 규칙) |
| Apache | Apache 조각 (+ ModSecurity v2) |
| IIS | `web.config.snippet.xml` 은 크기 상한만; `web.config.block-multipart.xml` 은 업로드 없음 선택 시에만 생성·적용 (Windows 러너의 IIS에서 검증: multipart 403·크기 상한 413·롤백, 정적 파일 대상 — `tests/windows_iis_check.ps1`) |
| 컨테이너 | compose 하드닝 + 이미지 교체 |
| 노출 감소 불가 + 완화 부족 | 서비스 중단 고려 |

## 적용 방법

1. DetectionOnly 로 시작(ModSecurity `SecRuleEngine DetectionOnly`), 감사 로그에서 오탐 확인.
2. 오탐이 없거나 예외 처리가 끝나면 On 으로 전환. 규칙별 제외는 `SecRuleRemoveById`.
3. 설정마다 구문 테스트(`nginx -t`, `apachectl configtest`, `php-fpm -t`) 후 reload.
4. 스테이징에서 로그인, 업로드, 세션 기능 확인.

## 롤백

각 파일 머리말에 방법이 있습니다. 공통: 추가한 줄/파일 삭제, 구문 테스트, reload.
systemd 는 daemon-reload 후 restart, SELinux 는 setsebool/semanage 되돌리기.

## 우회와 한계

- 문자셋 변형, RFC 2231/5987 인코딩, 대용량 본문, 분할 요청으로 규칙이 우회될 수 있습니다.
- 규칙은 공개된 표지만 봅니다. 알려지지 않은 변형은 탐지하지 못합니다.
- 크기 제한은 공격 가능한 입력을 완전히 막지 않습니다.
- 정상 요청을 막을 수 있습니다(오탐). 업로드 앱에서 특히 주의.
- OS 메모리 상한은 가용성 보호일 뿐 코드 실행/메모리 노출을 막지 않습니다.
- 침해 후 계층(egress, auditd 등)은 피해 축소/탐지이지 방어가 아닙니다.
- 결국 패치만이 근본 조치입니다.
