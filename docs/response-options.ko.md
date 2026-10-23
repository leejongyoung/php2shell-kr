# PHP2Shell 대응 옵션 선택 가이드

기준일: 2026-10-23. 대상: CVE-2026-109618, CVE-2026-109619 (PHP 엔진의 인증 없는 원격 코드 실행 및 프로세스 메모리 노출, CVSS v4.0 9.2).
이 문서는 방어용입니다. 공격 코드, 페이로드, 취약점을 발생시키는 방법은 담지 않습니다.

관련 문서:

- 폐쇄망·오프라인 패치 절차: [`offline-patching.ko.md`](offline-patching.ko.md)
- 가상 패치(WAF, 웹 서버, PHP 설정, OS 수준 완화): [`virtual-patching.ko.md`](virtual-patching.ko.md)
- 사고 대응 런북(KISA 수칙 1~8 순서): [`runbook.ko.md`](runbook.ko.md)
- 연락처·신고: [`contacts.ko.md`](contacts.ko.md)

## 0. 먼저 알아둘 사실 (출처 표기)

| 사실 | 출처 |
|---|---|
| 수정 버전: PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (2026-10-21 공개). 8.6.0 RC4에도 수정 포함(테스트용, 운영 사용 금지). | [PHP 보안 공지](https://www.php.net/archive/2026.php#2026-10-21-5), [PHP 8.6.0 RC4 공지](https://www.php.net/archive/2026.php#2026-10-21-6) |
| 웹 요청을 처리하는 모든 SAPI(PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed)가 대상. 위험은 mod_php가 가장 높다고 PHP가 밝힘. | PHP 보안 공지 |
| 8.1 이하는 PHP 프로젝트의 업데이트가 없음. 일부 배포판·LTS 업체가 백포트를 제공. PHP 보안팀이 7.4, 8.0, 8.1용 최소 소스 백포트 브랜치를 공개. | PHP 보안 공지 |
| 5.4~7.3은 EOL이며 PHP 프로젝트의 수정이 없음. 취약 코드는 PHP 5.4(2012)부터 존재. | [Sysdig](https://www.sysdig.com/blog/php2shell-cve-2026-109618-and-cve-2026-109619-detecting-unauthenticated-remote-code-execution-in-php-core) |
| PHP 8.2는 2026-12-31에 보안 지원 종료. KISA는 8.3 이상 전환을 권장. | PHP 8.2.35 공지, [KISA 수칙 3](https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72230) |
| PHP 공식 입장: "완전한 완화책은 없으며 업데이트만이 안전한 선택". 임시 설정은 일부 공격 경로만 줄입니다. | PHP 8.5.12 등 릴리스 공지 |
| 배포판 패키지는 버전 번호를 바꾸지 않고 패치만 백포트할 수 있으므로, 패키지 변경 이력에서 CVE 반영 여부를 확인해야 함. | KISA 수칙 2, Sysdig |
| 최초 악용 관측: 2026-10-17(공개 4일 전). KISA는 최소 10-20 이후 기록 점검을 요구. | Sysdig, KISA 수칙 5 |

> 이 문서의 모든 "가상 패치"는 시간을 버는 수단일 뿐입니다. 우회가 쉽고(문자셋 변형, RFC 2231/5987 인코딩, 대용량 데이터 등, 출처: Xint) 같은 원인의 변종 경로가 더 있다고 알려져 있습니다. 패치를 적용하고 모든 워커를 재시작해야 끝납니다.

## 1. 옵션 한눈에 보기

| 옵션 | 이름 | 근본 해결 | 한 줄 요약 |
|---|---|---|---|
| A | 온라인 패치(패키지 업데이트) | 예 | 인터넷(또는 사내 미러)이 되는 서버에서 배포판 패키지를 업데이트하고 재시작 |
| B | 오프라인/폐쇄망 패치 | 예 | 연결된 PC에서 패키지를 받아 무결성을 확인한 뒤 매체로 옮겨 설치 |
| C | 컨테이너 이미지 재빌드·재배포 | 예 | 베이스 이미지를 고친 버전으로 올려 재빌드하고 롤링 재배포 |
| D | 소스 빌드 | 예(백포트 브랜치는 "최소 백포트") | 공식 소스 tarball 또는 7.4/8.0/8.1 PHP 보안팀 백포트 브랜치를 직접 빌드 |
| E | 벤더·호스팅·장비 제조사에 요청 | 업체가 하면 예 | PHP가 내장된 제품은 직접 고칠 수 없으므로 업체에 적용 여부 확인·요청 |
| F | 가상 패치 | 아니오 | WAF/웹 서버/PHP 설정/OS 한도로 일부 경로만 완화. 상세는 [`virtual-patching.ko.md`](virtual-patching.ko.md) |
| G | 노출 축소·서비스 중단 | 아니오 | 외부 접근 차단, 허용 IP 제한, 점검 페이지로 대체 |
| H | 사후 피해 억제·탐지 | 아니오 | 침해를 가정하고 권한·외부 통신·비밀정보를 줄이고 로그·프로세스를 감시 |
| I | 지원 버전으로 이전 | 예(이전 완료 후) | 8.3 이상(KISA 권고)으로 전환하는 계획·실행 |

원칙: 근본 해결(A, B, C, D, E, I) 중 하나를 목표로 정하고, 그 사이를 F, G, H로 메웁니다. F, G, H만으로 끝내지 마세요.

## 2. 내 시스템 분석 (옵션을 고르기 전에)

KISA 수칙 1은 "자산 목록에만 의존하지 말고 실제 동작 중인 서버를 기준으로" 확인하라고 합니다. 아래 명령은 읽기만 하며 서버 상태를 바꾸지 않습니다.

### 2.1 어떤 PHP가 어떤 SAPI로 도는가

```bash
# PHP 관련 프로세스 (SAPI 추정): php-fpm, php-cgi, frankenphp, lsphp(LiteSpeed), apache2/httpd(mod_php 가능성)
ps -eo pid,user,lstart,args | grep -E 'php-fpm|php-cgi|frankenphp|lsphp|litespeed|apache2|httpd' | grep -v grep

# Apache에 PHP 모듈이 적재됐는가 (mod_php 여부). Debian/Ubuntu: apache2ctl, RHEL계열: httpd
apache2ctl -M 2>&1 | grep -i php        # 결과 예: php_module (shared)
httpd -M 2>&1 | grep -i php

# 서버에 설치된 PHP 실행 파일·모듈 후보 (여러 버전이 있을 수 있음)
find / -xdev \( -name 'php-fpm*' -o -name 'php-cgi*' -o -name 'libphp*.so' -o -name 'frankenphp' -o -name 'lsphp*' \) -type f 2>/dev/null
```

- `php -v`(CLI)는 웹 서비스가 쓰는 PHP와 다를 수 있습니다(KISA 수칙 2). 한 서버에 PHP가 여러 개면 각각 확인하세요.
- Xint는 웹으로 직접 설정을 확인하는 점검 스크립트(`php2shell_check.php`, 다운로드 `https://gist.github.com/xint-io/14630b00ed2ff90cdde3bb92162e316f`, SHA-256 `87fd1076386a8c4fd0b3f9477eaf02debca1c36b54c9913e73b76fd18f562e08`)를 제공합니다. 이 저장소는 그 스크립트를 실행·검증하지 않았습니다(미검증). 쓰려면 먼저 코드를 직접 읽고 해시를 대조하고, 추측하기 어려운 이름으로 올렸다가 확인 직후 삭제하세요. KISA 수칙 8은 출처 불분명한 PoC 실행을 금하며 버전 확인과 기록 점검으로 판단하라고 합니다.
- 웹 SAPI가 실제로 어떤 버전·설정인지는 웹 요청으로만 알 수 있습니다. 임시 확인 파일은 확인 직후 삭제합니다.

### 2.2 판단에 필요한 질문

| 질문 | 확인 방법 | 선택에 미치는 영향 |
|---|---|---|
| SAPI | 2.1 | mod_php가 최우선(PHP가 위험이 가장 높다고 평가). 요청이 애플리케이션 코드 전에 영향을 줄 수 있음 |
| PHP 브랜치 | `php-fpm8.2 -v`, `rpm -q php-fpm`, 이미지 태그 | 8.2~8.5: A/B/C. 7.4/8.0/8.1: 벤더 패치 확인(A/B/E) 또는 D. 5.4~7.3: 수정 없음 -> I와 G/F |
| 인터넷 연결 | 서버에서 저장소 접근 가능 여부 | 연결: A. 폐쇄망: B |
| 업로드가 필요한가 | 애플리케이션 담당자 확인 | 필요 없으면 multipart 차단(F/G)이 쉬움. 필요하면 post_max_size 32M 수준과 경로 단위 허용 |
| 세션 사용 | `grep -rln '\$_SESSION' DOCROOT`, `grep -rln 'session_start' DOCROOT` | `session.auto_start=0`은 `session_start()` 없이 `$_SESSION`을 쓰는 페이지를 멈출 수 있음(출처: Xint) |
| 컨테이너 | `docker ps`, 배포 매니페스트 | 호스트 패키지를 고쳐도 이미지 안의 PHP는 그대로. C 필요 |
| WAF/CDN 존재 | 업체 콘솔 | 관리형 규칙 적용 여부 확인(출처: Xint, KISA 수칙 4). WAF는 패치를 대체하지 못함 |
| 다운타임 허용 | 서비스 담당자 | 무중단이 필요하면 LB에서 노드를 빼고 한 대씩 롤링 |
| 제3자 제품 | 공급사 확인 | E. 목록은 [NCSC-NL 저장소](https://github.com/NCSC-NL/php2shell)의 `software` 디렉터리 참고 |

## 3. 결정표: 시스템 분석 -> 옵션 순서

"순서"는 먼저 할 일부터입니다. 괄호는 병행 또는 대체입니다. 여러 행에 해당하면 가장 위험한 행(mod_php, 인터넷 공개)의 순서를 따르세요.

| 상황 | 순서 | 비고 |
|---|---|---|
| mod_php + 인터넷 공개 | 공개 서버 중 최우선: A/B/C -> (패치 전 F + 필요 시 G) -> H | PHP가 위험이 가장 높다고 평가. 인터넷에 공개된 서버부터 조치(KISA 수칙 2) |
| 8.2~8.5 + 인터넷 연결 | A -> 재시작 -> 증명(5절) -> H | 가장 빠른 경로 |
| 8.2~8.5 + 폐쇄망 | B -> (대기 중 F, 외부 접점이 있으면 G) -> H | 사전 점검표는 [`offline-patching.ko.md`](offline-patching.ko.md) |
| 컨테이너(Docker, Kubernetes) | C -> (이미지 레지스트리가 폐쇄망이면 B의 Docker 절차) -> H | 컨테이너 환경은 신규 이미지 재배포(KISA 수칙 2) |
| 7.4/8.0/8.1 + 배포판·LTS 패치 제공 | A 또는 B(벤더 패키지) -> 변경 이력 확인 -> I 계획 | 버전 번호가 안 바뀔 수 있어 변경 이력으로 증명 |
| 7.4/8.0/8.1 + 벤더 패치 없음 | F + (필요 시 G) -> D(PHP 보안팀 백포트 브랜치) 또는 E -> I | 백포트는 "최소 소스 백포트". 스테이징에서 먼저 시험 |
| 5.4~7.3 | G/F로 노출 축소 -> I(지원 버전 이전). 벤더 연장 지원이 있으면 E | PHP 프로젝트의 수정과 소스 백포트 브랜치가 없음. EOL 버전을 직접 고치는 것은 권장하지 않음(이 문서의 판단) |
| PHP 내장 장비·솔루션, 호스팅 | E -> G(관리 화면 접근을 VPN/허용 IP로 제한) -> F(가능한 계층에서) | 직접 업데이트 불가. 업체에 적용 일정 확인(KISA 개요의 "※" 항목) |
| 업로드 불필요 | F에서 multipart 차단 + `post_max_size=8M` -> A/B/C | KISA 수칙 4, PHP 공지 |
| 업로드 필요 | F에서 업로드 경로만 예외 + `post_max_size=32M` -> A/B/C | `upload_max_filesize`는 `post_max_size`보다 작게 |
| 세션 기능이 `session_start()` 없이 동작 | `session.auto_start=0` 적용 전 코드 확인 | 적용 시 로그인·장바구니가 멈출 수 있음 |
| WAF 있음 | 업체의 최신 규칙 적용 확인(F) + 패치 | WAF는 우회가 쉬움. 규칙만 믿지 말 것 |
| 다운타임 불가 | LB에서 노드 분리 -> 패치 -> 재시작 -> 복귀를 노드별 반복(A/C) | 재시작 전 헬스체크 |
| 침해 흔적 있음 | 즉시 [`runbook.ko.md`](runbook.ko.md)의 격리 -> 신고 -> 증거 확보 -> 조치. 패치와 재시작은 증거 확보 뒤 | KISA 수칙 7 |
| 지금 패치도 임시 조치도 불가 | G(외부 접속 차단 또는 서비스 일시 중단) | KISA 수칙 3, 4 |

## 4. 옵션별 상세

### 옵션 A. 온라인 패치(패키지 업데이트)

**언제 고르나**: 배포판·벤더가 수정된 패키지를 제공하고 서버가 저장소에 접근할 수 있을 때. 가장 빠르고 되돌리기 쉬운 근본 조치입니다.

**전제 조건**
- 작업 창과 롤링 계획. 변경 전 설정 백업(`/etc/php`, `/etc/php-fpm.d`, `/etc/httpd`, `/etc/apache2`, `/etc/nginx`, 애플리케이션 `.user.ini`).
- 패키지 고정(hold)·핀 설정 확인: `apt-mark showhold`, `dnf versionlock list`(versionlock 플러그인 사용 시).
- 제3자 PHP 저장소(예: Remi 등)를 쓰면 그 저장소의 공지·변경 이력 확인. 배포판 저장소 기준 명령이 그대로 맞지 않을 수 있음.
- 한 서버에 PHP 버전이 여러 개인지 확인(KISA 수칙 2).

**절차**
1. 5절의 OS별 명령으로 업데이트.
2. 설정 파일 덮어쓰기 여부 확인. apt가 수정된 설정 파일에 대해 묻는다면 기존 설정 유지 옵션 `-o Dpkg::Options::="--force-confold"`를 쓸 수 있습니다(문법만 모의 실행으로 확인).
3. **웹 서비스 재시작** (PHP-FPM, Apache, LiteSpeed, FrankenPHP 등). 재시작하지 않으면 메모리에 남은 이전 버전이 계속 동작합니다(KISA 수칙 2).
4. 6절의 방법으로 패치를 증명.

**장점**: 빠름, 벤더 지원 유지, 의존성 자동 해결. **단점**: 배포판이 아직 패키지를 내지 않았을 수 있음(실제로 이 문서 검증 시점에 Alpine 3.20 저장소는 php83 8.3.15, openSUSE Leap 15.6은 8.2.30으로 CVE 항목이 없었음. 5절, 8절 참고). 호환성 문제 가능성(KISA 개요의 "사전 영향도 검토 및 테스트" 권고).

**검증**: 6절.

**롤백**: 설정 파일은 백업에서 복원할 수 있습니다. **패키지를 이전 버전으로 되돌리는 것은 권장하지 않습니다.** 이전 버전은 인증 없는 RCE에 노출된 버전이기 때문입니다. 호환성 문제가 생기면 (1) 고치는 방향으로 해결하고, (2) 부득이하게 되돌리면 같은 시간 안에 F+G를 적용하고 되돌린 기간을 최소화하며 증거 확인(H)을 병행하세요.

### 옵션 B. 오프라인/폐쇄망 패치

**언제 고르나**: 서버가 인터넷과 사내 미러에 접근할 수 없을 때.

**핵심**: 연결된 PC에서 서버와 같은 OS 릴리스·아키텍처의 패키지를 받고, 독립 채널의 체크섬·서명으로 무결성을 확인한 뒤 매체로 옮겨 설치하고, 설치 전후에 변경 이력으로 CVE 반영을 확인합니다. 전체 절차, 사전 점검표, 검증한 명령은 [`offline-patching.ko.md`](offline-patching.ko.md)에 있습니다.

**장점**: 인터넷 없이 가능. **단점**: 의존성 닫힘(closure) 계산이 어렵고, 절차가 느리며, 전송 매체가 공격 경로가 될 수 있음. **롤백**: 옵션 A와 같은 이유로 이전 패키지로의 롤백은 권장하지 않음. 설정은 백업에서 복원.

### 옵션 C. 컨테이너 이미지 재빌드·재배포

**언제 고르나**: PHP가 컨테이너 이미지 안에 있을 때. 호스트의 패키지를 업데이트해도 컨테이너 내부 PHP는 바뀌지 않습니다. 컨테이너 환경은 신규 이미지를 재배포해야 합니다(KISA 수칙 2). 외부에서 받아 쓰는 이미지도 별도 확인 대상입니다(KISA 수칙 1).

**전제 조건**
- 이미지 출처 파악: 직접 빌드(Dockerfile) 또는 외부 이미지. 외부 이미지는 공급사가 재빌드했는지 확인(예: NCSC-NL 목록에 UnoPim 공식 이미지가 2026-10-22에 PHP 8.4.27로 재빌드됐다는 항목이 있음).
- 고정할 태그 결정. 존재를 `docker manifest inspect`로 확인한 공식 태그(2026-10-23 확인, 예시): `php:8.2.35-cli`, `php:8.2.35-fpm`, `php:8.2.35-apache`, `php:8.3.36-fpm`, `php:8.3.36-fpm-alpine`, `php:8.3.36-apache`, `php:8.4.27-cli`, `php:8.4.27-fpm`, `php:8.4.27-apache`, `php:8.4.27-fpm-alpine`, `php:8.4.27-cli-alpine`, `php:8.4.27-zts`, `php:8.5.12-fpm`, `php:8.5.12-apache`, `php:8.5.12-cli-alpine`. 목록에 없는 변형은 같은 방법으로 먼저 확인하세요.

**절차**
```bash
# 태그 존재 확인 (레지스트리 접근 필요)
docker manifest inspect php:8.4.27-fpm > /dev/null && echo exists

# Dockerfile의 FROM을 수정 버전으로 올린 뒤, 캐시를 쓰지 않고 베이스를 새로 받아 빌드
docker build --pull --no-cache -t myapp:2026-10-23-php8.4.27 .

# 빌드 결과의 PHP 버전 (CLI임에 유의: 웹 SAPI 확인은 6절)
docker run --rm myapp:2026-10-23-php8.4.27 php -v
```
- Docker Compose를 쓰면 `docker compose build --pull --no-cache` 후 `docker compose up -d`(미검증).
- Kubernetes는 새 이미지 태그로 매니페스트를 갱신해 롤아웃: `kubectl set image deployment/NAME CONTAINER=IMAGE:TAG` 후 `kubectl rollout status deployment/NAME`. [검증] kind 클러스터에서 `php:8.4.26-fpm` → `8.4.27-fpm` 롤아웃이 성공했고, 옛 파드가 삭제된 뒤 새 파드에서 점검 스크립트가 취약(종료 코드 1) → 수정됨(0)으로 바뀌는 것을 확인했습니다(`tests/k8s_check.sh`). 같은 태그를 덮어써 `rollout restart`만 하면 노드의 이미지 캐시 정책에 따라 옛 이미지를 쓸 수 있다는 점은 시험하지 않았으므로 새 태그나 다이제스트 사용을 권장합니다.
- 이미지 안의 PHP 설정(`conf.d`의 ini)도 이미지에 포함합니다(Xint: 컨테이너는 이미지의 `conf.d`에 ini 추가 후 재빌드·재배포).

**장점**: 재현 가능, 롤링 배포 쉬움. **단점**: 파생 이미지가 여러 겹이면 모두 재빌드해야 함. 오래된 베이스 이미지(예: 7.x, 8.0, 8.1)는 공식 이미지 수정이 없음.

**검증**: 실행 중인 컨테이너의 이미지 ID/다이제스트가 새 이미지인지, 컨테이너 안의 웹 SAPI 바이너리 버전이 수정 버전인지(6절). 레지스트리의 옛 태그와 오래된 컨테이너가 남아 있지 않은지 확인.

**롤백**: 이전 이미지 태그로 되돌리는 것은 취약한 이미지를 다시 띄우는 것이므로 **권장하지 않습니다**. 앱이 새 PHP에서 오류를 내면 같은 PHP 수정 버전의 다른 변형이나 앱 수정으로 해결하고, 불가피하면 F를 이미지에 포함해 최소 기간만 쓰세요.

### 옵션 D. 소스 빌드

**언제 고르나**
- 8.2~8.5를 직접 빌드해서 쓰고 있을 때: PHP 공식 tarball의 수정 버전으로 재빌드.
- 7.4/8.0/8.1이고 벤더 패치가 없을 때: PHP 보안팀이 "소스 빌드 또는 LTS 벤더 접근이 없는 사용자를 돕기 위해" 공개한 최소 백포트 브랜치를 사용.

**백포트 브랜치 (PHP 보안 공지 및 `data/advisory.json`)**
- 7.4: <https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619>
- 8.0: <https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619>
- 8.1: <https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619>

**전제 조건**: 현재 빌드의 configure 옵션 기록(`php -i | grep 'Configure Command'`), 빌드 도구·개발 헤더, 스테이징 서버, 설치 위치를 기존과 분리(`--prefix`)해 전환·복귀가 쉽도록.

**절차(요약)**
```bash
git clone --depth 1 --branch PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src
cd php-src
git log -1 --format='%H %an %ad %s'      # 커밋 해시를 기록하고 독립 채널(다른 PC의 GitHub 웹 화면)과 대조
./buildconf --force
./configure --prefix=/opt/php-8.1-backport <기존 Configure Command 옵션>
make -j"$(nproc)" && make test            # 테스트 결과는 반드시 검토
sudo make install
```
- 검증 환경(debian:12, aarch64): 위 클론~`buildconf`~`configure --disable-all --enable-cli --enable-fpm`~`make`는 이 문서 8절 "소스 빌드 검증"에 결과를 적었습니다. 확장(extension)이 많은 실제 운영 빌드는 검증하지 않았습니다(미검증).
- 설치 후 PHP-FPM/Apache가 새 바이너리·모듈을 가리키도록 서비스 단위 파일 또는 모듈 경로를 수정하고 **재시작**.
- 공식 tarball을 쓸 때의 무결성 확인은 [`offline-patching.ko.md`](offline-patching.ko.md)의 "소스 tarball" 절 참고.

**장점**: 공식 수정이 없는 7.4/8.0/8.1에도 적용 가능. **단점**: 백포트는 "최소 소스 백포트"로 정식 릴리스가 아니며, 이후 보안 수정은 직접 추적해야 합니다. 자체 빌드는 패키지 관리자의 보안 업데이트 체계 밖에 놓입니다. 임시 조치로만 쓰고 I(이전) 계획을 세우세요(KISA 수칙 3). 5.4~7.3에는 백포트 브랜치가 없습니다.

**검증**: 새 바이너리의 `-v`, 웹 SAPI가 새 바이너리를 쓰는지(6절), 테스트 스위트·애플리케이션 회귀 시험.

**롤백**: `--prefix`로 분리했다면 서비스 단위를 이전 경로로 돌리면 되지만, 이전 빌드는 취약합니다. 롤백은 **권장하지 않으며** 불가피하면 F+G를 함께 적용하세요.

### 옵션 E. 벤더·호스팅·장비 제조사에 요청

**언제 고르나**: PHP가 장비·솔루션(네트워크 장비 관리 화면, PHP가 포함된 Windows용 설치 패키지 등)에 내장되었거나, 호스팅 업체가 PHP를 관리할 때. KISA는 이 경우 해당 업체에 조치 적용 여부를 확인하고 요청하라고 안내합니다.

**전제 조건**: 제품명·버전, 내장 PHP 버전(알 수 있다면), 외부 노출 여부. 공급사 상태 목록으로 [NCSC-NL php2shell 저장소](https://github.com/NCSC-NL/php2shell)의 `software` 디렉터리(2026-10-23 00:48 CEST 기준 갱신)를 참고할 수 있습니다. 예를 들어 같은 문서의 최신 상태에 Fortinet 일부 제품이 "Investigation"으로 표시돼 있었습니다. 상태는 계속 바뀌므로 공급사 공지 원문을 확인하세요.

**절차**
1. 공급사 보안 공지 확인(제품별 PSIRT 등). 알려진 연락처는 [`contacts.ko.md`](contacts.ko.md) 참고.
2. 업체에 문의할 항목: (a) 이 제품이 CVE-2026-109618/109619 영향을 받는가, (b) 내장 PHP 버전과 패치 여부, (c) 패치·펌웨어 제공 일정, (d) 그 전까지 권장되는 임시 조치, (e) 침해 확인 방법.
3. 호스팅: PHP 업데이트 일정과 임시 설정 적용을 요청. 가상호스팅에서 설정 변경이 막혀 있다면 호스팅사가 막아둔 것입니다(Xint).
4. 업체 패치가 나올 때까지 G(관리 화면을 VPN/허용 IP로만 접근)를 적용.

**장점**: 직접 고칠 수 없는 제품의 유일한 근본 조치. **단점**: 일정이 업체에 달림. **검증**: 업체 공지의 수정 버전 확인, 가능하면 제품 화면에서 내장 PHP 버전 확인. **롤백**: 펌웨어·패치는 벤더 절차를 따르되, 롤백이 가능하더라도 되돌린 동안 G를 유지.

### 옵션 F. 가상 패치

**언제 고르나**: 패치까지 시간이 걸릴 때 그 사이에 공격 경로 일부를 줄이기 위해. 대표적으로 WAF/웹 서버에서 요청 크기·multipart 제한, PHP 설정(`session.upload_progress.enabled=0`, `memory_limit=-1` + OS 메모리 상한, `post_max_size` 하향 등).

**내용은 [`virtual-patching.ko.md`](virtual-patching.ko.md)를 보세요.** 이 문서는 선택 기준만 다룹니다.

반드시 알아둘 것:
- PHP는 "완전한 완화책은 없다"고 밝혔습니다. F는 특정 경로만 줄이며 우회가 쉽습니다.
- `memory_limit=-1`은 컨테이너·cgroup·systemd `MemoryMax` 등 OS 수준 메모리 상한과 함께 써야 하며, 그 대안으로 `RLIMIT_AS`/`RLIMIT_DATA`를 쓰면 안 됩니다(취약한 할당 실패를 유발할 수 있다고 PHP가 경고).
- `session.auto_start=0`은 `session_start()` 없이 `$_SESSION`을 쓰는 페이지를 멈출 수 있습니다(Xint).
- 설정 반영 후 **모든 워커 재시작**, CLI가 아닌 웹 요청으로 값 확인(Sysdig, PHP 공지).

**롤백**: 설정·규칙은 백업에서 복원하면 되지만, 패치 전에는 되돌리지 마세요. 패치 완료 뒤 불필요해진 규칙(예: `memory_limit=-1`)은 정리하되 업로드 한도 등 안전한 값은 유지해도 됩니다.

### 옵션 G. 노출 축소·서비스 중단

**언제 고르나**: 5.4~7.3처럼 수정이 없거나, 패치와 임시 조치 모두 어려울 때(KISA 수칙 3, 4: "외부 접속 차단 또는 서비스 일시 중단 검토"), 또는 침해가 의심될 때 외부 노출을 끊어야 할 때.

**방법(강도 순)**
1. 관리자 화면·내부 도구를 VPN/허용 IP로만 접근(방화벽, LB, 클라우드 보안 그룹, 웹 서버 ACL).
2. 필요한 경로(예: 정적 파일)만 열고 PHP 경로는 허용 IP로 제한.
3. 점검 페이지(정적 응답)로 대체.
4. PHP 서비스 중단 또는 외부 연결 차단.

예시: nginx에서 PHP 경로를 허용 IP로 제한하고 나머지에 점검 응답(구문은 `nginx -t`로 확인, 동작 부하는 시험하지 않음). 주소 `192.0.2.0/24`는 문서용 예시이므로 실제 값으로 바꾸세요.
```nginx
# 목적: PHP 경로를 허용 IP로만 열고 나머지는 503 점검 응답.
# 보호하지 못하는 것: 허용 IP 안의 공격자, 허용된 프록시를 통한 우회. 패치의 대체가 아님.
# 적용 전: nginx -t 로 구문 확인, 허용 IP 목록 확인.  롤백: 이 파일을 제거하고 nginx -s reload.
server {
    listen 8081;
    server_name _;
    root /var/www/html;
    location ~ \.php$ {
        allow 192.0.2.0/24;
        deny  all;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        include fastcgi_params;
    }
    location / {
        default_type text/plain;
        return 503 "maintenance";
    }
}
```
Apache에서는 `<LocationMatch "\.php$"> Require ip 192.0.2.0/24 </LocationMatch>`로 같은 제한을 걸 수 있습니다(`apache2ctl configtest`로 구문 확인). 더 자세한 웹 서버·WAF 설정은 [`virtual-patching.ko.md`](virtual-patching.ko.md)를 보세요.

**장점**: 즉시 효과, 도구가 필요 없음. **단점**: 서비스 영향 큼, 허용 범위 안의 공격은 막지 못함. **검증**: 외부 네트워크에서 PHP 경로가 차단되는지, 허용 IP에서만 열리는지 확인. **롤백**: 규칙 제거는 패치·검증 완료 뒤에만.

> 침해 사고라면 서버를 끄거나 재시작하지 말고 외부 접속만 차단합니다(KISA 수칙 7). 증거 보존 순서는 [`runbook.ko.md`](runbook.ko.md).

### 옵션 H. 사후 피해 억제·탐지

**언제 고르나**: 항상 병행. Sysdig는 "assume breach" 관점을 권합니다. 취약점은 애플리케이션 아래 단계에서 동작해 애플리케이션 로그에 흔적이 적고, 공격이 실패해도 PHP·웹 서버 로그에는 남을 수 있습니다(Xint).

**조치**
- 로그 점검: [`runbook.ko.md`](runbook.ko.md)의 명령(최소 2026-10-17 이후). "이상 없음"이 "안전함"을 뜻하지 않습니다(KISA 수칙 5).
- 웹 서버 계정이 셸(sh, bash)이나 다운로드 도구를 실행하는지 감시(KISA 수칙 5, Sysdig). Falco는 HTTP 요청을 보지 못하고 호스트에서 일어나는 결과(웹 프로세스가 띄운 셸 등)를 봅니다(Sysdig).
- 웹 서버 프로세스의 외부 아웃바운드 연결 제한(필요한 목적지만 허용).
- 웹 문서 루트를 웹 계정이 쓸 수 없도록 하고, 업로드·임시 디렉터리에서 PHP 실행 금지(애플리케이션 영향 시험 필요).
- 인증정보 교체(수칙 6): 서버 메모리에 있던 DB 비밀번호, 토큰, API 키가 유출될 수 있음. Sysdig는 TLS 개인 키도 메모리에 있을 수 있다고 언급.
- auditd로 웹 사용자의 `execve`를 기록하는 방식도 있으나 이 저장소에서는 시험하지 않았습니다(미검증).

**장점**: 침해를 빨리 발견하고 피해 범위를 줄임. **단점**: 패치를 대체하지 못함, 오탐·노이즈. **검증**: 알림이 실제로 발생하는지 시험(공격 코드 없이, 예: 정상적인 테스트 환경에서 웹 계정으로 셸 실행을 흉내). **롤백**: 해당 없음(관측성 강화). 단, 수집한 증거는 삭제하지 마세요([`contacts.ko.md`](contacts.ko.md)의 증거 은닉·폐기 주의 참고).

### 옵션 I. 지원 버전으로 이전

**언제 고르나**: 8.1 이하(수정 없음 또는 벤더 패치에 의존), 8.2(2026-12-31 종료). KISA는 8.1 이하를 지원 버전으로 전환하고, 8.2도 8.3 이상 전환을 권장합니다. 전환에 시간이 걸리면 벤더 패치 또는 PHP 보안팀 소스 패치(7.4/8.0/8.1)를 임시로 적용하고 전환 계획을 세웁니다.

**전제 조건**: 애플리케이션 호환성 목록(프레임워크·CMS·플러그인이 지원하는 PHP 버전), 스테이징, 테스트 자동화.

**절차(요약)**
1. 인벤토리 확정(수칙 1).
2. 목표 브랜치 결정(8.3 이상. 이 문서 기준 수정 버전: 8.3.36, 8.4.27, 8.5.12).
3. 호환성 점검: `composer check-platform-reqs`(Composer 사용 시, 미검증), 프레임워크·플러그인 요구 버전 확인, 폐기 예정 기능 사용 점검.
4. 새 PHP를 별도 풀/소켓/컨테이너로 올려 일부 트래픽부터 전환.
5. 전환 완료 후 옛 PHP 제거(남겨두면 공격면이 됨).

**장점**: 장기적 해결. **단점**: 시간·비용, 회귀 위험. **검증**: 인벤토리에서 옛 버전이 0인지, 웹 SAPI가 새 버전인지. **롤백**: 전환 중 롤백 경로는 옛 PHP이므로 취약합니다. 옛 환경으로 되돌리는 경우 F+G를 적용하고 기간을 정하세요.

## 5. OS별 온라인 빠른 패치 명령

아래는 "패키지에 이미 수정이 들어 있다"는 전제입니다. 저장소가 아직 수정을 내지 않았다면 업데이트해도 해결되지 않습니다. 업데이트 전후에 6절로 증명하세요. `[검증]`은 이 문서 작성 중 컨테이너에서 실행한 것, `[미검증]`은 실행하지 않은 것입니다.

### Debian / Ubuntu (apt)
```bash
sudo apt-get update
# 설치된 php*, libapache2-mod-php* 패키지만 골라 업그레이드 (업그레이드가 없으면 0 upgraded)
sudo apt-get install --only-upgrade $(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk '$1=="ii"{print $2}')
```
- [검증] debian:12에서 `apt-get -s`(모의 실행)로 명령 문법 확인. Ubuntu 24.04에서는 이 명령 자체를 실행하지 않았고(같은 apt 계열이라는 점에서 같은 문법으로 보이나 미검증), 변경 이력 확인과 다운로드 목록 생성만 실행했습니다. `dpkg-query -W 'php*'`만 쓰면 설치되지 않은 패키지 이름까지 나오므로 위처럼 `ii` 상태만 거릅니다.
- 재시작: `sudo systemctl restart php8.2-fpm`(버전은 환경에 맞게), Apache는 `sudo systemctl restart apache2` [미검증, debian:12에서 `php8.2-fpm.service` 유닛 파일이 설치되는 것은 확인].
- 보류(hold) 확인: `apt-mark showhold`.

### RHEL 계열 (Rocky, Alma, RHEL 등: dnf / yum)
```bash
sudo dnf upgrade --refresh 'php*'      # RHEL 7 등 yum: sudo yum update 'php*'  [미검증]
dnf module list php                    # 모듈 스트림 사용 시 현재 스트림 확인
```
- [검증] rockylinux:9에서 `dnf check-update 'php*'`, `dnf upgrade --refresh 'php*'`, `dnf module list php` 문법 확인. 이미지에는 `php-cli-8.0.30-8.el9_8.1`이 설치되며 그 변경 이력에 CVE가 반영돼 있었음.
- 모듈 스트림(`php:8.3` 등)을 쓰면 스트림 안에서 업데이트하세요. 스트림 변경은 별도 계획이 필요합니다.
- 재시작: `sudo systemctl restart php-fpm`, `sudo systemctl restart httpd` [미검증]. 재시작이 필요한 프로세스 확인은 `zypper ps`(SUSE, 아래) 같은 도구를 쓰거나 6절의 "삭제된 바이너리" 점검을 쓰세요. `dnf needs-restarting` 옵션은 usage만 확인했고 동작은 미검증입니다.

### Alpine (apk)
```bash
sudo apk update            # root라면 apk update
apk upgrade -U $(apk info | grep '^php')     # 설치된 php 계열만. 모두 업그레이드하려면 apk upgrade
```
- [검증] alpine:3.22에서 `apk fetch`/`apk add`(오프라인 문서 참고)와 `apk upgrade -U $(apk info | grep '^php')`(php84, php84-common이 설치된 이미지에서 문법 오류 없이 동작)를 확인했습니다. `apk info`는 `php84-cli`가 아니라 `php84`처럼 패키지 이름이 다를 수 있으니 출력을 확인하세요.
- 중요: 검증 시점의 **Alpine 3.20 저장소에는 php83 8.3.15-r0만 있었고 수정 버전이 없었습니다.** 3.22에는 php82 8.2.35-r0, php83 8.3.36-r0, php84 8.4.27-r0이 있었고, 3.23에는 php83 8.3.36-r0, php84 8.4.27-r0, php85 8.5.12-r0이 있었습니다. 수정이 없는 릴리스는 저장소 업데이트로 해결되지 않으므로 OS 릴리스 업그레이드(또는 옵션 C/D/I)를 고려하세요.
- Alpine에는 패키지 변경 이력 명령이 없으므로 업스트림 버전·릴리스 번호(예: `8.4.27-r0`)로 판단합니다.
- 재시작(OpenRC): `rc-service php-fpm84 restart` 등 [미검증].

### SUSE / openSUSE (zypper)
```bash
sudo zypper refresh
sudo zypper update 'php*'
sudo zypper list-patches --cve=CVE-2026-109618     # 이 CVE를 고치는 패치가 있는지
sudo zypper ps                                     # 업그레이드 후에도 옛 파일을 쓰고 있는 프로세스
```
- [검증] registry.opensuse.org/opensuse/leap:15.6에서 `zypper list-patches --cve=CVE-2026-109618`이 "No matching issues found."를 반환(그 시점 패치 없음), `zypper ps`가 존재함을 확인, `zypper -n update 'php*'`가 문법 오류 없이 동작("No update candidate ... highest available version is already installed").
- 재시작: `sudo systemctl restart php-fpm`, `sudo systemctl restart apache2` [미검증].

### FreeBSD (pkg)
```sh
pkg update && pkg audit -F                 # 취약점 DB를 받아 점검
pkg upgrade -g 'php*'                      # php84 등과 php84-* 확장 모두
service php_fpm restart                    # rc 스크립트 이름은 설치에 따라 다를 수 있음
```
[부분 검증] GitHub Actions의 FreeBSD 14.3 VM에서 `pkg install php84`(8.4.27)로 설치한 뒤 `tests/freebsd_check.sh`로 확인했습니다: sh 하네스 통과, 점검 도구(sh·Python)가 `/usr/local/bin/php`, `/usr/local/bin/php-cgi`, `/usr/local/sbin/php-fpm`과 버전을 찾았고 Python 판이 패키지 관리자를 `pkg`로 인식했습니다. `pkg audit -F`는 동작했고(종료 코드 1 = 취약 패키지 보고, 이 실행에서는 python312·brotli·curl 등 PHP 외 패키지가 보고됨), `pkg upgrade -n -g 'php*'`(모의 실행), `sysrc php_fpm_enable=YES` 후 `service php_fpm onestart`/`restart`가 동작했으며, 실행 중인 php-fpm을 두 구현 모두 `running=true`로 찾았습니다. 이 검증 중 FreeBSD의 `ps -o pid=,comm=`가 첫 열 머리글만 바꾸고 다른 열을 내지 않아 두 구현 모두 프로세스를 하나도 못 찾던 결함을 찾아 `-o pid= -o comm=` 형태로 고쳤습니다. **미검증**: 취약 버전이 설치된 상태에서 `pkg upgrade -g 'php*'`로 수정 버전으로 교체되는 흐름(그 시점 저장소 패키지가 이미 8.4.27), `pkg audit`에 이 CVE가 등재되는지.

### macOS Homebrew (개발용)
```sh
brew update && brew upgrade php            # 버전 지정 설치는 php@8.4 등
brew services restart php
```
[부분 검증] GitHub Actions의 macOS 26.6.2(arm64) 러너에서 `brew install php`(8.5.11)로 설치한 뒤 점검 도구(Python·sh)가 설치 경로(`/opt/homebrew/Cellar/php/<버전>/bin/php`, `sbin/php-fpm`)와 버전을 올바르게 찾았고, `brew info php`가 설치 버전을 보여 줬으며, `brew services start php`(launchd)로 띄운 php-fpm을 `running=true`로 탐지했습니다(재현: `tests/brew_check.sh`). 이 검증 중 실행 중인 php-fpm을 놓치던 결함 두 가지를 찾아 고쳤습니다: (1) sh 판은 php-fpm이 바꾼 프로세스 제목(`php-fpm: master process (...)`)을 실행 파일로 연결하지 못했고, (2) Python 판은 `ps` 출력을 4KB에서 잘라 뒤쪽 프로세스를 놓쳤습니다. **`brew upgrade php`로 취약 버전이 수정 버전으로 바뀌는 흐름과 `brew services restart php` 자체는 시험하지 못했습니다**(그 시점 포뮬러가 이미 최신이라 업그레이드할 대상이 없음). Homebrew 포뮬러가 수정 버전을 반영했는지는 `php -v`와 `brew info php`로 확인하세요. 운영 서버용으로는 권장하지 않습니다.

### Windows (windows.php.net / php.net 다운로드 페이지)
PHP 공식 공지는 Windows 소스와 바이너리를 [다운로드 페이지](https://www.php.net/downloads.php?os=windows)에서 받으라고 안내합니다.

1. **TS와 NTS를 맞춥니다.** 지금 쓰는 빌드와 같은 종류를 받으세요. 일반적으로 IIS(FastCGI)나 nginx+php-cgi는 NTS, Apache mod_php 모듈은 TS입니다. 현재 설치 폴더의 DLL·`php -i`의 "Thread Safety" 값으로 확인하세요. 일반적 대응 관계는 문서·경험에 따른 것이며 이 저장소에서 시험하지 않았습니다(미검증).
2. 같은 아키텍처(x64/x86)와 VS 런타임 버전을 맞춥니다(Visual C++ 재배포 가능 패키지 필요).
3. 다운로드 페이지에 표시된 SHA-256과 대조합니다(독립 채널: 다른 PC·다른 네트워크에서 같은 페이지를 열어 비교).
```powershell
# 예시 파일명은 다운로드 페이지에서 실제 이름으로 바꾸세요.
Get-FileHash -Algorithm SHA256 .\php-8.4.27-nts-Win32-vs17-x64.zip
# 페이지의 SHA-256 값과 대소문자 무시하고 같은지 확인
```
4. 교체 절차(요약): 서비스/앱 풀 중지 -> 기존 PHP 폴더 이름 변경(백업) -> 새 zip을 새 폴더에 압축 해제 -> `php.ini`와 확장 설정 이식 -> 새 폴더를 기존 경로로 교체(또는 서비스 경로 수정) -> 서비스 시작.
```powershell
Expand-Archive -Path .\php-8.4.27-nts-Win32-vs17-x64.zip -DestinationPath .\php-8.4.27 -Force
Copy-Item C:\php\php.ini .\php-8.4.27\php.ini
Rename-Item C:\php php-old
Rename-Item .\php-8.4.27 php        # 같은 상위 폴더에서
```
- [미검증] 위 PowerShell 명령과 Windows·IIS 동작은 이 저장소에서 실행하지 못했습니다(PowerShell 컨테이너가 에뮬레이션에서 비정상 종료). 문법과 동작은 실제 Windows에서 먼저 시험하세요.
- 옛 폴더(`php-old`)는 취약하므로 확인이 끝나면 접근 불가능한 곳으로 옮기거나 삭제하고 PATH·핸들러 매핑이 새 폴더를 가리키는지 확인.
- PHP가 포함된 Windows용 설치 패키지(제품에 내장된 PHP)는 직접 교체하지 말고 공급사에 확인(옵션 E).

### Docker 공식 이미지
```bash
docker manifest inspect php:8.4.27-fpm > /dev/null && echo exists   # 태그 존재 확인
docker pull php:8.4.27-fpm          # 출력의 "Digest: sha256:..."를 기록해 고정 근거로 보관
```
- 존재를 확인한 태그(`docker manifest inspect`, 2026-10-23): `php:8.2.35-cli`, `-fpm`, `-apache`, `php:8.3.36-fpm`, `-fpm-alpine`, `-apache`, `php:8.4.27-cli`, `-fpm`, `-apache`, `-fpm-alpine`, `-cli-alpine`, `-zts`, `php:8.5.12-fpm`, `-apache`, `-cli-alpine`. (`php:8.4-fpm` 같은 부동 태그도 존재하지만 어느 시점의 내용인지 고정되지 않으므로 운영에는 정확한 버전 태그 또는 다이제스트를 권장.)
- 전체 절차는 옵션 C.

## 6. 패치를 증명하는 방법

> `php -v`는 웹 SAPI의 증거가 아닙니다. CLI는 웹 서비스와 다른 바이너리·설정을 쓸 수 있고(KISA 수칙 2, Xint), 배포판 패키지는 버전 번호가 그대로인 채로 패치될 수 있습니다(Sysdig). 그리고 **업데이트 후 워커를 재시작하지 않으면 메모리의 옛 버전이 계속 동작합니다(KISA 수칙 2).**

증거는 세 겹으로 모읍니다: (1) 설치된 패키지에 수정이 들어 있다, (2) 실행 중인 프로세스가 그 패키지의 바이너리다(재시작됨), (3) 웹 SAPI가 의도한 PHP·설정이다.

### 6.1 패키지 변경 이력에 CVE가 있다 (검증한 명령)
```bash
# Debian / Ubuntu (패키지 이름은 설치된 것에 맞춤: php8.2-cli, php8.3-cli 등. 변경 이력 파일이 없는 패키지가 있을 수 있으니 php*-common도 확인)
zcat /usr/share/doc/php8.2-cli/changelog.Debian.gz | grep -E 'CVE-2026-10961[89]'

# RHEL 계열, SUSE
rpm -q --changelog php-cli | grep -E 'CVE-2026-10961[89]'
rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'
rpm -q --changelog php8-fpm | grep -E 'CVE-2026-10961[89]'      # SUSE 패키지 이름 예

# 설치하지 않은 .rpm 파일에서
rpm -qp --changelog ./php-fpm-*.rpm | grep -E 'CVE-2026-10961[89]'
```
- [검증] debian:12에서 `php8.2 8.2.35-1~deb12u1` 변경 이력에 "Fix CVE-2026-109618 and CVE-2026-109619: State corruption via bailout."이 있음. ubuntu:24.04에서 `php -v`는 `8.3.6`이지만 `php8.3 (8.3.6-0ubuntu0.24.04.13)` 변경 이력에 두 CVE가 있음(**버전 번호만 보면 오판**하는 사례). rockylinux:9의 `php-cli-8.0.30-8.el9_8.1`(8.0 브랜치)과 그 `php-fpm` 패키지 파일의 `rpm -qp --changelog`에도 CVE가 있음. openSUSE Leap 15.6의 `php8-fpm-8.2.30-150600.3.25.1`에는 CVE 항목이 없었음(그 시점 미수정).
- `grep`에 아무것도 나오지 않으면 **그 패키지의 변경 이력에 CVE 기재가 없다**는 뜻입니다(수정 전이거나 변경 이력이 다른 서브 패키지에 있는 경우). 나오면 해당 패키지 변경 이력에 기재됐다는 뜻이며, 이후 6.2, 6.3을 반드시 함께 확인하세요.
- 패키지에 따라 변경 이력이 어느 서브 패키지에 있는지 다릅니다. SAPI 패키지(`php-fpm`, `libapache2-mod-php`)와 `php-common`/`php-cli` 둘 다 확인하세요.

### 6.2 실행 중인 프로세스가 새 바이너리다 (재시작됨)
```bash
# 프로세스 시작 시각을 패키지 설치·업데이트 시각과 비교
ps -eo pid,user,lstart,args | grep -E 'php-fpm|apache2|httpd' | grep -v grep
# Debian 계열 업데이트 시각: grep ' upgrade ' /var/log/dpkg.log | grep php | tail
# RHEL 계열 업데이트 시각: rpm -q --last php-fpm

# 삭제된 옛 바이너리·모듈을 계속 쓰는 프로세스 찾기
ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E 'php|httpd|apache2' | grep deleted
grep -l 'libphp.*(deleted)' /proc/[0-9]*/maps 2>/dev/null     # mod_php
sudo zypper ps                                                # SUSE
```
- [검증] debian:12에서 삭제된 바이너리로 돈 프로세스를 `ls -l /proc/PID/exe`가 `(deleted)`로 표시함을 확인. `libphp` 맵 점검 문법 확인(적재된 mod_php는 1건, 삭제된 것은 0건). `dpkg.log`/`rpm -q --last` 문장은 설명용 [미검증].
- `(deleted)`가 나오면 아직 옛 버전이 도는 중이므로 재시작하세요. 단, 이 점검이 비어 있어도 설정만 바꾸고 재시작하지 않은 경우는 걸러내지 못하므로 6.3도 함께 보세요.
- `systemctl reload`/`apache2ctl graceful`이 코드를 새로 적재하는지 이 저장소에서 확인하지 않았으므로, 증거가 필요하면 **전체 재시작**을 권장합니다(KISA 수칙 2: "반드시 재시작").

### 6.3 웹 SAPI가 의도한 PHP다
- 웹 SAPI 바이너리 자체의 버전: `php-fpm8.2 -v`, `php-fpm -v`, `httpd -M | grep php` 등. Debian 12의 `php-fpm8.2 -v`는 `PHP 8.2.35 (fpm-fcgi) (built: Oct 21 2026 ...)`로 출력됨 [검증]. 빌드 날짜는 참고일 뿐 증거가 아닙니다(벤더가 패치를 미리 받았음).
- 웹 요청으로 확인하는 방법: 임시 페이지에 `PHP_VERSION`과 `PHP_SAPI`를 출력하고 확인 직후 삭제(공격과 무관한 읽기 전용 표시). 단, 패키지가 번호를 바꾸지 않는 배포판(Ubuntu의 8.3.6 등)에서는 6.1이 없으면 의미가 없습니다.
- 임시 설정(F)을 적용했다면 같은 방식(웹 요청)으로 `ini_get('session.upload_progress.enabled')`, `ini_get('memory_limit')` 값을 확인하세요. `.user.ini`나 `ini_set()`에 의존하지 마세요(PHP 공지).
- 여러 vhost/FPM 풀이 있으면 각각 확인(Xint).

### 6.4 컨테이너
```bash
docker ps --format '{{.ID}} {{.Image}}'                    # 실행 중인 이미지 태그
docker image inspect IMAGE --format '{{.Id}}'              # 이미지 ID
docker exec CONTAINER php -v                               # 컨테이너 안 PHP(CLI)
docker exec CONTAINER sh -c 'php-fpm -v || apache2ctl -v'  # 웹 SAPI 바이너리 [미검증]
```
컨테이너가 새 이미지로 교체됐는지(옛 컨테이너가 남아 있지 않은지)까지 확인합니다.

## 7. 옵션 선택 후 공통 후속 작업

1. 패치 후 로그 점검: 최소 2026-10-20 이후, 가능하면 2026-10-17부터(그 이전도 가능하면). 절차는 [`runbook.ko.md`](runbook.ko.md).
2. 인증정보 교체(수칙 6), 단 침해 흔적이 있으면 증거 확보 후.
3. F로 올린 임시 설정이 남아 있으면 정리 계획을 세우되 `memory_limit=-1`과 OS 메모리 상한이 짝인지 확인.
4. 인벤토리를 갱신해 옛 PHP가 남은 곳(백업 서버, 테스트 서버, 외주 사이트)이 없는지 확인.

## 8. 검증 기록 (이 문서에 적힌 명령 중 직접 실행한 것)

환경: aarch64 호스트의 Docker(OrbStack). Docker Hub 익명 pull이 제한(429)되어 이미지는 `mirror.gcr.io/library/<이미지>`에서 받았거나(예: alpine) 이미 받아둔 이미지를 썼습니다. 날짜는 컨테이너 내부 시계(2026-10-23) 기준입니다.

| 항목 | 이미지 | 결과 |
|---|---|---|
| `docker manifest inspect php:<태그>` | Docker Hub / mirror.gcr.io | 5절·옵션 C의 태그 존재 확인 |
| `apt-get install --only-upgrade $(dpkg-query ...)` 모의 실행(`-s`) | debian:12 | 문법 정상 (이미 최신이면 `0 upgraded`) |
| `zcat .../changelog.Debian.gz \| grep` | debian:12, ubuntu:24.04 | CVE 확인 |
| `dnf check-update 'php*'`, `dnf upgrade --refresh 'php*'`, `dnf module list php`, `rpm -q --changelog \| grep` | rockylinux:9 | 동작 |
| `zypper list-patches --cve=`, `zypper ps` | registry.opensuse.org/opensuse/leap:15.6 | 동작 (패치 없음 응답) |
| `apk fetch -R`, `apk add`, `apk verify` | alpine:3.22 | 동작([`offline-patching.ko.md`](offline-patching.ko.md)) |
| `ls -l /proc/PID/exe`, `libphp` 맵 점검, `find ... php-fpm*`, `apache2ctl -M`, `nginx -t`, `apache2ctl configtest` | debian:12 | 동작 |
| PowerShell `Get-FileHash`, `Expand-Archive` 등 Windows 절차 | mcr.microsoft.com/powershell | **실행하지 못함(미검증)**: aarch64 호스트에서 에뮬레이션 중 PowerShell이 비정상 종료 |
| 7.4/8.0/8.1 백포트 브랜치 클론·빌드 | debian:12 | 아래 "소스 빌드 검증" 참고 |
| FreeBSD pkg, Homebrew, Windows 실제 교체, Kubernetes, Docker Compose, systemd 재시작, auditd, `dnf needs-restarting` 동작 | - | 미검증 |

### 소스 빌드 검증 (옵션 D)

debian:12(aarch64)에서 `git ls-remote`로 세 백포트 브랜치가 존재함을 확인했습니다(`PHP-7.4-...`, `PHP-8.0-...`, `PHP-8.1-...` + `-CVE-2026-109618-109619`). 8.1 브랜치를 `git clone --depth 1`로 받아 다음을 실행해 모두 성공했습니다.

- 브랜치 끝 커밋: `1d7dec178a094e6e75b229ce22754045f8c6070a` "Avoid state corruption via bailout"(작성자 Arnaud Le Blanc, 2026-10-18, 커미터 Ilija Tovilo). `git log --show-signature`는 서명이 있음(EDDSA 키 `259299AD4C7E1F40DE1302FF115CEA7A713E12E9`)을 보였고, 커미터의 GitHub 공개 키를 가져오면 `Good signature` 였습니다. 다만 이 키 지문은 php.net 키 페이지에 없으므로 **PHP 릴리스 관리자의 키인지는 독립 채널에서 확인하세요**([`offline-patching.ko.md`](offline-patching.ko.md) 11.1절).
- `main/php_version.h`의 `PHP_VERSION`은 `8.1.34`.
- 설치한 의존성: `git build-essential autoconf bison re2c pkg-config libxml2-dev libsqlite3-dev ca-certificates`. `./buildconf --force`, `./configure --disable-all --enable-cli --enable-fpm --prefix=/opt/php81`, `make -j4` 성공, `./sapi/cli/php -v` 출력 `PHP 8.1.34 (cli) (built: Oct 23 2026 ...) (NTS)`.
- 이 빌드는 확장이 없는 최소 구성입니다. `make test`, 운영 확장 포함 빌드는 하지 않았습니다(미검증). 이 빌드의 버전 번호(8.1.34)만으로는 수정 여부를 알 수 없으므로, 백포트 브랜치의 커밋이 수정을 포함한다는 사실은 PHP 공지에 의존합니다.
- 7.4, 8.0 브랜치도 같은 최소 구성으로 debian:12에서 빌드되어 실행됐습니다(CLI `7.4.34-dev`, `8.0.30`, `php-fpm -v` 출력 포함. GitHub Actions 3개 잡 성공, 재현: `sh tests/backport_build_check.sh 7.4 8.0 8.1`). 7.4는 개발판 번호(`-dev`)로 표시되며 8.1은 `8.1.34`입니다.
