# 검증 현황

실제로 실행해 확인한 것과 확인하지 못한 것을 구분해 적습니다. 숫자는 실행 결과를 그대로 옮긴 것입니다.

- 기준 커밋: 1~4절은 `851bb54`(보안 하드닝 반영 후), 5절의 확장 검증은 `3ae9663`(그 이후 코드 변경은 5절에 적은 도구 결함 수정 6건과 테스트 추가. 이후 커밋은 문서·주석만 바꿈). Windows ACL 판정 수정(5절 결함 표 마지막 행)은 그 뒤 커밋에서 별도로 검증함
- 날짜: 2026-10-23, 권고 데이터 기준일 `data/advisory.json`의 `as_of`
- 주의: 하드닝 이전 커밋의 CI 통과 기록은 이 문서의 근거로 쓰지 않았습니다. 이전 커밋에는 하드닝이 들어 있지 않았고, 하드닝 후 첫 CI(`76d589f`)에서는 4건이 실패해 고쳤습니다.

## 1. GitHub Actions (실제 Windows·macOS·Linux 러너)

run `39931232943`, 커밋 `851bb54`: **21개 잡 모두 성공**

| 잡 | 확인한 것 |
| --- | --- |
| unit × (ubuntu / macos / windows) × (py3.8, py3.13) | 단위·회귀 테스트(POSIX 전용은 Windows에서 skip) |
| unit (python 3.6 container) | Python 3.6 호환 |
| sh quickcheck × debian:12-slim, ubuntu:24.04, alpine:3.20, rockylinux:9-minimal, almalinux:9-minimal, opensuse/leap:15.6, macOS | sh 하네스 |
| powershell × (windows-latest 5.1, windows-latest pwsh 7, ubuntu pwsh, macos pwsh) | PowerShell 하네스 |
| real PHP images and distro packages (docker) | 공식 PHP 이미지와 배포판 패키지로 Python·sh 판정 일치 |
| real PHP on Windows | windows.php.net에서 8.4.26(취약)·8.4.27(수정) 설치, 단일 파일 `.bat`과 Python 도구가 두 빌드를 올바르게 분류 (다운로드 파일은 SHA-256 고정값으로 검증) |
| dist bundle | 배포 묶음 생성, `SHA256SUMS` 검증 |

하드닝 후 첫 CI(`76d589f`)의 실패 4건과 원인:

| 실패 | 원인 | 수정 |
| --- | --- | --- |
| openSUSE sh 하네스 | 테스트 대상 `/bin/ls`가 Leap에서는 심볼릭 링크(도구는 링크를 거부하는 것이 맞음) | 하네스가 일반 파일을 고르도록 수정 |
| macOS pwsh 하네스 3건 | 임시 경로 `/var/...`가 링크라 ACL 테스트의 링크 거부와 충돌 | 하네스가 실제 경로를 쓰도록 수정 |
| Windows unit 2건 | 하위 프로세스 출력 디코딩, CRLF 체크아웃을 읽지 못한 sync 도구(도구 결함) | 인코딩 명시, CRLF 정규화 + 회귀 테스트 |

## 2. 로컬(Apple Silicon Mac + Docker/OrbStack)

| 항목 | 결과 |
| --- | --- |
| 호스트 `unittest` | 62개 통과, 2 skip |
| `python:3.6` 컨테이너 `unittest` | 62개 통과, 2 skip |
| sh 하네스 | macOS 181 · debian:12-slim 182 · alpine:3.20 182 · rockylinux:9-minimal 182 · opensuse/leap:15.6 181, 모두 실패 0 |
| PowerShell 하네스(pwsh 7.4.6 arm64, Debian 컨테이너) | 43,605 통과, 실패 0 |
| `tests/platform_matrix.py` (Python·sh 모두 실행) | 통과 3 · 정보 4 · 실패 0 |

`platform_matrix.py`의 통과 항목: `php:8.4.26-fpm`(취약), `php:8.4.27-fpm`(수정됨), 바이너리를 교체한 뒤 재시작하지 않은 경우(재시작 필요). 정보 항목(실제 배포판 상태, 날짜에 따라 바뀜): Debian 12 `php8.2` 8.2.35 수정됨 · Ubuntu 24.04 `php8.3` 8.3.6 **벤더 패치**(변경 이력에 두 CVE 있음, 버전 번호만 보면 오판) · Rocky 9 `php-fpm` 8.0.30 벤더 패치 · Alpine 3.20 `php83` 8.3.15 취약(저장소에 수정 없음).

## 3. 가상 패치

| 대상 | 확인한 것 |
| --- | --- |
| nginx 스니펫 | `nginx -t` |
| Apache 설정 | `php:8.4-apache`에서 `apachectl configtest` |
| PHP ini / FPM 풀 | `php -n -c`, `php-fpm -t` |
| ModSecurity 규칙 | `owasp/modsecurity-crs:nginx`에서 `nginx -t`와 요청 시험: 규칙 91001~91007, 91010이 의도대로 403(표지·쿠키·괄호 8개·인자 600개·파일 21개·chunked multipart), 정상 폼과 괄호 2개는 차단되지 않음 |
| docker-compose | `docker compose config`, 실제 `php:8.4.27-fpm` 기동. `cap_drop: ALL`만 쓰면 `failed to setgid(33)`로 워커가 못 뜨고, `SETUID`·`SETGID`를 추가하면 root 마스터와 UID 33 워커가 뜨고 nginx→FastCGI 응답 200 (TCP listen 구성). unix 소켓 구성은 5절 |

## 4. 대응 문서의 명령

`response-options.ko.md`, `offline-patching.ko.md`의 명령에는 각각 `[검증]`/`[미검증]`이 붙어 있습니다. 컨테이너에서 실행해 확인한 것: apt·dnf·apk·zypper의 오프라인 다운로드와 설치 흐름, `docker save`/`load`, 변경 이력 조회, 8.1 소스 백포트 빌드(최소 구성).

## 5. 확장 검증: 실제 환경에서 실행한 것 (2026-10-23)

컨테이너로는 확인할 수 없던 항목을 실제 환경에서 실행했습니다. 스크립트는 `tests/*_check.sh`·`tests/windows_*`, CI는 `.github/workflows/extended.yml`입니다. 결과: run `39963166117`(커밋 `3ae9663`) **10개 잡 모두 성공**, 같은 커밋의 `ci.yml` run `39963165973`도 성공.

| 항목 | 환경 | 확인한 것 | 스크립트 |
| --- | --- | --- | --- |
| docker-compose unix 소켓 | 로컬 Docker, CI | `cap_drop: ALL` + `SETUID, SETGID`만으로는 `failed to chown() the socket`로 FPM 초기화 실패, `CHOWN`을 더하면 nginx→소켓 FastCGI 응답 200 (`FOWNER`는 불필요). 시험은 소켓 권한 0666으로 함 | `compose_socket_check.sh` |
| GPG 서명 | 로컬, CI | `php-8.4.27.tar.xz` 서명 정상(키 지문이 php.net 키 페이지에 있음), 1바이트 변조는 `BAD signature`, 7.4/8.0/8.1 백포트 브랜치 끝 커밋 서명 정상 | `gpg_source_check.sh` |
| 7.4/8.0/8.1 백포트 빌드 | debian:12-slim | 최소 구성 빌드 후 CLI `7.4.34-dev`·`8.0.30`·`8.1.34`와 `php-fpm -v` 실행 | `backport_build_check.sh` |
| Kubernetes | kind (로컬: kind v0.33.0 · Kubernetes v1.37.0, CI: helm/kind-action) | jsonpath 이미지 목록, 파드 안 점검(8.4.26 취약, 종료 코드 1), `set image` + `rollout status`, 새 파드 점검(8.4.27 수정됨, 0) | `k8s_check.sh` |
| Linux 호스트 | Ubuntu 24.04 러너(진짜 systemd), php8.3-fpm | systemd drop-in 적용·롤백(MemoryMax·OOMPolicy 반영), 패키지 파일 교체 후 "재시작 필요" 탐지와 `systemctl restart` 후 해소, root 실행 시 `process_visibility=full`, auditd 규칙 로드(`auditctl -R`·`-l`), `nft -c`·적용(www-data 신규 외부 연결만 차단)·롤백 | `linux_host_check.sh` |
| Homebrew | macOS 26.6.2 arm64 러너, `brew install php`(8.5.11) | Python·sh 판이 Cellar 경로·버전 탐지, `brew info php`, `brew services start php`로 띄운 php-fpm을 `running=true` | `brew_check.sh` |
| FreeBSD | FreeBSD 14.3 VM, `pkg install php84`(8.4.27) | sh 하네스, Python·sh 판 탐지, 패키지 관리자 `pkg` 인식, `pkg audit -F`, `pkg upgrade -n`, `service php_fpm onestart/restart`, 실행 중 php-fpm 탐지 | `freebsd_check.sh` |
| Windows ACL (실제 ACL로 `trusted_binary` 판정) | windows-latest | `System32\cmd.exe`와 Administrators/SYSTEM 전용 폴더의 파일은 trusted. 거부: Everyone 쓰기 가능 폴더, 앱 폴더에 Users가 새 파일을 만들 수 있는 경우, 상위 폴더에서 Authenticated Users가 하위 항목을 삭제할 수 있는 경우, 정션 경로. 무시: 앱 폴더 위 상위 폴더의 `Authenticated Users:(AD)`(기본 `C:\` 와 같은 권한) | `windows_acl_check.py` |
| IIS web.config | windows-latest, IIS + URL Rewrite | 병합한 web.config로 multipart POST 403(`{HTTP_CONTENT_TYPE}`·`{CONTENT_TYPE}` 모두 Content-Type 전달), 크기 상한 초과 본문 413, 파일 삭제로 롤백 | `windows_iis_check.ps1` |
| IIS FastCGI | windows-latest, php-cgi 8.4.27 | IIS가 PHP를 FastCGI로 서빙, 점검 도구가 php-cgi를 `running`으로 탐지, `iisreset /stop` 후 프로세스 없음, `/start` 후 더 늦은 StartTime으로 재기동 | `windows_iis_check.ps1` |
| 패치 계획(ps1) | windows-latest | 생성된 `patch-plan.ps1`의 증거 단계 실행: 폴더 생성, `processes.csv`·`tcp.csv`·`SHA256.csv`, ACL이 Administrators·SYSTEM만 | `windows_iis_check.ps1` |
| cp949 콘솔 | windows-latest | `chcp 949`에서도 Python 도구와 단일 `.bat`의 출력이 BOM 없는 유효 UTF-8이고 한글이 깨지지 않음(파일로 받아 바이트 검증) | `windows_iis_check.ps1` |

**이 검증에서 찾아 고친 도구 결함 (회귀 테스트 추가)**

| 결함 | 증상 | 수정 |
| --- | --- | --- |
| Linux에서 커널 스레드를 접근 거부로 셈 | root로 실행해도 `process_visibility=limited`. PHP가 없는 호스트에서 확인 불가(종료 코드 3)로 나올 수 있었음 | `EACCES`만 센다 |
| macOS: php-fpm 프로세스 제목 (sh 판) | `php-fpm: master process (...)`로 바뀐 제목을 실행 파일에 연결하지 못해 `running=false`, 가짜 후보 생성 | 제목에서 이름만 남기고 `lsof`(macOS)·`procstat`(FreeBSD)로 경로 확인 |
| Python 판이 `ps` 출력을 4KB에서 자름 | 프로세스가 많은 macOS/BSD에서 뒤쪽 php-fpm을 놓침 | `ps` 목록은 8MiB까지 읽음 |
| FreeBSD의 `ps -o pid=,comm=` | 첫 열 머리글만 바뀌고 다른 열이 없어 두 구현 모두 프로세스를 하나도 못 찾음 | `-o pid= -o comm=` 형태로 분리 |
| 패치 계획 증거 단계의 SHA256 명령 | 출력 파일(`SHA256.csv`)을 해시하려다 읽기 오류 | 파일 목록을 먼저 확정한 뒤 해시 |
| Windows ACL 신뢰 판정이 기본 Windows에서 항상 False | `System32\cmd.exe`조차 untrusted라 Windows에서는 PHP를 실행하지 않고 파일의 버전 문자열로만 판정. 원인 두 가지: (1) ACE 식별자를 `Translate()`로 SID로 되돌리다 `ALL APPLICATION PACKAGES` 같은 항목에서 예외가 나 전체가 untrusted, (2) 기본 `C:\` 의 `Authenticated Users:(AD)`(하위 폴더 만들기)가 상위 폴더 검사에 걸림 | SID를 처음부터 `GetAccessRules(..., [SecurityIdentifier])`로 받고, 파일과 그 폴더(앱 폴더)만 전체 쓰기 권한을 보며 더 위의 상위 폴더는 만들기 권한(0x2·0x4)을 무시. `quickcheck/php2shell-quickcheck.ps1`의 `Test-TrustedPath`에도 같은 정책을 적용하고 하네스 케이스 추가 |

**확인한 한계와 주의**

- (해결됨) 처음에는 "기본 Windows에서 `System32\cmd.exe`조차 untrusted인 것은 `C:\` 루트 ACL 때문"이라고 판단했으나 진단 결과 원인이 하나 더 있었고(위 결함 표), 둘 다 고쳤습니다. 주의: 사용자가 만든 `C:\php` 같은 폴더는 기본으로 `Authenticated Users:(M)`을 상속하므로 여전히 untrusted이며, 관리자가 폴더 ACL을 잠가야 실행 대상이 됩니다(의도된 동작).
- IIS는 크기 상한 초과를 404.13이 아니라 413으로 거절했습니다(시험한 러너 기준).
- 백포트 브랜치 서명 키 `2592 99AD ...`는 php.net 키 페이지와 `keyserver.ubuntu.com`에 없었고, 커미터의 GitHub 계정 키로만 검증했습니다. 릴리스 관리자의 키인지는 독립 확인이 필요합니다.
- 한 번 CI에서 점검 도구가 IIS의 php-cgi를 `running`으로 보고하지 못한 적이 있었으나(run `39960499983`) 재현되지 않았고 원인을 확정하지 못했습니다. 진단 출력과 재시도를 넣었고 최종 실행은 첫 시도에 통과했습니다.
- IIS 잡은 `appcmd`로 핸들러를 등록하거나 `iisreset /start` 한 직후의 첫 PHP 요청이 정적 파일 404.17로 실패한 적이 있습니다(main의 run `39965994292`). 설정 반영 시간차로 추정하지만 원인은 확정하지 못했고, 하네스가 최대 40초까지 재시도하도록 고친 뒤 통과했습니다(run `39967792839`). 설정 변경 직후 점검·시험은 잠시 기다린 뒤 하세요.

## 6. 확인하지 못한 것

- **Windows**: 폴더 교체 전체 절차(서비스 중지 → 폴더 이름 변경 → `php.ini` 이식 → 시작), `Stop-Service Apache2.4` 등 Apache 서비스, 실제 PHP 사이트를 얹은 IIS(ARR 포함)에서의 가상 패치, 레지스트리 조회(도구는 레지스트리를 사용하지 않음)
- **OS 가상 패치**: auditd의 `augenrules --load` 경로와 실제 이벤트 기록, systemd 메모리 한도 초과 시 워커 종료 동작, nftables 허용 목록(DB·DNS) 동작, **SELinux/AppArmor 메모**(전혀 시험하지 않음)
- 취약 버전이 설치된 상태에서의 **교체 흐름**: `brew upgrade php`, `pkg upgrade -g 'php*'`, `dnf needs-restarting`(그 시점 저장소가 이미 수정 버전), `pkg audit`에 이 CVE가 등재되는지
- Kubernetes에서 같은 태그를 덮어쓰고 `rollout restart`만 했을 때 이미지 캐시 정책에 따른 동작, `docker compose build --pull --no-cache` 흐름
- 운영 확장을 포함한 소스 빌드, `make test`
- 장시간 부하·실제 공격 트래픽에서의 가상 패치 효과(우회 가능성은 문서에 명시)
- 이 도구의 판정이 모든 배포판·설정을 포괄한다는 보장. 가상호스트별 `.user.ini`·`.htaccess`·`ini_set()`는 정적으로 알 수 없습니다.
- 이 검증은 임시 VM·CI 러너에서 한 번 실행한 결과입니다. 서로 다른 OS 버전·설정에서의 재현성은 보장하지 않습니다.
- `quickcheck/php2shell-quickcheck.ps1`·`.bat`의 `Test-TrustedPath`를 **실제 Windows ACL로** 시험하지는 않았습니다(하네스는 주입한 ACL 값 사용). Python 판의 실제 ACL 판정만 위 표대로 검증했습니다.

## 7. 재현
