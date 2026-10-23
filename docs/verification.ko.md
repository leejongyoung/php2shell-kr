# 검증 현황

실제로 실행해 확인한 것과 확인하지 못한 것을 구분해 적습니다. 숫자는 실행 결과를 그대로 옮긴 것입니다.

- 기준 커밋: `851bb54` (보안 하드닝 반영 후)
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
| docker-compose | `docker compose config`, 실제 `php:8.4.27-fpm` 기동. `cap_drop: ALL`만 쓰면 `failed to setgid(33)`로 워커가 못 뜨고, `SETUID`·`SETGID`를 추가하면 root 마스터와 UID 33 워커가 뜨고 nginx→FastCGI 응답 200 (TCP listen 구성) |

## 4. 대응 문서의 명령

`response-options.ko.md`, `offline-patching.ko.md`의 명령에는 각각 `[검증]`/`[미검증]`이 붙어 있습니다. 컨테이너에서 실행해 확인한 것: apt·dnf·apk·zypper의 오프라인 다운로드와 설치 흐름, `docker save`/`load`, 변경 이력 조회, 8.1 소스 백포트 빌드(최소 구성).

## 5. 확인하지 못한 것

- **Windows**: 실제 ACL 조회에 의한 신뢰 판정의 단독 검증(하네스는 주입한 ACL 값으로 시험), `icacls` 증거 폴더 권한 적용, IIS·레지스트리·서비스 열거, 계획 파일의 `iisreset`/`Stop-Service` 실제 실행, cp949 콘솔 출력
- **IIS** `web.config` 스니펫(XML 형식만 확인), 가상 패치의 systemd drop-in·auditd·nftables·SELinux 참고 내용
- docker-compose의 Unix 소켓 구성
- FreeBSD, Homebrew, Kubernetes, 재시작 명령(`systemctl restart` 등)의 실제 실행, GPG 서명 검증
- 7.4/8.0 소스 백포트 브랜치 빌드, 운영 확장을 포함한 빌드
- 장시간 부하·실제 공격 트래픽에서의 가상 패치 효과(우회 가능성은 문서에 명시)
- 이 도구의 판정이 모든 배포판·설정을 포괄한다는 보장. 가상호스트별 `.user.ini`·`.htaccess`·`ini_set()`는 정적으로 알 수 없습니다.

## 6. 재현

[testing.ko.md](testing.ko.md)를 참고하세요. Apple Silicon에서는 `mcr.microsoft.com/powershell`(amd64 전용)이 에뮬레이션에서 비정상 종료하므로 PowerShell 하네스는 arm64용 pwsh 압축 파일을 컨테이너에 넣어 실행했습니다(또는 CI 사용).
