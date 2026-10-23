# PHP2Shell 패치 안내서 (체계관리자용)

> **핵심 원칙**: 이 도구는 방어용입니다. 패치를 자동으로 적용하지 않습니다. **패치의 책임은 체계관리자에게 있습니다.**
> 여기서 제시하는 명령은 분석한 **그 시스템**에 맞춘 '실행 후보'이며, 실행 전 반드시 검토·테스트하세요. 실행 결과에 대한 책임은 체계관리자가 집니다.

> **검증 상태**: 이 문서의 [검증] 표시는 `aarch64` 호스트의 Docker에서 **실제로 실행해 확인**한 것입니다. Windows·macOS·FreeBSD·systemd 재시작·`journalctl`·공식 미러 저장소 등은 실제 환경에서 검증하지 못했습니다(문서에 '미검증' 표시).

---

## 5분 요약 (바쁜 관리자를 위해)

1. **점검**: `python3 php2shell_triage.py` (또는 `sh php2shell-quickcheck.sh` / `php2shell-quickcheck.bat`)
2. **판정 읽기**: `취약`/`EOL`/`수정됨`/`벤더 패치`/`확인 필요` 중 어느 쪽인지 확인.
3. **패치**:
   - `취약` / `벤더 패치` / `EOL(지원 종료)` → **즉시 업데이트** 또는 **지원 버전으로 이전**.
   - `수정됨`인데 **재시작 필요** → 모든 PHP 프로세스 재시작.
   - `확인 필요` / `EOL(수정 없음)` → 가상 패치 + 노출 축소 + 지원 버전 이전 계획.
4. **재시작**: `sudo systemctl restart <유닛>` (mod_php/apache, php-fpm, php-cgi, LiteSpeed, 프랑켄PHP, IIS 앱 풀, w3wp...). **모두** 재시작해야 합니다.
5. **재확인**: 도구를 다시 실행해 `수정됨` / `재시작 필요 없음` 확인.
6. **사후**: 2026-10-17 이후 로그 점검(웹셸, 비정상 메모리 초과, 비정상 프로세스 종료, 외부 연결). DB 비밀번호·API 키·세션 키 교체. 로그에 이상이 없어도 안전 보장은 아닙니다.

---

## 실행 전 체크리스트 (한 번만 읽고 체크)

- [ ] **점검 시간대** 확보 (피크 시간 피하고 롤백 시간 확보)
- [ ] **배포판/버전/SAPI 확인**: `php2shell_triage.py --json` 결과 저장
- [ ] **영향도/롤백** 결정: 패키지 관리자 다운그레이드 명령(`apt-get install php8.2=버전`, `dnf downgrade`, `zypper in --oldpackage`, `apt-get install php8.2=버전`)과 롤백 시나리오 문서화
- [ ] **영향 범위** 파악: 동일 서버의 다른 PHP 앱(mod_php/php-fpm 공존 등), 프록시/로드밸런서 뒤의 멀티 서버 동시 적용 필요 여부
- [ ] **백업**: 설정 파일(`/etc/php*/`, `/etc/php*/fpm/pool.d/`, `/etc/apache2/`, `/etc/httpd/`, `/etc/nginx/`, `C:\php\php.ini`, IIS `applicationHost.config`), PHP 실행 파일(`/usr/sbin/php-fpm*`, `C:\php\`) 통째로 백업
- [ ] **연락망/에스컬레이션**: 장애·침해 시 연락할 사람·채널·절차(비상 연락망, `docs/contacts.ko.md` 참고)
- [ ] **점검 도구 버전 확인**: `python3 php2shell_triage.py --version` (내장 권고 데이터의 `as_of` 확인)
- [ ] **체크섬 확인**: 배포 묶음(`SHA256SUMS`)과 Windows ZIP(`Get-FileHash -Algorithm SHA256`)

---

## 1단계: 점검 — 현재 상태 파악

```bash
# 전체 판정 (Python 전체판)
sudo python3 php2shell_triage.py

# 또는 Python 없이 (Linux/macOS)
sudo sh php2shell-quickcheck.sh

# Windows (관리자 권한 cmd)
php2shell-quickcheck.bat
```

**판정 읽기**
| 판정 | 의미 | 다음 행동 |
| --- | --- | --- |
| `수정됨` | 이미 패치됨 | 재시작 필요 여부 확인 (아래 2단계) |
| `취약` / `벤더 패치` / `EOL`(EOL/지원 종료) | **취약** | 즉시 업데이트/이전 (2단계) |
| `확인 필요` | 버전 판독 실패 | `--exec` 로 강제 실행(신뢰 트리면) 또는 `--no-exec`로 문자열 스캔, 수동 확인 필요 |

**종료 코드**: `0` = 조치 필요 없음, `1` = 조치 필요(취약/EOL/재시작 필요), `3` = 확인 불가(권한·도구 부족). **종료 코드 3은 안전하다는 뜻이 아닙니다.**

### JSON으로 받아 자동화
```bash
python3 php2shell_triage.py --json > report.json
jq -r '.installations[] | "\(.path)\t\(.version)\t\(.verdict)\t\(.needs_restart)\t\(.sapi)"' report.json
```

---

## 2단계: 패치 — OS·SAPI·환경별 실행 명령

> **핵심**: **수정 버전은 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 / 8.6.0RC4 이상**.
> **8.2는 2026-12-31 보안 지원 종료**이므로 8.3 이상으로 이전 권장.
> **8.1 이하(EOL) / 7.x / 5.x**는 공식 수정 없음 → 벤더 백포트 확인 → 지원 버전(8.3+)로 이전.

### 2.1 온라인 환경 (인터넷 가능)

#### Debian / Ubuntu (apt)
```bash
# 수정 패키지만 골라 업그레이드 (나머지는 건드리지 않음)
sudo apt-get update
sudo apt-get install --only-upgrade php8.2 php8.2-fpm php8.2-cli libapache2-mod-php8.2
# 또는 현재 설치된 php* 패키지만
sudo apt-get install --only-upgrade $(dpkg-query -W -f='${Package}\n' 'php*' | xargs)
# 남아 있는 구버전 확인
apt list --upgradable 2>/dev/null | grep -i php
```

#### RHEL / Rocky / Alma / AlmaLinux (dnf / yum)
```bash
# dnf
sudo dnf upgrade --refresh php php-fpm php-cli php-common

# yum (구버전)
sudo yum update php php-fpm php-cli php-common

# 변경 이력에서 CVE 확인
rpm -q --changelog php8.4-fpm | grep -i 'CVE-2026-1096(18|19)' | head -2
```

#### Alpine (apk)
```bash
apk update && apk upgrade php83 php83-fpm php83-cli
# 서명 검증 실패 시 해시 별도 확인 후
apk add --no-network ./php83-*.apk ./php83-fpm-*.apk ...
```

#### SUSE / openSUSE (zypper)
```bash
sudo zypper refresh && sudo zypper update php8 php8-fpm php8-cli
```

#### FreeBSD (pkg)
```bash
pkg update && pkg upgrade php83 php83-fpm php83-cli
```

#### Windows (windows.php.net)
> **Apache(mod_php)**는 **Thread Safe (TS)**, **IIS FastCGI(php-cgi)**는 **Non Thread Safe (NTS)**.
```powershell
# 인터넷이 되는 PC에서
$ver = "8.4.27"
$zip = "php-${ver}-nts-Win32-vs17-x64.zip"   # IIS FastCGI
# $zip = "php-${ver}-Win32-vs17-x64.zip"      # Apache mod_php
Invoke-WebRequest "https://windows.php.net/downloads/releases/$zip" -OutFile $zip
Get-FileHash -Algorithm SHA256 $zip  # 페이지의 SHA256 과 대조 (대소문자 무시)

# 대상 서버로 이동 -> 서비스 중지 -> 폴더 교체(php.ini 보존) -> 시작
iisreset /stop   # IIS
# Stop-Service Apache2.4   # Apache
Expand-Archive -Path $zip -DestinationPath C:\php-new
Copy-Item C:\php\php.ini C:\php-new\php.ini
iisreset /start
# Start-Service Apache2.4
```

#### Docker / 컨테이너
```dockerfile
# 베이스 이미지를 수정 버전으로
FROM php:8.4.27-fpm      # 또는 -apache, -cli, -alpine, -zts
# 도커 이미지 재빌드
docker build --pull --no-cache -t myapp:php-patched .
docker push myapp:php-patched
# 배포: 새 이미지로 롤링 재배포
# 컨테이너 안에서 패키지 올리지 마세요(이미지가 바뀌지 않습니다).
```

#### 2.2 오프라인 / 폐쇄망
> 인터넷이 되는 **같은 배포판·같은 CPU 아키텍처**의 PC/컨테이너에서 패키지와 의존성을 내려받아 이동 매체로 반입.

```bash
# Debian/Ubuntu
apt-get install --download-only php8.2 php8.2-fpm php8.2-cli libapache2-mod-php8.2
# 또는 apt-get download php8.2 php8.2-fpm php8.2-cli libapache2-mod-php8.2

# RHEL/Rocky/Alma
dnf download --resolve --alldeps php php-fpm php-cli

# Alpine
apk fetch -R -o /tmp/php-pkgs php83 php83-fpm php83-cli

# 대상 서버 (apt 예)
sudo apt-get install ./*.deb   # 또는 sudo dpkg -i *.deb
```

> **체크섬/서명**: 배포판이 공개한 SHA256/gpg 값과 **독립된 경로로** 대조. 매체 자체가 신뢰돼서는 안 됨.

### 2.3 컨테이너 이미지 재빌드
```dockerfile
FROM php:8.4.27-fpm   # 또는 -apache, -cli, -alpine, -zts
# docker build --pull --no-cache -t myapp:php-patched .
# docker push registry/myapp:php-patched
# 배포: 새 이미지로 롤링 재배포
```
> **태그 존재 확인**: `docker manifest inspect php:8.4.27-fpm` 등.

### 2.3 소스 빌드 (7.4 / 8.0 / 8.1)
공식 바이너리 없음. PHP 보안팀 백포트 브랜치 사용.
```bash
git clone --branch PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src
cd php-src
./buildconf
./configure --disable-all --enable-cli --enable-fpm  # 필요 옵션만
make -j$(nproc)
# 테스트 환경 검증 -> 설치 -> 모든 PHP 프로세스 재시작
```
> 소스 빌드용 백포트 브랜치: 7.4/8.0/8.1 각각 존재함(커밋 해시는 `data/advisory.json` `source_backport_urls` 참조).

---

## 3단계: 재시작 — 필수

> **모든 PHP 프로세스 재시작**하지 않으면 메모리에 남은 **옛 코드가 계속 실행**됩니다(KISA 수칙 2).

```bash
# systemd
sudo systemctl restart php8.4-fpm php8.4-fpm@www.service    # pool 이름 확인
sudo systemctl restart apache2          # mod_php
sudo systemctl restart httpd            # RHEL 계열
sudo systemctl restart nginx            # nginx + php-fpm
sudo systemctl restart lsws             # LiteSpeed

# Windows
iisreset /restart        # IIS
# Start-Service Apache2.4  # Apache

# 컨테이너: 이미지 재배포 (컨테이너 안 재시작만으로는 새 이미지가 되지 않음)
```

**확인**: `ps -eo pid,ppid,lstart,cmd | grep -E 'php|httpd|nginx|php-fpm'` — 시작 시각이 교체 이후여야 함. 또는 이 도구를 다시 실행해 `재시작 필요: 아니오` 확인.

---

## 4단계: 적용 확인 (반드시)

```bash
# 1. 이 도구 재실행
python3 php2shell_triage.py
# → 모든 설치가 '수정됨', '재시작 필요: 아니오' 여야 함

# 2. 벤더 변경 이력에서 CVE 확인
# Debian/Ubuntu
zcat /usr/share/doc/php8.2-fpm/changelog.Debian.gz | grep -m2 -E 'CVE-2026-1096(18|19)'
# RHEL/Rocky/Alma
rpm -q --changelog php8.4-fpm | grep -m2 -E 'CVE-2026-1096(18|19)'

# 3. php -v 로만 확인하지 마세요 (CLI 와 웹 SAPI 가 다를 수 있음).
# 이 도구를 다시 실행하거나 웹 프로세스의 /proc/<pid>/exe 와 시작 시각을 확인

# 4. 로그 점검(2026-10-17 이후) & 인증정보 교체
# DB 비밀번호, API 키, 세션 키 교체. 로그에 이상이 없어도 안전이 보장되지 않습니다.
```

---

## 5단계: 실패·이상 시 대응 (롤백·가상 패치·격리)

| 상황 | 즉시 조치 | 참고 |
| --- | --- | --- |
| 패치 후 서비스 장애/이상 | **롤백**(`apt-get install php8.2=이전버전`, `dnf downgrade`, `yum downgrade`, `zypper in --oldpackage`, `dpkg -i` 이전 버전 `.deb`, 롤백 전 `apt-get install php8.2=이전버전`) | 이전 버전은 다시 취약함. 가상 패치(F)·노출 축소(G)로 버티며 원인 해결. |
| 가상 패치(F) | [docs/virtual-patching.ko.md](virtual-patching.ko.md) | 완전한 해결 아님. 우회 가능. |
| 노출 축소(G) / 서비스 중단 | 유지보수 페이지 / IP 허용목록(nginx/Apache `allow/deny` 또는 방화벽) / VPN / 서비스 일시 중단 | NSM(국가사이버안보센터)·CISA·CERT-EU 도 동일 권고. |
| 침해 의심 | **재시작하지 말고** 외부 접속만 차단 → 증거 보존(로그·프로세스·연결·메모리) → KISA 118 / 보호나라 신고 → 업데이트·웹셸 제거·인증정보 교체 | KISA 수칙 7. 증거 보존이 먼저! |

---

## 6. 맞춤 패치 계획 (자동 생성)

```bash
# Markdown 리포트 + 검토용 셸 스크립트
python3 php2shell_triage.py --emit-patch-plan ./patch-plan --plan-format sh
# 또는 PowerShell
python3 php2shell_triage.py --emit-patch-plan ./patch-plan --plan-format ps1
```
생성된 스크립트(`patch-plan.sh` / `patch-plan.ps1`)는 **자동 실행되지 않음**.
- `PHP2SHELL_I_REVIEWED=yes sh patch-plan.sh` 로만 실행 가능
- 각 단계마다 `y/N` 확인 → 관리자가 직접 검토·실행
- 증거 보존 단계가 0단계로 포함(KISA 수칙 7: 재시작 전 증거 확보)
- `P2S_NOPAUSE=1` 로 더블클릭 모드 `pause` 비활성화(CI용)

---

## 부록 A. 배포판·버전별 현황 (2026-10-23 확인 기준)

| 배포판 | 패키지 | 상태 | 비고 |
| --- | --- | --- | --- |
| Debian 12 | php8.2 (8.2.35) | **수정됨** | security 저장소 |
| Ubuntu 24.04 | php8.3 (8.3.6) | **벤더 패치** | 변경 이력에 두 CVE 포함 |
| Rocky 9 / Alma 9 | php-fpm 8.0.30 | **벤더 패치** | RHEL 백포트 |
| Alpine 3.20 | php83 (8.3.15) | **취약** | 저장소에 수정 없음 → 3.22+ 필요 |
| openSUSE Leap 15.6 | php8 (8.2.30) | **취약** | `zypper list-patches --cve=CVE-2026-109618` 결과 없음 |
| Windows (공식) | 8.4.27 / 8.5.12 | **수정됨** | `windows.php.net` 확인 |
| PHP 8.1 이하 / 7.x / 5.x | 공식 업데이트 없음 | **EOL** | 지원 버전으로 이전 필수 |
| PHP 7.4 / 8.0 / 8.1 | 소스 백포트만 | **벤더 패치 필요** | PHP 보안팀 백포트 브랜치 있음 |

> **표는 2026-10-23 검증 시점 기준**. 최신 상태는 배포판 보안 공지·`php2shell-triage` 재실행으로 확인.

---

## 부록: 피해야 할 흔한 실수

| 실수 | 왜 위험한가 | 올바른 방법 |
| --- | --- | --- |
| `php -v` 만 보고 "패치됨" 판단 | CLI와 웹 SAPI가 다른 바이너리일 수 있음 | `php2shell_triage.py` 재실행 또는 `/proc/<pid>/exe` 확인 |
| 재시작 생략 | 메모리에 옛 코드 계속 실행됨 | 모든 PHP 프로세스 강제 재시작 (`systemctl restart`) |
| `php -v` 만 믿고 '수정됨'으로 판단 | 웹 SAPI가 다른 버전일 수 있음 | 도구 재실행 또는 웹 프로세스 `/proc/<pid>/exe` 확인 |
| 가상 패치만 하고 업데이트 미룸 | 우회 가능(문자셋·인코딩·RFC 인코딩) | 가상 패치는 시간 벌기일 뿐, 업데이트가 근본 조치 |
| 폐쇄망에서 `apt-get update` 시도 | 저장소에 닿지 않아 실패 | `apt-get install --download-only` / `dnf download --resolve` |
| 재시작 전 증거 미확보 | 메모리 흔적 사라짐 | KISA 수칙 7: 격리 → 신고 → 증거 확보 → 조치 |
| `memory_limit=-1` 만 쓰고 OS 상한 없음 | 한 요청이 메모리 다 써서 서비스 중단 | 컨테이너 `--memory`, systemd `MemoryMax`, `cgroup` 상한 필수 |
| `session.auto_start=0` 후 로그인·장바구니 먹통 | `session_start()` 없이 `$_SESSION` 쓰던 페이지 멈춤 | 공통 include 파일에 `session_start()` 추가 후 끄기 |
| PoC 실행해 "확인" | 악성코드 숨긴 가짜 PoC 많음 | 버전·로그·기록으로만 판정. PoC 실행 금지. |

---

## 참고 문서

| 문서 | 내용 |
| --- | --- |
| `docs/response-options.ko.md` | 9개 대응 옵션 상세 + 결정표 |
| `docs/offline-patching.ko.md` | 폐쇄망 패치 절차·체크섬·미러 |
| `docs/virtual-patching.ko.md` | 가상 패치 6개 레이어·우회·롤아웃 |
| `docs/runbook.ko.md` | 침해 사고 순서·증거·신고·조치·타임라인 템플릿 |
| `docs/contacts.ko.md` | KISA·개인정보위·경찰청·금융기관 등 신고 채널(법적 기한·출처 포함) |
| `docs/testing.ko.md` | 로컬/Docker/Windows 검증 재현 방법 |
| `docs/verification.ko.md` | 검증된 것 / 미검증 것 / 한계 |

---

## 문의·기여

이 문서는 `php2shell-triage` 저장소의 [CONTRIBUTING.md](../CONTRIBUTING.md) 와 [SECURITY.md](../SECURITY.md) 를 따릅니다. 오류·보완·새 배포판 정보는 이슈·PR 로 알려주세요.

---

> 이 가이드는 **2026-10-23** 현재 정보를 바탕으로 합니다. PHP/배포판 공식 공지를 최우선으로 따르세요.