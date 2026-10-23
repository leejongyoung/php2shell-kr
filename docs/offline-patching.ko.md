# PHP2Shell 오프라인·폐쇄망 패치 절차

기준일: 2026-10-23. 대상: CVE-2026-109618, CVE-2026-109619. 방어용 문서이며 공격 코드·페이로드는 없습니다.
옵션 선택은 [`response-options.ko.md`](response-options.ko.md), 패치 전 임시 완화는 [`virtual-patching.ko.md`](virtual-patching.ko.md), 사고 대응은 [`runbook.ko.md`](runbook.ko.md)를 보세요.

## 0. 먼저 읽을 것

- 수정 버전: PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 이상. 배포판·제조사 제공 업데이트 포함(KISA 수칙 2). 8.1 이하는 PHP 프로젝트의 업데이트가 없고 배포판·LTS 업체의 백포트 또는 PHP 보안팀의 7.4/8.0/8.1 소스 백포트 브랜치가 대안입니다(PHP 공지).
- 배포판 패키지는 **버전 번호를 바꾸지 않고** 패치할 수 있습니다(KISA 수칙 2, Sysdig). 이 문서의 검증에서도 ubuntu:24.04의 `php -v`는 `8.3.6`이었지만 변경 이력에는 두 CVE가 들어 있었고, rockylinux:9의 `php-cli-8.0.30-8.el9_8.1`도 변경 이력에 CVE가 있었습니다. 반대로 **저장소에 수정이 아직 없을 수도 있습니다**(검증 시점의 alpine:3.20 저장소는 php83 8.3.15-r0, openSUSE Leap 15.6은 php8 8.2.30). 받은 패키지가 정말 수정본인지 **설치 전에** 확인하는 방법을 각 절에 적었습니다.
- 폐쇄망이라도 패치는 서버를 인터넷에 연결하지 않고 가능합니다. 다만 절차가 길어 패치 전까지는 F(가상 패치), G(노출 축소)를 병행하세요. 이들은 우회가 쉽고 완전한 완화책이 아닙니다(PHP 공지).

## 1. 사전 점검표 (Pre-flight)

작업 전에 모두 확인하세요. 하나라도 "아니오"면 진행하지 말고 먼저 해결합니다.

| 확인 | 방법 | 이유 |
|---|---|---|
| 대상 서버의 OS 종류·릴리스·아키텍처를 기록했다 | `cat /etc/os-release`, `uname -m`(Debian 계열은 `dpkg --print-architecture`) | 다른 릴리스·아키텍처의 패키지를 섞으면 설치가 실패하거나 시스템이 깨진다 |
| 받는 PC(연결된 구역)가 같은 릴리스·아키텍처 환경이다 | 같은 OS의 VM, 컨테이너(`--platform`로 아키텍처 지정), 대상 서버의 스냅샷 복원본 | 의존성 계산이 대상과 같아야 한다 |
| 현재 설치된 PHP 패키지와 모듈 스트림을 기록했다 | 5~8절 각 OS의 "대상 서버에서 먼저 할 일" | 어떤 패키지를 받을지, 모듈 스트림을 바꾸지 않을지 판단 |
| 의존성 닫힘(closure)을 계산했다 | 각 절의 `--print-uris`, `dnf download --resolve`, `apk fetch -R`, `zypper --download-only` | 빠진 의존성이 있으면 오프라인에서 해결할 수 없다 |
| 여유 디스크 공간 | `df -h /var /tmp`, 이전 문서에서 본 패키지 묶음 크기(검증 환경에서 23~47 MB) 이상 + 여유 | 설치 중 공간 부족은 반쯤 설치된 상태를 만든다 |
| 백업 | `/etc/php`, `/etc/php-fpm.d`, `/etc/httpd`, `/etc/apache2`, `/etc/nginx`, 애플리케이션 설정, VM 스냅샷 | 설정 복원용. 패키지 롤백은 취약 버전 복귀이므로 권장하지 않음 |
| 작업 창과 롤링 계획 | 무중단이면 LB에서 노드를 하나씩 분리 | 재시작 순간의 서비스 단절 최소화 |
| 패키지 고정(hold) 점검 | `apt-mark showhold`, `dnf versionlock list`(해당 시), `zypper locks` | 고정된 패키지는 설치가 막히거나 이전 버전으로 남는다 |
| 이미 침해되었을 가능성을 판단했다 | [`runbook.ko.md`](runbook.ko.md)의 로그 점검 | 침해 의심 서버는 **재시작 전에 증거 확보**(KISA 수칙 7) |
| 전송 매체 정책 | 새 USB/DVD, 읽기 전용 마운트, 사용 후 폐기·초기화 | 아래 2절 |
| 설치 후 검증·재시작 계획 | 이 문서 9절 | 재시작하지 않으면 옛 버전이 계속 동작(KISA 수칙 2) |

## 2. 무결성 규칙

1. **체크섬·서명은 패키지를 받은 경로와 다른, 독립 채널에서 얻습니다.** 같은 서버에서 받은 파일과 같은 서버가 알려준 해시를 대조하면 서버가 침해됐을 때 의미가 없습니다. 다른 PC·다른 네트워크의 배포판 공식 사이트, 배포판 서명 키링, PHP 공식 다운로드 페이지의 값을 쓰세요.
2. **전송 매체를 신뢰하지 마세요.** USB·DVD·사내 파일 서버를 오가는 동안 바뀌거나 오염될 수 있습니다. 연결된 구역에서 해시 목록(`SHA256SUMS`)을 만들고, 목록 자체는 별도로 (예: 종이·다른 매체·사람이 읽는 화면으로) 전달해, **대상 구역에서 설치 직전에 다시** 검증합니다.
3. 패키지 서명이 있는 형식(rpm, apk)은 서명을 검증하고, 서명이 없는 형식(deb 개별 파일)은 서명된 저장소 색인에 있는 SHA-256과 대조합니다.
4. 서명 검증을 끄는 옵션(예: `apk add --allow-untrusted`, `--nogpgcheck`)을 해결책으로 쓰지 마세요. 검증이 실패하면 키·파일 중 무엇이 틀렸는지 찾아야 합니다.
5. 받은 패키지에 수정이 들어 있는지 **설치 전에** 변경 이력으로 확인합니다(각 절).
6. 한 번 쓴 매체는 공유 매체로 되돌리지 말고, 패치 기록(누가·언제·어떤 해시)을 남깁니다.

## 3. 연결된 PC에서 쓰는 도구

- Linux/macOS: `curl`, `sha256sum`(macOS는 `shasum -a 256`), `docker`(검증 환경 복제용).
- Windows: PowerShell의 `Get-FileHash`, `Invoke-WebRequest`(미검증).
- 이 문서의 명령은 별도 표기가 없는 한 Linux 셸입니다.

## 4. 검증 요약

| 대상 | 검증 이미지 | 어디까지 |
|---|---|---|
| Debian 12 | debian:12 (aarch64) | 목록 생성(`--print-uris`), 해시 목록, 다운로드, 설치 전 변경 이력 확인, `--network none` 컨테이너에서 `apt-get install ./*.deb` |
| Ubuntu 24.04 | ubuntu:24.04 (aarch64) | 위와 같음 + 변경 이력(CVE) 확인 |
| RHEL 계열 | rockylinux:9 (aarch64) | `dnf download --resolve`, `yumdownloader --resolve`, `rpmkeys -K`, `dnf install --disablerepo='*' ./*.rpm`(`--network none`), `reposync` 옵션 이름 확인(미실행) |
| Alpine | alpine:3.22 (3.20은 수정 버전이 없어 저장소 조회까지) | `apk fetch -R`, `apk verify`, `apk add --no-network`, 서명 거부 동작 |
| SUSE | registry.opensuse.org/opensuse/leap:15.6 | `zypper install --download-only`, `rpmkeys -K`, `zypper install ./*.rpm`(`--network none`) |
| Docker | 호스트 Docker | `docker save`/`docker load`, 이미지 ID 비교 |
| Windows ZIP, 소스 빌드 | - | 절차는 문헌 기반, Windows·PowerShell은 미검증 |

중요: 위 시점에 Debian 12, Ubuntu 24.04, Rocky 9의 공식 저장소에는 수정이 이미 반영되어 있었습니다. 이 문서가 검증한 것은 "오프라인 절차가 동작한다"이며, 설치한 패키지가 수정본임은 설치 전 변경 이력 확인(Debian/Ubuntu의 `php8.2-common` 등, rpm의 `--changelog`)으로 별도로 확인했습니다. 업그레이드 대상이 이미 패치된 버전이 설치된 컨테이너였으므로 "취약 버전 -> 수정 버전 교체" 자체를 시연한 것은 아닙니다.

## 5. Debian / Ubuntu

### 5.1 대상 서버에서 먼저 할 일 (오프라인 상태에서 가능)
```bash
cat /etc/os-release | grep -E '^(ID|VERSION_ID|VERSION_CODENAME)='
dpkg --print-architecture
# 설치된 패키지 목록(이름=버전)을 기록: 연결된 구역에서 비교용
dpkg-query -W -f='${db:Status-Abbrev} ${Package}=${Version}\n' | awk '$1=="ii"{print $2}' > installed-packages.txt
# 설치된 PHP 패키지 이름만
dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk '$1=="ii"{print $2}'
apt-mark showhold
```
`dpkg-query -W 'php*'`만 쓰면 설치되지 않은 패키지 이름까지 나오므로 `ii`(설치됨)만 거릅니다.

### 5.2 연결된 구역에서 URI 목록 만들기
`apt-get --print-uris`는 "이 컴퓨터의 상태와 이 컴퓨터의 최신 패키지 목록으로 설치하면 무엇을 받아야 하는가"를 출력합니다. 그래서 **최신 패키지 목록을 가진 같은 릴리스의 컴퓨터**에서 돌려야 합니다. 대상 서버의 목록은 오프라인이라 오래됐기 때문에 수정 버전이 없습니다.

방법 가: 대상 서버의 스냅샷/클론 VM을 연결된 구역에 복원해 `apt-get update` 후 실행(가장 정확: 이미 설치된 의존성이 같음).
방법 나: 같은 릴리스·아키텍처의 컨테이너(깨끗한 상태). 대상에 이미 있는 의존성까지 목록에 포함되지만 설치 때 같은 버전은 건너뜁니다(받는 양이 늘 뿐).
```bash
# 방법 나 예: Debian 12, 아키텍처는 대상과 맞춤(--platform linux/amd64 등)
docker run --rm -it -v "$PWD":/work -w /work debian:12 bash
# 컨테이너 안에서
apt-get update
# 설치할 PHP 패키지 이름은 대상 서버의 5.1 결과로 채운다(아래는 예시)
apt-get --print-uris -y install php8.2-fpm php8.2-cli > uris.txt
grep -c "^'" uris.txt      # 받을 파일 수 (검증 예: 41개, 23 MB)
```
출력 형식은 `'URL' 파일명 크기 해시` 입니다(검증 예: `'http://deb.debian.org/debian/pool/main/l/lvm2/dmsetup_1.02.185-2_arm64.deb' dmsetup_2%3a1.02.185-2_arm64.deb 75212 MD5Sum:...`). 이 환경의 apt는 **MD5Sum만 표시**했으므로 MD5는 쓰지 말고, 아래처럼 같은 컴퓨터의 패키지 색인에서 SHA-256을 가져옵니다.

```bash
# uris.txt를 만든 같은 컴퓨터에서: 파일마다 SHA-256을 뽑아 sha256.txt 생성 (검증됨)
grep "^'" uris.txt | while read -r url name size hash; do
  pkg=${name%%_*}; rest=${name#*_}; ver=${rest%_*}; ver=${ver//%3a/:}
  sha=$(apt-cache show "$pkg=$ver" | sed -n 's/^SHA256: //p' | head -1)
  echo "$sha  $name"
done > sha256.txt
head -2 sha256.txt
```
파일명의 `%3a`는 epoch의 `:`이 URL 인코딩된 것으로, 그대로 파일 이름이 되며 설치에는 문제가 없었습니다.

### 5.3 연결된 PC에서 다운로드·검증
```bash
mkdir debs && cd debs
grep "^'" ../uris.txt | while read -r url name size hash; do
  curl -fsS -o "$name" "${url//\'/}" || echo "FAIL $name"
done
# SHA-256 대조 (Linux: sha256sum -c, macOS: shasum -a 256 -c)
sha256sum -c ../sha256.txt        # 모두 OK여야 함. FAIL이나 누락이 있으면 중단
```
검증에서는 41개(debian:12)와 46개(ubuntu:24.04) 모두 `OK`였습니다.

**설치 전 수정 포함 여부 확인 (필수)**: 받은 `.deb` 안의 변경 이력에서 CVE를 찾습니다.
```bash
for f in php*.deb; do
  dpkg-deb --fsys-tarfile "$f" | tar -xOf - --wildcards './usr/share/doc/*/changelog.Debian.gz' 2>/dev/null \
    | zcat 2>/dev/null | grep -m1 -E 'CVE-2026-10961[89]' && echo "  <- $f"
done
```
검증 결과(debian:12): `Fix CVE-2026-109618 and CVE-2026-109619: State corruption via bailout.  <- php8.2-common_8.2.35-1~deb12u1_arm64.deb`. 변경 이력은 `php8.2-common` 패키지에 들어 있고 `php8.2-cli`, `php8.2-fpm`은 같은 문서를 가리킬 수 있으므로, 아무 줄도 안 나오면 `php*-common` 패키지가 목록에 있는지부터 확인하세요. **아무것도 안 나오면 이 묶음은 수정본이 아니거나 변경 이력이 다른 패키지에 있는 것이므로 설치하지 마세요.**

### 5.4 대상 서버로 복사 후 설치
```bash
# 대상 서버 (오프라인). 매체를 읽기 전용으로 마운트한 뒤 작업 디렉터리로 복사
cd /path/to/debs
sha256sum -c ../sha256.txt                       # 설치 직전에 다시 검증 (2절 규칙 2)
sudo apt-get install -y --no-install-recommends ./*.deb
```
- [검증] `docker run --network none`인 컨테이너에서 위 명령이 성공(`rc=0`). ubuntu:24.04에서는 설치가 끝난 뒤 `W: Tried to start delayed item ... but failed` 경고가 출력되었지만 설치는 완료되었고 종료 코드는 0이었습니다(오프라인이라 apt가 의존 패키지를 네트워크에서 다시 받으려다 실패하는 경고로 추정, 원인 미확인).
- `apt-get install ./*.deb`는 로컬 파일의 서명을 검사하지 않습니다. deb 개별 파일에는 서명이 없으므로, **무결성은 5.3의 SHA-256 대조에 달려 있습니다.**
- `--no-download`와 상대 경로 `./*.deb`를 함께 쓰면 "Pathname to install is not absolute" 내부 오류가 났습니다(debian:12). 쓰지 마세요.
- `dpkg -i ./*.deb`는 한 번에 끝나지 않았습니다. 첫 실행은 종료 코드 1(Pre-Depends 순서 문제), 같은 명령을 한 번 더 실행하니 성공했습니다(debian:12). 가능하면 `apt-get install ./*.deb`를 쓰고, `dpkg -i`는 두 번 실행해야 할 수 있음을 알아두세요.
- 설치 중 설정 파일 충돌 질문이 나오면 기존 설정을 유지하려면 `-o Dpkg::Options::="--force-confold"`를 추가합니다(문법만 모의 실행으로 확인).

### 5.5 로컬 미러(대안, 미검증)
여러 대를 폐쇄망에서 계속 운영하면 연결된 구역에서 저장소 일부를 미러해 매체로 옮기고 내부 저장소로 쓰는 편이 안전합니다. `apt-mirror`는 원본 저장소의 서명 파일을 그대로 복사하는 도구, `aptly`는 필터(예: 특정 패키지와 그 의존성)를 지정해 부분 미러를 만들고 자체 키로 다시 서명하는 도구로 알려져 있으나, **이 저장소에서는 시험하지 않았습니다(미검증).** `aptly`처럼 자체 키로 서명하는 경우 그 공개 키를 대상 서버에 독립 채널로 배포해야 합니다.

## 6. RHEL 계열 (RHEL, Rocky, Alma 등)

### 6.1 대상 서버에서 먼저 할 일
```bash
cat /etc/os-release | grep -E '^(ID|VERSION_ID)='
uname -m
rpm -qa 'php*' | sort
dnf module list --enabled php 2>/dev/null       # 모듈 스트림을 쓰는 경우
```
- 모듈 스트림(예: `php:8.3`)을 쓰는 서버는 **같은 스트림 안에서** 업데이트하세요. 연결된 구역에서 `dnf module enable php:8.3` 후 받은 패키지는 모듈 버전(예: `php-fpm-8.3.36-1.module+el9.8.0+...`)이었습니다. 이미 설치된 다른 스트림(예: 비모듈 8.0.30) 위에 스트림을 바꾸는 오프라인 설치는 **시험하지 않았습니다(미검증)**.

### 6.2 연결된 구역에서 다운로드
같은 메이저 릴리스·아키텍처·저장소 구성(필요하면 모듈 스트림도 같음)의 환경에서 실행합니다.
```bash
sudo dnf install 'dnf-command(download)' yum-utils     # 필요 시 (download 플러그인, yumdownloader)
mkdir rpms

# 방법 1: dnf (검증됨)
dnf download --resolve --destdir rpms php-fpm php-cli
# 방법 2: yumdownloader (검증됨)
yumdownloader --resolve --destdir rpms php-fpm
```
- `--resolve`는 **이 컴퓨터에 설치되지 않은 의존성만** 받습니다. 그래서 이 컴퓨터가 대상 서버와 비슷한 상태(스냅샷/클론)일수록 좋습니다. 검증에서 `php-cli`가 설치된 Rocky 9에서 `php-fpm`을 받으면 17개 파일이었습니다.
- `--alldeps`(의존성 전부)는 `--resolve`와 함께 쓰면 설치 여부와 무관하게 닫힘 전체를 받습니다. 깨끗한 rockylinux:9 컨테이너에서 `php-fpm php-cli`를 `--alldeps`로 받으니 107개(47 MB)였고, 이를 다른 rockylinux:9 컨테이너에서 설치하려 하자 `libcurl-minimal`과 `libcurl`이 충돌해 **설치가 실패**했습니다. 최소 이미지와 전체 패키지가 섞였기 때문입니다. 따라서 기본은 `--resolve`만 쓰고 `--alldeps`는 권하지 않습니다.

**서명 검증** (RPM은 패키지마다 서명이 있음):
```bash
# 배포판 공식 키를 독립 채널에서 확보해 지문을 대조한 뒤 가져온다 (키 파일 경로는 배포판마다 다름)
sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
rpmkeys -K rpms/*.rpm          # 각 줄이 "digests signatures OK"여야 함
```
검증(rockylinux:9): 17개 모두 OK. 배포판 키가 아닌 서명이거나 서명이 없으면 `NOT OK` 또는 `(MISSING KEYS)`로 표시됩니다. `dnf install ./*.rpm`은 로컬 파일의 서명 검사를 기본 설정에 따라 건너뛸 수 있으므로(`localpkg_gpgcheck` 설정, 미검증) `rpmkeys -K`를 반드시 따로 실행하세요.

**해시 목록 만들기**:
```bash
(cd rpms && sha256sum *.rpm > ../SHA256SUMS)
```

**설치 전 수정 포함 여부 확인 (필수)**:
```bash
rpm -qp --changelog rpms/php-fpm-*.rpm | grep -E 'CVE-2026-10961[89]'
rpm -qp --changelog rpms/php-cli-*.rpm | grep -E 'CVE-2026-10961[89]'
```
검증(rockylinux:9): `CVE-2026-109618, CVE-2026-109619`가 출력됨(`php-fpm-8.0.30-8.el9_8.1`). 출력이 없으면 이 묶음은 수정본이 아닙니다.

### 6.3 대상 서버에서 설치
```bash
cd /path/to/rpms
sha256sum -c ../SHA256SUMS
rpmkeys -K ./*.rpm
sudo dnf install --disablerepo='*' ./*.rpm       # 저장소 접근을 막고 로컬 파일만 사용
```
검증: `--network none`인 rockylinux:9 컨테이너에서 성공. 설치 후 `php-fpm -v`는 `PHP 8.0.30 (fpm-fcgi) (built: Oct 21 2026 ...)`, `rpm -q --changelog php-fpm`에 CVE가 있었습니다.

### 6.4 내부 미러 (reposync, 부분 검증)
```bash
# 연결된 구역
sudo dnf install dnf-plugins-core createrepo_c
dnf reposync --repoid=appstream --newest-only --download-metadata --download-path /srv/mirror
```
- 검증은 `dnf reposync --help`에서 `--download-metadata`, `--newest-only`, `--repoid`, `--download-path`, `--delete` 옵션 이름이 있다는 것까지입니다. 실제 미러 생성과 `baseurl=file://...` 저장소 설정은 시험하지 않았습니다(미검증). `--repoid` 값(`appstream`, `baseos` 등)은 배포판마다 다르며, AppStream 전체 미러는 용량이 큽니다.
- 미러를 쓰면 대상에서 `dnf upgrade 'php*'`가 평소처럼 동작해 의존성 해결이 가장 안전합니다. 패키지 서명(`gpgcheck=1`)은 유지하세요.

## 7. Alpine

### 7.1 먼저 알아둘 점
- **저장소에 수정이 있는지부터 확인하세요.** 검증 시점에 alpine:3.20 저장소의 php83은 `8.3.15-r0`이었고 수정 버전이 없었습니다. alpine:3.22에는 php82 `8.2.35-r0`, php83 `8.3.36-r0`, php84 `8.4.27-r0`, alpine:3.23에는 php83 `8.3.36-r0`, php84 `8.4.27-r0`, php85 `8.5.12-r0`이 있었습니다. 수정이 없는 릴리스(예: 3.20)는 같은 릴리스의 업데이트로 해결되지 않으므로 Alpine 릴리스 업그레이드나 컨테이너 이미지 교체(옵션 C), 소스 빌드(옵션 D)를 고려하세요.
- Alpine에는 패키지 변경 이력 명령이 없습니다. 업스트림 버전과 릴리스 번호(`8.4.27-r0`)로 판단합니다(예: `php-fpm84 -v`는 `PHP 8.4.27 ... (built: Oct 22 2026 ...)`).

### 7.2 다운로드
같은 Alpine 릴리스·아키텍처의 환경(예: `alpine:3.22`)에서:
```bash
apk update
mkdir pkgs
apk fetch -R -o pkgs php84-fpm          # -R: 의존성까지 재귀적으로 받음. 대상에 이미 있는 것도 포함될 수 있음
ls pkgs | wc -l                         # 검증 예: 12개
(cd pkgs && sha256sum *.apk > ../SHA256SUMS)
```
검증에서 `php84-cli`가 설치된 alpine:3.22에서 `php84-fpm`을 받으니 12개 파일이었습니다.

### 7.3 서명 확인과 설치
APK는 개별 서명이 있으며, 설치 시 `/etc/apk/keys`의 공개 키로 검증됩니다.
```bash
# 대상 서버 (오프라인)
cd /path/to/pkgs
sha256sum -c ../SHA256SUMS
apk verify ./*.apk                       # 서명·해시 검증 (각 줄 "0 - OK")
sudo apk add --no-network ./*.apk        # 네트워크 접근 없이 로컬 파일만
```
검증(alpine:3.22, `--network none`): `apk verify`가 각 파일에 `0 - OK`를 출력했고 설치에 성공했으며 `php-fpm84 -v`는 `PHP 8.4.27`이었습니다.

**서명 주의점**
- 검증 시 파일 끝에 1바이트를 덧붙인 사본은 `BAD archive`로 거부되었습니다(변조 탐지 동작 확인).
- `/etc/apk/keys`를 비운 상태에서 설치하면 `ERROR: ... UNTRUSTED signature`로 거부되었습니다. 이 오류가 나면 `--allow-untrusted`로 우회하지 말고, **같은 릴리스의 Alpine에서 공개 키(`alpine-keys` 패키지가 `/etc/apk/keys`에 두는 파일)를 독립 채널로 가져와 지문을 대조**한 뒤 대상의 `/etc/apk/keys`에 넣으세요. 대상 서버가 이미 해당 릴리스로 설치돼 있으면 키는 이미 있습니다.
- Alpine 릴리스가 다르면(예: 대상 3.20, 받은 곳 3.22) 패키지 ABI가 달라 설치가 깨질 수 있으므로 같은 릴리스에서 받으세요.

## 8. SUSE / openSUSE

### 8.1 연결된 구역에서 다운로드
```bash
mkdir -p cache
sudo zypper --pkg-cache-dir "$PWD/cache" install --download-only php8-fpm
find cache -name '*.rpm'                   # 패키지가 저장소별 하위 폴더에 저장됨
```
검증(Leap 15.6): `php8-fpm-8.2.30-150600.3.25.1.aarch64.rpm` 등 의존성 5개가 `cache/repo-sle-update/aarch64/` 등에 저장되었습니다. `zypper download`라는 하위 명령(`--pkg-cache-dir`로 저장 위치를 바꿀 수 있음)도 존재하며 도움말만 확인하고 실행하지는 않았습니다(미검증).

수정 여부 확인(필수) 및 서명 확인:
```bash
find cache -name '*.rpm' -exec cp {} rpms/ \;     # rpms 디렉터리를 먼저 만들어 둔다
rpm -qp --changelog rpms/php8-fpm-*.rpm | grep -E 'CVE-2026-10961[89]'
rpmkeys -K rpms/*.rpm
(cd rpms && sha256sum *.rpm > ../SHA256SUMS)
```
검증(Leap 15.6): 위 시점에는 `php8-fpm-8.2.30-150600.3.25.1`의 변경 이력에 CVE 항목이 **없었습니다**(출력 0줄). 즉 이 묶음은 수정본이 아니므로 설치해서는 안 됩니다. 서명 검사는 5개 모두 `digests signatures OK`였습니다(서명이 올바르다는 것과 수정본이라는 것은 별개). `zypper list-patches --cve=CVE-2026-109618`도 `No matching issues found.`를 반환했습니다.

### 8.2 대상 서버에서 설치
```bash
cd /path/to/rpms
sha256sum -c ../SHA256SUMS
rpmkeys -K ./*.rpm
sudo zypper --non-interactive --no-refresh install --no-recommends ./*.rpm
sudo zypper ps                         # 업데이트 후에도 옛 파일을 쓰는 프로세스 확인
```
검증(`--network none`인 Leap 15.6 컨테이너): 설치 성공. SUSE 저장소가 수정본을 내기 전에는 8.1의 확인에서 걸러집니다.

## 9. Windows ZIP

PHP 공식 공지: Windows 소스와 바이너리는 [PHP 다운로드 페이지](https://www.php.net/downloads.php?os=windows)에 있습니다. **이 절의 PowerShell 명령은 이 저장소 작업 환경에서 실제로 실행하지 못했습니다(미검증).** 시도한 PowerShell 컨테이너(mcr.microsoft.com/powershell)가 aarch64 호스트에서 에뮬레이션으로 비정상 종료했기 때문입니다.

### 9.1 연결된 PC
1. 현재 운영 중인 빌드와 **같은 종류**를 고릅니다: 스레드 안전(TS) 대 비스레드 안전(NTS), x64/x86, 같은 Visual C++ 런타임 계열. 일반적으로 IIS(FastCGI)·nginx+php-cgi는 NTS, Apache mod_php 모듈은 TS를 씁니다(미검증, 현재 설치의 `php -i`의 "Thread Safety"로 확인).
2. 받은 zip의 SHA-256을 구합니다.
```powershell
Get-FileHash -Algorithm SHA256 .\php-8.4.27-nts-Win32-vs17-x64.zip     # 예시 파일명: 페이지의 실제 이름으로 교체
```
3. 다운로드 페이지에 표시된 SHA-256과 **다른 PC·다른 네트워크에서 연 같은 페이지의 값**으로 대조합니다(2절 규칙 1).

### 9.2 대상 서버(폐쇄망)
```powershell
# 설치 직전에 다시 해시 확인
Get-FileHash -Algorithm SHA256 .\php-8.4.27-nts-Win32-vs17-x64.zip

# 새 폴더에 압축 해제 (기존 폴더를 덮어쓰지 않음)
Expand-Archive -Path .\php-8.4.27-nts-Win32-vs17-x64.zip -DestinationPath C:\php-8.4.27

# 설정 이식 (php.ini와 확장 설정을 새 폴더로)
Copy-Item C:\php\php.ini C:\php-8.4.27\php.ini
```
교체 절차:
1. 서비스 또는 IIS 앱 풀/핸들러 사용을 중지한다(점검 시간 공지).
2. `C:\php`를 `C:\php-old`로 이름 변경(백업), `C:\php-8.4.27`을 `C:\php`로 이름 변경. 또는 서비스·핸들러가 새 경로를 가리키게 수정.
3. 새 `php.ini`에서 확장 경로·`extension_dir`·타임존 등 이식 항목 확인. Windows PHP는 `php.ini-production`을 템플릿으로 줍니다.
4. 서비스 시작. 프로세스 시작 시각이 새 것인지, 열려 있는 핸들이 옛 폴더가 아닌지 확인.
5. `php -v`와 **웹으로 접근한 SAPI**의 버전을 각각 확인(KISA 수칙 2). `php-old`는 취약한 바이너리이므로 접근 불가능한 곳으로 옮기거나 삭제합니다(침해 의심 서버는 증거로 보존).

롤백은 폴더 이름을 되돌리는 것으로 가능하지만 이전 폴더는 취약합니다(권장하지 않음). 불가피하면 F+G를 함께 적용하세요.

## 10. Docker 이미지

폐쇄망 레지스트리나 호스트에 이미지를 옮기는 방법입니다.

### 10.1 연결된 PC
```bash
# 아키텍처를 대상과 맞춘다 (예: --platform linux/amd64)
docker manifest inspect php:8.4.27-fpm > /dev/null && echo exists       # 태그 존재 확인
docker pull --platform linux/amd64 php:8.4.27-fpm                         # 출력의 Digest 값을 기록
docker image inspect php:8.4.27-fpm --format '{{.Id}}'                    # 이미지 ID 기록
docker save -o php-8.4.27-fpm.tar php:8.4.27-fpm
sha256sum php-8.4.27-fpm.tar | tee php-8.4.27-fpm.tar.sha256
```
태그 존재(2026-10-23, `docker manifest inspect`)는 [`response-options.ko.md`](response-options.ko.md)의 옵션 C에 목록이 있습니다.

### 10.2 대상 구역
```bash
sha256sum -c php-8.4.27-fpm.tar.sha256
docker load -i php-8.4.27-fpm.tar
docker image inspect php:8.4.27-fpm --format '{{.Id}}'     # 연결된 PC에서 기록한 값과 같아야 함
```
- 검증: `docker save`로 낸 tar를 `docker rmi` 후 `docker load`로 되돌린 결과 이미지 ID(`sha256:f197...`)가 저장 전과 동일했습니다.
- 다이제스트(`php@sha256:...`)는 레지스트리에서의 식별자입니다. `docker load`로 옮긴 이미지의 RepoDigests가 유지되는지는 확인하지 않았으므로(미검증), 비교에는 이미지 ID와 tar의 SHA-256을 쓰고, 연결된 쪽에서 기록한 `docker pull`의 `Digest:` 값은 출처 기록으로 남기세요.
- 폐쇄망에 사내 레지스트리가 있으면 `docker tag` 후 `docker push`로 올려 배포하는 방식을 쓸 수 있습니다(미검증).
- 이 tar 안의 이미지는 자체 PHP를 포함하므로 호스트 패키지 업데이트와 무관합니다. 새 이미지를 쓰도록 컨테이너를 교체하세요(KISA 수칙 2).

## 11. 소스 tarball

8.2~8.5를 직접 빌드하거나, 7.4/8.0/8.1에 PHP 보안팀 백포트 브랜치를 쓰는 경우입니다(옵션 D).

### 11.1 무결성
- 공식 릴리스 tarball: [PHP 다운로드 페이지](https://www.php.net/downloads.php?source=Y)에서 받습니다. 페이지는 각 tarball의 SHA-256과 서명 링크를 제공합니다. **독립 채널**(다른 PC·다른 네트워크)에서 연 페이지의 해시와 대조하세요.
```bash
sha256sum php-8.4.27.tar.xz              # 파일명은 받은 것에 맞춤
# 서명: 릴리스 관리자 공개 키를 PHP 사이트의 GPG 키 페이지에서 독립 채널로 확보해 지문을 대조한 뒤
gpg --import KEYS
gpg --verify php-8.4.27.tar.xz.asc php-8.4.27.tar.xz
```
위 `gpg` 절차는 이 저장소에서 실행하지 못했습니다(미검증). 서명 파일 이름은 다운로드 페이지의 링크를 따르세요.
- 백포트 브랜치(Git)는 릴리스 tarball이 아닙니다. 연결된 PC에서 클론하고 `git log -1 --format=%H`의 커밋 해시를 독립 채널의 GitHub 웹 화면과 대조한 뒤, `git archive`나 디렉터리 전체의 `tar`로 묶어 해시를 만들어 옮깁니다.
  - 브랜치 주소: 7.4 `https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619`, 8.0 `.../tree/PHP-8.0-CVE-2026-109618-109619`, 8.1 `.../tree/PHP-8.1-CVE-2026-109618-109619` (PHP 공지).
  - 커밋이 서명되었는지는 확인하지 않았습니다.

### 11.2 오프라인 빌드 의존성
빌드 도구와 개발 헤더도 오프라인으로 옮겨야 합니다. 같은 방법으로 목록·해시를 만들고 같은 절차로 설치하세요. 검증된 최소 구성(debian:12: `git build-essential autoconf bison re2c pkg-config libxml2-dev libsqlite3-dev` 설치 후 `./buildconf --force`, `./configure --disable-all --enable-cli --enable-fpm`, `make`)의 결과는 [`response-options.ko.md`](response-options.ko.md) 8절을 보세요. 실제 운영 빌드는 쓰는 확장(openssl, curl, zlib, mbstring 등)의 개발 패키지가 더 필요하며, 필요한 목록은 현재 빌드의 `php -i | grep 'Configure Command'`로 알 수 있습니다.
```bash
# 연결된 구역의 같은 릴리스 환경에서 (5.2~5.3 절차를 재사용)
apt-get --print-uris -y install build-essential autoconf bison re2c pkg-config libxml2-dev libsqlite3-dev > build-uris.txt
```
- 빌드는 연결되지 않은 별도 빌드 서버에서 하고, 결과물(설치 폴더)을 운영 서버로 옮기는 편이 운영 서버에 컴파일러를 두지 않는 면에서 안전합니다(이 문서의 권고).
- 백포트 브랜치는 "최소 소스 백포트"이므로 스테이징에서 먼저 검증하고 이전(옵션 I)을 계획합니다.

## 12. 설치 후 검증·재시작 체크리스트

| 순서 | 확인 | 방법 |
|---|---|---|
| 1 | 설치된 패키지가 수정본이다 | `zcat /usr/share/doc/php8.2-common/changelog.Debian.gz | grep -E 'CVE-2026-10961[89]'`, `rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'`, Alpine은 버전(`8.4.27-r0` 이상) |
| 2 | 설정 파일이 의도대로다 | 백업과 `diff`, `php-fpm8.2 -t`(PHP-FPM 설정 시험: debian:12에서 `test is successful` 확인), `apache2ctl configtest`, `nginx -t` |
| 3 | **웹 SAPI를 재시작했다** | `systemctl restart php8.2-fpm` / `apache2` / `httpd` 등 (KISA 수칙 2: 재시작하지 않으면 옛 버전이 계속 동작) |
| 4 | 프로세스가 새 바이너리다 | `ls -l /proc/[0-9]*/exe | grep deleted`, `grep -l 'libphp.*(deleted)' /proc/[0-9]*/maps`, SUSE는 `zypper ps`, 프로세스 시작 시각 |
| 5 | 웹 SAPI의 버전·설정 | CLI의 `php -v`는 증거가 아님. 웹 SAPI 바이너리의 `-v`, 임시 확인 페이지(확인 후 삭제) |
| 6 | 서비스 정상 | 헬스체크, 로그인·업로드·세션 기능 시험, 에러 로그 |
| 7 | 다른 PHP가 남아 있지 않다 | 한 서버에 PHP가 여러 개면 각각(KISA 수칙 2) |
| 8 | 기록 | 누가·언제·무엇을(패키지 이름·버전·SHA-256)·어느 매체로 적용했는지 |
| 9 | 후속 | 로그 점검(최소 2026-10-17 이후), 인증정보 교체: [`runbook.ko.md`](runbook.ko.md) |

## 13. 이 문서에서 실제로 실행하지 못한 것 (미검증 목록)

- Windows 전체 절차와 PowerShell 명령(컨테이너가 에뮬레이션으로 종료됨)
- `apt-mirror`, `aptly`, `dnf reposync` 실제 미러 생성과 `file://` 저장소 구성
- RHEL 모듈 스트림을 바꾸는 오프라인 설치
- 소스 tarball의 `gpg --verify` 절차
- 사내 Docker 레지스트리 push/pull, `docker load` 후 RepoDigests 유지 여부
- 실제 수정 버전으로의 **교체**(검증 환경의 저장소 패키지가 이미 수정본이거나, 아직 수정본이 없었음)
- systemd 서비스 재시작, 로드밸런서 롤링
