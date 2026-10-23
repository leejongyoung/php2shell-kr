# 테스트 방법 (여러 플랫폼 · 컨테이너)

점검 도구의 판정이 환경마다 같은지 직접 재현해 볼 수 있습니다. 모든 테스트는 **익스플로잇 없이** 버전·프로세스·설정·파일만 읽습니다.
어떤 환경에서 무엇이 실제로 검증됐는지는 [verification.ko.md](verification.ko.md) 를 보세요.

## 1. 단위·일관성 테스트 (Python 3.6+)
```sh
python3 -m unittest discover -s tests -v
```
- `tests/vectors/versions.json` 의 공유 벡터(44개)로 버전 판정을 확인합니다. Python·sh·PowerShell 세 구현이 같은 벡터를 통과해야 합니다.
- `tests/test_consistency.py` 는 같은 서버 트리에서 Python 판과 sh 판이 같은 판정과 종료 코드를 내는지 비교합니다.
- `tests/test_dist.py` 는 배포 묶음(단일 `.bat`/`.sh`/`.ps1`, `SHA256SUMS`)을 만들어 내용을 검사합니다.
- Python 3.6 호환은 컨테이너에서 확인합니다:
  `docker run --rm -v "$PWD:/r:ro" -w /r python:3.6 sh -c 'cp -r /r /tmp/w && cd /tmp/w && python -m unittest discover -s tests'`

## 2. sh · PowerShell 간이판 하네스
```sh
sh tests/test_quickcheck_sh.sh                                            # 이 호스트의 sh
docker run --rm -v "$PWD:/r:ro" debian:12-slim sh /r/tests/test_quickcheck_sh.sh   # 배포판별 (alpine:3.20, ubuntu:24.04, rockylinux:9-minimal ...)
docker run --rm -v "$PWD:/r:ro" mcr.microsoft.com/powershell:latest pwsh -NoProfile -File /r/tests/test_quickcheck_ps1.ps1
```
Windows 의 실제 레지스트리·IIS·서비스 동작은 Linux 컨테이너로 검증할 수 없습니다. 저장소의 GitHub Actions(`windows-latest`)가
실제 Windows PHP 빌드(취약 8.4.26, 수정 8.4.27)를 내려받아 `.bat` 단일 파일이 둘을 올바르게 분류하는지 확인합니다.

## 3. 실제 PHP 컨테이너 매트릭스 (Docker)
```sh
python3 tests/platform_matrix.py --list
python3 tests/platform_matrix.py                         # 전체
python3 tests/platform_matrix.py --only php-8.4.26-fpm --only needs-restart
python3 tests/platform_matrix.py --registry docker.io/library   # 기본은 mirror.gcr.io/library
```
공식 PHP 이미지(취약 8.4.26 / 수정 8.4.27, FPM·Apache mod_php·Alpine·8.1 EOL)와 배포판 패키지(Debian, Ubuntu, Rocky, Alpine)를 컨테이너에서 띄우고
Python 판과 sh 판을 **둘 다** 실행해 (1) 기대 판정, (2) 두 구현의 일치, (3) "판정은 분류와 벤더 근거로 정해진다"는 불변식, (4) 패치 후 재시작하지 않은 프로세스 탐지를 확인합니다.
배포판 패키지 시나리오는 **그 시점의 실제 저장소 상태**를 보여 주므로 기대 판정을 고정하지 않고 불변식만 봅니다.

> Docker Hub 는 익명 pull 을 제한(429)합니다. 기본값으로 `mirror.gcr.io/library` 를 쓰는 이유입니다.

## 4. 이미 떠 있는 컨테이너 · 이미지 점검
**실행 중인 컨테이너** (컨테이너에 Python 이 없어도 됩니다 — sh 판은 기본 도구만 씁니다):
```sh
docker cp php2shell-quickcheck.sh <컨테이너>:/tmp/q.sh
docker exec <컨테이너> sh /tmp/q.sh            # 또는 --json
```
**정지된 컨테이너 / 이미지** (바이너리를 실행하지 않는 정적 점검, 다른 아키텍처여도 됨):
```sh
docker create --name tmp <이미지> && mkdir rootfs && docker export tmp | tar -x -C rootfs && docker rm tmp
python3 php2shell_triage.py --root ./rootfs            # 또는 sh php2shell-quickcheck.sh --root ./rootfs
```
`--root` 는 **기본적으로 대상 트리의 바이너리를 호스트에서 실행하지 않습니다**(의심 이미지 대비). 버전은 패키지 정보와 바이너리 안의
`X-Powered-By: PHP/x.y.z` 문자열로 읽습니다. 신뢰할 수 있는 트리에서만 `--exec` 를 함께 주세요. 실행 중인 프로세스 점검(재시작 필요 여부)은 `--root` 에서는 하지 않습니다.
컨테이너에서 패치는 **이미지를 수정 버전 베이스로 다시 빌드해 재배포**하는 것이 정석입니다.

## 5. 배포 묶음 만들기
```sh
python3 tools/build_dist.py            # dist/php2shell-triage-<버전>/ 와 .zip/.tar.gz, SHA256SUMS
```
`php2shell-quickcheck.bat` 는 PowerShell 스크립트를 내장한 단일 파일입니다(헤더는 ASCII). 환경 변수 `P2S_NOPAUSE=1` 이면 더블클릭 모드의 `pause` 를 건너뜁니다.

## 6. 실제 환경이 있어야 하는 확장 검증
컨테이너로는 할 수 없는 항목은 `tests/*_check.sh` 와 `.github/workflows/extended.yml` 로 실제 환경에서 실행합니다. 각 스크립트는 머리말에 무엇을 확인하는지 적혀 있고, 끝나면 `PASS`/`FAIL` 줄과 종료 코드를 냅니다. **임시 VM·CI 러너 전용**인 것은 호스트에 패키지를 설치하거나 방화벽 규칙을 잠시 적용합니다.

| 스크립트 | 환경 | 확인하는 것 |
| --- | --- | --- |
| `tests/compose_socket_check.sh` | Docker + compose | `cap_drop: ALL` 에서 unix 소켓 listen 에 `CHOWN` 이 필요한지 |
| `tests/gpg_source_check.sh` | curl, gpg, git | tarball 서명, 변조 탐지, 백포트 브랜치 커밋 서명 (임시 GNUPGHOME 사용) |
| `tests/backport_build_check.sh 7.4 8.0 8.1` | Docker, git | 백포트 브랜치 최소 구성 빌드와 실행 |
| `tests/k8s_check.sh` | kubectl + 클러스터(kind 등) | jsonpath 이미지 목록, `rollout status`, 파드 안 점검 |
| `tests/brew_check.sh` | macOS + Homebrew | Homebrew PHP 탐지, `brew info`, `brew services start` |
| `sudo sh tests/linux_host_check.sh` | systemd 호스트(임시 VM) | systemd drop-in, 재시작 필요 탐지, auditd, nftables |
| `sudo sh tests/freebsd_check.sh` | FreeBSD(임시 VM) | pkg 설치 PHP 탐지, `pkg audit`, `service php_fpm` |
| `tests/windows_acl_check.py`, `tests/windows_iis_check.ps1` | 관리자 권한 Windows(임시) | 실제 ACL 신뢰 판정, IIS `web.config`·FastCGI·`iisreset`, 패치 계획 증거 단계, cp949 콘솔 출력 |

`tests/_inspect_json.py` 는 이 스크립트들이 점검 도구의 JSON(Python·sh 공통)을 검사하는 도우미입니다. 결과와 한계는 [verification.ko.md](verification.ko.md) 를 보세요.
