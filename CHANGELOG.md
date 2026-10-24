# 변경 이력

버전 번호는 0.x 입니다. JSON 출력 필드와 종료 코드(0/1/3)는 아직 호환성을 약속하지 않습니다. 검증한 것과 못한 것은 [docs/verification.ko.md](docs/verification.ko.md) 에 있습니다.

## 0.2.0 — 2026-10-24

### 바뀐 이름 (호출하는 쪽 수정 필요)

- 도구 이름을 `php2shell-triage` 에서 `php2shell-kr` 로 통일했습니다.
  - Python 전체판 `php2shell_triage.py` → `php2shell_kr.py`
  - 배포 묶음 `php2shell-triage-<버전>` → `php2shell-kr-<버전>`
  - JSON 의 `tool` 값과 `--version` 출력이 `php2shell-kr` 로 바뀝니다.
  - 이전 이름으로 호환되는 별칭은 남기지 않았습니다. `php2shell-quickcheck.*` 는 그대로입니다.

### 고친 결함 (모두 실제 환경에서 찾았고 회귀 테스트가 있습니다)

- Linux: root 로 실행해도 커널 스레드 때문에 `process_visibility` 가 `limited` 로 나오던 문제.
- macOS: php-fpm 이 바꾼 프로세스 제목(`php-fpm: master process (...)`)을 실행 파일에 연결하지 못해 실행 중인 php-fpm 을 놓치던 문제(sh 판).
- Python 판이 `ps` 출력을 4KB 에서 잘라 뒤쪽의 php-fpm 을 놓치던 문제.
- FreeBSD: `ps -o pid=,comm=` 가 첫 열 머리글만 바꾸고 다른 열을 내지 않아 두 구현 모두 프로세스를 하나도 못 찾던 문제.
- Windows: 기본 환경에서 `System32\cmd.exe` 조차 신뢰하지 않던 문제. ACE 식별자 변환 예외, 기본 `C:\` 의 `Authenticated Users:(AD)`, 최소 환경에서 PowerShell 이 20~30초 걸려 시간 제한에 걸리는 것이 겹친 원인이었습니다. ACL 은 이제 PowerShell 없이 `advapi32` 로 직접 읽고, 앱 폴더(실행 파일이 든 폴더) 위의 상위 폴더에서는 "새 파일·하위 폴더 만들기" 권한만 무시합니다.
- 패치 계획의 증거 보존 단계가 자기 출력 파일(`SHA256.csv`)을 읽으려다 오류를 내던 문제.

### 추가

- 실제 환경 확장 검증(`.github/workflows/extended.yml`): docker-compose 소켓, GPG 서명, 7.4/8.0/8.1 백포트 빌드, Kubernetes(kind), Homebrew, FreeBSD, systemd·auditd·nftables 호스트, Windows IIS·ACL·cp949.
- IIS 가상 패치(`web.config`)와 docker-compose 하드닝의 검증 상태 갱신. `CHOWN` 이 필요한 경우를 문서화.
- README 배너(애니메이션 SVG)와 생성 스크립트 `tools/build_art.py`.
- GitHub Actions 버전 갱신(SHA 고정 유지).

### 알려진 한계

- `quickcheck/php2shell-quickcheck.ps1`·`.bat` 의 Windows 신뢰 판정은 실제 ACL 로 시험하지 못했습니다(Python 판만 검증).
- 취약 버전을 수정 버전으로 교체하는 흐름(`brew upgrade`, `pkg upgrade`, `dnf needs-restarting`), Windows 폴더 교체 전체 절차, SELinux/AppArmor 는 검증하지 못했습니다.
- 백포트 브랜치 서명 키는 커미터의 GitHub 계정 키로만 확인했습니다. PHP 릴리스 관리자의 키인지는 독립 확인이 필요합니다.

## 0.1.0 — 2026-10-23

첫 공개: Python 전체판, sh·PowerShell·bat 간이판, 가상 패치 템플릿, 한국어 런북.
