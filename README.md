# php2shell-triage

PHP2Shell(**CVE-2026-109618 / CVE-2026-109619**, PHP 엔진의 인증 없는 원격 코드 실행·메모리 노출 취약점) 점검과 대응을
돕는 **방어용** 도구 모음입니다. Linux·Unix·macOS·Windows·컨테이너에서 쓸 수 있습니다.

> **이 저장소에는 익스플로잇이 없습니다.** 공격 코드(PoC)도 받지 않습니다. 인터넷에 도는 `php2shell` 이름의 저장소 중 상당수가
> 익스플로잇이거나 악성코드입니다(KISA도 출처 불명 PoC 실행을 경고했습니다). 취약 여부는 PoC가 아니라 **버전·프로세스·설정·로그**로 판단합니다.
>
> 이 도구는 **KISA·PHP 등 어느 기관의 공식 도구가 아닙니다.** 권고 내용은 `data/advisory.json` 에 출처와 함께 정리했고 상황에 따라 바뀝니다.

## 핵심 원칙
- **읽기 전용**: 서버를 바꾸지 않고, 네트워크로 아무것도 보내지 않습니다.
- **자동 패치 없음**: 패치의 책임은 체계관리자에게 있습니다. 대신 **분석한 그 서버에 맞춘 명령**을 출력하거나 검토용 스크립트 파일로 만들어 줍니다. 생성된 스크립트는 `PHP2SHELL_I_REVIEWED=yes` 로 검토를 확인해야 열리고, 단계마다 `y/N` 확인을 받습니다.
- **정직한 판정**: 임시 완화·가상 패치는 "완전한 해결이 아님"을 항상 밝힙니다. 로그에 흔적이 없어도 안전하다고 말하지 않습니다.

## 빠른 시작 (체계관리자)

| 환경 | 파일 | 실행 |
| --- | --- | --- |
| Linux / Unix / macOS (Python 불필요) | `php2shell-quickcheck.sh` | `sudo sh php2shell-quickcheck.sh` |
| Windows (Python 불필요, 더블클릭 가능) | `php2shell-quickcheck.bat` | 관리자 권한 명령 프롬프트에서 `php2shell-quickcheck.bat` |
| Windows PowerShell | `php2shell-quickcheck.ps1` | `powershell -ExecutionPolicy Bypass -File .\php2shell-quickcheck.ps1` |
| 전체 기능 (Python 3.6+) | `php2shell_triage.py` | `sudo python3 php2shell_triage.py` |

릴리스에는 단일 파일들과 `SHA256SUMS` 가 들어 있습니다. **내려받은 뒤 해시를 확인하세요.**

```sh
sh php2shell-quickcheck.sh                  # 판정 + 이 서버 맞춤 조치 계획
sh php2shell-quickcheck.sh --json           # 기계가 읽는 JSON
sh php2shell-quickcheck.sh --no-exec        # 침해가 의심될 때: 발견한 바이너리를 실행하지 않음
sh php2shell-quickcheck.sh --offline        # 폐쇄망용 패치 절차 포함
sh php2shell-quickcheck.sh --plan-file ./patch-plan.sh   # 검토용 맞춤 패치 스크립트 저장 (실행은 관리자가 직접)
```

Python 전체판은 추가로 `--emit-patch-plan DIR`(맞춤 패치 계획 md + sh/ps1), `--emit-virtual-patch DIR`(WAF·웹서버·PHP·OS 가상 패치 설정 생성, `--uploads yes|no`),
`--mode offline`, `--list-options`, `--format md` 를 지원합니다.

### 종료 코드
| 코드 | 의미 |
| --- | --- |
| 0 | 확인한 범위에서 조치가 필요한 설치 없음 |
| 1 | 취약·EOL이거나, 패치했지만 옛 코드가 계속 실행 중(재시작 필요)인 설치가 있음 |
| 3 | 확인 불가(권한·필수 도구 부족 등) — 안전하다는 뜻이 아닙니다 |

### 이 도구가 보는 것
실행 중인 PHP(PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed, IIS FastCGI)와 설치된 바이너리를 찾아 버전을 분류하고,
배포판 패키지의 **벤더 백포트 근거**(변경 이력의 CVE 번호), **재시작 필요 여부**(옛 프로세스가 계속 실행 중인지),
php.ini·FPM 풀·Apache의 **임시 완화 적용 상태**(정적 분석)를 확인합니다. `php -v` 는 웹 SAPI를 대표하지 못하므로 쓰지 않습니다.

## 대응 옵션
도구는 시스템을 분석한 뒤 상황에 맞는 **권장 순서**를 계산해 보여 줍니다. 전체 목록은 `--list-options`.

A 온라인 패치 · B 오프라인(폐쇄망) 패치 · C 컨테이너 이미지 재빌드 · D 소스 빌드(7.4/8.0/8.1은 PHP 보안팀 백포트 브랜치) · E 벤더·호스팅·장비 제조사에 요청 ·
F 가상 패치 · G 노출 축소·서비스 중단 · H 사후 피해 억제·탐지 · I 지원 버전으로 이전 · R 재시작

자세한 안내: [대응 옵션](docs/response-options.ko.md) · [오프라인 패치](docs/offline-patching.ko.md) · [가상 패치](docs/virtual-patching.ko.md) ·
[대응 런북](docs/runbook.ko.md) · [연락처·담당 기관](docs/contacts.ko.md) · [패치 안내서](docs/patch-guide.ko.md)

## 테스트와 검증 현황
- 단위 테스트, Python 3.6, sh(여러 배포판), PowerShell, 실제 PHP 컨테이너 이미지, Windows·macOS·Linux CI 결과는
  [docs/verification.ko.md](docs/verification.ko.md) 에 **실행한 것과 하지 못한 것을 구분해** 적었습니다.
- Docker가 있으면 누구나 재현할 수 있습니다: `python3 tests/platform_matrix.py` ([docs/testing.ko.md](docs/testing.ko.md)).

## 한계와 책임
- 점검은 **서버 안에서** 정적으로 읽을 수 있는 것만 봅니다. 가상호스트별 `.user.ini`·`.htaccess`·`ini_set()` 값은 알 수 없습니다.
- 가상 패치·임시 완화는 우회될 수 있고, PHP 공식 입장은 "완전한 완화책은 없고 업데이트만이 안전"입니다.
- 이 도구의 판정은 참고 자료입니다. 패치 적용과 그 결과(서비스 장애 포함)의 책임은 시스템을 운영하는 관리자에게 있습니다.
  적용 전 영향도 검토와 테스트를 하세요(KISA 대응 수칙도 같은 권고).

## 기여 · 보안 · 라이선스
[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · 라이선스: [Apache License 2.0](LICENSE) (`NOTICE` 참고)

---

## English summary
`php2shell-triage` is a **defensive** toolkit for the PHP2Shell vulnerabilities (CVE-2026-109618 / CVE-2026-109619): a Python 3.6+ tool,
single-file POSIX `sh` and Windows `.bat`/`.ps1` checkers (no Python needed), generators for **host-specific patch plans** and **virtual-patch**
(WAF / web server / PHP / OS) configuration, offline (air-gapped) patching guidance, and a Korean incident runbook with contact points.
It contains **no exploit code**, is **read-only**, makes **no network calls**, and **never applies patches** — the system administrator stays responsible.
Licensed under Apache-2.0. See `docs/verification.ko.md` for what was and was not verified.
