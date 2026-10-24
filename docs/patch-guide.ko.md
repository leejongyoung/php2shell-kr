# PHP2Shell 패치 안내서 (체계관리자용)

> **패치의 책임은 체계관리자에게 있습니다.** 이 도구는 패치를 자동으로 적용하지 않습니다. 이 문서와 도구가 만드는 계획 파일의 명령은 '실행 후보'이며, 적용 전 영향도 검토와 시험이 필요합니다.
>
> 명령은 모두 [response-options.ko.md](response-options.ko.md) 5~6절과 [offline-patching.ko.md](offline-patching.ko.md)에 있고, 각 명령에 `[검증]`(컨테이너에서 실행해 확인) / `[미검증]` 표시가 있습니다. 이 안내서는 **순서**만 정리합니다. 무엇을 실제로 확인했는지는 [verification.ko.md](verification.ko.md)를 보세요.

## 0. 시작 전

- 점검 도구와 권고 기준일 확인: `python3 php2shell_kr.py --version`, 결과 JSON의 `advisory_source`(경로·sha256).
- 설정 백업(`php.ini`, FPM 풀, Apache/nginx/IIS 설정)과 되돌리는 방법을 정해 둡니다. 되돌리면 다시 취약해지므로 [가상 패치](virtual-patching.ko.md)·노출 축소를 함께 준비합니다.
- **침해가 의심되면 패치·재시작 전에** [runbook.ko.md](runbook.ko.md)의 순서(격리 → 신고 → 증거 확보 → 조치)를 먼저 따릅니다. 재시작하면 메모리 증거가 사라집니다.

## 1. 점검

```sh
sudo python3 php2shell_kr.py                  # 또는 sudo sh php2shell-quickcheck.sh
python3 php2shell_kr.py --json > report.json  # 기록용
```

종료 코드: `0` 조치 필요 없음 · `1` 조치 필요 · `3` 확인 불가(**안전하다는 뜻이 아님**).

| 판정 | 의미 | 다음 |
| --- | --- | --- |
| 취약 | 수정 이전 버전 | 2단계 |
| EOL | 지원 종료 브랜치 | 옵션 E/D/I (response-options 4절) |
| 벤더 패치 | 버전은 낮지만 패키지 변경 이력에 두 CVE가 있음 | 재시작 여부 확인(3단계) |
| 수정됨 | 수정 버전 이상 | 재시작 여부 확인(3단계) |
| 확인 필요 | 버전을 알 수 없음 | `--exec` 사용 여부 판단, 수동 확인 |

## 2. 패치 방법 선택

도구는 점검 결과로 **권장 순서**를 계산합니다. 시스템에 맞춘 명령은 계획 파일로 받을 수 있습니다.

```sh
python3 php2shell_kr.py --emit-patch-plan ./plan --mode online     # 인터넷 가능
python3 php2shell_kr.py --emit-patch-plan ./plan --mode offline    # 폐쇄망
sh php2shell-quickcheck.sh --plan-file ./patch-plan.sh                 # Python 없이
```

생성된 `.sh`/`.ps1`은 `PHP2SHELL_I_REVIEWED=yes` 를 설정해야 실행되고(안 하면 종료 코드 64), 단계마다 `y/N` 확인을 받습니다. 기존 파일은 덮어쓰지 않습니다(`--force` 필요).

| 상황 | 방법 | 자세한 문서 |
| --- | --- | --- |
| 저장소에 수정 패키지가 있음 | A 온라인 패치 | response-options 5절 |
| 인터넷 없음 | B 오프라인 패치 | offline-patching |
| 컨테이너 | C 수정 버전 이미지로 재빌드·재배포 | response-options 옵션 C |
| 7.4 / 8.0 / 8.1 | D 소스 백포트 브랜치 또는 E 벤더 | response-options 옵션 D·E |
| 5.4~7.3 등 수정 불가 | I 지원 버전으로 이전 + F·G로 위험 축소 | 옵션 F·G·I |
| 지금 패치할 수 없음 | F 가상 패치, G 노출 축소 | virtual-patching |

수정 버전: **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 / 8.6.0RC4**. 저장소가 아직 수정을 내지 않았다면(예: 검증 시점의 Alpine 3.20) 업데이트해도 해결되지 않습니다. 이때는 OS 릴리스 업그레이드나 옵션 C/D/I를 고려합니다.

## 3. 재시작 (필수)

패치 후 **모든 PHP 프로세스를 재시작**해야 합니다(KISA 수칙 2). 재시작하지 않으면 메모리의 옛 코드가 계속 실행됩니다. `systemctl reload`/`graceful`이 코드를 새로 적재하는지는 이 저장소에서 확인하지 않았으므로 전체 재시작을 권장합니다. 유닛 이름은 환경마다 다릅니다(`php8.2-fpm`, `php-fpm`, `apache2`, `httpd` 등). 재시작 명령은 대부분 `[미검증]`이며 response-options 5절에 있습니다.

## 4. 적용 확인

세 가지를 함께 확인합니다(response-options 6절).

1. 패키지에 수정이 들어 있다 — 변경 이력에 두 CVE가 있거나 버전이 수정 버전 이상.
2. 실행 중인 프로세스가 새 바이너리다 — 도구를 다시 실행해 `재시작 필요: 아니오`를 확인.
3. 웹 SAPI가 의도한 PHP·설정이다 — `php -v`(CLI)만으로 판단하지 않습니다.

패치 후에는 2026-10-17 이후 로그를 점검하고(runbook), DB 비밀번호·API 키·세션 키를 교체합니다. 로그에 흔적이 없어도 안전이 보장되지는 않습니다.

## 5. 문제가 생기면

- 패치 후 장애: 이전 버전으로 되돌리기 전에 가상 패치·노출 축소로 위험을 줄일 수 있는지 먼저 검토합니다. 되돌리면 다시 취약합니다.
- 침해 의심: runbook의 순서를 따르고, [연락처](contacts.ko.md)의 기관에 신고합니다. 법정 신고 기한이 있을 수 있으니 확인하세요.
