# 기여 안내

환영합니다. 아래 규칙은 이 저장소를 안전하게 유지하기 위한 것입니다.

## 절대 규칙
1. **익스플로잇·PoC·공격 페이로드를 올리지 마세요.** 탐지 규칙에는 공개 문서에 나온 표지(예: 필드 이름)만 씁니다.
2. 점검 도구는 **읽기 전용**이고 **네트워크로 아무것도 보내지 않으며** 패치를 **자동 적용하지 않습니다.** 이 성질을 깨는 변경은 받지 않습니다.
3. 사실(버전, 날짜, 연락처, 법령 조문)에는 출처를 붙이세요. 공식 출처(PHP.net, KISA 보호나라, 법령정보센터 등)를 우선합니다. 확인하지 못한 값은 `unverified` 로 표시하고 추측하지 마세요.
4. 새 설정 예시·명령은 컨테이너 등에서 실제로 확인했거나 문서에 '미검증'이라고 적어야 합니다.

## 개발
- 점검 도구는 Python 3.6+ 표준 라이브러리만 씁니다(의존성 추가 금지). 3.7+ 전용 문법·API(dataclass, `capture_output`, `fromisoformat` 등)를 쓰지 마세요.
- `quickcheck/` 의 sh·PowerShell 스크립트는 Python 이 없는 서버용입니다. 판정 규칙은 `tests/vectors/versions.json` 의 공유 벡터로 세 구현이 같은 결과를 내야 합니다.
- 테스트: `python3 -m unittest discover -s tests`, `sh tests/test_quickcheck_sh.sh`, PowerShell 은 `pwsh -File tests/test_quickcheck_ps1.ps1`. Docker 기반 플랫폼 점검은 `docs/testing.ko.md` 를 보세요.
- 권고 데이터를 바꾸면 `python3 tools/sync_embedded_advisory.py --force` 로 내장본을 맞춥니다(기존 파일 교체는 `--force` 가 필요합니다).

## 보안 문제
[SECURITY.md](SECURITY.md) 를 따르세요. 공개 이슈에 위험한 재현 정보를 올리지 마세요.

## 라이선스
기여한 내용은 Apache License 2.0 에 따라 배포됩니다.
