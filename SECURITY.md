# 보안 정책 / Security Policy

## 이 저장소가 하는 일, 하지 않는 일
- 이 저장소는 PHP2Shell(CVE-2026-109618, CVE-2026-109619)에 대한 **방어용** 점검·대응 도구입니다.
- **익스플로잇, PoC, 공격 페이로드를 포함하지 않으며 받지도 않습니다.** 그런 내용이 담긴 이슈·PR은 내용을 지우고 닫습니다.
- 점검 도구는 읽기 전용이며 네트워크로 아무것도 보내지 않습니다. 패치를 자동으로 적용하지 않습니다. 패치의 책임은 체계관리자에게 있습니다.

## 취약점 신고
이 저장소의 코드(예: 점검 도구가 서버를 바꾸거나, 생성한 스크립트에 명령 주입이 가능한 경우)에 보안 문제가 있다면
**공개 이슈로 올리지 말고** GitHub 의 *Security → Report a vulnerability*(비공개 보안 권고)로 알려 주세요.
재현 방법은 안전한 최소 예시로만 적어 주세요. 위험한 PoC 는 첨부하지 마세요.

PHP 자체의 취약점 신고는 PHP 프로젝트로, 한국 내 침해사고 신고는 KISA 보호나라(https://boho.or.kr, 국번 없이 118)로 하세요.
담당 기관 정리는 [docs/contacts.ko.md](docs/contacts.ko.md) 를 참고하세요.

## 지원 버전
최신 릴리스만 지원합니다. 권고 데이터(`data/advisory.json`)는 상황에 따라 자주 바뀌므로 사용 전에 `as_of` 날짜를 확인하세요.

## English summary
This is a defensive check and response toolkit for the PHP2Shell vulnerabilities. It contains no exploit code and accepts none.
The tools are read-only, make no network calls, and never apply patches (the system administrator remains responsible).
Report security issues in this repository privately through GitHub's "Report a vulnerability" feature, not as public issues.
