# 출력 형식과 종료 코드 (1.x 호환 약속)

스크립트가 이 도구의 결과를 읽을 때(`--json`, `-Json`, 종료 코드) 기대어도 되는 것만 적습니다. 1.x 안에서는 여기 적은 **공통 필드를 없애거나 뜻을 바꾸지 않습니다.** 필드나 열거 값은 **추가될 수 있으므로** 모르는 필드는 무시하고 모르는 값은 "확인 필요"로 처리하세요.

## 종료 코드

| 코드 | 뜻 | 조건 |
| --- | --- | --- |
| 0 | 확인한 범위에서 조치가 필요한 설치 없음 | 취약 · EOL · 재시작 필요 · 판단 불가가 모두 0 |
| 1 | 조치 필요 | 취약(`vulnerable`), EOL(`eol`), 또는 재시작 필요(`needs_restart`)인 설치가 하나 이상 |
| 2 | 실행 오류 | 인자 오류, 결과·계획 파일을 쓰지 못함(기존 파일을 덮어쓰지 않음) 등. 판정은 아님 |
| 3 | 확인 불가 | 판단 불가(`unknown`)인 설치가 있거나, 설치를 못 찾았는데 권한 · 프로세스 열거 제한으로 확정할 수 없음. **안전하다는 뜻이 아님** |

우선순위는 1 > 3 > 0입니다(조치할 것이 있으면 확인 불가가 함께 있어도 1).

## JSON 공통 필드 (Python · sh · PowerShell/bat 모두)

최상위:

| 필드 | 형식 | 설명 |
| --- | --- | --- |
| `tool` | 문자열 | 도구 이름 (Python 판은 `php2shell-kr`, 간이판은 `php2shell-quickcheck-*`) |
| `as_of` | 문자열(날짜) | 권고 데이터 기준일 |
| `host` | 문자열 | 점검한 호스트 이름 |
| `platform` | 문자열 | OS 설명 |
| `installations` | 배열 | 찾은 PHP 설치(없으면 빈 배열) |
| `summary` | 객체 | `vulnerable` · `fixed` · `vendor_patched` · `eol` · `unknown` · `needs_restart` 개수 |
| `exit_code` | 정수 | 위 종료 코드와 같은 값 |

`installations[]` 항목:

| 필드 | 형식 | 설명 |
| --- | --- | --- |
| `path` | 문자열 | 실행 파일 또는 모듈 경로 |
| `version` | 문자열 또는 null | 읽은 PHP 버전. 못 읽었으면 null |
| `class` | 문자열 | 버전만으로 본 분류 (아래 열거) |
| `verdict` | 문자열 | 벤더 패치 증거까지 반영한 최종 판정 (아래 열거) |
| `sapi` | 문자열 | `cli` · `cgi` · `fpm` · `apache` · `litespeed` · `frankenphp` · `unknown` |
| `running` | 불리언 | 이 바이너리가 지금 실행 중인가 |
| `pids` | 정수 배열 | 실행 중인 프로세스 ID(없으면 빈 배열) |
| `package` | 문자열 또는 null | 소유 패키지 이름(없거나 해당 없으면 null) |
| `vendor_patch` | 문자열 | `yes` · `no` · `unknown` (패키지 변경 이력에서 두 CVE 수정 근거를 찾았는가) |
| `needs_restart` | 불리언 또는 null | 수정했지만 옛 코드가 계속 실행 중이면 true. 실행 중이 아니면 null/false |
| `notes` | 문자열 배열 | 사람이 읽는 근거 · 주의 |

열거 값:

- `class`: `fixed` · `vulnerable` · `eol_backport` · `eol_no_fix` · `old_unsupported` · `unknown`
- `verdict`: `fixed`(수정됨) · `vendor_patched`(벤더 패치 확인) · `vulnerable`(취약) · `eol`(지원 종료) · `unknown`(판단 불가)

판정 규칙: `class`가 `fixed`면 `fixed`, `vulnerable` · `eol_backport` · `eol_no_fix`면 `vendor_patch`가 `yes`일 때만 `vendor_patched`(아니면 `vulnerable`), `old_unsupported`면 `eol`, 그 밖에는 `unknown`.

## 공통이 아닌 필드 (있을 수 있지만 기대지 마세요)

- Python 전체판 최상위: `tool_version` · `package_manager` · `container` · `process_visibility`(`full`/`limited`/`skipped`) · `exec_policy` · `notes` · `advisory_source` · `response`(조치 계획 요약, `--no-response`면 null)
- Python 전체판 설치 항목: `alias` · `exposure` · `units` · `version_source` · `exec_note` · `executed` · `mitigation`
- PowerShell 간이판 최상위: `warnings` · `plan_file`

이 필드들은 버전이 바뀔 때 이름이나 구조가 달라질 수 있습니다.

## 버전과 호환

- 0.x에서는 이 약속이 없었습니다. 1.0.0부터 위 공통 필드와 종료 코드 의미를 유지합니다.
- 열거 값이나 필드를 **추가**하는 것은 1.x 안에서도 일어날 수 있습니다(예: 새 SAPI 이름).
- 위를 깨는 변경은 2.0.0에서만 합니다.
- 이 약속은 JSON 형식과 종료 코드에 관한 것입니다. 판정 내용(어떤 버전이 취약한지)은 권고 데이터(`data/advisory.json`)에 따라 바뀔 수 있습니다.
