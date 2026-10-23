# SELinux / AppArmor 메모 (PHP2Shell 침해 후 피해 축소)

> 상태: 미검증. 이 문서의 명령은 컨테이너에서 시험하지 않았다. 스테이징에서 먼저 확인할 것.
> 이 설정은 취약점을 막지 않는다. 코드 실행이 일어나도 피해 범위를 줄이는 보조 수단이다.
> 롤백: 각 항목에 되돌리는 명령을 적었다.

## SELinux (RHEL 계열)

- 현재 상태 확인: `getenforce`, `sestatus`
- 웹 프로세스의 외부 네트워크 연결 허용 여부 boolean 확인: `getsebool httpd_can_network_connect`
  - 외부 연결이 필요 없으면 off 유지: `setsebool -P httpd_can_network_connect off`
  - DB 연결만 필요하면 `httpd_can_network_connect_db` 를 별도로 검토.
- 웹 프로세스가 임의 메모리 실행을 못 하게 하는 boolean 상태 확인: `getsebool httpd_execmem` (필요한 앱만 on)
- 웹루트를 읽기 전용 컨텍스트로 두고 쓰기 디렉터리만 `httpd_sys_rw_content_t` 로 지정:
  `semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/uploads(/.*)?"` 후 `restorecon -Rv /var/www/html/uploads`
- 거부 로그 확인: `ausearch -m avc -ts recent`
- 롤백: `setsebool -P 이름 이전값`, `semanage fcontext -d "경로패턴"` 후 `restorecon`.
- permissive 로 전환(`setenforce 0`)은 진단 용도로만 쓰고 즉시 복구한다.

## AppArmor (Debian/Ubuntu 계열)

- 상태: `aa-status`
- php-fpm 프로파일을 직접 작성하는 경우, 처음에는 complain 모드: `aa-complain /경로/프로파일` 로그를 확인한 뒤
  `aa-enforce /경로/프로파일` 로 전환. (aa-complain/aa-enforce 는 apparmor-utils 패키지 제공)
- 프로파일에서 네트워크(`network inet stream`), 쓰기 경로, `ix`/`Px` 실행 허용을 최소화.
- 롤백: `aa-disable /경로/프로파일` 또는 `apparmor_parser -R /경로/프로파일`.
- 구체적 프로파일 내용은 배포판/앱마다 달라 이 저장소에서는 제공하지 않는다(미검증).
