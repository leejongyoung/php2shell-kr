#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""GitHub Pages 용 한국어 안내 페이지(검색 노출용)를 만든다. 표준 라이브러리만 쓴다.

실행: python3 tools/build_site.py [--out _site]
  data/advisory.json (수정 버전·영향 범위·출처)과 site/config.json(주소·검색 엔진 소유 확인 코드)에서 index.html, robots.txt,
  sitemap.xml 을 만들고 site/ 의 정적 파일(og.png 등)과 docs/assets 의 그림을 복사한다.

수정 버전 같은 사실은 코드에 적지 않고 권고 데이터에서만 읽는다(권고가 바뀌면 페이지가 같이 바뀐다).
페이지는 이 도구가 공식 도구가 아님을 맨 위에 밝힌다.
"""
import argparse
import html
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import php2shell_kr  # noqa: E402


def load_json(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return json.load(handle)


def e(value):
    return html.escape(str(value), quote=True)


def faq(advisory, repo, release_url):
    cves = " · ".join(advisory["cves"])
    fixed = ", ".join(advisory["fixed_releases"][branch] for branch in sorted(advisory["fixed_releases"]))
    no_fix = ", ".join(advisory["affected_no_official_fix"]["source_backport_only_branches"])
    return [
        ("PHP2Shell 취약점이 무엇인가요?",
         "%s (%s, CVSS v4.0 %s). 기준일 %s. 최초 악용 관측일은 %s입니다." % (
             advisory["summary_ko"], cves, advisory["cvss_v4"], advisory["as_of"], advisory["first_exploitation_observed"])),
        ("내 서버가 영향을 받는지 어떻게 확인하나요?",
         "`php -v`는 명령줄(CLI) PHP만 보여 주므로 웹 서버가 실제로 쓰는 PHP와 다를 수 있습니다. 이 도구는 실행 중인 PHP-FPM · Apache · "
         "php-cgi · IIS FastCGI 등을 찾아 버전과 벤더 패치 근거, 패치 후 재시작 필요 여부를 판정합니다. 설정과 패키지는 바꾸지 않습니다."),
        ("어떤 버전으로 올려야 하나요?",
         "공식 수정 버전은 %s입니다. PHP %s는 공식 릴리스 대신 PHP 보안팀의 소스 백포트 브랜치만 있고, 더 오래된 5.4~7.3은 수정이 없습니다. "
         "OS 배포판 PHP는 버전 번호가 낮아도 보안 수정을 백포트했을 수 있어 패키지 변경 이력으로 확인합니다." % (fixed, no_fix)),
        ("패치한 뒤 PHP를 재시작해야 하나요?",
         "네. PHP-FPM · Apache · LiteSpeed 같은 웹 SAPI를 재시작하지 않으면 메모리에 올라온 옛 코드가 계속 실행됩니다. "
         "도구는 옛 파일을 쓰는 프로세스를 찾아 '재시작 필요'로 알려 줍니다."),
        ("지금 당장 패치할 수 없으면 어떻게 하나요?",
         "임시 완화(설정 · WAF · 웹서버 규칙)는 공격 경로 일부만 줄이며 완전한 해결이 아닙니다. 이 도구는 서버에 맞춘 가상 패치 설정 파일을 "
         "만들어 주지만 적용 전 스테이징 시험이 필요합니다. 패치할 때까지 외부 접근을 제한하세요."),
        ("KISA나 PHP 공식 도구인가요?",
         "아닙니다. 개인이 만든 비공식 방어용 도구이며 익스플로잇을 포함하지 않습니다. 권고 내용은 출처와 함께 저장소의 권고 데이터에 있습니다."),
    ]


def render(config, advisory):
    base = config["base_url"].rstrip("/") + "/"
    repo = "https://github.com/%s" % config["repo"]
    release_url = repo + "/releases/latest"
    version = php2shell_kr.__version__
    cves = advisory["cves"]
    title = "PHP2Shell 취약점(%s·%s) 점검·대응 도구 - php2shell-kr" % (cves[0], cves[1].split("-")[-1])
    description = ("PHP2Shell(%s, %s) 취약 여부를 버전·프로세스·재시작 필요 여부로 점검하고 서버에 맞춘 패치 계획과 가상 패치를 만드는 "
                   "한국어 방어용 도구와 런북(비공식)." % (cves[0], cves[1]))
    questions = faq(advisory, repo, release_url)
    rows = "".join("<tr><td>PHP %s</td><td><code>%s</code></td></tr>" % (e(branch), e(advisory["fixed_releases"][branch]))
                   for branch in sorted(advisory["fixed_releases"]))
    verify = [
        ("Linux · Unix · macOS (Python 불필요)", "sudo sh php2shell-quickcheck.sh"),
        ("Windows (관리자 명령 프롬프트)", "php2shell-quickcheck.bat"),
        ("전체 기능 (Python 3.6+)", "sudo python3 php2shell_kr.py"),
    ]
    verify_rows = "".join("<tr><td>%s</td><td><code>%s</code></td></tr>" % (e(a), e(b)) for a, b in verify)
    faq_html = "".join("<details><summary>%s</summary><p>%s</p></details>" % (e(q), e(a).replace("`", "")) for q, a in questions)
    source_links = "".join('<li><a href="%s" rel="noopener">%s</a></li>' % (e(s["url"]), e(s["title"])) for s in advisory["sources"])
    ld = [
        {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "php2shell-kr",
         "applicationCategory": "SecurityApplication", "operatingSystem": "Linux, macOS, Windows, FreeBSD",
         "softwareVersion": version, "inLanguage": "ko", "license": "https://www.apache.org/licenses/LICENSE-2.0",
         "codeRepository": repo, "url": base, "description": description,
         "offers": {"@type": "Offer", "price": "0", "priceCurrency": "KRW"}},
        {"@context": "https://schema.org", "@type": "FAQPage",
         "mainEntity": [{"@type": "Question", "name": q,
                         "acceptedAnswer": {"@type": "Answer", "text": a.replace("`", "")}} for q, a in questions]},
    ]
    metas = ""
    if config.get("google_site_verification"):
        metas += '<meta name="google-site-verification" content="%s">\n' % e(config["google_site_verification"])
    if config.get("naver_site_verification"):
        metas += '<meta name="naver-site-verification" content="%s">\n' % e(config["naver_site_verification"])
    if config.get("bing_site_verification"):
        metas += '<meta name="msvalidate.01" content="%s">\n' % e(config["bing_site_verification"])
    return """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<meta name="description" content="%(description)s">
<link rel="canonical" href="%(base)s">
<meta name="robots" content="index, follow, max-snippet:-1">
<meta property="og:type" content="website">
<meta property="og:locale" content="ko_KR">
<meta property="og:site_name" content="php2shell-kr">
<meta property="og:title" content="%(title)s">
<meta property="og:description" content="%(description)s">
<meta property="og:url" content="%(base)s">
<meta property="og:image" content="%(base)sog.png">
<meta property="og:image:width" content="1280">
<meta property="og:image:height" content="640">
<meta property="og:image:alt" content="보라색 픽셀아트 코끼리가 서버 전원을 끄는 그림">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="assets/elephant.svg" type="image/svg+xml">
%(metas)s<script type="application/ld+json">%(ld)s</script>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1c1b29;--muted:#5b5a70;--card:#f4f2fb;--line:#d9d5ee;--accent:#5c4fa3}
@media (prefers-color-scheme:dark){:root{--bg:#14121f;--fg:#ecebf6;--muted:#a9a7c4;--card:#1f1c33;--line:#3a3560;--accent:#aea3e8}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.7 system-ui,-apple-system,"Apple SD Gothic Neo","Noto Sans KR","Malgun Gothic",sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 18px 64px}
h1{font-size:1.7rem;line-height:1.35;margin:.4em 0}h2{margin-top:2.2em;border-bottom:1px solid var(--line);padding-bottom:.3em}
.hero{text-align:center}.hero img{max-width:100%%;height:auto;image-rendering:pixelated}
.note{background:var(--card);border-left:4px solid var(--accent);padding:12px 16px;border-radius:6px}
table{border-collapse:collapse;width:100%%}td,th{border:1px solid var(--line);padding:8px 10px;text-align:left}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--card);border-radius:4px}code{padding:1px 5px}
details{border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:10px 0}summary{cursor:pointer;font-weight:600}
a{color:var(--accent)}footer{margin-top:3em;color:var(--muted);font-size:.9rem}
.btn{display:inline-block;background:var(--accent);color:var(--bg);padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:600;margin:4px}
</style>
</head>
<body>
<main>
<div class="hero"><img src="assets/banner.svg" width="448" alt="보라색 픽셀아트 코끼리가 코로 서버의 전원 버튼을 눌러 불을 끄는 애니메이션"></div>
<h1>PHP2Shell 취약점(%(cve1)s · %(cve2)s) 점검·대응 도구</h1>
<p class="note"><strong>비공식 방어용 도구입니다.</strong> KISA · PHP 등 어느 기관의 공식 도구가 아니며 익스플로잇을 포함하지 않습니다.
저장소 이름의 <code>kr</code>은 한국어 자료라는 뜻입니다. 패치의 책임은 체계관리자에게 있습니다.</p>
<p>%(summary)s 이 도구는 서버의 PHP 버전, 벤더 패치 근거, 패치 후 재시작 필요 여부를 읽어 판정하고, 그 서버에 맞춘 패치 계획과
가상 패치 설정 파일을 만들어 줍니다. 설정과 패키지는 바꾸지 않습니다.</p>
<p><a class="btn" href="%(release)s" rel="noopener">최신 릴리스 내려받기 (v%(version)s)</a>
<a class="btn" href="%(repo)s" rel="noopener">GitHub 저장소</a></p>

<h2>점검하는 법</h2>
<p>내려받은 압축 파일의 SHA-256을 릴리스 노트의 값과 대조한 뒤 실행하세요. 종료 코드 0은 확인한 범위에 조치가 필요한 설치가 없다는 뜻이고,
1은 조치 필요, 3은 확인 불가입니다(<strong>안전하다는 뜻이 아닙니다</strong>).</p>
<table><thead><tr><th>환경</th><th>명령</th></tr></thead><tbody>%(verify_rows)s</tbody></table>

<h2>수정 버전</h2>
<p>영향 범위: PHP %(affected)s. 수정 버전은 아래와 같고 기준일은 %(as_of)s입니다.</p>
<table><thead><tr><th>브랜치</th><th>수정 버전</th></tr></thead><tbody>%(rows)s</tbody></table>
<p>PHP %(no_fix)s는 공식 릴리스 대신 소스 백포트 브랜치만 있습니다. 지원 버전으로 옮기는 계획을 세우세요.</p>

<h2>자주 묻는 질문</h2>
%(faq)s

<h2>문서</h2>
<ul>
<li><a href="%(repo)s/blob/main/docs/runbook.ko.md" rel="noopener">사고 대응 런북 (KISA 대응 수칙 기준)</a></li>
<li><a href="%(repo)s/blob/main/docs/patch-guide.ko.md" rel="noopener">패치 안내서</a></li>
<li><a href="%(repo)s/blob/main/docs/offline-patching.ko.md" rel="noopener">오프라인·폐쇄망 패치</a></li>
<li><a href="%(repo)s/blob/main/docs/virtual-patching.ko.md" rel="noopener">가상 패치</a></li>
<li><a href="%(repo)s/blob/main/docs/verification.ko.md" rel="noopener">검증 현황 (실행한 것과 하지 못한 것)</a></li>
</ul>

<h2>출처</h2>
<ul>%(sources)s</ul>

<footer>php2shell-kr %(version)s · Apache-2.0 · 권고 기준일 %(as_of)s. 이 페이지의 수정 버전은 저장소의 권고 데이터에서 만들어집니다.</footer>
</main>
</body>
</html>
""" % {
        "title": e(title), "description": e(description), "base": e(base), "metas": metas,
        "ld": json.dumps(ld, ensure_ascii=False).replace("</", "<\\/"), "cve1": e(cves[0]), "cve2": e(cves[1]),
        "summary": e(advisory["summary_ko"]), "release": e(release_url), "repo": e(repo), "version": e(version),
        "verify_rows": verify_rows, "affected": e(advisory["affected_range"]), "as_of": e(advisory["as_of"]), "rows": rows,
        "no_fix": e(", ".join(advisory["affected_no_official_fix"]["source_backport_only_branches"])),
        "faq": faq_html, "sources": source_links,
    }


def build(config, advisory):
    base = config["base_url"].rstrip("/") + "/"
    return {
        "index.html": render(config, advisory),
        "robots.txt": "User-agent: *\nAllow: /\n\nSitemap: %ssitemap.xml\n" % base,
        "sitemap.xml": ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                        "  <url><loc>%s</loc><lastmod>%s</lastmod></url>\n</urlset>\n" % (e(base), e(advisory["as_of"]))),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default=os.path.join(ROOT, "_site"))
    args = parser.parse_args(argv)
    config, advisory = load_json("site/config.json"), load_json("data/advisory.json")
    if os.path.isdir(args.out):
        shutil.rmtree(args.out)
    os.makedirs(os.path.join(args.out, "assets"))
    for name, text in build(config, advisory).items():
        with open(os.path.join(args.out, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    for name in os.listdir(os.path.join(ROOT, "site")):
        source = os.path.join(ROOT, "site", name)
        if os.path.isfile(source) and name != "config.json":
            shutil.copy(source, os.path.join(args.out, name))
    for name in ("banner.svg", "elephant.svg"):
        shutil.copy(os.path.join(ROOT, "docs", "assets", name), os.path.join(args.out, "assets", name))
    print("site: %s (%s)" % (args.out, ", ".join(sorted(os.listdir(args.out)))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
