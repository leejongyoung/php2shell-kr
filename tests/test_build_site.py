# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""tools/build_site.py: 검색 노출용 안내 페이지가 권고 데이터의 사실을 그대로 담고 검색 엔진이 읽는 메타데이터가 올바른지."""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, ROOT)

import build_site  # noqa: E402

CONFIG = build_site.load_json("site/config.json")
ADVISORY = build_site.load_json("data/advisory.json")


class BuildSite(unittest.TestCase):
    def page(self, config=CONFIG):
        return build_site.build(config, ADVISORY)

    def test_every_fixed_release_and_cve_from_the_advisory_is_on_the_page(self):
        text = self.page()["index.html"]
        for branch, fixed in ADVISORY["fixed_releases"].items():
            self.assertRegex(text, r"PHP %s</td><td><code>%s</code>" % (re.escape(branch), re.escape(fixed)))
        for cve in ADVISORY["cves"]:
            self.assertIn(cve, text)
        self.assertIn(ADVISORY["as_of"], text)

    def test_canonical_robots_and_sitemap_use_the_configured_base_url(self):
        pages = self.page()
        base = CONFIG["base_url"].rstrip("/") + "/"
        self.assertIn('<link rel="canonical" href="%s">' % base, pages["index.html"])
        self.assertIn("Sitemap: %ssitemap.xml" % base, pages["robots.txt"])
        self.assertIn("<loc>%s</loc>" % base, pages["sitemap.xml"])
        self.assertIn('<meta property="og:image" content="%sog.png">' % base, pages["index.html"])

    def test_structured_data_is_valid_json_with_the_faq_questions(self):
        text = self.page()["index.html"]
        blocks = []
        for raw in re.findall(r'<script type="application/ld\+json">(.*?)</script>', text, re.S):
            data = json.loads(raw)
            blocks.extend(data if isinstance(data, list) else [data])
        kinds = {b["@type"] for b in blocks}
        self.assertEqual(kinds, {"SoftwareApplication", "FAQPage"})
        faq = [b for b in blocks if b["@type"] == "FAQPage"][0]
        questions = [q["name"] for q in faq["mainEntity"]]
        self.assertGreaterEqual(len(questions), 5)
        for question in questions:                      # 같은 질문이 화면에도 있어야 구조화 데이터가 유효하다
            self.assertIn(question, text)

    def test_search_engine_verification_tags_appear_only_when_configured(self):
        self.assertNotIn("site-verification", self.page(dict(CONFIG, google_site_verification="", naver_site_verification=""))["index.html"])
        text = self.page(dict(CONFIG, google_site_verification="g-code", naver_site_verification="n-code", bing_site_verification="b-code"))["index.html"]
        self.assertIn('name="google-site-verification" content="g-code"', text)
        self.assertIn('name="naver-site-verification" content="n-code"', text)
        self.assertIn('name="msvalidate.01" content="b-code"', text)

    def test_page_says_it_is_unofficial_and_has_no_unfilled_template_markers(self):
        text = self.page()["index.html"]
        self.assertIn("비공식", text)
        self.assertNotRegex(text, r"%\(|\{\{|%s")
        self.assertTrue(os.path.getsize(os.path.join(ROOT, "site", "og.png")) > 1000)


if __name__ == "__main__":
    unittest.main()
