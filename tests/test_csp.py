"""Content security policy without inline scripts: the page has no inline script and no inline event handlers,
the interface logic is served as /app.js, handlers are data-on-* attributes with a parsed (never evaluated) syntax."""

import re
import unittest
from pathlib import Path
from unittest import mock

import _paths

ROOT = Path(_paths.ROOT)
WEB = ROOT / "samonboarding" / "web"
HTML = (WEB / "index.html").read_text(encoding="utf-8")
JS = (WEB / "app.js").read_text(encoding="utf-8")

# The grammar the dispatcher in app.js accepts (parseActions)
ARG = (
    r"""(?:'(?:[^'\\]|\\.)*'|-?\d+(?:\.\d+)?|true|false|null|event"""
    r"""|this(?:\.value|\.checked|\.dataset\.[A-Za-z_$][\w$]*)?|\$\{[^}]*\})"""
)
CALL = rf"[A-Za-z_$][\w$]*\(\s*(?:{ARG}(?:\s*,\s*{ARG})*)?\s*\)"
HANDLER = re.compile(rf"^\s*{CALL}(?:\s*;\s*{CALL})*\s*;?\s*$")


class CspTests(unittest.TestCase):
    def test_policy_forbids_inline_scripts(self):
        main = (ROOT / "samonboarding" / "main.py").read_text(encoding="utf-8")
        csp = "".join(
            re.findall(r'^\s*"([^"]*)"\s*$', main[main.index("CSP = (") : main.index(")", main.index("CSP = ("))], re.M)
        )
        script_src = re.search(r"script-src ([^;]*)", csp).group(1)
        self.assertEqual(script_src.strip(), "'self'")
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("object-src 'none'", csp)

    def test_page_has_no_inline_script(self):
        for tag in re.findall(r"<script\b[^>]*>", HTML):
            self.assertTrue(
                'src="/app.js?v=__APP_VERSION__"' in tag
                or 'src="/theme.js?v=__APP_VERSION__"' in tag
                or 'type="application/json"' in tag,
                tag,
            )
        self.assertEqual(HTML.count("<script"), 3)
        self.assertNotIn("javascript:", HTML.lower())

    def test_no_inline_event_handlers(self):
        attr = re.compile(r"""\son[a-z]+\s*=\s*["']""", re.I)
        self.assertEqual(attr.findall(HTML), [])
        self.assertEqual(attr.findall(JS), [], "templates in app.js must use data-on-*")
        self.assertNotIn("<script", JS.replace("<script id=", ""), "no inline script written by the interface")

    def test_every_handler_has_the_supported_syntax_and_exists(self):
        handlers = re.findall(r"""data-on-(click|change|input|keydown|mousemove)=(["'])(.*?)\2""", HTML + JS)
        self.assertGreater(len(handlers), 120)
        declared = set(re.findall(r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", JS, re.M))
        for _event, _q, text in handlers:
            if text == "fn('x', this.value)":
                continue  # example in the comment of the dispatcher
            self.assertRegex(text, HANDLER, text)
            for name in re.findall(r"([A-Za-z_$][\w$]*)\s*\(", re.sub(r"\$\{[^}]*\}", "0", text)):
                self.assertIn(name, declared, f"{text}: {name} is not a global function")

    def test_no_code_from_strings(self):
        for pattern in (r"\beval\(", r"new Function\(", r"setTimeout\(\s*['\"`]", r"setInterval\(\s*['\"`]"):
            self.assertIsNone(re.search(pattern, JS), pattern)

    def test_tailwind_scans_the_script(self):
        # the templates in app.js use Tailwind classes; without the script in "content" they would be missing
        config = (ROOT / "tailwind.config.js").read_text(encoding="utf-8")
        self.assertIn("'./samonboarding/web/**/*.js'", config)

    def test_script_is_served_with_version(self):
        ui = (ROOT / "samonboarding" / "routers" / "ui.py").read_text(encoding="utf-8")
        self.assertIn('@router.get("/app.js")', ui)
        self.assertIn('load_app_js().replace("__APP_VERSION__", updatecheck.installed())', ui)
        self.assertIn("text/javascript", ui)

    def test_page_shows_the_installed_release_with_security_update(self):
        """After a security update the interface shows 2.11.0-s1, not only the program version 2.11.0."""
        try:
            from samonboarding.routers import ui
        except ImportError as e:  # without the installed packages
            self.skipTest(str(e))
        with mock.patch.object(ui.updatecheck, "installed", return_value="9.8.7-s3"):
            page = ui.serve_gui()
            body = ui.serve_app_js().body
            script = body.decode("utf-8") if isinstance(body, bytes) else str(body)  # stub: str
        self.assertIn('<span class="version-chip">v9.8.7-s3</span>', page)
        self.assertIn("SAMONBOARDING v9.8.7-s3</title>", page)
        self.assertIn("/app.js?v=9.8.7-s3", page)  # new image: new address, no stale script from the cache
        self.assertIn("SAMONBOARDING v9.8.7-s3", script)
        self.assertNotIn("__APP_VERSION__", page + script)


if __name__ == "__main__":
    unittest.main()
