"""Run against an isolated local fixture server: python tests/browser_smoke.py URL.

Requires playwright (see requirements-browser.txt) and a local Chromium binary.
The test uploads synthetic bytes and saves public settings on that fixture.
"""
import json
import os
import sys
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


def main(url: str) -> None:
    assert urlsplit(url).hostname in {"127.0.0.1", "localhost", "::1"}
    with sync_playwright() as playwright:
        from pathlib import Path
        executable = os.environ.get("M3MX_CHROMIUM") or ("/usr/bin/chromium" if Path("/usr/bin/chromium").exists() else None)
        browser = playwright.chromium.launch(executable_path=executable, headless=True,
                                             args=["--no-sandbox"])
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors, external, failed = [], [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
            page.on("request", lambda req: external.append(req.url) if not req.url.startswith(
                (url.rstrip("/") + "/", "data:", "blob:")) else None)
            page.on("response", lambda response: failed.append([response.status, response.url])
                    if response.status >= 400 else None)
            page.goto(url, wait_until="networkidle")
            page.wait_for_selector("#app:not(.hidden)", timeout=15000)
            for view in ("manual", "extractor", "ai", "automation", "full", "settings", "home"):
                page.locator(f'.pn-btn[data-view="{view}"]').click()
                page.wait_for_selector(f"#scene-{view}.active")
                assert page.locator(f'.pn-btn[data-view="{view}"]').evaluate("el => el.classList.contains('active')")
            with page.expect_response("**/api/upload") as upload:
                page.locator("#fileInput").set_input_files({"name": "browser-fixture.raw",
                    "mimeType": "application/octet-stream", "buffer": b"synthetic browser memory fixture"})
            assert upload.value.status == 200, upload.value.text()
            page.wait_for_function("() => AppState.currentFile !== null")
            assert upload.value.json()["sha256"]
            page.locator('.pn-btn[data-view="settings"]').click()
            with page.expect_response(lambda response: "/api/settings" in response.url and
                                      response.request.method == "POST") as settings:
                page.locator("#save-settings-btn").click()
            assert settings.value.status == 200, settings.value.text()
            assert not external, external
            assert not failed, failed
            assert not errors, errors
            print(json.dumps({"navigation": "passed", "upload": "passed", "settings": "passed",
                              "external_requests": external, "browser_errors": errors}))
        finally:
            browser.close()


if __name__ == "__main__":
    main(sys.argv[1])
