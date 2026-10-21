# Third-party components

M3MX's first-party code is MIT licensed; see [LICENSE](LICENSE). This does not
relicense bundled or installed third-party software.

| Component | Location / distribution | License information |
|---|---|---|
| Volatility 2 source | `bin/volatility2/`; optional legacy image | GPL version 2 or later; retain `LICENSE.txt`, `LEGAL.txt`, and source headers |
| Volatility 3 | pip dependency in modern runtime | Volatility Software License (VSL); see installed package license and upstream repository |
| Font Awesome Free 6.4.0 | `static/vendor/fontawesome/` | Fonts SIL OFL 1.1, icons CC BY 4.0, code MIT; bundled `LICENSE.txt` contains terms |
| Space Mono, Syne, DM Mono | `static/vendor/fonts/` | SIL Open Font License; individual `*-OFL.txt` files are included |
| Python dependencies | `requirements.txt` | Their installed package metadata and license files retain their own terms |

Font Awesome assets originate from the pinned 6.4.0 distribution on
cdnjs.cloudflare.com and the FortAwesome/Font-Awesome repository. Font files
originate from Google Fonts; bundled font licenses identify their copyright
holders. These assets are served locally at runtime.

The modern Dockerfile copies only the Vol3 launcher, not the bundled Vol2
source. The optional legacy Dockerfile copies Vol2 together with its notices.
Keep these notices and applicable dependency licenses when redistributing
packages or container images. Review the actual distribution and upstream
terms rather than assuming the repository's MIT license covers every component.
