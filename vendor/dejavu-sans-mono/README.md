# DejaVu Sans Mono

Bundled in `src/tcptrace_ng/static/fonts/` and served at `/_tt/fonts/*.woff2`
by the running app. License at `./LICENSE.txt` (DejaVu Fonts License — a
Bitstream-Vera-derived permissive grant).

**Version:** 2.37 (current at vendor time)
**Source:** https://github.com/dejavu-fonts/dejavu-fonts
**Conversion:** `woff2_compress` from Google's woff2 reference tool.

Updating:
1. Download new `.ttf` and `LICENSE` from the upstream tag.
2. `woff2_compress <ttf>` to regenerate `.woff2`.
3. Drop into `src/tcptrace_ng/static/fonts/`, bump this README.
