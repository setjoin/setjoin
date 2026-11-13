# Third-party licenses

Setjoin's own code is licensed under the PolyForm Noncommercial License 1.0.0
(see [LICENSE](LICENSE)). The items below are third-party material vendored or
bundled in this repository. They are NOT covered by that license: each one
keeps its own terms, listed here with its source.

Status column:

- **in tree**: the license was read from the files in this repository
  (font name tables, license headers, or a license file next to the item).
- **upstream**: the files carry no license statement; the license is the one
  the upstream project publishes.
- **to verify**: no license statement was found in the files; check upstream
  before a release.

## Vendored items

| Item | Path | License (SPDX) | Status | Source |
|---|---|---|---|---|
| Mozilla CA certificate bundle (curl `cacert.pem`, Mozilla data as of 2026-05-14) | `mailserver/internal/smime/cacert.pem`, `server-rust/crates/protocols/smtp/src/inbound/cacert.pem` | MPL-2.0 | upstream | https://curl.se/docs/caextract.html (from Mozilla NSS `certdata.txt`) |
| Excalidraw 0.18.1 (npm package, built into the webmail bundle; only its fonts are vendored) | `mailserver/webmail/package.json` dependency | MIT | in tree (npm `package.json`) | https://github.com/excalidraw/excalidraw |
| Assistant font (4 files) | `mailserver/webmail/static/excalidraw/fonts/Assistant/` | OFL-1.1 | in tree | https://github.com/hafontia/Assistant |
| Cascadia Code font (1 file) | `mailserver/webmail/static/excalidraw/fonts/Cascadia/` | OFL-1.1 | in tree | https://github.com/microsoft/cascadia-code |
| Comic Shanns font (4 files) | `mailserver/webmail/static/excalidraw/fonts/ComicShanns/` | MIT | in tree | https://github.com/shannpersand/comic-shanns (modified version shipped by Excalidraw) |
| Excalifont font (7 files) | `mailserver/webmail/static/excalidraw/fonts/Excalifont/` | OFL-1.1 (expected) | to verify | https://github.com/excalidraw/excalifont |
| Setjoin Sans Fallback font (1 file): modified Latin subset of Liberation Sans 2.1.5, converted to woff2 and renamed per the OFL Reserved Font Name clause | `mailserver/webmail/static/excalidraw/fonts/Liberation/` | OFL-1.1 | in tree (font name table, and the full upstream notice below) | https://github.com/liberationfonts/liberation-fonts (tag 2.1.5) |
| Lilita One font (2 files) | `mailserver/webmail/static/excalidraw/fonts/Lilita/` | OFL-1.1 | in tree | https://fonts.google.com/specimen/Lilita+One |
| Nunito font (5 files) | `mailserver/webmail/static/excalidraw/fonts/Nunito/` | OFL-1.1 | in tree | https://github.com/googlefonts/nunito |
| Virgil font (1 file) | `mailserver/webmail/static/excalidraw/fonts/Virgil/` | OFL-1.1 | in tree | https://github.com/excalidraw/virgil |
| Xiaolai SC font (209 files) | `mailserver/webmail/static/excalidraw/fonts/Xiaolai/` | OFL-1.1 (expected) | to verify | https://github.com/lxgw/kose-font |
| IBM Plex Sans and IBM Plex Mono (9 files) | `mailserver/webmail/static/fonts/ibm-plex-*.woff2`, `mailserver/api/ibm-plex-sans-*.woff2` | OFL-1.1 | in tree (`mailserver/webmail/static/fonts/IBM-PLEX-OFL.txt`) | https://github.com/IBM/plex |
| Noto Sans SC 2.004 (4 source files, 36 generated shards) | `mailserver/webmail/assets/fonts/source/`, `mailserver/webmail/static/fonts/noto-sans-sc-*.woff2` | OFL-1.1 | in tree (`mailserver/webmail/assets/fonts/source/NOTICE.md`) | https://github.com/notofonts/noto-cjk |
| Redoc 2.5.3 standalone bundle | `mailserver/api/redoc.standalone.js` | MIT (bundled components listed in the license file) | in tree (`mailserver/api/redoc.standalone.js.LICENSE.txt`) | https://github.com/Redocly/redoc |
| IETF RFCs (58 unmodified texts) | `docs/ref/rfc/*.txt`, `docs/ref/rfcs/*.txt` | LicenseRef-IETF-Trust-Legal-Provisions | in tree (each file carries its notice) | https://www.rfc-editor.org/ |
| OpenHarmony docs, curated English security-kit subset at upstream commit `ea48936`, images removed | `clients/harmonyos/refs/openharmony-docs/` | CC-BY-4.0 (expected) | to verify | https://gitcode.com/openharmony/docs |
| rust-security-framework at `df2c535` (reference copy) | `clients/rust/refs/ios-security-framework/` | MIT OR Apache-2.0 | in tree (`Cargo.toml`) | https://github.com/kornelski/rust-security-framework |
| tauri-plugin-biometric 2.3.2 (reference copy) | `clients/rust/refs/tauri-plugin-biometric/` | MIT OR Apache-2.0 (expected) | to verify | https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/biometric |

## Copyright notices

- Excalidraw: Copyright (c) 2020 Excalidraw
- Assistant: Copyright 2020 The Assistant Project Authors (https://github.com/hafontia/Assistant); Copyright 2010 The Source Sans Pro Authors
- Cascadia Code: Copyright (c) Microsoft Corporation (to verify)
- Comic Shanns: Copyright (c) 2018 Shannon Miwa; Copyright (c) 2023 Jesus Gonzalez; Copyright (c) 2023 Rodrigo Batista de Moraes
- Excalifont: Copyright (c) 2024 by Excalidraw
- Setjoin Sans Fallback (derived from Liberation Sans 2.1.5): Digitized data copyright (c) 2010 Google Corporation, with Reserved Font Arimo, Tinos and Cousine; Copyright (c) 2012 Red Hat, Inc., with Reserved Font Name Liberation
- Lilita One: Copyright (c) 2011 Juan Montoreano
- Nunito: Copyright 2014 The Nunito Project Authors (https://github.com/googlefonts/nunito)
- Virgil: Copyright (c) 2011 by Your Own Font Foundry
- Xiaolai SC: Copyright (c) 2020 LXGW
- IBM Plex: Copyright (c) 2017 IBM Corp. with Reserved Font Name "Plex"
- Noto Sans SC: Copyright (c) 2014-2021 Adobe (http://www.adobe.com/), with Reserved Font Name 'Source'
- Redoc and its bundled components: see `mailserver/api/redoc.standalone.js.LICENSE.txt`
- IETF RFCs: Copyright (c) IETF Trust and the persons identified as the document authors (older RFCs: Copyright (C) The Internet Society)
- OpenHarmony docs: Copyright (c) OpenHarmony contributors
- rust-security-framework: Copyright (c) Steven Fackler and contributors (to verify)
- tauri-plugin-biometric: Copyright (c) Tauri Programme within The Commons Conservancy (to verify)

## MIT License

Applies, each with its copyright notice above, to Excalidraw, Comic Shanns,
and the two Rust reference copies (MIT option of their MIT OR Apache-2.0
dual license).

```
MIT License

Copyright (c) 2020 Excalidraw

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## SIL Open Font License 1.1

The full license text ships in this repository at
`mailserver/webmail/static/fonts/IBM-PLEX-OFL.txt` (lines 8-93) and in
`mailserver/webmail/assets/fonts/source/NOTICE.md`. It is also available at
https://openfontlicense.org. It applies to every font marked OFL-1.1 above,
each with its own copyright notice and Reserved Font Names.

## Mozilla Public License 2.0

Both `cacert.pem` copies are unmodified Source Code Form files:

> This Source Code Form is subject to the terms of the Mozilla Public License,
> v. 2.0. If a copy of the MPL was not distributed with this file, You can
> obtain one at https://mozilla.org/MPL/2.0/.

## IETF RFCs

The RFC texts are reproduced in full and unmodified, under the IETF Trust
Legal Provisions (https://trustee.ietf.org/license-info). Each file keeps its
original copyright notice.

## OpenHarmony documentation (CC-BY-4.0)

`clients/harmonyos/refs/openharmony-docs/` contains excerpts from the
OpenHarmony documentation (https://gitcode.com/openharmony/docs, commit
`ea48936`), licensed under the Creative Commons Attribution 4.0 International
License (https://creativecommons.org/licenses/by/4.0/). Changes: only the
English `application-dev` security kits and their API references are kept,
and all images were removed.

## Dependencies fetched at build time (not vendored)

Go modules (`*/go.mod`, `go.sum`), npm packages (`package-lock.json` files)
and Rust crates (`Cargo.lock` files) are downloaded at build time and are not
part of this repository. Their licenses are permissive or file-level
copyleft. Those under MPL-2.0 are:

- Go: github.com/hashicorp/errwrap, go-cleanhttp, go-multierror,
  go-retryablehttp, go-uuid
- npm: lightningcss, dompurify (MPL-2.0 OR Apache-2.0), axe-core (development
  only)
- Rust: cssparser-macros, dtoa-short, option-ext (desktop client), plus any
  crate `cargo deny list` reports for `server-rust/`

Two npm packages use WTFPL: truncate-utf8-bytes and sanitize-filename.
Binary releases must ship a generated notice file for these dependencies.

## Setjoin Sans Fallback (modified Liberation Sans 2.1.5)

`mailserver/webmail/static/excalidraw/fonts/Liberation/LiberationSans-Regular.woff2` is a
**modified version** of Liberation Sans 2.1.5: a Latin subset of the upstream TTF,
converted to woff2. The SIL Open Font License 1.1 reserves the font name "Liberation"
for the copyright holder, so a modified version may not use it. The font family is
therefore renamed "Setjoin Sans Fallback" (PostScript name `SetjoinSansFallback-Regular`);
the copyright and license name records are unchanged and no name record contains the
Reserved Font Name. The file path is kept only so the vendored package's font URL still
resolves. The font remains under the OFL 1.1; it is not sold by itself, and this renamed
subset is not endorsed by Red Hat, Inc. or Google. The complete upstream notice follows
verbatim (liberation-fonts tag 2.1.5, file `LICENSE`).

```text
Digitized data copyright (c) 2010 Google Corporation
	with Reserved Font Arimo, Tinos and Cousine.
Copyright (c) 2012 Red Hat, Inc.
	with Reserved Font Name Liberation.

This Font Software is licensed under the SIL Open Font License,
Version 1.1.

This license is copied below, and is also available with a FAQ at:
http://scripts.sil.org/OFL

SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007

PREAMBLE The goals of the Open Font License (OFL) are to stimulate
worldwide development of collaborative font projects, to support the font
creation efforts of academic and linguistic communities, and to provide
a free and open framework in which fonts may be shared and improved in
partnership with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves.
The fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works.  The fonts and derivatives,
however, cannot be released under any other type of license.  The
requirement for fonts to remain under this license does not apply to
any document created using the fonts or their derivatives.

 

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such.
This may include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components
as distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting ? in part or in whole ?
any of the components of the Original Version, by changing formats or
by porting the Font Software to a new environment.

"Author" refers to any designer, engineer, programmer, technical writer
or other person who contributed to the Font Software.


PERMISSION & CONDITIONS

Permission is hereby granted, free of charge, to any person obtaining a
copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,in
   Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
   redistributed and/or sold with any software, provided that each copy
   contains the above copyright notice and this license. These can be
   included either as stand-alone text files, human-readable headers or
   in the appropriate machine-readable metadata fields within text or
   binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
   Name(s) unless explicit written permission is granted by the
   corresponding Copyright Holder. This restriction only applies to the
   primary font name as presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
   Software shall not be used to promote, endorse or advertise any
   Modified Version, except to acknowledge the contribution(s) of the
   Copyright Holder(s) and the Author(s) or with their explicit written
   permission.

5) The Font Software, modified or unmodified, in part or in whole, must
   be distributed entirely under this license, and must not be distributed
   under any other license. The requirement for fonts to remain under
   this license does not apply to any document created using the Font
   Software.


 
TERMINATION
This license becomes null and void if any of the above conditions are not met.

 

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT.  IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM OTHER
DEALINGS IN THE FONT SOFTWARE.
```
