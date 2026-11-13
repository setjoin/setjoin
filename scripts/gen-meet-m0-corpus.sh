#!/usr/bin/env bash
# MEET M0 producer/format corpus + bandwidth benchmark fixture generator
# (MEET plan retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-
# semantic-recording.md, M0 "Freeze a producer/format corpus and bandwidth
# benchmark fixtures"; owner decision D3 in
# retired-docs:verification/2026-09-19-owner-consolidated-decisions.md).
#
# Modes:
#   scripts/gen-meet-m0-corpus.sh          # regenerate the synthetic-seed
#                                         # corpus (byte-deterministic)
#   scripts/gen-meet-m0-corpus.sh verify   # recompute digests/counts and
#                                         # compare against the frozen
#                                         # docs/verification/meet-m0-corpus.json
#   scripts/gen-meet-m0-corpus.sh acquire  # stage the five producer-pinned
#                                         # conversions through the pinned
#                                         # LibreOffice engine (SOFFICE env
#                                         # var or PATH), into a STAGING dir
#                                         # (never the corpus dir); prints a
#                                         # digest/size/count fragment for the
#                                         # manifest update + dated receipt.
#                                         # This is the linux-ci-host
#                                         # re-qualification procedure.
#
# Properties:
#   - Deterministic: no timestamps, no randomness beyond shake_256 streams
#     keyed by fixed seeds, sorted/fixed zip metadata. A re-run on the same
#     inputs reproduces byte-identical files (the frozen manifest pins the
#     digests, so drift is caught by `verify` and by the Go test).
#   - No network, no third-party dependencies: bash + python3 stdlib only.
#   - These files are SYNTHETIC SEEDS (bandwidth/structure benchmarking and
#     LibreOffice conversion INPUTS). They are never passable as
#     producer-pinned evidence; producer-pinned corpus entries are generated
#     by the pinned LibreOffice engine per D3 and are acquisition-pending in
#     docs/verification/meet-m0-corpus.json until that capture happens.

source "$(dirname "$0")/_base.sh"

MODE="${1:-gen}"
CORPUS_DIR="$ROOT/mailserver/internal/meet/presentation/testdata/corpus"
MANIFEST="$ROOT/docs/verification/meet-m0-corpus.json"

if ! command -v python3 >/dev/null 2>&1; then
  echo "gen-meet-m0-corpus: python3 is required (stdlib only, no pip deps)" >&2
  exit 1
fi

exec python3 - "$MODE" "$CORPUS_DIR" "$MANIFEST" <<'PY'
import hashlib
import io
import json
import os
import sys
import zipfile
import zlib

MODE, CORPUS_DIR, MANIFEST = sys.argv[1], sys.argv[2], sys.argv[3]

# ---------------------------------------------------------------------------
# Deterministic primitives
# ---------------------------------------------------------------------------

def stream(seed, n):
    """n deterministic bytes keyed by seed (shake_256 XOF; stable across
    Python versions and platforms; no global RNG state)."""
    return hashlib.shake_256(seed.encode("utf-8")).digest(n)

WORDS = ("setjoin meet corpus page deck fixture bandwidth rendition "
         "prefetch manifest caption annotation notes slide sheet buffer "
         "anchor launch lane tenant digest entity oracle margin".split())

def filler_text(seed, words):
    """Deterministic pseudo-prose for a given seed."""
    raw = stream(seed, words * 2)
    picks = [WORDS[(raw[i] * 256 + raw[i + 1]) % len(WORDS)] for i in range(0, words * 2, 2)]
    return " ".join(picks)

# ---------------------------------------------------------------------------
# Minimal deterministic PDF writer (PDF 1.4, no dates, no IDs)
# ---------------------------------------------------------------------------

def pdf_escape(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

class PDFBuilder:
    def __init__(self):
        self.objects = []  # (body_bytes, stream_bytes or None)

    def add(self, body, stream=None):
        self.objects.append((body, stream))
        return len(self.objects)  # 1-based object number

    def stream_obj(self, dict_extra, data):
        body = dict_extra + b" /Length " + str(len(data)).encode() + b" >>"
        return self.add(body, data)

    def build(self, root):
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0] * (len(self.objects) + 1)
        for i, (body, sdata) in enumerate(self.objects, start=1):
            offsets[i] = out.tell()
            out.write(str(i).encode() + b" 0 obj\n" + body)
            if sdata is not None:
                out.write(b"\nstream\n" + sdata + b"\nendstream")
            out.write(b"\nendobj\n")
        xref_at = out.tell()
        out.write(b"xref\n0 " + str(len(self.objects) + 1).encode() + b"\n")
        out.write(b"0000000000 65535 f \n")
        for i in range(1, len(self.objects) + 1):
            out.write(("%010d 00000 n \n" % offsets[i]).encode())
        out.write(b"trailer\n<< /Size " + str(len(self.objects) + 1).encode() +
                  b" /Root " + str(root).encode() + b" 0 R >>\nstartxref\n" +
                  str(xref_at).encode() + b"\n%%EOF\n")
        return out.getvalue()

def make_pdf(slug, pages, page_text_lines, annots_per_page=0, image_maker=None, image_w=1024, image_h=1024):
    """One flat page tree; each page draws its text lines and optionally one
    full-page incompressible image (image_maker(p) -> raw RGB bytes, one
    distinct object per page); optional /FreeText annots per page."""
    b = PDFBuilder()
    font = b.add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    # Object 2 is the /Pages tree; page dicts hardcode /Parent 2 0 R. It is
    # added as a placeholder now and its real body is patched in once the
    # page object ids are known.
    b.add(b"<< /Type /Pages >>")

    page_ids, annot_ids = [], []
    for p in range(pages):
        annot_refs_this_page = []
        image_ref = None
        if image_maker is not None:
            image_ref = b.stream_obj(
                b"<< /Type /XObject /Subtype /Image /Width " + str(image_w).encode() +
                b" /Height " + str(image_h).encode() +
                b" /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode",
                zlib.compress(image_maker(p), 6))
        for a in range(annots_per_page):
            note = ("MEET M0 synthetic annotation p%d #%d %s"
                    % (p + 1, a + 1, filler_text("%s/annot/%d/%d" % (slug, p, a), 8))).encode()
            annot_ids.append(b.add(
                b"<< /Type /Annot /Subtype /FreeText /F 4 /Rect [306 " +
                str(760 - (a % 20) * 18).encode() + b" 552 " +
                str(748 - (a % 20) * 18).encode() + b"] /Contents (" +
                pdf_escape(note.decode()).encode() + b") >>"))
            annot_refs_this_page.append(annot_ids[-1])

        lines = [ln.replace("{PAGE}", str(p + 1)).replace("{PAGES}", str(pages))
                 for ln in page_text_lines]
        lines.append(filler_text("%s/page/%d" % (slug, p), 24))
        content = io.BytesIO()
        content.write(b"BT /F1 20 Tf 54 760 Td (MEET M0 synthetic seed: " +
                      pdf_escape(slug).encode() + b") Tj ET\n")
        y = 728
        for ln in lines:
            content.write(b"BT /F1 11 Tf 54 " + str(y).encode() + b" Td (" +
                          pdf_escape(ln).encode() + b") Tj ET\n")
            y -= 16
        if image_ref is not None:
            content.write(b"q 504 0 0 648 54 72 cm /Im1 Do Q\n")
        cid = b.stream_obj(b"<<", content.getvalue())

        page_dict = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                     b"/Resources << /Font << /F1 " + str(font).encode() +
                     b" 0 R >>")
        if image_ref is not None:
            page_dict += (b" /XObject << /Im1 " + str(image_ref).encode() + b" 0 R >>")
        page_dict += b" >> /Contents " + str(cid).encode() + b" 0 R"
        if annot_refs_this_page:
            page_dict += b" /Annots [" + b" ".join(
                str(r).encode() + b" 0 R" for r in annot_refs_this_page) + b"]"
        page_dict += b" >>"
        page_ids.append(b.add(page_dict))

    kids = b"[" + b" ".join(str(i).encode() + b" 0 R" for i in page_ids) + b"]"
    b.objects[1] = (b"<< /Type /Pages /Count " + str(pages).encode() +
                    b" /Kids " + kids + b" >>", None)
    catalog = b.add(b"<< /Type /Catalog /Pages 2 0 R >>")
    return b.build(root=catalog)

# ---------------------------------------------------------------------------
# Minimal deterministic OOXML / ODF writers
# ---------------------------------------------------------------------------

def make_zip(items):
    """items: list of (arcname, data_bytes, stored_bool). Fixed 1980-01-01
    timestamps and fixed attrs keep the archive byte-deterministic."""
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    for name, data, stored in items:
        zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
        zi.external_attr = 0o644 << 16
        zf.writestr(zi, data)
    zf.close()
    return buf.getvalue()

CT_XML = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '{overrides}</Types>')

RELS_ROOT = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{doc}"/>'
             '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
             '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
             '</Relationships>')

CORE_XML = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>MEET M0 synthetic seed '
            '{title}</dc:title><dc:creator>setjoin gen-meet-m0-corpus</dc:creator></cp:coreProperties>')

def make_pptx(slug, slides):
    slide_cts = "".join(
        '<Override PartName="/ppt/slides/slide%d.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        '<Override PartName="/ppt/notesSlides/notesSlide%d.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>' % (i, i)
        for i in range(1, slides + 1))
    ct = CT_XML.format(overrides=slide_cts +
                       '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
                       '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                       '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>')

    sld_ids = "".join('<p:sldId id="%d" r:id="rId%d"/>' % (255 + i, i + 1)
                      for i in range(1, slides + 1))
    pres = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
            'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
            '<p:sldIdLst>' + sld_ids + '</p:sldIdLst>'
            '<p:sldSz cx="12192000" cy="6858000"/>'
            '</p:presentation>')

    # The slideMaster relationship MUST be FIRST in presentation.xml.rels
    # (rId1): measured on the D3 pinned producer (LibreOffice 26.8.0.3,
    # 2026-09-20 qualification run), a trailing master relationship makes its
    # pptx import consume the first SLIDE relationship for the master —
    # slide 1's content is dropped, every slide shifts one page early, and a
    # blank trailing page appears. Master-first matches what real producers
    # emit and imports faithfully.
    pres_rels_items = ('<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>')
    pres_rels_items += "".join(
        '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide%d.xml"/>' % (i + 1, i)
        for i in range(1, slides + 1))
    pres_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 + pres_rels_items + '</Relationships>')

    def slide_xml(i):
        body = filler_text("%s/pptx/slide/%d" % (slug, i), 18)
        # Shapes carry explicit geometry (a:xfrm) and run color/size: a
        # synthetic slide with an EMPTY spPr is dropped entirely by the
        # LibreOffice Impress import (the D3 producer) — its text never
        # reaches the pinned PDF. Measured 2026-09-20 (renderer-qualification
        # run): empty-spPr slides produced all-blank PDF pages in BOTH paging
        # primitives, i.e. the producer emitted nothing to render.
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                '<p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/>'
                '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Title %d"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>'
                '<p:spPr><a:xfrm><a:off x="838200" y="609600"/><a:ext cx="10515600" cy="1371600"/></a:xfrm></p:spPr>'
                '<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US" sz="2800" b="1"><a:solidFill><a:srgbClr val="1A1A1A"/></a:solidFill></a:rPr><a:t>MEET M0 synthetic seed slide %d of %d</a:t></a:r></a:p></p:txBody></p:sp>'
                '<p:sp><p:nvSpPr><p:cNvPr id="3" name="Body %d"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>'
                '<p:spPr><a:xfrm><a:off x="838200" y="2286000"/><a:ext cx="10515600" cy="3886200"/></a:xfrm></p:spPr>'
                '<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US" sz="1800"><a:solidFill><a:srgbClr val="1A1A1A"/></a:solidFill></a:rPr><a:t>%s</a:t></a:r></a:p></p:txBody></p:sp>'
                '</p:spTree></p:cSld></p:sld>') % (i, i, slides, i, body)

    def notes_xml(i):
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                '<p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/>'
                '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Notes Placeholder %d"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>'
                '<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>PROTECTED synthetic speaker note %d: %s</a:t></a:r></a:p></p:txBody></p:sp>'
                '</p:spTree></p:cSld></p:notes>') % (i, i, filler_text("%s/pptx/notes/%d" % (slug, i), 24))

    master = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
              '<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
              'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
              'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
              '<p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/></p:spTree></p:cSld>'
              '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
              '<p:sldLayoutIdLst/></p:sldMaster>')

    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
           'xmlns:ep="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           '<Application>setjoin gen-meet-m0-corpus (synthetic)</Application><Slides>%d</Slides></Properties>') % slides

    items = [("[Content_Types].xml", ct.encode(), False),
             ("_rels/.rels", RELS_ROOT.format(doc="ppt/presentation.xml").encode(), False),
             ("docProps/core.xml", CORE_XML.format(title=slug).encode(), False),
             ("docProps/app.xml", app.encode(), False),
             ("ppt/presentation.xml", pres.encode(), False),
             ("ppt/_rels/presentation.xml.rels", pres_rels.encode(), False),
             ("ppt/slideMasters/slideMaster1.xml", master.encode(), False)]
    for i in range(1, slides + 1):
        items.append(("ppt/slides/slide%d.xml" % i, slide_xml(i).encode(), False))
        items.append(("ppt/slides/_rels/slide%d.xml.rels" % i,
                      ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
                       '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../notesSlides/notesSlide%d.xml"/>'
                       '</Relationships>') % i, False))
        items.append(("ppt/notesSlides/notesSlide%d.xml" % i, notes_xml(i).encode(), False))
        items.append(("ppt/notesSlides/_rels/notesSlide%d.xml.rels" % i,
                      ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="../slides/slide%d.xml"/>'
                       '</Relationships>') % i, False))
    items.append(("ppt/slideLayouts/slideLayout1.xml",
                  ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                   '<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                   'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">'
                   '<p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/></p:spTree></p:cSld></p:sldLayout>').encode(), False))
    return make_zip(items)

def make_docx(slug, declared_pages):
    body_paras = "".join(
        '<w:p><w:r><w:t>MEET M0 synthetic seed, declared page %d of %d: %s</w:t></w:r></w:p>'
        '<w:p><w:r><w:br w:type="page"/></w:r></w:p>' % (i, declared_pages,
        filler_text("%s/docx/%d" % (slug, i), 16))
        for i in range(1, declared_pages + 1))
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body>' + body_paras +
           '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr></w:body></w:document>')
    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           '<Application>setjoin gen-meet-m0-corpus (synthetic)</Application>'
           '<Pages>%d</Pages><Words>%d</Words></Properties>') % (
        declared_pages, declared_pages * 20)
    ct = CT_XML.format(overrides=
                       '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                       '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                       '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>')
    items = [("[Content_Types].xml", ct.encode(), False),
             ("_rels/.rels", RELS_ROOT.format(doc="word/document.xml").encode(), False),
             ("docProps/core.xml", CORE_XML.format(title=slug).encode(), False),
             ("docProps/app.xml", app.encode(), False),
             ("word/document.xml", doc.encode(), False)]
    return make_zip(items)

def make_xlsx(slug, sheets):
    sheet_cts = "".join(
        '<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % i
        for i in range(1, sheets + 1))
    ct = CT_XML.format(overrides=sheet_cts +
                       '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                       '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                       '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>')
    sheet_entries = "".join(
        '<sheet name="Seed %d" sheetId="%d" r:id="rId%d"/>' % (i, i, i)
        for i in range(1, sheets + 1))
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets>' + sheet_entries + '</sheets></workbook>')
    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i, i)
                         for i in range(1, sheets + 1)) +
               '</Relationships>')

    def sheet_xml(i):
        rows = ""
        for r in range(1, 41):
            cells = ('<c r="A%d" t="inlineStr"><is><t>MEET M0 synthetic seed sheet %d row %d: %s</t></is></c>'
                     % (r, i, r, filler_text("%s/xlsx/%d/%d" % (slug, i, r), 8)))
            rows += '<row r="%d">%s</row>' % (r, cells)
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheetData>' + rows + '</sheetData></worksheet>')

    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           '<Application>setjoin gen-meet-m0-corpus (synthetic)</Application></Properties>')
    items = [("[Content_Types].xml", ct.encode(), False),
             ("_rels/.rels", RELS_ROOT.format(doc="xl/workbook.xml").encode(), False),
             ("docProps/core.xml", CORE_XML.format(title=slug).encode(), False),
             ("docProps/app.xml", app.encode(), False),
             ("xl/workbook.xml", wb.encode(), False),
             ("xl/_rels/workbook.xml.rels", wb_rels.encode(), False)]
    for i in range(1, sheets + 1):
        items.append(("xl/worksheets/sheet%d.xml" % i, sheet_xml(i).encode(), False))
    return make_zip(items)

def make_odp(slug, slides):
    pages = "".join(
        '<draw:page draw:name="page%d">'
        '<draw:frame svg:width="22cm" svg:height="3cm" svg:x="2cm" svg:y="2cm">'
        '<draw:text-box><text:p>MEET M0 synthetic seed slide %d of %d</text:p></draw:text-box></draw:frame>'
        '<draw:frame svg:width="22cm" svg:height="10cm" svg:x="2cm" svg:y="6cm">'
        '<draw:text-box><text:p>%s</text:p></draw:text-box></draw:frame>'
        '</draw:page>' % (i, i, slides, filler_text("%s/odp/%d" % (slug, i), 20))
        for i in range(1, slides + 1))
    content = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               '<office:document-content '
               'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
               'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
               'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
               'xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" '
               'office:version="1.2"><office:body><office:presentation>'
               + pages + '</office:presentation></office:body></office:document-content>')
    styles = ('<?xml version="1.0" encoding="UTF-8"?>\n'
              '<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
              'office:version="1.2"><office:styles/></office:document-styles>')
    manifest = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
                'manifest:version="1.2">'
                '<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.presentation"/>'
                '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
                '<manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>'
                '</manifest:manifest>')
    items = [("mimetype", b"application/vnd.oasis.opendocument.presentation", True),
             ("META-INF/manifest.xml", manifest.encode(), False),
             ("content.xml", content.encode(), False),
             ("styles.xml", styles.encode(), False)]
    return make_zip(items)

def make_vtt(slug, cues):
    out = ["WEBVTT - MEET M0 synthetic caption seed %s" % slug, ""]
    ms = 0
    for i in range(1, cues + 1):
        start = ms
        end = ms + 3000
        h, rem = divmod(start, 3600000)
        m, rem = divmod(rem, 60000)
        s, milli = divmod(rem, 1000)
        h2, rem2 = divmod(end, 3600000)
        m2, rem2 = divmod(rem2, 60000)
        s2, milli2 = divmod(rem2, 1000)
        out.append("cue-%06d" % i)
        out.append("%02d:%02d:%02d.%03d --> %02d:%02d:%02d.%03d" % (h, m, s, milli, h2, m2, s2, milli2))
        out.append("Caption cue %d of %d: %s" % (i, cues, filler_text("%s/vtt/%d" % (slug, i), 10)))
        out.append("")
        ms += 2500
    return ("\n".join(out)).encode()

# ---------------------------------------------------------------------------
# Corpus definition
# ---------------------------------------------------------------------------

IMG_BYTES = 1024 * 1024 * 3  # 3 MiB incompressible (random) RGB per page

def build_all():
    files = {}
    files["m0corpus-pdf-small-deck.pdf"] = make_pdf(
        "small-deck", 10,
        ["Synthetic small deck, page {PAGE} of {PAGES} (10-page reference start cell)."])
    files["m0corpus-pdf-medium-deck.pdf"] = make_pdf(
        "medium-deck", 50,
        ["Synthetic medium deck, page {PAGE} of {PAGES} (prefetch window cell)."])
    files["m0corpus-pdf-large-500p.pdf"] = make_pdf(
        "large-500p", 500,
        ["Synthetic large deck, page {PAGE} of {PAGES} (500-page manifest cell)."])
    # 9 pages, each its own 3 MiB incompressible page asset ~= 28.3 MiB
    # aggregate, which crosses the 24 MiB encoded-client-assets cap
    # (rendition.go MaxEncodedClientAssetsBytes) while each page stays under
    # the 16 MiB per-encoded-page ceiling (MaxEncodedPageBytes).
    files["m0corpus-pdf-asset-heavy-9x3mib.pdf"] = make_pdf(
        "asset-heavy-9x3mib", 9,
        ["Asset-heavy page {PAGE} of {PAGES}: one incompressible 3 MiB page asset."],
        image_maker=lambda p: stream("m0corpus/image/%d" % p, IMG_BYTES))
    files["m0corpus-pdf-annotation-heavy-ref20.pdf"] = make_pdf(
        "annotation-heavy-ref20", 20,
        ["Synthetic annotation-heavy 20-page reference-deck shape, page {PAGE} of {PAGES}."],
        annots_per_page=40)
    files["m0corpus-pptx-reference20.pptx"] = make_pptx("pptx-reference20", 20)
    files["m0corpus-docx-paged12.docx"] = make_docx("docx-paged12", 12)
    files["m0corpus-xlsx-sheets3.xlsx"] = make_xlsx("xlsx-sheets3", 3)
    files["m0corpus-odp-slides10.odp"] = make_odp("odp-slides10", 10)
    files["m0corpus-vtt-caption-dense-5000.vtt"] = make_vtt("vtt-caption-dense", 5000)
    return files

# Intrinsic count measurers (mirrored in Go by corpus_manifest.go; the two
# implementations must agree — the frozen manifest and the Go test pin it).
def measure(format_, data):
    if format_ == "pdf":
        # Synthetic seeds write "/Type /Page" (spaced); LibreOffice — the D3
        # pinned producer — writes "/Type/Page" (unspaced). Count both
        # spellings, subtracting the page-tree token ("/Type/Pages") per
        # spelling because it contains the page token as a prefix. Mirrored
        # by MeasureM0CorpusCount in corpus_manifest.go; the two must agree.
        return ((data.count(b"/Type /Page") - data.count(b"/Type /Pages")) +
                (data.count(b"/Type/Page") - data.count(b"/Type/Pages")))
    if format_ in ("pptx", "xlsx"):
        prefix = {"pptx": "ppt/slides/slide", "xlsx": "xl/worksheets/sheet"}[format_]
        zf = zipfile.ZipFile(io.BytesIO(data))
        return sum(1 for n in zf.namelist()
                   if n.startswith(prefix) and n.endswith(".xml") and "/_rels/" not in n)
    if format_ == "odp":
        zf = zipfile.ZipFile(io.BytesIO(data))
        return zf.read("content.xml").decode().count("<draw:page ")
    if format_ == "docx":
        zf = zipfile.ZipFile(io.BytesIO(data))
        app = zf.read("docProps/app.xml").decode()
        start = app.index("<Pages>") + len("<Pages>")
        return int(app[start:app.index("</Pages>", start)])
    if format_ == "vtt":
        return sum(1 for ln in data.decode().splitlines() if "-->" in ln)
    raise ValueError("unknown format " + format_)

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def fragment(files):
    entries = []
    for name in sorted(files):
        data = files[name]
        fmt = {"m0corpus-pdf": "pdf", "m0corpus-pptx": "pptx", "m0corpus-docx": "docx",
               "m0corpus-xlsx": "xlsx", "m0corpus-odp": "odp", "m0corpus-vtt": "vtt"}[
            "-".join(name.split("-")[:2])]
        entries.append({
            "file": name,
            "format": fmt,
            "byteSize": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "countKind": {"pdf": "pages", "pptx": "slides", "docx": "declared-pages",
                          "xlsx": "sheets", "odp": "slides", "vtt": "cues"}[fmt],
            "count": measure(fmt, data),
        })
    return {"schemaVersion": "setjoin.meet.m0-corpus/1", "kind": "generated-fragment",
            "entries": entries}

if MODE == "gen":
    os.makedirs(CORPUS_DIR, exist_ok=True)
    files = build_all()
    for name, data in sorted(files.items()):
        with open(os.path.join(CORPUS_DIR, name), "wb") as f:
            f.write(data)
    print(json.dumps(fragment(files), indent=2, sort_keys=True))
elif MODE == "acquire":
    # Stage the producer-pinned conversions through the pinned engine. The
    # bytes are a SINGLE CAPTURE pinned by digest at acquisition: they are
    # written to a staging directory, never over the frozen corpus rows (a
    # re-capture re-pins digests via the manifest + a dated receipt).
    soffice = os.environ.get("SOFFICE") or "soffice"
    staging = os.path.join(CORPUS_DIR, "..", "corpus-acquire-staging")
    staging = os.path.normpath(staging)
    os.makedirs(staging, exist_ok=True)
    import subprocess

    with open(MANIFEST, "r", encoding="utf-8") as f:
        frozen = json.load(f)
    staged = {}
    for entry in frozen["entries"]:
        if entry.get("class") != "producer-pinned":
            continue
        target = entry["format"]  # 'pdf' or 'odp'
        src = os.path.join(CORPUS_DIR, entry["sourceEntry"])
        if not os.path.exists(src):
            print("acquire: missing seed input %s" % src, file=sys.stderr)
            sys.exit(1)
        cmd = [soffice, "--headless", "--norestore",
               "--convert-to", target, "--outdir", staging, src]
        subprocess.run(cmd, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stem = os.path.splitext(entry["sourceEntry"])[0]
        produced = os.path.join(staging, stem + "." + target)
        if not os.path.exists(produced):
            print("acquire: engine produced no %s for %s" % (target, src),
                  file=sys.stderr)
            sys.exit(1)
        staged[entry["file"]] = produced
    entries = []
    for name in sorted(staged):
        with open(staged[name], "rb") as f:
            data = f.read()
        fmt = "pdf" if name.endswith(".pdf") else "odp"
        entries.append({
            "file": name,
            "format": fmt,
            "byteSize": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "countKind": "pages" if fmt == "pdf" else "slides",
            "count": measure(fmt, data),
        })
    print(json.dumps({"schemaVersion": "setjoin.meet.m0-corpus/1",
                      "kind": "acquired-producer-fragment",
                      "stagingDir": staging,
                      "engineVersion": subprocess.run(
                          [soffice, "--version"], check=True,
                          capture_output=True, text=True).stdout.strip(),
                      "entries": entries}, indent=2, sort_keys=True))
elif MODE == "verify":
    files = {}
    for name in sorted(os.listdir(CORPUS_DIR)):
        with open(os.path.join(CORPUS_DIR, name), "rb") as f:
            files[name] = f.read()
    recomputed = {e["file"]: e for e in fragment(files)["entries"]}
    with open(MANIFEST, "r", encoding="utf-8") as f:
        frozen = json.load(f)
    failures = []
    claimed = set()
    for entry in frozen["entries"]:
        name = entry["file"]
        claimed.add(name)
        if entry.get("class") == "producer-pinned" and entry.get("status") == "acquisition-pending":
            # Acquisition-pending: bytes must NOT exist; a synthetic seed or
            # hand-made file parked under the pinned name is fabrication.
            # FROZEN producer-pinned entries (post-acquisition) fall through
            # and are digest/size/count-verified like every other row.
            if name in recomputed:
                failures.append("producer-pinned entry %s has bytes on disk (fabrication)" % name)
            continue
        got = recomputed.get(name)
        if got is None:
            failures.append("manifest entry %s missing from corpus dir" % name)
            continue
        for field in ("byteSize", "sha256", "countKind", "count", "format"):
            if got[field] != entry.get(field):
                failures.append("%s: %s drifted (frozen %r, actual %r)"
                                % (name, field, entry.get(field), got[field]))
    extra = set(recomputed) - claimed
    if extra:
        failures.append("unmanifested files in corpus dir: %s" % sorted(extra))
    if failures:
        print("gen-meet-m0-corpus verify: FAILED")
        for f_ in failures:
            print("  - " + f_)
        sys.exit(1)
    print("gen-meet-m0-corpus verify: OK (%d frozen entries verified)" % len(claimed))
else:
    print("usage: gen-meet-m0-corpus.sh [gen|verify]", file=sys.stderr)
    sys.exit(2)
PY
