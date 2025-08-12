import streamlit as st
import re
import io
import csv
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional

st.set_page_config(page_title="CIS Benchmark Parser (v3)", layout="wide")

# -----------------------------
# PDF text extraction (pdfminer.six required)
# -----------------------------
def extract_lines_with_pages(pdf_bytes: bytes) -> List[Tuple[str, int]]:
    """
    Extract text per page and return as a list of (line, page_number).
    Page numbers are 1-based.
    """
    from pdfminer.high_level import extract_text
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTTextContainer, LTTextLine

    lines_with_pages: List[Tuple[str, int]] = []
    # Iterate pages to get per-page text
    page_num = 0
    for page_layout in extract_pages(io.BytesIO(pdf_bytes)):
        page_num += 1
        # Gather text lines in reading order
        page_text_chunks = []
        for element in page_layout:
            if isinstance(element, LTTextContainer):
                for text_line in element:
                    if isinstance(text_line, LTTextLine):
                        s = text_line.get_text()
                        if s:
                            page_text_chunks.append(s)
        # Join then split by lines to normalize
        page_text = "".join(page_text_chunks).replace("\r", "")
        page_text = re.sub(r"[ \t]+", " ", page_text)
        for ln in page_text.splitlines():
            lines_with_pages.append((ln.rstrip(), page_num))
    return lines_with_pages

# -----------------------------
# Patterns
# -----------------------------
HEADER_RE = re.compile(r"^(?P<num>(\d+\.)+\d+)\s+(?P<title>.+?)\s*(\(|$)")
SECTION_LABELS = ["Description", "Rationale", "Audit", "Remediation"]
LABEL_RE = re.compile(rf"^({'|'.join(SECTION_LABELS)}):?\s*$", re.IGNORECASE)
CIS_CONTROLS_MARK = re.compile(r"^\s*CIS Controls\b", re.IGNORECASE)
DESCRIPTION_LINE = re.compile(r"^\s*Description:?\s*$", re.IGNORECASE)
PAGE_NOISE = [
    re.compile(r"Center for Internet Security", re.IGNORECASE),
    re.compile(r"\bPage\s+\d+\s+of\s+\d+\b", re.IGNORECASE),
    re.compile(r"Copyright\s+©", re.IGNORECASE),
]

# -----------------------------
# Utilities (page-aware)
# -----------------------------
def strip_page_noise_lines(lines_with_pages: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Remove repeated header/footer noise; keep (line, page)."""
    out = []
    for ln, pg in lines_with_pages:
        if any(p.search(ln) for p in PAGE_NOISE):
            continue
        out.append((ln, pg))
    return out

def to_text(lines_with_pages: List[Tuple[str, int]]) -> str:
    """Utility to show as plain text (drops page numbers)."""
    return "\n".join(ln for ln, _ in lines_with_pages)

def gate_by_headings_lines(lines_with_pages: List[Tuple[str, int]], start_mark: Optional[str], end_mark: Optional[str]) -> List[Tuple[str, int]]:
    """Keep only [start_mark .. end_mark) if provided; page-aware implementation."""
    if not start_mark and not end_mark:
        return lines_with_pages
    n = len(lines_with_pages)
    start_idx = 0
    if start_mark:
        for i, (ln, _) in enumerate(lines_with_pages):
            if re.match(rf"^\s*{re.escape(start_mark)}\s*$", ln, re.IGNORECASE):
                start_idx = i
                break
    end_idx = n
    if end_mark:
        for j in range(start_idx + 1, n):
            if re.match(rf"^\s*{re.escape(end_mark)}\s*$", lines_with_pages[j][0], re.IGNORECASE):
                end_idx = j
                break
    return lines_with_pages[start_idx:end_idx]

def scrub_controls_blocks_lines(lines_with_pages: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """
    Implements the requested strategy, page-aware:
    - On 'CIS Controls': enter discard mode
    - While discarding, if 'Description' is seen -> start buffering (with pages)
    - Keep buffering until a RULE HEADER appears; then emit HEADER, then flush buffer after it
    - If another 'CIS Controls' appears before a header -> clear buffer and keep discarding
    - If EOF while discarding -> drop buffer
    """
    out: List[Tuple[str, int]] = []
    discarding = False
    buffering = False
    buffer: List[Tuple[str, int]] = []
    i = 0
    n = len(lines_with_pages)

    while i < n:
        ln, pg = lines_with_pages[i]

        if not discarding and CIS_CONTROLS_MARK.match(ln):
            discarding = True
            buffering = False
            buffer = []
            i += 1
            continue

        if discarding:
            if CIS_CONTROLS_MARK.match(ln):
                buffering = False
                buffer = []
                i += 1
                continue

            if DESCRIPTION_LINE.match(ln) and not buffering:
                buffering = True
                buffer = [(ln, pg)]
                i += 1
                continue

            if buffering and not HEADER_RE.match(ln):
                buffer.append((ln, pg))
                i += 1
                continue

            if HEADER_RE.match(ln):
                # emit header then buffered lines
                out.append((ln, pg))
                out.extend(buffer)
                discarding = False
                buffering = False
                buffer = []
                i += 1
                continue

            i += 1
            continue

        # normal mode
        out.append((ln, pg))
        i += 1

    return out

def parse_sections(body_text: str) -> Dict[str, str]:
    """Parse labeled sections inside one recommendation block from body text."""
    lines = [ln.strip() for ln in body_text.splitlines()]
    sections: Dict[str, str] = {}
    current_label = None
    buf: List[str] = []

    def flush():
        nonlocal buf, current_label
        if current_label:
            text = "\n".join(buf).strip()
            text = re.split(r"\n(?i:Default Value:|References?:)", text)[0].strip()
            sections[current_label.capitalize()] = text
        buf = []

    for ln in lines:
        m = LABEL_RE.match(ln)
        if m:
            flush()
            current_label = m.group(1)
        else:
            buf.append(ln)
    flush()
    return sections

def parse_description_anchored_lines(lines_with_pages: List[Tuple[str, int]], pdf_name: str) -> List[Dict[str, str]]:
    """
    Description-anchored parsing over (line, page) pairs.
    The page for an item is taken as the page where its header appears.
    """
    results: List[Dict[str, str]] = []
    n = len(lines_with_pages)

    def is_header_at(idx: int) -> bool:
        return 0 <= idx < n and HEADER_RE.match(lines_with_pages[idx][0]) is not None

    def find_prev_header_idx(idx: int) -> int:
        for j in range(idx, -1, -1):
            if is_header_at(j):
                return j
        return -1

    def find_next_header_idx(idx: int) -> int:
        for j in range(idx + 1, n):
            if is_header_at(j):
                return j
        return n

    i = 0
    while i < n:
        ln, pg = lines_with_pages[i]
        if DESCRIPTION_LINE.match(ln):
            h = find_prev_header_idx(i)
            if h == -1:
                i += 1
                continue
            end = find_next_header_idx(h)
            block_lines = lines_with_pages[h:end]
            if not block_lines:
                i += 1
                continue
            header_line, header_page = block_lines[0]
            m = HEADER_RE.match(header_line)
            if not m:
                i += 1
                continue
            rule_id = m.group("num")
            title = m.group("title").strip()
            block_text = "\n".join(l for l, _ in block_lines)
            sections = parse_sections(block_text)
            if any(sections.get(k) for k in ("Description", "Audit", "Remediation")):
                results.append({
                    "pdf_file": pdf_name,
                    "page": header_page,
                    "rule_id": rule_id,
                    "title": title,
                    "description": sections.get("Description",""),
                    "audit": sections.get("Audit",""),
                    "remediation": sections.get("Remediation",""),
                })
            i = end
            continue
        i += 1

    return results

# -----------------------------
# UI
# -----------------------------
st.title("CIS Benchmark PDF → Clean + Parse (v3)")

with st.sidebar:
    st.header("Options")
    start_gate = st.text_input("Gate START heading (optional)", value="Recommendations")
    end_gate = st.text_input("Gate END heading (optional)", value="Appendix")
    show_raw = st.checkbox("Show RAW extracted text", value=False)
    show_scrubbed = st.checkbox("Show SCRUBBED text", value=True)

uploaded = st.file_uploader("Upload a CIS Benchmark PDF", type=["pdf"])
sample_on = st.toggle("No PDF? Use a small sample text (demo)")

lines_with_pages: List[Tuple[str, int]] = []
pdf_name: str = ""

if uploaded is not None:
    pdf_name = uploaded.name
    try:
        pdf_bytes = uploaded.read()
        lines_with_pages = extract_lines_with_pages(pdf_bytes)
    except Exception as e:
        st.error(f"PDF extract failed. Ensure pdfminer.six is installed. Error: {e}")
elif sample_on:
    pdf_name = "SAMPLE.pdf"
    sample_text = """
Preface
Page 1 of 200

1.1.1 Ensure Web Content is on Non-System Partition (Level 1)
Description:
Alpha
Audit:
Audit A
Remediation:
Fix A

CIS Controls
Description:
THIS SHOULD BE IGNORED
(controls text...)

Some interim text that should be discarded until we meet a header...
Description:
Buffered lines that will be re-attached after the next header.

1.1.2 Remove Or Rename Well-Known URLs (Level 1)
Description:
Bravo
Rationale:
R
Audit:
Audit B
Remediation:
Fix B

Appendix
Page 200 of 200
"""
    # put the sample on one page for demo simplicity
    lines_with_pages = [(ln.rstrip(), 1) for ln in sample_text.splitlines()]

if lines_with_pages:
    # 1) Noise strip
    cleaned = strip_page_noise_lines(lines_with_pages)

    # 2) Scrub 'CIS Controls' ranges (page-aware)
    scrubbed = scrub_controls_blocks_lines(cleaned)

    # 3) Optional gate by headings
    scoped = gate_by_headings_lines(
        scrubbed,
        start_gate if start_gate.strip() else None,
        end_gate if end_gate.strip() else None
    )

    # Show text areas
    if show_raw:
        st.subheader("RAW extracted text")
        st.text_area("RAW", value=to_text(lines_with_pages), height=240)
    if show_scrubbed:
        st.subheader("SCRUBBED text (after removing CIS Controls blocks)")
        st.text_area("SCRUBBED", value=to_text(scoped), height=320)

    if st.button("Parse to DataFrame", type="primary"):
        rows = parse_description_anchored_lines(scoped, pdf_name=pdf_name)
        if not rows:
            st.warning("No recommendations extracted. Adjust START/END headings or verify the PDF structure.")
        else:
            import pandas as pd
            df = pd.DataFrame(rows, columns=["pdf_file","page","rule_id","title","description","audit","remediation"])
            st.success(f"Extracted {len(df)} recommendations.")
            st.dataframe(df, use_container_width=True)

            # Export filenames derived from uploaded PDF name
            base = Path(pdf_name).stem or "cis_extract"
            json_name = f"{base}.json"
            csv_name = f"{base}.csv"

            # Downloads
            json_bytes = json.dumps(rows, ensure_ascii=False, indent=2).encode("utf-8")
            st.download_button(
                f"Download JSON ({json_name})",
                data=json_bytes,
                file_name=json_name,
                mime="application/json"
            )

            csv_buf = io.StringIO()
            w = csv.writer(csv_buf)
            w.writerow(["pdf_file","page","rule_id","title","description","audit","remediation"])
            for r in rows:
                w.writerow([r["pdf_file"], r["page"], r["rule_id"], r["title"], r["description"], r["audit"], r["remediation"]])
            st.download_button(
                f"Download CSV ({csv_name})",
                data=csv_buf.getvalue().encode("utf-8"),
                file_name=csv_name,
                mime="text/csv"
            )
else:
    st.info("Upload a CIS Benchmark PDF or enable the demo sample to proceed.")
