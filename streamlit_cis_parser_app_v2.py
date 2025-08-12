import streamlit as st
import re
import io
import csv
import json
from typing import List, Dict

st.set_page_config(page_title="CIS Benchmark Parser (v2)", layout="wide")

# -----------------------------
# PDF text extraction (pdfminer.six required)
# -----------------------------
def extract_text_from_pdf_bytes(pdf_bytes: bytes) -> str:
    from pdfminer.high_level import extract_text
    bio = io.BytesIO(pdf_bytes)
    text = extract_text(bio)
    text = text.replace("\r", "")
    text = re.sub(r"[ \t]+", " ", text)
    return text

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
# Utilities
# -----------------------------
def strip_page_noise(text: str) -> str:
    """Remove repeated header/footer noise."""
    out_lines = []
    for ln in text.splitlines():
        if any(p.search(ln) for p in PAGE_NOISE):
            continue
        out_lines.append(ln.rstrip())
    return "\n".join(out_lines)

def scrub_controls_blocks(text: str) -> str:
    """
    Implements the user's strategy:
    - Scan the entire text line-by-line.
    - When 'CIS Controls' is encountered, start discarding lines.
    - While discarding, if we see 'Description', begin buffering lines (not output yet).
    - Keep buffering until we see a RULE HEADER; at that moment:
        * We re-add (flush) the buffered lines AFTER the header (so order stays correct).
        * Output the header as well (so the block starts properly).
        * Exit discard mode and continue in normal mode.
    - If we hit a new 'CIS Controls' before a header, clear the buffer and keep discarding.
    - If EOF occurs while discarding without any subsequent header, we drop the buffer.
    """
    lines = [ln.rstrip() for ln in text.splitlines()]
    n = len(lines)
    out: List[str] = []
    discarding = False
    buffering = False
    buffer: List[str] = []

    i = 0
    while i < n:
        ln = lines[i]

        # Enter Controls discard mode
        if not discarding and CIS_CONTROLS_MARK.match(ln):
            discarding = True
            buffering = False
            buffer = []
            i += 1
            continue

        if discarding:
            # If another Controls appears, reset buffer and keep discarding
            if CIS_CONTROLS_MARK.match(ln):
                buffering = False
                buffer = []
                i += 1
                continue

            # Start buffering once a Description line is seen
            if DESCRIPTION_LINE.match(ln) and not buffering:
                buffering = True
                buffer = [ln]
                i += 1
                continue

            # Keep buffering if already started
            if buffering and not HEADER_RE.match(ln):
                buffer.append(ln)
                i += 1
                continue

            # If we hit a rule header while discarding:
            if HEADER_RE.match(ln):
                # Output the header
                out.append(ln)
                # Flush buffered lines AFTER header to keep the natural order
                if buffer:
                    out.extend(buffer)
                # Exit discard mode and resume normal output
                discarding = False
                buffering = False
                buffer = []
                i += 1
                continue

            # Otherwise (non-header, no buffering yet): keep discarding
            i += 1
            continue

        # Normal mode: copy through
        out.append(ln)
        i += 1

    # If EOF reached while discarding, we intentionally drop the buffer
    return "\n".join(out)

def gate_by_headings(text: str, start_mark: str = None, end_mark: str = None) -> str:
    """Keep only [start_mark .. end_mark) if provided."""
    if not start_mark and not end_mark:
        return text
    lines = text.splitlines()
    n = len(lines)
    start_idx = 0
    if start_mark:
        for i, ln in enumerate(lines):
            if re.match(rf"^\s*{re.escape(start_mark)}\s*$", ln, re.IGNORECASE):
                start_idx = i
                break
    end_idx = n
    if end_mark:
        for j in range(start_idx + 1, n):
            if re.match(rf"^\s*{re.escape(end_mark)}\s*$", lines[j], re.IGNORECASE):
                end_idx = j
                break
    return "\n".join(lines[start_idx:end_idx])

def parse_sections(body: str) -> Dict[str, str]:
    """Parse labeled sections inside one recommendation block."""
    lines = [ln.strip() for ln in body.splitlines()]
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

def split_recommendations(text: str) -> List[Dict[str, str]]:
    """Split by rule headers into blocks with header+body."""
    recs = []
    matches = list(HEADER_RE.finditer(text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i+1].start() if i+1 < len(matches) else len(text)
        header_line = text[m.start():text.find("\n", m.start())]
        body = text[text.find("\n", m.start()):end]
        recs.append({"header": header_line.strip(), "body": body.strip()})
    return recs

def parse_cis_text_desc_anchored(text: str) -> List[Dict[str, str]]:
    """
    Final parse (after scrubbing):
    Still uses Description-anchored logic as an additional safeguard.
    """
    text = strip_page_noise(text)
    lines = [ln.rstrip() for ln in text.splitlines()]
    n = len(lines)

    def find_prev_header(idx: int) -> int:
        for j in range(idx, -1, -1):
            if HEADER_RE.match(lines[j]):
                return j
        return -1

    def find_next_header(idx: int) -> int:
        for j in range(idx + 1, n):
            if HEADER_RE.match(lines[j]):
                return j
        return n

    results: List[Dict[str, str]] = []
    i = 0
    while i < n:
        ln = lines[i]
        if DESCRIPTION_LINE.match(ln):
            h = find_prev_header(i)
            if h == -1:
                i += 1
                continue
            end = find_next_header(h)
            block_lines = lines[h:end]
            if not block_lines:
                i += 1
                continue
            m = HEADER_RE.match(block_lines[0])
            if not m:
                i += 1
                continue
            rule_id = m.group("num")
            title = m.group("title").strip()
            block_text = "\n".join(block_lines)
            sections = parse_sections(block_text)
            if any(sections.get(k) for k in ("Description", "Audit", "Remediation")):
                results.append({
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
st.title("CIS Benchmark PDF → Clean + Parse (v2)")

with st.sidebar:
    st.header("Options")
    start_gate = st.text_input("Gate START heading (optional)", value="Recommendations")
    end_gate = st.text_input("Gate END heading (optional)", value="Appendix")
    show_raw = st.checkbox("Show RAW extracted text", value=False)
    show_scrubbed = st.checkbox("Show SCRUBBED text", value=True)

uploaded = st.file_uploader("Upload a CIS Benchmark PDF", type=["pdf"])
sample_on = st.toggle("No PDF? Use a small sample text (demo)")

raw_text = ""
if uploaded is not None:
    try:
        pdf_bytes = uploaded.read()
        raw_text = extract_text_from_pdf_bytes(pdf_bytes)
    except Exception as e:
        st.error(f"PDF extract failed. Ensure pdfminer.six is installed. Error: {e}")
elif sample_on:
    raw_text = """
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
More lines that should be buffered, but not emitted, until we reach the next rule header.
Even more lines...

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

if raw_text:
    # 1) Strip page noise
    cleaned = strip_page_noise(raw_text)

    # 2) Scrub CIS Controls blocks per the requested algorithm
    scrubbed = scrub_controls_blocks(cleaned)

    # 3) Optional: gate by headings (after scrubbing)
    scoped = gate_by_headings(
        scrubbed,
        start_gate if start_gate.strip() else None,
        end_gate if end_gate.strip() else None
    )

    # Show text areas as requested
    if show_raw:
        st.subheader("RAW extracted text")
        st.text_area("RAW", value=raw_text, height=240)
    if show_scrubbed:
        st.subheader("SCRUBBED text (after removing CIS Controls blocks)")
        st.text_area("SCRUBBED", value=scoped, height=320)

    if st.button("Parse to DataFrame", type="primary"):
        rows = parse_cis_text_desc_anchored(scoped)
        if not rows:
            st.warning("No recommendations extracted. Adjust START/END headings or verify the PDF structure.")
        else:
            import pandas as pd
            df = pd.DataFrame(rows, columns=["rule_id","title","description","audit","remediation"])
            st.success(f"Extracted {len(df)} recommendations.")
            st.dataframe(df, use_container_width=True)

            # Downloads
            json_bytes = json.dumps(rows, ensure_ascii=False, indent=2).encode("utf-8")
            st.download_button(
                "Download JSON",
                data=json_bytes,
                file_name="cis_extract.json",
                mime="application/json"
            )

            csv_buf = io.StringIO()
            w = csv.writer(csv_buf)
            w.writerow(["rule_id","title","description","audit","remediation"])
            for r in rows:
                w.writerow([r["rule_id"], r["title"], r["description"], r["audit"], r["remediation"]])
            st.download_button(
                "Download CSV",
                data=csv_buf.getvalue().encode("utf-8"),
                file_name="cis_extract.csv",
                mime="text/csv"
            )
else:
    st.info("Upload a CIS Benchmark PDF or enable the demo sample to proceed.")
