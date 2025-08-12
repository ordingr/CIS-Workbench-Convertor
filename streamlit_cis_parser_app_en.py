import streamlit as st
import re
import io
import csv
import json
from typing import List, Dict

# -----------------------------
# Streamlit configuration
# -----------------------------
st.set_page_config(page_title="CIS Benchmark Parser", layout="wide")

# -----------------------------
# PDF text extraction (requires pdfminer.six)
# -----------------------------
def extract_text_from_pdf_bytes(pdf_bytes: bytes) -> str:
    """
    Extract text from a PDF (bytes) using pdfminer.six.
    Normalizes whitespace for easier downstream parsing.
    """
    from pdfminer.high_level import extract_text
    bio = io.BytesIO(pdf_bytes)
    text = extract_text(bio)
    text = text.replace("\r", "")
    text = re.sub(r"[ \t]+", " ", text)
    return text

# -----------------------------
# Regex patterns and helpers
# -----------------------------
# Example rule header: "1.1.1 Ensure X ..." (at least 2 dots typical; regex is flexible)
HEADER_RE = re.compile(r"^(?P<num>(\d+\.)+\d+)\s+(?P<title>.+?)\s*(\(|$)")

# Section labels we want to extract from each recommendation block
SECTION_LABELS = ["Description", "Rationale", "Audit", "Remediation"]
LABEL_RE = re.compile(rf"^({'|'.join(SECTION_LABELS)}):?\s*$", re.IGNORECASE)

# Markers for sections we want to skip
CIS_CONTROLS_MARK = re.compile(r"^\s*CIS Controls\b", re.IGNORECASE)
DESCRIPTION_LINE = re.compile(r"^\s*Description:?\s*$", re.IGNORECASE)

# Common header/footer noise to remove before parsing
PAGE_NOISE = [
    re.compile(r"Center for Internet Security", re.IGNORECASE),
    re.compile(r"\bPage\s+\d+\s+of\s+\d+\b", re.IGNORECASE),
    re.compile(r"Copyright\s+©", re.IGNORECASE),
]

def strip_page_noise(text: str) -> str:
    """
    Remove known page headers/footers and legal/copyright noise.
    """
    out_lines = []
    for ln in text.splitlines():
        if any(p.search(ln) for p in PAGE_NOISE):
            continue
        out_lines.append(ln.rstrip())
    return "\n".join(out_lines)

def gate_by_headings(text: str, start_mark: str = None, end_mark: str = None) -> str:
    """
    Optionally restrict parsing to the [start_mark .. end_mark) range.
    Useful to gate to 'Recommendations' .. 'Appendix' if present.
    """
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
    """
    Parse labeled sections inside a single recommendation block.
    Captures Description, Audit, Remediation (and Rationale if present).
    Stops early if it encounters 'Default Value' or 'References' inside the same block.
    """
    lines = [ln.strip() for ln in body.splitlines()]
    sections: Dict[str, str] = {}
    current_label = None
    buf: List[str] = []

    def flush():
        nonlocal buf, current_label
        if current_label:
            text = "\n".join(buf).strip()
            # Trim at 'Default Value' or 'References' if they appear in-line
            text = re.split(r"\n(?i:Default Value:|References?:)", text)[0].strip()
            sections[current_label.capitalize()] = text
        buf = []

    for ln in lines:
        m = LABEL_RE.match(ln)
        if m:
            # Finish previous section, start a new labeled section
            flush()
            current_label = m.group(1)
        else:
            buf.append(ln)
    flush()
    return sections

def parse_cis_text_desc_anchored(text: str) -> List[Dict[str, str]]:
    """
    Description-anchored parsing strategy:
    - Find each 'Description' line.
    - Walk backward to the nearest preceding rule header line (HEADER_RE).
    - Use the block [header .. next header) as one recommendation,
      but stop early if 'CIS Controls' appears inside the block.
    - Skip any 'Description' that lies within a 'CIS Controls' section.
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
    skip_controls = False
    i = 0

    while i < n:
        ln = lines[i]

        # Enter 'CIS Controls' region; skip until next Description
        if CIS_CONTROLS_MARK.match(ln):
            skip_controls = True
            i += 1
            continue

        # Ignore Description lines while inside Controls
        if DESCRIPTION_LINE.match(ln) and skip_controls:
            i += 1
            continue

        # Valid Description outside Controls
        if DESCRIPTION_LINE.match(ln) and not skip_controls:
            h = find_prev_header(i)
            if h == -1:
                i += 1
                continue

            # If 'CIS Controls' appears between header and this Description, treat as contaminated
            contaminated = any(CIS_CONTROLS_MARK.match(lines[k]) for k in range(h, i))
            if contaminated:
                i += 1
                continue

            # End of block is either next rule header or 'CIS Controls' inside the block
            end = find_next_header(h)
            for k in range(i, end):
                if CIS_CONTROLS_MARK.match(lines[k]):
                    end = k
                    break

            block_lines = lines[h:end]
            if not block_lines:
                i += 1
                continue

            header_line = block_lines[0]
            m = HEADER_RE.match(header_line)
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
                    "description": sections.get("Description", ""),
                    "audit": sections.get("Audit", ""),
                    "remediation": sections.get("Remediation", ""),
                })

            # Jump to end of this block for efficiency
            i = end
            continue

        i += 1

    return results

# -----------------------------
# UI
# -----------------------------
st.title("CIS Benchmark PDF → Parsed Recommendations")

with st.sidebar:
    st.header("Options")
    start_gate = st.text_input("Gate START heading (optional)", value="Recommendations")
    end_gate = st.text_input("Gate END heading (optional)", value="Appendix")
    show_full_text = st.checkbox("Show full extracted text", value=True)

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

1.1.2 Remove Or Rename Well-Known URLs (Level 1)
Description:
Bravo
Rationale:
R
Audit:
Audit B
Remediation:
Fix B
"""

if raw_text:
    # Optional: gate by high-level headings
    scoped = gate_by_headings(
        raw_text,
        start_gate if start_gate.strip() else None,
        end_gate if end_gate.strip() else None
    )

    if show_full_text:
        st.subheader("Extracted Text (after gating)")
        st.text_area("Full text", value=scoped, height=320)

    if st.button("Parse to DataFrame", type="primary"):
        rows = parse_cis_text_desc_anchored(scoped)
        if not rows:
            st.warning("No recommendations extracted. Adjust START/END headings or verify the PDF structure.")
        else:
            import pandas as pd
            df = pd.DataFrame(rows, columns=["rule_id", "title", "description", "audit", "remediation"])
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
            w.writerow(["rule_id", "title", "description", "audit", "remediation"])
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
