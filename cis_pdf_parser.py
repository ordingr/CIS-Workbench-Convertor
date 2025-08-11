#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CIS Benchmark PDF parser
- Extracts rule title, description, audit, remediation (and keeps room for rationale)
- Tested on multiple CIS PDFs (Linux/Windows/IIS). Your mileage may vary per vendor/version.
Usage:
  python cis_pdf_parser.py --pdf_file <path.pdf> --out_json out.json --out_csv out.csv

Dependencies:
  pip install pdfminer.six
"""
import re
import json
import argparse
from typing import List, Dict, Optional

# --- Text extraction ---
def extract_text_from_pdf(pdf_path: str) -> str:
    """
    Extract raw text from a PDF using pdfminer.six.
    """
    try:
        from pdfminer.high_level import extract_text
    except Exception as e:
        raise RuntimeError(
            "pdfminer.six is required. Install with: pip install pdfminer.six"
        ) from e
    text = extract_text(pdf_path)
    # Normalize whitespace a bit
    text = text.replace('\r', '')
    text = re.sub(r'[ \t]+', ' ', text)
    return text

# --- Parsing ---
# CIS sections we care about (case-insensitive, allow optional colon)
SECTION_LABELS = ["Description", "Rationale", "Audit", "Remediation"]
LABEL_RE = re.compile(rf"^({'|'.join(SECTION_LABELS)}):?\s*$", re.IGNORECASE)

# Recommendation header examples:
# "1.1.1 Ensure Web Content is on Non-System Partition (Level 1, Scorable)"
# "2.2.5 Ensure ... (Automated)"
# Some PDFs include Roman numerals or long titles; keep it simple but strict enough.
HEADER_RE = re.compile(
    r"^(?P<num>(\d+\.)+\d+)\s+(?P<title>.+?)\s*(\(|$)", re.MULTILINE
)

def split_recommendations(text: str) -> List[Dict[str, str]]:
    """
    Split the CIS text into recommendation blocks using numeric headers.
    Returns list of dicts: {header, body}
    """
    recs = []
    matches = list(HEADER_RE.finditer(text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i+1].start() if i+1 < len(matches) else len(text)
        header_line = text[m.start():text.find("\n", m.start())]
        body = text[text.find("\n", m.start()):end]
        recs.append({"header": header_line.strip(), "body": body.strip()})
    return recs

def parse_sections(body: str) -> Dict[str, str]:
    """
    Within a recommendation body, pull out Description, Audit, Remediation (and Rationale if present).
    We detect labels on their own line (case-insensitive). Gather text until next label or end.
    """
    # Normalize line breaks
    lines = [ln.strip() for ln in body.splitlines()]
    sections = {}
    current_label = None
    buf = []

    def flush():
        nonlocal buf, current_label, sections
        if current_label:
            text = "\n".join(buf).strip()
            # Some CIS PDFs place default value / references immediately after Audit or Remediation;
            # we attempt to stop at "Default Value" or "References" if present within the captured text.
            text = re.split(r"\n(?i:Default Value:|References?:)", text)[0].strip()
            sections[current_label.capitalize()] = text
        buf = []

    for ln in lines:
        if LABEL_RE.match(ln):
            flush()
            current_label = LABEL_RE.match(ln).group(1)
        else:
            buf.append(ln)
    flush()

    return sections

def parse_cis_text(text: str) -> List[Dict[str, str]]:
    """
    Parse entire text and return list of rows with fields:
    rule_id, title, description, audit, remediation
    """
    out = []
    for rec in split_recommendations(text):
        header = rec["header"]
        # Extract rule number and title
        m = HEADER_RE.search(header)
        rule_id = m.group("num") if m else ""
        title = m.group("title").strip() if m else header
        sections = parse_sections(rec["body"])
        out.append({
            "rule_id": rule_id,
            "title": title,
            "description": sections.get("Description", ""),
            "audit": sections.get("Audit", ""),
            "remediation": sections.get("Remediation", ""),
        })
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdf_file", help="Path to CIS Benchmark PDF")
    ap.add_argument("--out_json", default="cis_extract.json", help="Output JSON path")
    ap.add_argument("--out_csv", default="cis_extract.csv", help="Output CSV path")
    args = ap.parse_args()

    # Extract text (from file) and parse
    if not args.pdf_file:
        ap.error("--pdf_file is required")
    raw_text = extract_text_from_pdf(args.pdf_file)
    rows = parse_cis_text(raw_text)

    # Save
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)

    # Pandas is optional; we'll avoid importing here to keep deps minimal
    # But CSV is easy to write without pandas:
    import csv
    with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rule_id","title","description","audit","remediation"])
        for r in rows:
            w.writerow([r["rule_id"], r["title"], r["description"], r["audit"], r["remediation"]])

    print(f"Extracted {len(rows)} recommendations.")
    print(f"Wrote: {args.out_json}")
    print(f"Wrote: {args.out_csv}")

if __name__ == "__main__":
    main()
