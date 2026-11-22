"""
Targeted corrections for ThreatSense_AI_Seminar_Report_v2.docx → v3.docx

Changes:
1. Para 266 (Section 4.10 Testing): 402 tests → 427 tests (update full paragraph)
2. Para 276 (Section 5.1): update test count if present
3. Table 5 (Dev Stages):
   - Stage 4: "Implemented" → "Done"
   - Stage 12: "Pending" → "Done"
   - Stage 13: status → "Done — DeBERTa-v3-small trained on 51 labeled examples and deployed to Render via Hugging Face."
4. Any remaining mentions of "402" test count → "427"
"""
import os
from docx import Document

INPUT = r"C:\Users\Rajj9\ThreatSense-AI\docs\ThreatSense_AI_Seminar_Report_v2.docx"
OUTPUT = r"C:\Users\Rajj9\ThreatSense-AI\docs\ThreatSense_AI_Seminar_Report_v3.docx"


def get_para_text(para):
    return "".join(r.text for r in para.runs)


def set_para_text(para, new_text):
    """Replace paragraph content, preserving first run style."""
    if not para.runs:
        para.add_run(new_text)
        return
    # Preserve formatting from first run
    r0 = para.runs[0]
    bold = r0.bold
    italic = r0.italic
    fname = r0.font.name
    fsize = r0.font.size
    # Remove all runs except first
    for r in para.runs[1:]:
        r._r.getparent().remove(r._r)
    # Set first run text with preserved formatting
    para.runs[0].text = new_text
    para.runs[0].bold = bold
    para.runs[0].italic = italic
    if fname:
        para.runs[0].font.name = fname
    if fsize:
        para.runs[0].font.size = fsize


def fix_paragraphs(doc):
    """Apply paragraph-level fixes."""
    for i, para in enumerate(doc.paragraphs):
        txt = get_para_text(para)

        # Fix 4.10 Testing paragraph with old test count
        if "402 tests" in txt and ("backend test run" in txt or "suite" in txt.lower() or "testing" in txt.lower()):
            new = txt.replace("402 tests", "427 tests").replace("401 passed", "426 passed")
            if new != txt:
                print(f"  [para {i}] Testing count fix: {txt[:100]}")
                set_para_text(para, new)

        # Generic 402→427 replacement (only if about tests)
        if "402" in txt and "test" in txt.lower():
            new = txt.replace("402", "427")
            if new != txt:
                print(f"  [para {i}] 402→427: {txt[:100]}")
                set_para_text(para, new)

        # Fix Section 5.1 if it mentions 402
        if "402" in txt:
            new = txt.replace("402", "427")
            if new != txt:
                print(f"  [para {i}] 402 general fix: {txt[:100]}")
                set_para_text(para, new)


def fix_tables(doc):
    """Apply table-level fixes."""
    for ti, table in enumerate(doc.tables):
        for ri, row in enumerate(table.rows):
            cells = row.cells
            # Get text of all cells in row
            row_texts = [" ".join(p.text for p in c.paragraphs).strip() for c in cells]
            row_joined = " | ".join(row_texts)

            # Dev stages table: Stage 12 — fix Pending → Done
            if "12" in row_texts[0] and "Pending" in row_joined:
                for ci, cell in enumerate(cells):
                    ct = " ".join(p.text for p in cell.paragraphs).strip()
                    if ct == "Pending" or ct.lower() == "pending":
                        print(f"  [table {ti} row {ri} cell {ci}] Stage 12 Pending → Done")
                        for para in cell.paragraphs:
                            set_para_text(para, "Done")

            # Dev stages table: Stage 13 — update status
            if "13" in row_texts[0] and ("DeBERTa checkpoint" in row_joined or "bootstrap checkpoint" in row_joined or "Implemented" in row_joined):
                for ci, cell in enumerate(cells):
                    ct = " ".join(p.text for p in cell.paragraphs).strip()
                    if "Implemented" in ct or "bootstrap" in ct.lower():
                        new_status = "Done — DeBERTa-v3-small fine-tuned on 51 labeled examples (average loss 0.6413 over 4 epochs, 258 s on CPU). Weights hosted on Hugging Face and loaded via NLP_FINETUNED_PATH on Render."
                        print(f"  [table {ti} row {ri} cell {ci}] Stage 13 status update")
                        for para in cell.paragraphs:
                            set_para_text(para, new_status)
                        break  # only fix the status cell, not the deliverable cell

            # Dev stages table: Stage 4 — Implemented → Done
            if "4" in row_texts[0] and "Pluggable NLP" in row_joined and "Implemented" in row_joined:
                for ci, cell in enumerate(cells):
                    ct = " ".join(p.text for p in cell.paragraphs).strip()
                    if ct == "Implemented":
                        print(f"  [table {ti} row {ri} cell {ci}] Stage 4 Implemented → Done")
                        for para in cell.paragraphs:
                            set_para_text(para, "Done")

            # Also fix any remaining 402 → 427 in table cells
            for ci, cell in enumerate(cells):
                for para in cell.paragraphs:
                    pt = get_para_text(para)
                    if "402" in pt:
                        new = pt.replace("402", "427")
                        print(f"  [table {ti} row {ri} cell {ci}] 402→427: {pt[:80]}")
                        set_para_text(para, new)


def main():
    print(f"Opening: {INPUT}")
    doc = Document(INPUT)

    print("\n--- Fixing paragraphs ---")
    fix_paragraphs(doc)

    print("\n--- Fixing tables ---")
    fix_tables(doc)

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    doc.save(OUTPUT)
    print(f"\nSaved to: {OUTPUT}")
    print("DONE")


if __name__ == "__main__":
    main()
