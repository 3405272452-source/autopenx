"""Generate minimal CET-4 test PDF fixtures using reportlab.

These PDFs contain the expected section anchors and question patterns
so that the PDF parser orchestrator can be integration-tested against
real PDF files (not mocked layout blocks).

Two fixtures are generated:
1. complete_paper.pdf — A "complete" paper with all 4 sections and
   correct question counts (Writing 1, Listening 25, Reading 30, Translation 1)
2. miscount_paper.pdf — A paper with incorrect question counts in some
   sections (triggers needs-review flags)
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas


def _write_text_block(c: canvas.Canvas, text: str, x: float, y: float) -> float:
    """Write a text block and return the new y position."""
    lines = text.split("\n")
    for line in lines:
        c.drawString(x, y, line)
        y -= 14
    return y


def generate_complete_paper(output_path: Path) -> None:
    """Generate a minimal but complete CET-4 paper PDF.

    Contains all 4 section anchors with correct question counts:
    - Writing: 1 question
    - Listening: 25 questions (7 news + 8 conversation + 10 passage)
    - Reading: 30 questions (10 banked_cloze + 10 long_matching + 10 careful)
    - Translation: 1 question
    """
    c = canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4
    margin = 2 * cm

    # --- Page 1: Cover + Writing ---
    y = height - margin
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "CET-4 Examination Paper - 2024-12 Set 1")
    y -= 30

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part I Writing (30 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Directions: For this part, you are allowed 30 minutes to write an essay.")
    y -= 14
    c.drawString(margin, y, "You should write at least 120 words but no more than 180 words.")
    y -= 14
    c.drawString(margin, y, "Topic: The Importance of Reading")
    y -= 30

    # --- Page 2: Listening ---
    c.showPage()
    y = height - margin

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part II Listening Comprehension (25 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Section A News Report")
    y -= 14

    # Generate 7 news report questions (questions 1-7)
    for i in range(1, 8):
        c.drawString(margin, y, f"{i}. A) Option A for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"B) Option B for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"C) Option C for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"D) Option D for question {i}")
        y -= 16
        if y < margin:
            c.showPage()
            y = height - margin

    c.drawString(margin, y, "Section B Long Conversation")
    y -= 14

    # Generate 8 long conversation questions (questions 8-15)
    for i in range(8, 16):
        c.drawString(margin, y, f"{i}. A) Option A for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"B) Option B for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"C) Option C for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"D) Option D for question {i}")
        y -= 16
        if y < margin:
            c.showPage()
            y = height - margin

    c.drawString(margin, y, "Section C Passage")
    y -= 14

    # Generate 10 passage questions (questions 16-25)
    for i in range(16, 26):
        c.drawString(margin, y, f"{i}. A) Option A for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"B) Option B for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"C) Option C for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"D) Option D for question {i}")
        y -= 16
        if y < margin:
            c.showPage()
            y = height - margin

    # --- Reading Section ---
    c.showPage()
    y = height - margin

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part III Reading Comprehension (40 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Section A")
    y -= 14
    c.drawString(margin, y, "Directions: In this section, there is a passage with ten blanks.")
    y -= 14
    c.drawString(margin, y, "You are required to select one word for each blank from a list of choices")
    y -= 14
    c.drawString(margin, y, "given in a word bank following the passage.")
    y -= 20

    # Candidate words (15 words)
    words = ["A) abundant", "B) acquired", "C) challenges", "D) combined",
             "E) demands", "F) emerged", "G) essential", "H) familiar",
             "I) function", "J) innovative", "K) maintain", "L) potential",
             "M) previously", "N) process", "O) survived"]
    for w in words:
        c.drawString(margin, y, w)
        y -= 12
        if y < margin:
            c.showPage()
            y = height - margin

    # Passage with blanks (10 blanks: __26__ through __35__)
    y -= 10
    c.drawString(margin, y, "The development of technology has __26__ many changes in our daily lives.")
    y -= 14
    c.drawString(margin, y, "These changes have __27__ new opportunities for people around the world.")
    y -= 14
    c.drawString(margin, y, "It is __28__ to understand how technology affects our __29__ activities.")
    y -= 14
    c.drawString(margin, y, "Many people have __30__ new skills to adapt to the digital age.")
    y -= 14
    c.drawString(margin, y, "The __31__ for technological literacy continues to grow in modern society.")
    y -= 14
    c.drawString(margin, y, "New solutions have __32__ to address the __33__ we face today.")
    y -= 14
    c.drawString(margin, y, "It is important to __34__ a balance between technology and human connection.")
    y -= 14
    c.drawString(margin, y, "The __35__ of technology to transform lives remains largely untapped.")
    y -= 30

    if y < margin:
        c.showPage()
        y = height - margin

    # Section B: Long Reading
    c.drawString(margin, y, "Section B")
    y -= 14
    c.drawString(margin, y, "Directions: In this section, you are going to read a passage with ten")
    y -= 14
    c.drawString(margin, y, "statements attached to it. Each statement contains information given in")
    y -= 14
    c.drawString(margin, y, "one of the paragraphs. Identify the paragraph from which the information")
    y -= 14
    c.drawString(margin, y, "is derived. You may choose a paragraph more than once.")
    y -= 20

    # Paragraphs A-O (minimal)
    for letter in "ABCDEFGHIJKLMNO":
        c.drawString(margin, y, f"{letter}) This is paragraph {letter} content about various topics.")
        y -= 14
        if y < margin:
            c.showPage()
            y = height - margin

    # 10 matching questions (36-45)
    y -= 10
    for i in range(36, 46):
        c.drawString(margin, y, f"{i}. Statement {i} about the passage content.")
        y -= 14
        if y < margin:
            c.showPage()
            y = height - margin

    # Section C: Careful Reading
    y -= 10
    c.drawString(margin, y, "Section C")
    y -= 14
    c.drawString(margin, y, "Directions: There are 2 passages in this section. Each passage is followed")
    y -= 14
    c.drawString(margin, y, "by some questions or unfinished statements.")
    y -= 20

    # Passage One with 5 questions (46-50)
    c.drawString(margin, y, "Passage One")
    y -= 14
    c.drawString(margin, y, "This is the first passage about modern education and its challenges.")
    y -= 14
    c.drawString(margin, y, "The passage discusses various aspects of learning in the digital age.")
    y -= 20

    for i in range(46, 51):
        c.drawString(margin, y, f"{i}. What does the passage suggest about topic {i}?")
        y -= 12
        c.drawString(margin + 20, y, f"A) First option for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"B) Second option for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"C) Third option for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"D) Fourth option for question {i}")
        y -= 16
        if y < margin:
            c.showPage()
            y = height - margin

    # Passage Two with 5 questions (51-55)
    c.drawString(margin, y, "Passage Two")
    y -= 14
    c.drawString(margin, y, "This is the second passage about environmental sustainability.")
    y -= 14
    c.drawString(margin, y, "It explores how communities can work together for a greener future.")
    y -= 20

    for i in range(51, 56):
        c.drawString(margin, y, f"{i}. According to the passage, what is true about topic {i}?")
        y -= 12
        c.drawString(margin + 20, y, f"A) First option for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"B) Second option for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"C) Third option for question {i}")
        y -= 12
        c.drawString(margin + 20, y, f"D) Fourth option for question {i}")
        y -= 16
        if y < margin:
            c.showPage()
            y = height - margin

    # --- Translation Section ---
    c.showPage()
    y = height - margin

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part IV Translation (30 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Directions: For this part, you are allowed 30 minutes to translate a passage")
    y -= 14
    c.drawString(margin, y, "from Chinese into English. You should write your answer on Answer Sheet 2.")
    y -= 20
    # Use ASCII-safe Chinese-like text representation
    c.drawString(margin, y, "Translate the following paragraph into English (not less than 140 words):")
    y -= 14
    c.drawString(margin, y, "zhong guo shi shi jie shang zui gu lao de wen ming zhi yi.")
    y -= 14
    c.drawString(margin, y, "zhong guo wen hua dui shi jie chan sheng le shen yuan de ying xiang.")

    c.save()


def generate_miscount_paper(output_path: Path) -> None:
    """Generate a CET-4 paper PDF with incorrect question counts.

    This paper has:
    - Writing: 1 question (correct)
    - Listening: 20 questions instead of 25 (WRONG - triggers needs-review)
    - Reading: Only 8 banked_cloze instead of 10 (WRONG - triggers needs-review)
    - Translation: 1 question (correct)
    """
    c = canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4
    margin = 2 * cm

    # --- Page 1: Cover + Writing ---
    y = height - margin
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "CET-4 Examination Paper - 2024-06 Set 2")
    y -= 30

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part I Writing (30 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Directions: For this part, you are allowed 30 minutes to write an essay.")
    y -= 14
    c.drawString(margin, y, "You should write at least 120 words.")
    y -= 14
    c.drawString(margin, y, "Topic: Technology and Education")
    y -= 30

    # --- Listening (only 20 questions instead of 25) ---
    c.showPage()
    y = height - margin

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part II Listening Comprehension (25 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Section A News Report")
    y -= 14

    # Only 5 news questions (should be 7)
    for i in range(1, 6):
        c.drawString(margin, y, f"{i}. A) Option A  B) Option B  C) Option C  D) Option D")
        y -= 14
        if y < margin:
            c.showPage()
            y = height - margin

    c.drawString(margin, y, "Section B Long Conversation")
    y -= 14

    # Only 7 conversation questions (should be 8)
    for i in range(6, 13):
        c.drawString(margin, y, f"{i}. A) Option A  B) Option B  C) Option C  D) Option D")
        y -= 14
        if y < margin:
            c.showPage()
            y = height - margin

    c.drawString(margin, y, "Section C Passage")
    y -= 14

    # Only 8 passage questions (should be 10)
    for i in range(13, 21):
        c.drawString(margin, y, f"{i}. A) Option A  B) Option B  C) Option C  D) Option D")
        y -= 14
        if y < margin:
            c.showPage()
            y = height - margin

    # --- Reading Section ---
    c.showPage()
    y = height - margin

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part III Reading Comprehension (40 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Section A")
    y -= 14
    c.drawString(margin, y, "Directions: In this section, there is a passage with ten blanks.")
    y -= 14
    c.drawString(margin, y, "You are required to select one word for each blank from a list of choices")
    y -= 14
    c.drawString(margin, y, "given in a word bank following the passage.")
    y -= 20

    # Candidate words (15 words)
    words = ["A) ancient", "B) benefits", "C) critical", "D) designed",
             "E) effective", "F) global", "G) highlight", "H) impact",
             "I) journey", "K) limited", "L) modern", "M) narrow",
             "N) obvious", "O) primary", "J) knowledge"]
    for w in words:
        c.drawString(margin, y, w)
        y -= 12
        if y < margin:
            c.showPage()
            y = height - margin

    # Only 8 blanks instead of 10 (WRONG)
    y -= 10
    c.drawString(margin, y, "Technology has had a __26__ impact on education worldwide.")
    y -= 14
    c.drawString(margin, y, "The __27__ of online learning have become increasingly __28__.")
    y -= 14
    c.drawString(margin, y, "Many institutions have __29__ new programs to meet __30__ demands.")
    y -= 14
    c.drawString(margin, y, "The __31__ nature of these changes is __32__ to many educators.")
    y -= 14
    c.drawString(margin, y, "Understanding the __33__ of technology remains a key challenge.")
    y -= 30

    if y < margin:
        c.showPage()
        y = height - margin

    # Section B: Long Reading (10 questions - correct)
    c.drawString(margin, y, "Section B")
    y -= 14
    c.drawString(margin, y, "Directions: In this section, you are going to read a passage with ten")
    y -= 14
    c.drawString(margin, y, "statements attached to it. Each statement contains information given in")
    y -= 14
    c.drawString(margin, y, "one of the paragraphs.")
    y -= 20

    for letter in "ABCDEFGHIJKLMNO":
        c.drawString(margin, y, f"{letter}) Paragraph {letter} discusses important topics.")
        y -= 14
        if y < margin:
            c.showPage()
            y = height - margin

    for i in range(36, 46):
        c.drawString(margin, y, f"{i}. Statement about paragraph content {i}.")
        y -= 14
        if y < margin:
            c.showPage()
            y = height - margin

    # Section C: Careful Reading (10 questions - correct)
    y -= 10
    c.drawString(margin, y, "Section C")
    y -= 14
    c.drawString(margin, y, "Directions: There are 2 passages in this section.")
    y -= 20

    c.drawString(margin, y, "Passage One")
    y -= 14
    c.drawString(margin, y, "A passage about technology in modern society.")
    y -= 20

    for i in range(46, 51):
        c.drawString(margin, y, f"{i}. Question about the passage?")
        y -= 12
        c.drawString(margin + 20, y, f"A) Option A  B) Option B  C) Option C  D) Option D")
        y -= 16
        if y < margin:
            c.showPage()
            y = height - margin

    c.drawString(margin, y, "Passage Two")
    y -= 14
    c.drawString(margin, y, "A passage about environmental issues.")
    y -= 20

    for i in range(51, 56):
        c.drawString(margin, y, f"{i}. Question about the passage?")
        y -= 12
        c.drawString(margin + 20, y, f"A) Option A  B) Option B  C) Option C  D) Option D")
        y -= 16
        if y < margin:
            c.showPage()
            y = height - margin

    # --- Translation Section ---
    c.showPage()
    y = height - margin

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Part IV Translation (30 minutes)")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(margin, y, "Directions: Translate the following passage from Chinese into English.")
    y -= 14
    c.drawString(margin, y, "You should write at least 140 words.")
    y -= 20
    c.drawString(margin, y, "zhong guo jing ji zai guo qu ji shi nian li qu de le ju da fa zhan.")

    c.save()


if __name__ == "__main__":
    output_dir = Path(__file__).parent
    generate_complete_paper(output_dir / "complete_paper.pdf")
    generate_miscount_paper(output_dir / "miscount_paper.pdf")
    print("Generated test PDF fixtures.")
