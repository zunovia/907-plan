---
name: markdown-to-pptx
description: "Use this skill when the user wants to convert Markdown content into a PowerPoint presentation, or when they want to create a PPTX from a structured text outline. Triggers on: 'Markdownからスライド', 'Markdownをプレゼンに', 'convert markdown to slides', 'outline to presentation', 'text to pptx', 'アウトラインからスライド', or when the user provides a markdown file or structured text and asks for a presentation. This skill defines the conversion workflow; the built-in pptx skill handles file generation."
---

# Markdown → PPTX Conversion Skill

Convert structured Markdown content into polished PowerPoint presentations. This skill defines the conversion rules and workflow; the built-in pptx skill (PptxGenJS) handles actual file generation.

## Supported Input Formats

### Format A: Heading-Based (Most Common)

```markdown
# Presentation Title
## Subtitle or Author

---

# Slide Title 1
- Bullet point one
- Bullet point two
  - Sub-bullet

> Speaker notes go in blockquotes

---

# Slide Title 2
Body paragraph text here.

![alt text](image.png)
```

### Format B: YAML Frontmatter + Content

```markdown
---
title: "Quarterly Review"
author: "Team Name"
date: "2026-03-20"
theme: "midnight-executive"
---

# Revenue grew 23% YoY
- Key driver: Enterprise segment
- APAC expansion contributed 40%

---

# Customer retention improved to 94%
...
```

### Format C: Outline Format

```markdown
# Title: AI Strategy 2026

## 1. Current Landscape
- Market size: $200B
- Growth rate: 35% CAGR

## 2. Our Position
- Market share: 12%
- Key differentiator: Vertical integration

## 3. Roadmap
- Q1: Platform launch
- Q2: Enterprise tier
- Q3: International expansion
```

## Conversion Rules

### Mapping: Markdown → Slide Elements

| Markdown Element | PPTX Element |
|---|---|
| `# Heading 1` (after first) | Slide title (36-44pt bold) |
| `## Heading 2` | Section header or subtitle (24-28pt) |
| `### Heading 3` | Content subheader (20pt bold) |
| `- List item` | Bullet point (16pt) |
| `  - Nested item` | Indented bullet (14pt, indentLevel: 1) |
| `1. Numbered item` | Numbered list |
| `> Blockquote` | Speaker notes (NOT displayed on slide) |
| `**Bold text**` | Bold formatting |
| `*Italic text*` | Italic formatting |
| `![alt](path)` | Image placement |
| `---` (horizontal rule) | Slide separator |
| `` `code` `` | Monospace text (Consolas/Courier) |
| `| Table |` | Table element |
| Plain paragraph | Body text (16pt) |

### Slide Separator Logic

Slides are separated by:
1. `---` (horizontal rule) — explicit separator (highest priority)
2. `# Heading 1` — each H1 starts a new slide
3. If neither is present, split on `## Heading 2`

### Special First Slide

The first `# Heading` becomes the **title slide**:
- H1 text → Title (centered, 44pt)
- H2 text immediately after → Subtitle (centered, 24pt)
- Author/date from YAML frontmatter if present
- Dark or accent background (differs from content slides)

### Auto-Layout Selection

Based on content analysis of each slide:

| Content Pattern | Layout |
|---|---|
| Title + subtitle only | **Title Slide** (centered, large type) |
| Title + bullets (≤5) | **Standard Content** (title top, bullets below) |
| Title + 2 groups of bullets | **Two Column** (split left/right) |
| Title + image only | **Full Image** (image fills most of slide) |
| Title + image + bullets | **Image + Text** (60/40 split) |
| Title + table | **Table Slide** (title + centered table) |
| Title + single stat/number | **Big Number** (large stat callout) |
| Only a short phrase | **Section Divider** (centered, accent bg) |

### Image Handling

```markdown
![Chart showing revenue growth](revenue_chart.png)
```

- If the image path exists in `/mnt/user-data/uploads/`, use it
- If it's a URL, embed it
- Position: centered, max 70% of slide width
- Alt text → used as image caption (small text below)

### Speaker Notes

Blockquotes are converted to speaker notes, not displayed on slides:

```markdown
> Remember to mention the Q2 partnership announcement here
```

This becomes `slide.addNotes("Remember to mention the Q2 partnership announcement here")`

## Conversion Workflow

### Step 1: Parse the Markdown
- Detect input format (A, B, or C)
- Split into slide units
- Extract YAML frontmatter if present

### Step 2: Analyze Content
For each slide unit:
- Count bullets, images, tables
- Determine auto-layout
- Extract speaker notes
- Check content density (warn if >7 bullets)

### Step 3: Theme Selection
If no theme specified, ask the user or auto-select based on context:

| Context | Suggested Theme |
|---|---|
| Business/corporate | Midnight Executive (navy + ice blue) |
| Technology | Ocean Gradient (deep blue + teal) |
| Academic/research | Charcoal Minimal (charcoal + off-white) |
| Creative/design | Coral Energy (coral + gold) |
| Nature/sustainability | Forest & Moss (forest + moss green) |
| Healthcare/medical | Teal Trust (teal + seafoam) |

### Step 4: Generate PPTX

Use the built-in pptx skill's PptxGenJS workflow:

1. Read `/mnt/skills/public/pptx/pptxgenjs.md` for API reference
2. Create slides following the auto-layout mapping
3. Apply the selected theme colors consistently
4. Set font pairing from the pptx skill's typography guide
5. Run QA as specified in the pptx skill's SKILL.md

### Step 5: QA Verification

1. **Content check**: `python -m markitdown output.pptx` — verify all markdown content appears
2. **Visual check**: Convert to images and inspect for layout issues
3. **Speaker notes**: Verify blockquote content appears in notes
4. **Image placement**: Confirm all images render correctly

## Content Density Warnings

During conversion, warn the user if:
- A slide has more than 7 bullet points → suggest splitting
- Body text exceeds 50 words → suggest simplifying
- More than 20 slides total → suggest condensing
- No images in a 10+ slide deck → suggest adding visuals

## Example

**Input (Markdown):**

```markdown
---
title: "AI Strategy 2026"
author: "Product Team"
theme: ocean-gradient
---

# AI Strategy 2026
## Product Team | March 2026

---

# The AI market will reach $300B by 2028
- Current TAM: $200B (2025)
- CAGR: 35% through 2028
- Enterprise adoption accelerating

> Cite McKinsey Global AI Survey 2025

---

# Our platform captures 12% market share
- Vertical integration is key differentiator
- NPS: 72 (industry avg: 45)

![Market position](market_share.png)

---

# Three strategic priorities for 2026
## Platform | Enterprise | International

---

# Priority 1: Platform relaunch in Q2
- New API architecture
- 10x throughput improvement
- Backward compatibility maintained

---

# Conclusions
- $300B market, 12% share, growing
- Platform relaunch is the foundation
- Enterprise + international expansion in H2
```

**Output:** 6-slide PPTX with Ocean Gradient theme, proper layouts, speaker notes, and QA-verified visuals.
