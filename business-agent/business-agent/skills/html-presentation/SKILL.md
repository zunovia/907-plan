---
name: html-presentation
description: "Use this skill when the user wants to create a web-based presentation, HTML slides, or a rich interactive slide deck. Triggers on: 'HTML presentation', 'web slides', 'interactive presentation', 'HTML deck', 'web-based slides', 'animated slides', 'rich presentation', or when the user wants slides with animations, transitions, hover effects, or interactive elements that go beyond what PowerPoint can do. Output is a single self-contained HTML file. Do NOT use for .pptx file creation — use the built-in pptx skill instead."
---

# HTML Presentation Skill

Create stunning, animation-rich web presentations as single self-contained HTML files. Zero dependencies, no frameworks, no build tools.

## Philosophy

- **Show, don't tell** — generate visual style previews rather than asking users to describe aesthetics in words
- **Anti-AI-slop** — avoid generic purple gradients, bland layouts, and cookie-cutter designs
- **Single HTML file** — everything inline (CSS + JS). Works forever, no npm, no build tools
- **Every deck should feel custom-crafted** — not templated

## Workflow

### Step 1: Understand the Content
Ask the user about:
- Topic and key messages (what story are the slides telling?)
- Audience (investors, engineers, students, executives?)
- Number of slides (default: 8-12)
- Any existing content to incorporate (text, data, images)

### Step 2: Style Discovery
Unless the user specifies a style, generate **2-3 visual style options** as brief descriptions with color palettes and mood. Let the user pick.

**Style presets for inspiration** (never copy exactly — customize for context):

| Style | Mood | Colors | Typography |
|---|---|---|---|
| **Midnight Editorial** | Premium, authoritative | Near-black bg, cream text, gold accent | Serif headers + sans body |
| **Neon Terminal** | Tech-forward, hacker aesthetic | Black bg, green/cyan glow, monospace | Monospace throughout |
| **Paper & Ink** | Academic, thoughtful | Off-white bg, charcoal text, red accent | Serif with generous spacing |
| **Glass Morphism** | Modern, layered | Translucent panels, gradient bg, white text | Clean sans-serif |
| **Brutalist** | Bold, raw, unapologetic | High contrast, thick borders, primary colors | Impact/bold condensed |
| **Warm Minimal** | Calm, approachable | Warm white bg, earth tones, subtle shadows | Rounded sans-serif |
| **Retro CRT** | Nostalgic, playful | Dark bg, scanlines, phosphor green/amber | Pixel/monospace fonts |
| **Magazine Spread** | Editorial, photographic | White bg, dramatic type scale, thin rules | Display serif + tight sans |

### Step 3: Generate the HTML Presentation

Create a single HTML file with all CSS and JS inline.

#### Required Structure

```html
<!DOCTYPE html>
<html lang="ja"> <!-- or appropriate language -->
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>[Presentation Title]</title>
  <style>
    /* All styles inline */
  </style>
</head>
<body>
  <div class="presentation">
    <div class="slide" id="slide-1"> ... </div>
    <div class="slide" id="slide-2"> ... </div>
    <!-- ... -->
  </div>
  <div class="controls">
    <button class="prev">←</button>
    <span class="slide-counter">1 / N</span>
    <button class="next">→</button>
  </div>
  <script>
    // All JS inline
  </script>
</body>
</html>
```

#### Required Features

1. **Keyboard navigation** — Left/Right arrows, Space for next
2. **Click/touch navigation** — Previous/Next buttons + swipe on mobile
3. **Slide counter** — "3 / 12" display
4. **Smooth transitions** — between slides (fade, slide, or custom)
5. **Responsive** — works on any screen size
6. **Progress indicator** — thin bar at top showing position

#### Animation Patterns

Use CSS animations and transitions. Stagger entry animations on each slide's elements:

```css
/* Staggered entrance */
.slide.active .element-1 { animation: fadeInUp 0.6s ease forwards; animation-delay: 0.1s; }
.slide.active .element-2 { animation: fadeInUp 0.6s ease forwards; animation-delay: 0.25s; }
.slide.active .element-3 { animation: fadeInUp 0.6s ease forwards; animation-delay: 0.4s; }

/* Useful keyframes */
@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(30px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes fadeInLeft {
  from { opacity: 0; transform: translateX(-40px); }
  to { opacity: 1; transform: translateX(0); }
}

@keyframes scaleIn {
  from { opacity: 0; transform: scale(0.9); }
  to { opacity: 1; transform: scale(1); }
}

@keyframes typeWriter {
  from { width: 0; }
  to { width: 100%; }
}
```

#### Interactive Elements (Optional Enhancements)

- **Hover reveals** — additional detail on hover
- **Animated counters** — numbers that count up when slide becomes active
- **Interactive charts** — CSS-only bar/pie charts with hover tooltips
- **Parallax backgrounds** — subtle movement on mouse move
- **Code blocks** — with syntax highlighting for tech presentations
- **Dark/light toggle** — let the presenter switch modes

## Design Rules

### Typography
- Use Google Fonts via `@import` or system fonts for offline
- Title slides: 4-6rem (bold, dramatic)
- Section headers: 2.5-3.5rem
- Body text: 1.2-1.6rem
- Minimum line-height: 1.5 for body text
- Max 60ch per line for readability

### Color
- Choose ONE dominant color (60-70% of visual weight)
- ONE accent color for emphasis
- Use CSS custom properties for the entire palette:
```css
:root {
  --bg-primary: #0a0a0f;
  --bg-secondary: #1a1a2e;
  --text-primary: #e8e8f0;
  --text-secondary: #8888a0;
  --accent: #6366f1;
  --accent-glow: rgba(99, 102, 241, 0.3);
}
```

### Layout Per Slide
- **Title slide**: Centered, dramatic type, minimal elements
- **Content slides**: Max 3-5 key points, generous whitespace
- **Data slides**: One visualization, clearly labeled
- **Quote slides**: Large text, attribution below
- **Image slides**: Full-bleed or large with minimal overlay text
- **Closing slide**: Key takeaway, contact/next steps

### Things to AVOID
- Bullet-point-heavy slides (use visual layout instead)
- More than 5 lines of text per slide
- Small fonts (nothing under 1rem)
- Conflicting animations (keep it cohesive)
- Generic stock photo backgrounds
- Purple gradients on white (the hallmark of AI slop)

## Output

Save the HTML file to `/mnt/user-data/outputs/presentation.html` (or a descriptive filename).

The file should:
- Be completely self-contained (no external dependencies except optional Google Fonts)
- Work by opening directly in a browser
- Print cleanly (add `@media print` styles)
- Be under 500KB total

## PPTX Conversion Note

If the user later wants a .pptx version, the HTML can serve as a design reference. Use the built-in pptx skill to recreate the content in PowerPoint format, matching colors and layout as closely as possible.
