"""Build combined Worker with landing page (index.html) + tool.html routing."""


def escape_for_template(s):
    """Escape string for JS template literal."""
    s = s.replace('\\', '\\\\')
    s = s.replace('`', '\\`')
    s = s.replace('${', '\\${')
    return s


def build_receipt_ocr_worker(html_path, worker_template_path, output_path):
    """Build receipt-ocr Worker by embedding HTML into the worker template."""
    with open(html_path, 'r', encoding='utf-8') as f:
        html = f.read()

    with open(worker_template_path, 'r', encoding='utf-8') as f:
        worker_template = f.read()

    html_escaped = escape_for_template(html)
    worker = worker_template.replace('__HTML_PLACEHOLDER__', html_escaped)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(worker)

    print(f"Generated: {output_path}")
    print(f"  HTML: {len(html):,} bytes")
    print(f"  Total worker: {len(worker):,} bytes")


def build_worker(landing_html_path, tool_html_path, output_path, tool_link_absolute=False):
    """Build a Worker JS file that serves landing + tool pages."""
    with open(landing_html_path, 'r', encoding='utf-8') as f:
        landing_html = f.read()

    with open(tool_html_path, 'r', encoding='utf-8') as f:
        tool_html = f.read()

    # For mainpage, replace relative tool.html links with absolute URL
    if tool_link_absolute:
        landing_html = landing_html.replace(
            'href="tool.html"',
            'href="https://keiri-yayoi-freee.kaneda-ryota.workers.dev/tool.html"'
        )

    landing_escaped = escape_for_template(landing_html)
    tool_escaped = escape_for_template(tool_html)

    worker = (
        'export default {\n'
        '  async fetch(request) {\n'
        '    const url = new URL(request.url);\n'
        '    \n'
        '    if (url.pathname === "/tool.html" || url.pathname === "/tool") {\n'
        '      const toolHtml = `' + tool_escaped + '`;\n'
        '      return new Response(toolHtml, {\n'
        "        headers: { 'Content-Type': 'text/html;charset=UTF-8' },\n"
        '      });\n'
        '    }\n'
        '    \n'
        '    const html = `' + landing_escaped + '`;\n'
        '    return new Response(html, {\n'
        "      headers: { 'Content-Type': 'text/html;charset=UTF-8' },\n"
        '    });\n'
        '  },\n'
        '};\n'
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(worker)

    print(f"Generated: {output_path}")
    print(f"  Landing HTML: {len(landing_html):,} bytes")
    print(f"  Tool HTML: {len(tool_html):,} bytes")
    print(f"  Total worker: {len(worker):,} bytes")


if __name__ == '__main__':
    base = 'C:/02.Claude_Agent/907-plan'
    landing = f'{base}/business-agent/index.html'
    tool = f'{base}/business-agent/tool.html'

    # keiri-yayoi-freee (relative tool.html links)
    build_worker(
        landing, tool,
        f'{base}/workers/keiri-yayoi-freee/src/index.js',
        tool_link_absolute=False,
    )

    # keiri-kaizen-mainpage (absolute tool.html links)
    build_worker(
        landing, tool,
        f'{base}/workers/keiri-kaizen-mainpage/src/index.js',
        tool_link_absolute=True,
    )

    # keiri-receipt-ocr (HTML embedded into API worker)
    import os
    receipt_html = f'{base}/business-agent/receipt-ocr.html'
    template_src = f'{base}/workers/keiri-receipt-ocr/src/index.template.js'
    if not os.path.exists(template_src):
        print(f"ERROR: {template_src} not found")
        raise SystemExit(1)
    build_receipt_ocr_worker(
        receipt_html, template_src,
        f'{base}/workers/keiri-receipt-ocr/src/index.js',
    )

    # ocr-public (HTML embedded, no API proxy)
    ocr_public_html = f'{base}/business-agent/ocr-public.html'
    ocr_public_template = f'{base}/workers/ocr-public/src/index.template.js'
    if not os.path.exists(ocr_public_template):
        print(f"ERROR: {ocr_public_template} not found")
        raise SystemExit(1)
    build_receipt_ocr_worker(
        ocr_public_html, ocr_public_template,
        f'{base}/workers/ocr-public/src/index.js',
    )

    print("\nDone! All workers updated")
