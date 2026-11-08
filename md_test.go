package main

import (
	"strings"
	"testing"
)

func TestMarkdownSicher(t *testing.T) {
	for in, bad := range map[string]string{
		`<script>alert(1)</script>`:                      "<script",
		`<img src=x onerror=alert(1)>`:                   "<img",
		`[klick](javascript:alert(1))`:                   `href="javascript:`,
		`[x](JaVaScRiPt:alert(1))`:                       `href="javascript:`,
		`![bild](data:text/html;base64,PHNjcmlwdD4=)`:    `src="data:text/html`,
		"<a href=\"https://evil\" onclick=\"x()\">a</a>": "<a href=\"https://evil\"",
		`[a](https://example.org "\" onmouseover=x")`:    `" onmouseover=x"`,
	} {
		if out := string(renderMarkdown(in)); strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
			t.Errorf("%q → %s", in, out)
		}
	}
	out := string(renderMarkdown("Schritte:\n1. Öffnen\n2. **Speichern**\n\n```go\nfmt.Println(\"<b>\")\n```\n\nhttps://example.org"))
	for _, want := range []string{"<ol>", "<strong>Speichern</strong>", `<code class="language-go">`, "&lt;b&gt;", `rel="nofollow ugc noopener noreferrer"`, `href="https://example.org"`} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in %s", want, out)
		}
	}
	if p := plainText("**Fett** und `code`\n\n- a\n- b"); p != "Fett und code a b" {
		t.Errorf("plainText: %q", p)
	}
}
