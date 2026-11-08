package main

import (
	"bytes"
	"html"
	"html/template"
	"net/http"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// Markdown für Meldungen und Antworten: GitHub-Flavor (Tabellen, Aufgabenlisten, Durchstreichen,
// automatische Links), Zeilenumbrüche bleiben erhalten. Roh-HTML wird NICHT übernommen (goldmark
// maskiert es ohne WithUnsafe), gefährliche URLs (javascript:, data: …) verwirft der Renderer.
// Externe Bilder blockiert zusätzlich die CSP (img-src 'self').

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithASTTransformers(util.Prioritized(linkHardening{}, 100))),
	goldmark.WithRendererOptions(gmhtml.WithHardWraps()),
)

// linkHardening markiert alle Links als extern und nicht vertrauenswürdig.
type linkHardening struct{}

func (linkHardening) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n.(type) {
		case *ast.Link, *ast.AutoLink:
			n.SetAttributeString("rel", []byte("nofollow ugc noopener noreferrer"))
			n.SetAttributeString("target", []byte("_blank"))
		case *ast.Heading:
			// Überschriften in Beiträgen kleiner halten: # wird zu h3 usw.
			h := n.(*ast.Heading)
			if h.Level < 3 {
				h.Level = 3
			}
		}
		return ast.WalkContinue, nil
	})
}

func renderMarkdown(src string) template.HTML {
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return template.HTML("<p>" + template.HTMLEscapeString(src) + "</p>")
	}
	return template.HTML(buf.String()) // sicher: goldmark rendert ohne Roh-HTML
}

var (
	tagRe   = regexp.MustCompile(`<[^>]*>`)
	spaceRe = regexp.MustCompile(`\s+`)
)

// plainText liefert den reinen Text eines Markdown-Beitrags (für Auszüge in Listen und E-Mails).
func plainText(src string) string {
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return src
	}
	s := strings.NewReplacer("</p>", " ", "<br>", " ", "</li>", " ", "</pre>", " ").Replace(buf.String())
	s = html.UnescapeString(tagRe.ReplaceAllString(s, ""))
	return strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
}

func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	src := r.PostFormValue("text")
	if len(src) > 60000 {
		src = src[:60000]
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": string(renderMarkdown(src))})
}
