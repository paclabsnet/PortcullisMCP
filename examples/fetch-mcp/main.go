package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/html"
)

type fetchInput struct {
	URL    string `json:"url"`
	Format string `json:"format,omitempty"` // "text" (default) or "html"
}

func handleFetch(_ context.Context, _ *mcp.CallToolRequest, in fetchInput) (*mcp.CallToolResult, any, error) {
	if in.URL == "" {
		return nil, nil, fmt.Errorf("url is required")
	}
	if in.Format == "" {
		in.Format = "text"
	}

	resp, err := http.Get(in.URL) //nolint:noctx
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %q: %w", in.URL, err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 1<<20) // 1 MB cap

	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(contentType, "text/html")

	var text string
	if in.Format == "html" || !isHTML {
		body, err := io.ReadAll(limited)
		if err != nil {
			return nil, nil, fmt.Errorf("read response: %w", err)
		}
		text = string(body)
	} else {
		text, err = htmlToText(limited)
		if err != nil {
			// Fall back to raw if parsing fails
			body, _ := io.ReadAll(limited)
			text = string(body)
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}, nil, nil
}

// htmlToText converts HTML to plain text by walking the parse tree.
// script, style, head, and noscript elements are skipped entirely.
// Block-level elements get surrounding newlines to preserve structure.
func htmlToText(r io.Reader) (string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			buf.WriteString(n.Data)
			return
		case html.ElementNode:
			tag := strings.ToLower(n.Data)
			switch tag {
			case "script", "style", "head", "noscript":
				return // skip entirely
			}
			// Newline before block elements
			switch tag {
			case "p", "div", "br", "h1", "h2", "h3", "h4", "h5", "h6",
				"li", "tr", "blockquote", "pre", "article", "section",
				"header", "footer", "main", "nav", "aside":
				buf.WriteByte('\n')
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
			// Newline after block elements
			switch tag {
			case "p", "h1", "h2", "h3", "h4", "h5", "h6",
				"li", "blockquote", "pre", "article", "section":
				buf.WriteByte('\n')
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	// Collapse runs of 3+ newlines down to 2
	text := buf.String()
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(text), nil
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "fetch-mcp",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "fetch_url",
		Description: "Fetch the contents of a URL. " +
			"For HTML pages, use format=\"text\" (default) to receive clean readable text with scripts, styles, and markup removed — " +
			"much smaller than raw HTML and suitable for reading articles, documentation, or any page where you need the content. " +
			"Use format=\"html\" when you need the raw HTML structure, such as when scraping data from tables or parsing specific elements. " +
			"Non-HTML responses (JSON, plain text, XML, etc.) are always returned as-is regardless of format.",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"url": {
					Type:        "string",
					Description: "The URL to fetch",
				},
				"format": {
					Type:        "string",
					Description: "Response format. \"text\" (default): strips HTML to clean readable text. \"html\": returns raw HTML.",
					Enum:        []any{"text", "html"},
				},
			},
			Required: []string{"url"},
		},
	}, handleFetch)

	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, nil)

	http.Handle("/mcp", handler)

	log.Printf("fetch-mcp listening on %s/mcp", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}
