package htmlreport

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"strings"
)

type HTMLHelper struct {
	tabs []tab
}

type tab struct {
	name string
	body string
}

// AddTab adds a new tab with the specified name and body content.
func (h *HTMLHelper) AddTab(name, body string) {
	newTab := tab{
		name: name,
		body: body,
	}
	h.tabs = append(h.tabs, newTab)
}

// Generate generates the HTML report file with the provided filename and permission.
func (h *HTMLHelper) Generate(filename string, perm fs.FileMode) error {
	if h == nil || len(h.tabs) == 0 {
		return nil
	}

	tabsHTML := ""
	contentHTML := ""
	for i, tab := range h.tabs {
		class := ""
		if i == 0 {
			class = "active"
		}
		tabHeader := fmt.Sprintf(tabLink, class, strings.ReplaceAll(tab.name, " ", ""), tab.name)
		tabsHTML += tabHeader

		tabContent := fmt.Sprintf(tabContent, strings.ReplaceAll(tab.name, " ", ""), class, tab.body)
		contentHTML += tabContent
	}

	// Combine all HTML components
	finalHTML := fmt.Sprintf(html, tabsHTML, contentHTML)

	// Write HTML to file
	return ioutil.WriteFile(filename, []byte(finalHTML), perm)

}
