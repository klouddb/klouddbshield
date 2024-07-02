package htmlreport

import (
	"bytes"
	"embed"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"html/template"
	"io/fs"
	"strings"
)

var (
	//go:embed template/*.tmpl
	templates embed.FS

	tmpl = template.Must(template.New("*.tmpl").Funcs(template.FuncMap{
		"replace": func(s, old, new string) template.HTML {
			replaced := strings.ReplaceAll(s, old, new)
			return template.HTML(replaced)
		},
	}).ParseFS(templates, "template/*.tmpl"))
)

type Tab struct {
	Title   string
	Body    interface{}
	Prority int
}

var templateData = []Tab{}

// Render generates the HTML report file with the provided filename and permission.
func Render(filename string, perm fs.FileMode) (string, error) {
	if len(templateData) == 0 {
		return "", nil
	}

	output := bytes.NewBuffer(nil)

	sort.Slice(templateData, func(i, j int) bool {
		return templateData[i].Prority > templateData[j].Prority
	})

	err := tmpl.ExecuteTemplate(output, "html", templateData)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %v", err)
	}

	err = os.WriteFile(filename, output.Bytes(), perm)
	if err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return filepath.Abs(filename)
}

func CreateAllTab() {
	allTabData := []any{}
	for _, t := range templateData {
		allTabData = append(allTabData, t)
	}

	templateData = append(templateData, Tab{
		Title:   "All",
		Body:    allTabData,
		Prority: 10, // adding priority to make sure this tab is the last one
	})

	// remove postgres tab when we add all tab
	postgresIndex := -1
	for i, t := range templateData {
		if t.Title == "Postgres" {
			postgresIndex = i
			break
		}
	}

	if postgresIndex != -1 {
		templateData = append(templateData[:postgresIndex], templateData[postgresIndex+1:]...)
	}
}
