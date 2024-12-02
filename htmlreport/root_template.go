package htmlreport

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"html/template"
	"io/fs"
	"strings"

	"github.com/google/uuid"
)

var (
	//go:embed template/*.tmpl
	templates embed.FS

	tmpl = template.Must(template.New("*.tmpl").Funcs(template.FuncMap{
		"replace": func(s, old, new string) template.HTML {
			replaced := strings.ReplaceAll(s, old, new)
			return template.HTML(replaced)
		},
		"toJson": func(v interface{}) (template.JS, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return template.JS(b), nil
		},
		"isGreater": func(x, y float32) bool {
			return x > y
		},
		"add": func(x, y int) int {
			return x + y
		},
		"randomString": func() string {
			uid, err := uuid.NewRandom()
			if err != nil {
				return ""
			}

			return uid.String()
		},
		"join":  strings.Join,
		"split": strings.Split,
	}).ParseFS(templates, "template/*.tmpl"))
)

func RenderTemplateFile(templateName, outputfile string, data interface{}, perm fs.FileMode) (string, error) {
	output := bytes.NewBuffer(nil)

	err := tmpl.ExecuteTemplate(output, templateName, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %v", err)
	}

	err = os.WriteFile(outputfile, output.Bytes(), perm)
	if err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return filepath.Abs(outputfile)
}

type Tab struct {
	Title   string
	Body    interface{}
	Prority int
}

type HtmlReportHelperMap map[string]*HtmlReportHelper

func NewHtmlReportHelperMap() HtmlReportHelperMap {
	return HtmlReportHelperMap{}
}

func (m HtmlReportHelperMap) Get(key string) *HtmlReportHelper {
	if m == nil {
		m = make(HtmlReportHelperMap)
	}
	if _, ok := m[key]; !ok {
		m[key] = NewHtmlReportHelper()
	}

	return m[key]
}

type HtmlReportHelper struct {
	templateData []Tab
}

func NewHtmlReportHelper() *HtmlReportHelper {
	return &HtmlReportHelper{}
}

func (h *HtmlReportHelper) AddTab(title string, body interface{}) {
	if h == nil {
		return
	}
	h.templateData = append(h.templateData, Tab{
		Title: title,
		Body:  body,
	})
}

func (h *HtmlReportHelper) Reset() {
	if h == nil {
		return
	}

	h.templateData = []Tab{}
}

// Render generates the HTML report file with the provided filename and permission.
func (h *HtmlReportHelper) RenderInfile(filename string, perm fs.FileMode) (string, error) {

	// b, _ := json.Marshal(h.templateData)
	// fmt.Println(string(b))
	data, err := h.Render()
	if err != nil {
		return "", fmt.Errorf("failed to render html: %v", err)
	}

	if len(data) == 0 {
		return "", nil
	}

	err = os.WriteFile(filename, data, perm)
	if err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}

	return filepath.Abs(filename)
}

func (h *HtmlReportHelper) Render() ([]byte, error) {
	if h == nil || len(h.templateData) == 0 {
		return nil, nil
	}

	output := bytes.NewBuffer(nil)

	sort.Slice(h.templateData, func(i, j int) bool {
		return h.templateData[i].Prority > h.templateData[j].Prority
	})

	err := tmpl.ExecuteTemplate(output, "html", h.templateData)
	if err != nil {
		return nil, fmt.Errorf("failed to execute template: %v", err)
	}

	return output.Bytes(), nil
}

func (h *HtmlReportHelper) CreateAllTab() {
	if h == nil {
		return
	}

	allTabData := []any{}
	for _, t := range h.templateData {
		allTabData = append(allTabData, t)
	}

	if len(allTabData) == 0 {
		return
	}

	h.templateData[0] = Tab{
		Title:   "All",
		Body:    allTabData,
		Prority: 10, // adding priority to make sure this tab is the last one
	}
}
