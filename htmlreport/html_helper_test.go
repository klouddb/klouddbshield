package htmlreport

import (
	"fmt"
	"os"
)

func ExampleHTMLHelper_Generate() {
	// Create an instance of HTMLHelper
	h := &HTMLHelper{}

	// Add tabs
	h.AddTab("HBA Scanner Report", `<p>This is the HBA Scanner Report content.</p>`)
	h.AddTab("Postgres Report", `<p>This is the Postgres Report content.</p>`)

	// Generate the HTML report
	filename := "test_report.html"
	perm := os.FileMode(0644)
	err := h.Generate(filename, perm)
	fmt.Println("error from helper", err)
}
