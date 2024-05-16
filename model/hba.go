package model

type HBAFIleRules struct {
	LineNumber int    `json:"line_number"`
	Database   string `json:"database"`
	UserName   string `json:"user_name"`
	Address    string `json:"address"`
	NetMask    string `json:"netmask"`
}
