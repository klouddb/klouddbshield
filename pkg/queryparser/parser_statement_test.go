package queryparser

import "testing"

func TestParseSqlQuery(t *testing.T) {
	queries := []string{
		"SELECT * FROM users WHERE id = ? AND username = 'new user' OR (password is null and email = 'prince.soamedia@gmail.com' and phone like '?')",
		"UPDATE users SET username = 'admin' WHERE id = 1",
		"DELETE FROM users WHERE id = 1",
		"INSERT INTO users (username) VALUES ('admin'), ('new user'), ('another user')",
	}

	for _, query := range queries {
		out, err := ParseSqlQuery(query)
		if err != nil {
			t.Errorf("Error parsing query: %s", err)
		}

		if out == nil || len(out.v) == 0 {
			t.Errorf("Output is nil")
		}

		for _, kv := range out.v {
			if kv.Column == "" || len(kv.Value) == 0 {
				t.Errorf("Invalid key value pair")
			}

			t.Logf("Column: %s, Value: %s", kv.Column, string(kv.Value))
		}

	}
}
