package postgresdb

import (
	"testing"
)

func TestBuildConnectionString(t *testing.T) {
	tests := []struct {
		name     string
		config   Postgres
		expected string
	}{
		{
			name: "Basic connection without SSL",
			config: Postgres{
				Host:     "localhost",
				Port:     "5432",
				User:     "postgres",
				Password: "password",
				DBName:   "testdb",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=disable",
		},
		{
			name: "Connection with SSL mode enabled",
			config: Postgres{
				Host:     "localhost",
				Port:     "5432",
				User:     "postgres",
				Password: "password",
				DBName:   "testdb",
				SSLmode:  "require",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=require",
		},
		{
			name: "Connection with SSL certificates",
			config: Postgres{
				Host:        "localhost",
				Port:        "5432",
				User:        "postgres",
				Password:    "password",
				DBName:      "testdb",
				SSLmode:     "verify-full",
				SSLcert:     "/path/to/client.crt",
				SSLkey:      "/path/to/client.key",
				SSLrootcert: "/path/to/root.crt",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=verify-full sslcert=/path/to/client.crt sslkey=/path/to/client.key sslrootcert=/path/to/root.crt",
		},
		{
			name: "Connection with partial SSL certificates",
			config: Postgres{
				Host:     "localhost",
				Port:     "5432",
				User:     "postgres",
				Password: "password",
				DBName:   "testdb",
				SSLmode:  "require",
				SSLcert:  "/path/to/client.crt",
				SSLkey:   "/path/to/client.key",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=require sslcert=/path/to/client.crt sslkey=/path/to/client.key",
		},
		{
			name: "Connection with empty SSL mode defaults to disable",
			config: Postgres{
				Host:     "localhost",
				Port:     "5432",
				User:     "postgres",
				Password: "password",
				DBName:   "testdb",
				SSLmode:  "",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=disable",
		},
		{
			name: "Connection with SSL certificates but no SSL mode",
			config: Postgres{
				Host:        "localhost",
				Port:        "5432",
				User:        "postgres",
				Password:    "password",
				DBName:      "testdb",
				SSLcert:     "/path/to/client.crt",
				SSLkey:      "/path/to/client.key",
				SSLrootcert: "/path/to/root.crt",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=disable sslcert=/path/to/client.crt sslkey=/path/to/client.key sslrootcert=/path/to/root.crt",
		},
		{
			name: "Connection with special characters in password",
			config: Postgres{
				Host:     "localhost",
				Port:     "5432",
				User:     "postgres",
				Password: "pass@word#123",
				DBName:   "testdb",
				SSLmode:  "require",
			},
			expected: "host=localhost port=5432 user=postgres password=pass@word#123 dbname=testdb sslmode=require",
		},
		{
			name: "Connection with IPv6 host",
			config: Postgres{
				Host:     "::1",
				Port:     "5432",
				User:     "postgres",
				Password: "password",
				DBName:   "testdb",
				SSLmode:  "require",
			},
			expected: "host=::1 port=5432 user=postgres password=password dbname=testdb sslmode=require",
		},
		{
			name: "Connection with custom port",
			config: Postgres{
				Host:     "localhost",
				Port:     "5433",
				User:     "postgres",
				Password: "password",
				DBName:   "testdb",
				SSLmode:  "require",
			},
			expected: "host=localhost port=5433 user=postgres password=password dbname=testdb sslmode=require",
		},
		{
			name: "Connection with all SSL modes",
			config: Postgres{
				Host:        "localhost",
				Port:        "5432",
				User:        "postgres",
				Password:    "password",
				DBName:      "testdb",
				SSLmode:     "prefer",
				SSLcert:     "/path/to/client.crt",
				SSLkey:      "/path/to/client.key",
				SSLrootcert: "/path/to/root.crt",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=prefer sslcert=/path/to/client.crt sslkey=/path/to/client.key sslrootcert=/path/to/root.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildConnectionString(tt.config)
			if result != tt.expected {
				t.Errorf("BuildConnectionString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuildConnectionString_SSLModeVariations(t *testing.T) {
	baseConfig := Postgres{
		Host:     "localhost",
		Port:     "5432",
		User:     "postgres",
		Password: "password",
		DBName:   "testdb",
	}

	sslModes := []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}

	for _, mode := range sslModes {
		t.Run("SSL mode: "+mode, func(t *testing.T) {
			config := baseConfig
			config.SSLmode = mode

			result := BuildConnectionString(config)
			expected := "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=" + mode

			if result != expected {
				t.Errorf("BuildConnectionString() with sslmode=%s = %v, want %v", mode, result, expected)
			}
		})
	}
}

func TestBuildConnectionString_EmptyValues(t *testing.T) {
	tests := []struct {
		name     string
		config   Postgres
		expected string
	}{
		{
			name: "Empty SSL certificates should not be included",
			config: Postgres{
				Host:        "localhost",
				Port:        "5432",
				User:        "postgres",
				Password:    "password",
				DBName:      "testdb",
				SSLmode:     "require",
				SSLcert:     "",
				SSLkey:      "",
				SSLrootcert: "",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=require",
		},
		{
			name: "Mixed empty and non-empty SSL certificates",
			config: Postgres{
				Host:        "localhost",
				Port:        "5432",
				User:        "postgres",
				Password:    "password",
				DBName:      "testdb",
				SSLmode:     "require",
				SSLcert:     "/path/to/client.crt",
				SSLkey:      "",
				SSLrootcert: "/path/to/root.crt",
			},
			expected: "host=localhost port=5432 user=postgres password=password dbname=testdb sslmode=require sslcert=/path/to/client.crt sslrootcert=/path/to/root.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildConnectionString(tt.config)
			if result != tt.expected {
				t.Errorf("BuildConnectionString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuildConnectionString_OrderConsistency(t *testing.T) {
	// Test that the connection string parameters are always in the same order
	config := Postgres{
		Host:        "localhost",
		Port:        "5432",
		User:        "postgres",
		Password:    "password",
		DBName:      "testdb",
		SSLmode:     "require",
		SSLcert:     "/path/to/client.crt",
		SSLkey:      "/path/to/client.key",
		SSLrootcert: "/path/to/root.crt",
	}

	// Run the function multiple times to ensure consistent ordering
	results := make([]string, 5)
	for i := 0; i < 5; i++ {
		results[i] = BuildConnectionString(config)
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Errorf("BuildConnectionString() returned inconsistent results: %v vs %v", results[0], results[i])
		}
	}
}

func TestBuildConnectionString_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name     string
		config   Postgres
		expected string
	}{
		{
			name: "Production-like configuration",
			config: Postgres{
				Host:        "prod-db.example.com",
				Port:        "5432",
				User:        "app_user",
				Password:    "secure_password_123",
				DBName:      "production_db",
				SSLmode:     "verify-full",
				SSLcert:     "/etc/ssl/certs/client.crt",
				SSLkey:      "/etc/ssl/private/client.key",
				SSLrootcert: "/etc/ssl/certs/ca-bundle.crt",
			},
			expected: "host=prod-db.example.com port=5432 user=app_user password=secure_password_123 dbname=production_db sslmode=verify-full sslcert=/etc/ssl/certs/client.crt sslkey=/etc/ssl/private/client.key sslrootcert=/etc/ssl/certs/ca-bundle.crt",
		},
		{
			name: "Development configuration",
			config: Postgres{
				Host:     "localhost",
				Port:     "5432",
				User:     "dev_user",
				Password: "dev_password",
				DBName:   "dev_db",
				SSLmode:  "disable",
			},
			expected: "host=localhost port=5432 user=dev_user password=dev_password dbname=dev_db sslmode=disable",
		},
		{
			name: "Docker container configuration",
			config: Postgres{
				Host:     "postgres-container",
				Port:     "5432",
				User:     "postgres",
				Password: "docker_password",
				DBName:   "app_db",
				SSLmode:  "prefer",
			},
			expected: "host=postgres-container port=5432 user=postgres password=docker_password dbname=app_db sslmode=prefer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildConnectionString(tt.config)
			if result != tt.expected {
				t.Errorf("BuildConnectionString() = %v, want %v", result, tt.expected)
			}
		})
	}
}
