package hbarules

import (
	"net"
	"testing"
)

func Test_IPAddressValidatorWithSubnet(t *testing.T) {

	tests := []struct {
		name    string
		subnet  string
		address string
		want    bool
		err     error
	}{
		{
			name:    "valid ip address with mask 24",
			subnet:  "192.168.0.1/24",
			address: "192.168.0.10",
			want:    true,
			err:     nil,
		},
		{
			name:    "valid ip address with mask 32",
			subnet:  "192.168.0.1/32",
			address: "192.168.0.1",
			want:    true,
			err:     nil,
		},
		{
			name:    "invalid ip address with mask 24",
			subnet:  "192.168.0.1/24",
			address: "192.168.1.10",
			want:    false,
			err:     nil,
		},
		{
			name:    "invalid ip address with mask 32",
			subnet:  "192.168.0.1/32",
			address: "192.168.0.2",
			want:    false,
			err:     nil,
		},
		{
			name:    "not parsable ip address with mask 32",
			subnet:  "192.168.0.1/32",
			address: ".example.com",
			want:    false,
			err:     nil,
		},
		{
			name:    "not parsable subnet",
			subnet:  "",
			address: ".example.com",
			want:    false,
			err:     net.InvalidAddrError("invalid CIDR address: "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipnet, err := GetIPnetFromSubnet(tt.subnet)

			// compare err with tt.err
			switch {
			case err == nil && tt.err != nil:
				t.Errorf("Expected error: %v, Got: nil", tt.err)
			case err != nil && tt.err == nil:
				t.Errorf("Unexpected error: %v", err)
			case err != nil && tt.err != nil && err.Error() != tt.err.Error():
				t.Errorf("Unexpected error. Expected: %v, Got: %v", tt.err, err)
			}

			validator := NewIPAddressValidator(ipnet)
			if got := validator.IsValid(tt.address); got != tt.want {
				t.Errorf("IPAddressValidator.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_IPAddressValidatorWithIpandMask(t *testing.T) {

	tests := []struct {
		name    string
		ip      string
		mask    string
		address string
		want    bool
		err     error
	}{
		{
			name:    "valid ip address with mask 32",
			ip:      "127.0.0.1",
			mask:    "0.0.0.0",
			address: "127.0.0.1",
			want:    true,
			err:     nil,
		},
		{
			name:    "allow any ip address with mask 0",
			ip:      "127.0.0.1",
			mask:    "255.255.255.255",
			address: "192.168.1.0",
			want:    false,
			err:     nil,
		},
		{
			name:    "invalid ip address with mask 24",
			ip:      "127.0.0.1",
			mask:    "255.255.255.0",
			address: "127.0.1.0",
			want:    false,
			err:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipnet, err := GetIPnetFromIPAndMask(tt.ip, tt.mask)

			// compare err with tt.err
			switch {
			case err == nil && tt.err != nil:
				t.Errorf("Expected error: %v, Got: nil", tt.err)
			case err != nil && tt.err == nil:
				t.Errorf("Unexpected error: %v", err)
			case err != nil && tt.err != nil && err.Error() != tt.err.Error():
				t.Errorf("Unexpected error. Expected: %v, Got: %v", tt.err, err)
			}

			validator := NewIPAddressValidator(ipnet)
			if got := validator.IsValid(tt.address); got != tt.want {
				t.Errorf("IPAddressValidator.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
