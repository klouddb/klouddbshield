package hbarules

import (
	"net"
	"strings"
)

type AddressValidator interface {
	IsValid(string) bool
}

type hostAddressValidator struct {
	host string
}

func NewHostAddressValidator(host string) AddressValidator {
	return &hostAddressValidator{
		host: host,
	}
}

func (h *hostAddressValidator) IsValid(address string) bool {
	return strings.Contains(address, h.host)
}

type ipAddressValidator struct {
	ipnet *net.IPNet
}

func NewIPAddressValidator(ipnet *net.IPNet) AddressValidator {
	return &ipAddressValidator{
		ipnet: ipnet,
	}
}

func (i *ipAddressValidator) IsValid(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}

	return i.ipnet.Contains(ip)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// Helper functions for ip validator //////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// GetIPnetFromSubnet creates net.IPNet from subnet
func GetIPnetFromSubnet(subnet string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	return ipnet, err
}

// GetIPnetFromIPAndMask creates net.IPNet from ip and mask
// here ip is 192.168.0.1 and mask is 255.255.255.0
func GetIPnetFromIPAndMask(ip, mask string) (*net.IPNet, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return nil, net.InvalidAddrError("invalid ip address : " + ip)
	}

	maskAddr := net.ParseIP(mask)
	if maskAddr == nil {
		return nil, net.InvalidAddrError("invalid mask address : " + mask)
	}

	return &net.IPNet{
		IP:   ipAddr,
		Mask: net.IPMask(maskAddr),
	}, nil
}
