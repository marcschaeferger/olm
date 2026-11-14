//go:build freebsd

package dns

import "errors"

// IsSystemdResolvedAvailable always reports false on FreeBSD, which has no
// systemd-resolved.
func IsSystemdResolvedAvailable() bool {
	return false
}

// NewSystemdResolvedDNSConfigurator is not supported on FreeBSD.
func NewSystemdResolvedDNSConfigurator(ifaceName string) (DNSConfigurator, error) {
	return nil, errors.New("systemd-resolved is not available on freebsd")
}
