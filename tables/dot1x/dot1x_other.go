//go:build !darwin && !windows

package dot1x

import (
	"fmt"
	"strconv"
)

func newBackend() Dot1XBackend {
	return noopBackend{}
}

type noopBackend struct{}

func (noopBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	return Dot1XStatus{Interface: ifname}, fmt.Errorf("%w: not supported on this platform", ErrBackendUnavailable)
}

func defaultInterfaces() []string {
	ifaces := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		ifaces = append(ifaces, "en"+strconv.Itoa(i))
	}
	return ifaces
}
