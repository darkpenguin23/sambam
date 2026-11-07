//go:build !linux && !darwin && !windows

package osfs

import "errors"

func diskStats(path string) (diskUsage, error) {
	return diskUsage{}, errors.ErrUnsupported
}
