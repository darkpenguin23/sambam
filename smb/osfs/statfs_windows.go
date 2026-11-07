package osfs

import "golang.org/x/sys/windows"

// diskStats reports the size of the volume holding path in 4 KiB units.
func diskStats(path string) (s diskUsage, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return s, err
	}
	var availToCaller, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &availToCaller, &total, &totalFree); err != nil {
		return s, err
	}
	const bs = 4096
	return diskUsage{
		blockSize: bs,
		blocks:    total / bs,
		free:      totalFree / bs,
		avail:     availToCaller / bs,
		files:     1000000,
		freeFiles: 1000000,
	}, nil
}
