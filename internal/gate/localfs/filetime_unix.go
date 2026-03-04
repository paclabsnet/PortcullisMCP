//go:build !windows

package localfs

import (
	"os"
	"time"
)

// fileCreationTime returns the best available approximation of file creation
// time on Unix systems. Most Unix filesystems don't expose birthtime via the
// standard stat interface, so we fall back to ModTime.
func fileCreationTime(info os.FileInfo) time.Time {
	return info.ModTime()
}
