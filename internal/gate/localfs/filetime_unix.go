// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
