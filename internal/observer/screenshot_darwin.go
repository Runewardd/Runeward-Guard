//go:build darwin

package observer

import (
	"context"
	"os/exec"
	"time"
)

const screenshotAttribute = "com.apple.metadata:kMDItemIsScreenCapture"

// AppleScreenshot checks a file's screenshot metadata without reading pixels.
// The marker is useful evidence, but can be copied or forged by a local user.
func AppleScreenshot(parent context.Context, path string) bool {
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/xattr", "-p", screenshotAttribute, path)
	return cmd.Run() == nil
}
