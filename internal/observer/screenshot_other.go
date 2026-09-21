//go:build !darwin

package observer

import "context"

func AppleScreenshot(context.Context, string) bool { return false }
