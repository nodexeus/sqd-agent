package discovery

import (
	"context"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
)

// execCommand executes a shell command with timeout and proper error handling
func execCommand(ctx context.Context, command string, timeout time.Duration) (string, string, error) {
	// Create context with timeout if specified
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	log.Debugf("Executing command: %s", command)
	
	// Create command with context
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	
	// Execute and capture output
	stdout, err := cmd.Output()
	stderr := ""
	
	if err != nil {
		// Try to get stderr from ExitError
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr = string(exitError.Stderr)
		}
		log.Debugf("Command failed: %v, stderr: %s", err, stderr)
		return string(stdout), stderr, err
	}
	
	log.Debugf("Command completed successfully")
	return string(stdout), stderr, nil
}