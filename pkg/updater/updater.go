package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/nodexeus/sqd-agent/pkg/config"
)

// ReleaseInfo represents information about a release
type ReleaseInfo struct {
	Version     string    `json:"version"`
	URL         string    `json:"url"`
	ReleaseDate time.Time `json:"releaseDate"`
	SHA256      string    `json:"sha256"`
}

// Updater is responsible for updating the agent
type Updater struct {
	config     *config.Config
	httpClient *http.Client
	// This would be replaced with the actual repository URL
	releaseURL string
	// Current version of the agent
	currentVersion string
	// Path to the current executable
	executablePath string
}

// NewUpdater creates a new updater
func NewUpdater(cfg *config.Config) (*Updater, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	return &Updater{
		config:         cfg,
		httpClient:     &http.Client{Timeout: 60 * time.Second},
		releaseURL:     "https://api.github.com/repos/nodexeus/sqd-agent/releases/latest",
		currentVersion: "0.1.0", // This would be replaced with a version from build
		executablePath: execPath,
	}, nil
}

// CheckForUpdates checks if there's a new version available
func (u *Updater) CheckForUpdates(ctx context.Context) (*ReleaseInfo, bool, error) {
	if !u.config.AutoUpdate {
		return nil, false, nil
	}

	// Get latest release info
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.releaseURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("failed to get latest release: status code %d", resp.StatusCode)
	}

	// Parse response
	var releaseData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&releaseData); err != nil {
		return nil, false, fmt.Errorf("failed to parse release data: %w", err)
	}

	// Extract version from tag name
	tagName, ok := releaseData["tag_name"].(string)
	if !ok {
		return nil, false, fmt.Errorf("invalid release data: tag_name not found")
	}

	// Remove 'v' prefix if present
	version := tagName
	if len(tagName) > 0 && tagName[0] == 'v' {
		version = tagName[1:]
	}

	// Extract download URL for the current platform
	assets, ok := releaseData["assets"].([]interface{})
	if !ok {
		return nil, false, fmt.Errorf("invalid release data: assets not found")
	}

	// Look for the asset for the current platform
	var downloadURL string
	assetName := fmt.Sprintf("sqd-agent-%s-%s", runtime.GOOS, runtime.GOARCH)
	for _, asset := range assets {
		assetMap, ok := asset.(map[string]interface{})
		if !ok {
			continue
		}

		name, ok := assetMap["name"].(string)
		if !ok {
			continue
		}

		if name == assetName {
			downloadURL, ok = assetMap["browser_download_url"].(string)
			if !ok {
				return nil, false, fmt.Errorf("invalid asset data: browser_download_url not found")
			}
			break
		}
	}

	if downloadURL == "" {
		return nil, false, fmt.Errorf("no asset found for platform %s-%s", runtime.GOOS, runtime.GOARCH)
	}

	// Extract release date
	releaseDateStr, ok := releaseData["published_at"].(string)
	if !ok {
		return nil, false, fmt.Errorf("invalid release data: published_at not found")
	}

	releaseDate, err := time.Parse(time.RFC3339, releaseDateStr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid release date: %w", err)
	}

	// Create release info
	releaseInfo := &ReleaseInfo{
		Version:     version,
		URL:         downloadURL,
		ReleaseDate: releaseDate,
		SHA256:      "", // In a real implementation, this would be extracted from the release data
	}

	// Check if the version is newer
	isNewer := version != u.currentVersion

	return releaseInfo, isNewer, nil
}

// Update updates the agent to the given release
func (u *Updater) Update(ctx context.Context, release *ReleaseInfo) error {
	// Create a temporary directory for the download
	tempDir, err := os.MkdirTemp("", "sqd-agent-update")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Download the new version
	tempFilePath := filepath.Join(tempDir, "sqd-agent-new")
	if err := u.downloadFile(ctx, release.URL, tempFilePath); err != nil {
		return fmt.Errorf("failed to download new version: %w", err)
	}

	// Make the file executable
	if err := os.Chmod(tempFilePath, 0755); err != nil {
		return fmt.Errorf("failed to make file executable: %w", err)
	}

	// Replace the current executable
	// On Unix-like systems, we can't replace a running executable directly
	// So we'll move the new executable to a backup location and use a script to replace it on next start
	backupPath := u.executablePath + ".new"
	if err := os.Rename(tempFilePath, backupPath); err != nil {
		return fmt.Errorf("failed to move new executable: %w", err)
	}

	// Create a script to replace the executable on next start
	scriptPath := u.executablePath + ".update.sh"
	scriptContent := fmt.Sprintf(`#!/bin/sh
# Wait for the current process to exit
sleep 1
# Replace the executable
mv "%s" "%s"
# Remove this script
rm "%s"
`, backupPath, u.executablePath, scriptPath)

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to create update script: %w", err)
	}

	// Execute the script in the background
	cmd := exec.Command("sh", "-c", fmt.Sprintf("nohup %s > /dev/null 2>&1 &", scriptPath))
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start update script: %w", err)
	}

	return nil
}

// downloadFile downloads a file from the given URL to the given path
func (u *Updater) downloadFile(ctx context.Context, url, path string) error {
	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute the request
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download file: status code %d", resp.StatusCode)
	}

	// Create the file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy the response body to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
