package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v45/github"
	log "github.com/sirupsen/logrus"
)

// ReleaseInfo represents information about a release
type ReleaseInfo struct {
	Version     string    `json:"version"`
	URL         string    `json:"url"`
	ReleaseDate time.Time `json:"releaseDate"`
	SHA256      string    `json:"sha256"`
	IsDebian    bool      `json:"isDebian"`
}

// Updater is responsible for updating the agent
type Updater struct {
	httpClient     *http.Client
	githubClient   *github.Client
	releaseURL     string
	currentVersion string
	executablePath string
	owner          string
	repo           string
}

// NewUpdater creates a new updater
func NewUpdater(currentVersion string) (*Updater, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	return &Updater{
		httpClient:     &http.Client{Timeout: 60 * time.Second},
		githubClient:   github.NewClient(nil),
		releaseURL:     "https://api.github.com/repos/nodexeus/sqd-agent/releases/latest",
		currentVersion: currentVersion,
		executablePath: execPath,
		owner:          "nodexeus",
		repo:           "sqd-agent",
	}, nil
}

// IsDebianPackage checks if the application was installed via Debian package
func (u *Updater) IsDebianPackage() bool {
	// Check for the existence of the debian control file
	if _, err := os.Stat("/var/lib/dpkg/info/sqd-agent.list"); err == nil {
		log.Infof("Found Debian package for sqd-agent")
		return true
	}
	// Alternative check for dpkg status
	cmd := exec.Command("dpkg-query", "-W", "--showformat=${Status}", "sqd-agent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "install ok installed")
}

// CheckForUpdates checks if there's a new version available
func (u *Updater) CheckForUpdates() (*ReleaseInfo, error) {
	if u.IsDebianPackage() {
		log.Infof("Checking for Debian updates")
		return u.checkDebianUpdate()
	}
	log.Infof("Checking for GitHub updates")
	return u.checkGitHubUpdate()
}

// checkDebianUpdate checks for updates using apt
func (u *Updater) checkDebianUpdate() (*ReleaseInfo, error) {
	// Get current installed version
	cmd := exec.Command("dpkg-query", "--showformat=${Version}", "--show", "sqd-agent")
	currentVersion, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get current package version: %v", err)
	}

	// Check for updates
	updateCmd := exec.Command("apt-get", "update", "-qq")
	if err := updateCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to update package list: %v", err)
	}

	// Check upgradeable packages
	upgradeCmd := exec.Command("apt-cache", "policy", "sqd-agent")
	output, err := upgradeCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to check for upgrades: %v", err)
	}

	// Parse output to find candidate version
	re := regexp.MustCompile(`Candidate: (\S+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return nil, fmt.Errorf("failed to parse apt-cache output")
	}

	candidateVersion := matches[1]
	if candidateVersion != strings.TrimSpace(string(currentVersion)) && candidateVersion != "(none)" {
		return &ReleaseInfo{
			Version:     candidateVersion,
			URL:         "apt:sqd-agent",
			ReleaseDate: time.Now(),
			IsDebian:    true,
		}, nil
	}

	return nil, nil
}

// checkGitHubUpdate checks for updates on GitHub releases
func (u *Updater) checkGitHubUpdate() (*ReleaseInfo, error) {
	release, _, err := u.githubClient.Repositories.GetLatestRelease(context.Background(), u.owner, u.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %v", err)
	}

	latestVersion := strings.TrimPrefix(release.GetTagName(), "v")
	if u.compareVersions(latestVersion, u.currentVersion) > 0 {
		// Find the appropriate asset
		var assetURL, checksumURL string
		for _, asset := range release.Assets {
			name := asset.GetName()
			if name == "sqd-agent_"+latestVersion+"_linux_amd64.deb" {
				assetURL = asset.GetBrowserDownloadURL()
			} else if name == "sqd-agent_"+latestVersion+"_linux_amd64.deb.sha256" {
				checksumURL = asset.GetBrowserDownloadURL()
			}
		}

		if assetURL == "" {
			return nil, fmt.Errorf("no matching asset found for this platform")
		}

		var sha256 string
		if checksumURL != "" {
			sha256, _ = u.fetchChecksum(checksumURL) // Ignore error, checksum is optional
		}

		return &ReleaseInfo{
			Version:     latestVersion,
			URL:         assetURL,
			ReleaseDate: release.GetPublishedAt().Time,
			SHA256:      sha256,
			IsDebian:    false,
		}, nil
	}

	return nil, nil
}

// fetchChecksum downloads and parses the checksum file
func (u *Updater) fetchChecksum(url string) (string, error) {
	resp, err := u.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Expected format: <checksum>  <filename>
	parts := strings.Fields(string(data))
	if len(parts) > 0 {
		return parts[0], nil
	}
	return "", fmt.Errorf("invalid checksum format")
}

// compareVersions compares two version strings
// Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func (u *Updater) compareVersions(v1, v2 string) int {
	// Simple comparison - you might want to use a proper version comparison library
	if v1 == v2 {
		return 0
	}
	if v1 > v2 {
		return 1
	}
	return -1
}

// Update downloads and installs the new version
func (u *Updater) Update(releaseInfo *ReleaseInfo) error {
	if releaseInfo == nil {
		return fmt.Errorf("no release information provided")
	}

	if releaseInfo.IsDebian {
		return u.updateDebian()
	}
	return u.updateFromGitHub(releaseInfo)
}

// updateDebian updates the package using apt
func (u *Updater) updateDebian() error {
	// Update package list
	cmd := exec.Command("apt-get", "update", "-qq")
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update package list: %v", err)
	}

	// Run the upgrade
	cmd = exec.Command("apt-get", "install", "--only-upgrade", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "sqd-agent")
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Run the update and wait for it to complete
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update package: %v", err)
	}

	// Restart the service
	log.Info("Restarting systemd service...")
	restartCmd := exec.Command("systemctl", "restart", "sqd-agent.service")
	restartCmd.Stdout = nil
	restartCmd.Stderr = nil
	if err := restartCmd.Run(); err != nil {
		return fmt.Errorf("failed to restart service: %v", err)
	}

	return nil
}

// updateFromGitHub downloads and installs the new version from GitHub
func (u *Updater) updateFromGitHub(releaseInfo *ReleaseInfo) error {
	// Create a temporary directory for the download
	tempDir, err := os.MkdirTemp("", "sqd-update-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Download the asset
	assetPath := filepath.Join(tempDir, filepath.Base(releaseInfo.URL))
	if err := u.downloadFile(releaseInfo.URL, assetPath); err != nil {
		return fmt.Errorf("failed to download update: %v", err)
	}

	// Verify checksum if available
	if releaseInfo.SHA256 != "" {
		checksum, err := u.calculateFileChecksum(assetPath)
		if err != nil {
			return fmt.Errorf("failed to calculate checksum: %v", err)
		}
		if checksum != releaseInfo.SHA256 {
			return fmt.Errorf("checksum verification failed: expected %s, got %s", releaseInfo.SHA256, checksum)
		}
	}

	// Install the update
	if strings.HasSuffix(assetPath, ".deb") {
		// Install Debian package
		cmd := exec.Command("dpkg", "-i", assetPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install deb package: %v", err)
		}
	} else {
		// For non-debian packages, replace the binary
		targetPath := u.executablePath + ".new"
		if err := os.Rename(assetPath, targetPath); err != nil {
			return fmt.Errorf("failed to move new binary: %v", err)
		}
		if err := os.Chmod(targetPath, 0755); err != nil {
			return fmt.Errorf("failed to set executable permissions: %v", err)
		}
		// The actual replacement should happen on next restart
	}

	return nil
}

// downloadFile downloads a file from URL to filepath
func (u *Updater) downloadFile(url, filepath string) error {
	resp, err := u.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// calculateFileChecksum calculates the SHA256 checksum of a file
func (u *Updater) calculateFileChecksum(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
