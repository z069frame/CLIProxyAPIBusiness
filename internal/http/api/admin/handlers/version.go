package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPIBusiness/internal/buildinfo"
)

// Legacy note: the previous implementation fetched latest versions from GitHub
// Releases to populate LatestVersion/ReleaseURL, but was removed to avoid
// external links in the admin UI.
const (
	defaultReleaseURL = "/"
)

// VersionHandler handles version check endpoints.
type VersionHandler struct{}

// NewVersionHandler constructs a VersionHandler.
func NewVersionHandler() *VersionHandler {
	return &VersionHandler{}
}

// VersionResponse is the response for version check.
type VersionResponse struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	HasUpdate      bool   `json:"has_update"`
	ReleaseURL     string `json:"release_url,omitempty"`
	Commit         string `json:"commit,omitempty"`
	BuildDate      string `json:"build_date,omitempty"`
	CheckError     string `json:"check_error,omitempty"`
}

// GetVersion returns current version metadata for the admin UI.
func (h *VersionHandler) GetVersion(c *gin.Context) {
	resp := VersionResponse{
		CurrentVersion: buildinfo.Version,
		Commit:         buildinfo.Commit,
		BuildDate:      buildinfo.BuildDate,
		HasUpdate:      false,
		ReleaseURL:     defaultReleaseURL,
	}

	c.JSON(http.StatusOK, resp)
}
