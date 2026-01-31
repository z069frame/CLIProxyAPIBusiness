package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	permissions "github.com/router-for-me/CLIProxyAPIBusiness/internal/http/api/admin/permissions"
	"github.com/router-for-me/CLIProxyAPIBusiness/internal/models"
	"github.com/router-for-me/CLIProxyAPIBusiness/internal/security"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// MFAHandler handles MFA endpoints for admins.
type MFAHandler struct {
	db       *gorm.DB
	webAuthn *webauthn.WebAuthn
}

// NewMFAHandler constructs an MFAHandler.
func NewMFAHandler(db *gorm.DB, webAuthn *webauthn.WebAuthn) *MFAHandler {
	return &MFAHandler{db: db, webAuthn: webAuthn}
}

// sessionEntry stores WebAuthn session data with expiry.
type sessionEntry struct {
	data    webauthn.SessionData
	expires time.Time
}

// sessionStore keeps temporary WebAuthn sessions in memory.
type sessionStore struct {
	mu    sync.Mutex
	items map[string]sessionEntry
}

// newSessionStore creates an empty session store.
func newSessionStore() *sessionStore {
	return &sessionStore{items: make(map[string]sessionEntry)}
}

// loadWebAuthn loads WebAuthn configuration.
func loadWebAuthn() (*webauthn.WebAuthn, error) {
	return security.NewWebAuthn()
}

// Set stores session data with expiry.
func (s *sessionStore) Set(key string, data webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expires := data.Expires
	if expires.IsZero() {
		expires = time.Now().Add(5 * time.Minute)
	}
	s.items[key] = sessionEntry{data: data, expires: expires}
}

// Get returns session data if present and not expired.
func (s *sessionStore) Get(key string) (webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.items[key]
	if !ok {
		return webauthn.SessionData{}, false
	}
	if time.Now().After(entry.expires) {
		delete(s.items, key)
		return webauthn.SessionData{}, false
	}
	return entry.data, true
}

// Delete removes a session entry.
func (s *sessionStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

// secretEntry stores a TOTP secret with expiry.
type secretEntry struct {
	secret  string
	expires time.Time
}

// secretStore keeps temporary TOTP secrets in memory.
type secretStore struct {
	mu    sync.Mutex
	items map[string]secretEntry
}

// newSecretStore creates an empty secret store.
func newSecretStore() *secretStore {
	return &secretStore{items: make(map[string]secretEntry)}
}

// Set stores a secret with expiry.
func (s *secretStore) Set(key, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = secretEntry{secret: secret, expires: time.Now().Add(10 * time.Minute)}
}

// Get returns a secret if present and not expired.
func (s *secretStore) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.items[key]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expires) {
		delete(s.items, key)
		return "", false
	}
	return entry.secret, true
}

// Delete removes a secret entry.
func (s *secretStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

// In-memory MFA session stores for passkey and TOTP flows.
var (
	// passkeyRegistrationSessions stores in-flight registration sessions.
	passkeyRegistrationSessions = newSessionStore()
	// passkeyLoginSessions stores in-flight login sessions.
	passkeyLoginSessions = newSessionStore()
	// totpPendingSecrets stores pending TOTP secrets for confirmation.
	totpPendingSecrets = newSecretStore()
)

// adminWebAuthnUser adapts an admin model to WebAuthn interfaces.
type adminWebAuthnUser struct {
	id          uint64
	username    string
	credentials []webauthn.Credential
}

// WebAuthnID returns the admin ID as a byte slice.
func (u adminWebAuthnUser) WebAuthnID() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, u.id)
	return buf
}

// WebAuthnName returns the admin username.
func (u adminWebAuthnUser) WebAuthnName() string {
	return u.username
}

// WebAuthnDisplayName returns the admin display name.
func (u adminWebAuthnUser) WebAuthnDisplayName() string {
	return u.username
}

// WebAuthnCredentials returns registered credentials.
func (u adminWebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// newAdminWebAuthnUser builds a WebAuthn adapter from an admin model.
func newAdminWebAuthnUser(admin models.Admin) adminWebAuthnUser {
	user := adminWebAuthnUser{
		id:       admin.ID,
		username: admin.Username,
	}
	if len(admin.PasskeyID) > 0 && len(admin.PasskeyPublicKey) > 0 {
		signCount := uint32(0)
		if admin.PasskeySignCount != nil {
			signCount = *admin.PasskeySignCount
		}
		flags := webauthn.CredentialFlags{}
		if admin.PasskeyBackupEligible != nil {
			flags.BackupEligible = *admin.PasskeyBackupEligible
		}
		if admin.PasskeyBackupState != nil {
			flags.BackupState = *admin.PasskeyBackupState
		}
		user.credentials = []webauthn.Credential{
			{
				ID:        admin.PasskeyID,
				PublicKey: admin.PasskeyPublicKey,
				Flags:     flags,
				Authenticator: webauthn.Authenticator{
					SignCount: signCount,
				},
			},
		}
	}
	return user
}

// readAdminIDFromContext returns the admin ID from request context.
func readAdminIDFromContext(c *gin.Context) (uint64, bool) {
	value, ok := c.Get("adminID")
	if !ok {
		return 0, false
	}
	id, ok := value.(uint64)
	return id, ok
}

// Status returns MFA enablement status for the admin.
func (h *MFAHandler) Status(c *gin.Context) {
	adminID, ok := readAdminIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin not found"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).Select("id", "totp_secret", "passkey_id", "passkey_public_key").First(&admin, adminID).Error; errFind != nil {
		if errFind == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}

	totpEnabled := strings.TrimSpace(admin.TOTPSecret) != ""
	passkeyEnabled := len(admin.PasskeyID) > 0 && len(admin.PasskeyPublicKey) > 0

	c.JSON(http.StatusOK, gin.H{
		"totp_enabled":    totpEnabled,
		"passkey_enabled": passkeyEnabled,
	})
}

// PrepareTOTP generates a new TOTP secret and QR code.
func (h *MFAHandler) PrepareTOTP(c *gin.Context) {
	adminID, ok := readAdminIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin not found"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).Select("id", "username").First(&admin, adminID).Error; errFind != nil {
		if errFind == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ZeroFrameTech",
		AccountName: admin.Username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "generate totp secret failed"})
		return
	}

	totpPendingSecrets.Set(fmt.Sprintf("%d", admin.ID), key.Secret())
	qrImage := ""
	if img, errImage := key.Image(220, 220); errImage == nil {
		var buf bytes.Buffer
		if errEncode := png.Encode(&buf, img); errEncode == nil {
			qrImage = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"secret":      key.Secret(),
		"otpauth_url": key.URL(),
		"qr_image":    qrImage,
	})
}

// totpConfirmRequest defines the request body for confirming TOTP.
type totpConfirmRequest struct {
	Code string `json:"code"`
}

// ConfirmTOTP validates and enables TOTP for the admin.
func (h *MFAHandler) ConfirmTOTP(c *gin.Context) {
	adminID, ok := readAdminIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin not found"})
		return
	}
	var body totpConfirmRequest
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	secret, ok := totpPendingSecrets.Get(fmt.Sprintf("%d", adminID))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "totp setup expired"})
		return
	}

	if !totp.Validate(code, secret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	if errUpdate := h.db.WithContext(c.Request.Context()).Model(&models.Admin{}).
		Where("id = ?", adminID).
		Updates(map[string]any{"totp_secret": secret, "updated_at": time.Now().UTC()}).Error; errUpdate != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	totpPendingSecrets.Delete(fmt.Sprintf("%d", adminID))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DisableTOTP removes the admin's TOTP secret.
func (h *MFAHandler) DisableTOTP(c *gin.Context) {
	adminID, ok := readAdminIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin not found"})
		return
	}

	res := h.db.WithContext(c.Request.Context()).Model(&models.Admin{}).
		Where("id = ?", adminID).
		Updates(map[string]any{
			"totp_secret": "",
			"updated_at":  time.Now().UTC(),
		})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	totpPendingSecrets.Delete(fmt.Sprintf("%d", adminID))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DisablePasskey removes the admin's passkey credentials.
func (h *MFAHandler) DisablePasskey(c *gin.Context) {
	adminID, ok := readAdminIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin not found"})
		return
	}

	res := h.db.WithContext(c.Request.Context()).Model(&models.Admin{}).
		Where("id = ?", adminID).
		Updates(map[string]any{
			"passkey_id":              nil,
			"passkey_public_key":      nil,
			"passkey_sign_count":      nil,
			"passkey_backup_eligible": nil,
			"passkey_backup_state":    nil,
			"updated_at":              time.Now().UTC(),
		})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	passkeyRegistrationSessions.Delete(fmt.Sprintf("%d", adminID))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// BeginPasskeyRegistration starts a passkey registration ceremony.
func (h *MFAHandler) BeginPasskeyRegistration(c *gin.Context) {
	webAuthn, errWebAuthn := loadWebAuthn()
	if errWebAuthn != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey not configured"})
		return
	}

	adminID, ok := readAdminIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin not found"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).
		Select("id", "username", "passkey_id", "passkey_public_key", "passkey_sign_count", "passkey_backup_eligible", "passkey_backup_state").
		First(&admin, adminID).Error; errFind != nil {
		if errFind == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}

	user := newAdminWebAuthnUser(admin)
	options := []webauthn.RegistrationOption{
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		}),
	}
	if len(user.WebAuthnCredentials()) > 0 {
		options = append(options, webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()))
	}

	creation, session, err := webAuthn.BeginRegistration(user, options...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "begin passkey registration failed"})
		return
	}

	passkeyRegistrationSessions.Set(fmt.Sprintf("%d", admin.ID), *session)
	c.JSON(http.StatusOK, creation)
}

// FinishPasskeyRegistration completes a passkey registration ceremony.
func (h *MFAHandler) FinishPasskeyRegistration(c *gin.Context) {
	webAuthn, errWebAuthn := loadWebAuthn()
	if errWebAuthn != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey not configured"})
		return
	}

	adminID, ok := readAdminIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin not found"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).
		Select("id", "username", "passkey_id", "passkey_public_key", "passkey_sign_count").
		First(&admin, adminID).Error; errFind != nil {
		if errFind == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}

	session, ok := passkeyRegistrationSessions.Get(fmt.Sprintf("%d", admin.ID))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "registration expired"})
		return
	}

	user := newAdminWebAuthnUser(admin)
	credential, err := webAuthn.FinishRegistration(user, session, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "registration failed"})
		return
	}

	signCount := uint32(credential.Authenticator.SignCount)
	if errUpdate := h.db.WithContext(c.Request.Context()).Model(&models.Admin{}).
		Where("id = ?", adminID).
		Updates(map[string]any{
			"passkey_id":              credential.ID,
			"passkey_public_key":      credential.PublicKey,
			"passkey_sign_count":      signCount,
			"passkey_backup_eligible": credential.Flags.BackupEligible,
			"passkey_backup_state":    credential.Flags.BackupState,
			"updated_at":              time.Now().UTC(),
		}).Error; errUpdate != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	passkeyRegistrationSessions.Delete(fmt.Sprintf("%d", admin.ID))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// LoginPrepare returns MFA status prior to admin login.
func (h *AuthHandler) LoginPrepare(c *gin.Context) {
	var body loginRequest
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	username := strings.TrimSpace(body.Username)
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).
		Select("id", "username", "active", "totp_secret", "passkey_id", "passkey_public_key").
		Where("username = ?", username).
		First(&admin).Error; errFind != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if !admin.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin account is disabled"})
		return
	}

	totpEnabled := strings.TrimSpace(admin.TOTPSecret) != ""
	passkeyEnabled := len(admin.PasskeyID) > 0 && len(admin.PasskeyPublicKey) > 0
	mfaEnabled := totpEnabled || passkeyEnabled

	c.JSON(http.StatusOK, gin.H{
		"mfa_enabled":     mfaEnabled,
		"totp_enabled":    totpEnabled,
		"passkey_enabled": passkeyEnabled,
	})
}

// loginTotpRequest defines the request body for TOTP login.
type loginTotpRequest struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

// LoginTOTP authenticates an admin using TOTP.
func (h *AuthHandler) LoginTOTP(c *gin.Context) {
	var body loginTotpRequest
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	username := strings.TrimSpace(body.Username)
	code := strings.TrimSpace(body.Code)
	if username == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and code are required"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).
		Where("username = ?", username).
		First(&admin).Error; errFind != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if !admin.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin account is disabled"})
		return
	}
	if strings.TrimSpace(admin.TOTPSecret) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "totp not enabled"})
		return
	}
	if !totp.Validate(code, admin.TOTPSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	h.respondWithAdminToken(c, admin)
}

// loginPasskeyRequest defines the request body for passkey login options.
type loginPasskeyRequest struct {
	Username string `json:"username"`
}

// LoginPasskeyOptions starts a passkey login ceremony.
func (h *AuthHandler) LoginPasskeyOptions(c *gin.Context) {
	webAuthn, errWebAuthn := loadWebAuthn()
	if errWebAuthn != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey not configured"})
		return
	}

	var body loginPasskeyRequest
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	username := strings.TrimSpace(body.Username)
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).
		Select("id", "username", "password", "active", "passkey_id", "passkey_public_key", "passkey_sign_count", "passkey_backup_eligible", "passkey_backup_state", "permissions", "is_super_admin").
		Where("username = ?", username).First(&admin).Error; errFind != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if !admin.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin account is disabled"})
		return
	}
	if len(admin.PasskeyID) == 0 || len(admin.PasskeyPublicKey) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "passkey not enabled"})
		return
	}

	user := newAdminWebAuthnUser(admin)
	assertion, session, err := webAuthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "begin passkey login failed"})
		return
	}

	passkeyLoginSessions.Set(username, *session)
	c.JSON(http.StatusOK, assertion)
}

// LoginPasskeyVerify completes a passkey login ceremony.
func (h *AuthHandler) LoginPasskeyVerify(c *gin.Context) {
	webAuthn, errWebAuthn := loadWebAuthn()
	if errWebAuthn != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "passkey not configured"})
		return
	}

	username := strings.TrimSpace(c.Query("username"))
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	var admin models.Admin
	if errFind := h.db.WithContext(c.Request.Context()).
		Select("id", "username", "active", "passkey_id", "passkey_public_key", "passkey_sign_count", "passkey_backup_eligible", "passkey_backup_state", "permissions", "is_super_admin").
		Where("username = ?", username).First(&admin).Error; errFind != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if !admin.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin account is disabled"})
		return
	}
	if len(admin.PasskeyID) == 0 || len(admin.PasskeyPublicKey) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "passkey not enabled"})
		return
	}

	session, ok := passkeyLoginSessions.Get(username)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "login expired"})
		return
	}

	rawBody, errRead := io.ReadAll(c.Request.Body)
	if errRead != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(rawBody))

	var derivedBackupEligible *bool
	var derivedBackupState *bool
	if admin.PasskeyBackupEligible == nil || admin.PasskeyBackupState == nil {
		parsed, errParse := protocol.ParseCredentialRequestResponseBytes(rawBody)
		if errParse != nil {
			log.WithError(errParse).WithField("username", username).Warn("passkey login parse failed")
		} else {
			backupEligible := parsed.Response.AuthenticatorData.Flags.HasBackupEligible()
			backupState := parsed.Response.AuthenticatorData.Flags.HasBackupState()
			derivedBackupEligible = &backupEligible
			derivedBackupState = &backupState
		}
	}

	user := newAdminWebAuthnUser(admin)
	if derivedBackupEligible != nil && len(user.credentials) > 0 {
		user.credentials[0].Flags.BackupEligible = *derivedBackupEligible
		user.credentials[0].Flags.BackupState = *derivedBackupState
	}
	credential, err := webAuthn.FinishLogin(user, session, c.Request)
	if err != nil {
		log.WithError(err).WithField("username", username).Warn("passkey login failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login failed"})
		return
	}

	signCount := uint32(credential.Authenticator.SignCount)
	_ = h.db.WithContext(c.Request.Context()).Model(&models.Admin{}).
		Where("id = ?", admin.ID).
		Updates(map[string]any{
			"passkey_sign_count":      signCount,
			"passkey_backup_eligible": credential.Flags.BackupEligible,
			"passkey_backup_state":    credential.Flags.BackupState,
			"updated_at":              time.Now().UTC(),
		}).Error

	passkeyLoginSessions.Delete(username)
	h.respondWithAdminToken(c, admin)
}

// respondWithAdminToken generates a JWT and responds with admin info.
func (h *AuthHandler) respondWithAdminToken(c *gin.Context, admin models.Admin) {
	token, errToken := security.GenerateAdminToken(h.jwtCfg.Secret, admin.ID, admin.Username, h.jwtCfg.Expiry)
	if errToken != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	adminPermissions := permissions.ParsePermissions(admin.Permissions)
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"admin": gin.H{
			"id":             admin.ID,
			"username":       admin.Username,
			"permissions":    adminPermissions,
			"is_super_admin": admin.IsSuperAdmin,
		},
		"user_id":        admin.ID,
		"username":       admin.Username,
		"name":           "",
		"email":          "",
		"permissions":    adminPermissions,
		"is_super_admin": admin.IsSuperAdmin,
	})
}
