package drive

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

const maxOfficeLaunchBodyBytes = 32 << 10

func (h *Handler) registerOfficeRoutes(mux router) {
	mux.HandleFunc("GET /drive/files/{id}/office/choices", h.officeChoices)
	mux.HandleFunc("POST /drive/files/{id}/office/launches", h.officeLaunch)
	mux.HandleFunc("DELETE /drive/files/{id}/office/launches/{launchId}", h.officeRevoke)
	mux.HandleFunc("POST /drive/files/{id}/office/local-open", h.officeLocalOpen)
}

type officeLocalOpenBody struct {
	AppID    string `json:"appId"`
	DeviceID string `json:"deviceId"`
}

func (h *Handler) officeLocalOpen(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureOfficeLocalOpen) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	fileID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOfficeLaunchBodyBytes)
	var body officeLocalOpenBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	var out json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT office_local_open_accept($1,$2,$3,$4)`,
			claims.UserID, fileID, body.AppID, body.DeviceID).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (h *Handler) officeChoicesEnabled(w http.ResponseWriter) bool {
	if h.flags.IsEnabled(toggle.FeatureOfficeEditing) || h.flags.IsEnabled(toggle.FeatureOfficeLocalOpen) {
		return true
	}
	httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
	return false
}

func (h *Handler) officeEditingEnabled(w http.ResponseWriter) bool {
	if h.flags.IsEnabled(toggle.FeatureOfficeEditing) {
		return true
	}
	httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
	return false
}

func (h *Handler) officeChoices(w http.ResponseWriter, r *http.Request) {
	if !h.officeChoicesEnabled(w) {
		return
	}
	claims := auth.UserFromContext(r.Context())
	fileID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	platform := r.URL.Query().Get("platform")
	if platform == "" {
		platform = "web"
	}
	var out json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT office_choice_query($1,$2,$3)`, claims.UserID, fileID, platform).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

type officeLaunchBody struct {
	BaseVersionID int64  `json:"baseVersionId"`
	ProviderID    string `json:"providerId"`
	DeviceID      string `json:"deviceId"`
	CohortKey     string `json:"cohortKey"`
}

func (h *Handler) officeLaunch(w http.ResponseWriter, r *http.Request) {
	if !h.officeEditingEnabled(w) {
		return
	}
	claims := auth.UserFromContext(r.Context())
	fileID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOfficeLaunchBodyBytes)
	var body officeLaunchBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if strings.TrimSpace(body.CohortKey) == "" {
		body.CohortKey = "file-" + r.PathValue("id")
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		h.logger.Error("drive: Office launch token generation failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "launch failed")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256([]byte(token))
	var reducerOut json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT office_launch_begin($1,$2,$3,$4,$5,$6,$7,$8)`,
			claims.UserID, fileID, body.BaseVersionID, body.ProviderID, body.DeviceID,
			body.CohortKey, hex.EncodeToString(digest[:]), 28800).Scan(&reducerOut)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	var out map[string]any
	if err := json.Unmarshal(reducerOut, &out); err != nil {
		h.logger.Error("drive: invalid Office launch reducer result", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "launch failed")
		return
	}
	out["accessToken"] = token
	publicBase, _ := out["wopiPublicBaseUrl"].(string)
	editorBase, _ := out["editorUrl"].(string)
	testTransport, _ := out["testTransport"].(bool)
	wopiSrc := strings.TrimRight(publicBase, "/") + "/api/office/wopi/files/" + r.PathValue("id")
	editorURL, parseErr := url.Parse(editorBase)
	validEditorScheme := false
	if parseErr == nil {
		validEditorScheme = editorURL.Scheme == "https"
		if testTransport && editorURL.Scheme == "http" && editorURL.Hostname() == "127.0.0.1" {
			validEditorScheme = true
		}
	}
	if parseErr != nil || !validEditorScheme {
		httputil.WriteProblemStatus(w, http.StatusConflict, "Office provider launch URL is invalid")
		return
	}
	query := editorURL.Query()
	query.Set("WOPISrc", wopiSrc)
	editorURL.RawQuery = query.Encode()
	out["editorUrl"] = editorURL.String()
	out["wopiSrc"] = wopiSrc
	delete(out, "wopiPublicBaseUrl")
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) officeRevoke(w http.ResponseWriter, r *http.Request) {
	if !h.officeEditingEnabled(w) {
		return
	}
	claims := auth.UserFromContext(r.Context())
	fileID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	launchID, err := uuid.Parse(r.PathValue("launchId"))
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid launch id")
		return
	}
	var out json.RawMessage
	err = dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT office_launch_revoke($1,$2,$3)`, claims.UserID, fileID, launchID).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}
