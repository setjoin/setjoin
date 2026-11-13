package admin

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/shared/httputil"
)

const brandingLogoKey = "branding/logo"

// BrandingHandler handles branding configuration for the admin portal.
type BrandingHandler struct {
	pool   *pgxpool.Pool
	minio  *minio.Client
	bucket string
	logger *slog.Logger
}

// NewBrandingHandler creates a branding admin handler.
func NewBrandingHandler(pool *pgxpool.Pool, minioClient *minio.Client, bucket string, logger *slog.Logger) *BrandingHandler {
	return &BrandingHandler{pool: pool, minio: minioClient, bucket: bucket, logger: logger}
}

// Get returns the current branding config from system_config.
func (h *BrandingHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var name, logoURL string
	h.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_name'), 'SetJoin'),
		        COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_logo_url'), '')`,
	).Scan(&name, &logoURL)
	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"name":    name,
		"logoUrl": logoURL,
	})
}

// Update handles multipart form upload with optional name and logo file.
func (h *BrandingHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // 2MB max

	if err := r.ParseMultipartForm(2 << 20); err != nil { //nolint:gosec // G120: bounded by MaxBytesReader (2MB) above
		httputil.WriteError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	name := r.FormValue("name")
	if name != "" {
		h.pool.Exec(ctx,
			`INSERT INTO system_config (key, value, description, updated_at)
			 VALUES ('brand_name', $1, 'Brand display name', now())
			 ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = now()`,
			name,
		)
	}

	file, header, err := r.FormFile("logo")
	if err == nil {
		defer file.Close()
		buf := make([]byte, header.Size)
		if _, err := io.ReadFull(file, buf); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "failed to read logo file")
			return
		}
		contentType := header.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "image/png"
		}
		_, err = h.minio.PutObject(ctx, h.bucket, brandingLogoKey, bytes.NewReader(buf), int64(len(buf)), minio.PutObjectOptions{
			ContentType: contentType,
		})
		if err != nil {
			h.logger.Error("branding logo upload failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "logo upload failed")
			return
		}
		logoURL := "/blob/" + brandingLogoKey
		h.pool.Exec(ctx,
			`INSERT INTO system_config (key, value, description, updated_at)
			 VALUES ('brand_logo_url', $1, 'Brand logo URL', now())
			 ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = now()`,
			logoURL,
		)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
