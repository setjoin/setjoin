// Command asrbotd is the setjoin room-bot sidecar (B3b): joins a meeting's
// LiveKit room as an unhidden (2026-07-16, B3b live-gate P0 1b — hidden
// participants' data-packet sender identity is stripped by livekit-server
// v1.13.3, killing webmail's F8 attestation), publish-nothing participant, streams
// subscribed audio through FunASR, and publishes {t:'cc',...} caption
// frames back on the room's data channel. Driven entirely by the gateway's
// loopback-only control API (bot.Server) — this process never talks to
// Postgres, S3, or mints its own LiveKit token (D4: no DB/S3 credentials at
// all, one secret universe held by the gateway).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"setjoin.com/asrbot/internal/bot"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg := loadConfig()
	if err := bot.ValidateLoopback(cfg.listen); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(1)
	}
	if err := bot.ValidateToken(cfg.token); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(1)
	}

	sessions := bot.NewSessions(bot.Config{
		LiveKitURL:      cfg.liveKitURL,
		FunASRURL:       cfg.funASRURL,
		MaxActiveTracks: cfg.maxActiveTracks,
	}, log)
	rooms := bot.NewRoomRegistry(cfg.maxMeetings, sessions)
	srv := bot.NewServer(rooms, cfg.token, log)

	// Resource bounding (D-ASRBOT-002): the loopback+bearer posture bounded
	// identity, not resources. IdleTimeout reaps pinned keep-alive connections,
	// ReadTimeout/WriteTimeout cap slow-body/stall holds on the {room,token}
	// JSON exchanges, and MaxBytesHandler bounds every decoded body (a few KiB
	// is generous for control payloads). /healthz stays a body-less GET so the
	// install.sh boot-probe contract is unchanged.
	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           http.MaxBytesHandler(srv.Handler(), maxControlBodyBytes),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("asrbotd listening", "addr", cfg.listen, "livekit_url", cfg.liveKitURL, "funasr_url", cfg.funASRURL, "max_meetings", cfg.maxMeetings, "max_active_tracks", cfg.maxActiveTracks)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("control server failed", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

// maxControlBodyBytes bounds every request body on the control API
// (D-ASRBOT-002): startRequest/stopRequest are {room,token} JSON, so 8 KiB
// leaves ample headroom while capping per-request decode buffers.
const maxControlBodyBytes = 8 << 10

type config struct {
	listen          string
	liveKitURL      string
	funASRURL       string
	token           string
	maxMeetings     int
	maxActiveTracks int
}

func loadConfig() config {
	return config{
		listen:     getenv("ASR_LISTEN", "127.0.0.1:7890"),
		liveKitURL: os.Getenv("LIVEKIT_URL"),
		funASRURL:  getenv("FUNASR_URL", "ws://127.0.0.1:10096"),
		// ASR_TOKEN: the shared control-API bearer secret (finding 1, B3 Task
		// 18 pipeline review) — no default, required (bot.ValidateToken
		// refuses to start without it). Never logged (the "asrbotd listening"
		// line below deliberately omits it).
		token:           os.Getenv("ASR_TOKEN"),
		maxMeetings:     getenvInt("ASR_MAX_MEETINGS", 2),
		maxActiveTracks: getenvInt("ASR_MAX_ACTIVE_TRACKS", 4),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
