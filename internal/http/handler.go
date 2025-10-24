package http

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"dproxy-server-go/internal/database"
	apperrors "dproxy-server-go/internal/errors"
	"dproxy-server-go/pkg/dproxy"
)

type Handler struct {
	dproxyServer *dproxy.Server
	repo         *database.Repository
	httpPassword string
	logger       *slog.Logger
}

func NewHandler(server *dproxy.Server, repo *database.Repository, httpPassword string) *Handler {
	return &Handler{
		dproxyServer: server,
		repo:         repo,
		httpPassword: httpPassword,
		logger:       slog.Default().WithGroup("http"),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/key-exchange" {
		h.getServerPublicKey(w, r)
		return
	}

	if r.Method == "POST" && r.URL.Path == "/key-exchange" {
		h.uploadClientPublicKey(w, r)
		return
	}

	if r.Method == "GET" && r.URL.Path == "/stats" {
		h.getClientsStats(w, r)
		return
	}

	if !h.isProxyRequest(r) {
		http.NotFound(w, r)
		return
	}

	h.logger.Debug("Received proxy request", "method", r.Method, "url", r.URL.String())

	client, err := h.authenticateRequest(r)
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	if r.Method == "CONNECT" {
		err = h.handleHttpsTunnel(w, r, client)
	} else {
		err = h.handleHttpTunnel(w, r, client)
	}

	if err != nil {
		h.logger.Error("Error when handling proxy request", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (h *Handler) isProxyRequest(r *http.Request) bool {
	return r.Method == "CONNECT" ||
		strings.HasPrefix(r.URL.String(), "http://") ||
		strings.HasPrefix(r.URL.String(), "ws://")
}

func (h *Handler) authenticateRequest(r *http.Request) (*dproxy.Client, error) {
	originalAuth := r.Header.Get("Authorization")
	r.Header.Set("Authorization", r.Header.Get("Proxy-Authorization"))

	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, apperrors.ErrInvalidCredentials
	}

	r.Header.Set("Authorization", originalAuth)

	return h.getDProxyClient(username, password)
}

func (h *Handler) getDProxyClient(username, password string) (*dproxy.Client, error) {
	clientDB, err := h.repo.GetClientByID(username)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return nil, apperrors.ErrInvalidCredentials
		}
		return nil, err
	}

	if !clientDB.Enabled {
		return nil, apperrors.ErrClientDisabled
	}

	if password != h.httpPassword {
		return nil, apperrors.ErrInvalidCredentials
	}

	if !h.dproxyServer.IsClientConnected(username) {
		return nil, apperrors.ErrClientNotConnected
	}

	return h.dproxyServer.GetClient(username), nil
}

func (h *Handler) handleAuthError(w http.ResponseWriter, err error) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="dproxy"`)

	switch {
	case errors.Is(err, apperrors.ErrInvalidCredentials):
		w.WriteHeader(http.StatusProxyAuthRequired)
	case errors.Is(err, apperrors.ErrClientNotConnected):
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusProxyAuthRequired)
	}
}
