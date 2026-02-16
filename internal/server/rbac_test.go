package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func stubServer() *Server {
	return &Server{logger: testLogger()}
}

func TestRequireRole_Allowed(t *testing.T) {
	s := stubServer()
	called := false
	handler := s.requireRole(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}, "admin", "submitter")

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Error("expected handler to be called for admin role")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequireRole_Forbidden(t *testing.T) {
	s := stubServer()
	called := false
	handler := s.requireRole(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}, "admin")

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "viewer")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if called {
		t.Error("handler should not be called for viewer role")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestAdminOnly_AdminAllowed(t *testing.T) {
	s := stubServer()
	called := false
	handler := s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Error("expected handler to be called for admin")
	}
}

func TestAdminOnly_SubmitterForbidden(t *testing.T) {
	s := stubServer()
	handler := s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "submitter")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCanWrite_SubmitterAllowed(t *testing.T) {
	s := stubServer()
	called := false
	handler := s.canWrite(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "submitter")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Error("expected handler to be called for submitter")
	}
}

func TestCanWrite_ViewerForbidden(t *testing.T) {
	s := stubServer()
	handler := s.canWrite(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest("POST", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "viewer")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCanReview_ReviewerAllowed(t *testing.T) {
	s := stubServer()
	called := false
	handler := s.canReview(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "reviewer")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Error("expected handler to be called for reviewer")
	}
}

func TestCanReview_ViewerForbidden(t *testing.T) {
	s := stubServer()
	handler := s.canReview(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "viewer")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRequireRole_EmptyRole(t *testing.T) {
	s := stubServer()
	handler := s.requireRole(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for empty role")
	}, "admin")

	// No auth context set — role will be empty string
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for empty role, got %d", rr.Code)
	}
}
