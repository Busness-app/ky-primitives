package syncauth

import (
	"context"
	"net/http"
)

func contextWith(r *http.Request, ev Event) context.Context {
	return context.WithValue(r.Context(), ctxKey{}, ev)
}
