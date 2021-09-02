package oauth

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/render"
)

var Respond = DefaultResponder

func Render(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		render.Render(w, NewInternalServerError(err))
	}
}
