package main

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/jeffreydwalter/oauth"
)

/*
   Resource Server Example

	Get Customers

		GET http://localhost:3200/customers
		User-Agent: Fiddler
		Host: localhost:3200
		Content-Length: 0
		Content-Type: application/json
		Authorization: Bearer {access_token}

	Get Orders

		GET http://localhost:3200/customers/12345/orders
		User-Agent: Fiddler
		Host: localhost:3200
		Content-Length: 0
		Content-Type: application/json
		Authorization: Bearer {access_token}

	{access_token} is produced by the Authorization Server response (see example /test/authserver).

*/
func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "PUT", "POST", "DELETE", "HEAD", "OPTION"},
		AllowedHeaders:   []string{"User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection", "DNT", "Host", "Origin", "Pragma", "Referer"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	registerAPI(r)
	http.ListenAndServe(":8081", r)
}

func registerAPI(r *chi.Mux) {
	r.Route("/", func(r chi.Router) {
		// use the Bearer Authentication middleware
		r.Use(oauth.Authorize("mySecretKey-10101", nil))
		r.Get("/customers", GetCustomers)
		r.Get("/customers/:id/orders", GetOrders)
	})
}

func GetCustomers(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	render.JSON(w, r, `{
		"Status":        "verified",
		"Customer":      "test001",
		"CustomerName":  "Max",
		"CustomerEmail": "test@test.com",
	}`)
}

func GetOrders(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	render.JSON(w, r, `{
		"status":          "sent",
		"customer":        c.Param("id"),
		"OrderId":         "100234",
		"TotalOrderItems": "199",
	}`)
}
