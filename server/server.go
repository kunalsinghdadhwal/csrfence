package server

import (
	"log"
	"net/http"

	"github.com/kunalsinghdadhwal/csrfence/server/middleware"
)

func StartServer(hostname string, port string) error {
	host := hostname + ":" + port
	log.Printf("Listening on %s\n", host)

	handler := middleware.NewHandler()

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}
