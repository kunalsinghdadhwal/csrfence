package middleware

import (
	"net/http"

	"github.com/justinas/alice"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {

}

func authHandler(next http.Handler) http.Handler {

}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
	case "/login":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/register":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/logout":
	case "/deleteUser":
	default:
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {

}

func setAuthAndRefreshCookies() {

}

func grabCsrfFromReq(r *http.Request) string {
	
}