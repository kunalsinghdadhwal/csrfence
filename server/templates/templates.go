package templates

import (
	"html/template"
	"log"
	"net/http"
)

type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RestrcitedPage struct {
	CsrfSecret    string
	SecretMessage string
}

var templates = template.Must(template.ParseFiles("./server/templates/login.html", "./server/templates/register.html", "./server/templates/restricted.html"))

func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".tmpl", p)
	if err != nil {
		log.Println("Template Error here: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
