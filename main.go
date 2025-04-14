package main

import (
	"log"

	"github.com/kunalsinghdadhwal/csrfence/db"
	"github.com/kunalsinghdadhwal/csrfence/server"
	myJwt "github.com/kunalsinghdadhwal/csrfence/server/middleware/myJwt"
)

var host = "localhost"
var port = "42069"

func main() {

	db.InitDB()

	jwtErr := myJwt.InitJWT()

	if jwtErr != nil {
		log.Println("Error Initializing the JWT")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error Starting Server")
		log.Fatal(serverErr)
	}
}
