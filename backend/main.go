package main

import (
	"backend/internal"
	"github.com/gin-gonic/gin"
	"log"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	server := internal.NewServer(r)

	log.Fatal(server.Run(":" + port))
}
