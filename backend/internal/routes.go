package internal

import (
	"backend/internal/scan"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Server struct {
	Router     *gin.Engine
	Logger     *zap.Logger
	ScanClient *scan.ScanClient
	DBClient   *scan.DBClient
}

func NewServer(router *gin.Engine) *Server {
	return &Server{
		Router: router,
	}
}

func (s *Server) Run(port string) error {
	s.bootstrapDependencies()
	s.Routes()
	return s.Router.Run(port)
}

func (s *Server) Routes() {
	s.Router.POST("/scan", s.postScanPortsHandler)
}

func (s *Server) bootstrapDependencies() {
	ENV := os.Getenv("ENV")
	if ENV == "" {
		panic("ENV is not set")
	}

	if ENV == "prod" {
		s.Logger, _ = zap.NewProduction()
	} else {
		s.Logger, _ = zap.NewDevelopment()
	}

	s.Logger.Info("bootstrapping dependencies")

	DBUsername := os.Getenv("DB_USERNAME")
	if DBUsername == "" {
		panic("DB_USERNAME is not set")
	}
	DBPassword := os.Getenv("DB_PASSWORD")
	if DBPassword == "" {
		panic("DB_PASSWORD is not set")
	}
	DBName := os.Getenv("DB_NAME")
	if DBName == "" {
		panic("DB_NAME is not set")
	}
	DBHost := os.Getenv("DB_HOST")
	if DBHost == "" {
		panic("DB_HOST is not set")
	}
	DBPort := os.Getenv("DB_PORT")
	if DBPort == "" {
		panic("DB_PORT is not set")
	}

	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", DBUsername, DBPassword, DBHost, DBPort, DBName)

	s.DBClient = scan.NewDBClient(connectionString, s.Logger)

	s.ScanClient = scan.NewScanClient(s.Logger, s.DBClient)

}
