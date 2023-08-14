package internal

import (
	"backend/internal/scan"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
	"net"
	"net/http"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func (s *Server) postScanPortsHandler(c *gin.Context) {
	ctx := c.Request.Context()

	var scanRequest scan.ScanRequest
	if err := c.ShouldBindJSON(&scanRequest); err != nil {
		s.Logger.Error("unable to bind json", zap.Error(err))
		c.JSON(http.StatusBadRequest, c.Error(err))
		return
	}

	var req scan.ScanRequestMapped
	for _, value := range scanRequest.IPsOrHostnames {
		if net.ParseIP(value) != nil {
			req.IPs = append(req.IPs, value)
		} else {
			req.Hostnames = append(req.Hostnames, value)
		}
	}

	// Check that at least one of the fields is not empty
	if len(req.IPs) == 0 && len(req.Hostnames) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Message: "At least one IP or hostname is required"})
		return
	}

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		validationErrors := err.(validator.ValidationErrors)
		s.Logger.Error("validation error", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{Message: validationErrors.Error()})
		return
	}

	scanResponse, err := s.ScanClient.ScanPorts(ctx, req)
	if err != nil {
		s.Logger.Error("unable to scan ports", zap.Error(err))
		c.JSON(http.StatusInternalServerError, c.Error(err))
		return
	}

	c.JSON(http.StatusOK, scanResponse)
}
