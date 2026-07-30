package sbi

import (
	"net/http"

	"github.com/free5gc/nef/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) getCallbackRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodPost,
			Pattern: "/notification/smf",
			APIFunc: s.apiPostSmfNotification,
		},
	}
}

func (s *Server) apiPostSmfNotification(gc *gin.Context) {
	var eeNotif models.NsmfEventExposureNotification
	reqBody, err := gc.GetRawData()
	if err != nil {
		logger.SBILog.Errorf("Get Request Body error: %+v", err)
		gc.JSON(http.StatusInternalServerError,
			openapi.ProblemDetailsSystemFailure(err.Error()))
		return
	}

	err = openapi.Deserialize(&eeNotif, reqBody, "application/json")
	if err != nil {
		logger.SBILog.Errorf("Deserialize Request Body error: %+v", err)
		gc.JSON(http.StatusBadRequest,
			openapi.ProblemDetailsMalformedReqSyntax(err.Error()))
		return
	}

	s.Processor().SmfNotification(gc, &eeNotif)
}
