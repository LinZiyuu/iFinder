package processor

import (
	"fmt"
	"net/http"

	"github.com/free5gc/nef/internal/logger"
	"github.com/free5gc/nef/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/gin-gonic/gin"
)

func (p *Processor) GetApplicationsPFD(c *gin.Context, appIDs []string) {
	logger.PFDFLog.Infof("GetApplicationsPFD - appIDs: %v", appIDs)

	// TODO: Support SupportedFeatures
	rspCode, rspBody := p.Consumer().AppDataPfdsGet(appIDs)

	c.JSON(rspCode, rspBody)
}

func (p *Processor) GetIndividualApplicationPFD(c *gin.Context, appID string) {
	logger.PFDFLog.Infof("GetIndividualApplicationPFD - appID[%s]", appID)

	// TODO: Support SupportedFeatures
	rspCode, rspBody := p.Consumer().AppDataPfdsAppIdGet(appID)

	c.JSON(rspCode, rspBody)
}

func (p *Processor) PostPFDSubscriptions(c *gin.Context, pfdSubsc *models.PfdSubscription) {
	logger.PFDFLog.Infof("PostPFDSubscriptions - appIDs: %v", pfdSubsc.ApplicationIds)

	// TODO: Support SupportedFeatures
	if len(pfdSubsc.NotifyUri) == 0 {
		pd := openapi.ProblemDetailsDataNotFound("Absent of Notify URI")
		c.JSON(int(pd.Status), pd)
		return
	}

	subID := p.Notifier().PfdChangeNotifier.AddPfdSub(pfdSubsc)
	hdrs := make(map[string][]string)
	addLocationheader(hdrs, p.genPfdSubscriptionURI(subID))

	for k, values := range hdrs {
		for _, value := range values {
			c.Header(k, value)
		}
	}
	c.JSON(http.StatusCreated, pfdSubsc)
}

func (p *Processor) DeleteIndividualPFDSubscription(c *gin.Context, subID string) {
	logger.PFDFLog.Infof("DeleteIndividualPFDSubscription - subID[%s]", subID)

	if err := p.Notifier().PfdChangeNotifier.DeletePfdSub(subID); err != nil {
		pd := openapi.ProblemDetailsDataNotFound(err.Error())
		c.JSON(int(pd.Status), pd)
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) genPfdSubscriptionURI(subID string) string {
	// E.g. "https://localhost:29505/nnef-pfdmanagement/v1/subscriptions/{subscriptionId}
	return fmt.Sprintf("%s/subscriptions/%s", p.Config().ServiceUri(factory.ServiceNefPfd), subID)
}
