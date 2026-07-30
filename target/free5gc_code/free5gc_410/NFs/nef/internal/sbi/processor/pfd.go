package processor

import (
	"fmt"
	"net/http"

	nef_context "github.com/free5gc/nef/internal/context"
	"github.com/free5gc/nef/internal/logger"
	"github.com/free5gc/nef/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/gin-gonic/gin"
)

const (
	DetailNoAF       = "Given AF is not existed"
	DetailNoPfdData  = "Absent of PfdManagement.PfdDatas"
	DetailNoPfd      = "Absent of PfdData.Pfds"
	DetailNoExtAppID = "Absent of PfdData.ExternalAppID"
	DetailNoPfdID    = "Absent of Pfd.PfdID"
	DetailNoPfdInfo  = "One of FlowDescriptions, Urls or DomainNames should be provided"
)

func (p *Processor) GetPFDManagementTransactions(c *gin.Context, scsAsID string) {
	logger.PFDManageLog.Infof("GetPFDManagementTransactions - scsAsID[%s]", scsAsID)

	nefCtx := p.Context()
	af := nefCtx.GetAf(scsAsID)
	if af == nil {
		c.JSON(http.StatusNotFound, openapi.ProblemDetailsDataNotFound(DetailNoAF))
		return
	}

	af.Mu.RLock()
	defer af.Mu.RUnlock()

	var pfdMngs []models.PfdManagement
	for _, afPfdTr := range af.PfdTrans {
		pfdMng, rsp := p.buildPfdManagement(scsAsID, afPfdTr)
		if rsp != nil {
			c.JSON(rsp.Status, rsp.Body)
			return
		}
		pfdMngs = append(pfdMngs, *pfdMng)
	}

	c.JSON(http.StatusOK, &pfdMngs)
}

func (p *Processor) PostPFDManagementTransactions(
	c *gin.Context,
	scsAsID string,
	pfdMng *models.PfdManagement,
) {
	logger.PFDManageLog.Infof("PostPFDManagementTransactions - scsAsID[%s]", scsAsID)

	// TODO: Authorize the AF

	nefCtx := p.Context()
	if pd := validatePfdManagement(scsAsID, "-1", pfdMng, nefCtx); pd != nil {
		if pd.Status == http.StatusInternalServerError {
			c.JSON(http.StatusInternalServerError, &pfdMng.PfdReports)
			return
		} else {
			c.JSON(int(pd.Status), pd)
			return
		}
	}

	af := nefCtx.GetAf(scsAsID)
	if af == nil {
		c.JSON(http.StatusNotFound, openapi.ProblemDetailsDataNotFound(DetailNoAF))
		return
	}

	af.Mu.Lock()
	defer af.Mu.Unlock()

	afPfdTr := af.NewPfdTrans()
	if afPfdTr == nil {
		pd := openapi.ProblemDetailsSystemFailure("No resource can be allocated")
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdNotifyContext := p.Notifier().PfdChangeNotifier.NewPfdNotifyContext()
	defer pfdNotifyContext.FlushNotifications()

	for appID, pfdData := range pfdMng.PfdDatas {
		afPfdTr.AddExtAppID(appID)
		pfdDataForApp := convertPfdDataToPfdDataForApp(&pfdData)
		if pfdReport := p.storePfdDataToUDR(appID, pfdDataForApp); pfdReport != nil {
			delete(pfdMng.PfdDatas, appID)
			addPfdReport(pfdMng, pfdReport)
		} else {
			pfdData.Self = p.genPfdDataURI(scsAsID, afPfdTr.TransID, appID)
			pfdMng.PfdDatas[appID] = pfdData
			pfdNotifyContext.AddNotification(appID, &models.PfdChangeNotification{
				ApplicationId: appID,
				Pfds:          pfdDataForApp.Pfds,
			})
		}
	}
	if len(pfdMng.PfdDatas) == 0 {
		// The PFDs for all applications were not created successfully.
		// PfdReport is included with detailed information.
		c.JSON(http.StatusInternalServerError, &pfdMng.PfdReports)
		return
	}

	af.PfdTrans[afPfdTr.TransID] = afPfdTr
	afPfdTr.Log.Infoln("PFD Management Transaction is added")

	nefCtx.AddAf(af)

	pfdMng.Self = p.genPfdManagementURI(scsAsID, afPfdTr.TransID)

	c.JSON(http.StatusCreated, pfdMng)
}

func (p *Processor) DeletePFDManagementTransactions(c *gin.Context, scsAsID string) {
	logger.PFDManageLog.Infof("DeletePFDManagementTransactions - scsAsID[%s]", scsAsID)

	nefCtx := p.Context()
	af := nefCtx.GetAf(scsAsID)
	if af == nil {
		c.JSON(http.StatusNotFound, openapi.ProblemDetailsDataNotFound(DetailNoAF))
		return
	}

	af.Mu.Lock()
	defer af.Mu.Unlock()

	pfdNotifyContext := p.Notifier().PfdChangeNotifier.NewPfdNotifyContext()
	defer pfdNotifyContext.FlushNotifications()

	for _, afPfdTr := range af.PfdTrans {
		for extAppID := range afPfdTr.ExtAppIDs {
			if rsp := p.deletePfdDataFromUDR(extAppID); rsp != nil {
				c.JSON(rsp.Status, rsp.Body)
				return
			}
			pfdNotifyContext.AddNotification(extAppID, &models.PfdChangeNotification{
				ApplicationId: extAppID,
				RemovalFlag:   true,
			})
		}
		delete(af.PfdTrans, afPfdTr.TransID)
		afPfdTr.Log.Infoln("PFD Management Transaction is deleted")
	}

	// TODO: Remove AfCtx if its subscriptions and transactions are both empty

	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) GetIndividualPFDManagementTransaction(
	c *gin.Context, scsAsID, transID string,
) {
	logger.PFDManageLog.Infof("GetIndividualPFDManagementTransaction - scsAsID[%s], transID[%s]",
		scsAsID, transID)

	af := p.Context().GetAf(scsAsID)
	if af == nil {
		pd := openapi.ProblemDetailsDataNotFound("AF not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	af.Mu.RLock()
	defer af.Mu.RUnlock()

	afPfdTr, ok := af.PfdTrans[transID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("PFD transaction not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdMng, rsp := p.buildPfdManagement(scsAsID, afPfdTr)
	if pfdMng == nil {
		c.JSON(rsp.Status, rsp.Body)
		return
	}

	c.JSON(http.StatusOK, pfdMng)
}

func (p *Processor) PutIndividualPFDManagementTransaction(
	c *gin.Context,
	scsAsID, transID string,
	pfdMng *models.PfdManagement,
) {
	logger.PFDManageLog.Infof("PutIndividualPFDManagementTransaction - scsAsID[%s], transID[%s]",
		scsAsID, transID)

	// TODO: Authorize the AF

	nefCtx := p.Context()
	if pd := validatePfdManagement(scsAsID, transID, pfdMng, nefCtx); pd != nil {
		if pd.Status == http.StatusInternalServerError {
			c.JSON(http.StatusInternalServerError, &pfdMng.PfdReports)
			return
		} else {
			c.JSON(int(pd.Status), pd)
			return
		}
	}

	af := nefCtx.GetAf(scsAsID)
	if af == nil {
		pd := openapi.ProblemDetailsDataNotFound("AF not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	af.Mu.Lock()
	defer af.Mu.Unlock()

	afPfdTr, ok := af.PfdTrans[transID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("PFD transaction not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdNotifyContext := p.Notifier().PfdChangeNotifier.NewPfdNotifyContext()
	defer pfdNotifyContext.FlushNotifications()

	// Delete PfdDataForApps in UDR with appID absent in new PfdManagement
	deprecatedAppIDs := []string{}
	for extAppID := range afPfdTr.ExtAppIDs {
		if _, exist := pfdMng.PfdDatas[extAppID]; !exist {
			deprecatedAppIDs = append(deprecatedAppIDs, extAppID)
		}
	}
	for _, appID := range deprecatedAppIDs {
		if rsp := p.deletePfdDataFromUDR(appID); rsp != nil {
			c.JSON(rsp.Status, rsp.Body)
			return
		}
		pfdNotifyContext.AddNotification(appID, &models.PfdChangeNotification{
			ApplicationId: appID,
			RemovalFlag:   true,
		})
	}

	afPfdTr.DeleteAllExtAppIDs()
	for appID, pfdData := range pfdMng.PfdDatas {
		afPfdTr.AddExtAppID(appID)
		pfdDataForApp := convertPfdDataToPfdDataForApp(&pfdData)
		if pfdReport := p.storePfdDataToUDR(appID, pfdDataForApp); pfdReport != nil {
			delete(pfdMng.PfdDatas, appID)
			addPfdReport(pfdMng, pfdReport)
		} else {
			pfdData.Self = p.genPfdDataURI(scsAsID, afPfdTr.TransID, appID)
			pfdMng.PfdDatas[appID] = pfdData
			pfdNotifyContext.AddNotification(appID, &models.PfdChangeNotification{
				ApplicationId: appID,
				Pfds:          pfdDataForApp.Pfds,
			})
		}
	}
	if len(pfdMng.PfdDatas) == 0 {
		// The PFDs for all applications were not created successfully.
		// PfdReport is included with detailed information.
		c.JSON(http.StatusInternalServerError, &pfdMng.PfdReports)
		return
	}

	pfdMng.Self = p.genPfdManagementURI(scsAsID, afPfdTr.TransID)

	c.JSON(http.StatusOK, pfdMng)
}

func (p *Processor) DeleteIndividualPFDManagementTransaction(
	c *gin.Context, scsAsID, transID string,
) {
	logger.PFDManageLog.Infof("DeleteIndividualPFDManagementTransaction - scsAsID[%s], transID[%s]", scsAsID, transID)

	nefCtx := p.Context()
	af := nefCtx.GetAf(scsAsID)
	if af == nil {
		pd := openapi.ProblemDetailsDataNotFound("AF not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	af.Mu.Lock()
	defer af.Mu.Unlock()

	afPfdTr, ok := af.PfdTrans[transID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("PFD transaction not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdNotifyContext := p.Notifier().PfdChangeNotifier.NewPfdNotifyContext()
	defer pfdNotifyContext.FlushNotifications()

	for extAppID := range afPfdTr.ExtAppIDs {
		if rsp := p.deletePfdDataFromUDR(extAppID); rsp != nil {
			c.JSON(rsp.Status, rsp.Body)
			return
		}
		pfdNotifyContext.AddNotification(extAppID, &models.PfdChangeNotification{
			ApplicationId: extAppID,
			RemovalFlag:   true,
		})
	}
	delete(af.PfdTrans, afPfdTr.TransID)
	afPfdTr.Log.Infoln("PFD Management Transaction is deleted")

	// TODO: Remove AfCtx if its subscriptions and transactions are both empty

	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) GetIndividualApplicationPFDManagement(
	c *gin.Context, scsAsID, transID, appID string,
) {
	logger.PFDManageLog.Infof("GetIndividualApplicationPFDManagement - scsAsID[%s], transID[%s], appID[%s]",
		scsAsID, transID, appID)

	af := p.Context().GetAf(scsAsID)
	if af == nil {
		pd := openapi.ProblemDetailsDataNotFound("AF not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	af.Mu.RLock()
	defer af.Mu.RUnlock()

	afPfdTr, ok := af.PfdTrans[transID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("PFD transaction not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	_, ok = afPfdTr.ExtAppIDs[appID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("Application ID not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	rspCode, rspBody := p.Consumer().AppDataPfdsAppIdGet(appID)
	if rspCode != http.StatusOK {
		c.JSON(rspCode, rspBody)
		return
	}
	pfdData := convertPfdDataForAppToPfdData(rspBody.(*models.PfdDataForAppExt))
	pfdData.Self = p.genPfdDataURI(scsAsID, transID, appID)

	c.JSON(http.StatusOK, pfdData)
}

func (p *Processor) DeleteIndividualApplicationPFDManagement(
	c *gin.Context, scsAsID, transID, appID string,
) {
	logger.PFDManageLog.Infof("DeleteIndividualApplicationPFDManagement - scsAsID[%s], transID[%s], appID[%s]",
		scsAsID, transID, appID)

	af := p.Context().GetAf(scsAsID)
	if af == nil {
		pd := openapi.ProblemDetailsDataNotFound("AF not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	af.Mu.Lock()
	defer af.Mu.Unlock()

	afPfdTr, ok := af.PfdTrans[transID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("PFD transaction not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	_, ok = afPfdTr.ExtAppIDs[appID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("Application ID not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdNotifyContext := p.Notifier().PfdChangeNotifier.NewPfdNotifyContext()
	defer pfdNotifyContext.FlushNotifications()

	if rsp := p.deletePfdDataFromUDR(appID); rsp != nil {
		c.JSON(rsp.Status, rsp.Body)
		return
	}
	afPfdTr.DeleteExtAppID(appID)
	pfdNotifyContext.AddNotification(appID, &models.PfdChangeNotification{
		ApplicationId: appID,
		RemovalFlag:   true,
	})

	// TODO: Remove afPfdTr if its appID is empty

	// TODO: Remove AfCtx if its subscriptions and transactions are both empty

	c.JSON(http.StatusNoContent, nil)
}

func (p *Processor) PutIndividualApplicationPFDManagement(
	c *gin.Context,
	scsAsID, transID, appID string,
	pfdData *models.PfdData,
) {
	logger.PFDManageLog.Infof("PutIndividualApplicationPFDManagement - scsAsID[%s], transID[%s], appID[%s]",
		scsAsID, transID, appID)

	// TODO: Authorize the AF

	nefCtx := p.Context()
	af := nefCtx.GetAf(scsAsID)
	if af == nil {
		pd := openapi.ProblemDetailsDataNotFound("AF not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	af.Mu.Lock()
	defer af.Mu.Unlock()

	afPfdTr, ok := af.PfdTrans[transID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("PFD transaction not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	_, ok = afPfdTr.ExtAppIDs[appID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("Application ID not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	if pd := validatePfdData(pfdData, nefCtx, false); pd != nil {
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdNotifyContext := p.Notifier().PfdChangeNotifier.NewPfdNotifyContext()
	defer pfdNotifyContext.FlushNotifications()

	pfdDataForApp := convertPfdDataToPfdDataForApp(pfdData)
	if pfdReport := p.storePfdDataToUDR(appID, pfdDataForApp); pfdReport != nil {
		c.JSON(http.StatusInternalServerError, pfdReport)
		return
	}
	pfdData.Self = p.genPfdDataURI(scsAsID, transID, appID)
	pfdNotifyContext.AddNotification(appID, &models.PfdChangeNotification{
		ApplicationId: appID,
		Pfds:          pfdDataForApp.Pfds,
	})

	c.JSON(http.StatusOK, pfdData)
}

func (p *Processor) PatchIndividualApplicationPFDManagement(
	c *gin.Context,
	scsAsID, transID, appID string,
	pfdData *models.PfdData,
) {
	logger.PFDManageLog.Infof("PatchIndividualApplicationPFDManagement - scsAsID[%s], transID[%s], appID[%s]",
		scsAsID, transID, appID)

	// TODO: Authorize the AF

	nefCtx := p.Context()
	af := nefCtx.GetAf(scsAsID)
	if af == nil {
		pd := openapi.ProblemDetailsDataNotFound("AF not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	af.Mu.Lock()
	defer af.Mu.Unlock()

	afPfdTr, ok := af.PfdTrans[transID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("PFD transaction not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	_, ok = afPfdTr.ExtAppIDs[appID]
	if !ok {
		pd := openapi.ProblemDetailsDataNotFound("Application ID not found")
		c.JSON(int(pd.Status), pd)
		return
	}

	if pd := validatePfdData(pfdData, nefCtx, true); pd != nil {
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdNotifyContext := p.Notifier().PfdChangeNotifier.NewPfdNotifyContext()
	defer pfdNotifyContext.FlushNotifications()

	rspCode, rspBody := p.Consumer().AppDataPfdsAppIdGet(appID)
	if rspCode != http.StatusOK {
		c.JSON(rspCode, rspBody)
		return
	}

	oldPfdData := convertPfdDataForAppToPfdData(rspBody.(*models.PfdDataForAppExt))
	if pd := patchModifyPfdData(oldPfdData, pfdData); pd != nil {
		c.JSON(int(pd.Status), pd)
		return
	}

	pfdDataForApp := convertPfdDataToPfdDataForApp(oldPfdData)
	if pfdReport := p.storePfdDataToUDR(appID, pfdDataForApp); pfdReport != nil {
		c.JSON(http.StatusInternalServerError, pfdReport)
		return
	}
	oldPfdData.Self = p.genPfdDataURI(scsAsID, transID, appID)
	pfdNotifyContext.AddNotification(appID, &models.PfdChangeNotification{
		ApplicationId: appID,
		Pfds:          pfdDataForApp.Pfds,
	})

	c.JSON(http.StatusOK, oldPfdData)
}

func (p *Processor) buildPfdManagement(
	afID string,
	afPfdTr *nef_context.AfPfdTransaction,
) (*models.PfdManagement, *HandlerResponse) {
	transID := afPfdTr.TransID
	appIDs := afPfdTr.GetExtAppIDs()
	pfdMng := &models.PfdManagement{
		Self:     p.genPfdManagementURI(afID, transID),
		PfdDatas: make(map[string]models.PfdData, len(appIDs)),
	}

	rspCode, rspBody := p.Consumer().AppDataPfdsGet(appIDs)
	if rspCode != http.StatusOK {
		return nil, &HandlerResponse{rspCode, nil, rspBody}
	}
	for _, pfdDataForApp := range *(rspBody.(*[]models.PfdDataForAppExt)) {
		pfdData := convertPfdDataForAppToPfdData(&pfdDataForApp)
		pfdData.Self = p.genPfdDataURI(afID, transID, pfdData.ExternalAppId)
		pfdMng.PfdDatas[pfdData.ExternalAppId] = *pfdData
	}
	return pfdMng, nil
}

func (p *Processor) storePfdDataToUDR(appID string, pfdDataForApp *models.PfdDataForAppExt) *models.PfdReport {
	rspCode, _ := p.Consumer().AppDataPfdsAppIdPut(appID, pfdDataForApp)
	if rspCode != http.StatusCreated && rspCode != http.StatusOK {
		return &models.PfdReport{
			ExternalAppIds: []string{appID},
			FailureCode:    models.FailureCode_MALFUNCTION,
		}
	}
	return nil
}

func (p *Processor) deletePfdDataFromUDR(appID string) *HandlerResponse {
	rspCode, rspBody := p.Consumer().AppDataPfdsAppIdDelete(appID)
	if rspCode != http.StatusNoContent {
		return &HandlerResponse{rspCode, nil, rspBody}
	}
	return nil
}

// The behavior of PATCH update is based on TS 29.250 v1.15.1 clause 4.4.1
func patchModifyPfdData(oldPfdData, newPfdData *models.PfdData) *models.ProblemDetails {
	for pfdID, newPfd := range newPfdData.Pfds {
		_, exist := oldPfdData.Pfds[pfdID]
		if len(newPfd.FlowDescriptions) == 0 && len(newPfd.Urls) == 0 && len(newPfd.DomainNames) == 0 {
			if exist {
				// New Pfd with existing PfdID and empty content implies deletion from old PfdData.
				delete(oldPfdData.Pfds, pfdID)
			} else {
				// Otherwire, if the PfdID doesn't exist yet, the Pfd still needs valid content.
				return openapi.ProblemDetailsDataNotFound(DetailNoPfdInfo)
			}
		} else {
			// Either add or update the Pfd to the old PfdData.
			oldPfdData.Pfds[pfdID] = newPfd
		}
	}
	return nil
}

func convertPfdDataForAppToPfdData(pfdDataForApp *models.PfdDataForAppExt) *models.PfdData {
	pfdData := &models.PfdData{
		ExternalAppId: pfdDataForApp.ApplicationId,
		Pfds:          make(map[string]models.Pfd, len(pfdDataForApp.Pfds)),
	}
	for _, pfdContent := range pfdDataForApp.Pfds {
		var pfd models.Pfd
		pfd.PfdId = pfdContent.PfdId
		pfd.FlowDescriptions = pfdContent.FlowDescriptions
		pfd.Urls = pfdContent.Urls
		pfd.DomainNames = pfdContent.DomainNames
		pfdData.Pfds[pfdContent.PfdId] = pfd
	}
	return pfdData
}

func convertPfdDataToPfdDataForApp(pfdData *models.PfdData) *models.PfdDataForAppExt {
	pfdDataForApp := &models.PfdDataForAppExt{
		ApplicationId: pfdData.ExternalAppId,
	}
	for _, pfd := range pfdData.Pfds {
		var pfdContent models.PfdContent
		pfdContent.PfdId = pfd.PfdId
		pfdContent.FlowDescriptions = pfd.FlowDescriptions
		pfdContent.Urls = pfd.Urls
		pfdContent.DomainNames = pfd.DomainNames
		pfdDataForApp.Pfds = append(pfdDataForApp.Pfds, pfdContent)
	}
	return pfdDataForApp
}

func (p *Processor) genPfdManagementURI(afID, transID string) string {
	// E.g. https://localhost:29505/3gpp-pfd-management/v1/{afID}/transactions/{transID}
	return fmt.Sprintf("%s/%s/transactions/%s",
		p.Config().ServiceUri(factory.ServicePfdMng), afID, transID)
}

func (p *Processor) genPfdDataURI(afID, transID, appID string) string {
	// E.g. https://localhost:29505/3gpp-pfd-management/v1/{afID}/transactions/{transID}/applications/{appID}
	return fmt.Sprintf("%s/%s/transactions/%s/applications/%s",
		p.Config().ServiceUri(factory.ServicePfdMng), afID, transID, appID)
}

func validatePfdManagement(
	afID, transID string,
	pfdMng *models.PfdManagement,
	nefCtx *nef_context.NefContext,
) *models.ProblemDetails {
	pfdMng.PfdReports = make(map[string]models.PfdReport)

	if len(pfdMng.PfdDatas) == 0 {
		return openapi.ProblemDetailsDataNotFound(DetailNoPfdData)
	}

	for appID, pfdData := range pfdMng.PfdDatas {
		// Check whether the received external Application Identifier(s) are already provisioned
		appAfID, appTransID, ok := nefCtx.IsAppIDExisted(appID)
		if ok && (appAfID != afID || appTransID != transID) {
			delete(pfdMng.PfdDatas, appID)
			addPfdReport(pfdMng, &models.PfdReport{
				ExternalAppIds: []string{appID},
				FailureCode:    models.FailureCode_APP_ID_DUPLICATED,
			})
		}
		if pd := validatePfdData(&pfdData, nefCtx, false); pd != nil {
			return pd
		}
	}

	if len(pfdMng.PfdDatas) == 0 {
		// The PFDs for all applications were not created successfully.
		// PfdReport is included with detailed information.
		return openapi.ProblemDetailsSystemFailure("None of the PFDs were created")
	}
	return nil
}

func validatePfdData(pfdData *models.PfdData, nefCtx *nef_context.NefContext, isPatch bool) *models.ProblemDetails {
	if pfdData.ExternalAppId == "" {
		return openapi.ProblemDetailsDataNotFound(DetailNoExtAppID)
	}

	if len(pfdData.Pfds) == 0 {
		return openapi.ProblemDetailsDataNotFound(DetailNoPfd)
	}

	for _, pfd := range pfdData.Pfds {
		if pfd.PfdId == "" {
			return openapi.ProblemDetailsDataNotFound(DetailNoPfdID)
		}
		// For PATCH method, empty these three attributes is used to imply the deletion of this PFD
		if !isPatch && len(pfd.FlowDescriptions) == 0 && len(pfd.Urls) == 0 && len(pfd.DomainNames) == 0 {
			return openapi.ProblemDetailsDataNotFound(DetailNoPfdInfo)
		}
	}

	return nil
}

func addPfdReport(pfdMng *models.PfdManagement, newReport *models.PfdReport) {
	if oldReport, ok := pfdMng.PfdReports[string(newReport.FailureCode)]; ok {
		oldReport.ExternalAppIds = append(oldReport.ExternalAppIds, newReport.ExternalAppIds...)
	} else {
		pfdMng.PfdReports[string(newReport.FailureCode)] = *newReport
	}
}
