package consumer

import (
	"net/http"
	"reflect"
	"sync"

	// "github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFDiscovery"
	"github.com/free5gc/openapi/udr/DataRepository"
)

type nudrService struct {
	consumer *Consumer

	mu      sync.RWMutex
	clients map[string]*DataRepository.APIClient
}

func (s *nudrService) getClient(uri string) *DataRepository.APIClient {
	s.mu.RLock()
	if client, ok := s.clients[uri]; ok {
		defer s.mu.RUnlock()
		return client
	} else {
		configuration := DataRepository.NewConfiguration()
		configuration.SetBasePath(uri)
		configuration.SetHTTPClient(http.DefaultClient)
		cli := DataRepository.NewAPIClient(configuration)

		s.mu.RUnlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.clients[uri] = cli
		return cli
	}
}

func (s *nudrService) getUdrDrUri() (string, error) {
	uri := s.consumer.Context().UdrDrUri()
	if uri == "" {
		localVarOptionals := NFDiscovery.SearchNFInstancesRequest{
			ServiceNames: []models.ServiceName{
				models.ServiceName_NUDR_DR,
			},
		}
		_, sUri, err := s.consumer.SearchNFInstances(s.consumer.Config().NrfUri(),
			models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR, models.NrfNfManagementNfType_NEF, &localVarOptionals)
		if err == nil {
			s.consumer.Context().SetUdrDrUri(sUri)
		}
		return sUri, err
	}
	return uri, nil
}

func (s *nudrService) AppDataInfluenceDataGet(influenceIDs []string) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.ReadInfluenceDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	readInfluenceDataReq := &DataRepository.ReadInfluenceDataRequest{
		InfluenceIds: influenceIDs,
	}
	result, err = client.InfluenceDataStoreApi.ReadInfluenceData(ctx, readInfluenceDataReq)
	if err != nil {
		return handleAPIServiceNoResponse(err)
	}

	if result == nil || reflect.DeepEqual(result.TrafficInfluData, []models.TrafficInfluData{}) {
		return http.StatusNoContent, nil
	}

	return http.StatusOK, result.TrafficInfluData
}

func (s *nudrService) AppDataInfluenceDataIdGet(influenceID string) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.ReadInfluenceDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	readInfluenceDataReq := &DataRepository.ReadInfluenceDataRequest{
		InfluenceIds: []string{influenceID},
	}
	result, err = client.InfluenceDataStoreApi.ReadInfluenceData(ctx, readInfluenceDataReq)

	if result != nil {
		rspCode = http.StatusOK
		rspBody = result.TrafficInfluData
	} else {
		rspCode, rspBody = handleAPIServiceNoResponse(err)
	}

	return rspCode, rspBody
}

func (s *nudrService) AppDataInfluenceDataPut(influenceID string,
	tiData *models.TrafficInfluData,
) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.CreateOrReplaceIndividualInfluenceDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	putInfluenceDataReq := &DataRepository.CreateOrReplaceIndividualInfluenceDataRequest{
		InfluenceId:      &influenceID,
		TrafficInfluData: tiData,
	}

	result, err = client.IndividualInfluenceDataDocumentApi.CreateOrReplaceIndividualInfluenceData(
		ctx, putInfluenceDataReq)

	if result != nil {
		if result.Location != "" {
			rspCode = http.StatusCreated
		} else if reflect.DeepEqual(result.TrafficInfluData, models.TrafficInfluData{}) {
			rspCode = http.StatusNoContent
		} else {
			rspCode = http.StatusOK
		}
		rspBody = result.TrafficInfluData
	} else {
		rspCode, rspBody = handleAPIServiceNoResponse(err)
	}

	return rspCode, rspBody
}

func (s *nudrService) AppDataInfluenceDataPatch(
	influenceID string, tiSubPatch *models.TrafficInfluDataPatch,
) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.UpdateIndividualInfluenceDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	patchInfluenceDataReq := &DataRepository.UpdateIndividualInfluenceDataRequest{
		InfluenceId:           &influenceID,
		TrafficInfluDataPatch: tiSubPatch,
	}
	result, err = client.IndividualInfluenceDataDocumentApi.UpdateIndividualInfluenceData(ctx, patchInfluenceDataReq)

	if result != nil {
		if reflect.DeepEqual(result.TrafficInfluData, models.TrafficInfluData{}) {
			rspCode = http.StatusNoContent
			rspBody = nil
		} else {
			rspCode = http.StatusOK
			rspBody = result.TrafficInfluData
		}
	} else {
		rspCode, rspBody = handleAPIServiceNoResponse(err)
	}

	return rspCode, rspBody
}

func (s *nudrService) AppDataInfluenceDataDelete(influenceID string) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.DeleteIndividualInfluenceDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	deleteInfluenceDataReq := &DataRepository.DeleteIndividualInfluenceDataRequest{
		InfluenceId: &influenceID,
	}
	result, err = client.IndividualInfluenceDataDocumentApi.
		DeleteIndividualInfluenceData(ctx, deleteInfluenceDataReq)

	if result != nil {
		rspCode = http.StatusNoContent
		rspBody = nil
	} else {
		rspCode, rspBody = handleAPIServiceNoResponse(err)
	}

	return rspCode, rspBody
}

// TS 29.519 v15.3.0 6.2.3.3.1
func (s *nudrService) AppDataPfdsGet(appIDs []string) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.ReadPFDDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	readPfdDataReq := &DataRepository.ReadPFDDataRequest{
		AppId: appIDs,
	}
	result, err = client.PFDDataStoreApi.ReadPFDData(ctx, readPfdDataReq)

	if err == nil && result != nil {
		rspCode = http.StatusOK
		rspBody = &result.PfdDataForAppExt
		return rspCode, rspBody
	}

	if err != nil {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if pd, ok := apiErr.ErrorModel.(DataRepository.ReadPFDDataError); ok {
				rspCode = int(pd.ProblemDetails.Status)
				rspBody = &pd.ProblemDetails
				return rspCode, rspBody
			}
		}
	}

	rspCode, rspBody = handleAPIServiceNoResponse(err)
	return rspCode, rspBody
}

// TS 29.519 v15.3.0 6.2.4.3.3
func (s *nudrService) AppDataPfdsAppIdPut(appID string, pfdDataForApp *models.PfdDataForAppExt) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.CreateOrReplaceIndividualPFDDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	putPfdDataReq := &DataRepository.CreateOrReplaceIndividualPFDDataRequest{
		AppId:            &appID,
		PfdDataForAppExt: pfdDataForApp,
	}
	result, err = client.IndividualPFDDataDocumentApi.CreateOrReplaceIndividualPFDData(ctx, putPfdDataReq)

	if result != nil {
		if reflect.DeepEqual(result.PfdDataForAppExt, models.PfdDataForAppExt{}) {
			rspCode = http.StatusNoContent
			rspBody = nil
		} else if result.Location != "" {
			rspCode = http.StatusCreated
			rspBody = &result.PfdDataForAppExt
		} else {
			rspCode = http.StatusOK
			rspBody = &result.PfdDataForAppExt
		}
	} else {
		rspCode, rspBody = handleAPIServiceNoResponse(err)
	}

	return rspCode, rspBody
}

// TS 29.519 v15.3.0 6.2.4.3.2
func (s *nudrService) AppDataPfdsAppIdDelete(appID string) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.DeleteIndividualPFDDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	deletePfdDataReq := &DataRepository.DeleteIndividualPFDDataRequest{
		AppId: &appID,
	}
	result, err = client.IndividualPFDDataDocumentApi.DeleteIndividualPFDData(ctx, deletePfdDataReq)

	if result != nil {
		rspCode = http.StatusNoContent
		rspBody = nil
	} else {
		// API Service Internal Error or Server No Response
		rspCode, rspBody = handleAPIServiceNoResponse(err)
	}

	return rspCode, rspBody
}

// TS 29.519 v15.3.0 6.2.4.3.1
func (s *nudrService) AppDataPfdsAppIdGet(appID string) (int, interface{}) {
	var (
		err     error
		rspCode int
		rspBody interface{}
		result  *DataRepository.ReadIndividualPFDDataResponse
	)

	uri, err := s.getUdrDrUri()
	if err != nil {
		return rspCode, rspBody
	}
	client := s.getClient(uri)

	ctx, _, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		return rspCode, rspBody
	}

	readPfdDataReq := &DataRepository.ReadIndividualPFDDataRequest{
		AppId: &appID,
	}
	result, err = client.IndividualPFDDataDocumentApi.ReadIndividualPFDData(ctx, readPfdDataReq)

	if err == nil && result != nil {
		rspCode = http.StatusOK
		rspBody = &result.PfdDataForAppExt
		return rspCode, rspBody
	}

	if err != nil {
		if apiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if pd, ok := apiErr.ErrorModel.(DataRepository.ReadIndividualPFDDataError); ok {
				rspCode = int(pd.ProblemDetails.Status)
				rspBody = &pd.ProblemDetails
				return rspCode, rspBody
			}
		}
	}

	rspCode, rspBody = handleAPIServiceNoResponse(err)
	return rspCode, rspBody
}
