package controllerservice

import (
	"net/http"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
)

type endpointStatusRequest struct {
	ValidForSeconds    uint32  `json:"valid_for_seconds"`
	ProductVersion     string  `json:"product_version"`
	Platform           string  `json:"platform"`
	CertificateState   string  `json:"certificate_state"`
	ConfigurationState string  `json:"configuration_state"`
	CarrierState       string  `json:"carrier_state"`
	RouteState         string  `json:"route_state"`
	SelectedExitState  string  `json:"selected_exit_state"`
	CleanupFailures    *uint32 `json:"cleanup_failure_count"`
	ConfigurationEpoch *uint64 `json:"configuration_epoch"`
}

func (request endpointStatusRequest) report() (controller.EndpointStatusReport, error) {
	if request.CleanupFailures == nil || request.ConfigurationEpoch == nil {
		return controller.EndpointStatusReport{}, malformed("endpoint status requires cleanup_failure_count and configuration_epoch")
	}
	return controller.EndpointStatusReport{
		ValidForSeconds: request.ValidForSeconds, ProductVersion: request.ProductVersion,
		Platform:           controller.EndpointPlatform(request.Platform),
		CertificateState:   controller.CertificateStatusState(request.CertificateState),
		ConfigurationState: controller.ConfigurationStatusState(request.ConfigurationState),
		CarrierState:       controller.CarrierStatusState(request.CarrierState),
		RouteState:         controller.RouteStatusState(request.RouteState),
		SelectedExitState:  controller.SelectedExitStatusState(request.SelectedExitState),
		CleanupFailures:    *request.CleanupFailures, ConfigurationEpoch: *request.ConfigurationEpoch,
	}, nil
}

// recordEndpointStatus accepts only a currently authorized node identity and
// stores one latest, expiring observation. Authentication happens before body
// parsing so malformed input cannot become a node-existence oracle.
func (s *Service) recordEndpointStatus(w http.ResponseWriter, r *http.Request) {
	caller, err := s.authenticatedNode(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request endpointStatusRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	report, err := request.report()
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if err := s.store.RecordEndpointStatus(r.Context(), caller, report, s.now()); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type endpointRuntimeReportResponse struct {
	ValidForSeconds    uint32 `json:"valid_for_seconds"`
	ProductVersion     string `json:"product_version"`
	Platform           string `json:"platform"`
	CertificateState   string `json:"certificate_state"`
	ConfigurationState string `json:"configuration_state"`
	CarrierState       string `json:"carrier_state"`
	RouteState         string `json:"route_state"`
	SelectedExitState  string `json:"selected_exit_state"`
	CleanupFailures    uint32 `json:"cleanup_failure_count"`
	ConfigurationEpoch uint64 `json:"configuration_epoch"`
}

type endpointStatusResponse struct {
	NodeID                          string                         `json:"node_id"`
	NetworkID                       string                         `json:"network_id"`
	NodeName                        string                         `json:"node_name"`
	AuthoritativeConfigurationEpoch uint64                         `json:"authoritative_configuration_epoch"`
	Freshness                       string                         `json:"freshness"`
	LastReportedAtUnixSeconds       *int64                         `json:"last_reported_at_unix_seconds,omitempty"`
	ExpiresAtUnixSeconds            *int64                         `json:"expires_at_unix_seconds,omitempty"`
	Report                          *endpointRuntimeReportResponse `json:"report,omitempty"`
}

func endpointStatusJSON(value controller.EndpointStatus) endpointStatusResponse {
	response := endpointStatusResponse{
		NodeID: value.NodeID.String(), NetworkID: value.NetworkID.String(), NodeName: value.NodeName,
		AuthoritativeConfigurationEpoch: value.AuthoritativeConfigurationEpoch, Freshness: string(value.Freshness),
	}
	if value.LastReportedAt != nil {
		lastReported := value.LastReportedAt.Unix()
		response.LastReportedAtUnixSeconds = &lastReported
	}
	if value.ExpiresAt != nil {
		expires := value.ExpiresAt.Unix()
		response.ExpiresAtUnixSeconds = &expires
	}
	if value.Report != nil {
		response.Report = &endpointRuntimeReportResponse{
			ValidForSeconds: value.Report.ValidForSeconds, ProductVersion: value.Report.ProductVersion,
			Platform: string(value.Report.Platform), CertificateState: string(value.Report.CertificateState),
			ConfigurationState: string(value.Report.ConfigurationState), CarrierState: string(value.Report.CarrierState),
			RouteState: string(value.Report.RouteState), SelectedExitState: string(value.Report.SelectedExitState),
			CleanupFailures: value.Report.CleanupFailures, ConfigurationEpoch: value.Report.ConfigurationEpoch,
		}
	}
	return response
}

func (s *Service) readEndpointStatuses(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	limit, err := queryLimit(r, 100)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.AdministratorNetworkEndpointStatuses(r.Context(), decision, networkID, limit, s.now())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]endpointStatusResponse, 0, len(values))
	for _, value := range values {
		response = append(response, endpointStatusJSON(value))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"endpoint_statuses": response})
}
