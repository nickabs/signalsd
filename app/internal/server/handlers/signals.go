package handlers

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/nickabs/signalsd/app/internal/apperrors"
	"github.com/nickabs/signalsd/app/internal/auth"
	"github.com/nickabs/signalsd/app/internal/database"
	"github.com/nickabs/signalsd/app/internal/server/responses"
	"github.com/rs/zerolog"
)

type SignalsHandler struct {
	queries *database.Queries
}

func NewSignalsHandler(queries *database.Queries) *SignalsHandler {
	return &SignalsHandler{queries: queries}
}

type CreateSignalsRequest struct {
	LocalRef      string     `json:"local_ref" example:"item1"`
	CorrelationId *uuid.UUID `json:"correlation_id" example:"75b45fe1-ecc2-4629-946b-fd9058c3b2ca"` //optional - supply the id of another signal if you want to link to it
	SignalBatchId uuid.UUID  `json:"signal_batch_id" example:"b51faf05-aaed-4250-b334-2258ccdf1ff2"`
}

// SignalsHandler godocs
//
//	@Summary		Send signals
//	@Tags			Signals Management
//
//	@Description	- the client can submit an array of signals to this endpoint for storage on the ISN
//	@Description	- payloads must not mix signals of different types, and the payload is subject to the sizen	limits defined on the ISN.
//	@Description	- The client-supplied local_ref must uniquely identify each signal of the specified signal type that will be supplied by the account.
//	@Description	- If a local reference is received more than once from an account for a specified signal_type it will be stored with a incremented version number.
//	@Description	The previous version will be marked as latest=false (it does not matter if the previous signal was received in a different batch, but the signal must
//	@Description	be owned by the same account).
//	@Description	- If a deletion request is received, all version of the signal will be marked as 'withdrawn'.
//	@Description	- Correlation_ids are auto generated on the server unless supplied by the client, in which case they are used to identify another signal that this signal is related to. The correlated signal does not need to be owned by the same account.
//	@Description	- requests are only accepted for the open signal batch for this account
//	@Description
//	@Description	* Authentication *
//	@Description
//	@Description	Requires a valid access token.
//	@Descirption	When the access token was created a database check was done to identify which isns the account has permission to use.
//	@Description	The claims in the access token include the ISNs that the account can use and all the available signal_types that can be received in each ISN.
//	@Description
//	@Description	- the RequireIsnWritePErmission middleware will consult the claims in the access token to confirm the user is allowed to write to the isn
//	@Description	- This handler checks that the signal_type in the url is also listed in the claims (this is to catch mistyped urls)
//
//	@Param			isn_slug	path		string								true	"isn slug"	example(sample-isn--example-org)
//	@Param			signal_type_slug	path		string								true	"signal type slug"	example(sample-signal--example-org)
//	@Param			version path		string								true	"signal type version number"	example(0.0.1)
//	@Param			request		body		handlers.CreateIsnReceiverRequest	true	"ISN receiver details"
//
//	@Success		204
//	@Failure		400	{object}	responses.ErrorResponse
//	@Failure		500	{object}	responses.ErrorResponse
//
//	@Security		BearerAccessToken
//
//	@Router			/isn/{isn_slug}/signal-types/{signal_type_slug}/v{version}/signals [post]
func (s *SignalsHandler) CreateSignalsHandler(w http.ResponseWriter, r *http.Request) {

	isnSlug := r.PathValue("isn_slug")
	signalTypeSlug := r.PathValue("signal_type_slug")
	version := r.PathValue("version")

	signalTypePath := fmt.Sprintf("%v/v%v", signalTypeSlug, version)
	claims, ok := auth.ContextAccessTokenClaims(r.Context())
	if !ok {
		responses.RespondWithError(w, r, http.StatusInternalServerError, apperrors.ErrCodeInternalError, "could not get claims from context")
		return
	}

	accountID, ok := auth.ContextAccountID(r.Context())
	if !ok {
		responses.RespondWithError(w, r, http.StatusInternalServerError, apperrors.ErrCodeInternalError, "could not get accountID from context")
		return
	}

	logger := zerolog.Ctx(r.Context())

	if claims.AccountID != accountID {
		responses.RespondWithError(w, r, http.StatusInternalServerError, apperrors.ErrCodeInternalError, "the accountID and the claims.AccountID from context do not match")
		return
	}

	// check that this the user is requesting a valid signal type/version for this isn
	found := false
	for _, path := range claims.IsnPerms[isnSlug].SignalTypePaths {
		if path == signalTypePath {
			found = true
			break
		}
	}
	if !found {
		responses.RespondWithError(w, r, http.StatusBadRequest, apperrors.ErrCodeResourceNotFound, fmt.Sprintf("signal type %v is not available on ISN %v", signalTypePath, isnSlug))
		return
	}

	logger.Debug().Msgf("user %v has perm for %v", accountID, signalTypePath)

	// is batch open?  Reject if not

	s.queries.GetLatestIsnSignalBatchByAccountID(r.Context(), accountID)
	//
	// split json into array
	// for array insert
	responses.RespondWithError(w, r, http.StatusNoContent, apperrors.ErrCodeNotImplemented, "todo - signals not yet implemented")
}

// DeleteSignalsHandler godocs
//
//	@Summary		Withdraw a signal (TODO)
//	@Tags			Signals Management
//
//	@Router			/isn/{isn_slug}/signal-types/{signal_type_slug}/signals/{signal_id} [delete]
func (s *SignalsHandler) DeleteSignalHandler(w http.ResponseWriter, r *http.Request) {
	responses.RespondWithError(w, r, http.StatusNoContent, apperrors.ErrCodeNotImplemented, "todo - signals not yet implemented")
}

// GetSignalsHandler godocs
//
//	@Summary		get a signal (TODO)
//	@Tags			Signals Management
//
//	@Router			/isn/{isn_slug}/signal-types/{signal_type_slug}/signals/{signal_id} [get]
func (s *SignalsHandler) GetSignalHandler(w http.ResponseWriter, r *http.Request) {
	responses.RespondWithError(w, r, http.StatusNoContent, apperrors.ErrCodeNotImplemented, "todo - signals not yet implemented")
}
