package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	ctx "github.com/gophish/gophish/context"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
)

// SendingProfiles handles requests for the /api/smtp/ endpoint
func (as *Server) SendingProfiles(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "GET":
		ss, err := models.GetSMTPs(ctx.Get(r, "user_id").(int64))
		if err != nil {
			log.Error(err)
		}
		JSONResponse(w, ss, http.StatusOK)
	//POST: Create a new SMTP and return it as JSON
	case r.Method == "POST":
		s := models.SMTP{}
		// Put the request into a page
		err := json.NewDecoder(r.Body).Decode(&s)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Invalid request"}, http.StatusBadRequest)
			return
		}
		// Check to make sure the name is unique
		_, err = models.GetSMTPByName(s.Name, ctx.Get(r, "user_id").(int64))
		if err != gorm.ErrRecordNotFound {
			JSONResponse(w, models.Response{Success: false, Message: "SMTP name already in use"}, http.StatusConflict)
			log.Error(err)
			return
		}
		s.ModifiedDate = time.Now().UTC()
		s.UserId = ctx.Get(r, "user_id").(int64)
		err = models.PostSMTP(&s)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
			return
		}
		JSONResponse(w, s, http.StatusCreated)
	}
}

// SendingProfile contains functions to handle the GET'ing, DELETE'ing, and PUT'ing
// of a SMTP object
func (as *Server) SendingProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, _ := strconv.ParseInt(vars["id"], 0, 64)
	s, err := models.GetSMTP(id, ctx.Get(r, "user_id").(int64))
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "SMTP not found"}, http.StatusNotFound)
		return
	}
	switch {
	case r.Method == "GET":
		JSONResponse(w, s, http.StatusOK)
	case r.Method == "DELETE":
		err = models.DeleteSMTP(id, ctx.Get(r, "user_id").(int64))
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Error deleting SMTP"}, http.StatusInternalServerError)
			return
		}
		JSONResponse(w, models.Response{Success: true, Message: "SMTP Deleted Successfully"}, http.StatusOK)
	case r.Method == "PUT":
		s = models.SMTP{}
		err = json.NewDecoder(r.Body).Decode(&s)
		if err != nil {
			log.Error(err)
		}
		if s.Id != id {
			JSONResponse(w, models.Response{Success: false, Message: "/:id and /:smtp_id mismatch"}, http.StatusBadRequest)
			return
		}
		
		// Set user context information
		s.UserId = ctx.Get(r, "user_id").(int64)
		
		// Get user from context and log what we find
		log.Infof("Processing SMTP profile update for user_id: %d", s.UserId)
		if user := ctx.Get(r, "user"); user != nil {
			log.Infof("User found in context")
			// Convert to User type - this might fail if user is not properly loaded
			u, ok := user.(models.User)
			if !ok {
				log.Errorf("User in context is not a models.User type")
			} else {
				log.Infof("User details - ID: %d, Username: %s, Tenant ID: %s", 
					u.Id, u.Username, u.TenantID)
				
				// Pass tenant info to the SMTP model if available
				if u.TenantID != "" {
					log.Infof("Setting tenant ID from context: %s", u.TenantID)
					s.TenantID = u.TenantID
					
					// Log provider tenants if available
					if len(u.ProviderTenants) > 0 {
						log.Infof("User has %d provider tenants", len(u.ProviderTenants))
						for i, pt := range u.ProviderTenants {
							log.Infof("Provider tenant %d: ID=%s, Type=%s, ProviderTenantID=%s", 
								i, pt.ID, pt.ProviderType, pt.ProviderTenantID)
							
							if pt.ProviderType == models.ProviderTypeAzure {
								log.Infof("Found Azure provider tenant: %s", pt.ID)
								s.ProviderTenant = pt
								break
							}
						}
					} else {
						log.Infof("No provider tenants found for user")
					}
				} else {
					log.Infof("No tenant ID available in user context")
				}
			}
		} else {
			log.Warnf("No user found in context, falling back to UserId only: %d", s.UserId)
			
			// Since we don't have the user in context with tenant info,
			// we'll let the model layer try to fetch it
		}
		
		s.ModifiedDate = time.Now().UTC()
		err = models.PutSMTP(&s)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
			return
		}
		JSONResponse(w, s, http.StatusOK)
	}
}
