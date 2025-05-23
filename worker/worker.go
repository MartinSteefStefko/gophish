package worker

import (
	"context"
	"fmt"
	"time"

	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/mailer"
	"github.com/gophish/gophish/models"
	"github.com/sirupsen/logrus"
)

// Worker is an interface that defines the operations needed for a background worker
type Worker interface {
	Start()
	LaunchCampaign(c models.Campaign)
	SendTestEmail(s *models.EmailRequest) error
}

// DefaultWorker is the background worker that handles watching for new campaigns and sending emails appropriately.
type DefaultWorker struct {
	mailer mailer.Mailer
}

// New creates a new worker object to handle the creation of campaigns
func New(options ...func(Worker) error) (Worker, error) {
	defaultMailer := mailer.NewMailWorker()
	w := &DefaultWorker{
		mailer: defaultMailer,
	}
	for _, opt := range options {
		if err := opt(w); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// WithMailer sets the mailer for a given worker.
// By default, workers use a standard, default mailworker.
func WithMailer(m mailer.Mailer) func(*DefaultWorker) error {
	return func(w *DefaultWorker) error {
		w.mailer = m
		return nil
	}
}

// processCampaigns loads maillogs scheduled to be sent before the provided
// time and sends them to the mailer.
func (w *DefaultWorker) processCampaigns(t time.Time) error {
	ms, err := models.GetQueuedMailLogs(t.UTC())
	if err != nil {
		log.Error(err)
		return err
	}
	// Lock the MailLogs (they will be unlocked after processing)
	err = models.LockMailLogs(ms, true)
	if err != nil {
		return err
	}
	campaignCache := make(map[int64]models.Campaign)
	// We'll group the maillogs by campaign ID to (roughly) group
	// them by sending profile. This lets the mailer re-use the Sender
	// instead of having to re-connect to the SMTP server for every
	// email.
	msg := make(map[int64][]mailer.Mail)
	for _, m := range ms {
		// We cache the campaign here to greatly reduce the time it takes to
		// generate the message (ref #1726)
		c, ok := campaignCache[m.CampaignId]
		if !ok {
			c, err = models.GetCampaignMailContext(m.CampaignId, m.UserId)
			if err != nil {
				return err
			}
			campaignCache[c.Id] = c
		}
		m.CacheCampaign(&c)
		msg[m.CampaignId] = append(msg[m.CampaignId], m)
	}

	// Next, we process each group of maillogs in parallel
	for cid, msc := range msg {
		go func(cid int64, msc []mailer.Mail) {
			c := campaignCache[cid]
			if c.Status == models.CampaignQueued {
				err := c.UpdateStatus(models.CampaignInProgress)
				if err != nil {
					log.Error(err)
					return
				}
			}
			log.WithFields(logrus.Fields{
				"num_emails": len(msc),
			}).Info("Sending emails to mailer for processing")
			w.mailer.Queue(msc)
		}(cid, msc)
	}
	return nil
}

// Start launches the worker to poll the database every minute for any pending maillogs
// that need to be processed.
func (w *DefaultWorker) Start() {
	log.Info("Background Worker Started Successfully - Waiting for Campaigns")
	go w.mailer.Start(context.Background())
	for t := range time.Tick(1 * time.Minute) {
		err := w.processCampaigns(t)
		if err != nil {
			log.Error(err)
			continue
		}
	}
}

// getAzureProviderTenantForUser gets the Azure provider tenant for a user
func getAzureProviderTenantForUser(userID int64) (*models.ProviderTenant, error) {
	// Get the user to get their provider tenants
	user, err := models.GetUser(userID)
	if err != nil {
		log.Errorf("Failed to get user %d: %v", userID, err)
		return nil, err
	}

	// Find the Azure provider tenant
	for _, pt := range user.ProviderTenants {
		if pt.ProviderType == models.ProviderTypeAzure {
			log.Infof("Found Azure provider tenant for user %d: %s (%s)", 
				userID, pt.DisplayName, pt.ProviderTenantID)
			return pt, nil
		}
	}

	err = fmt.Errorf("no Azure provider tenant found for user %d", userID)
	log.Error(err)
	return nil, err
}

// LaunchCampaign starts a campaign
func (w *DefaultWorker) LaunchCampaign(c models.Campaign) {
	ms, err := models.GetMailLogsByCampaign(c.Id)
	if err != nil {
		log.Error(err)
		return
	}
	models.LockMailLogs(ms, true)
	// This is required since you cannot pass a slice of values
	// that implements an interface as a slice of that interface.
	mailEntries := []mailer.Mail{}
	currentTime := time.Now().UTC()
	campaignMailCtx, err := models.GetCampaignMailContext(c.Id, c.UserId)
	if err != nil {
		log.Error(err)
		return
	}

	// If this is a Graph API profile, get the provider tenant
	if campaignMailCtx.SMTP.Interface == "GRAPH" {
		pt, err := getAzureProviderTenantForUser(c.UserId)
		if err != nil {
			log.Errorf("Failed to get Azure provider tenant for campaign %d: %v", c.Id, err)
			return
		}
		campaignMailCtx.SMTP.ProviderTenant = pt
		log.Infof("Using provider tenant for campaign %d: %s (%s)", 
			c.Id, pt.DisplayName, pt.ProviderTenantID)
	}

	for _, m := range ms {
		// Only send the emails scheduled to be sent for the past minute to
		// respect the campaign scheduling options
		if m.SendDate.After(currentTime) {
			m.Unlock()
			continue
		}
		err = m.CacheCampaign(&campaignMailCtx)
		if err != nil {
			log.Error(err)
			return
		}
		mailEntries = append(mailEntries, m)
	}
	w.mailer.Queue(mailEntries)
}

// SendTestEmail sends a test email
func (w *DefaultWorker) SendTestEmail(s *models.EmailRequest) error {
	// Log request details
	if s.SMTP.Interface == "GRAPH" {
		log.Infof("Processing Graph API test email request. From: %s", s.SMTP.FromAddress)
		
		// If provider tenant not set from context, get it from user
		if s.SMTP.ProviderTenant == nil {
			pt, err := getAzureProviderTenantForUser(s.UserId)
			if err != nil {
				return err
			}
			s.SMTP.ProviderTenant = pt
			log.Infof("Using provider tenant for test email: %s (%s)", 
				pt.DisplayName, pt.ProviderTenantID)
		} else {
			log.Infof("Using provider tenant from context: ID=%s, Type=%s, ProviderTenantID=%s", 
				s.SMTP.ProviderTenant.ID, s.SMTP.ProviderTenant.ProviderType, s.SMTP.ProviderTenant.ProviderTenantID)
		}
	}
	
	go func() {
		ms := []mailer.Mail{s}
		w.mailer.Queue(ms)
	}()
	return <-s.ErrorChan
}
