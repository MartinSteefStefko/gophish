package models

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/jinzhu/gorm"

	check "gopkg.in/check.v1"
)

func init() {
	// Set a test master key for encryption
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}
	os.Setenv("MASTER_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(testKey))
	InitializeEncryption()
}

func (s *ModelsSuite) TestPostSMTP(c *check.C) {
	smtp := SMTP{
		Name:        "Test SMTP",
		Host:        "1.1.1.1:25",
		FromAddress: "foo@example.com",
		UserId:      1,
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.Equals, nil)
	ss, err := GetSMTPs(1)
	c.Assert(err, check.Equals, nil)
	c.Assert(len(ss), check.Equals, 1)
}

func (s *ModelsSuite) TestPostSMTPNoHost(c *check.C) {
	smtp := SMTP{
		Name:        "Test SMTP",
		FromAddress: "foo@example.com",
		UserId:      1,
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.Equals, ErrHostNotSpecified)
}

func (s *ModelsSuite) TestPostSMTPNoFrom(c *check.C) {
	smtp := SMTP{
		Name:   "Test SMTP",
		UserId: 1,
		Host:   "1.1.1.1:25",
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.Equals, ErrFromAddressNotSpecified)
}

func (s *ModelsSuite) TestPostInvalidFrom(c *check.C) {
	smtp := SMTP{
		Name:        "Test SMTP",
		Host:        "1.1.1.1:25",
		FromAddress: "Foo Bar <foo@example.com>",
		UserId:      1,
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.Equals, ErrInvalidFromAddress)
}

func (s *ModelsSuite) TestPostInvalidFromEmail(c *check.C) {
	smtp := SMTP{
		Name:        "Test SMTP",
		Host:        "1.1.1.1:25",
		FromAddress: "example.com",
		UserId:      1,
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.Equals, ErrInvalidFromAddress)
}

func (s *ModelsSuite) TestPostSMTPValidHeader(c *check.C) {
	smtp := SMTP{
		Name:        "Test SMTP",
		Host:        "1.1.1.1:25",
		FromAddress: "foo@example.com",
		UserId:      1,
		Headers: []Header{
			Header{Key: "Reply-To", Value: "test@example.com"},
			Header{Key: "X-Mailer", Value: "gophish"},
		},
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.Equals, nil)
	ss, err := GetSMTPs(1)
	c.Assert(err, check.Equals, nil)
	c.Assert(len(ss), check.Equals, 1)
}

func (s *ModelsSuite) TestSMTPGetDialer(ch *check.C) {
	host := "localhost"
	port := 25
	smtp := SMTP{
		Host:             fmt.Sprintf("%s:%d", host, port),
		IgnoreCertErrors: false,
	}
	d, err := smtp.GetDialer()
	ch.Assert(err, check.Equals, nil)

	dialer := d.(*Dialer).Dialer
	ch.Assert(dialer.Host, check.Equals, host)
	ch.Assert(dialer.Port, check.Equals, port)
	ch.Assert(dialer.TLSConfig.ServerName, check.Equals, host)
	ch.Assert(dialer.TLSConfig.InsecureSkipVerify, check.Equals, smtp.IgnoreCertErrors)
}

func (s *ModelsSuite) TestGetInvalidSMTP(ch *check.C) {
	_, err := GetSMTP(-1, 1)
	ch.Assert(err, check.Equals, gorm.ErrRecordNotFound)
}

func (s *ModelsSuite) TestDefaultDeniedDial(ch *check.C) {
	host := "169.254.169.254"
	port := 25
	smtp := SMTP{
		Host: fmt.Sprintf("%s:%d", host, port),
	}
	d, err := smtp.GetDialer()
	ch.Assert(err, check.Equals, nil)
	_, err = d.Dial()
	ch.Assert(err, check.ErrorMatches, ".*upstream connection denied.*")
}

func (s *ModelsSuite) TestPostGraphAPISMTP(c *check.C) {
	// Create a test app registration first
	appReg := &AppRegistration{
		ID:               uuid.New().String(),
		ProviderTenantID: "test-tenant-id",
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost:3333",
	}
	appReg.SetScopes([]string{
		"https://graph.microsoft.com/Mail.Send",
		"https://graph.microsoft.com/Mail.Send.Shared",
	})

	// Set client secret directly without encryption
	appReg.ClientSecretEncrypted = "test-secret"

	err := appReg.Create()
	c.Assert(err, check.IsNil)

	// Now create the SMTP profile
	smtp := SMTP{
		Name:             "Graph",
		Interface:        "GRAPH",
		FromAddress:      "admin@example.com",
		UserId:          1,
		AppRegistrationID: appReg.ID,
	}
	err = PostSMTP(&smtp)
	c.Assert(err, check.IsNil)

	// Verify SMTP was created
	ss, err := GetSMTPs(1)
	c.Assert(err, check.IsNil)
	c.Assert(len(ss), check.Equals, 1)
	c.Assert(ss[0].Interface, check.Equals, "GRAPH")
	c.Assert(ss[0].AppRegistrationID, check.Equals, appReg.ID)
}

func (s *ModelsSuite) TestPostGraphAPISMTPNoAppReg(c *check.C) {
	// Create SMTP profile without app registration
	smtp := SMTP{
		Name:        "Graph",
		Interface:   "GRAPH",
		FromAddress: "admin@example.com",
		UserId:      1,
		TenantID:    "test-tenant-id",
		ClientID:    "test-client-id",
		ClientSecret: "test-secret",
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.IsNil)
	c.Assert(smtp.AppRegistrationID, check.Not(check.Equals), "")

	// Verify app registration was created
	appReg, err := GetAppRegistration(smtp.AppRegistrationID)
	c.Assert(err, check.IsNil)
	c.Assert(appReg.ProviderTenantID, check.Equals, smtp.TenantID)
	c.Assert(appReg.ClientID, check.Equals, smtp.ClientID)
}

func (s *ModelsSuite) TestPostGraphAPISMTPNoTenantID(c *check.C) {
	// Create SMTP profile without tenant ID
	smtp := SMTP{
		Name:        "Graph",
		Interface:   "GRAPH",
		FromAddress: "admin@example.com",
		UserId:      1,
		ClientID:    "test-client-id",
		ClientSecret: "test-secret",
	}
	err := PostSMTP(&smtp)
	c.Assert(err, check.NotNil)
	c.Assert(err.Error(), check.Matches, ".*failed to create app registration.*")
}

func (s *ModelsSuite) TestGraphAPISMTPGetDialer(ch *check.C) {
	// Create a test app registration first
	appReg := &AppRegistration{
		ID:               uuid.New().String(),
		ProviderTenantID: "test-tenant-id",
		ClientID:         "test-client-id",
		RedirectURI:      "http://localhost:3333",
	}
	appReg.SetScopes([]string{
		"https://graph.microsoft.com/Mail.Send",
		"https://graph.microsoft.com/Mail.Send.Shared",
	})

	// Set client secret directly without encryption
	appReg.ClientSecretEncrypted = "test-secret"

	err := appReg.Create()
	ch.Assert(err, check.IsNil)

	// Create and test the SMTP profile
	smtp := SMTP{
		Name:             "Graph",
		Interface:        "GRAPH",
		FromAddress:      "admin@example.com",
		UserId:          1,
		AppRegistrationID: appReg.ID,
	}

	// Get the dialer
	d, err := smtp.GetDialer()
	ch.Assert(err, check.IsNil)

	// Verify it's a GraphAPIDialer
	_, ok := d.(*GraphAPIDialer)
	ch.Assert(ok, check.Equals, true)
}

func (s *ModelsSuite) TestGraphAPISMTPGetDialerInvalidAppReg(ch *check.C) {
	// Create SMTP profile with invalid app registration ID
	smtp := SMTP{
		Name:             "Graph",
		Interface:        "GRAPH",
		FromAddress:      "admin@example.com",
		UserId:          1,
		AppRegistrationID: "invalid-id",
	}

	// Try to get the dialer
	_, err := smtp.GetDialer()
	ch.Assert(err, check.NotNil)
	ch.Assert(err.Error(), check.Matches, ".*failed to get app registration.*")
}
