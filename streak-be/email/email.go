// This package provides functionality for sending emails.
package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"text/template"

	"github.com/oklog/ulid/v2"
	"github.com/rohitxdev/go-api-starter/assets"
	"gopkg.in/gomail.v2"
)

type SMTPCredentials struct {
	Username           string
	Password           string
	Host               string
	Port               int
	InsecureSkipVerify bool
}

// Client is an email client that handles sending emails through SMTP.
type Client struct {
	dialer    *gomail.Dialer
	templates *template.Template
}

// New creates a new email client with the provided credentials and templates.
func New(c *SMTPCredentials) (*Client, error) {
	t, err := template.ParseFS(assets.FS, "templates/emails/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("failed to parse email templates: %w", err)
	}

	dialer := gomail.NewDialer(c.Host, c.Port, c.Username, c.Password)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify}

	client := Client{
		dialer:    dialer,
		templates: t,
	}
	return &client, nil
}

type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

type BaseOpts struct {
	Subject         string
	FromAddress     string
	FromName        string
	UnsubscribeLink string
	ToAddresses     []string
	Cc              []string
	Bcc             []string
	// Prevent email stacking in the same thread on the email client.
	NoStack bool
}

// 'send' sends an email with raw content of the specified MIME type.
func (c *Client) send(opts *BaseOpts, mimeType string, body string, attachments ...Attachment) error {
	msg := gomail.NewMessage()

	msg.SetHeaders(map[string][]string{
		"From":    {msg.FormatAddress(opts.FromAddress, opts.FromName)},
		"Subject": {opts.Subject},
		"To":      opts.ToAddresses,
	})

	if opts.NoStack {
		msg.SetHeader("X-Entity-Ref-ID", ulid.Make().String())
	}
	if opts.UnsubscribeLink != "" {
		msg.SetHeader("List-Unsubscribe", opts.UnsubscribeLink)
	}
	if len(opts.Cc) > 0 {
		msg.SetHeader("Cc", opts.Cc...)
	}
	if len(opts.Bcc) > 0 {
		msg.SetHeader("Bcc", opts.Bcc...)
	}

	msg.SetBody(mimeType, body)

	for _, attachment := range attachments {
		if attachment.ContentType == "" {
			attachment.ContentType = http.DetectContentType(attachment.Data)
		}
		msg.Attach(
			attachment.Filename,
			gomail.SetCopyFunc(func(w io.Writer) error {
				_, err := w.Write(attachment.Data)
				return err
			}),
			gomail.SetHeader(map[string][]string{
				"Content-Type": {attachment.ContentType},
			}),
		)
	}

	if err := c.dialer.DialAndSend(msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}

// SendHtml sends an HTML email using a template.
func (c *Client) SendHTML(opts *BaseOpts, templateName string, data map[string]any, attachments ...Attachment) error {
	var buf bytes.Buffer
	if err := c.templates.ExecuteTemplate(&buf, templateName+".tmpl", data); err != nil {
		// '%q' prints the template name in quotes
		return fmt.Errorf("failed to execute template %q: %w", templateName, err)
	}
	return c.send(opts, "text/html", buf.String(), attachments...)
}

// SendText sends a plain text email.
func (c *Client) SendText(opts *BaseOpts, body string, attachments ...Attachment) error {
	return c.send(opts, "text/plain", body, attachments...)
}
