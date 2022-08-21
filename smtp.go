package gomail

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// A Dialer is a dialer to an SMTP server.
type Dialer struct {
	// Host represents the host of the SMTP server.
	Host string
	// LocalName is the hostname sent to the SMTP server with the HELO command.
	// By default, "localhost" is sent.
	LocalName string
	// Username is the username to use to authenticate to the SMTP server.
	Username string
	// Password is the password to use to authenticate to the SMTP server.
	Password string
	// Auth represents the authentication mechanism used to authenticate to the
	// SMTP server.
	Auth smtp.Auth
	// Port represents the port of the SMTP server.
	Port int
	// NetDialer is the net.Dialer instance to use. For legacy purposes, if
	// NetDialTimeout is not net.DialTimeout, then this field is not used.
	NetDialer net.Dialer
	// TLSConfig represents the TLS configuration used for the TLS (when the
	// STARTTLS extension is used) or SSL connection.
	TLSConfig *tls.Config
	// StartTLSPolicy represents the TLS security level required to
	// communicate with the SMTP server.
	//
	// This defaults to OpportunisticStartTLS for backwards compatibility,
	// but we recommend MandatoryStartTLS for all modern SMTP servers.
	//
	// This option has no effect if SSL is set to true.
	StartTLSPolicy StartTLSPolicy
	// Timeout to use for read/write operations. Defaults to 10 seconds, can
	// be set to 0 to disable timeouts.
	Timeout time.Duration
	// Whether we should retry mailing if the connection returned an error,
	// defaults to true.
	RetryFailure bool
	// SSL defines whether an SSL connection is used. It should be false in
	// most cases since the authentication mechanism should use the STARTTLS
	// extension instead.
	SSL bool
}

// NewDialer returns a new SMTP Dialer. The given parameters are used to connect
// to the SMTP server.
func NewDialer(host string, port int, username, password string) *Dialer {
	return &Dialer{
		Host:         host,
		Port:         port,
		Username:     username,
		Password:     password,
		SSL:          port == 465,
		Timeout:      10 * time.Second,
		RetryFailure: true,
	}
}

// NewPlainDialer returns a new SMTP Dialer. The given parameters are used to
// connect to the SMTP server.
//
// Deprecated: Use NewDialer instead.
func NewPlainDialer(host string, port int, username, password string) *Dialer {
	return NewDialer(host, port, username, password)
}

// NetDialTimeout specifies the DialTimeout function to establish a connection
// to the SMTP server. This can be used to override dialing in the case that a
// proxy or other special behavior is needed.
//
// Deprecated: use (*Dialer).NetDialer instead. If NetDialTimeout is nil, then
// (*Dialer).NetDialer is used.
var NetDialTimeout func(network, address string, timeout time.Duration) (net.Conn, error) = nil

// Dial dials and authenticates to an SMTP server. The returned SendCloser
// should be closed when done using it.
func (d *Dialer) Dial() (SendCloser, error) {
	return d.DialCtx(context.Background())
}

// DialCtx is Dial with context support.
func (d *Dialer) DialCtx(ctx context.Context) (SendCloser, error) {
	var conn net.Conn
	var err error

	if NetDialTimeout == nil {
		ctx, cancel := context.WithTimeout(ctx, d.Timeout)
		defer cancel()

		conn, err = d.NetDialer.DialContext(ctx, "tcp", addr(d.Host, d.Port))
	} else {
		conn, err = NetDialTimeout("tcp", addr(d.Host, d.Port), d.Timeout)
	}
	if err != nil {
		return nil, err
	}

	if d.SSL {
		conn = tlsClient(conn, d.tlsConfig())
	}

	c, err := smtpNewClient(conn, d.Host)
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			// Parent context expired. Immediately terminate and return.
			c.Close()
		case <-done:
			// ok
		}
	}()

	if d.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(d.Timeout))
	}

	if d.LocalName != "" {
		if err := c.Hello(d.LocalName); err != nil {
			return nil, err
		}
	}

	if !d.SSL && d.StartTLSPolicy != NoStartTLS {
		ok, _ := c.Extension("STARTTLS")
		if !ok && d.StartTLSPolicy == MandatoryStartTLS {
			err := StartTLSUnsupportedError{
				Policy: d.StartTLSPolicy}
			return nil, err
		}

		if ok {
			if err := c.StartTLS(d.tlsConfig()); err != nil {
				c.Close()
				return nil, err
			}
		}
	}

	if d.Auth == nil && d.Username != "" {
		if ok, auths := c.Extension("AUTH"); ok {
			switch {
			case strings.Contains(auths, "CRAM-MD5"):
				d.Auth = smtp.CRAMMD5Auth(d.Username, d.Password)
			case strings.Contains(auths, "LOGIN") && !strings.Contains(auths, "PLAIN"):
				d.Auth = &loginAuth{
					username: d.Username,
					password: d.Password,
					host:     d.Host,
				}
			default:
				d.Auth = smtp.PlainAuth("", d.Username, d.Password, d.Host)
			}
		}
	}

	if d.Auth != nil {
		if err = c.Auth(d.Auth); err != nil {
			c.Close()
			return nil, err
		}
	}

	return &smtpSender{c, conn, d}, nil
}

func (d *Dialer) tlsConfig() *tls.Config {
	if d.TLSConfig == nil {
		return &tls.Config{ServerName: d.Host, MinVersion: tls.VersionTLS12}
	}
	return d.TLSConfig
}

// StartTLSPolicy constants are valid values for Dialer.StartTLSPolicy.
type StartTLSPolicy int

const (
	// OpportunisticStartTLS means that SMTP transactions are encrypted if
	// STARTTLS is supported by the SMTP server. Otherwise, messages are
	// sent in the clear. This is the default setting.
	OpportunisticStartTLS StartTLSPolicy = iota
	// MandatoryStartTLS means that SMTP transactions must be encrypted.
	// SMTP transactions are aborted unless STARTTLS is supported by the
	// SMTP server.
	MandatoryStartTLS
	// NoStartTLS means encryption is disabled and messages are sent in the
	// clear.
	NoStartTLS = -1
)

func (policy *StartTLSPolicy) String() string {
	switch *policy {
	case OpportunisticStartTLS:
		return "OpportunisticStartTLS"
	case MandatoryStartTLS:
		return "MandatoryStartTLS"
	case NoStartTLS:
		return "NoStartTLS"
	default:
		return fmt.Sprintf("StartTLSPolicy:%v", *policy)
	}
}

// StartTLSUnsupportedError is returned by Dial when connecting to an SMTP
// server that does not support STARTTLS.
type StartTLSUnsupportedError struct {
	Policy StartTLSPolicy
}

func (e StartTLSUnsupportedError) Error() string {
	return "gomail: " + e.Policy.String() + " required, but " +
		"SMTP server does not support STARTTLS"
}

func addr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// DialAndSend opens a connection to the SMTP server, sends the given emails and
// closes the connection.
func (d *Dialer) DialAndSend(m ...*Message) error {
	return d.DialAndSendCtx(context.Background(), m...)
}

// DialAndSendCtx is DialAndSend with context support.
func (d *Dialer) DialAndSendCtx(ctx context.Context, m ...*Message) error {
	s, err := d.DialCtx(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	for i := range m {
		m[i] = m[i].WithContext(ctx)
	}

	return Send(s, m...)
}

type smtpSender struct {
	smtpClient
	conn net.Conn
	d    *Dialer
}

func (c *smtpSender) retryError(err error) bool {
	if !c.d.RetryFailure {
		return false
	}

	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return true
	}

	return err == io.EOF
}

type messageContexter interface {
	Context() context.Context
}

var _ messageContexter = (*Message)(nil)

func (c *smtpSender) Send(from string, to []string, msg io.WriterTo) error {
	if ctxer, ok := msg.(messageContexter); ok {
		if ctx := ctxer.Context(); ctx != context.Background() {
			done := make(chan struct{})
			defer close(done)

			go func() {
				select {
				case <-ctx.Done():
					c.conn.Close()
				case <-done:
					// ok
				}
			}()
		}
	}

	if c.d.Timeout > 0 {
		c.conn.SetDeadline(time.Now().Add(c.d.Timeout))
	}

	if err := c.Mail(from); err != nil {
		if c.retryError(err) {
			// This is probably due to a timeout, so reconnect and try again.
			sc, derr := c.d.Dial()
			if derr == nil {
				if s, ok := sc.(*smtpSender); ok {
					*c = *s
					return c.Send(from, to, msg)
				}
			}
		}

		return err
	}

	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}

	if _, err = msg.WriteTo(w); err != nil {
		w.Close()
		return err
	}

	return w.Close()
}

func (c *smtpSender) Close() error {
	return c.Quit()
}

// Stubbed out for tests.
var (
	tlsClient     = tls.Client
	smtpNewClient = func(conn net.Conn, host string) (smtpClient, error) {
		return smtp.NewClient(conn, host)
	}
)

type smtpClient interface {
	Hello(string) error
	Extension(string) (bool, string)
	StartTLS(*tls.Config) error
	Auth(smtp.Auth) error
	Mail(string) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}
