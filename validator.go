package validator

// V is a validator implementation
type V struct {
	spamlist    Spam
	from        string
	enforceSMTP bool
	log         Logger
}

// Spam config
type Spam struct {
	// Hosts is list of email spam hosts (domains)
	Hosts []string
	// Emails is list of spam email addresses
	Emails []string
	// Localparts is list of spam localparts of email addresses
	Localparts []string
}

type Logger interface {
	Info(string, ...interface{})
	Error(string, ...interface{})
}

// New Validator
func New(spam Spam, smtpFrom string, smtpEnforce bool, log Logger) *V {
	return &V{
		spamlist:    spam,
		from:        smtpFrom,
		enforceSMTP: smtpEnforce,
		log:         log,
	}
}
