package validator

// V is a validator implementation
type V struct {
	spamlist Spam
	enforce  Enforce
	from     string
	log      Logger
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

// Enforce checks
type Enforce struct {
	SMTP bool
	MX   bool
}

type Logger interface {
	Info(string, ...interface{})
	Error(string, ...interface{})
}

// New Validator
func New(spam Spam, enforce Enforce, smtpFrom string, log Logger) *V {
	return &V{
		spamlist: spam,
		enforce:  enforce,
		from:     smtpFrom,
		log:      log,
	}
}
