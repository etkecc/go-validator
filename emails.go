package validator

import (
	"net/mail"
	"strings"

	"gitlab.com/etke.cc/go/trysmtp"
)

// Email checks if email is valid
func (v *V) Email(email string) bool {
	// edge case: email may be optional
	if email == "" {
		return true
	}

	length := len(email)
	// email cannot too short and too big
	if length < 3 || length > 254 {
		v.log.Info("email %s invalid, reason: length", email)
		return false
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		v.log.Info("email %s invalid, reason: %v", email, err)
		return false
	}

	if v.spam(email) {
		v.log.Info("email %s invalid, reason: spamlist", email)
		return false
	}

	localpart := email[:strings.LastIndex(email, "@")]
	if v.spam(localpart) {
		v.log.Info("email %s invalid, reason: spamlist", email)
		return false
	}

	if v.emailDomain(email) {
		return false
	}

	smtpCheck := !v.emailSMTP(email)
	if v.enforce.SMTP {
		return smtpCheck
	}

	return true
}

// emailDomain checks if email domain or host is invalid
func (v *V) emailDomain(email string) bool {
	at := strings.LastIndex(email, "@")
	domain := email[at+1:]
	host := v.GetBase(domain)

	if v.spam(domain) {
		v.log.Info("email %s domain %s invalid, reason: spamlist", email, domain)
		return true
	}
	if v.spam(host) {
		v.log.Info("email %s host %s invalid, reason: spamlist", email, host)
		return true
	}

	nomx := !v.MX(domain) && !v.MX(host)
	if nomx {
		v.log.Info("email %s domain/host %s invalid, reason: no MX", email, domain)
		if v.enforce.MX {
			return true
		}
	}

	return false
}

func (v *V) emailSMTP(email string) bool {
	client, err := trysmtp.Connect(v.from, email)
	if err != nil {
		if strings.HasPrefix(err.Error(), "451") {
			v.log.Info("email %s may be invalid, reason: SMTP check (%v)", email, err)
			return false
		}

		v.log.Info("email %s invalid, reason: SMTP check (%v)", email, err)
		return true
	}
	defer client.Close()

	return false
}

// spam checks spam lists for the item
func (v *V) spam(item string) bool {
	for _, address := range v.spamlist.Emails {
		if address == item {
			return true
		}
	}

	for _, localpart := range v.spamlist.Localparts {
		if localpart == item {
			return true
		}
	}

	for _, host := range v.spamlist.Hosts {
		if host == item {
			return true
		}
	}

	return false
}
