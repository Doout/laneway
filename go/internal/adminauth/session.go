package adminauth

import (
	"errors"
	"fmt"
	"time"
)

const (
	DefaultSessionIdleLifetime     = 30 * time.Minute
	DefaultSessionAbsoluteLifetime = 8 * time.Hour
	DefaultMaximumSessions         = 5
	SessionCookieName              = "__Host-laneway_admin_session"
	CSRFCookieName                 = "__Host-laneway_admin_csrf"
	CSRFHeaderName                 = "X-Laneway-CSRF"
	PublicClientAddressHeader      = "X-Laneway-Public-Client-IP"
)

type SessionPolicy struct {
	IdleLifetime     time.Duration
	AbsoluteLifetime time.Duration
	MaximumSessions  int
}

func DefaultSessionPolicy() SessionPolicy {
	return SessionPolicy{
		IdleLifetime: DefaultSessionIdleLifetime, AbsoluteLifetime: DefaultSessionAbsoluteLifetime,
		MaximumSessions: DefaultMaximumSessions,
	}
}

func (p SessionPolicy) Validate() error {
	if p.IdleLifetime < time.Minute || p.IdleLifetime > 24*time.Hour {
		return errors.New("administrator session idle lifetime must be from 1 minute through 24 hours")
	}
	if p.AbsoluteLifetime < p.IdleLifetime || p.AbsoluteLifetime > 7*24*time.Hour {
		return errors.New("administrator session absolute lifetime must be at least idle lifetime and at most 7 days")
	}
	if p.MaximumSessions < 1 || p.MaximumSessions > 20 {
		return errors.New("administrator concurrent session limit must be from 1 through 20")
	}
	return nil
}

type Session struct {
	ID                string
	Principal         Principal
	CSRFToken         string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

func (s Session) Validate(at time.Time) error {
	if s.ID == "" || s.CSRFToken == "" || !s.Principal.Enabled || !s.Principal.Valid() {
		return errors.New("invalid administrator session")
	}
	at = at.UTC()
	if s.CreatedAt.IsZero() || s.LastSeenAt.Before(s.CreatedAt) || !s.IdleExpiresAt.After(s.LastSeenAt) ||
		!s.AbsoluteExpiresAt.After(s.CreatedAt) || s.IdleExpiresAt.After(s.AbsoluteExpiresAt) {
		return errors.New("invalid administrator session lifetime")
	}
	if at.IsZero() || at.Before(s.CreatedAt) || at.Before(s.LastSeenAt) {
		return errors.New("administrator session validation time precedes session state")
	}
	if !at.Before(s.IdleExpiresAt) || !at.Before(s.AbsoluteExpiresAt) {
		return fmt.Errorf("administrator session expired")
	}
	return nil
}

func SessionDeadlines(createdAt, lastSeenAt time.Time, policy SessionPolicy) (time.Time, time.Time, error) {
	if err := policy.Validate(); err != nil {
		return time.Time{}, time.Time{}, err
	}
	createdAt, lastSeenAt = createdAt.UTC(), lastSeenAt.UTC()
	if createdAt.IsZero() || lastSeenAt.Before(createdAt) {
		return time.Time{}, time.Time{}, errors.New("invalid administrator session timestamps")
	}
	absolute := createdAt.Add(policy.AbsoluteLifetime)
	idle := lastSeenAt.Add(policy.IdleLifetime)
	if idle.After(absolute) {
		idle = absolute
	}
	return idle, absolute, nil
}
