package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	DefaultLoginLimitWindow      = time.Minute
	DefaultGlobalLoginAttempts   = 60
	DefaultSourceLoginAttempts   = 10
	DefaultUsernameLoginAttempts = 5
	DefaultTrackedLoginSources   = 4096
	DefaultTrackedLoginNames     = 4096
	loginLimiterKeyBytes         = 32
)

type LoginLimiterOptions struct {
	Window           time.Duration
	GlobalLimit      int
	SourceLimit      int
	UsernameLimit    int
	MaximumSources   int
	MaximumUsernames int
	Now              func() time.Time
	Key              []byte
	Random           io.Reader
}

type LoginLimitDecision struct {
	Allowed    bool
	RetryAfter time.Duration
}

type loginWindow struct {
	startedAt time.Time
	count     int
}

// LoginLimiter bounds credential attempts before memory-hard password work.
// Source keys use the direct peer address (/32 for IPv4, /64 for IPv6), and
// normalized usernames are retained only as keyed digests.
type LoginLimiter struct {
	mu sync.Mutex

	window           time.Duration
	globalLimit      int
	sourceLimit      int
	usernameLimit    int
	maximumSources   int
	maximumUsernames int
	now              func() time.Time
	key              [loginLimiterKeyBytes]byte

	global    loginWindow
	sources   map[netip.Prefix]loginWindow
	usernames map[[sha256.Size]byte]loginWindow
}

func NewLoginLimiter(options LoginLimiterOptions) (*LoginLimiter, error) {
	if options.Window == 0 {
		options.Window = DefaultLoginLimitWindow
	}
	if options.GlobalLimit == 0 {
		options.GlobalLimit = DefaultGlobalLoginAttempts
	}
	if options.SourceLimit == 0 {
		options.SourceLimit = DefaultSourceLoginAttempts
	}
	if options.UsernameLimit == 0 {
		options.UsernameLimit = DefaultUsernameLoginAttempts
	}
	if options.MaximumSources == 0 {
		options.MaximumSources = DefaultTrackedLoginSources
	}
	if options.MaximumUsernames == 0 {
		options.MaximumUsernames = DefaultTrackedLoginNames
	}
	if options.Window < time.Second || options.Window > time.Hour ||
		options.GlobalLimit < 1 || options.SourceLimit < 1 || options.UsernameLimit < 1 ||
		options.SourceLimit > options.GlobalLimit || options.UsernameLimit > options.GlobalLimit ||
		options.MaximumSources < 1 || options.MaximumSources > 65536 ||
		options.MaximumUsernames < 1 || options.MaximumUsernames > 65536 {
		return nil, errors.New("invalid administrator login limiter configuration")
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	key := options.Key
	if len(key) == 0 {
		key = make([]byte, loginLimiterKeyBytes)
		random := options.Random
		if random == nil {
			random = rand.Reader
		}
		if _, err := io.ReadFull(random, key); err != nil {
			return nil, fmt.Errorf("generate administrator login limiter key: %w", err)
		}
	}
	if len(key) != loginLimiterKeyBytes {
		return nil, errors.New("administrator login limiter key must be 32 bytes")
	}
	limiter := &LoginLimiter{
		window: options.Window, globalLimit: options.GlobalLimit, sourceLimit: options.SourceLimit,
		usernameLimit: options.UsernameLimit, maximumSources: options.MaximumSources,
		maximumUsernames: options.MaximumUsernames, now: options.Now,
		sources: make(map[netip.Prefix]loginWindow), usernames: make(map[[sha256.Size]byte]loginWindow),
	}
	copy(limiter.key[:], key)
	return limiter, nil
}

func (l *LoginLimiter) Allow(source netip.Addr, username string) (LoginLimitDecision, error) {
	if l == nil || l.now == nil || !source.IsValid() {
		return LoginLimitDecision{}, errors.New("administrator login limiter is not initialized")
	}
	normalized := strings.ToLower(strings.TrimSpace(username))
	if normalized == "" || len(normalized) > MaxUsernameLength {
		// Keep malformed names on the same bounded, opaque limiter path.
		normalized = "invalid"
	}
	source = source.Unmap()
	bits := 64
	if source.Is4() {
		bits = 32
	}
	sourceKey := netip.PrefixFrom(source, bits).Masked()
	usernameKey := l.usernameKey(normalized)
	now := l.now().UTC()
	if now.IsZero() {
		return LoginLimitDecision{}, errors.New("administrator login limiter clock returned zero")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)
	l.global = currentLoginWindow(l.global, now, l.window)
	if _, ok := l.sources[sourceKey]; !ok && len(l.sources) >= l.maximumSources {
		return LoginLimitDecision{RetryAfter: remainingLoginWindow(l.global, now, l.window)}, nil
	}
	if _, ok := l.usernames[usernameKey]; !ok && len(l.usernames) >= l.maximumUsernames {
		return LoginLimitDecision{RetryAfter: remainingLoginWindow(l.global, now, l.window)}, nil
	}
	sourceWindow := currentLoginWindow(l.sources[sourceKey], now, l.window)
	usernameWindow := currentLoginWindow(l.usernames[usernameKey], now, l.window)
	sourceAllowed := sourceWindow.count < l.sourceLimit
	usernameAllowed := usernameWindow.count < l.usernameLimit
	sourceWindow.count++
	usernameWindow.count++
	l.sources[sourceKey] = sourceWindow
	l.usernames[usernameKey] = usernameWindow
	if !sourceAllowed || !usernameAllowed {
		var retryAfter time.Duration
		if !sourceAllowed {
			retryAfter = remainingLoginWindow(sourceWindow, now, l.window)
		}
		if !usernameAllowed {
			retryAfter = max(retryAfter, remainingLoginWindow(usernameWindow, now, l.window))
		}
		return LoginLimitDecision{RetryAfter: retryAfter}, nil
	}
	if l.global.count >= l.globalLimit {
		return LoginLimitDecision{RetryAfter: remainingLoginWindow(l.global, now, l.window)}, nil
	}
	l.global.count++
	return LoginLimitDecision{Allowed: true}, nil
}

func (l *LoginLimiter) usernameKey(username string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, l.key[:])
	_, _ = mac.Write([]byte("laneway-admin-login-name-v1\x00"))
	_, _ = mac.Write([]byte(username))
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (l *LoginLimiter) prune(now time.Time) {
	for key, window := range l.sources {
		if !now.Before(window.startedAt.Add(l.window)) {
			delete(l.sources, key)
		}
	}
	for key, window := range l.usernames {
		if !now.Before(window.startedAt.Add(l.window)) {
			delete(l.usernames, key)
		}
	}
}

func currentLoginWindow(window loginWindow, now time.Time, duration time.Duration) loginWindow {
	if window.startedAt.IsZero() || !now.Before(window.startedAt.Add(duration)) {
		return loginWindow{startedAt: now}
	}
	return window
}

func remainingLoginWindow(window loginWindow, now time.Time, duration time.Duration) time.Duration {
	remaining := window.startedAt.Add(duration).Sub(now)
	if remaining < time.Second {
		return time.Second
	}
	return remaining
}
