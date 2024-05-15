package boltstore

import (
	"encoding/base32"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/uncle-gua/bolthold"
)

var _ sessions.Store = (*Store)(nil)

var ErrInvalidId = errors.New("boltstore: invalid session id")

// Session object store in BoltDB
type Session struct {
	ID       string `boltholdKey:"ID"`
	Data     string
	Modified time.Time `boltholdIndex:"Modified"`
}

// BoltStore stores sessions in BoltDB
type Store struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	store   *bolthold.Store
}

var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewBoltStore returns a new BoltStore.
func New(s *bolthold.Store, maxAge int, keyPairs ...[]byte) *Store {
	store := &Store{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: maxAge,
		},
		store: s,
	}

	store.MaxAge(maxAge)

	return store
}

// Get registers and returns a session for the given name and session store.
// It returns a new session if there are no sessions registered for the name.
func (m *Store) Get(r *http.Request, name string) (
	*sessions.Session, error,
) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New returns a session for the given name without adding it to the registry.
func (m *Store) New(r *http.Request, name string) (
	*sessions.Session, error,
) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     m.Options.Path,
		MaxAge:   m.Options.MaxAge,
		Domain:   m.Options.Domain,
		Secure:   m.Options.Secure,
		HttpOnly: m.Options.HttpOnly,
		SameSite: m.Options.SameSite,
	}

	session.IsNew = true
	cookie, err := r.Cookie(name)
	if err != nil {
		return session, err
	}

	if err = securecookie.DecodeMulti(name, cookie.Value, &session.ID, m.Codecs...); err != nil {
		return session, err
	}

	if err = m.load(session); err != nil {
		if err != bolthold.ErrNotFound {
			return session, err
		}
	} else {
		session.IsNew = false
	}

	return session, nil
}

// Save saves all sessions registered for the current request.
func (m *Store) Save(_ *http.Request, w http.ResponseWriter,
	session *sessions.Session,
) error {
	if session.Options.MaxAge < 0 {
		if err := m.delete(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		session.ID = base32RawStdEncoding.EncodeToString(
			securecookie.GenerateRandomKey(32))
	}

	if err := m.upsert(session); err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		m.Codecs...)
	if err != nil {
		return err
	}

	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (m *Store) MaxAge(age int) {
	m.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (m *Store) load(session *sessions.Session) error {
	s := Session{}
	if err := m.store.Get(session.ID, &s); err != nil {
		return err
	}

	if err := securecookie.DecodeMulti(session.Name(), s.Data, &session.Values,
		m.Codecs...); err != nil {
		return err
	}

	return nil
}

func (m *Store) upsert(session *sessions.Session) error {
	var modified time.Time
	if val, ok := session.Values["modified"]; ok {
		modified, ok = val.(time.Time)
		if !ok {
			return errors.New("boltstore: invalid modified value")
		}
	} else {
		modified = time.Now()
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		m.Codecs...)
	if err != nil {
		return err
	}

	s := Session{
		ID:       session.ID,
		Data:     encoded,
		Modified: modified,
	}

	return m.store.Upsert(session.ID, &s)
}

func (m *Store) delete(session *sessions.Session) error {
	return m.store.Delete(session.ID, &Session{})
}
