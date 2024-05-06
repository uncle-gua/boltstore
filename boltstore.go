package boltstore

import (
	"encoding/base32"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/uncle-gua/bolthold"
)

const sessionIDLen = 32
const defaultMaxAge = 60 * 60 * 24 * 30 // 30 days
const defaultPath = "/"

type Store struct {
	store       *bolthold.Store
	Codecs      []securecookie.Codec
	SessionOpts *sessions.Options
}

type Session struct {
	ID        uint64 `boltholdKey:"ID"`
	Session   string `boltholdIndex:"Session"`
	Data      string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time `boltholdIndex:"ExpiresAt"`
}

func New(store *bolthold.Store, keyPairs ...[]byte) *Store {
	st := &Store{
		store:  store,
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		SessionOpts: &sessions.Options{
			Path:   defaultPath,
			MaxAge: defaultMaxAge,
		},
	}

	return st
}

func (st *Store) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(st, name)
}

func (st *Store) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(st, name)
	opts := *st.SessionOpts
	session.Options = &opts
	session.IsNew = true

	st.MaxAge(st.SessionOpts.MaxAge)

	s := st.getSessionFromCookie(r, session.Name())
	if s != nil {
		if err := securecookie.DecodeMulti(session.Name(), s.Data, &session.Values, st.Codecs...); err != nil {
			return session, nil
		}
		session.ID = s.Session
		session.IsNew = false
	}

	return session, nil
}

func (st *Store) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	s := st.getSessionFromCookie(r, session.Name())

	if session.Options.MaxAge < 0 {
		if s != nil {
			if err := st.store.Delete(s.ID, s); err != nil {
				return err
			}
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	data, err := securecookie.EncodeMulti(session.Name(), session.Values, st.Codecs...)
	if err != nil {
		return err
	}
	now := time.Now()
	expire := now.Add(time.Second * time.Duration(session.Options.MaxAge))

	if s == nil {
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(sessionIDLen)), "=")
		s = &Session{
			Session:   session.ID,
			Data:      data,
			CreatedAt: now,
			UpdatedAt: now,
			ExpiresAt: expire,
		}
		if err := st.store.Insert(bolthold.NextSequence(), s); err != nil {
			return err
		}
	} else {
		s.Data = data
		s.UpdatedAt = now
		s.ExpiresAt = expire
		if err := st.store.Update(s.ID, s); err != nil {
			return err
		}
	}

	id, err := securecookie.EncodeMulti(session.Name(), s.ID, st.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), id, session.Options))

	return nil
}

func (st *Store) getSessionFromCookie(r *http.Request, name string) *Session {
	if cookie, err := r.Cookie(name); err == nil {
		sessionID := ""
		if err := securecookie.DecodeMulti(name, cookie.Value, &sessionID, st.Codecs...); err != nil {
			return nil
		}
		s := &Session{}
		err := st.store.FindOne(s, bolthold.Where("Session").Eq(sessionID).And("ExpiresAt").Gt(time.Now()))
		if err != nil {
			return nil
		}
		return s
	}
	return nil
}

func (st *Store) MaxAge(age int) {
	st.SessionOpts.MaxAge = age
	for _, codec := range st.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (st *Store) MaxLength(l int) {
	for _, c := range st.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

func (st *Store) Cleanup() {
	st.store.DeleteMatching(&Session{}, bolthold.Where("ExpiresAt").Le(time.Now()))
}

func (st *Store) PeriodicCleanup(interval time.Duration, quit <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			st.Cleanup()
		case <-quit:
			return
		}
	}
}
