// Package bornhack provides authentication strategies with your bornhack.dk account.
package bornhack

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"golang.org/x/oauth2"
)

const (
	apiURL = "https://bornhack.dk"
)

type Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`
}

func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	b := bornhackConnector{
		redirectURI:  c.RedirectURI,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		logger:       logger,
	}

	return &b, nil
}

type bornhackConnector struct {
	clientID     string
	clientSecret string
	redirectURI  string
	logger       log.Logger
}

func (c *bornhackConnector) oauth2Config() *oauth2.Config {
	endpoint := oauth2.Endpoint{
		AuthStyle: oauth2.AuthStyleInParams,
		AuthURL:   apiURL + "/o/authorize/",
		TokenURL:  apiURL + "/o/token/",
	}

	cfg := &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.redirectURI,
	}

	return cfg
}

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("Could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}

func (c *bornhackConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	return c.oauth2Config().AuthCodeURL(state), nil
}

func (c *bornhackConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()

	oauth2Config := c.oauth2Config()

	ctx := r.Context()

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("bornhack: failed to get token: %v", err)
	}

	client := oauth2Config.Client(ctx, token)

	user, err := c.user(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("bornhack: get user: %v", err)
	}

	identity = connector.Identity{
		UserID:            strconv.Itoa(user.User.UserId),
		Username:          user.User.Username,
		PreferredUsername: user.User.Username,
		// Some Clients really want an email address, even though the API doesn't return
		// one - provide a fake one.
		Email:         fmt.Sprintf("%v@users.bornhack.dk", user.User.UserId),
		EmailVerified: false,
	}

	// The groups field is populated by joining camp and team name.

	identity.Groups = make([]string, len(user.Teams))
	for i, team := range user.Teams {
		identity.Groups[i] = fmt.Sprintf("%v:%v", team.Camp, team.Team)
	}

	return identity, nil
}

// user queries the Bornhack API for profile information using the provided client.
//
// The HTTP client is expected to be constructed by the golang.org/x/oauth2 package,
// which inserts a bearer token as part of the request.
func (b *bornhackConnector) user(ctx context.Context, client *http.Client) (user, error) {
	var u user

	if err := get(ctx, client, &u); err != nil {
		return u, err
	}

	return u, nil
}
