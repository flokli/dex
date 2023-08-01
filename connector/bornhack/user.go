package bornhack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// user matches the structure that's available when querying the
// `/profile/api/` endpoint.
// Check https://github.com/bornhack/bornhack-website/blob/0c116321b8dddeb191cee13d88e1fea88a7d3a66/src/profiles/views.py#L42,
// ProfileAPIView.
type user struct {
	User    userUser    `json:"user"`
	Profile userProfile `json:"profile"`
	Teams   []userTeam  `json:"teams"`
}

type userUser struct {
	Username string `json:"username"`
	UserId   int    `json:"user_id"`
}

type userProfile struct {
	PublicCreditName string `json:"public_credit_name"`
	Description      string `json:"description"`
}

type userTeam struct {
	Team string `json:"team"`
	Camp string `json:"camp"`
}

// get queries the `/profile/api/` endpoint and decodes the resulting body into
// a userProfile struct at v.
func get(ctx context.Context, client *http.Client, v interface{}) error {
	req, err := http.NewRequest("GET", apiURL+"/profile/api", nil)
	if err != nil {
		return fmt.Errorf("bornhack: new req: %v", err)
	}

	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("bornhack: get URL %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("bornhack: read body: %v", err)
		}
		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	return nil
}
