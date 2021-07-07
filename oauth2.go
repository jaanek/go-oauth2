// based on https://levelup.gitconnected.com/oauth-2-0-in-go-846b257d32b4
package oauth2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	AUTHORIZE = "authorization_code"
	REFRESH   = "refresh_token"
	SECRET    = "secret"
	PKCE      = "pkce"
)

func InitOauth2() {
	PkceInit()
}

type Service map[string]string

func PkceInit() {
	rand.Seed(time.Now().UnixNano())
}

// returns a verifier, a pseudo random string code
func PkceVerifier(length int) string {
	if length > 128 {
		length = 128
	} else if length < 43 {
		length = 43
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// returns a challenge, a hashed verifier
func PkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
	return challenge
}

// auth session state
const (
	GcPeriod        = 60  // minutes - minimum ideal time between GC runs (unless MaxState)
	InitAuthTimeout = 10  // minutes - amount of time user has to complete Authorization and get Access Code from Authorization Server
	MaxState        = 400 // max allowed length of state map, to prevent malicious memory overflow
)

type AuthState struct {
	Key           string
	CreatedAt     time.Time
	Service       string
	AuthType      string
	PkceVerifier  string
	PkceChallenge string
}

var state = make(map[string]*AuthState)
var lastGc = time.Now().UTC()
var mutex = &sync.Mutex{}

func GetState(key string) (value *AuthState) {
	mutex.Lock()
	v, exists := state[key]
	if exists {
		n := time.Now().UTC()
		if n.After(v.CreatedAt.Add(InitAuthTimeout * time.Minute)) {
			value = nil // do not accept expired state
		} else {
			value = v
		}
		delete(state, key)
	} else {
		value = nil
	}
	defer mutex.Unlock()
	return
}

func SetState(key string, value *AuthState) {
	mutex.Lock()
	n := time.Now().UTC()
	value.CreatedAt = n
	state[key] = value
	// gc
	authTimeout := InitAuthTimeout * time.Minute
	gcTime := lastGc.Add(GcPeriod * time.Minute)
	if n.After(gcTime) || len(state) > MaxState {
		for ok := true; ok; ok = len(state) >= MaxState {
			for k, v := range state {
				expiresAt := v.CreatedAt.Add(authTimeout)
				if n.After(expiresAt) {
					delete(state, k)
				}
			}
			authTimeout /= 2
		}
		lastGc = time.Now().UTC()
	}
	defer mutex.Unlock()
	return
}

// build authorization link with new auth state set internally
func AuthLink(serviceKey string, service Service, authType string) (result string, state *AuthState) {
	stateKey := PkceVerifier(128)
	state = &AuthState{Key: stateKey, Service: serviceKey, AuthType: authType}
	result = service["authorize_endpoint"]
	result += "?client_id=" + service["client_id"]
	result += "&response_type=code"
	result += "&redirect_uri=" + service["redirect_uri"]
	result += "&scope=" + service["scope"]
	result += "&prompt=" + service["prompt"]
	if authType == PKCE {
		state.PkceVerifier = PkceVerifier(128)
		state.PkceChallenge = PkceChallenge(state.PkceVerifier)
		result += "&code_challenge=" + state.PkceChallenge
		result += "&code_challenge_method=S256"
	}
	result += "&state=" + stateKey
	return
}

// exchange the Authorization Code / Auth Token for Access Token
func ExchangeToken(state *AuthState, service Service, authToken string, httpOrigin string) (token string, err error) {
	// state := GetState(stateCode)
	if state == nil {
		err = errors.New("State not available")
		return
	}
	token, err = GetToken(service, AUTHORIZE, authToken, state.AuthType, state.PkceVerifier, httpOrigin)
	return
}

// subtract a small delta from exires_at to account for transport time
const DELTASECS = 5

// get a token from authorization endpoint
func GetToken(service Service, tokenType string, authToken string, authType string, verifier string, httpOrigin string) (token string, err error) {
	rParams := map[string]string{
		"client_id":    service["client_id"],
		"redirect_uri": service["redirect_uri"],
	}
	switch tokenType {
	case AUTHORIZE:
		rParams["code"] = authToken
		rParams["grant_type"] = AUTHORIZE
	case REFRESH:
		rParams["refresh_token"] = authToken
		rParams["grant_type"] = REFRESH
	default:
		err = errors.New("Unknown tokType")
		return
	}
	switch authType {
	case SECRET:
		rParams["client_secret"] = service["client_secret"]
	case PKCE:
		rParams["code_verifier"] = verifier
	default:
		err = errors.New("Unknown authType")
		return
	}
	endpoint := service["token_endpoint"]
	postType := service["post_type"]
	var resp *http.Response
	switch postType {
	case "json":
		var requestBody []byte
		requestBody, err = json.Marshal(rParams)
		if err != nil {
			return
		}
		resp, err = post(endpoint, "application/json", bytes.NewBuffer(requestBody), httpOrigin)
		if err != nil {
			return
		}
	case "form":
		vals := url.Values{}
		for k, v := range rParams {
			vals.Set(k, v)
		}
		resp, err = post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(vals.Encode()), httpOrigin)
		if err != nil {
			return
		}
	default:
		err = errors.New("Unknown post_type")
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(string(body))
		return
	}

	//check for expires_at
	var tokMap map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	err = decoder.Decode(&tokMap)
	if err != nil {
		err = errors.New("token endpoint result error! decoder.Decode: " + err.Error())
		return
	}
	expire, exists := tokMap["expires_at"]
	if exists {
		token = string(body)
		return
	}
	var expiresIn int64
	expire, exists = tokMap["expires_in"]
	if !exists { //no expiration, so make it a year
		expiresIn = 31536000
	} else {
		expiresIn, err = expire.(json.Number).Int64()
		if err != nil {
			err = errors.New("expire to number! json.Marshal: " + err.Error())
			return
		}
	}
	tokMap["expires_at"] = epochSeconds() + expiresIn - DELTASECS
	b, err := json.Marshal(tokMap)
	if err != nil {
		err = errors.New("json.Marshal: " + err.Error())
		return
	}
	token = string(b)
	return
}

func post(url string, contentType string, body io.Reader, httpOrigin string) (resp *http.Response, err error) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", httpOrigin)
	return client.Do(req)
}

func epochSeconds() int64 {
	now := time.Now()
	secs := now.Unix()
	return secs
}
