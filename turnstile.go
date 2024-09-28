package turnstile

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

// a formSubmission is the data submitted by the form
type formSubmission struct {
	TurnstileResponse string `json:"cf-turnstile-response"`
}

// a turnstilePostBody is the data sent to tunstile as a POST
type turnstilePostBody struct {
	IP       string `json:"remoteip"`
	Response string `json:"response"`
	Secret   string `json:"secret"`
}

// a turnstileVerifyResponseBody is the data returned from tunstile
type turnstileVerifyResponseBody struct {
	Success bool `json:"success"`
}

func IsSubmitterHuman(req *http.Request, turnstileUrl, turnstileSecretKey string) (bool, error) {
	if err := req.ParseForm(); err != nil {
		log.Printf("error parsing form body: %v", err)
		return false, err
	}

	formBody := formSubmission{
		TurnstileResponse: req.PostForm.Get("cf-turnstile-response"),
	}

	// get ip from headers
	ip := req.Header.Get("CF-Connecting-IP")

	// build request body
	postBody := turnstilePostBody{
		IP:       ip,
		Response: formBody.TurnstileResponse,
		Secret:   turnstileSecretKey,
	}
	postBytes, err := json.Marshal(postBody)
	if err != nil {
		log.Printf("error marshaling json: %s", err.Error())
		return false, err
	}

	// build request
	turnstileRequest, err := http.NewRequest("POST", turnstileUrl, bytes.NewReader(postBytes))
	if err != nil {
		log.Printf("error building turnstile  request: %v", err.Error())
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")

	// send request
	client := &http.Client{}
	resp, err := client.Do(turnstileRequest)
	if err != nil {
		log.Printf("error contacting turnstile: %v", err.Error())
		return false, err
	}
	defer resp.Body.Close()

	// parse response
	var response turnstileVerifyResponseBody
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil || !response.Success {
		log.Printf("error decoding turnstile response: %v", err.Error())
		return false, err
	}

	return true, nil
}
