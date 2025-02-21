package websocket

type Config struct {
	ClientID string `json:"clientId"`
	Secret   string `json:"secret"`
	Token    string `json:"token"`
	Endpoint string `json:"endpoint"`
}

type TokenResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}
