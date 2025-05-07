package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)

var (
	userStates     = make(map[string]string)
	userData       = make(map[string]*RequestData1)
	stateMutex     sync.Mutex
	config         *viper.Viper
	errInvalidBody = errors.New("invalid body supplied")
	letterBytes    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	complaintRegex = regexp.MustCompile(`(?i)^helpdesk([ \t]|$)`)
)

type MessageActor struct {
	Type string `json:"type"`
	Id   string `json:"id"`
	Name string `json:"name"`
}

type MessageObject struct {
	Type      string `json:"type"`
	Id        string `json:"id"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	MediaType string `json:"mediaType"`
}

type MessageTarget struct {
	Type string `json:"type"`
	Id   string `json:"id"`
	Name string `json:"name"`
}

type Message struct {
	Type   string        `json:"type"`
	Actor  MessageActor  `json:"actor"`
	Object MessageObject `json:"object"`
	Target MessageTarget `json:"target"`
}

type Response struct {
	Message string `json:"message"`
	ReplyTo string `json:"replyTo"`
}

type RichObjectParameter struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type RichObjectMessage struct {
	Message string `json:"message"`
}

type RichObjectMessageWithParameters struct {
	RichObjectMessage
	Parameters map[string]RichObjectParameter `json:"parameters,omitempty"`
}

func createMessage(input string) (Message, error) {
	var message Message
	reader := strings.NewReader(input)
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&message)
	if err != nil {
		return message, errInvalidBody
	}

	return message, nil
}

func createRichMessageWithoutParameters(input string) (RichObjectMessage, error) {
	var message RichObjectMessage
	reader := strings.NewReader(input)
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&message)
	if err != nil {
		return message, errInvalidBody
	}

	return message, nil
}

func generateRandomBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func sendReply(server string, message Message, responseText string) {
	random := generateRandomBytes(64)
	signature := generateHmacForString(responseText, random, config.GetString("bot.secret"))

	// Send actual message
	response := Response{
		Message: responseText,
		ReplyTo: message.Object.Id,
	}
	responseBody, _ := json.Marshal(response)
	bodyReader := bytes.NewReader(responseBody)

	requestURL := fmt.Sprintf("%socs/v2.php/apps/spreed/api/v1/bot/%s/message", server, message.Target.Id)
	request, err := http.NewRequest("POST", requestURL, bodyReader)
	if err != nil {
		log.Printf("[Response]      Error creating request %v", err)
		os.Exit(1)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("OCS-APIRequest", "true")
	request.Header.Set("X-Nextcloud-Talk-Bot-Random", random)
	request.Header.Set("X-Nextcloud-Talk-Bot-Signature", signature)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	_, err = client.Do(request)
	if err != nil {
		log.Printf("[Response]      Error posting request %v", err)
		return
	}
}

func HelpdeskHandling(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Only post allowed
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[Request]       Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	server := r.Header.Get("X-NEXTCLOUD-TALK-BACKEND")
	random := r.Header.Get("X-NEXTCLOUD-TALK-RANDOM")
	signature := r.Header.Get("X-NEXTCLOUD-TALK-SIGNATURE")
	digest := generateHmacForString(string(body), random, config.GetString("bot.secret"))

	if digest != signature {
		log.Printf("[Request]       Error validating signature: %s / %s", digest, signature)
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	message, err := createMessage(string(body))

	if err != nil {
		log.Printf("Request]       Error invalid body: %s", err)
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	if message.Object.Name == "message" {
		richMessage, err := createRichMessageWithoutParameters(message.Object.Content)
		if err == nil {
			text := richMessage.Message
			userID := message.Actor.Id

			stateMutex.Lock()
			currentState := userStates[userID]
			stateMutex.Unlock()

			switch currentState {
			case "awaiting_cpf":
				if validateCPF(text) != nil {
					sendReply(server, message, "❌ CPF inválido! Digite novamente (11 dígitos):")
					return
				}
				userData[userID] = &RequestData1{CPFAB: text}
				userStates[userID] = "awaiting_chapa"
				sendReply(server, message, "🔢 Digite sua matrícula:")

			case "awaiting_chapa":
				if len(text) < 3 {
					sendReply(server, message, "❌ Matrícula inválida! Mínimo 3 caracteres:")
					return
				}
				userData[userID].Chapa = text
				userStates[userID] = "awaiting_oper"
				sendReply(server, message, "⚙️ Escolha o tipo de operação:\n1 - ADM\n2 - Operação")

			case "awaiting_oper":
				num, err := strconv.Atoi(text)
				if err != nil || (num < 1 || num > 2) {
					sendReply(server, message, "❌ Opção inválida! Digite 1 ou 2:")
					return
				}
				userData[userID].IDOper = num
				userStates[userID] = "awaiting_idgrupo"
				sendReply(server, message, "🏷️ Digite o número do grupo (1-12):")

			case "awaiting_idgrupo":
				num, err := strconv.Atoi(text)
				if err != nil || num < 1 || num > 12 {
					sendReply(server, message, "❌ Grupo inválido! Digite 1-12:")
					return
				}
				userData[userID].IDGrupo = num
				userStates[userID] = "awaiting_idsubgrupo"
				sendReply(server, message, "🏷️ Digite o número do subgrupo (1-170):")

			case "awaiting_idsubgrupo":
				num, err := strconv.Atoi(text)
				if err != nil || num < 1 || num > 170 {
					sendReply(server, message, "❌ Subgrupo inválido! Digite 1-170:")
					return
				}
				userData[userID].IDSubgrupo = num
				userStates[userID] = "awaiting_cab_problema"
				sendReply(server, message, "📝 Descreva o tópico do problema:")

			case "awaiting_cab_problema":
				if len(text) < 5 {
					sendReply(server, message, "❌ Tópico muito curto! Mínimo 5 caracteres:")
					return
				}
				userData[userID].CabProblema = text
				userStates[userID] = "awaiting_desc_problema"
				sendReply(server, message, "📄 Descreva o problema em detalhes:")

			case "awaiting_desc_problema":
				if len(text) < 10 {
					sendReply(server, message, "❌ Descrição muito curta! Mínimo 10 caracteres:")
					return
				}
				userData[userID].DescProblema = text

				// Finalizar coleta
				data := userData[userID]
				data.SLA = 160
				data.IDResp = "1"
				data.CPF = data.CPFAB
				data.IP = getLocalIP()

				// Enviar para primeira API
				idHelp := sendFirstRequest(*data)
				if idHelp == 0 {
					sendReply(server, message, "❌ Falha ao criar helpdesk!")
					break
				}

				// Enviar para segunda API
				data2 := RequestData2{
					IDHelp: idHelp,
					CPF:    data.CPFAB,
					Hist:   data.DescProblema,
					Status: "A",
					File:   "",
				}
				sendSecondRequest(data2)

				// Feedback final
				sendReply(server, message, fmt.Sprintf("✅ Helpdesk #%d criado com sucesso!", idHelp))

				// Limpar dados
				stateMutex.Lock()
				delete(userStates, userID)
				delete(userData, userID)
				stateMutex.Unlock()

			default:
				if complaintRegex.MatchString(text) {
					stateMutex.Lock()
					userStates[userID] = "awaiting_cpf"
					userData[userID] = &RequestData1{}
					stateMutex.Unlock()
					sendReply(server, message, "🔑 Digite seu CPF (somente números):")
				}
			}
		}
	}
	http.Error(w, "Received", http.StatusOK)
}

func generateHmacForString(message string, random string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(random + message))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

// PARTE DE ENVIO DOS DADOS PARA URL

const (
	baseURL        = "http://192.168.101.16:8008"
	firstEndpoint  = "/api/helpdesk"
	secondEndpoint = "/api/hist"
)

type RequestData1 struct {
	CPFAB        string `json:"cpf_ab"`
	Chapa        string `json:"chapa"`
	IDOper       int    `json:"id_oper"`
	IDGrupo      int    `json:"idgrupo"`
	IDSubgrupo   int    `json:"idsubgrupo"`
	SLA          int    `json:"sla"`
	CabProblema  string `json:"cab_problema"`
	DescProblema string `json:"desc_problema"`
	IDResp       string `json:"id_resp"`
	CPF          string `json:"cpf"`
	IP           string `json:"ip"`
}

type FirstResponse struct {
	IDHelp int `json:"id"` // Campo que será retornado pelo primeiro endpoint
}

type RequestData2 struct {
	IDHelp int    `json:"id_help"`
	CPF    string `json:"id_usu"`
	Hist   string `json:"historico"`
	Status string `json:"status"`
	File   string `json:"file_str"`
}

func main() {

	config = viper.New()
	config.SetConfigName("config")
	config.AddConfigPath(".")
	if err := config.ReadInConfig(); err != nil {
		log.Fatalf("Fatal error config file: %s \n", err)
		return
	}
	log.Println("[Config]        File loaded")

	// Create a mux for routing incoming requests
	m := http.NewServeMux()

	// All URLs will be handled by this function
	m.HandleFunc("/helpdesk", HelpdeskHandling)

	s := &http.Server{
		Addr:    ":" + config.GetString("bot.port"),
		Handler: m,
	}

	log.Printf("[Network]       Listening on port %d", config.GetInt("bot.port"))
	log.Println("[Network]       Starting to listen and serve")
	log.Fatal(s.ListenAndServe())
}

// Validações
func validateCPF(input string) error {
	if len(input) != 11 || !onlyDigits(input) {
		return fmt.Errorf("CPF deve conter exatamente 11 dígitos numéricos")
	}
	return nil
}

func onlyDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Função para obter o IP local
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// Função para enviar requisições POST
func sendFirstRequest(data RequestData1) int {
	client := &http.Client{Timeout: 15 * time.Second}
	jsonBody, _ := json.Marshal(data)

	log.Printf("Enviando para %s:\n%s", firstEndpoint, string(jsonBody))

	resp, err := client.Post(baseURL+firstEndpoint, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("Erro na requisição: %v", err)
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Status: %d", resp.StatusCode)
		return 0
	}

	body, _ := io.ReadAll(resp.Body)
	var response FirstResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("Erro ao decodificar JSON: %v", err)
		return 0
	}

	return response.IDHelp
}

func sendSecondRequest(data RequestData2) {
	client := &http.Client{Timeout: 15 * time.Second}
	jsonBody, _ := json.Marshal(data)

	resp, err := client.Post(baseURL+secondEndpoint, "application/json",
		bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("Erro na segunda requisição: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("Segunda requisição falhou. Status: %d", resp.StatusCode)
		return
	}

	log.Printf("Segunda requisição bem-sucedida! Resposta: %s", string(body))
}
