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

var subgrupoMap = map[int]map[int]map[int]bool{
	// Operação 1
	1: {
		1:  {2: true, 4: true, 6: true, 53: true, 55: true, 63: true, 74: true, 89: true},
		2:  {8: true, 9: true, 10: true, 11: true, 12: true, 13: true, 14: true, 16: true, 56: true, 58: true, 131: true},
		3:  {83: true},
		4:  {76: true, 79: true, 85: true, 87: true, 92: true, 93: true, 101: true, 103: true, 107: true, 114: true, 116: true, 118: true, 124: true, 129: true},
		5:  {95: true, 97: true, 99: true},
		7:  {1: true, 57: true, 109: true, 111: true, 122: true, 135: true},
		8:  {137: true, 138: true, 139: true, 140: true, 141: true},
		9:  {142: true, 143: true, 144: true, 145: true, 146: true, 147: true, 148: true},
		10: {149: true},
		11: {150: true, 151: true, 152: true, 153: true, 154: true, 155: true, 156: true},
		12: {157: true},
	},

	// Operação 2
	2: {
		1:  {23: true, 25: true, 27: true, 61: true, 62: true, 90: true},
		2:  {29: true, 30: true, 31: true, 32: true, 33: true, 34: true, 35: true, 37: true, 65: true, 66: true, 67: true, 68: true, 69: true, 70: true, 71: true, 72: true, 73: true, 126: true, 128: true, 132: true, 133: true, 134: true},
		3:  {38: true, 39: true, 40: true, 41: true, 42: true, 77: true, 84: true, 121: true},
		4:  {75: true, 80: true, 86: true, 88: true, 91: true, 94: true, 102: true, 104: true, 108: true, 115: true, 117: true, 119: true, 125: true, 130: true},
		5:  {96: true, 98: true, 100: true},
		6:  {105: true, 106: true, 113: true, 127: true},
		7:  {22: true, 64: true, 110: true, 112: true, 123: true, 136: true},
		12: {158: true},
	},
}

var slaMap = map[int]map[int]map[int]int{
	// Operação 1
	1: {
		1: {
			2: 2, 4: 4, 6: 7, 53: 8, 55: 10, 63: 11, 74: 87, 89: 103,
		},
		2: {
			8: 12, 9: 16, 10: 17, 11: 14, 12: 15, 13: 18, 14: 19, 16: 20,
			56: 21, 58: 23, 131: 145,
		},
		3: {
			17: 24, 18: 25, 120: 134,
		},
		4: {
			76: 88, 79: 93, 85: 99, 87: 101, 92: 106, 93: 107, 101: 115,
			103: 117, 107: 121, 114: 128, 116: 130, 118: 132, 124: 138, 129: 143,
		},
		5: {
			95: 109, 97: 111, 99: 113,
		},
		7: {
			1: 1, 57: 22, 109: 123, 111: 125, 122: 136, 135: 149,
		},
		8: {
			137: 3, 138: 31, 139: 151, 141: 152,
		},
		9: {
			142: 153, 143: 154, 144: 155, 145: 156, 146: 157, 147: 158, 148: 159,
		},
		10: {
			149: 160,
		},
		11: {
			150: 161, 151: 162, 152: 163, 153: 164, 154: 165, 155: 166, 156: 167,
		},
		12: {
			157: 168,
		},
	},

	// Operação 2
	2: {
		1: {
			23: 30, 25: 32, 27: 35, 61: 38, 62: 39, 90: 104,
		},
		2: {
			29: 40, 30: 63, 31: 64, 32: 61, 33: 62, 34: 65, 35: 66, 37: 67,
			65: 68, 66: 70, 67: 71, 68: 72, 69: 73, 70: 74, 71: 75, 72: 76,
			73: 77, 126: 140, 128: 142, 132: 146, 133: 147, 134: 148,
		},
		3: {
			38: 78, 39: 79, 40: 80, 41: 85, 42: 86, 77: 92, 84: 98, 121: 135,
		},
		4: {
			75: 90, 80: 94, 86: 100, 88: 102, 91: 105, 94: 108, 102: 116,
			104: 118, 108: 122, 115: 129, 117: 131, 119: 133, 125: 139, 130: 144,
		},
		5: {
			96: 110, 98: 112, 100: 114,
		},
		6: {
			105: 119, 106: 120, 113: 127, 127: 141,
		},
		7: {
			22: 29, 64: 69, 110: 124, 112: 126, 123: 137, 136: 150,
		},
		12: {
			158: 169,
		},
	},
}

type CPFResponse struct {
	Chapa string `json:"chapa"` // Estrutura esperada da resposta
}

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

func subgrupos(id_oper int, idgrupo int) string {
	// id_oper = 1
	if id_oper == 1 && idgrupo == 1 {
		return "2- Office\n4- Programas\n6- Maxima\n53- WMS\n55- Sistema Catraca\n63- Sistema Operacional\n74- VM\n89- Psi"
	}
	if id_oper == 1 && idgrupo == 2 {
		return "8- Computador\n9- Impressora\n10- Leitor\n11- Monitor\n12- Teclado / Mouse\n13- Notebook\n14- Scanner\n16- Outros\n56- Catraca\n58- Coletor\n131- Relogio de Ponto"
	}
	if id_oper == 1 && idgrupo == 3 {
		return "83- Corporativo"
	}
	if id_oper == 1 && idgrupo == 4 {
		return "76- Cadastro RCA\n79- Cadastro Usuario\n85- Acesso Rotina / Dados\n87- Instalacao e Manutencao\n92- Erro de Rotina\n93- Cadastro Secao\n101- Banco de Dados\n103- Relatorios\n107- Inativar Usuario\n114- Ecommerce\n116- Duvidas\n118- Acertos\n124- Transferir Venda\n129- Alterar Rotina"
	}
	if id_oper == 1 && idgrupo == 5 {
		return "95- Sugestoes\n97- Erros\n99- Cadastros"
	}
	if id_oper == 1 && idgrupo == 7 {
		return "1- Internet\n57- Wi-Fi\n109- Compartilhamento\n111- Usuario AD\n122- Falhas\n135- Monitoramento"
	}
	if id_oper == 1 && idgrupo == 8 {
		return "137- Nova Conta\n138- Bloquear Conta\n139- Resetar Senha\n140- Thunderbird\n141- Problemas"
	}
	if id_oper == 1 && idgrupo == 9 {
		return "142- Usuario RM\n143- Acessos RM\n144- RM (Falhas)\n145- Usuario Digte\n146- Acessos Digte\n147- Digte (Falhas)\n148- Duvidas"
	}
	if id_oper == 1 && idgrupo == 10 {
		return "149- Teste TI (subgrupo)"
	}
	if id_oper == 1 && idgrupo == 11 {
		return "150- Cadastro Usuario\n151- Acesso Rotina / Dados\n152- Instalacao e Manutencao\n153- Erro de Rotina\n154- Banco de Dados\n155- Relatorios\n156- Duvidas"
	}
	if id_oper == 1 && idgrupo == 12 {
		return "157- Cadastro"
	}

	// id_oper = 2
	if id_oper == 2 && idgrupo == 1 {
		return "23- Office\n25- Programas\n27- Maxima\n61- Sistema Catraca\n62- Sistema Operacional\n90- Psi"
	}
	if id_oper == 2 && idgrupo == 2 {
		return "29- Computador\n30- Impressora\n31- Leitor\n32- Monitor\n33- Teclado / Mouse\n34- Notebook\n35- Scanner\n37- Outros\n65- Catraca\n66- Coletor\n67- Impressora Cartaz\n68- Impressora Preco\n69- Impressora Cupom\n70- Busca Preco\n71- Balanca\n72- Antifurto\n73- Leitor Biometrico\n126- Pinpad\n128- PDV\n132- Relogio de Ponto\n133- Impressora Cartao\n134- Telefone PDV"
	}
	if id_oper == 2 && idgrupo == 3 {
		return "38- Nova Conta\n39- Bloqueio Conta\n40- Novo Ramal\n41- Ramal Mudo\n42- Programacoes\n77- Recuperar Conta\n84- Corporativo\n121- Problemas"
	}
	if id_oper == 2 && idgrupo == 4 {
		return "75- Cadastro RCA\n80- Cadastro Usuario\n86- Acesso Rotina / Dados\n88- Instalacao e Manutencao\n91- Erro de Rotina\n94- Cadastro Secao\n102- Banco de Dados\n104- Relatorios\n108- Inativar Usuario\n115- Ecommerce\n117- Duvidas\n119- Acertos\n125- Transferir Venda\n130- Alterar Rotina"
	}
	if id_oper == 2 && idgrupo == 5 {
		return "96- Sugestoes\n98- Erros\n100- Cadastros"
	}
	if id_oper == 2 && idgrupo == 6 {
		return "105- Erros\n106- Sitef\n113- Diferenca Tesouraria\n127- Acessos"
	}
	if id_oper == 2 && idgrupo == 7 {
		return "22- Internet\n64- Wi-Fi\n110- Compartilhamento\n112- Usuario AD\n123- Falhas\n136- Monitoramento"
	}
	if id_oper == 2 && idgrupo == 12 {
		return "158- Cadastro"
	}

	return ""
}

func isValidSubgrupo(id_oper int, idgrupo int, selected_num int) bool {
	if oper, ok := subgrupoMap[id_oper]; ok {
		if grupo, ok := oper[idgrupo]; ok {
			return grupo[selected_num]
		}
	}
	return false
}

func GetSLA(id_oper, id_grupo, id_subgrupo int) int {
	if oper, ok := slaMap[id_oper]; ok {
		if grupo, ok := oper[id_grupo]; ok {
			if sla, ok := grupo[id_subgrupo]; ok {
				return sla
			}
		}
	}
	return 0
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
				if text == "Cancelar" || text == "cancelar" {
					sendReply(server, message, "❌ Helpdesk cancelado!")
					stateMutex.Lock()
					delete(userStates, userID)
					delete(userData, userID)
					stateMutex.Unlock()
					break
				} else if validateCPF(text) != nil {
					sendReply(server, message, "❌ CPF inválido! Digite novamente (somente números):")
					return
				} else if consultaCpfRequest(text) == "" {
					sendReply(server, message, "❌ CPF Não encontrado no nosso sistema! Digite novamente (somente números):")
					return
				}
				userData[userID] = &RequestData1{CPFAB: text}
				userStates[userID] = "awaiting_chapa"
				sendReply(server, message, "🔢 Digite sua matrícula:")

			case "awaiting_chapa":
				if text == "Cancelar" || text == "cancelar" {
					sendReply(server, message, "❌ Helpdesk cancelado!")
					stateMutex.Lock()
					delete(userStates, userID)
					delete(userData, userID)
					stateMutex.Unlock()
					break
				} else if len(text) < 3 {
					sendReply(server, message, "❌ Matrícula inválida! Mínimo 3 caracteres:")
					return
				} else if consultaCpfRequest(userData[userID].CPFAB) != text {
					sendReply(server, message, "❌ Matrícula inválida! Não corresponde com o cpf informado anteriormente!")
					return
				}
				userData[userID].Chapa = text
				userStates[userID] = "awaiting_oper"
				sendReply(server, message, "⚙️ Escolha o tipo de operação:\n1 - ADM\n2 - Operação")

			case "awaiting_oper":
				num, err := strconv.Atoi(text)
				if text == "Cancelar" || text == "cancelar" {
					sendReply(server, message, "❌ Helpdesk cancelado!")
					stateMutex.Lock()
					delete(userStates, userID)
					delete(userData, userID)
					stateMutex.Unlock()
					break
				} else if err != nil || (num < 1 || num > 2) {
					sendReply(server, message, "❌ Opção inválida! Digite de 1 ou 2:")
					return
				}
				userData[userID].IDOper = num
				userStates[userID] = "awaiting_idgrupo"
				sendReply(server, message, "🏷️ Digite o número do grupo\n1- Autosky\n2- Consinco\n3- Econect\n4- Email\n5- Hardware\n6- Intranet\n7- Rede\n8- Software\n9- Telefonia\n10- Teste TI\n11- TOTVS\n12- Winthor12\n")

			case "awaiting_idgrupo":
				num, err := strconv.Atoi(text)
				if text == "Cancelar" || text == "cancelar" {
					sendReply(server, message, "❌ Helpdesk cancelado!")
					stateMutex.Lock()
					delete(userStates, userID)
					delete(userData, userID)
					stateMutex.Unlock()
					break
				} else if err != nil || num < 1 || num > 12 {
					sendReply(server, message, "❌ Grupo inválido! Digite de 1 - 12")
					return
				}
				userData[userID].IDGrupo = num
				userStates[userID] = "awaiting_idsubgrupo"
				sendReply(server, message, subgrupos(userData[userID].IDOper, userData[userID].IDGrupo))

			case "awaiting_idsubgrupo":
				num, err := strconv.Atoi(text)
				if text == "Cancelar" || text == "cancelar" {
					sendReply(server, message, "❌ Helpdesk cancelado!")
					stateMutex.Lock()
					delete(userStates, userID)
					delete(userData, userID)
					stateMutex.Unlock()
					break
				} else if err != nil || !isValidSubgrupo(userData[userID].IDOper, userData[userID].IDGrupo, num) {
					sendReply(server, message, "❌ Subgrupo inválido!")
					return
				}
				userData[userID].IDSubgrupo = num
				userStates[userID] = "awaiting_cab_problema"
				sendReply(server, message, "📝 Descreva o tópico do problema:")

			case "awaiting_cab_problema":
				if text == "Cancelar" || text == "cancelar" {
					sendReply(server, message, "❌ Helpdesk cancelado!")
					stateMutex.Lock()
					delete(userStates, userID)
					delete(userData, userID)
					stateMutex.Unlock()
					break
				} else if len(text) < 5 {
					sendReply(server, message, "❌ Tópico muito curto! Mínimo 5 caracteres:")
					return
				}
				userData[userID].CabProblema = text
				userStates[userID] = "awaiting_desc_problema"
				sendReply(server, message, "📄 Descreva o problema em detalhes:")

			case "awaiting_desc_problema":
				if text == "Cancelar" || text == "cancelar" {
					sendReply(server, message, "❌ Helpdesk cancelado!")
					stateMutex.Lock()
					delete(userStates, userID)
					delete(userData, userID)
					stateMutex.Unlock()
					break
				} else if len(text) < 10 {
					sendReply(server, message, "❌ Descrição muito curta! Mínimo 10 caracteres:")
					return
				}
				userData[userID].DescProblema = text

				// Finalizar coleta
				data := userData[userID]
				data.SLA = GetSLA(userData[userID].IDOper, userData[userID].IDGrupo, userData[userID].IDSubgrupo)
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
	baseURL      = "http://192.168.101.16:"
	port8008     = "8008"
	port8001     = "8001"
	helpEndpoint = "/api/helpdesk"
	histEndpoint = "/api/hist"
	cpfEndpoint  = "/api/contusurA/"
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
	// Validação básica de formato
	if len(input) != 11 || !onlyDigits(input) {
		return fmt.Errorf("CPF deve conter exatamente 11 dígitos numéricos")
	}

	// Converte para slice de inteiros
	digits := make([]int, 11)
	for i, c := range input {
		digits[i] = int(c - '0')
	}

	// Verifica números repetidos (caso comum de CPF inválido)
	if allEqual(digits) {
		return fmt.Errorf("CPF inválido (números repetidos)")
	}

	// Cálculo do primeiro dígito verificador
	sum1 := 0
	for i := 0; i < 9; i++ {
		sum1 += digits[i] * (10 - i)
	}
	remainder1 := sum1 % 11
	digit1 := 11 - remainder1
	if digit1 >= 10 {
		digit1 = 0
	}

	// Validação do primeiro dígito
	if digit1 != digits[9] {
		return fmt.Errorf("Primeiro dígito verificador inválido")

	}

	// Cálculo do segundo dígito verificador
	sum2 := 0
	for i := 0; i < 10; i++ {
		sum2 += digits[i] * (11 - i)
	}
	remainder2 := sum2 % 11
	digit2 := 11 - remainder2
	if digit2 >= 10 {
		digit2 = 0
	}

	// Validação do segundo dígito
	if digit2 != digits[10] {
		return fmt.Errorf("Segundo dígito verificador inválido")
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

func allEqual(digits []int) bool {
	first := digits[0]
	for _, d := range digits[1:] {
		if d != first {
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

	log.Printf("Enviando para %s:\n%s", helpEndpoint, string(jsonBody))

	resp, err := client.Post(baseURL+port8008+helpEndpoint, "application/json", bytes.NewBuffer(jsonBody))
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

	resp, err := client.Post(baseURL+port8008+histEndpoint, "application/json",
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

func consultaCpfRequest(cpf string) string {
	client := &http.Client{Timeout: 15 * time.Second}
	url := baseURL + port8001 + cpfEndpoint + cpf

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Erro na requisição: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Status não OK: %d", resp.StatusCode)
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Erro ao ler resposta: %v", err)
		return ""
	}

	var result []CPFResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("Erro ao decodificar JSON: %v", err)
		return ""
	}

	if len(result) == 0 || result[0].Chapa == "" {
		log.Printf("Chapa não encontrada na resposta")
		return ""
	}

	log.Printf("Chapa encontrada: %s", result[0].Chapa)
	return result[0].Chapa
}
