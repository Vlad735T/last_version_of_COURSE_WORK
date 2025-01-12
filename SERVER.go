package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// HashPassword хеширует пароль
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPasswordHash проверяет пароль
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type ClientInfo struct {
	ClientID    int
	IPAddress   string
	ConnectTime time.Time
	LastSeen    time.Time
	Status      string
}

type Server struct {
	clients   map[string]ClientInfo
	nextID    int
	clientsMu sync.Mutex
	htmlTmpl  *template.Template
}

func NewServer(templatePath string) *Server {
	htmlTmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatalf("Ошибка загрузки шаблона: %v", err)
	}

	return &Server{
		clients:  make(map[string]ClientInfo),
		nextID:   1,
		htmlTmpl: htmlTmpl,
	}
}

func (s *Server) HandleAuth(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	var hashedpassword string
	err := db.QueryRow("SELECT hashed_password FROM Users WHERE phone_number = $1", request.Phone).Scan(&hashedpassword)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
		return
	}

	if !CheckPasswordHash(request.Password, hashedpassword) {
		http.Error(w, "Неверный пароль", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Авторизация успешна",
	})
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	hashedpassword, err := HashPassword(request.Password)
	if err != nil {
		http.Error(w, "Ошибка при хешировании пароля", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO Users (phone_number, hashed_password) VALUES ($1, $2)", request.Phone, hashedpassword)
	if err != nil {
		http.Error(w, "Ошибка при регистрации пользователя", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Регистрация успешна",
	})
}

// HandleRoot обрабатывает запросы к корневому маршруту "/"
func (s *Server) HandleRoot(w http.ResponseWriter, r *http.Request) {
	// Получаем IP-адрес клиента
	ipAddress := strings.Split(r.RemoteAddr, ":")[0]

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	if client, exists := s.clients[ipAddress]; exists {
		client.LastSeen = time.Now()
		client.Status = "подключен"
		s.clients[ipAddress] = client
	} else {
		s.clients[ipAddress] = ClientInfo{
			ClientID:    s.nextID,
			IPAddress:   ipAddress,
			ConnectTime: time.Now(),
			LastSeen:    time.Now(),
			Status:      "подключен",
		}
		s.nextID++
	}

	w.Header().Set("Content-Type", "text/html")
	if err := s.htmlTmpl.Execute(w, nil); err != nil {
		log.Printf("Ошибка при выполнении шаблона: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
	}
}

func (s *Server) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	ipAddress := strings.Split(r.RemoteAddr, ":")[0]

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	if client, exists := s.clients[ipAddress]; exists {
		client.LastSeen = time.Now()
		client.Status = "подключен"
		s.clients[ipAddress] = client
	} else {
		log.Printf("Клиент с IP %s не найден", ipAddress)
	}
}

func (s *Server) StartClientChecker() {
	go func() {
		for {
			s.clientsMu.Lock()
			activeClients := 0
			for ip, client := range s.clients {
				if time.Since(client.LastSeen) <= 10*time.Second {
					activeClients++
				} else {
					client.Status = "отключен"
					s.clients[ip] = client
				}
			}
			log.Printf("В данный момент к серверу подключены %d клиентов:", activeClients)
			for _, client := range s.clients {
				log.Printf(
					"ClientID: %d, IP: %s, время подключения: %v, статус: %s",
					client.ClientID,
					client.IPAddress,
					client.ConnectTime.Format("2006-01-02 15:04:05"),
					client.Status,
				)
			}
			s.clientsMu.Unlock()
			time.Sleep(3 * time.Second)
		}
	}()
}

func (s *Server) Start(ip, port string) {
	s.clientsMu.Lock()
	s.clients = make(map[string]ClientInfo)
	s.nextID = 1
	s.clientsMu.Unlock()

	http.HandleFunc("/", s.HandleRoot)
	http.HandleFunc("/heartbeat", s.HandleHeartbeat)
	http.HandleFunc("/auth", s.HandleAuth)
	http.HandleFunc("/register", s.HandleRegister)

	log.Printf("Сервер запущен на http://%s:%s\n", ip, port)
	if err := http.ListenAndServe(ip+":"+port, nil); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}

func main() {
	connStr := "user=car_dealer_user password=!322@VTB dbname=car_dealer sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Ошибка подключения к базе данных: %v", err)
	}
	defer db.Close()
	server := NewServer("home_page_website.html")
	server.StartClientChecker()
	server.Start("192.168.0.165", "8080")
}
