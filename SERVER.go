package main

import (
	"database/sql"
	"os"

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

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ??????????????????????????????????????????????????????????????????????????????????????????

type ClientInfo struct {
	ClientID     int
	IPAddress    string
	Status       string
	Disconnected time.Time
	Active       bool
}

// ??????????????????????????????????????????????????????????????????????????????????????????

type Server struct {
	clients            map[string]ClientInfo
	nextID             int
	activeClientsCount int
	clientsMu          sync.Mutex
	htmlTmpl           *template.Template
}

// ??????????????????????????????????????????????????????????????????????????????????????????

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ipAddress := strings.Split(r.RemoteAddr, ":")[0]
	s.clientsMu.Lock()
	client, exists := s.clients[ipAddress]
	s.clientsMu.Unlock()
	if !exists {
		client = ClientInfo{
			ClientID:  s.nextID,
			IPAddress: ipAddress,
			Active:    true,
		}
		s.clientsMu.Lock()
		s.clients[ipAddress] = client
		s.nextID++
		s.clientsMu.Unlock()
	}
	log.Printf("Попытка авторизации от клиента с IP: %s, ClientID: %d, Номер телефона: %s", ipAddress, client.ClientID, r.FormValue("phone_number"))
	if r.Method == http.MethodGet {
		_, err := os.Stat("login.html")
		if os.IsNotExist(err) {
			log.Printf("Ошибка: файл login.html не найден")
			http.Error(w, "Страница не найдена", http.StatusNotFound)
			return
		} else if err != nil {
			log.Printf("Ошибка при доступе к файлу: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}
		http.ServeFile(w, r, "login.html")
		return
	}

	if r.Method == http.MethodPost {
		phone := r.FormValue("phone_number")
		password := r.FormValue("password")
		if len(phone) != 11 || phone[0] != '8' {
			http.Error(w, "Номер телефона должен начинаться с 8 и содержать 11 цифр", http.StatusBadRequest)
			return
		}
		var hashedPassword string
		err := db.QueryRow("SELECT hashed_password FROM users WHERE phone_number = $1", phone).Scan(&hashedPassword)
		if err == sql.ErrNoRows {
			http.Error(w, "Номер не зарегистрирован", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Неправильный пароль", http.StatusUnauthorized)
			return
		}
		log.Printf("Успешная авторизация: ClientID: %d, IP: %s, Номер телефона: %s", client.ClientID, ipAddress, phone)
		http.ServeFile(w, r, "alinf.html")
	}
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_, err := os.Stat("register.html")
		if os.IsNotExist(err) {
			log.Printf("Ошибка: файл register.html не найден")
			http.Error(w, "Страница не найдена", http.StatusNotFound)
			return
		} else if err != nil {
			log.Printf("Ошибка при доступе к файлу: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		http.ServeFile(w, r, "register.html")
		return
	}

	if r.Method == http.MethodPost {
		phone := r.FormValue("phone_number")
		surname := r.FormValue("surname")
		name := r.FormValue("name")
		middleName := r.FormValue("middle_name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if len(phone) != 11 || phone[0] != '8' {
			http.Error(w, "Номер телефона должен начинаться с 8 и содержать 11 цифр", http.StatusBadRequest)
			return
		}

		if surname == "" || name == "" || middleName == "" || email == "" {
			http.Error(w, "Все поля, кроме пароля, должны быть заполнены", http.StatusBadRequest)
			return
		}

		if len(password) == 0 {
			http.Error(w, "Пароль не может быть пустым", http.StatusBadRequest)
			return
		}

		var existingPhone string
		err := db.QueryRow("SELECT phone_number FROM users WHERE phone_number = $1", phone).Scan(&existingPhone)
		if err != nil && err != sql.ErrNoRows {
			log.Printf("Ошибка при проверке существования телефона в базе данных: %v", err)
			http.Error(w, "Ошибка при регистрации", http.StatusInternalServerError)
			return
		}

		if err == nil {
			http.Error(w, "Этот номер телефона уже зарегистрирован", http.StatusBadRequest)
			return
		}

		hashedPassword, err := HashPassword(password)
		if err != nil {
			log.Printf("Ошибка при хешировании пароля: %v", err)
			http.Error(w, "Ошибка при хешировании пароля", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (phone_number, surname, name, middle_name, email, hashed_password) VALUES ($1, $2, $3, $4, $5, $6)",
			phone, surname, name, middleName, email, hashedPassword)
		if err != nil {
			log.Printf("Ошибка при вставке в базу данных: %v", err)
			http.Error(w, "Ошибка при регистрации", http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Регистрация успешна"))
	}
}

func (s *Server) HandleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_, err := os.Stat("alinf.html")
		if os.IsNotExist(err) {
			log.Printf("Ошибка: файл alinf.html не найден")
			http.Error(w, "Страница не найдена", http.StatusNotFound)
			return
		} else if err != nil {
			log.Printf("Ошибка при доступе к файлу: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		http.ServeFile(w, r, "alinf.html")
		return
	}
}

// ??????????????????????????????????????????????????????????????????????????????????????????

func (s *Server) HandleRoot(w http.ResponseWriter, r *http.Request) {
	ipAddress := strings.Split(r.RemoteAddr, ":")[0]

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	client, exists := s.clients[ipAddress]
	if !exists {
		client = ClientInfo{
			ClientID:  s.nextID,
			IPAddress: ipAddress,
			Active:    true,
		}
		s.clients[ipAddress] = client
		s.nextID++
		s.activeClientsCount++
	} else {
		client.Active = true
		s.clients[ipAddress] = client
	}

	rootTemplate, err := template.ParseFiles("HomePage.html")
	if err != nil {
		log.Printf("Ошибка загрузки шаблона: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	if err := rootTemplate.Execute(w, nil); err != nil {
		log.Printf("Ошибка при выполнении шаблона: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
	}
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

func (s *Server) HandleLeave(w http.ResponseWriter, r *http.Request) {
	ipAddress := strings.Split(r.RemoteAddr, ":")[0]
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	if client, exists := s.clients[ipAddress]; exists {
		if client.Active { // Уменьшаем счетчик только если клиент действительно был активен
			s.activeClientsCount--
		}
		client.Status = "отключен"
		client.Disconnected = time.Now()
		client.Active = false
		s.clients[ipAddress] = client
		log.Printf("Клиент с IP: %s отключен в %s", ipAddress, client.Disconnected.Format("2006-01-02 15:04:05"))
	}
}

func (s *Server) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	ipAddress := strings.Split(r.RemoteAddr, ":")[0]
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	if client, exists := s.clients[ipAddress]; exists {
		if !client.Active {
			log.Printf("Клиент с IP: %s повторно подключен в %s", ipAddress, time.Now().Format("2006-01-02 15:04:05"))
			s.activeClientsCount++ // Увеличиваем счетчик активных клиентов
		}

		client.Status = "подключен"
		client.Active = true
		client.Disconnected = time.Time{}
		s.clients[ipAddress] = client
	} else {
		log.Printf("Клиент с IP %s не найден", ipAddress)
	}
}

func (s *Server) CheckClientStatus() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.clientsMu.Lock()
		activeCount := 0
		for ip, client := range s.clients {
			if client.Active {
				activeCount++
				log.Printf("Клиент с ID: %d, IP: %s, статус: подключен", client.ClientID, ip)
			} else {
				log.Printf("Клиент с ID: %d, IP: %s, статус: отключен", client.ClientID, ip)
			}
		}

		s.activeClientsCount = activeCount
		log.Printf("В данный момент к серверу подключены: %d человек(а)", activeCount)
		s.clientsMu.Unlock()
	}
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

func CreateAndStartServer(templatePath, ip, port string) *Server {
	htmlTmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatalf("Ошибка загрузки шаблона: %v", err)
	}
	server := &Server{
		clients:            make(map[string]ClientInfo),
		nextID:             1,
		activeClientsCount: 0,
		htmlTmpl:           htmlTmpl,
	}

	http.HandleFunc("/", server.HandleRoot)
	http.HandleFunc("/leave", server.HandleLeave)
	http.HandleFunc("/heartbeat", server.HandleHeartbeat)
	http.HandleFunc("/login", server.HandleLogin)
	http.HandleFunc("/register", server.HandleRegister)
	http.HandleFunc("/alinf", server.HandleInfo)

	// go server.CheckClientStatus()

	log.Printf("Сервер запущен на http://%s:%s\n", ip, port)
	if err := http.ListenAndServe(ip+":"+port, nil); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}

	return server
}

func main() {
	connStr := "user=car_dealer_user password=!322@VTB dbname=car_dealer sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}

	defer db.Close()
	CreateAndStartServer("HomePage.html", "192.168.0.20", "8080")
}
