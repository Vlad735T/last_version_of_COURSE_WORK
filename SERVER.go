package main

import (
	"database/sql"
	"os"
	"regexp"

	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lib/pq"
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


// *******************************************
type ClientInfo struct {
	ClientID     int
	IPAddress    string
	Status       string
	Disconnected time.Time
	Active       bool
}

type UserData struct {
    ID          int
    Surname     string
    Name        string
    MiddleName  string
    PhoneNumber string
    Email       string
    TimeCreated string
}

type Car struct {
    ID            int
    Brand         string
    Model         string
    Year          int
    EngineVolume  float64
    Power         int
    Transmission  string
    Color         string
    Price         int
    SellerID      int
    SellerName    string
    SellerPhone   string
    SellerEmail   string
    SellerSurname string  
    SellerMiddleName string 
}
type Server struct {
	clients            map[string]ClientInfo
	nextID             int
	activeClientsCount int
	clientsMu          sync.Mutex
	htmlTmpl           *template.Template
}
// *******************************************


// ******************************************************************************************
var jwtSecretKey = []byte("KlN621!")

func GenerationJWT(ClientID int) (string, error){
	JwtData := jwt.MapClaims{
		"id_users": ClientID,
		"expirationTime":  time.Now().Add(24 * time.Hour).Unix(), // Время истечения токена
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtData)
	return token.SignedString(jwtSecretKey)
}
func CheckJwtToken(tokenStr string)(int, error){
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error){
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok{
			return nil, fmt.Errorf("неправильный метод подписи")
		}
		return jwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		return 0, fmt.Errorf("невалидный токен")
	}

	TokenData, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("не удалось получить данные из токена")
	}

	ClientID, ok := TokenData["id_users"].(float64)
	if !ok {
		return 0, fmt.Errorf("не удалось получить ID пользователя из токена")
	}
	return int(ClientID), nil
}
// ******************************************************************************************

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

    log.Printf("Клиент с IP: %s, ClientID: %d перешел на страницу авторизации", ipAddress, client.ClientID)

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
		phoneRegex := regexp.MustCompile(`^8\d{10}$`)
		if !phoneRegex.MatchString(phone) {
			http.Error(w, "Некорректный формат номера телефона", http.StatusBadRequest)
			return
		}

		stmt, err := db.Prepare("SELECT id_users, hashed_password FROM users WHERE phone_number = $1")
		if err != nil {
			log.Printf("Ошибка подготовки запроса: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		var idUsers int
		var hashedPassword string
		err = stmt.QueryRow(phone).Scan(&idUsers, &hashedPassword)
		if err != nil {
			log.Printf("Ошибка авторизации для номера %s: %v", phone, err)
			http.Error(w, "Неверный номер телефона или пароль", http.StatusUnauthorized)
			return
		}

		// Проверяем пароль
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
			log.Printf("Ошибка авторизации: неверный пароль для номера %s", phone)
			http.Error(w, "Неверный номер телефона или пароль", http.StatusUnauthorized)
			return
		}

		log.Printf("Успешная авторизация: ID пользователя: %d, IP: %s, Номер телефона: %s", client.ClientID, ipAddress, phone)

		token, err := GenerationJWT(idUsers)
		if err != nil {
			http.Error(w, "Ошибка генерации токена", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
		})

		http.ServeFile(w, r, "allinf.html")
    }
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	s.clientsMu.Lock()
	client, exists := s.clients[ip]
	if !exists {
		client = ClientInfo{
			ClientID:  s.nextID,
			IPAddress: ip,
			Active:    true,
		}
		s.clients[ip] = client
		s.nextID++
	}
	s.clientsMu.Unlock()
	log.Printf("Пользователь с ID: %d и IP: %s перешел на страницу регистрации", client.ClientID, ip)

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
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
				log.Printf("Ошибка: email уже зарегистрирован: %v", err)
				http.Error(w, "Этот email уже зарегистрирован", http.StatusBadRequest)
				return
			}

			log.Printf("Ошибка при вставке в базу данных: %v", err)
			http.Error(w, "Ошибка при регистрации", http.StatusInternalServerError)
			return
		}

		log.Printf("Пользователь с ID: %d и IP: %s успешно зарегистрирован", client.ClientID, ip)
		w.Write([]byte("Регистрация успешна"))
	}
}


func (s *Server) HandleSettingsAndUpdate(w http.ResponseWriter, r *http.Request) { 
    cookie, err := r.Cookie("jwt_token")
    if err != nil || cookie.Value == "" {
        log.Printf("JWT-токен не найден, редирект на страницу входа")
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    idUsers, err := CheckJwtToken(cookie.Value)
    if err != nil {
        log.Printf("Ошибка проверки токена: %v", err)
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    ipAddress := strings.Split(r.RemoteAddr, ":")[0]
	s.clientsMu.Lock()
	client, exists := s.clients[ipAddress]
	s.clientsMu.Unlock()
	if !exists || !client.Active {
		log.Printf("Клиент с IP: %s и id_users: %d неактивен", ipAddress, idUsers)
		http.Error(w, "Ваш аккаунт не активен", http.StatusForbidden)
		return
	}

    if r.Method == http.MethodGet {

        log.Printf("Пользователь с ID %d и IP %s перешел на страницу изменений данных", client.ClientID, ipAddress)

        user, err := getUserDataByID(db, idUsers)
        if err != nil {
            log.Printf("Ошибка при получении данных пользователя: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        data := struct {
            Username  string
            UserData  UserData
            Token     string
        }{
            Username: user.Name,
            UserData: user,
            Token:    cookie.Value,
        }

        tmpl, err := template.ParseFiles("settings.html")
        if err != nil {
            log.Printf("Ошибка при загрузке шаблона: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        err = tmpl.Execute(w, data)
        if err != nil {
            log.Printf("Ошибка при рендеринге шаблона: %v", err)
            return 
        }
    }

	if r.Method == http.MethodPost {
		surname := r.FormValue("surname")
		name := r.FormValue("name")
		middleName := r.FormValue("middle_name")
		email := r.FormValue("email")
		password := r.FormValue("password") 

		if surname == "" || name == "" || middleName == "" || email == "" {
			http.Error(w, "Пожалуйста, заполните все поля", http.StatusBadRequest)
			return
		}

		var existingEmail string
		query := `SELECT email FROM users WHERE email = $1 AND id_users != $2`
		err := db.QueryRow(query, email, idUsers).Scan(&existingEmail)
		if err == nil {
			http.Error(w, "Email уже используется другим пользователем", http.StatusBadRequest)
			return
		} else if err != sql.ErrNoRows {
			log.Printf("Ошибка при проверке email: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		// Проверка, нужно ли обновлять пароль
		if password != "" {
			err = UpdateUserDataWithPassword(db, idUsers, surname, name, middleName, email, password)
		} else {
			err = UpdateUserDataWithoutPassword(db, idUsers, surname, name, middleName, email)
		}

		if err != nil {
			log.Printf("Ошибка при обновлении данных пользователя: %v", err)
			http.Error(w, "Ошибка обновления данных", http.StatusInternalServerError)
			return
		}

		log.Printf("Пользователь с ID %d и IP %s обновил свои данные", client.ClientID, ipAddress)

		newToken, err := GenerationJWT(idUsers)
		if err != nil {
			log.Printf("Ошибка при генерации нового токена: %v", err)
			http.Error(w, "Ошибка обновления данных", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt_token",
			Value:    newToken,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		http.Redirect(w, r, "/allinf", http.StatusFound)
		return
	}





}
func UpdateUserDataWithPassword(db *sql.DB, idUsers int, surname, name, middleName, email, password string) error {
    hashedPassword, err := HashPassword(password)
    if err != nil {
        return fmt.Errorf("ошибка хеширования пароля: %v", err)
    }

    query := `UPDATE users SET surname=$1, name=$2, middle_name=$3, email=$4, hashed_password=$5 WHERE id_users=$6`
    _, err = db.Exec(query, surname, name, middleName, email, hashedPassword, idUsers)
    if err != nil {
        return fmt.Errorf("ошибка при обновлении данных пользователя: %v", err)
    }

    return nil
}
func UpdateUserDataWithoutPassword(db *sql.DB, idUsers int, surname, name, middleName, email string) error {
    query := `UPDATE users SET surname=$1, name=$2, middle_name=$3, email=$4 WHERE id_users=$5`
    _, err := db.Exec(query, surname, name, middleName, email, idUsers)
    if err != nil {
        return fmt.Errorf("ошибка при обновлении данных пользователя: %v", err)
    }

    return nil
}






func (s *Server) searchCarsHandler(w http.ResponseWriter, r *http.Request) {
	ipAddress := strings.Split(r.RemoteAddr, ":")[0]
	cookie, err := r.Cookie("jwt_token")
	if err != nil || cookie.Value == "" {
		log.Printf("[%s] JWT-токен не найден, редирект на страницу входа", ipAddress)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	idUsers, err := CheckJwtToken(cookie.Value)
	if err != nil {
		log.Printf("[%s] Ошибка проверки токена: %v", ipAddress, err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

    if r.Method == http.MethodGet {  
        var userData UserData
        err = db.QueryRow("SELECT surname, name, middle_name, phone_number, email FROM users WHERE id_users = $1", idUsers).
            Scan(&userData.Surname, &userData.Name, &userData.MiddleName, &userData.PhoneNumber, &userData.Email)
        if err != nil {
            log.Printf("[%s] Ошибка получения данных пользователя: %v", ipAddress, err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }

        brand := r.URL.Query().Get("brand")
        if brand == "" {
            http.Error(w, "Не указан бренд", http.StatusBadRequest)
            return
        }
        fmt.Println("Запрос на бренд:", brand)

        query := `SELECT cars.id_car, cars.brand, cars.model, cars.year, cars.engine_volume, cars.power, cars.transmission,
                    cars.color, cars.price, users.id_users, users.surname, users.name, users.middle_name, users.phone_number, users.email
                    FROM cars
                    JOIN users ON cars.id_seller = users.id_users
                    WHERE LOWER(cars.brand) = LOWER($1);`

        rows, err := db.Query(query, brand)
        if err != nil {
            log.Printf("[%s] Ошибка при запросе автомобилей: %v", ipAddress, err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        var cars []Car
        for rows.Next() {
            var car Car
            err := rows.Scan(&car.ID, &car.Brand, &car.Model, &car.Year, &car.EngineVolume, &car.Power, &car.Transmission,
                &car.Color, &car.Price, &car.SellerID, &car.SellerSurname, &car.SellerName, &car.SellerMiddleName,
                &car.SellerPhone, &car.SellerEmail)
            if err != nil {
                log.Printf("[%s] Ошибка обработки данных автомобиля: %v", ipAddress, err)
                http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
                return
            }
            cars = append(cars, car)
        }

        data := struct {
            Username string
            UserData UserData
            Token    string
            Cars     []Car
            Brand    string
        }{
            Username: userData.Name,
            UserData: userData,
            Token:    cookie.Value,
            Cars:     cars,
            Brand:    brand,
        }

        tmpl, err := template.ParseFiles("specialsearcher.html")
        if err != nil {
            log.Printf("[%s] Ошибка загрузки шаблона: %v", ipAddress, err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }

        err = tmpl.Execute(w, data)
        if err != nil {
            log.Printf("[%s] Ошибка рендеринга шаблона: %v", ipAddress, err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
    }
}












func (s *Server) HandleInfo(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
        return
    }

    ipAddress := strings.Split(r.RemoteAddr, ":")[0]

    cookie, err := r.Cookie("jwt_token")
    if err != nil || cookie.Value == "" {
        log.Printf("JWT-токен не найден, редирект на страницу входа")
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    idUsers, err := CheckJwtToken(cookie.Value)
    if err != nil {
        log.Printf("Ошибка проверки токена: %v", err)
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    s.clientsMu.Lock()
    client, exists := s.clients[ipAddress]
    s.clientsMu.Unlock()
    if !exists || !client.Active {
        log.Printf("Клиент с IP: %s и id_users: %d неактивен", ipAddress, idUsers)
        http.Error(w, "Ваш аккаунт не активен", http.StatusForbidden)
        return
    }
    log.Printf("Пользователь с ID %d и IP %s перешел на главную страницу с объявлениями", client.ClientID, ipAddress)

    userData, err := getUserDataByID(db, idUsers)
    if err != nil {
        log.Printf("Ошибка при извлечении данных пользователя: %v", err)
        http.Error(w, "Ошибка при извлечении данных пользователя", http.StatusInternalServerError)
        return
    }

    cars, carCounts, err := getCarsAndCounts(db)
    if err != nil {
        log.Printf("Ошибка при извлечении данных о машинах: %v", err)
        http.Error(w, "Ошибка при извлечении данных о машинах", http.StatusInternalServerError)
        return
    }

    data := struct {
        Username  string
        UserData  UserData
        Token     string
        CarData   map[string]int
        Cars      []Car 
    }{
        Username: userData.Name,
        UserData: userData,
        Token:    cookie.Value,
        CarData:  carCounts,
        Cars:     cars, 
    }

    tmpl, err := template.ParseFiles("allinf.html")
    if err != nil {
        log.Printf("Ошибка при парсинге шаблона: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("Ошибка при рендеринге шаблона: %v", err)
    }
}
func getCarsAndCounts(db *sql.DB) ([]Car, map[string]int, error) {
    rows, err := db.Query(`
        SELECT 
            cars.id_car, cars.brand, cars.model, cars.year, cars.engine_volume, cars.power,
            cars.transmission, cars.color, cars.price, cars.id_seller,
            users.surname, users.name, users.middle_name, users.phone_number, users.email
        FROM cars
        JOIN users ON cars.id_seller = users.id_users
    `)
    if err != nil {
        return nil, nil, err
    }
    defer rows.Close()

    var cars []Car
    carCounts := make(map[string]int)

    for rows.Next() {
        var car Car
        err := rows.Scan(
            &car.ID, &car.Brand, &car.Model, &car.Year, &car.EngineVolume, 
            &car.Power, &car.Transmission, &car.Color, &car.Price, &car.SellerID,
            &car.SellerSurname, &car.SellerName, &car.SellerMiddleName, &car.SellerPhone, &car.SellerEmail,
        )
        if err != nil {
            return nil, nil, err
        }
        cars = append(cars, car)
        carCounts[car.Brand]++ 
    }

    return cars, carCounts, nil
}
func getUserDataByID(db *sql.DB, idUsers int) (UserData, error) {
    var userData UserData
    query := `SELECT id_users, surname, name, middle_name, phone_number, email, time_created 
				FROM users WHERE id_users = $1`
    err := db.QueryRow(query, idUsers).Scan(&userData.ID, &userData.Surname, &userData.Name, 
										&userData.MiddleName, &userData.PhoneNumber, 
										&userData.Email, &userData.TimeCreated)
    if err != nil {
        if err == sql.ErrNoRows {
            return UserData{}, fmt.Errorf("пользователь не найден")
        }
        return UserData{}, fmt.Errorf("ошибка при извлечении данных: %v", err)
    }
    return userData, nil
}


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

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

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

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


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
	http.HandleFunc("/allinf", server.HandleInfo)
	http.HandleFunc("/settings", server.HandleSettingsAndUpdate)
	http.HandleFunc("/update_inf", server.HandleSettingsAndUpdate)
	http.HandleFunc("/specialsearcher", server.searchCarsHandler) 
	
	// http.HandleFunc("/filter", server.searchHandler) 


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
	CreateAndStartServer("HomePage.html", "192.168.0.125", "8080")
}
