package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
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

// *****************************************
type ClientInfo struct {
	ClientID     int
	IPAddress    string
	Status       string
	Disconnected time.Time
	Active       bool
}

type UserData struct {
    ID               int
    Surname          string
    Name             string
    MiddleName       string
    PhoneNumber      string
    Email            string
    RoleStr          string
    TimeCreated      string
    Role             int
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
// *****************************************


// *******************************************************************************

var jwtSecretKey = []byte("KlN621!")
func GenerationJWT(ClientID int) (string, error){
	JwtData := jwt.MapClaims{
		"id_users": ClientID,
		"expirationTime":  time.Now().Add(24 * time.Hour).Unix(),
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

// *******************************************************************************


// ******************************************************************************************************************************************************

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
        _, err := os.Stat("AllPages/login.html")
        if os.IsNotExist(err) {
            log.Printf("Ошибка: файл login.html не найден")
            http.Error(w, "Страница не найдена", http.StatusNotFound)
            return
        } else if err != nil {
            log.Printf("Ошибка при доступе к файлу: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        http.ServeFile(w, r, "AllPages/login.html")
        return
    } else if r.Method == http.MethodPost {
        phone := r.FormValue("phone_number")
        password := r.FormValue("password")
        phoneRegex := regexp.MustCompile(`^8\d{10}$`)
        if !phoneRegex.MatchString(phone) {
            http.Error(w, "Номер телефона должен начинаться с 8 и содержать 11 цифр!!!", http.StatusBadRequest)
            return
        }

        stmt, err := db.Prepare("SELECT id_users, hashed_password, role FROM users WHERE phone_number = $1")
        if err != nil {
            log.Printf("Ошибка подготовки запроса: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        defer stmt.Close()

        var idUsers int
        var hashedPassword string
        var role int 
        err = stmt.QueryRow(phone).Scan(&idUsers, &hashedPassword, &role)
        if err == sql.ErrNoRows {
            log.Printf("Ошибка авторизации: номер %s не зарегистрирован", phone)
            http.Error(w, "Ошибка авторизации: номер телефона не зарегистрирован", http.StatusUnauthorized)
            return
        } else if err != nil {
            log.Printf("Ошибка при запросе к БД: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }

        if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
            log.Printf("Ошибка авторизации: неверный пароль для номера %s", phone)
            http.Error(w, "Ошибка авторизации: неверный пароль", http.StatusUnauthorized)
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

        response := map[string]interface{}{
            "id_users": idUsers,
            "role":     role,
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }

}



func (s *Server) HandleAdmin(w http.ResponseWriter, r *http.Request) {
    ipAddress := strings.Split(r.RemoteAddr, ":")[0]
    cookie, err := r.Cookie("jwt_token")
    if err != nil || cookie.Value == "" {
        log.Printf("[DEBUG] JWT-токен не найден для IP: %s, редирект на страницу входа", ipAddress)
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }
    idUsers, err := CheckJwtToken(cookie.Value)
    if err != nil {
        log.Printf("[DEBUG] Ошибка проверки токена для IP: %s, ошибка: %v", ipAddress, err)
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }
    s.clientsMu.Lock()
    client, exists := s.clients[ipAddress]
    s.clientsMu.Unlock()
    if !exists || !client.Active {
        log.Printf("[DEBUG] Клиент с IP: %s и id_users: %d не активен, редирект на страницу входа", ipAddress, idUsers)
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    var Usurname, Uname, UmiddleName, UphoneNumber, Uemail string
    var role int
    queryUserData := `SELECT surname, name, middle_name, phone_number, email, role FROM users WHERE id_users = $1`
    err = db.QueryRow(queryUserData, idUsers).Scan(&Usurname, &Uname, &UmiddleName, &UphoneNumber, &Uemail, &role)
    if err != nil {
        log.Printf("[DEBUG] Ошибка при получении данных пользователя: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    log.Printf("Пользователь %s с IP: %s и id_users: %d перешел на страницу администрирования", Uname, ipAddress, idUsers)

    carPage := r.URL.Query().Get("car_page")
    if carPage == "" {
        carPage = "1"
    }
    carCurrentPage, err := strconv.Atoi(carPage)
    if err != nil || carCurrentPage <= 0 {
        carCurrentPage = 1
    }

    userPage := r.URL.Query().Get("user_page")
    if userPage == "" {
        userPage = "1"
    }
    userCurrentPage, err := strconv.Atoi(userPage)
    if err != nil || userCurrentPage <= 0 {
        userCurrentPage = 1
    }

    cars, err := s.getCarsDataPaged(carCurrentPage, 7)
    if err != nil {
        log.Printf("[DEBUG] Ошибка при получении данных о машинах: %v", err)
        http.Error(w, "Не удалось получить данные о машинах", http.StatusInternalServerError)
        return
    }

    users, err := s.getUsersDataPaged(userCurrentPage, 7)
    if err != nil {
        log.Printf("[DEBUG] Ошибка при получении данных о пользователях: %v", err)
        http.Error(w, "Не удалось получить данные о пользователях", http.StatusInternalServerError)
        return
    }

    var totalCars, totalUsers int
    queryCars := `SELECT COUNT(*) FROM cars`
    err = db.QueryRow(queryCars).Scan(&totalCars)
    if err != nil {
        log.Printf("[DEBUG] Ошибка при подсчете автомобилей: %v", err)
        http.Error(w, fmt.Sprintf("Ошибка при подсчёте автомобилей: %v", err), http.StatusInternalServerError)
        return
    }

    queryUsers := `SELECT COUNT(*) FROM users`
    err = db.QueryRow(queryUsers).Scan(&totalUsers)
    if err != nil {
        log.Printf("[DEBUG] Ошибка при подсчете пользователей: %v", err)
        http.Error(w, fmt.Sprintf("Ошибка при подсчёте пользователей: %v", err), http.StatusInternalServerError)
        return
    }

    totalCarPages := (totalCars + 6) / 7
    totalUserPages := (totalUsers + 6) / 7

    data := struct {
        Cars            []Car
        Users           []UserData
        TotalCarPages   int
        TotalUserPages  int
        CarCurrentPage  int
        UserCurrentPage int
        CurrentUser     UserData
    }{
        Cars:            cars,
        Users:           users,
        TotalCarPages:   totalCarPages,
        TotalUserPages:  totalUserPages,
        CarCurrentPage:  carCurrentPage,
        UserCurrentPage: userCurrentPage,
        CurrentUser: UserData{
            Surname:    Usurname,
            Name:       Uname,
            MiddleName: UmiddleName,
            PhoneNumber: UphoneNumber,
            Email:      Uemail,
            Role:       role,
        },
    }



    tmpl, err := template.ParseFiles("AllPages/adminPage.html")
    if err != nil {
        log.Printf("[DEBUG] Ошибка при загрузке шаблона: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "text/html")
    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("[DEBUG] Ошибка при рендеринге шаблона: %v", err)
        return
    }
}
func (s *Server) getCarsDataPaged(page int, limit int) ([]Car, error) {
    offset := (page - 1) * limit
    query := `SELECT c.id_car, c.brand, c.model, c.year, c.engine_volume, c.power, c.transmission, c.color, c.price, 
            c.id_seller, u.surname, u.name, u.middle_name 
            FROM cars c
            JOIN users u ON c.id_seller = u.id_users
            LIMIT $1 OFFSET $2`
    rows, err := db.Query(query, limit, offset)
    if err != nil {
        return nil, fmt.Errorf("ошибка при запросе машин: %v", err)
    }
    defer rows.Close()
    var cars []Car
    for rows.Next() {
        var car Car
        err := rows.Scan(&car.ID, &car.Brand, &car.Model, &car.Year, &car.EngineVolume, &car.Power, &car.Transmission, &car.Color, 
            &car.Price, &car.SellerID, &car.SellerSurname, &car.SellerName, &car.SellerMiddleName)
        if err != nil {
            return nil, fmt.Errorf("ошибка при чтении данных о машине: %v", err)
        }
        cars = append(cars, car)
    }
    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("ошибка при итерации по строкам: %v", err)
    }
    return cars, nil
}
func (s *Server) getUsersDataPaged(page int, limit int) ([]UserData, error) {
    offset := (page - 1) * limit
    query := `SELECT id_users, surname, name, middle_name, phone_number, email, role, time_created
                FROM users
                LIMIT $1 OFFSET $2`
    rows, err := db.Query(query, limit, offset)
    if err != nil {
        return nil, fmt.Errorf("ошибка при запросе пользователей: %v", err)
    }
    defer rows.Close()
    var users []UserData
    for rows.Next() {
        var user UserData
        var rawTime time.Time 
        err := rows.Scan(&user.ID, &user.Surname, &user.Name, &user.MiddleName, &user.PhoneNumber, &user.Email, &user.Role, &rawTime)
        if err != nil {
            return nil, fmt.Errorf("ошибка при чтении данных о пользователе: %v", err)
        }
        user.TimeCreated = rawTime.Format("02.01.2006 15:04")
        if user.Role == 1 {
            user.RoleStr = "Администратор"
        } else {
            user.RoleStr = "Обычный пользователь"
        }
        users = append(users, user)
    }
    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("ошибка при итерации по строкам: %v", err)
    }
    return users, nil
}


func (s *Server) HandleChangeRole(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("id")
    newRole := r.URL.Query().Get("role")

    if userID == "" || (newRole != "admin" && newRole != "user") {
        http.Error(w, "Неверные параметры", http.StatusBadRequest)
        return
    }

    id, err := strconv.Atoi(userID)
    if err != nil {
        http.Error(w, "Ошибка конвертации ID", http.StatusInternalServerError)
        return
    }

    role := 0
    if newRole == "admin" {
        role = 1
    }

    query := `UPDATE users SET role = $1 WHERE id_users = $2`
    _, err = db.Exec(query, role, id)
    if err != nil {
        log.Printf("Ошибка при изменении роли пользователя: %v", err)
        http.Error(w, "Ошибка при изменении роли", http.StatusInternalServerError)
        return
    }

    response := map[string]interface{}{
        "success": true,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
func (s *Server) deleteCarHandlerADM(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }

    carID := r.URL.Query().Get("id")
    if carID == "" {
        http.Error(w, "Не указан ID автомобиля", http.StatusBadRequest)
        return
    }

    _, err := db.Exec("DELETE FROM cars WHERE id_car = $1", carID)
    if err != nil {
        http.Error(w, "Ошибка удаления автомобиля", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}
func (s *Server) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }

    userID := r.URL.Query().Get("id")
    if userID == "" {
        http.Error(w, "Не указан ID пользователя", http.StatusBadRequest)
        return
    }

    _, err := db.Exec("DELETE FROM cars WHERE id_seller = $1", userID)
    if err != nil {
        http.Error(w, "Ошибка удаления объявлений пользователя", http.StatusInternalServerError)
        return
    }

    _, err = db.Exec("DELETE FROM users WHERE id_users = $1", userID)
    if err != nil {
        http.Error(w, "Ошибка удаления пользователя", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
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
		_, err := os.Stat("AllPages/register.html")
		if os.IsNotExist(err) {
			log.Printf("Ошибка: файл register.html не найден")
			http.Error(w, "Страница не найдена", http.StatusNotFound)
			return
		} else if err != nil {
			log.Printf("Ошибка при доступе к файлу: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		http.ServeFile(w, r, "AllPages/register.html")
		return
	} else if r.Method == http.MethodPost {
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

        _, err = db.Exec("INSERT INTO users (phone_number, surname, name, middle_name, email, hashed_password, role) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            phone, surname, name, middleName, email, hashedPassword, 0)
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

        log.Printf("Пользователь с номером телефона %s успешно зарегистрирован", phone)
        w.Write([]byte("Регистрация успешна"))
    }

}

// ******************************************************************************************************************************************************


// ******************************************************************************************************************************************************

func (s *Server) HandleSettingsAndUpdate(w http.ResponseWriter, r *http.Request) { 
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
        log.Printf("Клиент с IP: %s и id_users: %d был не найден в системе и перенаправлен на страницу с регистрацией", ipAddress, idUsers)
		http.Redirect(w, r, "/login", http.StatusFound) 
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

        tmpl, err := template.ParseFiles("AllPages/settings.html")
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



func (s *Server) handleAddCar(w http.ResponseWriter, r *http.Request) {
    ipAddress := strings.Split(r.RemoteAddr, ":")[0]
    cookie, err := r.Cookie("jwt_token")
    if err != nil {
        log.Printf("[%s] JWT-токен не найден, редирект на страницу входа", ipAddress)
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
        http.Redirect(w, r, "/login", http.StatusFound) 
        return
    }

    log.Printf("Клиент с IP: %s, ClientID: %d перешел на страницу с размещением объявления о машине", ipAddress, client.ClientID)

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

    if r.Method == http.MethodGet {
        t, err := template.ParseFiles("AllPages/AddNewCar.html")
        if err != nil {
            log.Printf("Ошибка загрузки шаблона: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }

        err = t.Execute(w, data) 
        if err != nil {
            log.Printf("Ошибка рендеринга шаблона: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        return
    } else if r.Method == http.MethodPost {
        err = r.ParseMultipartForm(10 << 20)
        if err != nil {
            http.Error(w, "Ошибка обработки формы", http.StatusBadRequest)
            return
        }
        brand := r.FormValue("brand")
        model := r.FormValue("model")
        year := r.FormValue("year")
        price := r.FormValue("price")
        engineVolume := r.FormValue("engineVolume")
        power := r.FormValue("power")
        transmission := r.FormValue("transmission")
        color := r.FormValue("color")

        query := `INSERT INTO cars (brand, model, year, engine_volume, power, transmission, color, price, id_seller) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id_car`
        var carID int
        err = db.QueryRow(query, brand, model, year, engineVolume, power, transmission, color, price, idUsers).Scan(&carID)
        if err != nil {
            log.Printf("Ошибка добавления автомобиля в БД: %v", err)
            http.Error(w, "Ошибка добавления автомобиля", http.StatusInternalServerError)
            return
        }

        log.Printf("Автомобиль ID %d успешно добавлен продавцом ID %d", carID, idUsers)
        http.Redirect(w, r, "AllPages/allinf.html", http.StatusSeeOther)
    }
}
// ******************************************************************************************************************************************************


// ******************************************************************************************************************************************************

func (s *Server) filterHandler(w http.ResponseWriter, r *http.Request) {
    ipAddress := strings.Split(r.RemoteAddr, ":")[0]
    s.clientsMu.Lock()
    client, exists := s.clients[ipAddress]
    s.clientsMu.Unlock()
    if !exists || !client.Active {
        log.Printf("Клиент с IP: %s неактивен", ipAddress)
        http.Redirect(w, r, "/login", http.StatusFound) 
        return
    }
    
    var (
        userData UserData
        token    string
        idUsers  int
        hasJWT   bool
    )

    if cookie, err := r.Cookie("jwt_token"); err == nil {
        if idUsers, err = CheckJwtToken(cookie.Value); err == nil {
            hasJWT = true
            token = cookie.Value

            queryUser := `SELECT surname, name, middle_name, phone_number, email FROM users WHERE id_users = $1`
            row := db.QueryRow(queryUser, idUsers)
            if err := row.Scan(&userData.Surname, &userData.Name, &userData.MiddleName, &userData.PhoneNumber, &userData.Email); err != nil {
                log.Printf("[ERROR] Ошибка получения данных пользователя: %v", err)
                hasJWT = false
            }
        } else {
            log.Printf("[WARNING] Ошибка проверки токена: %v", err)
        }
    }

    qp := r.URL.Query()
    yearFrom, yearTo := qp.Get("year-from"), qp.Get("year-to")
    engineVolumeFrom, engineVolumeTo := qp.Get("engine-volume-from"), qp.Get("engine-volume-to")
    priceFrom, priceTo := qp.Get("price-from"), qp.Get("price-to")
    powerFrom, powerTo := qp.Get("power-from"), qp.Get("power-to")
    color := qp.Get("color")
    color = strings.Trim(color, "[]\"") 
    transmission := qp.Get("transmission")
    transmission = strings.Trim(transmission, "[]\"") 

    query := `
        SELECT c.id_car, c.brand, c.model, c.year, c.engine_volume, c.power, c.transmission,
            c.color, c.price, u.id_users, u.surname, u.name, u.middle_name,
            u.phone_number, u.email
        FROM cars c
        JOIN users u ON c.id_seller = u.id_users
        WHERE c.year BETWEEN $1 AND $2
        AND c.engine_volume BETWEEN $3 AND $4`

    args := []interface{}{yearFrom, yearTo, engineVolumeFrom, engineVolumeTo}
    paramIndex := 5

    if priceFrom != "" && priceTo != "" {
        query += fmt.Sprintf(" AND c.price BETWEEN $%d AND $%d", paramIndex, paramIndex+1)
        args = append(args, priceFrom, priceTo)
        paramIndex += 2
    }
    if powerFrom != "" && powerTo != "" {
        query += fmt.Sprintf(" AND c.power BETWEEN $%d AND $%d", paramIndex, paramIndex+1)
        args = append(args, powerFrom, powerTo)
        paramIndex += 2
    }
    if color != "" {
        query += fmt.Sprintf(" AND c.color = $%d", paramIndex)
        args = append(args, color)
        paramIndex++
    }
    if transmission != "" {
        query += fmt.Sprintf(" AND c.transmission = $%d", paramIndex)
        args = append(args, transmission) 
        paramIndex++
    }

    rows, err := db.Query(query, args...)
    if err != nil {
        log.Printf("[ERROR] Ошибка при запросе автомобилей: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var cars []Car
    for rows.Next() {
        var car Car
        if err := rows.Scan(&car.ID, &car.Brand, &car.Model, &car.Year, &car.EngineVolume, &car.Power, &car.Transmission,
            &car.Color, &car.Price, &car.SellerID, &car.SellerSurname, &car.SellerName, &car.SellerMiddleName,
            &car.SellerPhone, &car.SellerEmail); err != nil {
            log.Printf("[ERROR] Ошибка обработки данных автомобиля: %v", err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        cars = append(cars, car)
    }

    log.Printf("Пользователь %s с IP: %s сделал запрос по поиску специального фильтра и нашел %d машин", userData.Name, ipAddress, len(cars))

    page, err := strconv.Atoi(r.URL.Query().Get("page"))
    if err != nil || page < 1 {
        page = 1
    }
    carsPerPage := 8
    offset := (page - 1) * carsPerPage
    var paginatedCars []Car
    totalCars := len(cars) 
    if offset < totalCars {
        end := offset + carsPerPage
        if end > totalCars {
            end = totalCars
        }
        paginatedCars = cars[offset:end]
    }
    totalPages := (totalCars + carsPerPage - 1) / carsPerPage

    var carRows [][]Car
    rowSize := 4
    for i := 0; i < len(paginatedCars); i += rowSize {
        end := i + rowSize
        if end > len(paginatedCars) {
            end = len(paginatedCars)
        }
        carRows = append(carRows, paginatedCars[i:end])
    }

    data := struct {
        IsAuthenticated bool
        Username        string
        UserData        UserData
        Token           string
        Cars          []Car
        CarRows         [][]Car 
        TotalPages    int
        CurrentPage   int
    }{
        IsAuthenticated: hasJWT,
        Username:        userData.Name,
        UserData:        userData,
        Token:           token, 
        Cars:          cars,
        CarRows:         carRows,
        TotalPages:    totalPages,
        CurrentPage:   page,
    }

    tmpl, err := template.ParseFiles("AllPages/filterSearch.html")
    if err != nil {
        log.Printf("[ERROR] Ошибка загрузки шаблона: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "text/html")
    tmpl.Execute(w, data)
}



func (s *Server) searchCarsHandler(w http.ResponseWriter, r *http.Request) {
    ipAddress := strings.Split(r.RemoteAddr, ":")[0]
    s.clientsMu.Lock()

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

    s.clientsMu.Unlock()

    var userData UserData
    var idUsers int
    var hasJWT bool 

    cookie, err := r.Cookie("jwt_token")
    if err == nil {
        idUsers, err = CheckJwtToken(cookie.Value)
        if err == nil {
            hasJWT = true
        }
    }

    brand := r.URL.Query().Get("brand")
    if brand == "" {
        http.Error(w, "Не указан бренд", http.StatusBadRequest)
        return
    }

    page, err := strconv.Atoi(r.URL.Query().Get("page"))
    if err != nil || page < 1 {
        page = 1
    }
    carsPerPage := 8
    offset := (page - 1) * carsPerPage

    var totalCars int
    err = db.QueryRow(`SELECT COUNT(*) FROM cars WHERE LOWER(brand) = LOWER($1);`, brand).Scan(&totalCars)
    if err != nil {
        log.Printf("[%s] Ошибка подсчёта машин: %v", ipAddress, err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    totalPages := (totalCars + carsPerPage - 1) / carsPerPage

    query := `SELECT cars.id_car, cars.brand, cars.model, cars.year, cars.engine_volume, cars.power, cars.transmission,
                cars.color, cars.price, users.id_users, users.surname, users.name, users.middle_name, users.phone_number, users.email
                FROM cars
                JOIN users ON cars.id_seller = users.id_users
                WHERE LOWER(cars.brand) = LOWER($1)
                ORDER BY cars.id_car
                LIMIT $2 OFFSET $3;`

    rows, err := db.Query(query, brand, carsPerPage, offset)
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

    if hasJWT {
        err = db.QueryRow("SELECT surname, name, middle_name, phone_number, email FROM users WHERE id_users = $1", idUsers).
            Scan(&userData.Surname, &userData.Name, &userData.MiddleName, &userData.PhoneNumber, &userData.Email)
        if err != nil {
            log.Printf("[%s] Ошибка получения данных пользователя: %v", ipAddress, err)
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
    }

    var carRows [][]Car
    rowSize := 4
    for i := 0; i < len(cars); i += rowSize {
        end := i + rowSize
        if end > len(cars) {
            end = len(cars)
        }
        carRows = append(carRows, cars[i:end])
    }

    data := struct {
        Username    string
        UserData    UserData
        Cars        []Car
        Brand       string
        Auth        bool 
        CarRows     [][]Car 
        TotalPages  int
        CurrentPage int
    }{
        Cars:        cars,
        Brand:       brand,
        Auth:        hasJWT,
        CarRows:     carRows,
        TotalPages:  totalPages,
        CurrentPage: page,
    }

    if hasJWT {
        data.UserData = userData
        data.Username = userData.Name
    }

    log.Printf("Пользователь %s (IP: %s) сделал запрос на поиск автомобилей бренда: %s", data.Username, ipAddress, brand)

    tmpl, err := template.ParseFiles("AllPages/specialsearcher.html")
    if err != nil {
        log.Printf("[%s] Ошибка загрузки шаблона: %v", ipAddress, err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("[%s] Ошибка рендеринга шаблона: %v", ipAddress, err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
    }
}



func (s *Server) CarsInfoHandler(w http.ResponseWriter, r *http.Request){
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
    s.clientsMu.Lock()
    client, exists := s.clients[ipAddress]
    s.clientsMu.Unlock()
    if !exists || !client.Active {
        log.Printf("Клиент с IP: %s и id_users: %d неактивен", ipAddress, idUsers)
        http.Redirect(w, r, "/login", http.StatusFound) 
        return
    }


	if r.Method == http.MethodGet {
		userData, err := getUserDataByID(db, idUsers)
		if err != nil {
			log.Printf("[%s] Ошибка получения данных пользователя: %v", ipAddress, err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

        log.Printf("Пользователь %s с IP-адресом %s перешел на страницу своих объявлений", 
			userData.Name, ipAddress)

		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 {
			page = 1
		}

		carsPerPage := 10
		offset := (page - 1) * carsPerPage

		query := `SELECT c.id_car, c.brand, c.model, c.year, c.engine_volume, c.power, 
			c.transmission, c.color, c.price, u.id_users, u.name, u.surname, u.middle_name, 
			u.phone_number, u.email 
			FROM cars c 
			JOIN users u ON c.id_seller = u.id_users 
			WHERE c.id_seller = $1 
			ORDER BY c.id_car DESC 
			LIMIT $2 OFFSET $3`

		rows, err := db.Query(query, idUsers, carsPerPage, offset)
		if err != nil {
			log.Printf("[%s] Ошибка выполнения SQL-запроса: %v", ipAddress, err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var cars []Car
		for rows.Next() {
			var car Car
			err := rows.Scan(&car.ID, &car.Brand, &car.Model, &car.Year, &car.EngineVolume, &car.Power,
				&car.Transmission, &car.Color, &car.Price, &car.SellerID, &car.SellerName,
				&car.SellerSurname, &car.SellerMiddleName, &car.SellerPhone, &car.SellerEmail)
			if err != nil {
				log.Printf("[%s] Ошибка сканирования данных: %v", ipAddress, err)
				http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
				return
			}
			cars = append(cars, car)
		}

		var totalCars int
		err = db.QueryRow(`SELECT COUNT(*) FROM cars WHERE id_seller = $1`, idUsers).Scan(&totalCars)
		if err != nil {
			log.Printf("[%s] Ошибка получения общего числа машин: %v", ipAddress, err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		totalPages := (totalCars + carsPerPage - 1) / carsPerPage

		var carRows [][]Car
		rowSize := 5
		for i := 0; i < len(cars); i += rowSize {
			end := i + rowSize
			if end > len(cars) {
				end = len(cars)
			}
			carRows = append(carRows, cars[i:end])
		}

		data := struct {
			Username   string
			UserData   UserData
			Token      string
			Cars       [][]Car
			Page       int
			TotalCars  int
			TotalPages int
		}{
			Username:   userData.Name,
			UserData:   userData,
			Token:      cookie.Value,
			Cars:       carRows,
			Page:       page,
			TotalCars:  totalCars,
			TotalPages: totalPages,
		}

		tmpl, err := template.ParseFiles("AllPages/carperson.html")
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
	} else if r.Method == http.MethodPost {
		err = r.ParseMultipartForm(10 << 20)
		if err != nil {
			http.Error(w, "Ошибка обработки формы", http.StatusBadRequest)
			return
		}
		carID := r.FormValue("carID")
		brand := r.FormValue("brand")
		model := r.FormValue("model")
		year := r.FormValue("year")
		price := r.FormValue("price")
		engineVolume := r.FormValue("engineVolume")
		power := r.FormValue("power")
		transmission := r.FormValue("transmission")
		color := r.FormValue("color")

		updateQuery := `UPDATE cars SET brand=$1, model=$2, year=$3, engine_volume=$4, 
						power=$5, transmission=$6, color=$7, price=$8 
						WHERE id_car=$9 AND id_seller=$10`

		result, err := db.Exec(updateQuery, brand, model, year, engineVolume, power, transmission, color, price, carID, idUsers)
		if err != nil {
			log.Printf("[%s] Ошибка обновления данных: %v", ipAddress, err)
			http.Error(w, "Ошибка обновления данных", http.StatusInternalServerError)
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			log.Printf("[%s] Автомобиль с ID %s не найден или принадлежит другому пользователю", ipAddress, carID)
			http.Error(w, "Автомобиль не найден", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Данные успешно обновлены"))
	}
}
func deleteCarHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Неверный метод", http.StatusMethodNotAllowed)
        return
    }
    err := r.ParseMultipartForm(10 << 20) 
    if err != nil {
        http.Error(w, "Ошибка обработки формы", http.StatusBadRequest)
        return
    }
    carID := r.FormValue("carID")
    if carID == "" {
        http.Error(w, "ID машины не передан", http.StatusBadRequest)
        return
    }

    id, err := strconv.Atoi(carID)
    if err != nil {
        http.Error(w, "Неверный формат ID машины", http.StatusBadRequest)
        return
    }

    _, err = db.Exec("DELETE FROM cars WHERE id_car = $1", id)
    if err != nil {
        http.Error(w, "Не удалось удалить объявление", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// ******************************************************************************************************************************************************


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
        log.Printf("Клиент с IP: %s и id_users: %d был не найден в системе и перенаправлен на страницу с регистрацией", ipAddress, idUsers)
		http.Redirect(w, r, "/login", http.StatusFound) 
        return
    }
    log.Printf("Пользователь с ID %d и IP %s перешел на главную страницу с объявлениями", client.ClientID, ipAddress)
    userData, err := getUserDataByID(db, idUsers)
    if err != nil {
        log.Printf("Ошибка при извлечении данных пользователя: %v", err)
        http.Error(w, "Ошибка при извлечении данных пользователя", http.StatusInternalServerError)
        return
    }

    page, err := strconv.Atoi(r.URL.Query().Get("page"))
    if err != nil || page < 1 {
        page = 1
    }
    carsPerPage := 7
    offset := (page - 1) * carsPerPage

    cars, totalCars, err := getPaginatedCars(db, carsPerPage, offset)
    if err != nil {
        log.Printf("Ошибка при извлечении данных о машинах: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    carsAll, carCounts, err := getCarsAndCounts(db)
    if err != nil {
        log.Printf("Ошибка при подсчете брендов: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    colors, err := getDistinctValues(db, "color")
    if err != nil {
        log.Printf("Ошибка при получении списка цветов: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    transmissions, err := getDistinctValues(db, "transmission")
    if err != nil {
        log.Printf("Ошибка при получении списка коробок передач: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    brandColumns := DelenieBrandsIntoColumns(carCounts)
    totalPages := (totalCars + carsPerPage - 1) / carsPerPage


    data := struct {
        Username    string
        UserData    UserData
        Token       string

        Cars          []Car
        CarsAll       []Car  
        CarData       map[string]int

        BrandColumns [][]string 
        Colors       []string
        Transmissions []string
        TotalPages    int
        CurrentPage   int
    }{
        Username:    userData.Name,
        UserData:    userData,
        Token:       cookie.Value,
        Cars:          cars,
        CarsAll:       carsAll,  
        CarData:       carCounts,
        BrandColumns: brandColumns, 
        Colors:       colors,
        Transmissions: transmissions,
        TotalPages:    totalPages,
        CurrentPage:   page,
    }



    tmpl, err := template.ParseFiles("AllPages/allinf.html")
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
    if r.Method != http.MethodGet {
        http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
        return
    }

    // log.Println("Все куки в запросе:", r.Cookies())
    cookie, err := r.Cookie("jwt_token")
    if err != nil {
        log.Println("Кука jwt_token отсутствует (или не установлена)")
    } else {
        log.Println("jwt_token:", cookie.Value)
    }

    ipAddress := strings.Split(r.RemoteAddr, ":")[0]
    s.clientsMu.Lock()
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
    s.clientsMu.Unlock()

    page, err := strconv.Atoi(r.URL.Query().Get("page"))
    if err != nil || page < 1 {
        page = 1
    }
    carsPerPage := 7
    offset := (page - 1) * carsPerPage

    cars, totalCars, err := getPaginatedCars(db, carsPerPage, offset)
    if err != nil {
        log.Printf("Ошибка при извлечении данных о машинах: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    totalPages := (totalCars + carsPerPage - 1) / carsPerPage

    carsAll, carCounts, err := getCarsAndCounts(db)
    if err != nil {
        log.Printf("Ошибка при подсчете брендов: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    colors, err := getDistinctValues(db, "color")
    if err != nil {
        log.Printf("Ошибка при получении списка цветов: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    transmissions, err := getDistinctValues(db, "transmission")
    if err != nil {
        log.Printf("Ошибка при получении списка коробок передач: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    brandColumns := DelenieBrandsIntoColumns(carCounts)

    data := struct {
        Cars          []Car
        CarsAll       []Car  
        CarData       map[string]int
        BrandColumns  [][]string
        Colors        []string
        Transmissions []string
        TotalPages    int
        CurrentPage   int
    }{
        Cars:          cars,
        CarsAll:       carsAll,  
        CarData:       carCounts,
        BrandColumns:  brandColumns,
        Colors:        colors,
        Transmissions: transmissions,
        TotalPages:    totalPages,
        CurrentPage:   page,
    }

    // log.Printf("Страница: %d / %d", page, totalPages)
    tmpl, err := template.ParseFiles("AllPages/HomePage.html")
    if err != nil {
        log.Printf("Ошибка загрузки шаблона: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "text/html")
    if err := tmpl.Execute(w, data); err != nil {
        log.Printf("Ошибка при рендеринге шаблона: %v", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
    }
}
func getDistinctValues(db *sql.DB, column string) ([]string, error) {
    query := fmt.Sprintf("SELECT DISTINCT %s FROM cars ORDER BY %s", column, column)
    rows, err := db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var values []string
    for rows.Next() {
        var value string
        if err := rows.Scan(&value); err != nil {
            return nil, err
        }
        values = append(values, value)
    }
    return values, nil
}
func DelenieBrandsIntoColumns(carData map[string]int) [][]string {
    var brands []string
    for brand := range carData {
        brands = append(brands, brand)
    }

    sort.Strings(brands) 
    var brandColumns [][]string
    for i := 0; i < len(brands); i += 5 {
        end := i + 5
        if end > len(brands) {
            end = len(brands)
        }
        brandColumns = append(brandColumns, brands[i:end])
    }

    return brandColumns
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
func getPaginatedCars(db *sql.DB, limit, offset int) ([]Car, int, error) {
    query := `
        SELECT 
            cars.id_car, cars.brand, cars.model, cars.year, cars.engine_volume, cars.power,
            cars.transmission, cars.color, cars.price, cars.id_seller,
            users.surname, users.name, users.middle_name, users.phone_number, users.email,
            COUNT(*) OVER() AS total_count
        FROM cars
        JOIN users ON cars.id_seller = users.id_users
        ORDER BY cars.id_car
        LIMIT $1 OFFSET $2
    `

    rows, err := db.Query(query, limit, offset)
    if err != nil {
        return nil, 0, err
    }
    defer rows.Close()

    var cars []Car
    var totalCars int

    for rows.Next() {
        var car Car
        err := rows.Scan(
            &car.ID, &car.Brand, &car.Model, &car.Year, &car.EngineVolume, 
            &car.Power, &car.Transmission, &car.Color, &car.Price, &car.SellerID,
            &car.SellerSurname, &car.SellerName, &car.SellerMiddleName, &car.SellerPhone, &car.SellerEmail,
            &totalCars,
        )
        if err != nil {
            return nil, 0, err
        }
        cars = append(cars, car)
    }
    return cars, totalCars, nil
}



func (s *Server)  LogoutHandler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{
        Name:     "jwt_token",
        Value:    "",
        Path:     "/",
        Expires:  time.Unix(0, 0), 
        MaxAge:   -1, 
        HttpOnly: true,
    })

    // log.Println("JWT успешно удалён из cookie")

    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"message": "Logged out successfully"}`))
}


// ******************************************************************************************************************************************************

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

	// http.HandleFunc("/leave", server.HandleLeave)
	// http.HandleFunc("/heartbeat", server.HandleHeartbeat)
    http.HandleFunc("/logout", server.LogoutHandler)
    http.HandleFunc("/deletecar", deleteCarHandler)

	http.HandleFunc("/", server.HandleRoot)
	http.HandleFunc("/login", server.HandleLogin)

    http.HandleFunc("/adminpage", server.HandleAdmin)
    http.HandleFunc("/delete_car",  server.deleteCarHandlerADM)
    http.HandleFunc("/delete_user",  server.deleteUserHandler)
    http.HandleFunc("/change_role", server.HandleChangeRole)
    
	http.HandleFunc("/register", server.HandleRegister)

	http.HandleFunc("/allinf", server.HandleInfo)
	http.HandleFunc("/addcars", server.handleAddCar) 
	http.HandleFunc("/mycar", server.CarsInfoHandler) 
	http.HandleFunc("/updatecarinfo", server.CarsInfoHandler) 

	http.HandleFunc("/settings", server.HandleSettingsAndUpdate)
	http.HandleFunc("/update_inf", server.HandleSettingsAndUpdate)

	http.HandleFunc("/specialsearcher", server.searchCarsHandler) 
	http.HandleFunc("/filter", server.filterHandler) 


	// go server.CheckClientStatus()

	log.Printf("Сервер запущен на http://%s:%s\n", ip, port)
	if err := http.ListenAndServe(ip+":"+port, nil); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
	return server
}

// func main() {
// 	connStr := "user=car_dealer_user password=!322@VTB dbname=car_dealer sslmode=disable"
// 	var err error
// 	db, err = sql.Open("postgres", connStr)
// 	if err != nil {
// 		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
// 	}

// 	defer db.Close()
// 	// CreateAndStartServer("AllPages/HomePage.html", "192.168.0.125", "8080")
//     // CreateAndStartServer("AllPages/HomePage.html", "0.0.0.0", "8080")
//     CreateAndStartServer("AllPages/HomePage.html", "127.0.0.1", "8080")
// }


func main() {
    if err := godotenv.Load("settings.env"); err != nil {
        log.Fatal("Error loading .env file")
    }

    connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
        os.Getenv("DB_HOST"),  
        os.Getenv("DB_PORT"),
        os.Getenv("DB_USER"),
        os.Getenv("DB_PASSWORD"),
        os.Getenv("DB_NAME"),
        os.Getenv("DB_SSLMODE"),
    )

    var dbErr error
    db, dbErr = sql.Open("postgres", connStr)
    if dbErr != nil {
        log.Fatalf("Не удалось подключиться к базе данных: %v", dbErr)
    }
    defer db.Close()

    CreateAndStartServer(
        "AllPages/HomePage.html",
        os.Getenv("SERVER_IP"),
        os.Getenv("SERVER_PORT"),
    )
}

// func main() {
//     debugEnvVars := []string{"DB_HOST", "DB_PORT", "DB_USER", "DB_NAME", "DB_SSLMODE", "SERVER_IP", "SERVER_PORT"}
//     for _, v := range debugEnvVars {
//         log.Printf("[DEBUG] %s=%s", v, os.Getenv(v))
//     }

//     connStr := fmt.Sprintf(
//         "host=%s port=%s user=%s dbname=%s sslmode=%s",
//         os.Getenv("DB_HOST"),
//         os.Getenv("DB_PORT"),
//         os.Getenv("DB_USER"),
//         os.Getenv("DB_NAME"),
//         os.Getenv("DB_SSLMODE"),
//     )
//     log.Printf("[DEBUG] Подключение к БД: %s (пароль скрыт)", connStr)

//     connStrWithPassword := fmt.Sprintf("%s password=%s", connStr, os.Getenv("DB_PASSWORD"))

//     db, err := sql.Open("postgres", connStrWithPassword)
//     if err != nil {
//         log.Fatalf("[ERROR] Ошибка подключения к БД: %v", err)
//     }
//     defer db.Close()

//     if err := db.Ping(); err != nil {
//         log.Fatalf("[ERROR] Не удалось проверить подключение к БД: %v", err)
//     }
//     log.Println("[DEBUG] Успешное подключение к БД")

//     log.Printf("[DEBUG] Запуск сервера на %s:%s", 
//         os.Getenv("SERVER_IP"), 
//         os.Getenv("SERVER_PORT"))
    
//     CreateAndStartServer(
//         "AllPages/HomePage.html",
//         os.Getenv("SERVER_IP"), 
//         os.Getenv("SERVER_PORT"),
//     )
// }


