package main

import (
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
)

type ClientInfo struct {
	ClientId    int
	ConnectTime time.Time
}

var (
	clients   = make(map[int]ClientInfo)
	clientsMu sync.Mutex
	nextID    = 1
)

func main() {
	html_content, err := template.ParseFiles("home_page_website.html")
	if err != nil {
		log.Fatalf("Ошибка загрузки шаблона: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientID := nextID
		nextID++
		clientsMu.Lock()
		clients[clientID] = ClientInfo{
			ClientId:    clientID,
			ConnectTime: time.Now(),
		}
		clientsMu.Unlock()
		log.Printf("Клиент с ID %d подключился в %v", clientID, time.Now().Format("2006-01-02 15:04:05"))

		w.Header().Set("Content-Type", "text/html")
		if err := html_content.Execute(w, nil); err != nil {
			log.Printf("Ошибка при выполнении шаблона: %v", err)
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		}

		defer func() {
			clientsMu.Lock()
			delete(clients, clientID)
			clientsMu.Unlock()
			log.Printf("Клиент с ID %d отключился в %v", clientID, time.Now().Format("2006-01-02 15:04:05"))
		}()
	})

	go func() {
		for {
			clientsMu.Lock()
			log.Printf("Текущее количество подключенных клиентов: %d", len(clients))
			for _, client := range clients {
				log.Printf("Клиент с ID %d подключен с %v", client.ClientId, client.ConnectTime)
			}
			clientsMu.Unlock()
			time.Sleep(7 * time.Second) // Проверяем каждый 10 секунд
		}
	}()

	port := "8080"
	log.Printf("Сервер запущен на http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
