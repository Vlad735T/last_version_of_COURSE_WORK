package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type inf_client_request struct {
	Time    time.Time
	Message string
}

type client_info struct {
	ID            int
	IP            string
	Connect_time  time.Time
	Status        string
	Request_count int
	Requests      []inf_client_request // srez zaprosov
}

var (
	clientID       int
	clients        = make(map[int]*client_info)
	total_requests int
	mu             sync.Mutex
)

func log_client_connect(client_ip string) int {
	mu.Lock()
	defer mu.Unlock()
	clientID++
	clients[clientID] = &client_info{
		ID:           clientID,
		IP:           client_ip,
		Connect_time: time.Now(),
		Status:       "Connected",
		Requests:     []inf_client_request{},
	}
	return clientID
}

func log_client_disconnected(id int) {
	mu.Lock()
	defer mu.Unlock()
	if client, exists := clients[id]; exists {
		client.Status = "Disconnected"
		log.Printf("Client %d disconnected: %s", client.ID, client.IP)
	}
}

func log_client_request(id int, message string) {
	mu.Lock()
	defer mu.Unlock()
	if client, exists := clients[id]; exists {
		client.Request_count++
		client.Requests = append(client.Requests, inf_client_request{
			Time:    time.Now(),
			Message: message,
		})
		total_requests++
	}
}

func clientHandler(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	clientID := log_client_connect(clientIP)
	defer log_client_disconnected(clientID)
	log.Printf("Client %d connected: %s", clientID, clientIP)

	for {
		// Обработка POST запроса
		if r.Method == http.MethodPost {
			body := r.FormValue("message")
			if body != "" {
				log_client_request(clientID, body)
				fmt.Fprintf(w, "Hello, Client %d! Your message was: %s", clientID, body)
				log.Printf("Client %d sent message: %s", clientID, body)
			} else {
				http.Error(w, "No message received", http.StatusBadRequest)
			}
		} else {
			http.Error(w, "Only POST method is supported.", http.StatusMethodNotAllowed)
			break
		}
	}
}

func main() {
	http.HandleFunc("/connect", clientHandler)

	addr := "localhost:7432"
	log.Printf("Server is running on %s", addr)
	log.Printf("Tracking client connections and requests...")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
