package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {

	serverAddr := "http://localhost:7432/connect"

	for {
		fmt.Print("Enter message to send to the server (or type 'exit' to quit): ")
		var message string
		fmt.Scanln(&message)
		if message == "exit" {
			fmt.Println("Exiting client.")
			break
		}

		resp, err := http.PostForm(serverAddr, map[string][]string{
			"message": {message},
		})

		if err != nil {
			log.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()
		fmt.Println("Server response:", resp.Status)
	}
}
