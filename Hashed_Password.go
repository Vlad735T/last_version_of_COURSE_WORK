package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	// Генерация хэша
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

func main() {

	password := "koftyguhijn45ru6ty"
	Hashed_Password, err := HashPassword(password)
	if err != nil {
		fmt.Println("Ошибка хэширования:", err)
		return
	}

	fmt.Println("Сам пароль:", password)
	fmt.Println("Хэш пароля:", Hashed_Password)
	IsValid := CheckPasswordHash(password, Hashed_Password)
	fmt.Println("Пароль валиден:", IsValid)
}
