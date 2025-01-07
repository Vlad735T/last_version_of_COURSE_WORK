package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq" // Для работы с PostgreSQL
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

func INSERT_INTO_TABLES(db *sql.DB, users [][6]string) error {
	for _, user := range users {
		hashed_password, err := HashPassword(user[5])
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			INSERT INTO users (surname, name, middle_name, phone_number, email, hashed_password)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			user[0], user[1], user[2], user[3], user[4], hashed_password,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func INSERT_INTO_CARS(db *sql.DB, cars [][9]interface{}) error {
	for _, car := range cars {
		_, err := db.Exec(`
			INSERT INTO cars (brand, model, year, engine_volume, power, transmission, color, price, id_seller)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			car[0], car[1], car[2], car[3], car[4], car[5], car[6], car[7], car[8],
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	conn_str_to_db := "user=car_dealer_user password=!322@VTB dbname=car_dealer sslmode=disable"
	db, err := sql.Open("postgres", conn_str_to_db)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Срез с пользователями
	users := [][6]string{
		{"Макаров", "Стефан", "Евгеньевич", "89012481919", "fWZHkkp@mail.ru", "12345"},
		{"Чернов", "Петр", "Алексеевич", "89217956666", "4fpyyuk@microsoft.com", "hash13"},
	}

	err = INSERT_INTO_TABLES(db, users)
	if err != nil {
		log.Fatal(err)
	}

	cars := [][9]interface{}{
		{"BMW", "X6", 2017, 3.0, 249, "АКПП", "белый", 4750000, 2},
		{"Nissan", "Patrol", 2023, 4.0, 275, "АВТОМАТИЧЕСКАЯ", "белый", 8350000, 1},
		{"Chevrolet", "Camaro", 2019, 2.0, 238, "АКПП", "белый", 4400000, 1},
	}

	err = INSERT_INTO_CARS(db, cars)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Данные успешно вставлены в таблицы!")
}
