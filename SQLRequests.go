package main

import (
	"database/sql"
	"reflect"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	id       int
	Login    string `json:"Login"`
	Password []byte `json:"Password"`
}

type Note struct {
	id          int
	User_id     int
	Title       string `json:"Title"`
	Description string `json:"Description"`
}

const dblog = "host=localhost port=5432 user=postgres password=123 dbname=postgres sslmode=disable"

func CheckForLoginData(login, password string) (bool, string) {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	loginData, err := db.Query("select * from users where login = '%v'", login)
	if err != nil {
		panic(err.Error())
	}
	var user User
	for loginData.Next() {
		err := loginData.Scan(&user.id, &user.Login, &user.Password)
		if err != nil {
			panic(err.Error())
		}
	}
	if (reflect.DeepEqual(user, User{})) {
		return false, "No user with such login"
	}
	if bcrypt.CompareHashAndPassword(user.Password, []byte(password)) != nil {
		return false, "Wrong password"
	}
	return true, "Gut"
}

func CheckIfLoginFree(login string) bool {
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=123 dbname=postgres sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var username string
	err = db.QueryRow("select login from users where login = '%v'", login).Scan(&username)
	if err != nil {
		panic(err.Error())
	}
	return username == ""
}

func CreateNote(userid int) int {
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=123 dbname=postgres sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	//result, err = db.Exec("insert into notes(user_id, title, description) values('%v', '', '')", userid)
	if err != nil {
		panic(err)
	}
	return 0
}
