package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	fiber "github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID           int    `gorm:"type:serial;primaryKey"`
	Login        string `json:"Login"`
	Password     string `json:"Password"`
	RefreshToken string `json:"RefreshToken"`
}

type Note struct {
	ID          int    `gorm:"type:serial;primaryKey"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	UserID      int
	User        User
}

// Осторожно! В js действия основаны на названии этих ошибок, поэтому при их изменении придется лезть в js
// todo: переделать передаваемые клиенту значения с string на int
const (
	InvalidToken      = "Invalid token"
	ExpiredToken      = "Expired token"
	WrongLogin        = "Wrong login"
	WrongPassword     = "Wrong password"
	NonIdentifiedUser = "User is not identified"
	NonExistentUser   = "User does not exist"
	OkayStatus        = "OKAY"
)

var (
	dblog     string
	key       *rsa.PrivateKey
	publicKey *rsa.PublicKey
	db        *gorm.DB
)

const (
	accessTokenExpiration  = time.Minute * 10
	refreshTokenExpiration = time.Hour * 2
)

// Получаем из env файла параметры для работы БД и секретный ключ
func init() {
	if err := godotenv.Load("go.env"); err != nil {
		panic(err)
	}
	dblog, _ = os.LookupEnv("dblog")
	GetKey()
	publicKey = &key.PublicKey
	Migrate()
}

//*** Серверная часть ***//

// Запуск сервера. /resources загружает все необходимые для функционирования страниц файлы и не предполагается для использования юзером.
func main() {
	app := fiber.New()

	app.Static("/resources", "./resources", fiber.Static{CacheDuration: time.Minute})
	app.Static("/", "./resources/html/MainPage.html")
	app.Static("/login", "./resources/html/LoginPage.html")
	app.Static("/register", "./resources/html/RegisterPage.html")
	app.Static("/note", "./resources/html/NotePage.html")
	app.Static("/addnote", "./resources/html/AddNotePage.html")

	app.Post("/login-user", LoginUser)
	app.Post("/register-user", RegisterUser)
	app.Post("/add-note", AddNote)
	app.Get("/get-notes", GetNotes)
	app.Get("/get-note", GetNote)
	app.Put("/change-note", ChangeNote)
	app.Delete("/delete-note", DeleteNote)

	app.Listen(":8080")
}

// Логинит юзера, возвращает мапу с status:wrong password/login если неправильные логин или пароль.
// Если всё нормально, возвращает status:gut и токены, а также обновляет рефреш токен в бд
func LoginUser(c *fiber.Ctx) error {
	var user User
	err := json.Unmarshal(c.Body(), &user)
	if err != nil {
		panic(err)
	}
	status, user_id := CheckLoginAndPassword(user)
	if status == OkayStatus {
		access, refresh := GenerateTokensForUser(user_id)
		PutRefreshToken(user_id, refresh)
		return c.JSON(fiber.Map{"status": status, "accessToken": access, "refreshToken": refresh})
	}
	return c.JSON(fiber.Map{"status": status})
}

// Пытается зарегать пользователя, в случае, если логин занят, возвращает мапу в которой это указано.
// Если не занят, возвращает мапу с тем, что не занято, а также access и refresh токеном
func RegisterUser(c *fiber.Ctx) error {
	var user User
	err := json.Unmarshal(c.Body(), &user)
	if err != nil {
		panic(err)
	}
	if !IsLoginOccupied(user.Login) {
		user.ID = AddNewUser(user)
		access, refresh := GenerateTokensForUser(user.ID)
		PutRefreshToken(user.ID, refresh)
		return c.JSON(fiber.Map{"occupied": false, "accessToken": access, "refreshToken": refresh})
	}
	return c.JSON(fiber.Map{"occupied": true})
}

func GetNotes(c *fiber.Ctx) error {
	return CheckTokensAndDoFunction(c, GetAndMarshalNotes)
}

func GetNote(c *fiber.Ctx) error { // todo: добавить обработку на разрешение доступа по id пользователя
	log.Printf("id of note to return: %v", c.Query("id"))
	note_id, err := strconv.Atoi(c.Query("id"))
	if err != nil {
		return c.JSON(fiber.Map{"status": "bad id"})
	}
	return CheckTokensAndDoFunction(c, GetAndMarshalNote, note_id)
}

func AddNote(c *fiber.Ctx) error {
	note := Note{}
	err := json.Unmarshal(c.Body(), &note)
	if err != nil {
		return err
	}
	log.Printf("Request note to add: %v, %v\n", note.Title, note.Description)
	return CheckTokensAndDoFunction(c, AddNoteToDB, note.Title, note.Description)
}

func ChangeNote(c *fiber.Ctx) error {
	note := Note{}
	err := json.Unmarshal(c.Body(), &note)
	if err != nil {
		return err
	}
	note_id, err := strconv.Atoi(c.Query("id"))
	if err != nil {
		return c.JSON(fiber.Map{"status": "bad id"})
	}
	return CheckTokensAndDoFunction(c, ChangeNoteInDB, note.Title, note.Description, note_id)
}

func DeleteNote(c *fiber.Ctx) error {
	var requestBody map[string]string
	err := json.Unmarshal(c.Body(), &requestBody)
	if err != nil {
		panic(err)
	}
	noteID, err := strconv.Atoi(requestBody["note_id"])
	log.Printf("Note to delete: %v\n", noteID)
	if err != nil {
		panic(err)
	}
	return CheckTokensAndDoFunction(c, DeleteNoteFromDB, noteID)
}

// Позволяет перед выполнением любого действия проверять токены на валидность и создать респонс мапу, которая будет служить телом ответа.
// Переданная функция наполнит мапу дополнительной информацией. В функцию можно закинуть любое количество параметров, user_id при этом будет всегда и всегда будет последним.
func CheckTokensAndDoFunction(c *fiber.Ctx, function func(fiber.Map, ...interface{}) fiber.Map, params ...interface{}) error {
	headers := c.GetReqHeaders()
	if len(headers["X-Access-Token"]) == 0 {
		return c.JSON(fiber.Map{"status": "User is not identified"})
	}
	if headers["X-Access-Token"][0] == "" {
		return c.JSON(fiber.Map{"status": "User is not identified"})
	}
	accessToken := headers["X-Access-Token"][0]
	claims, status := IsTokenValid(accessToken)

	switch status {
	case InvalidToken:
		return c.JSON(fiber.Map{"status": status})
	case ExpiredToken:
		refreshToken := headers["X-Refresh-Token"][0]
		_, refreshTokenStatus := IsTokenValid(refreshToken)
		switch refreshTokenStatus {
		case InvalidToken:
			return c.JSON(fiber.Map{"status": status})
		case ExpiredToken:
			return c.JSON(fiber.Map{"status": status})
		case OkayStatus:
			user_id := GetUserIDFromToken(claims)
			access, refresh := GenerateTokensForUser(user_id)
			PutRefreshToken(user_id, refresh)
			responseBody := fiber.Map{"status": "Success with tokens", "accessToken": access, "refreshToken": refresh}
			params = append(params, user_id)
			responseBody = function(responseBody, params...)
			return c.JSON(responseBody)
		}
	case OkayStatus:
		user_id := GetUserIDFromToken(claims)
		responseBody := fiber.Map{"status": "Success"}
		params = append(params, user_id)
		responseBody = function(responseBody, params...)
		return c.JSON(responseBody)
	}
	return c.JSON(fiber.Map{"status": "Чтото пошло не так. Сильно"})
}

func GetAndMarshalNotes(response fiber.Map, params ...interface{}) fiber.Map {
	notes := GetNotesFromDB(params[0].(int))
	jsonedNotes, err := json.Marshal(notes)
	if err != nil {
		panic(err)
	}
	response["notes"] = jsonedNotes
	log.Printf("GetNotes response: %v\n", response)
	return response
}

func GetAndMarshalNote(response fiber.Map, params ...interface{}) fiber.Map {
	note := GetNoteFromDB(params[0].(int))
	if note.ID == 0 {
		response["status"] = "note does not exist"
		return response
	}
	jsonedNote, err := json.Marshal(note)
	if err != nil {
		panic(err)
	}
	response["note"] = jsonedNote
	log.Printf("GetNote response: %v\n", response)
	return response
}

func AddNoteToDB(response fiber.Map, params ...interface{}) fiber.Map {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	title := params[0].(string)
	description := params[1].(string)
	user_id := params[2].(int)
	res, err := db.Exec(fmt.Sprintf("insert into notes(title, description, user_id) values ('%v','%v','%v')", title, description, user_id))
	if err != nil {
		panic(err)
	}
	log.Printf("Note add result: %v\n", res)
	return response
}

func ChangeNoteInDB(response fiber.Map, params ...interface{}) fiber.Map {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	title := params[0].(string)
	description := params[1].(string)
	note_id := params[2].(int)
	log.Printf("New note values: %v, %v at id=%v\n", title, description, note_id)
	res, err := db.Exec(fmt.Sprintf("update notes set title='%v', description='%v' where id='%v'", title, description, note_id))
	if err != nil {
		panic(err)
	}
	log.Printf("Note change result: %v\n", res)
	return response
}

//*** Работа с токенами ***//

// Создаём токены для пользователя, возвращает access и refresh токены в виде string
// В access токене лежит user.ID
// В refresh токене лежит только дата смерти
func GenerateTokensForUser(user_id int) (string, string) {
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenExpiration)),
		Subject:   strconv.Itoa(user_id),
	}).SignedString(key)
	if err != nil {
		panic(err)
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenExpiration)),
	}).SignedString(key)
	if err != nil {
		panic(err)
	}
	return accessToken, refreshToken
}

// проверка токена на валидность и на срок годности, возвращает соответствующие статусы
func IsTokenValid(token string) (jwt.MapClaims, string) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return claims, ExpiredToken
		case errors.Is(err, jwt.ErrSignatureInvalid) || errors.Is(err, jwt.ErrTokenUnverifiable):
			return claims, InvalidToken
		default:
			panic(err)
		}
	}
	return claims, OkayStatus
}

// возвращает id пользователя на основе токена
func GetUserIDFromToken(claims jwt.MapClaims) int {
	idString := claims["sub"].(string)
	user_id, err := strconv.Atoi(idString)
	if err != nil {
		panic(fmt.Sprintf("%v, idString is %v", err, idString))
	}
	log.Printf("ID from token: %v\n", user_id)
	return user_id
}

//*** Колдунства для получения из файла и сохранения в нем секретного ключа ***//

func GetKey() {
	privateKeyString, _ := os.LookupEnv("key")
	if privateKeyString == "" {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyString = fmt.Sprintf("%v", keyBytes)
		err := os.Setenv("key", privateKeyString) //не записывает в go.env на самом деле. надо фиксить както
		if err != nil {
			panic(err)
		}
	}
	keyBytes := convertStringToBytesSlice(privateKeyString)
	var err error
	key, err = x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		panic(err)
	}
}

func convertStringToBytesSlice(line string) []byte {
	line = strings.Trim(line, "[]")
	parts := strings.Split(line, " ")
	var bytes []byte
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			panic(err)
		}
		bytes = append(bytes, byte(num))
	}
	return bytes
}

//*** Взаимодействие с БД ***//

// Мигрирование таблицы(создаёт в БД таблицы users и notes на основе соответствующих структур)
func Migrate() {
	var err error
	db, err = gorm.Open(postgres.Open(dblog), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Note{})
}

// Проверяет, занят ли логин, возвращает true, если занят и false, если нет
func IsLoginOccupied(requestLogin string) bool {
	var user User
	db.First(&user, "login = ?", requestLogin)
	return user.Login != ""
}

// Проверяет на существование логина, затем на соответствие логина и пароля
func CheckLoginAndPassword(user User) (string, int) {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if !IsLoginOccupied(user.Login) {
		return WrongLogin, -1
	}
	row := db.QueryRow(fmt.Sprintf("SELECT id, password FROM users where login = '%v' limit 1", user.Login))
	var user_id int
	var password []byte
	row.Scan(&user_id, &password)
	err = bcrypt.CompareHashAndPassword(password, []byte(user.Password))
	if err == nil {
		return OkayStatus, user_id
	}
	return WrongPassword, -1
}

// Обновляет рефреш токен пользователю
func PutRefreshToken(user_id int, refreshToken string) {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	refresh := []byte(refreshToken)
	res, err := db.Exec(fmt.Sprintf("update users set refresh_token = '%v' where id = '%v'", refresh, user_id))
	if err != nil {
		panic(err)
	}
	log.Printf("Refresh token update result+%v", res)
}

// Добавляет в БД нового пользователя
func AddNewUser(user User) int {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	userPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	res := db.QueryRow(fmt.Sprintf("insert into users(login, password) values('%v', '%v') returning id", user.Login, string(userPassword)))
	var user_id int
	res.Scan(&user_id)
	log.Printf("New user's id: %v\n", user_id)
	return user_id
}

func GetNoteFromDB(note_id int) Note {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	note := Note{}
	res := db.QueryRow(fmt.Sprintf("select id, title, description from notes where id = '%v'", note_id))
	res.Scan(&note.ID, &note.Title, &note.Description)
	log.Printf("Note to return: %v\n", note)
	return note
}

// получает по id список нотесов
func GetNotesFromDB(user_id int) []Note {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	notes := []Note{}
	res, err := db.Query(fmt.Sprintf("select * from notes where user_id = %v", user_id))
	if err != nil {
		panic(err)
	}
	defer res.Close()
	for res.Next() {
		note := Note{}
		if err := res.Scan(&note.ID, &note.Title, &note.Description, &note.UserID); err != nil {
			panic(err)
		}
		notes = append(notes, note)
	}
	log.Printf("Notes to return: %v\n", notes)
	return notes
}

func DeleteNoteFromDB(response fiber.Map, params ...interface{}) fiber.Map {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	noteId := params[0]
	res, err := db.Exec(fmt.Sprintf("delete from notes where id=%v", noteId))
	if err != nil {
		panic(err)
	}
	log.Printf("Note delete result: %v\n", res)
	return response
}

/*⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⠤⠤⠤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡤⠾⠯⠷⢦⣄⣀⠀⠀⣠⠞⠋⠀⠀⠀⠀⠀⠈⠉⠹⢷⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡼⠋⠁⠀⠀⠀⠀⠀⠈⠉⠓⢾⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣠⣾⣧⠀⣸⣿⣦⠀⠀⠀⠀⠀⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀привет!⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡟⠀⠀⠀⠀⠀⠀⠀⣶⣶⣦⣄⠀⠀⠀⠘⣿⣿⣿⣶⣿⣿⣿⡇⠀⠀⠀⠀⠸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⢰⣷⣄⣹⣿⣿⣿⣷⡀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣽⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⣸⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⠛⡆⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⢰⠙⠛⠛⠛⠉⠀⠀⠀⠀⠀⣰⠃⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⡟⠁⠀⢳⡀⠀⠀⠀⠀⠈⠻⠿⣿⡿⠟⠁⠀⠀⢀⡾⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡃⠀⠀⠈⠻⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣾⠏⠀⠀⠀⠀⣳⣄⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⢀⠞⠣⣄⣀⡀⠀⣀⣀⠤⠖⠉⠀⠀⠀⠀⠀⠀⠙⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣾⠏⠀⠀⠀⠀⠀⠈⠀⠀⠈⠉⠻⢷⣦⡀⠀⠀⣀⡴⠋⠀⠀⠀⠀⠉⠉⠉⠀⠀⣠⡴⠆⠀⠀⠀⠀⠀⠀⠈⢿⣆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣶⡾⠷⠛⠛⠛⠛⠻⠿⠷⣶⣦⣤⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣆⠀⠀⠀⠀⠀⠀
⠀⢀⣀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣧⠀⣠⣦⡀⠀⠀⠀⣠⣿⣿⣿⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡆⠀⠀⠀⠀⠀
⣼⣿⠟⠻⠷⢾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢤⣄⣀⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣿⣿⣿⣿⣿⣷⣤⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⢹⣾⣿⣿⡿⣷⡆⠀
⢻⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⡿⠁
⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⠏⠀
⠀⠈⢿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀
⠀⠀⠈⢿⣳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀
⠀⠀⠀⠀⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀
⠀⠀⠀⠀⢼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⡟⠁⠀⠀⠙⠉⠉⠻⢿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀
⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠘⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠁⠀⠀⠀
⠀⠀⠀⠀⠀⢻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣏⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡟⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡝⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣼⠀⠀⠀⢀⡀⢀⣤⡀⣠⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢹⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣦⣠⠏⠁⠙⠛⢀⣼⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡏⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣶⣦⣤⡶⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣶⡟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠿⣷⡄⠀⠀⠀⠀⣤⣤⣤⣤⣤⣤⣴⣶⣾⡿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣷⡄⠀⠀⢀⣿⠉⢿⢿⣿⣿⣿⢿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠿⣶⣤⣾⠏⠀⠀⢿⣿⣿⡟⠋⠀⠀⠀⠀⠀⠀
*/
