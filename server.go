package main

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
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

var (
	dblog string
	key   *rsa.PrivateKey
	db    *gorm.DB
)

const (
	accessTokenExpiration  = time.Minute * 10
	refreshTokenExpiration = time.Hour * 2
)

// Получаем из env файла параметры для работы БД и ключик секретик
func init() {
	if err := godotenv.Load("go.env"); err != nil {
		panic(err)
	}
	dblog, _ = os.LookupEnv("dblog")
	key, _ = rsa.GenerateKey(rand.Reader, 2048)
	Migrate()
}

// aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
func main() {
	app := fiber.New()
	app.Static("/resources", "./resources", fiber.Static{CacheDuration: -1 * time.Second})
	app.Static("/", "./resources/html/MainPage.html")
	app.Static("/login", "./resources/html/LoginPage.html")
	app.Static("/register", "./resources/html/RegisterPage.html")
	app.Post("/login-user", LoginUser)
	app.Post("/register-user", RegisterUser)
	app.Get("/get-notes", GetNotes)
	app.Listen(":8080")
}

// Логинит юзера, возвращает мапу с status:wrong password/login если неправильные логин или пароль
// Если всё нормально, возвращает status:gut и токены, а также обновляет рефреш токен в бд
func LoginUser(c *fiber.Ctx) error {
	var user User
	err := json.Unmarshal(c.Body(), &user)
	if err != nil {
		panic(err)
	}
	status := CheckLoginAndPassword(user)
	if status == "gut" {
		access, refresh := GenerateTokensForUser(user.ID)
		PutRefreshToken(user.ID, refresh)
		return c.JSON(fiber.Map{"status": status, "accessToken": access, "refreshToken": refresh})
	}
	return c.JSON(fiber.Map{"status": status})
}

// Пытается зарегать пользователя, в случае, если логин занят, возвращает мапу в которой это указано
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

// Попытка вернуть список нотесов, сначала проверяет access токен на валидность и на срок годности, если невалиден - возвращает ошибку
// если истёк - проверяет рефреш токен, если он невалиден - возвращает ошибку, если истёк - возвращает ошибку(надо перезайти в аккаунт)
// если с рефрешем всё ок - создает новую пару токенов и возвращает список нотесов. если с аксессом всё ок - возвращает список нотесов
func GetNotes(c *fiber.Ctx) error {
	headers := c.GetReqHeaders()
	if len(headers["x-access-token"]) == 0 {
		return c.JSON(fiber.Map{"status": "Log in pls"})
	}
	accessToken := headers["x-access-token"][0]
	status := IsTokenValid(accessToken)
	switch status {
	case "Invalid token":
		return c.JSON(fiber.Map{"status": status})
	case "Expired token":
		refreshToken := headers["x-refresh-token"][0]
		refreshTokenStatus := IsTokenValid(refreshToken)
		switch refreshTokenStatus {
		case "Invalid token":
			return c.JSON(fiber.Map{"status": status})
		case "Expired token":
			return c.JSON(fiber.Map{"status": status})
			//заставить пользоватея перезаходить
		case "":
			id := GetUserIDFromToken(accessToken)
			access, refresh := GenerateTokensForUser(id)
			PutRefreshToken(id, refresh)
			notes := GetNotesFromDB(id)
			return c.JSON(fiber.Map{"status": "Success with tokens", "accessToken": access, "refreshToken": refresh, "notes": notes})
			//получить список нотесов из бд и вернуть вместе с новой парой токенов
		}
	case "":
		id := GetUserIDFromToken(accessToken)
		notes := GetNotesFromDB(id)
		return c.JSON(fiber.Map{"status": "Success", "notes": notes})
		//получить список нотесов из бд и вернуть
	}
	return c.JSON(fiber.Map{"status": "Чтото пошло не так. Сильно"})
}

// проверка токена на валидность и на срок годности, возвращает соответствующие статусы
func IsTokenValid(token string) string {
	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})
	if err != nil {
		panic(err)
	}
	if !parsedToken.Valid {
		return "Invalid token"
	}
	if claims["exp"].(time.Time).After(time.Now()) {
		return "Expired token"
	}
	return ""
}

// возвращает id пользователя на основе токена
func GetUserIDFromToken(token string) int {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})
	if err != nil {
		panic(err)
	}
	return claims["sub"].(int)
}

// получает по id список нотесов
func GetNotesFromDB(id int) []Note {
	notes := []Note{}
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	res, err := db.Query(fmt.Sprintf("select * from notes where user_id = %v", id))
	if err != nil {
		panic(err)
	}
	for res.Next() {
		note := Note{}
		res.Scan(note)
		notes = append(notes, note)
	}
	return notes
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
	var id int
	res.Scan(&id)
	log.Printf("New user's id: %v\n", id)
	return id
}

// Создаём токены для пользователя, возвращает access и refresh токены в виде string
// В access токене лежит user.ID
// В refresh токене лежит только дата смерти
func GenerateTokensForUser(userid int) (string, string) {
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenExpiration)),
		Subject:   strconv.Itoa(userid),
	}).SignedString(key)
	if err != nil {
		panic(err)
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenExpiration)),
	}).SignedString(key)
	if err != nil {
		panic(err)
	}
	return accessToken, refreshToken
}

// Обновляет рефреш токен пользователю
func PutRefreshToken(userid int, refreshToken string) {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	refresh := []byte(refreshToken)
	res, err := db.Exec(fmt.Sprintf("update users set refresh_token = '%v' where id = '%v'", refresh, userid))
	if err != nil {
		panic(err)
	}
	log.Println(res)
}

// Проверяет на существование логина, затем на соответствие логина и пароля
func CheckLoginAndPassword(user User) string {
	db, err := sql.Open("postgres", dblog)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if !IsLoginOccupied(user.Login) {
		return "Wrong login"
	}
	row := db.QueryRow(fmt.Sprintf("SELECT password FROM users where login = '%v' limit 1", user.Login))
	var password []byte
	row.Scan(&password)
	log.Println(password)
	log.Println(user.Password)
	err = bcrypt.CompareHashAndPassword(password, []byte(user.Password))
	log.Println(err)
	if err == nil {
		return "gut"
	}
	return "Wrong password"

}

// Проверяет, занят ли логин, возвращает true, если занят и false, если нет
func IsLoginOccupied(requestLogin string) bool {
	var user User
	db.First(&user, "login = ?", requestLogin)
	return user.Login != ""
}

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

/*⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⠤⠤⠤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡤⠾⠯⠷⢦⣄⣀⠀⠀⣠⠞⠋⠀⠀⠀⠀⠀⠈⠉⠹⢷⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡼⠋⠁⠀⠀⠀⠀⠀⠈⠉⠓⢾⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣠⣾⣧⠀⣸⣿⣦⠀⠀⠀⠀⠀⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
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
