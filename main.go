package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type product struct {
	Pid       uint32  `json:"id"` // Product id
	Name      string  `json:"name"`
	SellerUid uint32  `json:"selleruid"` // User id
	Desc      string  `json:"desc"`
	Price     float32 `json:"price"`
	//Image1    string  `json:"image1"` // Can be null
	//Image2    string  `json:"image2"`
	//Image3    string  `json:"image3"`
}

type user struct {
	Uid   uint32 `json:"uid"` // User id
	Uname string `json:"uname"`
	Pass  string `json:"pass"`
}

type cart struct {
	//	Cid uint32 `json:"cid"` // cart id
	Uid uint32 `json:"uid"` // user id
	Pid uint32 `json:"pid"` // product id
}

type conf struct {
	Port       uint16 `json:"port"`
	Userdb     string `json:"userdb"`
	Productdb  string `json:"productdb"`
	Commentdb  string `json:"commentdb"`
	Sessionsdb string `json:"sessionsdb"`
}

type save_err struct {
	Err       string `json:"err"`
	Date      string `json:"date"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	IP        string `json:"ip"`
	Useragent string `json:"user_agent"`
}

type error_log struct {
	Errs []save_err `json:"errs"`
}

type Comment struct {
	Comid    string
	Username string
	Date     string
	Comment  string
}

var (
	userdb     *sql.DB
	productdb  *sql.DB
	commentdb  *sql.DB
	sessionsdb *sql.DB

	chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	tpl *template.Template

	port uint16

	sessions = make(map[string]string)
)

func main() {
	err := INIT()
	if err != nil {
		log.Println(err.Error())
		LogError(err, nil)
		return
	}

	sessions["1"] = "test"
	sessions["2"] = "admin"

	defer userdb.Close()
	defer productdb.Close()

	println("Server started on port", port)
	if err = http.ListenAndServe(fmt.Sprintf(":%v", port), nil); err != nil {
		log.Println(err.Error())
		LogError(err, nil)
	}
}

func INIT() error {
	LogError(fmt.Errorf("server init started"), nil)

	var conff conf
	data, err := os.ReadFile("./conf.json")
	if err == nil {
		err = json.Unmarshal(data, &conff)
		if err != nil {
			return err
		}
		port = conff.Port
	} else {
		// Default settings
		if len(data) == 0 {
			conff.Port = 8088
			conff.Productdb = "product.db"
			conff.Userdb = "user.db"
			conff.Commentdb = "comment.db"
			conff.Sessionsdb = "sessions.db"
		}

		LogError(fmt.Errorf("default settings loaded"), nil)
	}

	userdb, err = sql.Open("sqlite3", "./"+conff.Userdb)
	if err != nil {
		return err
	}

	productdb, err = sql.Open("sqlite3", "./"+conff.Productdb)
	if err != nil {
		return err
	}

	commentdb, err = sql.Open("sqlite3", "./"+conff.Commentdb)
	if err != nil {
		return err
	}

	sessionsdb, err = sql.Open("sqlite3", "./"+conff.Sessionsdb)
	if err != nil {
		return err
	}

	tpl, err = template.ParseGlob("./tpls/*.html")
	if err != nil {
		return err
	}

	file, err := os.OpenFile("./logs.json", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	var b []byte
	b, err = ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		_, err = file.Seek(0, 0)
		if err != nil {

			return err
		}
		_, err = file.Write([]byte("{\n}"))
		if err != nil {

			return err
		}
	}

	// HTTP Handlers
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/register", register)
	http.HandleFunc("/search", search)
	http.HandleFunc("/products", products)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("GET /about", about)
	http.HandleFunc("POST /newproduct", newproduct)
	http.HandleFunc("POST /delproduct", delproduct)
	http.HandleFunc("GET /mycart", mycart)
	http.HandleFunc("POST /addcart", addcart)
	http.HandleFunc("POST /delcart", delcart)
	http.HandleFunc("GET /myaccount", myaccount)
	http.HandleFunc("GET /admin", admin)
	http.HandleFunc("POST /adduser", adduser)
	http.HandleFunc("POST /deluser", deluser)
	http.HandleFunc("POST /changepass", change_pass)
	http.HandleFunc("POST /make_comment", make_comment)
	http.HandleFunc("POST /del_comment", del_comment)
	http.HandleFunc("GET /detail", get_detailed_product)
	http.HandleFunc("GET /image", image)
	http.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile("./static/favicon.ico")
		if err != nil {
			w.Write(nil)
			return
		}

		w.Write(data)
	})
	http.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile("./static/robots.txt")
		if err != nil {
			w.Write(nil)
			return
		}

		w.Write(data)
	})
	http.HandleFunc("GET /sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile("./static/sitemap.xml")
		if err != nil {
			w.Write(nil)
			return
		}

		w.Write(data)
	})

	return nil
}

func index(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connections"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		cookie = &http.Cookie{}
	}

	uname := CheckCredentials(cookie.Value)

	prdct := getproduct(0)
	if prdct == nil {
		http.Error(w, "Failed to retrieve products", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
		Products []product
	}{
		Username: uname,
		Products: prdct,
	}

	tpl.ExecuteTemplate(w, "index.html", data)
}

func login(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connection/request"), r)

	if r.Method == http.MethodGet {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			tpl.ExecuteTemplate(w, "login.html", nil)
			return
		}
		_, ok := sessions[cookie.Value]
		if ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	} else if r.Method == http.MethodPost {

		r.ParseForm()

		uname := r.FormValue("uname")
		pass := r.FormValue("pass")

		if (uname == "" || pass == "") || (len(uname) > 255 || len(pass) > 255) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			log.Println("Username or Pass not shuld be not empty")
			LogError(fmt.Errorf("username or pass should not be empty"), r)

			return
		}

		// Get stored username and password
		stored_pass := ""
		row := userdb.QueryRow("SELECT pass FROM users WHERE uname = ?", uname)

		err := row.Scan(&stored_pass)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				log.Println("Username not found")
				LogError(fmt.Errorf("username not found"), r)

				return
			}
		}

		// Check these are valid ?
		inputHash := hash(pass)
		if stored_pass != inputHash {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			log.Println("Passwords are not match")
			LogError(fmt.Errorf("passwords are not match"), r)

			return
		} // else these are valid

		sessionid, err := GenNewUID()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			log.Println("Random string generaton failed: ", err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: sessionid,
		})

		// OK Username
		sessions[sessionid] = uname
		LogError(fmt.Errorf("user %v logged in", uname), r)

		http.Redirect(w, r, "/index", http.StatusSeeOther)
	} else {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		LogError(fmt.Errorf("method not allowed"), r)

		return
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connection/request"), r)

	if r.Method == http.MethodGet {
		cookie, err := r.Cookie("session")
		if err != nil {
			tpl.ExecuteTemplate(w, "register.html", nil)
			return
		}
		_, ok := sessions[cookie.Value]
		if ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	} else if r.Method == http.MethodPost {

		r.ParseForm()

		uname := r.FormValue("uname")
		pass := r.FormValue("pass")

		if (uname == "" || pass == "") || (len(uname) > 255 || len(pass) > 255) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			log.Println("Username or Pass shoudnt empty")
			LogError(fmt.Errorf("username or pass shoudnt empty"), r)

			return
		}

		// Check is username already registered?
		var count int
		row := userdb.QueryRow("SELECT COUNT(*) FROM users WHERE uname = ?", uname)
		err := row.Scan(&count)
		if err != nil || count != 0 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			log.Println("Username already registered")
			LogError(fmt.Errorf("username already registered"), r)

			return
		} // ELSE

		// Register user
		hashedPass := hash(pass)
		_, err = userdb.Exec("INSERT INTO users (uname, pass) VALUES (?, ?)", uname, hashedPass)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			log.Println(err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

			return
		}

		// Add session id
		sessionid, err := GenNewUID()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			log.Println(err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: sessionid,
		})

		sessions[sessionid] = uname
		LogError(fmt.Errorf("%v registered", uname), r)

	} else {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		LogError(fmt.Errorf("method not allowed"), r)

		return
	}
}

func about(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connetion"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		tpl.ExecuteTemplate(w, "about.html", nil)
		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		tpl.ExecuteTemplate(w, "about.html", nil)
		return
	}

	tpl.ExecuteTemplate(w, "about.html", uname)
}

func logout(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Delete current cookie
	delete(sessions, cookie.Value)

	// Add here "delete session/cookie value from database"

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})

	LogError(fmt.Errorf("user %v logged out", uname), r)
	http.Redirect(w, r, "/index", http.StatusSeeOther)
}

func hash(pass string) string {
	hash := sha256.Sum256([]byte(pass))
	return hex.EncodeToString(hash[:])
}

func search(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connection/request"), r)

	if r.Method == http.MethodGet {
		tpl.ExecuteTemplate(w, "search.html", nil)
	} else if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		keywords := r.FormValue("keywords")
		if keywords == "" {
			http.Error(w, "Minimum enter 1 keyword", http.StatusBadRequest)
			return
		}

		rows, err := productdb.Query("SELECT id, name, selleruid, desc, price FROM products WHERE name LIKE ?", "%"+keywords+"%")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var products []product

		for rows.Next() {
			var p product
			err = rows.Scan(&p.Pid, &p.Name, &p.SellerUid, &p.Desc, &p.Price)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			products = append(products, p)
		}

		tpl.ExecuteTemplate(w, "search.html", products)
	} else {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func get_detailed_product(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	r.ParseForm()

	pid := r.URL.Query().Get("pid") // /detail?pid=12
	if pid == "" {
		http.Error(w, "please enter a pid", http.StatusBadRequest)
		LogError(fmt.Errorf("please enter a pid"), r)
		return
	}

	pidInt, err := strconv.Atoi(pid)
	if err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		LogError(fmt.Errorf("invalid pid"), r)
		return
	}

	var pr product
	pr.Pid = uint32(pidInt)

	row := productdb.QueryRow("SELECT name, selleruid, desc, price FROM products WHERE id = ?", pidInt)
	if err = row.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError(err, r)
		return
	}

	err = row.Scan(&pr.Name, &pr.SellerUid, &pr.Desc, &pr.Price)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "product not found", http.StatusNotFound)
			LogError(fmt.Errorf("product not found"), r)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			LogError(err, r)
		}
		return
	}
	pr.Pid = uint32(pidInt)

	var comments []Comment
	rows, err := commentdb.Query("SELECT comid, uname, cdate, comment FROM comments WHERE pid = ?", pidInt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError(err, r)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var c Comment
		err := rows.Scan(&c.Comid, &c.Username, &c.Date, &c.Comment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			LogError(err, r)
			return
		}
		comments = append(comments, c)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError(err, r)
		return
	}

	data := struct {
		Product  product
		Comments []Comment
	}{
		Product:  pr,
		Comments: comments,
	}

	if err := tpl.ExecuteTemplate(w, "detail_product.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError(err, r)
		return
	}
}

func make_comment(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	r.ParseForm()
	pid := r.FormValue("pid")
	comment := r.FormValue("comment")
	cookie, err := r.Cookie("session")
	if err != nil {
		cookie = nil
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		uname = "Anonymous"
	}

	_, err = commentdb.Exec("INSERT INTO comments (pid, uname, cdate, comment) VALUES (?,?,?,?);",
		pid, uname, time.Now().Format("2006-01-02 15:04:05"), comment,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError(err, r)
		return
	}

	fmt.Fprint(w, "<script>history.back();</script>")
}

func getproduct(offset int32) []product {
	rows, err := productdb.Query("SELECT * FROM products ORDER BY RANDOM() LIMIT 9 OFFSET $1", offset)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var products []product
	for rows.Next() {
		var p product
		err := rows.Scan(&p.Pid, &p.Name, &p.SellerUid, &p.Desc, &p.Price)
		if err != nil {
			return nil
		}
		products = append(products, p)
	}

	// Check for any errors after scanning all rows
	if err := rows.Err(); err != nil {
		return nil
	}

	return products
}

func products(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connections"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get user id from users database
	var uid uint32
	row := userdb.QueryRow("SELECT uid FROM users WHERE uname = ?", uname)
	err = row.Scan(&uid)
	if err != nil {
		http.Error(w, "Failed to retrieve user ID", http.StatusInternalServerError)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

		return
	}

	rows, err := productdb.Query("SELECT * FROM products WHERE selleruid = ?", uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

		return
	}
	defer rows.Close()

	var products []product
	for rows.Next() {
		var p product
		err = rows.Scan(&p.Pid, &p.Name, &p.SellerUid, &p.Desc, &p.Price)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

			return
		}

		products = append(products, p)
	}

	err = tpl.ExecuteTemplate(w, "products.html", products)
	if err != nil {
		log.Println(err)
		http.Error(w, "Failed to execute template", http.StatusInternalServerError)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)

		return
	}
}

func newproduct(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	// Parse form data
	err := r.ParseMultipartForm(10 << 20) // Limit upload size to 10MB
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	// Retrieve session cookie
	cookie, err := r.Cookie("session")
	uname, ok := sessions[cookie.Value]
	if err != nil || !ok || uname == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get form values
	pname := r.FormValue("pname")
	desc := r.FormValue("desc")
	priceStr := r.FormValue("price")
	file, handler, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Image upload failed", http.StatusBadRequest)
		LogError(fmt.Errorf("image upload failed"), r)
		return
	}
	defer file.Close()

	if pname == "" || desc == "" || priceStr == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		LogError(fmt.Errorf("all fields are required"), r)
		return
	}

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		http.Error(w, "Invalid price format", http.StatusBadRequest)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	// Get user ID
	var uid uint32
	err = userdb.QueryRow("SELECT uid FROM users WHERE uname = ?", uname).Scan(&uid)
	if err != nil {
		http.Error(w, "Failed to retrieve user ID", http.StatusInternalServerError)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	println(handler.Filename)

	// Insert product into database
	_, err = productdb.Exec("INSERT INTO products (name, selleruid, `desc`, price) VALUES (?, ?, ?, ?)", pname, uid, desc, price)
	if err != nil {
		http.Error(w, "Failed to add product", http.StatusInternalServerError)
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	var pid uint32
	row := productdb.QueryRow("SELECT id FROM products WHERE selleruid = ? AND name = ?", uid, pname)
	row.Scan(&pid)

	// Save the image to the "images" directory
	imagePath := fmt.Sprintf("./images/%v.png", pid)
	dst, err := os.Create(imagePath)
	if err != nil {
		http.Error(w, "Failed to save image", http.StatusInternalServerError)
		LogError(fmt.Errorf("failed to save image"), r)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to save image", http.StatusInternalServerError)
		LogError(fmt.Errorf("failed to save image"), r)
		return
	}

	http.Redirect(w, r, "/products", http.StatusSeeOther)
	LogError(fmt.Errorf("product name: %v added", pname), r)
}

func delproduct(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	// Retrieve session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		log.Println("Error retrieving session cookie:", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		LogError(fmt.Errorf(strings.ToLower(http.StatusText(http.StatusUnauthorized))), r)

		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		log.Println("Invalid session or username")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		LogError(fmt.Errorf(strings.ToLower(http.StatusText(http.StatusUnauthorized))), r)

		return
	}

	// Retrieve product ID from form value
	pid := r.FormValue("pid")
	log.Println("Product ID:", pid)
	if pid == "" {
		http.Error(w, "Product ID is required", http.StatusBadRequest)
		LogError(fmt.Errorf(strings.ToLower("product id is requied")), r)

		return
	}

	// Convert product ID to int32
	pidInt, err := strconv.ParseInt(pid, 10, 32)
	if err != nil {
		log.Println("Error parsing product ID:", err)
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		LogError(fmt.Errorf("invalid product id"), r)

		return
	}

	{ // FOR SECURITY
		// Verify product ownership if user not admin
		if uname != "admin" {
			// Get user ID
			var uid uint32
			err = userdb.QueryRow("SELECT uid FROM users WHERE uname = ?", uname).Scan(&uid)
			if err != nil {
				log.Println("Error retrieving user ID:", err)
				http.Error(w, "Failed to retrieve user ID", http.StatusInternalServerError)
				LogError(fmt.Errorf("failed to retrieve user id"), r)

				return
			}
			log.Println("User ID:", uid)

			var sellerUid uint32
			err = productdb.QueryRow("SELECT selleruid FROM products WHERE id = ?", pidInt).Scan(&sellerUid)
			if err != nil {
				log.Println("Error retrieving seller UID:", err)
				if err == sql.ErrNoRows {
					log.Println("Product not found")
				}

				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				LogError(fmt.Errorf(strings.ToLower(http.StatusText(http.StatusNotFound))), r)

				return
			}
			log.Println("Seller UID:", sellerUid)

			if sellerUid != uid {
				log.Println("Product ownership mismatch")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				LogError(fmt.Errorf(strings.ToLower(http.StatusText(http.StatusForbidden))), r)

				return
			}
		}

		// Delete product
		_, err = productdb.Exec("DELETE FROM products WHERE id = ?", pidInt)
		if err != nil {
			log.Println("Error deleting product:", err)
			http.Error(w, "Failed to delete product", http.StatusInternalServerError)
			LogError(fmt.Errorf("failed to delete product"), r)

			return
		}
		log.Println("Product deleted successfully")
	}

	if uname == "admin" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/products", http.StatusSeeOther)

	LogError(fmt.Errorf("product uid: %v deleted", pid), r)
}

func mycart(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connection"), r)

	// Get session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	// Get user ID from session
	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		http.Error(w, "Session not found", http.StatusBadRequest)
		log.Println("Session not found")
		return
	}

	var uid int32
	row := userdb.QueryRow("SELECT uid FROM users WHERE uname = ?", uname)
	if err = row.Scan(&uid); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			log.Println("User not found")
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	// Get cart items from database
	rows, err := userdb.Query("SELECT product_id FROM cart WHERE user_id = ?", uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}
	defer rows.Close()

	// Create a slice to hold cart items
	var ucart []cart
	for rows.Next() {
		var c cart
		if err = rows.Scan(&c.Pid); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println(err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
			return
		}
		ucart = append(ucart, c)
	}

	if err = rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	// Create a slice to hold products
	var prod []product
	for _, c := range ucart {
		var p product
		row := productdb.QueryRow("SELECT name, selleruid, desc, price FROM products WHERE id = ?", c.Pid)

		if err = row.Scan(&p.Name, &p.SellerUid, &p.Desc, &p.Price); err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Product with ID %d not found\n", c.Pid)
				continue // Skip this product and move to the next
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println(err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
			return
		}
		p.Pid = c.Pid
		prod = append(prod, p)
	}

	// Execute template
	if err = tpl.ExecuteTemplate(w, "mycart.html", prod); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}
}

func addcart(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		log.Printf("Error getting cookie: %v", err)
		LogError(fmt.Errorf("error getting cookie"), r)
		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		http.Error(w, "Cookie not found", http.StatusInternalServerError)
		log.Println("Cookie not found")
		LogError(fmt.Errorf("cookie not found"), r)
		return
	}

	r.ParseForm()

	// Product id
	pid := r.FormValue("pid")

	// Check if this product exists [if reaches this code block exist]
	var productID int32
	if err = productdb.QueryRow("SELECT id FROM products WHERE id = ?", pid).Scan(&productID); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Product not found", http.StatusNotFound)
			log.Printf("Product not found: %s", pid)
			LogError(fmt.Errorf("product not found"), r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error checking product: %v", err)
		LogError(fmt.Errorf("error checking product"), r)
		return
	}

	// Get uid
	var uid int32
	if err = userdb.QueryRow("SELECT uid FROM users WHERE uname = ?", uname).Scan(&uid); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			log.Printf("User not found: %s", uname)
			LogError(fmt.Errorf("user not found: %s", uname), r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error getting user ID: %v", err)
		LogError(fmt.Errorf("error getting user id"), r)
		return
	}

	// Check if product is already in cart
	var count int32
	if err = userdb.QueryRow("SELECT COUNT(*) FROM cart WHERE user_id = ? AND product_id = ?", uid, productID).Scan(&count); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error checking cart: %v", err)
		LogError(fmt.Errorf("error checking cart"), r)
		return
	}
	if count > 0 {
		http.Error(w, "Product already in cart", http.StatusConflict)
		log.Printf("Product already in cart: %s", pid)
		LogError(fmt.Errorf("product already in cart"), r)
		return
	}

	// Add to database
	_, err = userdb.Exec("INSERT INTO cart (user_id, product_id) VALUES (?, ?)", uid, productID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error adding to cart: %v", err)
		LogError(fmt.Errorf("error adding to cart"), r)
		return
	}

	http.Redirect(w, r, "/mycart", http.StatusSeeOther)

	LogError(fmt.Errorf("pid: %v added to user cart: %v", pid, uname), r)
}

func delcart(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Printf("Error getting cookie: %v", err)
		LogError(fmt.Errorf("error getting cookie"), r)
		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" {
		http.Error(w, "Cookie not found", http.StatusInternalServerError)
		log.Println("Cookie not found")
		LogError(fmt.Errorf("cookie not found"), r)
		return
	}

	r.ParseForm()

	// Product id
	pid := r.FormValue("pid")

	// Check if this product exists
	var productID int32
	if err = productdb.QueryRow("SELECT id FROM products WHERE id = ?", pid).Scan(&productID); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Product not found", http.StatusNotFound)
			log.Printf("Product not found: %s", pid)
			LogError(fmt.Errorf("product not found"), r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error checking product: %v", err)
		LogError(fmt.Errorf("error checking product"), r)
		return
	}

	// Get uid
	var uid int32
	if err = userdb.QueryRow("SELECT uid FROM users WHERE uname = ?", uname).Scan(&uid); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			log.Printf("User not found: %s", uname)
			LogError(fmt.Errorf("user not found"), r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error getting user ID: %v", err)
		LogError(fmt.Errorf("error gettinf user id"), r)
		return
	}

	// Check if product is in cart
	var count int32
	if err = userdb.QueryRow("SELECT COUNT(*) FROM cart WHERE user_id = ? AND product_id = ?", uid, productID).Scan(&count); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error checking cart: %v", err)
		LogError(fmt.Errorf("checking cart"), r)
		return
	}
	if count == 0 {
		http.Error(w, "Product not in cart", http.StatusNotFound)
		log.Printf("Product not in cart: %s", pid)
		LogError(fmt.Errorf("product not in cart"), r)
		return
	}

	// Delete from database
	_, err = userdb.Exec("DELETE FROM cart WHERE user_id = ? AND product_id = ?", uid, productID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error deleting from cart: %v", err)
		LogError(fmt.Errorf("error deleting from cart"), r)
		return
	}

	http.Redirect(w, r, "/mycart", http.StatusSeeOther)

	LogError(fmt.Errorf("pid: %v deleted from user cart: %v", pid, uname), r)
}

func myaccount(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connection"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		log.Println(http.StatusText(http.StatusUnauthorized))
		LogError(fmt.Errorf(http.StatusText(http.StatusUnauthorized)), r)
		return
	}

	uname := CheckCredentials(cookie.Value)
	if uname == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		log.Println(http.StatusText(http.StatusUnauthorized))
		LogError(fmt.Errorf(http.StatusText(http.StatusUnauthorized)), r)
		return
	}

	tpl.ExecuteTemplate(w, "myaccount.html", uname)
}

func CheckChars(file string) string {
	for i := 0; i < len(file); i++ {
		if file[i] >= 'A' || file[i] <= 'Z' || file[i] >= 'a' || file[i] <= 'z' || file[i] >= '0' || file[i] <= '9' {
			continue
		}
		return ""
	}

	return file
}

func image(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new conntection"), r)

	file := r.URL.Query().Get("file")

	// Block path traversal
	file = CheckChars(file)

	if file == "" {
		// If no ID is found, return a 404 error
		LogError(fmt.Errorf("file not found in url"), r)
		http.Error(w, "file not found in URL", http.StatusBadRequest)
		return
	}

	// Construct the file path
	filePath := filepath.Join("./images", file)

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		// If the file cannot be read, return a 404 error
		log.Println(err.Error())
		LogError(err, r)
		http.Error(w, "Image not found", http.StatusNotFound)
		return
	}

	// Set the Content-Type header
	w.Header().Set("Content-Type", "image/png")
	w.Write(data)
}

func LogError(err error, r *http.Request) {
	var errorLog error_log

	// Check if the file exists
	_, errStat := os.Stat("./logs.json")
	if errStat == nil {
		// If the file exists, read the existing data
		data, err := os.ReadFile("./logs.json")
		if err != nil {
			log.Println(err.Error())
			return
		}
		err = json.Unmarshal(data, &errorLog)
		if err != nil {
			log.Println(err.Error())
			return
		}
	} else if !os.IsNotExist(errStat) {
		log.Println(errStat.Error())
		return
	}

	// Create a new error
	var er save_err
	if r != nil {
		er.Err = err.Error()
		er.Date = time.Now().Format("2006-01-02 15:04:05.000")
		er.Path = r.URL.Path
		er.Method = r.Method
		er.IP = r.RemoteAddr
		er.Useragent = r.UserAgent()
	} else {
		er.Err = err.Error()
		er.Date = time.Now().Format("2006-01-02 15:04:05.000")
		er.Useragent = "[SERVER]"
	}

	// Append the new error to the existing data
	errorLog.Errs = append(errorLog.Errs, er)

	// Write the updated data to the file
	jsonData, err := json.MarshalIndent(errorLog, "", "\t")
	if err != nil {
		log.Println(err.Error())
		return
	}
	err = os.WriteFile("./logs.json", jsonData, 0644)
	if err != nil {
		log.Println(err.Error())
		return
	}
}

/////////////////////Admin functions///////////////////

func admin(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new connection"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		http.Error(w, http.StatusText(404), 404)
		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" || uname != "admin" {
		http.Error(w, http.StatusText(404), 404)
		return
	}

	rows, err := userdb.Query("SELECT * FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	var users []user
	for rows.Next() {
		var u user
		if err = rows.Scan(&u.Uid, &u.Uname, &u.Pass); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			log.Println(err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
			return
		}

		if u.Uname == "admin" {
			continue
		}

		users = append(users, u)
	}

	/////////////////////////////////////////////

	rows, err = productdb.Query("SELECT * FROM products")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	var products []product
	for rows.Next() {
		var p product
		if err = rows.Scan(&p.Pid, &p.Name, &p.SellerUid, &p.Desc, &p.Price); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			log.Println(err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
			return
		}

		products = append(products, p)
	}

	data := struct {
		Users    []user
		Products []product
	}{
		Users:    users,
		Products: products,
	}

	tpl.ExecuteTemplate(w, "admin.html", data)
}

func adduser(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" || uname != "admin" {
		http.Error(w, "Session not found or you are not admin", http.StatusBadRequest)
		log.Println("Session not found or you are not admin")
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	r.ParseForm()

	new_uname := r.FormValue("uname")
	new_pass := hash(r.FormValue("pass"))
	if new_pass == "" || new_uname == "" {
		http.Error(w, "You can't empty the textbox'es", http.StatusBadRequest)
		log.Println("You can't empty the textbox'es")
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	_, err = userdb.Exec("INSERT INTO users (uname, pass) VALUES (?, ?);", new_uname, new_pass)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)

	LogError(fmt.Errorf("admin added user: %v", new_uname), r)
}

func deluser(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err.Error())
		LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" || uname != "admin" {
		http.Error(w, "Session not found or you are not admin", http.StatusUnauthorized)
		log.Println("Session not found or you are not admin")
		LogError(fmt.Errorf("session not found or you are not admin"), r)
		return
	}

	r.ParseForm()
	uid := r.FormValue("uid")
	if uid == "" {
		http.Error(w, "You can't make empty uid value", http.StatusBadRequest)
		log.Println("Empty uid value")
		LogError(fmt.Errorf("empty uid value"), r)
		return
	}

	_, err = userdb.Exec("DELETE FROM users WHERE uid = ?", uid)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			log.Println("User not found")
			LogError(fmt.Errorf("user not found"), r)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println(err.Error())
			LogError(fmt.Errorf(strings.ToLower(err.Error())), r)
		}
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)

	LogError(fmt.Errorf("admin deleted user uid: %v", uid), r)
}

func change_pass(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		log.Println("Error getting session cookie: ", err)
		LogError(fmt.Errorf("error getting session cookie"), r)
		return
	}

	uname, ok := sessions[cookie.Value]
	if !ok || uname == "" || uname != "admin" {
		http.Error(w, "Session not found or you are not admin", http.StatusUnauthorized)
		log.Println("Invalid session or not admin")
		LogError(fmt.Errorf("invalid session or not admin"), r)
		return
	}

	r.ParseForm()
	uid := r.FormValue("uid")
	pass := hash(r.FormValue("pass"))
	if uid == "" || pass == "" {
		http.Error(w, "You can't make empty uid or pass value", http.StatusBadRequest)
		log.Println("Empty uid or pass value")
		LogError(fmt.Errorf("empty uid or pass value"), r)
		return
	}

	// Check if the user exists
	var exists bool
	err = userdb.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE uid = ?)", uid).Scan(&exists)
	if err != nil {
		http.Error(w, "Error checking user existence", http.StatusInternalServerError)
		log.Println("Error checking user existence: ", err)
		LogError(fmt.Errorf("error checking user existence"), r)
		return
	}
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		log.Println("User not found")
		LogError(fmt.Errorf("user not found"), r)
		return
	}

	// Update the password
	_, err = userdb.Exec("UPDATE users SET pass = ? WHERE uid = ?", pass, uid)
	if err != nil {
		http.Error(w, "Error updating password", http.StatusInternalServerError)
		log.Println("Error updating password: ", err)
		LogError(fmt.Errorf("error updating password"), r)
		return
	}

	// Provide feedback to the user
	http.Redirect(w, r, "/admin", http.StatusSeeOther)

	LogError(fmt.Errorf("admin changed user password uid: %v", uid), r)
}

func del_comment(w http.ResponseWriter, r *http.Request) {
	LogError(fmt.Errorf("new request"), r)

	r.ParseForm()

	comid := r.FormValue("comid")

	cookie, err := r.Cookie("session")
	uname, ok := sessions[cookie.Value]

	if !ok || err != nil || uname == "" || uname != "admin" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		LogError(fmt.Errorf("redirected to /login"), r)
		return
	}

	_, err = commentdb.Exec("DELETE FROM comments WHERE comid = ?", comid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError(err, r)
		return
	}

	fmt.Fprint(w, "<script>history.back();</script>")
}

///////////////////////////////////////////////////////

func GenNewUID() (string, error) {
	var sessionID string
	for i := 0; i < 32; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		sessionID += string(chars[idx.Int64()])
	}
	return sessionID, nil
}

func CheckCredentials(sid string) string {
	uname, ok := sessions[sid]
	if !ok || uname == "" {
		return ""
	}
	return uname
}
