# go-login

[![license](https://img.shields.io/github/license/reddec/go-login.svg)](https://github.com/reddec/go-login)
[![](https://godoc.org/github.com/reddec/go-login?status.svg)](http://godoc.org/github.com/reddec/go-login)

Go handler for login pages with configurable fields.

- Zero-dependencies
- Type-safe configuration (Go generics)
- CSRF protection by-default
- Works well with any HTTP frameworks
- Default minimalistic, mobile-friendly login page


Example


```go
package main

import (
	"fmt"
	"log"
	"net/http"

	login "githun.com/reddec/go-login"
)

func loginFunc(writer http.ResponseWriter, r *http.Request, cred login.UserPassword) error {
	ok := cred.User == "admin" && cred.Password == "admin" // user proper login and validation
	if !ok {
		return fmt.Errorf("username or password is incorrect")
	}
	// use sessions/JWT/cookies and mark following requests as authorized
	return nil
}

func main() {
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("<html><body><h1>Home</h1><br/><a href='/login'>Login</a></body></html>"))
	})
	http.Handle("/login", login.New[login.UserPassword](loginFunc, login.Log(func(err error) {
		log.Println(err)
	})))
	panic(http.ListenAndServe("127.0.0.1:8080", nil))
}
```

<img width="407" alt="image" src="https://user-images.githubusercontent.com/6597086/212119984-bee69f07-c4ba-46f4-9186-c022f25506bf.png">



## Custom form

Use annotations on string fields:

- `title` for form labels
- `placeholder` for input placeholders
- `hidden` to mark input as hidden (password)

```go
type DomainLogin struct {
	Domain   string `title:"Domain name" placeholder:"domain or company"`
	User     string `title:"Username" placeholder:"enter username"`
	Password string `title:"Password" placeholder:"enter password" hidden:"true"`
}

```

and handle it as normal

```go

func loginFunc(writer http.ResponseWriter, r *http.Request, cred DomainLogin) error {
	// ...
	return nil
}

func main() {
	// ...
	http.Handle("/login", login.New[DomainLogin](loginFunc))
}

```
