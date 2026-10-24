package validator

import "fmt"

func ExampleV_Domain() {
	v := New(&Config{Log: func(string, ...any) {}})
	fmt.Println(v.Domain("example.com"), v.Domain("not a domain"))
	// Output: true false
}

func ExampleV_GetBase() {
	v := New(&Config{})
	fmt.Println(v.GetBase("mail.example.co.uk"))
	// Output: example.co.uk
}
