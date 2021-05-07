# aff-sdk-go
用户可基于该SDK使用Go语言接入爱番番的产品

# Example
```go
package main

import (
	"fmt"
	"github.com/ado1ph/aff-sdk-go/auth"
)

func main() {
	a := auth.NewAuth("234","123")
	a.Expire = 1000000
	a.Header = map[string]string{
		"Host": "api-aifanfan.baidu.com",
	}
	a.Path = "/common/v1/acct/init"
	a.Time = "2006-01-02T15:04:05Z"

	sign := a.Sign(auth.Post)
	fmt.Print("the sign is %s", sign)
}
```
