package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// sign 生成 https://cloud.baidu.com/signature/index.html
func TestSign(t *testing.T) {
	ast := assert.New(t)
	a := NewAuth("84d0b59b18b947f6bb0b1bcea00969e3", "20e18679605f4efdbb3e64bfc0112a25")
	a.Expire = 1000000
	a.Header = map[string]string{
		"Host": "api-aifanfan.baidu.com",
	}
	a.Path = "/common/v1/acct/init"
	a.Time = "2006-01-02T15:04:05Z"
	signA := "bce-auth-v1/84d0b59b18b947f6bb0b1bcea00969e3/2006-01-02T15:04:05Z/1000000/host/8248bac9fc0bdcc4a009de272c0a00cdd8a96a2e6b0ddef60c52eab79f47f3b1"
	signB := a.Sign(Post)
	ast.EqualValues(signA, signB)

	a.QueryParam = map[string]string{
		"aa":            "123",
		"aaas":          "",
		"authorization": "123",
	}
	a.Header = map[string]string{
		"Host": "api-aifanfan.baidu.com",
	}
	signB = a.Sign(Post)
	signA = "bce-auth-v1/84d0b59b18b947f6bb0b1bcea00969e3/2006-01-02T15:04:05Z/1000000/host/a2cb0fe3552894c05ef2eaec4a7c6b4a3cd7f08baeea8efde5efc97f34b3ea55"
	ast.EqualValues(signA, signB)

	a.QueryParam = map[string]string{
		"aa":            "123",
		"aaas":          "",
		"authorization": "123",
	}
	a.Header = map[string]string{}
	a.Time = ""
	signB = a.Sign(Post)
	ast.EqualValues(signB, signB)
}

