[![Build Status](https://travis-ci.org/yageek/hhmac.svg?branch=master)](https://travis-ci.org/yageek/hhmac)
[![Coverage Status](https://coveralls.io/repos/github/yageek/hhmac/badge.svg?branch=master)](https://coveralls.io/github/yageek/hhmac?branch=master)
[![GoDoc](https://godoc.org/github.com/yageek/hhmac?status.png)](https://godoc.org/github.com/yageek/hhmac)  [![Report Cart](http://goreportcard.com/badge/yageek/hhmac)](http://goreportcard.com/report/yageek/hhmac)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)

# HMAC HTTP Authentication with Go

Simple HMAC authentication for Go. This has been inspired by  http://stackoverflow.com/questions/7802116/custom-http-authorization-header and http://www.thebuzzmedia.com/designing-a-secure-rest-api-without-oauth-authentication/.

# Installation

```
go get -v github.com/yageek/hhmac
```

# How it works

## Authenticaton Header

This authentication system use the `Authorization` HTTP header.
The format of the header should be the following:

```
Authorization: HHMAC key="0PN5J17HBGZHT7JJ3X82", hash="12345678abcdef", time="1234567"
```

## Secret provider

You have to implement a `SecretProvider` interface to retrieve the 
secret and the valid scopes for a specific user:

```
type MockProvider struct {
}

func (m *MockProvider) GetSecret(identifier string) (string, error) {
	return "MYSECRET", nil
}

func (m *MockProvider) GetScopes(identifier string) ([]string, error) {
	return []string{"scope1", "scope2"}, nil
}
```

## Validator

Then you can create a `Validator`:

```
v := NewValidator(30*time.Second, &MockProvider{}, crypto.SHA256.New)
```

Now, simply wrap the handler you want to protect using the `Auth` method.