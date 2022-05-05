// Package docs GENERATED BY SWAG; DO NOT EDIT
// This file was generated by swaggo/swag
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/adm/doot": {
            "get": {
                "summary": "Admin ming",
                "parameters": [
                    {
                        "type": "string",
                        "description": "JWT Cookie set by /admin",
                        "name": "jwt",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {}
            }
        },
        "/admin": {
            "post": {
                "description": "Secured login for any user accounts",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "User login",
                "parameters": [
                    {
                        "description": "email, password and 2FA code. 2FA code is required",
                        "name": "login",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/core.login"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "",
                        "headers": {
                            "jwt": {
                                "type": "string",
                                "description": "The authentication token for this session, valid for 24h"
                            }
                        }
                    },
                    "400": {
                        "description": "userkey, 2fa token or password missing"
                    },
                    "401": {
                        "description": "not found or credentials invalid"
                    }
                }
            }
        },
        "/doot": {
            "get": {
                "summary": "Unauthenticated Ping",
                "responses": {}
            }
        },
        "/forgot": {
            "post": {
                "description": "Request a password reset for the provided userkey",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Forgot password",
                "parameters": [
                    {
                        "description": "email to reset",
                        "name": "userkey",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/core.forgotten"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": ""
                    },
                    "400": {
                        "description": "userkey not provided"
                    }
                }
            }
        },
        "/login": {
            "post": {
                "description": "Secured login for any user accounts",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "User login",
                "parameters": [
                    {
                        "description": "Login information",
                        "name": "login",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/core.login"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "",
                        "headers": {
                            "jwt": {
                                "type": "string",
                                "description": "The authentication token for this session, valid for 24h"
                            }
                        }
                    },
                    "400": {
                        "description": "userkey or password missing"
                    },
                    "401": {
                        "description": "not found or credentials invalid"
                    }
                }
            }
        },
        "/reset": {
            "post": {
                "description": "Use a JWT token to validate and reset a password",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Password reset",
                "parameters": [
                    {
                        "description": "the reset token and the password",
                        "name": "reset",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/core.reset"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": ""
                    },
                    "400": {
                        "description": "token and password not provided"
                    },
                    "401": {
                        "description": "bad token or user not found"
                    }
                }
            }
        },
        "/sec/doot": {
            "get": {
                "summary": "User ping",
                "parameters": [
                    {
                        "type": "string",
                        "description": "JWT Cookie set by /login",
                        "name": "jwt",
                        "in": "header",
                        "required": true
                    }
                ],
                "responses": {}
            }
        },
        "/signup": {
            "post": {
                "description": "Sign a user up for a new account",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "User signup",
                "parameters": [
                    {
                        "description": "The signup information",
                        "name": "signup",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/core.signup"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": ""
                    },
                    "400": {
                        "description": "userkey missing, or password missing or not strong enough"
                    }
                }
            }
        },
        "/verify": {
            "post": {
                "description": "Email verification based on a token sent to a registered email",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "User verify",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Verification JWT",
                        "name": "verify",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": ""
                    },
                    "401": {
                        "description": "bad token"
                    }
                }
            }
        }
    },
    "definitions": {
        "core.forgotten": {
            "type": "object",
            "required": [
                "userkey"
            ],
            "properties": {
                "userkey": {
                    "type": "string"
                }
            }
        },
        "core.login": {
            "type": "object",
            "required": [
                "password",
                "userkey"
            ],
            "properties": {
                "password": {
                    "type": "string"
                },
                "twofactorcode": {
                    "type": "string"
                },
                "userkey": {
                    "type": "string"
                }
            }
        },
        "core.reset": {
            "type": "object",
            "required": [
                "password",
                "token"
            ],
            "properties": {
                "password": {
                    "type": "string"
                },
                "token": {
                    "type": "string"
                }
            }
        },
        "core.signup": {
            "type": "object",
            "required": [
                "password",
                "userkey"
            ],
            "properties": {
                "password": {
                    "type": "string"
                },
                "userkey": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1",
	Host:             "",
	BasePath:         "/v1",
	Schemes:          []string{},
	Title:            "Go-Gin Prepack",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
