package main

import (
	"crypto/ecdsa"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lechgu/jwks/internal/keys"
)

func main() {
	km, err := keys.NewKeyManager()
	if err != nil {
		log.Fatalln(err)
	}
	gin.SetMode("release")
	r := gin.Default()
	r.GET("/", func(ctx *gin.Context) {
		handleJwks(ctx, km)
	})
	r.GET("/jwt/", func(ctx *gin.Context) {
		handleJwt(ctx, km)
	})
	r.GET("/v1/token/", func(ctx *gin.Context) {
		handleSaladJwt(ctx, km)
	})

	r.Run()
}

func handleJwks(ctx *gin.Context, km *keys.KeyManager) {
	ctx.JSON(http.StatusOK, km.Jwks)
}

func handleJwt(ctx *gin.Context, km *keys.KeyManager) {
	kid := ctx.Query("kid")
	if kid == "" {
		ctx.String(http.StatusBadRequest, "kid must be specified")
		return
	}
	pk, ok := km.Cache[kid]
	if !ok {
		ctx.String(http.StatusBadRequest, "invalid kid")
	}
	iat := time.Now().UTC().Unix()
	exp := time.Now().AddDate(1, 0, 0).UTC().Unix()
	sub := ctx.Query("sub")
	if sub == "" {
		sub = uuid.NewString()
	}
	jti := uuid.NewString()
	sOid := ctx.Query("s_oid")
	if sOid == "" {
		sOid = uuid.NewString()
	}
	sMid := ctx.Query("s_mid")
	if sMid == "" {
		sMid = uuid.NewString()
	}
	sWid := ctx.Query("s_wid")
	if sWid == "" {
		sWid = uuid.NewString()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat":   iat,
		"exp":   exp,
		"iss":   "https://matrix-api.salad.io",
		"aud":   "https://matrix-api.salad.io",
		"jti":   jti,
		"sub":   sub,
		"s_oid": sOid,
		"s_mid": sMid,
		"s_wid": sWid,
	})
	token.Header["kid"] = kid
	signedToken, err := token.SignedString(pk)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}
	ctx.String(http.StatusOK, signedToken)
}

type TokenResponse struct {
	JWT string `json:"jwt"`
}

func handleSaladJwt(ctx *gin.Context, km *keys.KeyManager) {
	now := time.Now().UTC().Unix()
	saladMachineID := uuid.NewString()
	iat := now
	nbf := now
	exp := time.Now().AddDate(1, 0, 0).UTC().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":              saladMachineID,
		"iss":              "https://matrix-api.salad.io",
		"aud":              "https://matrix-api.salad.io",
		"iat":              iat,
		"nbf":              nbf,
		"exp":              exp,
		"salad_machine_id": saladMachineID,
	})
	var kid string
	var pk *ecdsa.PrivateKey
	for k, v := range km.Cache {
		kid = k
		pk = v
		break
	}
	token.Header["kid"] = kid
	signedToken, err := token.SignedString(pk)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}
	response := TokenResponse{
		JWT: signedToken,
	}
	ctx.JSON(http.StatusOK, response)

}
