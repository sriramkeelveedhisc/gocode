package hello

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/appengine"

	"cloud.google.com/go/storage"
	"github.com/dgrijalva/jwt-go"
)

const (
	rsaKeySize = 2048
	bucketName = "lightweight-client-auth.appspot.com"
)

func init() {
	http.HandleFunc("/", handler2)
}

func handler2(w http.ResponseWriter, r *http.Request) {
	if err := installKey("test@account.com", w, r); err != nil {
		s := fmt.Sprintf("Failure :(\n%s", err)
		fmt.Fprint(w, s)
	} else {
		fmt.Fprint(w, "Success!")
	}
}

func installKey(account string, w http.ResponseWriter, r *http.Request) error {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return err
	}

	pub := priv.PublicKey
	h := sha256.New()
	h.Write([]byte("test"))
	hash := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash)
	if err != nil {
		return err
	}
	pkb, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	pub2, err := x509.ParsePKIXPublicKey(pkb)
	if err != nil {
		return err
	}
	rsaPub, ok := pub2.(*rsa.PublicKey)
	if !ok {
		return errors.New("Value returned from ParsePKIXPublicKey was not an RSA public key")
	}

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash, sig)
	if err == nil {
		fmt.Fprint(w, "Verification passed")
	} else {
		fmt.Fprint(w, "Verification failed")

	}
	return updateRegistry("test", "test", w, r)
}

// RegistryEntry is a struct to represent a (key, account) pair in the registry.
type RegistryEntry struct {
	Key     string `json:"key"`
	Account string `json:"account"`
}

func updateRegistry(account string, pub crypto.PublicKey, w http.ResponseWriter, rz *http.Request) error {
	//ctx := context.Background(rz)
	ctx := appengine.NewContext(rz)
	client, err := storage.NewClient(ctx)
	if err != nil {
		return err
	}
	registry := client.Bucket(bucketName).Object("registry")
	r, err := registry.NewReader(ctx)
	if err != nil {
		return err
	}
	contents := new(bytes.Buffer)
	if _, err = contents.ReadFrom(r); err != nil {
		return err
	}
	var entries []RegistryEntry
	if err = json.Unmarshal(contents.Bytes(), &entries); err != nil {
		return err
	}
	fmt.Fprint(w, entries)
	ePub := "testpub" //base64.StdEncoding.EncodeToString([]byte(pub))
	newEntry := RegistryEntry{Key: ePub, Account: account}
	entries = append(entries, newEntry)
	fmt.Fprint(w, entries)
	newData, err := json.Marshal(entries)
	fmt.Fprint(w, newData)
	if err != nil {
		return err
	}
	wr := registry.NewWriter(ctx)
	if _, err := fmt.Fprintf(wr, string(newData)); err != nil {
		return err
	}
	if err := wr.Close(); err != nil {
		return err
	}

	return nil

	/*			// Insert an object into a bucket.
				object := &storage.Object{Name: objectName}
				file, err := os.Open(*fileName)
				if err != nil {
								fatalf(service, "Error opening %q: %v", *fileName, err)
				}
				if res, err := service.Objects.Insert(*bucketName, object).Media(file).Do(); err == nil {
								fmt.Printf("Created object %v at location %v\n\n", res.Name, res.SelfLink)
				} else {
								fatalf(service, "Objects.Insert failed: %v", err)
				}*/

	/*"lightweight-client-auth.appspot.com"
	data, err := json.Marshal(newEntry)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	entries := append(entries, newEntry)
	newData, err := json.Marshal(entries)
	if err != nil {
		return err
	}*/
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hola!")
	privKB64 := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBdVlac1ZjbnBFMG9US0xkdjgwNGdFWXhOWDZhZGVFT0VucFZESkVDUjcxTGhDRkFuCjZvdk8wZEVOYXY5YVpTdEYyc3h1am1XVnBmYXJQeXpKVFJPazZlaXhJSXNwS0NFUHBnZVBBdzZZU3ZaL1Rsb1IKVGlHUVVaU0kwWjNNU0s1YWdEbmF1ak5RTFRJczhoQ1NlMWxFUzB0MG9PMXlNS1FBZ1NzRFdNT0xpZ3pETSt3Rgo5YW5GaC9NRkEvMHg1Q3FmTzNqYVRRTlovUHVFREVXdDl4eGVNbzh3MDhVZ2J4N2U2cEQzWGNGREpGUzZaSkNoCnIzOFB3ZWY2S295TW45WkpHZmtuN3pGZjlVbFVVUFFQOFQvQW5xVWNSTTdVWUFZYmZzRGVKZzVMbjk5bUc2T0cKeEFBNG5FK0tjSWlnMUxnNjZpb1kvak12dGx1Wnp6VVB2cDliSndJREFRQUJBb0lCQVFDWW11MzZFei9aVWhFNAphTXQ1ZzBYMXFVYnI2dzJVbzFVdmJPL3huZnRzdE92Ti9zRVd1VEhDZlFkZ2YvTkhUTFVGS1N1M2plL3V1RnhjCmR1YU90QjN2R2l5NDdEOUtkd2Q4TnJONGZFVGhSS21yTllNT2xhVTB0YzFsUHp1T2ZYeU1CUXJhSnVOSWlnRlcKakRNeHExZjE1M2RqK0d6NWZhMjhramtLaHE3OU9lSEwzR3U3QXpSbDNWc3lCbUplazNKOUJyZkV0RS9wU1llUwppRGlhaE5Cc1NXV3hKRzkrVlZ6Vzl4ZDhOWFBxOEEyNVdYODdYblBXdUsyc3NRRU1tYWgydStEUWlFaGpKWFVCCmVxS20vVTJJS2VkN2xXa1I5YVBmcUpXRkhnV2tMeTBLdGhjL3dFR3ZKemFXbzBxQXFKRXhCdFVKVElWVjF6VWoKeml2N2I3c0JBb0dCQVBIblNVRHg3a0o1bGNUMENNSEppaG1nOWxuaXRobmNuSng1OVVPa2RHdFJQVDBIUUhHUQpnSlRudVlVeHBtTmYyc2lIZ2ZCYitkVXZ3NEk4ZzlDbjBXaFBWbHNuVjE5NU9lYlh1eDlCN2VyYzNDQmRrM05ICm02dlAyU3RvN240TkdSa1BPSytBK0dMOU9sM1dncW1QKzVFQzVOTDJJWWNWOVZXWkk1dzJ2L2pIQW9HQkFNUlcKRmNBUE9zMXE4R3ZHQkh5eGY0OVlqV0hWNUJJSlEvdnZLZ3lDelc1NlBpczNGMGsyWkVNbStKVEkrNkJOWURQMQo2QyszajVEbUtBVEs2d1J0cWNwYk1GRTIwU29wdnFpbUplZi9DeE11VHQxZTVmUkdMbjlQYWRSZkZKN2tMMGhGCmp6VWxvTkRrOWxZbmxpZHNBVFdDNytyeXhKQXJHY3ZOOVVOamt1cWhBb0dCQUluNyt4NFBvbS9LdVBLeW5QZ2wKUlNBZlg4YWYrbTNBR0psdE84a00ydGVJYkowT01PVldudkhSU0ZMQW9uK1c0czUxOVZtc3JWSzh2eEhnQVBTWgpkV3JCcnFtcVJEMlNnY082bE9OY2tTRGlRTEk1am0wNGtJU3R0OXY2SytnOUFtNzM3c2ExazNtcnBvcDJYT3ZwCjFIN0FIdFJ6VDJhbDBONjF6c2xCdGJsckFvR0JBTUJ6WVg2UmJ5Skw0TDdEcTBKTytxcVlNbjNrRzF0U21jRXAKL2gybFdaa2hXaThpSVVFeWY3VVRUamNKaXh6bXU1WXpSUlVBNlVrdlVhcmcvTjJxWVBScHprTE5hTm5iY1hmKwo1TWt6eHJkV2ZSZWhIZWNEcERCR3Q0WGtiV0lTYWdaOXFKSi8vOUxEbkhOMitraEtKaVU5NDg1NWlST0lMQkVLCklZK2MyellCQW9HQVE4VmdCTmh4Qk5rUHcwMUpRQTd2bFhRaWdHKzNhdG9tVkZDRmVwNjh2TFhlQnNxL1NYTEYKQ0EwclFsSGNvcGdqM3pjcW9ybENaZWpBMk0wZ29mYUk5VGVMTzFWak5BNlhNMUFMd1UxL2cxVkw3RmNqRUsrNwpSczlNblpTVm96aDd1NERVUVFsZktzZWZhbThUL0gvd3UwK2U2UEd1QXFYUTQ3bHZzenZpVlR3PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="
	pubKB64 := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF1WVpzVmNucEUwb1RLTGR2ODA0ZwpFWXhOWDZhZGVFT0VucFZESkVDUjcxTGhDRkFuNm92TzBkRU5hdjlhWlN0RjJzeHVqbVdWcGZhclB5ekpUUk9rCjZlaXhJSXNwS0NFUHBnZVBBdzZZU3ZaL1Rsb1JUaUdRVVpTSTBaM01TSzVhZ0RuYXVqTlFMVElzOGhDU2UxbEUKUzB0MG9PMXlNS1FBZ1NzRFdNT0xpZ3pETSt3RjlhbkZoL01GQS8weDVDcWZPM2phVFFOWi9QdUVERVd0OXh4ZQpNbzh3MDhVZ2J4N2U2cEQzWGNGREpGUzZaSkNocjM4UHdlZjZLb3lNbjlaSkdma243ekZmOVVsVVVQUVA4VC9BCm5xVWNSTTdVWUFZYmZzRGVKZzVMbjk5bUc2T0d4QUE0bkUrS2NJaWcxTGc2NmlvWS9qTXZ0bHVaenpVUHZwOWIKSndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
	key1, _ := base64.StdEncoding.DecodeString(privKB64)
	key2, _ := base64.StdEncoding.DecodeString(pubKB64)
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(key1)
	if err != nil {
		fmt.Fprint(w, err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(key2)
	if err != nil {
		fmt.Fprint(w, err)
	}

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		Issuer:    "test",
		Audience:  "kelso",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	method := jwt.GetSigningMethod("RS256")
	ss, err := token.SignedString(privKey)
	if err != nil {
		fmt.Fprint(w, err)
	}
	parts := strings.Split(ss, ".")
	//sig2, err := method.Sign(strings.Join(parts[0:2], "."), privKey)
	errz := method.Verify(strings.Join(parts[0:2], "."), parts[2], pubKey)
	if errz != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, ss+"\n")
	token2, err := jwt.Parse(ss, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		fmt.Fprint(w, err)
	}
	fmt.Fprint(w, token2.Claims)
}
