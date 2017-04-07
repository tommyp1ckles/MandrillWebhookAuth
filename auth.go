package MandrillWebhookAuth

import (
  "net/http"
  "sort"
  "errors"
  "strings"
  "crypto/hmac"
  "crypto/sha1"
  "encoding/base64"
)

var (
  ErrBadSig = errors.New("Bad Signature")
)

// VerifyRequest verifies a mandrill request authentication
// signature.
func VerifyRequest(req *http.Request, authKey string) error {
  signature := req.Header.Get("X-Mandrill-Signature")
  url := req.URL.String()
  params := postParams(req)
  return VerifySignature(authKey, url, signature, params)
}

func postParams(req *http.Request) []KeyValue {
  req.ParseForm()
  arr := make([]KeyValue, 0, len(req.PostForm))
  for k, v := range req.PostForm {
    arr = append(arr, KeyValue{Key: k, Val: v[0]})
  }
  sort.Sort(ByKey(arr))
  return arr
}

type KeyValue struct {
    Key string
    Val string
}

type ByKey []KeyValue

func (a ByKey) Len() int            { return len(a) }
func (a ByKey) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByKey) Less(i, j int) bool {
  return strings.Compare(a[i].Key, a[j].Key) == -1
}

// VerifySignature verifies mandrill request fields.
func VerifySignature(authKey, url, signature string, params []KeyValue) error {
  signedData := url
  for _, kv := range params {
    signedData += kv.Key + kv.Val
  }

  mac := hmac.New(sha1.New, []byte(authKey))
  mac.Write([]byte(signedData))
  hashedData := mac.Sum(nil)

  encodedHashedData := base64.StdEncoding.EncodeToString(hashedData)

  if hmac.Equal([]byte(encodedHashedData), []byte(signature)) {
    return nil
  } else {
    return ErrBadSig
  }
}
