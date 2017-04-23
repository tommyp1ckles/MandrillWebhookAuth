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
  // ErrBadSig is returned when verification with an incorrect 
  // is used.
  ErrBadSig = errors.New("Bad Signature")
)

// VerifyRequest verifies a mandrill request authentication
// signature.
func VerifyRequest(req *http.Request, authKey string) error {
  signature := req.Header.Get("X-Mandrill-Signature")
  url := req.URL.String()
  params := postParams(req)
  signedData := sign(authKey, url, params)

  if hmac.Equal([]byte(signedData), []byte(signature)) {
    return nil
  } else {
    return ErrBadSig
  }
}

// SignRequest returns a signature string given a HTTP request 
// and a key.
func SignRequest(authKey string, req *http.Request) string {
  url := req.URL.String()
  params := postParams(req)
  return sign(authKey, url, params)
}

func sign(authKey, url string, params []KeyValue) string {
  signedData := url
  for _, kv := range params {
    signedData += kv.Key + kv.Val
  }

  mac := hmac.New(sha1.New, []byte(authKey))
  mac.Write([]byte(signedData))
  hashedData := mac.Sum(nil)

  sig := base64.StdEncoding.EncodeToString(hashedData)
  return sig
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

// KeyValue holds a key and corresponding value, to be used for sorting
// collections of key-value pairs.
type KeyValue struct {
    Key string
    Val string
}

// ByKey implements the sortable interface for a KeyValue slice 
// such that it is sorted by key, in non-decreasing order.
type ByKey []KeyValue

func (a ByKey) Len() int           { return len(a) }
func (a ByKey) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByKey) Less(i, j int) bool {
  return strings.Compare(a[i].Key, a[j].Key) == -1
}
