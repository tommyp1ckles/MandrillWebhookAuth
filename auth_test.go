package MandrillWebhookAuth

import (
  "net/http"
  "net/url"
  "testing"
  . "github.com/smartystreets/goconvey/convey"
)

var (
  authKey = "redacted"
  URL = "redacted"
  XMandrillSignature = "redacted"

  MandrillEvents = `redacted`
  params = []KeyValue{
    {"mandrill_events", MandrillEvents},
  }
)


func TestVerifyRequest(t *testing.T) {
  Convey("VerifyRequest", t, func() {
    req, err :=  http.NewRequest("POST", URL, nil)
    So(err, ShouldBeNil)
    req.Header.Add("X-Mandrill-Signature", XMandrillSignature)
    req.PostForm = url.Values(map[string][]string{})
    req.PostForm["mandrill_events"] = []string{MandrillEvents}
    Convey("should verify request correctly", func() {
      So(VerifyRequest(req, authKey), ShouldBeNil)
    })
  })

  Convey("VerifyRequest", t, func() {
    req, err :=  http.NewRequest("POST", URL, nil)
    So(err, ShouldBeNil)
    req.Header.Add("X-Mandrill-Signature", "")
    req.PostForm = url.Values(map[string][]string{})
    req.PostForm["mandrill_events"] = []string{MandrillEvents}
    Convey("bad request should fail", func() {
      So(VerifyRequest(req, authKey), ShouldNotBeNil)
    })
  })
}
