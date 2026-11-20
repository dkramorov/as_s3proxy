package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func main() {
	minioAccess := os.Getenv("MINIO_ACCESS_KEY")
	minioSecret := os.Getenv("MINIO_SECRET_KEY")
	cloudAccess := os.Getenv("CLOUD_ACCESS_KEY")
	cloudSecret := os.Getenv("CLOUD_SECRET_KEY")
	cloudEndpoint := os.Getenv("CLOUD_ENDPOINT")
	if cloudEndpoint == "" {
		cloudEndpoint = "https://s3.cloud.ru"
	}
	cloudRegion := os.Getenv("CLOUD_REGION")
	if cloudRegion == "" {
		cloudRegion = "ru-central-1"
	}

	targetURL, err := url.Parse(cloudEndpoint)
	if err != nil {
		log.Fatalf("Invalid endpoint: %v", err)
	}

	signer := v4.NewSigner()
	creds := aws.Credentials{
		AccessKeyID:     cloudAccess,
		SecretAccessKey: cloudSecret,
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			isPresigned := req.URL.Query().Get("X-Amz-Algorithm") != ""
			if isPresigned {
				if err := verifyPresignedSigV4(req, minioAccess, minioSecret); err != nil {
					log.Printf("[AUTH FAIL PRESIGN] %s %s -> %v", req.Method, req.URL.RequestURI(), err)
					req.Header.Set("X-Internal-Auth-Err", err.Error())
					return
				}
			} else {
				if err := verifySigV4(req, minioAccess, minioSecret); err != nil {
					log.Printf("[AUTH FAIL] %s %s -> %v", req.Method, req.URL.RequestURI(), err)
					req.Header.Set("X-Internal-Auth-Err", err.Error())
					return
				}
			}

			log.Printf("[PROXY] %s %s (presigned=%v)", req.Method, req.URL.RequestURI(), isPresigned)

			for k := range req.Header {
				lk := strings.ToLower(k)
				if strings.HasPrefix(lk, "x-forwarded-") ||
					lk == "x-real-ip" ||
					lk == "forwarded" ||
					lk == "authorization" ||
					lk == "x-amz-security-token" {
					req.Header.Del(k)
				}
			}

			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host

			req.Header.Del("X-Forwarded-For")
			req.Header.Del("X-Forwarded-Proto")
			req.Header.Del("X-Forwarded-Host")

			now := time.Now().UTC()
			if isPresigned {
				expiresStr := "900"
				if exp := req.URL.Query().Get("X-Amz-Expires"); exp != "" {
					if sec, err := strconv.Atoi(exp); err == nil && sec > 0 {
						expiresStr = strconv.Itoa(sec)
					}
				}

				q := req.URL.Query()
				for k := range q {
					if strings.HasPrefix(strings.ToLower(k), "x-amz-") {
						q.Del(k)
					}
				}
				q.Set("X-Amz-Expires", expiresStr)
				req.URL.RawQuery = q.Encode()

				signedURI, signedHeaders, err := signer.PresignHTTP(
					context.Background(),
					creds,
					req,
					"UNSIGNED-PAYLOAD",
					"s3",
					cloudRegion,
					now,
					func(o *v4.SignerOptions) {
						o.DisableURIPathEscaping = true
					},
				)
				if err != nil {
					log.Printf("[PRESIGN ERROR] %v", err)
					req.Header.Set("X-Internal-Auth-Err", "internal presign error")
					return
				}

				parsedSigned, err := url.Parse(signedURI)
				if err != nil {
					log.Printf("[PRESIGN PARSE ERROR] %v", err)
					req.Header.Set("X-Internal-Auth-Err", "internal presign parse error")
					return
				}

				// Меняем только RawQuery, чтобы не сломать кодировку Path/RawPath с кириллицей!
				req.URL.RawQuery = parsedSigned.RawQuery
				for k, vals := range signedHeaders {
					req.Header[k] = vals
				}
			} else {
				req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
				payloadHash := "UNSIGNED-PAYLOAD"
				req.Header.Set("X-Amz-Content-Sha256", payloadHash)

				if err := signer.SignHTTP(
					context.Background(),
					creds,
					req,
					payloadHash,
					"s3",
					cloudRegion,
					now,
					func(o *v4.SignerOptions) {
						o.DisableURIPathEscaping = true
					},
				); err != nil {
					log.Printf("[SIGN ERROR] %v", err)
					req.Header.Set("X-Internal-Auth-Err", "internal sign error")
				}
			}
		},
		Transport: &authTransport{rt: http.DefaultTransport},
	}

	log.Println("Cloud.ru S3 Reverse Proxy listening on :7070")
	log.Fatal(http.ListenAndServe(":7070", proxy))
}

type authTransport struct {
	rt http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if errMsg := req.Header.Get("X-Internal-Auth-Err"); errMsg != "" {
		xmlErr := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>SignatureDoesNotMatch</Code><Message>%s</Message></Error>`, errMsg)
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"application/xml"}},
			Body:       io.NopCloser(strings.NewReader(xmlErr)),
		}, nil
	}
	return t.rt.RoundTrip(req)
}

func verifySigV4(r *http.Request, expectedAccess, expectedSecret string) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return fmt.Errorf("missing AWS4-HMAC-SHA256 header")
	}

	params := make(map[string]string)
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}

	cred := strings.Split(params["Credential"], "/")
	if len(cred) != 5 {
		return fmt.Errorf("bad Credential format")
	}

	accessKey, dateStamp, region, service := cred[0], cred[1], cred[2], cred[3]
	if accessKey != expectedAccess {
		return fmt.Errorf("invalid AccessKeyId")
	}

	signedHeaders := strings.Split(params["SignedHeaders"], ";")
	sort.Strings(signedHeaders)

	var canonHeaders strings.Builder
	for _, h := range signedHeaders {
		val := r.Header.Get(h)
		if strings.EqualFold(h, "host") {
			val = r.Host
		}
		canonHeaders.WriteString(strings.ToLower(h) + ":" + strings.TrimSpace(val) + "\n")
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	canonURI := r.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}

	q := r.URL.Query()
	var keys []string
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonQuery []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			canonQuery = append(canonQuery, awsQueryEscape(k)+"="+awsQueryEscape(v))
		}
	}

	canonReq := strings.Join([]string{
		r.Method,
		canonURI,
		strings.Join(canonQuery, "&"),
		canonHeaders.String(),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")

	amzDate := r.Header.Get("X-Amz-Date")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	sum := sha256.Sum256([]byte(canonReq))
	strToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, scope, hex.EncodeToString(sum[:]))

	kDate := hmacSHA([]byte("AWS4"+expectedSecret), dateStamp)
	kRegion := hmacSHA(kDate, region)
	kService := hmacSHA(kRegion, service)
	kSigning := hmacSHA(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(kSigning, strToSign))

	if !bytes.Equal([]byte(sig), []byte(params["Signature"])) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func verifyPresignedSigV4(r *http.Request, expectedAccess, expectedSecret string) error {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return fmt.Errorf("unsupported algorithm")
	}

	amzDate := q.Get("X-Amz-Date")
	expiresStr := q.Get("X-Amz-Expires")
	if amzDate != "" && expiresStr != "" {
		if reqTime, err := time.Parse("20060102T150405Z", amzDate); err == nil {
			if expSec, err := strconv.Atoi(expiresStr); err == nil {
				if time.Now().UTC().After(reqTime.Add(time.Duration(expSec) * time.Second)) {
					return fmt.Errorf("presigned URL has expired")
				}
			}
		}
	}

	cred := strings.Split(q.Get("X-Amz-Credential"), "/")
	if len(cred) != 5 {
		return fmt.Errorf("bad X-Amz-Credential format")
	}

	accessKey, dateStamp, region, service := cred[0], cred[1], cred[2], cred[3]
	if accessKey != expectedAccess {
		return fmt.Errorf("invalid AccessKeyId")
	}

	signedHeaders := strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
	sort.Strings(signedHeaders)

	var canonHeaders strings.Builder
	for _, h := range signedHeaders {
		val := r.Header.Get(h)
		if strings.EqualFold(h, "host") {
			val = r.Host
		}
		canonHeaders.WriteString(strings.ToLower(h) + ":" + strings.TrimSpace(val) + "\n")
	}

	canonURI := r.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}

	var keys []string
	for k := range q {
		if k == "X-Amz-Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonQuery []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			canonQuery = append(canonQuery, awsQueryEscape(k)+"="+awsQueryEscape(v))
		}
	}

	canonReq := strings.Join([]string{
		r.Method,
		canonURI,
		strings.Join(canonQuery, "&"),
		canonHeaders.String(),
		strings.Join(signedHeaders, ";"),
		"UNSIGNED-PAYLOAD",
	}, "\n")

	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	sum := sha256.Sum256([]byte(canonReq))
	strToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, scope, hex.EncodeToString(sum[:]))

	kDate := hmacSHA([]byte("AWS4"+expectedSecret), dateStamp)
	kRegion := hmacSHA(kDate, region)
	kService := hmacSHA(kRegion, service)
	kSigning := hmacSHA(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(kSigning, strToSign))

	if !bytes.Equal([]byte(sig), []byte(q.Get("X-Amz-Signature"))) {
		return fmt.Errorf("presigned signature mismatch")
	}
	return nil
}

func hmacSHA(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func awsQueryEscape(s string) string {
	esc := url.QueryEscape(s)
	esc = strings.ReplaceAll(esc, "+", "%20")
	esc = strings.ReplaceAll(esc, "*", "%2A")
	esc = strings.ReplaceAll(esc, "%7E", "~")
	return esc
}