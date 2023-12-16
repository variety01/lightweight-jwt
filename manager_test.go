package jwt_test

import (
	"errors"
	"testing"

	jwt "github.com/variety01/lightweight-jwt"
)

func TestGeneration(t *testing.T) {
	type generateTestCase struct {
		name           string
		manager        *jwt.JWTTokenManager[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]
		header         *jwt.DefaultJWTHeader
		payload        *jwt.DefaultJWTPayload
		expectedOutput string
		expectedError  error
	}

	hmacSecretKey := []byte("hmacSecretKey")
	HS256Manager := jwt.NewJWTTokenManager[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload](
		jwt.DefaultBase64Codec, jwt.DefaultJSONCodec,
		func(token *jwt.JWT[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]) error {
			if token.Header.Type != "JWT" {
				return errors.New("invalid type")
			}

			if token.Header.Algorithm != "HS256" {
				return jwt.ErrInvalidAlgorithm
			}

			return jwt.HS256SignatureManager.Verify(token.GetSignatureSource(), token.Signature, hmacSecretKey)
		},
		func(token *jwt.JWT[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]) error {
			signature, err := jwt.HS256SignatureManager.Sign(token.GetSignatureSource(), hmacSecretKey)
			if err != nil {
				return err
			}

			token.Signature = signature

			return nil
		},
	)

	testCases := []generateTestCase{
		{
			name:    "Valid",
			manager: &HS256Manager,
			header: &jwt.DefaultJWTHeader{
				Type:      "JWT",
				Algorithm: "HS256",
			},
			payload:        &jwt.DefaultJWTPayload{Subject: "test"},
			expectedOutput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.AjLsevnWc1O1PVnG1NjiQ26DutU9hHqX0tgQPTpkY3U",
			expectedError:  nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			token, err := testCase.manager.GenerateJWT(testCase.header, testCase.payload)
			if err != testCase.expectedError {
				t.Fatalf("unexpected error: %v", err)
			}

			if token != testCase.expectedOutput {
				t.Fatalf("unexpected token, got: %s want: %s", token, testCase.expectedOutput)
			}
		})
	}
}

func TestParsing(t *testing.T) {
	type parseTestCase struct {
		name            string
		manager         *jwt.JWTTokenManager[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]
		token           string
		expectedHeader  *jwt.DefaultJWTHeader
		expectedPayload *jwt.DefaultJWTPayload
		expectedError   error
	}

	hmacSecretKey := []byte("hmacSecretKey")
	HS256Manager := jwt.NewJWTTokenManager[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload](
		jwt.DefaultBase64Codec, jwt.DefaultJSONCodec,
		func(token *jwt.JWT[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]) error {
			if token.Header.Type != "JWT" {
				return errors.New("invalid type")
			}

			if token.Header.Algorithm != "HS256" {
				return jwt.ErrInvalidAlgorithm
			}

			return jwt.HS256SignatureManager.Verify(token.GetSignatureSource(), token.Signature, hmacSecretKey)
		},
		func(token *jwt.JWT[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]) error {
			signature, err := jwt.HS256SignatureManager.Sign(token.GetSignatureSource(), hmacSecretKey)
			if err != nil {
				return err
			}

			token.Signature = signature

			return nil
		},
	)

	testCases := []parseTestCase{
		{
			name:    "Valid",
			manager: &HS256Manager,
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.AjLsevnWc1O1PVnG1NjiQ26DutU9hHqX0tgQPTpkY3U",
			expectedHeader: &jwt.DefaultJWTHeader{
				Type:      "JWT",
				Algorithm: "HS256",
			},
			expectedPayload: &jwt.DefaultJWTPayload{Subject: "test"},
			expectedError:   nil,
		},
		{
			name:            "Malformed token header",
			manager:         &HS256Manager,
			token:           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiJ0ZXN0In0.AjLsevnWc1O1PVnG1NjiQ26DutU9hHqX0tgQPTpkY3U",
			expectedHeader:  nil,
			expectedPayload: nil,
			expectedError:   jwt.ErrMalformedToken,
		},
		{
			name:            "Malformed token payload",
			manager:         &HS256Manager,
			token:           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In.AjLsevnWc1O1PVnG1NjiQ26DutU9hHqX0tgQPTpkY3U",
			expectedHeader:  nil,
			expectedPayload: nil,
			expectedError:   jwt.ErrMalformedToken,
		},
		{
			name:            "Invalid algorithm",
			manager:         &HS256Manager,
			token:           "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.0IFWlIOxvQhPQsSSJviPynhtSLFEBPpqpWthJA-19G4iYD09fT4QBRRRt-F1weXm-pnTYfWTTILrqjzb0aaStw",
			expectedHeader:  nil,
			expectedPayload: nil,
			expectedError:   jwt.ErrInvalidAlgorithm,
		},
		{
			name:            "Invalid signature",
			manager:         &HS256Manager,
			token:           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.gRoWNj9TuFRhh4lw77lKN7c-wWPoZJPl0QEvKMrNtcA",
			expectedHeader:  nil,
			expectedPayload: nil,
			expectedError:   jwt.ErrInvalidSignature,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			jwtToken, err := testCase.manager.ParseJWT(testCase.token)
			if err != testCase.expectedError {
				t.Fatalf("unexpected error, got: %v, want: %+v", err, testCase.expectedError)
			}

			if err != nil {
				return
			}

			if jwtToken.Header.Type != testCase.expectedHeader.Type {
				t.Fatalf("unexpected header type, got: %s want: %s", jwtToken.Header.Type, testCase.expectedHeader.Type)
			}

			if jwtToken.Header.Algorithm != testCase.expectedHeader.Algorithm {
				t.Fatalf("unexpected header algorithm, got: %s want: %s", jwtToken.Header.Algorithm, testCase.expectedHeader.Algorithm)
			}

			if jwtToken.Payload.Subject != testCase.expectedPayload.Subject {
				t.Fatalf("unexpected payload subject, got: %s want: %s", jwtToken.Payload.Subject, testCase.expectedPayload.Subject)
			}
		})
	}
}

func BenchmarkJWTTokenManager(b *testing.B) {
	type benchmarkCase struct {
		name    string
		manager jwt.JWTTokenManager[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]
	}

	var benchmarkCases = []benchmarkCase{
		{
			name: "HS256 generate",
			manager: jwt.NewJWTTokenManager[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload](
				jwt.DefaultBase64Codec, jwt.DefaultJSONCodec,
				func(token *jwt.JWT[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]) error {
					if token.Header.Type != "JWT" {
						return errors.New("invalid type")
					}

					if token.Header.Algorithm != "HS256" {
						return jwt.ErrInvalidAlgorithm
					}

					return jwt.HS256SignatureManager.Verify(token.GetSignatureSource(), token.Signature, []byte("hmacSecretKey"))
				},
				func(token *jwt.JWT[jwt.DefaultJWTHeader, jwt.DefaultJWTPayload]) error {
					signature, err := jwt.HS256SignatureManager.Sign(token.GetSignatureSource(), []byte("hmacSecretKey"))
					if err != nil {
						return err
					}

					token.Signature = signature

					return nil
				},
			),
		},
	}

	for _, benchmarkCase := range benchmarkCases {
		b.Run(benchmarkCase.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := benchmarkCase.manager.GenerateJWT(
					&jwt.DefaultJWTHeader{
						Type:      "JWT",
						Algorithm: "HS256",
					},
					&jwt.DefaultJWTPayload{
						Issuer:     "test.go",
						Subject:    "test",
						Audience:   "test.go",
						Expiration: 1234567890,
					},
				)
				if err != nil {
					b.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
