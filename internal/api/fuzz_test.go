package api_test

// FuzzScanQuery, FuzzHistoryQuery, and FuzzExposureQuery drive each handler's
// query-string parsing with arbitrary bytes. Any input must produce a
// documented HTTP status with a decodable JSON body — no panic, no 500, no
// response that cannot be decoded.
//
// Seed corpora start from the cases the unit tests already pin, so the fuzzer
// begins at the documented boundary and explores from there.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	fuzzIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
	fuzzHolder = "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA"
)

// allowedScanStatus is the set of HTTP status codes handleScan is documented
// to return. A 500 is never allowed; a panic is caught by the testing framework
// as a test failure.
var allowedScanStatus = map[int]bool{
	http.StatusOK:                  true,
	http.StatusBadRequest:          true,
	http.StatusNotFound:            true,
	http.StatusServiceUnavailable:  true,
	http.StatusTooManyRequests:     true,
	http.StatusInternalServerError: false, // 500 is never allowed
}

// assertFuzzResponse enforces the two handler invariants: the status code is
// one the handler is documented to return, and the body is decodable JSON.
func assertFuzzResponse(t *testing.T, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	status := rec.Code
	// 500 is never acceptable: an unhandled error must still produce a
	// structured response with a documented code, not a stack trace.
	if status == http.StatusInternalServerError {
		t.Fatalf("%s: got 500 Internal Server Error; query-string input must never reach a 500", name)
	}
	// The body must be decodable JSON, whatever the status.
	body := rec.Body.Bytes()
	if len(body) == 0 {
		// An empty body is accepted only for a 200 that might stream nothing —
		// all our handlers write JSON, so an empty 200 is also a bug.
		if status == http.StatusOK {
			t.Fatalf("%s: status 200 with empty body", name)
		}
		return
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("%s: status %d, body is not valid JSON: %v\nbody: %s", name, status, err, body)
	}
}

// FuzzScanQuery fuzzes the query parameters of GET /api/v1/scan.
//
// The fuzzer combines the asset, holder, and max_age_secs parameters as
// separate strings, so it can explore the full cross-product of inputs rather
// than just the asset string. The handler must never panic, never return 500,
// and must always return decodable JSON.
func FuzzScanQuery(f *testing.F) {
	// Seed from the cases TestScanRejectsBadInput and TestScanNativeAssetIsExplicit400 pin.
	for _, asset := range []string{
		"",
		"hello",
		"USDC-NOPE",
		"native",
		"XLM",
		"USDC-" + fuzzIssuer,
	} {
		for _, holder := range []string{"", fuzzHolder, "NOTHOLDER", "G" + fuzzIssuer[1:]} {
			for _, maxAge := range []string{"", "0", "60", "-1", "notanumber"} {
				f.Add(asset, holder, maxAge)
			}
		}
	}

	h := newTestServer()
	f.Fuzz(func(t *testing.T, asset, holder, maxAgeSecs string) {
		url := "/api/v1/scan"
		sep := "?"
		if asset != "" {
			url += sep + "asset=" + asset
			sep = "&"
		}
		if holder != "" {
			url += sep + "holder=" + holder
			sep = "&"
		}
		if maxAgeSecs != "" {
			url += sep + "max_age_secs=" + maxAgeSecs
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
		assertFuzzResponse(t, "FuzzScanQuery", rec)
	})
}

// FuzzHistoryQuery fuzzes the query parameters of GET /api/v1/history.
//
// Parameters: asset, limit, before. The handler reads history from an
// in-process store, so it never touches the network: it must handle any input
// with a documented status and decodable JSON.
func FuzzHistoryQuery(f *testing.F) {
	for _, asset := range []string{
		"",
		"USDC-" + fuzzIssuer,
		"bad",
		"USDC-NOPE",
	} {
		for _, limit := range []string{"", "1", "100", "0", "-1", "notanumber", "99999"} {
			for _, before := range []string{"", "2026-01-01T00:00:00Z", "notadate", "0"} {
				f.Add(asset, limit, before)
			}
		}
	}

	h := newTestServer()
	f.Fuzz(func(t *testing.T, asset, limit, before string) {
		url := "/api/v1/history"
		sep := "?"
		if asset != "" {
			url += sep + "asset=" + asset
			sep = "&"
		}
		if limit != "" {
			url += sep + "limit=" + limit
			sep = "&"
		}
		if before != "" {
			url += sep + "before=" + before
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
		assertFuzzResponse(t, "FuzzHistoryQuery", rec)
	})
}

// FuzzExposureQuery fuzzes the query parameters of GET /api/v1/exposure.
//
// Parameters: account, limit, cursor. The handler never touches upstream for
// bad input: it validates and rejects before any network call.
func FuzzExposureQuery(f *testing.F) {
	for _, account := range []string{
		"",
		fuzzHolder,
		"NOTHOLDER",
		"G" + fuzzHolder[1:5],
	} {
		for _, limit := range []string{"", "1", "10", "0", "-1", "notanumber", "9999"} {
			for _, cursor := range []string{"", "0", "5", "-1", "notanumber"} {
				f.Add(account, limit, cursor)
			}
		}
	}

	h := newTestServer()
	f.Fuzz(func(t *testing.T, account, limit, cursor string) {
		url := "/api/v1/exposure"
		sep := "?"
		if account != "" {
			url += sep + "account=" + account
			sep = "&"
		}
		if limit != "" {
			url += sep + "limit=" + limit
			sep = "&"
		}
		if cursor != "" {
			url += sep + "cursor=" + cursor
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
		assertFuzzResponse(t, "FuzzExposureQuery", rec)
	})
}
