package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"github.com/euicc-go/bertlv"
	"github.com/syumai/workers/cloudflare/kv"
)

func onAuthenClient(response *bertlv.TLV, client *http.Client) (err error) {
	var report dump.Report
	if err = report.UnmarshalBerTLV(response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	jsonStr, err := NewJSON(&report)
	if err != nil {
		return fmt.Errorf("failed to create JSON: %w", err)
	}

	matchingID := strings.TrimSpace(report.MatchingID)
	if matchingID == "" {
		return fmt.Errorf("matching-id is empty")
	}

	kvNamespace, err := kv.NewNamespace(config.KVNamespace)
	if err != nil {
		return fmt.Errorf("failed to init KV namespace: %w", err)
	}

	if err := kvNamespace.PutString(matchingID, jsonStr, nil); err != nil {
		return fmt.Errorf("failed to store report to KV: %w", err)
	}

	return nil
}

// handleKVRoute handles KV operations
func handleKVRoute(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id parameter", http.StatusBadRequest)
		return
	}

	kvNamespace, err := kv.NewNamespace(config.KVNamespace)
	if err != nil {
		http.Error(w, "failed to init KV namespace", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Retrieve a stored entry
		data, err := kvNamespace.GetString(id, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to retrieve entry: %v", err), http.StatusInternalServerError)
			return
		}

		if data == "" {
			http.Error(w, "entry not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(data))

	case http.MethodDelete:
		// Delete a stored entry
		if err := kvNamespace.Delete(id); err != nil {
			http.Error(w, fmt.Sprintf("failed to delete entry: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
