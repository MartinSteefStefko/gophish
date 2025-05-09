package models

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func setupBenchmarkServer() *httptest.Server {
	var (
		requestCount int
		mu           sync.Mutex
	)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		currentCount := requestCount
		mu.Unlock()

		// Simulate rate limiting after 30 requests per second
		if currentCount > 30 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		// Simulate realistic API latency (50-150ms)
		time.Sleep(time.Duration(50+currentCount%100) * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
}

func BenchmarkGraphAPISend(b *testing.B) {
	server := setupBenchmarkServer()
	defer server.Close()

	sender := &GraphAPISender{
		client:       http.DefaultClient,
		tokenCache:   &TokenCache{AccessToken: "test_token", ExpiresAt: time.Now().Add(1 * time.Hour)},
		graphBaseURL: server.URL,
	}

	msg := &mockMessage{content: "benchmark test message"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := sender.Send("from@test.com", []string{"to@test.com"}, msg)
		if err != nil {
			b.Logf("Send error at iteration %d: %v", i, err)
		}
	}
}

func BenchmarkGraphAPIConcurrentSend(b *testing.B) {
	server := setupBenchmarkServer()
	defer server.Close()

	sender := &GraphAPISender{
		client:       http.DefaultClient,
		tokenCache:   &TokenCache{AccessToken: "test_token", ExpiresAt: time.Now().Add(1 * time.Hour)},
		graphBaseURL: server.URL,
	}

	msg := &mockMessage{content: "benchmark test message"}

	// Test different concurrency levels
	concurrencyLevels := []int{5, 10, 20, 50}

	for _, numWorkers := range concurrencyLevels {
		b.Run(fmt.Sprintf("Workers_%d", numWorkers), func(b *testing.B) {
			var wg sync.WaitGroup
			errChan := make(chan error, b.N)

			// Create worker pool
			jobs := make(chan struct{}, b.N)
			for w := 0; w < numWorkers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range jobs {
						err := sender.Send("from@test.com", []string{"to@test.com"}, msg)
						errChan <- err
					}
				}()
			}

			b.ResetTimer()
			// Send jobs
			for i := 0; i < b.N; i++ {
				jobs <- struct{}{}
			}
			close(jobs)

			// Wait for completion
			wg.Wait()
			close(errChan)

			// Count errors
			var errorCount int
			for err := range errChan {
				if err != nil {
					errorCount++
				}
			}
			b.ReportMetric(float64(errorCount)/float64(b.N), "error_rate")
		})
	}
}

func BenchmarkGraphAPIBurst(b *testing.B) {
	server := setupBenchmarkServer()
	defer server.Close()

	sender := &GraphAPISender{
		client:       http.DefaultClient,
		tokenCache:   &TokenCache{AccessToken: "test_token", ExpiresAt: time.Now().Add(1 * time.Hour)},
		graphBaseURL: server.URL,
	}

	msg := &mockMessage{content: "benchmark test message"}

	// Test burst sending patterns
	burstSizes := []int{10, 30, 50, 100}

	for _, burstSize := range burstSizes {
		b.Run(fmt.Sprintf("Burst_%d", burstSize), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				errors := make([]error, burstSize)

				// Send burst
				for j := 0; j < burstSize; j++ {
					wg.Add(1)
					go func(index int) {
						defer wg.Done()
						errors[index] = sender.Send("from@test.com", []string{"to@test.com"}, msg)
					}(j)
				}
				wg.Wait()

				// Count errors in this burst
				var errorCount int
				for _, err := range errors {
					if err != nil {
						errorCount++
					}
				}
				b.ReportMetric(float64(errorCount)/float64(burstSize), "error_rate")
			}
		})
	}
} 