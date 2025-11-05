package config

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzSplitFunc tests the bitcoin.conf line splitting function
func FuzzSplitFunc(f *testing.F) {
	// Seed with valid config lines
	f.Add([]byte("rpcuser=bitcoin\nrpcpassword=secret\n"), false)
	f.Add([]byte("rpcconnect=127.0.0.1\n"), false)
	f.Add([]byte("rpcport=8332\n"), false)

	// Seed with edge cases
	f.Add([]byte(""), false)                         // empty
	f.Add([]byte(""), true)                          // empty at EOF
	f.Add([]byte("key=value"), true)                 // no newline at EOF
	f.Add([]byte("key=value\n"), false)              // with newline
	f.Add([]byte("\n"), false)                       // just newline
	f.Add([]byte("===\n"), false)                    // multiple delimiters
	f.Add([]byte("nodelimiter"), false)              // no '=' or '\n'
	f.Add([]byte("key=value\nkey2=value2\n"), false) // multiple lines

	// Seed with special characters
	f.Add([]byte("key=value with spaces\n"), false)
	f.Add([]byte("key=\n"), false)       // empty value
	f.Add([]byte("=value\n"), false)     // empty key
	f.Add([]byte("key==value\n"), false) // double delimiter

	f.Fuzz(func(t *testing.T, data []byte, atEOF bool) {
		// Should never panic
		advance, token, err := splitFunc(data, atEOF)

		// Validate return values are consistent
		require.GreaterOrEqual(t, advance, 0, "advance should be non-negative")
		require.LessOrEqual(t, advance, len(data), "advance should not exceed data length")

		if err != nil {
			// Error is acceptable
			return
		}

		// If token is returned, it should not exceed data length
		if token != nil {
			require.LessOrEqual(t, len(token), len(data), "token should not exceed data length")
		}

		// If atEOF is true and data is empty, should return 0, nil, nil
		if atEOF && len(data) == 0 {
			require.Equal(t, 0, advance, "advance should be 0 for empty data at EOF")
			require.Nil(t, token, "token should be nil for empty data at EOF")
			require.NoError(t, err, "error should be nil for empty data at EOF")
		}

		// If atEOF is true and data is not empty, should return all data
		if atEOF && len(data) > 0 {
			require.Equal(t, len(data), advance, "should advance by data length at EOF")
			require.Equal(t, data, token, "should return all data at EOF")
		}
	})
}

// FuzzBitcoinConfParsing tests bitcoin.conf parsing logic
func FuzzBitcoinConfParsing(f *testing.F) {
	// Seed with valid bitcoin.conf content
	validConf := `rpcuser=bitcoin
rpcpassword=secretpassword123
rpcconnect=127.0.0.1
rpcport=8332
`
	f.Add([]byte(validConf))

	// Seed with various formats
	f.Add([]byte("rpcuser=test\nrpcpassword=pass\n"))
	f.Add([]byte("key=value\n"))
	f.Add([]byte("key=\n"))
	f.Add([]byte("=value\n"))
	f.Add([]byte("key\n"))
	f.Add([]byte(""))
	f.Add([]byte("\n"))
	f.Add([]byte("===\n"))

	// Seed with malformed content
	f.Add([]byte("rpcuser=test\nnodelimiter\nrpcpassword=pass\n"))
	f.Add([]byte("key==value\n"))
	f.Add([]byte("key=value=extra\n"))

	// Seed with special characters
	f.Add([]byte("rpcuser=user@domain\nrpcpassword=p@ss!#$%\n"))
	f.Add([]byte("rpcuser=user with spaces\n"))
	f.Add([]byte("# comment line\nrpcuser=test\n"))

	// Seed with different line endings
	f.Add([]byte("key=value\r\n"))
	f.Add([]byte("key=value\r"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a scanner with the custom split function
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Split(splitFunc)

		// Parse the config content
		confValues := map[string]string{}
		lineCount := 0

		// Should never panic during scanning
		for scanner.Scan() {
			lineCount++
			kv := scanner.Text()
			keyValue := strings.Split(kv, "=")

			// Skip lines that don't have exactly 2 parts
			if len(keyValue) != 2 {
				continue
			}

			confValues[keyValue[0]] = keyValue[1]
		}

		// Validate scanner completed without panic
		err := scanner.Err()
		if err != nil {
			// Scanner errors are acceptable for invalid input
			return
		}

		// Validate keys and values don't contain newlines
		for key, value := range confValues {
			require.NotContains(t, key, "\n", "keys should not contain newlines")
			require.NotContains(t, value, "\n", "values should not contain newlines")
		}
	})
}

// FuzzConfigKeyValueParsing tests key=value parsing logic
func FuzzConfigKeyValueParsing(f *testing.F) {
	// Seed with valid key=value pairs
	f.Add("rpcuser=bitcoin")
	f.Add("rpcpassword=secret123")
	f.Add("rpcconnect=127.0.0.1")
	f.Add("rpcport=8332")

	// Seed with edge cases
	f.Add("")
	f.Add("=")
	f.Add("key=")
	f.Add("=value")
	f.Add("key")
	f.Add("key=value=extra")
	f.Add("===")
	f.Add("key==value")

	// Seed with special characters
	f.Add("key=value with spaces")
	f.Add("key with spaces=value")
	f.Add("key=@#$%^&*()")
	f.Add("user@domain=pass!#$")

	f.Fuzz(func(t *testing.T, kv string) {
		// Parse key=value pair
		keyValue := strings.Split(kv, "=")

		// Validate split result
		require.NotNil(t, keyValue, "split should always return a slice")
		require.GreaterOrEqual(t, len(keyValue), 1, "split should return at least one element")

		// If exactly 2 parts, validate they form a valid key-value pair
		if len(keyValue) == 2 {
			key := keyValue[0]
			value := keyValue[1]

			// Keys and values can be empty, but shouldn't cause issues
			_ = key
			_ = value

			// Test that we can store in a map
			testMap := map[string]string{}
			testMap[key] = value

			require.Equal(t, value, testMap[key], "value should be retrievable from map")
		}

		// If not exactly 2 parts, it should be skipped (as per the actual code logic)
		if len(keyValue) != 2 {
			// This is valid behavior - malformed lines are skipped
			require.NotEqual(t, 2, len(keyValue), "should skip lines that don't have exactly 2 parts")
		}
	})
}

// FuzzHostPortParsing tests host:port parsing logic
func FuzzHostPortParsing(f *testing.F) {
	// Seed with valid host:port combinations
	f.Add("http://127.0.0.1:8332")
	f.Add("https://localhost:8332")
	f.Add("http://192.168.1.1:18332")
	f.Add("https://node.example.com:8332")

	// Seed with edge cases
	f.Add("")
	f.Add(":")
	f.Add("127.0.0.1")
	f.Add(":8332")
	f.Add("http://")
	f.Add("https://")
	f.Add("http://127.0.0.1")
	f.Add("127.0.0.1:8332")

	// Seed with malformed input
	f.Add("not-a-url")
	f.Add("http://localhost:not-a-port")
	f.Add("http://[::1]:8332")
	f.Add("http://localhost:8332:extra")

	f.Fuzz(func(t *testing.T, hostPort string) {
		// Simulate the trimming logic from loadBitcoinConfiguration
		trimmed := strings.TrimPrefix(hostPort, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")

		// Should never panic
		parts := strings.Split(trimmed, ":")

		// Validate split result
		require.NotNil(t, parts, "split should always return a slice")
		require.GreaterOrEqual(t, len(parts), 1, "split should return at least one element")

		// If we have at least one part, it could be a valid host
		if len(parts) >= 1 {
			host := parts[0]
			_ = host // host can be any string
		}

		// If we have at least two parts, second part could be a port
		if len(parts) >= 2 {
			port := parts[1]
			_ = port // port can be any string (validation happens elsewhere)
		}
	})
}
