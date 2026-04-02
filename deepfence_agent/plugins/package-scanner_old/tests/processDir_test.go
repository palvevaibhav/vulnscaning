package main

import (
    "testing"
    "regexp"
    
)

// TestHelloName calls greetings.Hello with a name, checking
// for a valid return value.
func TestHelloName(t *testing.T) {
    ctx := context.Background()

    // Create a temporary root directory
    tmpRoot := t.TempDir()       // tmp directory for sbom output

    config := utils.Config{} // use default config for test

    output, err := ProcessDir(ctx, "/", "/", tmpRoot, config)
    if err != nil {
        t.Fatalf("ProcessDir failed: %v", err)
    }

    // Check if output file exists
    if _, err := os.Stat(output); os.IsNotExist(err) {
        t.Fatalf("Expected output file %s to exist", output)
    }
}
