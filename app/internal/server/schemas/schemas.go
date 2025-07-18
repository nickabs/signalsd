package schemas

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	signalsd "github.com/information-sharing-networks/signalsd/app"
	"github.com/information-sharing-networks/signalsd/app/internal/database"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func SkipValidation(url string) bool {
	return url == signalsd.SkipValidationURL
}

// stores compiled JSON schemas indexed by signal type path: {signal_type_slug}/v{sem_ver}
type schemaCache struct {
	schemas    map[string]*jsonschema.Schema
	schemaURLs map[string]string // tracks schema URLs for each signal type path
}

// signal types can be added while the signals handler is running, so...
// the validateSignal function will refresh the cache when encountering an uncached Signal Type.
// the schemaMutex protects the cache from concurrent access when multiple http go routines are validating signals
var (
	cache      *schemaCache
	cacheMutex sync.RWMutex
)

// ValidateAndCompileSchema validates schema content and returns the compiled schema
func ValidateAndCompileSchema(schemaURL, content string) (*jsonschema.Schema, error) {
	// check if it's valid JSON
	var jsonData any
	if err := json.Unmarshal([]byte(content), &jsonData); err != nil {
		return nil, fmt.Errorf("schema content is not valid JSON: %v", err)
	}

	// Compile the schema (this also validates it)
	schema, err := jsonschema.CompileString(schemaURL, content)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON Schema format: %w", err)
	}
	return schema, nil
}

// LoadSchemaCache loads schemas from database and compiles them into memory cache
func LoadSchemaCache(ctx context.Context, queries *database.Queries) error {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	return refreshCache(ctx, queries)
}

// ValidateSignal validates signal JSON content against its schema
// Automatically refreshes schema cache if the signal type is not found
func ValidateSignal(ctx context.Context, queries *database.Queries, signalTypePath string, rawJSON json.RawMessage) error {
	// Try cache first
	cacheMutex.RLock()
	if cache != nil {
		if schemaURL, exists := cache.schemaURLs[signalTypePath]; exists {
			if SkipValidation(schemaURL) {
				cacheMutex.RUnlock()
				return nil
			}
			if schema, exists := cache.schemas[signalTypePath]; exists {
				cacheMutex.RUnlock()
				// Validate with cached schema
				var data any
				if err := json.Unmarshal(rawJSON, &data); err != nil {
					return fmt.Errorf("invalid JSON format: %v", err)
				}
				if err := schema.Validate(data); err != nil {
					return fmt.Errorf("schema validation failed: %w", err)
				}
				return nil // valid json confirmed
			}
		}
	}
	cacheMutex.RUnlock()

	// Schema not in cache, refresh cache
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// Refresh entire cache from database
	if err := refreshCache(ctx, queries); err != nil {
		return fmt.Errorf("failed to refresh schema cache: %w", err)
	}

	// Try validation with refreshed cache
	if cache != nil {
		if schemaURL, exists := cache.schemaURLs[signalTypePath]; exists {
			if SkipValidation(schemaURL) {
				return nil
			}
			if schema, exists := cache.schemas[signalTypePath]; exists {
				// Validate with refreshed schema
				var data any
				if err := json.Unmarshal(rawJSON, &data); err != nil {
					return fmt.Errorf("invalid JSON format: %v", err)
				}
				if err := schema.Validate(data); err != nil {
					return fmt.Errorf("schema validation failed: %w", err)
				}
				return nil
			}
		}
	}

	// Schema still not found after refresh
	return fmt.Errorf("signal type not found: %s", signalTypePath)
}

// refreshCache refreshes the cache from database (caller must hold write lock)
func refreshCache(ctx context.Context, queries *database.Queries) error {
	// Initialize the cache if needed
	if cache == nil {
		cache = &schemaCache{
			schemas:    make(map[string]*jsonschema.Schema),
			schemaURLs: make(map[string]string),
		}
	}

	signalTypes, err := queries.GetSignalTypes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get signal types from database: %w", err)
	}

	// Clear existing cache and rebuild
	cache.schemas = make(map[string]*jsonschema.Schema)
	cache.schemaURLs = make(map[string]string)

	var loadErrors []string

	for _, signalType := range signalTypes {
		// Create signal type path as cache key
		signalTypePath := fmt.Sprintf("%s/v%s", signalType.Slug, signalType.SemVer)

		// Compile the schema from the stored content
		schema, err := jsonschema.CompileString(signalType.SchemaURL, signalType.SchemaContent)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("signal type %s: %v", signalTypePath, err))
		} else {
			cache.schemas[signalTypePath] = schema
			// Store the schema URL for this signal type path
			cache.schemaURLs[signalTypePath] = signalType.SchemaURL
		}
	}

	if len(loadErrors) > 0 {
		return fmt.Errorf("failed to load some schemas: %s", strings.Join(loadErrors, "; "))
	}

	return nil
}
