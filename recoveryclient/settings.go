package recoveryclient

import "errors"

// ErrNotFound is what Settings.Get returns for a key never written. Products map their
// store's not-found error onto it; a key deliberately set to "" is not ErrNotFound.
var ErrNotFound = errors.New("recoveryclient: setting not found")

// Settings is the slice of the product's key-value store this package needs. The keys it
// writes are: kyrecovery_key_id, kyrecovery_threshold, kyrecovery_total_shares,
// kyrecovery_url, kyrecovery_token_enc, kyrecovery_last_deposit, backup_interval_sec,
// backup_last_attempt.
type Settings interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}
