package skydbstorage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/skynetlabs/certmagic-storage-skydb/skydb"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"gitlab.com/NebulousLabs/errors"
	"go.sia.tech/siad/crypto"
)

const (
	lockTimeoutMinutes  = caddy.Duration(5 * time.Minute)
	lockPollingInterval = caddy.Duration(5 * time.Second)
)

var (
	// The registry doesn't support DELETE as an operation but setting a
	// registry value to an empty version 2 skylink will result in 404 when we
	// try to read from the registry.
	emptyRegistryEntry = [34]byte{}

	// errNotExist is returned when the requested item doesn't exist.
	errNotExist certmagic.ErrNotExist = errors.New("item doesn't exist")
)

// Item holds structure of domain, certificate data,
// and last updated for marshaling with SkyDB
type Item struct {
	PrimaryKey  string    `json:"PrimaryKey"`
	Contents    []byte    `json:"Contents"`
	LastUpdated time.Time `json:"LastUpdated"`
}

// Storage implements certmagic.Storage to facilitate
// storage of certificates in DynamoDB for a clustered environment.
// Also implements certmagic.Locker to facilitate locking
// and unlocking of cert data during storage
type Storage struct {
	SkyDB               skydb.SkyDBI   `json:"-"`
	LockTimeout         caddy.Duration `json:"lock_timeout,omitempty"`
	LockPollingInterval caddy.Duration `json:"lock_polling_interval,omitempty"`
	KeyListDataKey      crypto.Hash    `json:"key_list_data_key"`
}

func NewStorage() (*Storage, error) {
	s := &Storage{}
	err := s.initConfig()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// initConfig initializes configuration for table name and AWS session
func (s *Storage) initConfig() error {
	if s.SkyDB == nil {
		sdb, err := skydb.New()
		if err != nil {
			return err
		}
		s.SkyDB = sdb
	}
	if s.LockTimeout == 0 {
		s.LockTimeout = lockTimeoutMinutes
	}
	if s.LockPollingInterval == 0 {
		s.LockPollingInterval = lockPollingInterval
	}
	if isEmpty(s.KeyListDataKey[:]) {
		s.KeyListDataKey = crypto.HashBytes([]byte("key_list"))
	}
	return nil
}

// Store puts value at key.
func (s *Storage) Store(key string, value []byte) error {
	fmt.Println(" >>> Store ", key)
	if err := s.initConfig(); err != nil {
		return err
	}

	if key == "" {
		return errors.New("key must not be empty")
	}
	// Get the item.
	it, rev, err := s.getItem(key)
	if err != nil && !errors.Contains(err, errNotExist) {
		return err
	}
	keyList, keyListRev, err := s.keyList()
	if err != nil && !errors.Contains(err, skydb.ErrNotFound) {
		return err
	}
	if keyList == nil {
		keyList = make(map[string]bool)
	}

	keyListChanged := false
	// Are we deleting the entry? If so, remove the key from the key list.
	// Otherwise add it to the list.
	if slicesEqual(value, emptyRegistryEntry[:]) {
		delete(keyList, key)
		keyListChanged = true
	} else {
		_, exists := keyList[key]
		if !exists {
			keyList[key] = true
			keyListChanged = true
		}
	}
	if keyListChanged {
		bytes, err := json.Marshal(keyList)
		if err != nil {
			return errors.AddContext(err, "failed to serialise a new key list")
		}
		err = s.SkyDB.Write(bytes, s.KeyListDataKey, keyListRev+1)
		if err != nil {
			return errors.AddContext(err, "failed to store the key list")
		}
	}

	// Update the item.
	it.PrimaryKey = key
	it.Contents = value
	it.LastUpdated = time.Now().UTC()
	// Store the key's new value
	bytes, err := json.Marshal(it)
	if err != nil {
		return errors.AddContext(err, "failed to marshal the item record")
	}
	dataKey := crypto.HashBytes([]byte(key))
	return s.SkyDB.Write(bytes, dataKey, rev+1)
}

// Load retrieves the value at key.
func (s *Storage) Load(key string) ([]byte, error) {
	fmt.Println(" >>> Load ", key)
	if err := s.initConfig(); err != nil {
		return []byte{}, err
	}

	if key == "" {
		return []byte{}, errors.New("key must not be empty")
	}

	domainItem, _, err := s.getItem(key)
	if err != nil {
		return []byte{}, err
	}
	fmt.Println(" >>> Load ", key, string(domainItem.Contents))
	return domainItem.Contents, err
}

// Delete deletes key.
func (s *Storage) Delete(key string) error {
	fmt.Println(" >>> Delete ", key)
	return s.Store(key, emptyRegistryEntry[:])
}

// Exists returns true if the key exists
// and there was no error checking.
func (s *Storage) Exists(key string) bool {
	cert, err := s.Load(key)
	if err == nil && !isEmpty(cert[:]) {
		return true
	}
	return false
}

// List returns all keys that match prefix.
// If recursive is true, non-terminal keys
// will be enumerated (i.e. "directories"
// should be walked); otherwise, only keys
// prefixed exactly by prefix will be listed.
func (s *Storage) List(prefix string, _ bool) ([]string, error) {
	fmt.Println(" >>> List ", prefix)
	if err := s.initConfig(); err != nil {
		return []string{}, err
	}

	if prefix == "" {
		return []string{}, errors.New("key prefix must not be empty")
	}

	keyList, _, err := s.keyList()
	if err != nil && errors.Contains(err, skydb.ErrNotFound) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}

	var matchingKeys []string
	for key := range keyList {
		if strings.HasPrefix(key, prefix) {
			matchingKeys = append(matchingKeys, key)
		}
	}
	fmt.Printf(" >>> List %s, %v\n", prefix, matchingKeys)
	return matchingKeys, nil
}

// Stat returns information about key.
func (s *Storage) Stat(key string) (certmagic.KeyInfo, error) {
	fmt.Println(" >>> Stat ", key)
	domainItem, _, err := s.getItem(key)
	if err != nil && !errors.Contains(err, errNotExist) {
		return certmagic.KeyInfo{}, nil
	}
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	ki := certmagic.KeyInfo{
		Key:        key,
		Modified:   domainItem.LastUpdated,
		Size:       int64(len(domainItem.Contents)),
		IsTerminal: true,
	}
	fmt.Printf(" >>> Stat %s: %+v\n", key, ki)
	return ki, nil
}

// Lock acquires the lock for key, blocking until the lock
// can be obtained or an error is returned. Note that, even
// after acquiring a lock, an idempotent operation may have
// already been performed by another process that acquired
// the lock before - so always check to make sure idempotent
// operations still need to be performed after acquiring the
// lock.
//
// The actual implementation of obtaining of a lock must be
// an atomic operation so that multiple Lock calls at the
// same time always results in only one caller receiving the
// lock at any given time.
//
// To prevent deadlocks, all implementations (where this concern
// is relevant) should put a reasonable expiration on the lock in
// case Unlock is unable to be called due to some sort of network
// failure or system crash.
func (s *Storage) Lock(ctx context.Context, key string) error {
	fmt.Println(" >>> Lock ", key)
	if err := s.initConfig(); err != nil {
		return err
	}

	lockKey := fmt.Sprintf("LOCK-%s", key)

	// Check for existing lock
	var it Item
	var rev uint64
	var err error
	for {
		it, rev, err = s.getItem(lockKey)
		if err != nil && !errors.Contains(err, errNotExist) {
			return err
		}
		// if lock doesn't exist or is empty, break to create a new one
		if isEmpty(it.Contents) {
			break
		}
		// Lock exists, check if expired or sleep 5 seconds and check again
		expires, err := time.Parse(time.RFC3339, string(it.Contents))
		if err != nil {
			return err
		}
		if time.Now().After(expires) {
			if err := s.Unlock(key); err != nil {
				return err
			}
			break
		}

		select {
		case <-time.After(time.Duration(s.LockPollingInterval)):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// lock doesn't exist, create it
	contents := []byte(time.Now().Add(time.Duration(s.LockTimeout)).Format(time.RFC3339))

	it.PrimaryKey = lockKey
	it.Contents = contents
	it.LastUpdated = time.Now().UTC()
	bytes, err := json.Marshal(it)
	if err != nil {
		return errors.AddContext(err, "failed to marshal the item record")
	}
	dataKey := crypto.HashBytes([]byte(it.PrimaryKey))
	return s.SkyDB.Write(bytes, dataKey, rev+1)

	//return s.Store(lockKey, contents)
}

// Unlock releases the lock for key. This method must ONLY be
// called after a successful call to Lock, and only after the
// critical section is finished, even if it errored or timed
// out. Unlock cleans up any resources allocated during Lock.
func (s *Storage) Unlock(key string) error {
	fmt.Println(" >>> Unlock ", key)
	if err := s.initConfig(); err != nil {
		return err
	}

	lockKey := fmt.Sprintf("LOCK-%s", key)
	it, rev, err := s.getItem(lockKey)
	if err != nil && !errors.Contains(err, errNotExist) {
		return err
	}
	// if lock doesn't exist or is empty, break to create a new one
	if isEmpty(it.Contents) {
		return nil
	}
	it.PrimaryKey = lockKey
	it.Contents = emptyRegistryEntry[:]
	it.LastUpdated = time.Now().UTC()
	bytes, err := json.Marshal(it)
	if err != nil {
		return errors.AddContext(err, "failed to marshal the item record")
	}
	dataKey := crypto.HashBytes([]byte(it.PrimaryKey))
	return s.SkyDB.Write(bytes, dataKey, rev+1)
	//return s.Delete(lockKey)
}

// getItem fetches an ItemRecord from SkyDB.
func (s *Storage) getItem(key string) (Item, uint64, error) {
	fmt.Println(" >>> getItem:", key)
	dataKey := crypto.HashBytes([]byte(key))
	data, rev, err := s.SkyDB.Read(dataKey)
	// The string check is annoying and probably unnecessary but I want to get this working.
	if err != nil && (errors.Contains(err, skydb.ErrNotFound) || strings.Contains(err.Error(), "registry entry not found")) {
		return Item{}, 0, errNotExist
	}
	if err != nil {
		return Item{}, 0, err
	}
	// Check if `data` is empty, i.e. the item never existed.
	if isEmpty(data) {
		return Item{}, 0, errNotExist
	}
	var it Item
	err = json.Unmarshal(data, &it)
	if err != nil {
		return Item{}, 0, err
	}
	fmt.Printf(" >>> getItem: %s, %+v, %d\n", key, it, rev)
	return it, rev, nil
}

func (s *Storage) keyList() (map[string]bool, uint64, error) {
	fmt.Println(" >>> Fetching keylist. DataKey: " + string(s.KeyListDataKey[:]))
	keyList := make(map[string]bool)
	klData, rev, err := s.SkyDB.Read(s.KeyListDataKey)
	if err != nil {
		return nil, 0, errors.AddContext(err, "failed to get key list from SkyDB")
	}
	if !isEmpty(klData) {
		err = json.Unmarshal(klData, &keyList)
		if err != nil {
			return nil, 0, errors.AddContext(err, "failed to unmarshal key list")
		}
	}
	fmt.Printf(">>> Keylist: %+v\n", keyList)
	return keyList, rev, nil
}

func isEmpty(data []byte) bool {
	for _, v := range data {
		if v > 0 {
			return false
		}
	}
	return true
}

func slicesEqual(s1, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

// Interface guard
var _ certmagic.Storage = (*Storage)(nil)
