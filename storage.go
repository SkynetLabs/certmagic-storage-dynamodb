package skydbstorage

import (
	"context"
	"encoding/json"
	"fmt"
	"gitlab.com/SkynetLabs/skyd/skymodules/renter"
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

	// keylistModificationAttempts defines how many times we will try to change
	// the keylist before giving up.
	keylistModificationAttempts = 5
	// keylistModificationSleep defines how long we're going to wait between
	// modification attempts.
	keylistModificationSleep = 3 * time.Second
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
	err := s.initConfig()
	if err != nil {
		return err
	}

	if key == "" {
		return errors.New("key must not be empty")
	}
	// Are we deleting the entry? If we're not deleting item then we're adding item.
	isDeletion := slicesEqual(value, emptyRegistryEntry[:])
	// Modifying the keylist might fail because somebody else has locked item.
	// We will retry several times.
	for triesLeft := keylistModificationAttempts; triesLeft > 0; triesLeft-- {
		if isDeletion {
			err = s.keyListDelete(key)
		} else {
			err = s.keyListAdd(key)
		}
		if err == nil {
			break
		}
		if triesLeft > 0 {
			fmt.Println("failed to modify keylist, will try again. error:", err)
		}
		time.Sleep(keylistModificationSleep)
	}
	if err != nil {
		return errors.AddContext(err, "failed to modify keylist")
	}

	// Get the item in order to get its revision.
	_, rev, err := s.getItem(key)
	if err != nil && !errors.Contains(err, errNotExist) {
		return err
	}
	return s.writeItem(key, value, rev+1)
}

// Load retrieves the value at key.
func (s *Storage) Load(key string) ([]byte, error) {
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
	return domainItem.Contents, err
}

// Delete deletes key.
func (s *Storage) Delete(key string) error {
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
	return matchingKeys, nil
}

// Stat returns information about key.
func (s *Storage) Stat(key string) (certmagic.KeyInfo, error) {
	domainItem, _, err := s.getItem(key)
	if err != nil && !errors.Contains(err, errNotExist) {
		return certmagic.KeyInfo{}, nil
	}
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   domainItem.LastUpdated,
		Size:       int64(len(domainItem.Contents)),
		IsTerminal: true,
	}, nil
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
	if err := s.initConfig(); err != nil {
		return err
	}

	lockKey := fmt.Sprintf("LOCK-%s", key)

	// Check for existing lock
	var item Item
	var rev uint64
	var err error
	for {
		item, rev, err = s.getItem(lockKey)
		if err != nil && !errors.Contains(err, errNotExist) {
			return err
		}
		// if lock doesn't exist or is empty, break to create a new one
		if isEmpty(item.Contents) {
			break
		}
		// Lock exists, check if expired or sleep 5 seconds and check again
		expires, err := time.Parse(time.RFC3339, string(item.Contents))
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

	// lock doesn't exist, create item
	contents := []byte(time.Now().Add(time.Duration(s.LockTimeout)).Format(time.RFC3339))
	return s.writeItem(lockKey, contents, rev+1)
}

// Unlock releases the lock for key. This method must ONLY be
// called after a successful call to Lock, and only after the
// critical section is finished, even if it errored or timed
// out. Unlock cleans up any resources allocated during Lock.
func (s *Storage) Unlock(key string) error {
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
	return s.writeItem(lockKey, emptyRegistryEntry[:], rev+1)
}

// getItem fetches an ItemRecord from SkyDB.
func (s *Storage) getItem(key string) (Item, uint64, error) {
	dataKey := crypto.HashBytes([]byte(key))
	data, rev, err := s.SkyDB.Read(dataKey)
	// The string check is annoying and probably unnecessary but I want to get this working.
	if errNotFound(err) {
		return Item{}, 0, errNotExist
	}
	if err != nil {
		return Item{}, 0, err
	}
	// Check if `data` is empty, i.e. the item never existed.
	if isEmpty(data) {
		return Item{}, 0, errNotExist
	}
	var item Item
	err = json.Unmarshal(data, &item)
	if err != nil {
		return Item{}, 0, err
	}
	return item, rev, nil
}

func (s *Storage) keyList() (map[string]bool, uint64, error) {
	keyList := make(map[string]bool)
	klData, rev, err := s.SkyDB.Read(s.KeyListDataKey)
	if err != nil && !errNotFound(err) {
		return nil, 0, errors.AddContext(err, "failed to get key list from SkyDB")
	}
	if !isEmpty(klData) {
		err = json.Unmarshal(klData, &keyList)
		if err != nil {
			return nil, 0, errors.AddContext(err, "failed to unmarshal key list")
		}
	}
	return keyList, rev, nil
}

// keyListAdd adds the given key to the keylist
func (s *Storage) keyListAdd(key string) error {
	keyList, keyListRev, err := s.keyList()
	if err != nil && !errNotFound(err) {
		return err
	}
	if keyList == nil {
		keyList = make(map[string]bool)
	}
	// If the key is already in the keylist there's nothing to do.
	if _, exists := keyList[key]; exists {
		return nil
	}
	keyList[key] = true
	bytes, err := json.Marshal(keyList)
	if err != nil {
		return errors.AddContext(err, "failed to serialise the new key list")
	}
	err = s.SkyDB.Write(bytes, s.KeyListDataKey, keyListRev+1)
	if err != nil {
		return errors.AddContext(err, "failed to store the key list")
	}
	return nil
}

// keyListDelete deletes the given key from the keylist
func (s *Storage) keyListDelete(key string) error {
	keyList, keyListRev, err := s.keyList()
	if err != nil && !errNotFound(err) {
		return err
	}
	// If the keylist is empty there's nothing to do.
	if keyList == nil {
		return nil
	}
	// If the key is not in the keylist there's nothing to do.
	if _, exists := keyList[key]; !exists {
		return nil
	}
	delete(keyList, key)
	bytes, err := json.Marshal(keyList)
	if err != nil {
		return errors.AddContext(err, "failed to serialise the new key list")
	}
	err = s.SkyDB.Write(bytes, s.KeyListDataKey, keyListRev+1)
	if err != nil {
		return errors.AddContext(err, "failed to store the key list")
	}
	return nil
}

// writeItem is a helper that writes a new item to SkyDB.
func (s *Storage) writeItem(pk string, contents []byte, rev uint64) error {
	item := Item{
		PrimaryKey:  pk,
		Contents:    contents,
		LastUpdated: time.Now().UTC(),
	}
	bytes, err := json.Marshal(item)
	if err != nil {
		return errors.AddContext(err, "failed to marshal the item record")
	}
	dataKey := crypto.HashBytes([]byte(item.PrimaryKey))
	return s.SkyDB.Write(bytes, dataKey, rev+1)
}

// errNotFound checks the various failure modes of the registry which all mean
// that the entry was not found.
func errNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Contains(err, skydb.ErrNotFound) ||
		errors.Contains(err, renter.ErrRegistryEntryNotFound) ||
		errors.Contains(err, renter.ErrRegistryLookupTimeout)
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
