package skydb

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"gitlab.com/NebulousLabs/errors"
	"gitlab.com/SkynetLabs/skyd/node/api/client"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"gitlab.com/SkynetLabs/skyd/skymodules/renter"
	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/types"
)

var (
	// ErrNotFound is returned when an entry is not found.
	ErrNotFound = errors.New("skydb entry not found")
)

// SkyDBI is the interface for communicating with SkyDB. We use an interface, so
// we can easily override it for testing purposes.
type SkyDBI interface {
	Read(crypto.Hash) ([]byte, uint64, error)
	Write(data []byte, dataKey crypto.Hash, rev uint64) error
}

type SkyDB struct {
	Client *client.Client
	sk     crypto.SecretKey
	pk     crypto.PublicKey
}

// New creates a new SkyDB client with default option.
// The default options are to look for a skyd node at localhost:9980,
// to use "Sia-Agent" as user agent and to get the password for skyd from the
// environment.
func New() (*SkyDB, error) {
	entropy, err := EntropyFromEnv()
	if err != nil {
		return nil, err
	}
	sk, pk := crypto.GenerateKeyPairDeterministic(entropy)
	skydEndpoint := os.Getenv("CADDY_SKYDB_ENDPOINT")
	if skydEndpoint == "" {
		return nil, errors.New("missing CADDY_SKYDB_ENDPOINT environment variable")
	}
	opts, err := client.DefaultOptions()
	if err != nil {
		return nil, errors.AddContext(err, "failed to get default client options")
	}
	opts.Address = skydEndpoint
	skydb := &SkyDB{
		Client: &client.Client{Options: opts},
		sk:     sk,
		pk:     pk,
	}
	return skydb, nil
}

// Read retrieves from SkyDB the data that corresponds to the given key set.
func (db SkyDB) Read(dataKey crypto.Hash) ([]byte, uint64, error) {
	waitUntilSkydReady(db.Client)
	s, rev, err := registryRead(db.Client, db.pk, dataKey)
	// This error string covers both "not found" and "not found in time".
	if err != nil && (strings.Contains(err.Error(), renter.ErrRegistryEntryNotFound.Error()) || strings.Contains(err.Error(), renter.ErrRegistryLookupTimeout.Error())) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, errors.AddContext(err, "skydb failed to read from registry")
	}
	b, err := db.Client.SkynetSkylinkGet(s.String())
	if err != nil && strings.Contains(err.Error(), renter.ErrRootNotFound.Error()) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, errors.AddContext(err, "failed to download data from Skynet")
	}
	return b, rev, nil
}

// Write stores the given `data` in SkyDB under the given key set.
func (db SkyDB) Write(data []byte, dataKey crypto.Hash, rev uint64) error {
	waitUntilSkydReady(db.Client)
	skylink, err := uploadData(db.Client, data)
	if err != nil {
		return errors.AddContext(err, "failed to upload data")
	}
	_, err = registryWrite(db.Client, skylink, db.sk, db.pk, dataKey, rev)
	if err != nil {
		return errors.AddContext(err, "failed to write to the registry")
	}
	return nil
}

// EntropyFromEnv returns the configured value of the CADDY_SKYDB_ENTROPY environment
// variable or an error.
func EntropyFromEnv() (crypto.Hash, error) {
	var e crypto.Hash
	eStr := os.Getenv("CADDY_SKYDB_ENTROPY")
	if eStr == "" {
		return e, errors.New("missing or empty CADDY_SKYDB_ENTROPY environment variable. it needs to contain 32 bytes of base64 encoded entropy.")
	}
	eBytes, err := base64.StdEncoding.DecodeString(eStr)
	if err != nil || len(eBytes) != 32 {
		return e, fmt.Errorf("invalid CADDY_SKYDB_ENTROPY environment variable. it needs to contain 32 bytes of base64 encoded entropy. error: %v", err)
	}
	copy(e[:], eBytes)
	return e, nil
}

// registryWrite updates the registry entry with the given dataKey to contain the
// given skylink. Returns a SkylinkV2.
func registryWrite(c *client.Client, skylink string, sk crypto.SecretKey, pk crypto.PublicKey, dataKey crypto.Hash, rev uint64) (skymodules.Skylink, error) {
	var sl skymodules.Skylink
	err := sl.LoadString(skylink)
	if err != nil {
		return skymodules.Skylink{}, errors.AddContext(err, "failed to load skylink data")
	}
	// Update the registry with that link.
	spk := types.Ed25519PublicKey(pk)
	srv := modules.NewRegistryValue(dataKey, sl.Bytes(), rev, modules.RegistryTypeWithoutPubkey).Sign(sk)
	err = c.RegistryUpdate(spk, dataKey, srv.Revision, srv.Signature, sl)
	if err != nil {
		return skymodules.Skylink{}, err
	}
	return skymodules.NewSkylinkV2(spk, dataKey), nil
}

// registryRead reads a registry entry and returns the SkylinkV2 it contains, as well
// as the revision.
func registryRead(c *client.Client, pk crypto.PublicKey, dataKey crypto.Hash) (skymodules.Skylink, uint64, error) {
	spk := types.Ed25519PublicKey(pk)
	srv, err := c.RegistryRead(spk, dataKey)
	if err != nil {
		return skymodules.Skylink{}, 0, errors.AddContext(err, "failed to read from the registry")
	}
	err = srv.Verify(pk)
	if err != nil {
		return skymodules.Skylink{}, 0, errors.AddContext(err, "the value we read failed validation")
	}
	var sl skymodules.Skylink
	err = sl.LoadBytes(srv.Data)
	if err != nil {
		return skymodules.Skylink{}, 0, errors.AddContext(err, "registry value is not a valid skylink")
	}
	return sl, srv.Revision, nil
}

// uploadData uploads the given data to skynet and returns a SkylinkV1.
func uploadData(c *client.Client, content []byte) (string, error) {
	sup := &skymodules.SkyfileUploadParameters{
		SiaPath:  skymodules.RandomSkynetFilePath(),
		Filename: "data.json",
		Force:    true,
		Mode:     skymodules.DefaultFilePerm,
		Reader:   bytes.NewReader(content),
	}
	skylink, _, err := c.SkynetSkyfilePost(*sup)
	if err != nil {
		return "", errors.AddContext(err, "failed to upload")
	}
	return skylink, nil
}

// waitUntilSkydReady checks the /daemon/ready endpoint and waits until skyd is
// fully ready
func waitUntilSkydReady(c *client.Client) {
	for {
		dr, err := c.DaemonReadyGet()
		if err == nil && dr.Ready && dr.Renter {
			break
		}
		fmt.Println("skyd is not ready, yet. Waiting...")
		time.Sleep(time.Second)
	}
}
