// Copyright 2014 The rkt Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package keystore implements the ACI keystore.
package keystore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/spec/schema/types"
	"github.com/coreos/rkt/Godeps/_workspace/src/golang.org/x/crypto/openpgp"
	"github.com/coreos/rkt/common"
)

// A Config structure is used to configure a Keystore.
type Config struct {
	LocalRootPath    string
	LocalPrefixPath  string
	SystemRootPath   string
	SystemPrefixPath string
}

// A Keystore represents a repository of trusted public keys which can be
// used to verify PGP signatures.
type Keystore struct {
	*Config
}

// New returns a new Keystore based on config.
func New(config *Config) *Keystore {
	if config == nil {
		config = defaultConfig
	}
	return &Keystore{config}
}

func NewConfig(systemPath, localPath string) *Config {
	return &Config{
		LocalRootPath:    filepath.Join(localPath, "trustedkeys", "root.d"),
		LocalPrefixPath:  filepath.Join(localPath, "trustedkeys", "prefix.d"),
		SystemRootPath:   filepath.Join(systemPath, "trustedkeys", "root.d"),
		SystemPrefixPath: filepath.Join(systemPath, "trustedkeys", "prefix.d"),
	}
}

var defaultConfig = NewConfig(common.DefaultSystemConfigDir, common.DefaultLocalConfigDir)

// CheckSignature is a convenience method for creating a Keystore with a default
// configuration and invoking CheckSignature.
func CheckSignature(prefix string, signed, signature io.ReadSeeker) (*openpgp.Entity, error) {
	ks := New(defaultConfig)
	return checkSignature(ks, prefix, signed, signature)
}

// CheckSignature takes a signed file and a detached signature and returns the signer
// if the signature is signed by a trusted signer.
// If the signer is unknown or not trusted, opengpg.ErrUnknownIssuer is returned.
func (ks *Keystore) CheckSignature(prefix string, signed, signature io.ReadSeeker) (*openpgp.Entity, error) {
	return checkSignature(ks, prefix, signed, signature)
}

func checkSignature(ks *Keystore, prefix string, signed, signature io.ReadSeeker) (*openpgp.Entity, error) {
	acidentifier, err := types.NewACIdentifier(prefix)
	if err != nil {
		return nil, err
	}
	keyring, err := ks.loadKeyring(acidentifier.String())
	if err != nil {
		return nil, fmt.Errorf("keystore: error loading keyring %v", err)
	}
	entities, err := openpgp.CheckArmoredDetachedSignature(keyring, signed, signature)
	if err == io.EOF {
		// When the signature is binary instead of armored, the error is io.EOF.
		// Let's try with binary signatures as well
		if _, err := signed.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("error seeking ACI file: %v", err)
		}
		if _, err := signature.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("error seeking signature file: %v", err)
		}
		entities, err = openpgp.CheckDetachedSignature(keyring, signed, signature)
	}
	if err == io.EOF {
		// otherwise, the client failure is just "EOF", which is not helpful
		return nil, fmt.Errorf("keystore: no valid signatures found in signature file")
	}
	return entities, err
}

// DeleteTrustedKeyPrefix deletes the prefix trusted key identified by fingerprint.
func (ks *Keystore) DeleteTrustedKeyPrefix(prefix, fingerprint string) error {
	acidentifier, err := types.NewACIdentifier(prefix)
	if err != nil {
		return err
	}
	return os.Remove(path.Join(ks.LocalPrefixPath, acidentifier.String(), fingerprint))
}

// MaskTrustedKeySystemPrefix masks the system prefix trusted key identified by fingerprint.
func (ks *Keystore) MaskTrustedKeySystemPrefix(prefix, fingerprint string) (string, error) {
	acidentifier, err := types.NewACIdentifier(prefix)
	if err != nil {
		return "", err
	}
	dst := path.Join(ks.LocalPrefixPath, acidentifier.String(), fingerprint)
	return dst, ioutil.WriteFile(dst, []byte(""), 0644)
}

// DeleteTrustedKeyRoot deletes the root trusted key identified by fingerprint.
func (ks *Keystore) DeleteTrustedKeyRoot(fingerprint string) error {
	return os.Remove(path.Join(ks.LocalRootPath, fingerprint))
}

// MaskTrustedKeySystemRoot masks the system root trusted key identified by fingerprint.
func (ks *Keystore) MaskTrustedKeySystemRoot(fingerprint string) (string, error) {
	dst := path.Join(ks.LocalRootPath, fingerprint)
	return dst, ioutil.WriteFile(dst, []byte(""), 0644)
}

func (ks *Keystore) TrustedKeyPrefixExists(prefix string, r io.ReadSeeker) (bool, error) {
	defer r.Seek(0, os.SEEK_SET)

	entityList, err := openpgp.ReadArmoredKeyRing(r)
	if err != nil {
		return false, err
	}
	if len(entityList) < 1 {
		return false, errors.New("missing opengpg entity")
	}
	pubKey := entityList[0].PrimaryKey
	fileName := fingerprintToFilename(pubKey.Fingerprint)

	pathNamesRoot := []string{
		// example: /etc/rkt/trustedkeys/root.d/8b86de38890ddb7291867b025210bd8888182190
		path.Join(ks.LocalRootPath, fileName),
		// example: /usr/lib/rkt/trustedkeys/root.d/8b86de38890ddb7291867b025210bd8888182190
		path.Join(ks.SystemRootPath, fileName),
	}

	var pathNamesPrefix []string
	if prefix != "" {
		acidentifier, err := types.NewACIdentifier(prefix)
		if err != nil {
			return false, err
		}
		pathNamesPrefix = []string{
			// example: /etc/rkt/trustedkeys/prefix.d/coreos.com/etcd/8b86de38890ddb7291867b025210bd8888182190
			path.Join(ks.LocalPrefixPath, acidentifier.String(), fileName),
			// example: /usr/lib/rkt/trustedkeys/prefix.d/coreos.com/etcd/8b86de38890ddb7291867b025210bd8888182190
			path.Join(ks.SystemPrefixPath, acidentifier.String(), fileName),
		}
	}

	pathNames := append(pathNamesRoot, pathNamesPrefix...)
	for _, p := range pathNames {
		_, err := os.Stat(p)
		if err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, fmt.Errorf("cannot check file %q: %v", p, err)
		}
	}

	return false, nil
}

// StoreTrustedKeyPrefix stores the contents of public key r as a prefix trusted key.
func (ks *Keystore) StoreTrustedKeyPrefix(prefix string, r io.Reader) (string, error) {
	acidentifier, err := types.NewACIdentifier(prefix)
	if err != nil {
		return "", err
	}
	return storeTrustedKey(path.Join(ks.LocalPrefixPath, acidentifier.String()), r)
}

// StoreTrustedKeyRoot stores the contents of public key r as a root trusted key.
func (ks *Keystore) StoreTrustedKeyRoot(r io.Reader) (string, error) {
	return storeTrustedKey(ks.LocalRootPath, r)
}

func storeTrustedKey(dir string, r io.Reader) (string, error) {
	pubkeyBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pubkeyBytes))
	if err != nil {
		return "", err
	}
	if len(entityList) < 1 {
		return "", errors.New("missing opengpg entity")
	}
	pubKey := entityList[0].PrimaryKey
	trustedKeyPath := path.Join(dir, fingerprintToFilename(pubKey.Fingerprint))
	if err := ioutil.WriteFile(trustedKeyPath, pubkeyBytes, 0644); err != nil {
		return "", err
	}
	return trustedKeyPath, nil
}

func entityFromFile(path string) (*openpgp.Entity, error) {
	trustedKey, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer trustedKey.Close()
	entityList, err := openpgp.ReadArmoredKeyRing(trustedKey)
	if err != nil {
		return nil, err
	}
	if len(entityList) < 1 {
		return nil, errors.New("missing opengpg entity")
	}
	fingerprint := fingerprintToFilename(entityList[0].PrimaryKey.Fingerprint)
	keyFile := filepath.Base(trustedKey.Name())
	if fingerprint != keyFile {
		return nil, fmt.Errorf("fingerprint mismatch: %q:%q", keyFile, fingerprint)
	}
	return entityList[0], nil
}

func (ks *Keystore) loadKeyring(prefix string) (openpgp.KeyRing, error) {
	acidentifier, err := types.NewACIdentifier(prefix)
	if err != nil {
		return nil, err
	}
	var keyring openpgp.EntityList
	trustedKeys := make(map[string]*openpgp.Entity)

	prefixRoot := strings.Split(acidentifier.String(), "/")[0]
	paths := []struct {
		root     string
		fullPath string
	}{
		{ks.SystemRootPath, ks.SystemRootPath},
		{ks.LocalRootPath, ks.LocalRootPath},
		{path.Join(ks.SystemPrefixPath, prefixRoot), path.Join(ks.SystemPrefixPath, acidentifier.String())},
		{path.Join(ks.LocalPrefixPath, prefixRoot), path.Join(ks.LocalPrefixPath, acidentifier.String())},
	}
	for _, p := range paths {
		err := filepath.Walk(p.root, func(path string, info os.FileInfo, err error) error {
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if info == nil {
				return nil
			}
			if info.IsDir() {
				switch {
				case strings.HasPrefix(p.fullPath, path):
					return nil
				default:
					return filepath.SkipDir
				}
			}
			// Remove trust for default keys.
			if info.Size() == 0 {
				delete(trustedKeys, info.Name())
				return nil
			}
			entity, err := entityFromFile(path)
			if err != nil {
				return err
			}
			trustedKeys[fingerprintToFilename(entity.PrimaryKey.Fingerprint)] = entity
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	for _, v := range trustedKeys {
		keyring = append(keyring, v)
	}
	return keyring, nil
}

func fingerprintToFilename(fp [20]byte) string {
	return fmt.Sprintf("%x", fp)
}

// NewTestKeystore creates a new KeyStore backed by a temp directory.
// NewTestKeystore returns a KeyStore, the path to the temp directory, and
// an error if any.
func NewTestKeystore() (*Keystore, string, error) {
	dir, err := ioutil.TempDir("", "keystore-test")
	if err != nil {
		return nil, "", err
	}
	systemDir := filepath.Join(dir, common.DefaultSystemConfigDir)
	localDir := filepath.Join(dir, common.DefaultLocalConfigDir)
	c := NewConfig(systemDir, localDir)
	for _, path := range []string{c.LocalRootPath, c.SystemRootPath, c.LocalPrefixPath, c.SystemPrefixPath} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, "", err
		}
	}
	return New(c), dir, nil
}
