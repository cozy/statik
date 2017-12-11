// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fs contains an HTTP file system that works with zip contents.
package fs

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	"camlistore.org/pkg/magic"
)

var assets map[string]*Asset

const sumLen = 10

// Asset holds unzipped read-only file contents and file metadata.
type Asset struct {
	zippedData   []byte
	zippedSize   string
	unzippedData []byte
	unzippedSize string
	etag         string
	name         string
	mime         string
}

func (f *Asset) Etag() string { return f.etag }
func (f *Asset) Name() string { return f.name }
func (f *Asset) Mime() string { return f.mime }

func (f *Asset) Size() string {
	return f.unzippedSize
}
func (f *Asset) Reader() *bytes.Reader {
	return bytes.NewReader(f.unzippedData)
}

func (f *Asset) GzipSize() string {
	return f.zippedSize
}
func (f *Asset) GzipReader() *bytes.Reader {
	return bytes.NewReader(f.zippedData)
}

// Register registers zip contents data, later used to initialize
// the statik file system.
func Register(zipData string) {
	if assets != nil {
		panic("statik/fs: already registered")
	}
	if zipData == "" {
		panic("statik/fs: no zip data registered")
	}
	assets = make(map[string]*Asset)
	if err := unzip([]byte(zipData)); err != nil {
		panic(fmt.Errorf("statik/fs: error unzipping data: %s", err))
	}
}

func unzip(data []byte) (err error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		var zippedData, unzippedData []byte
		zippedData = block.Bytes
		var gr *gzip.Reader
		gr, err = gzip.NewReader(bytes.NewReader(block.Bytes))
		if err != nil {
			return
		}
		h := sha256.New()
		r := io.TeeReader(gr, h)
		unzippedData, err = ioutil.ReadAll(r)
		if err != nil {
			return
		}
		if err = gr.Close(); err != nil {
			return
		}

		name := block.Headers["Name"]
		mime := magic.MIMEType(unzippedData)
		if mime == "" {
			mime = magic.MIMETypeByExtension(path.Ext(name))
		}
		if mime == "" {
			mime = "application/octet-stream"
		}

		sumx := hex.EncodeToString(h.Sum(nil))
		etag := fmt.Sprintf(`"%s"`, sumx[:sumLen])
		nameWithSum := name
		if off := strings.IndexByte(name, '.'); off >= 0 {
			nameWithSum = name[:off] + "." + sumx[:sumLen] + name[off:]
		}

		assets[name] = &Asset{
			zippedData: zippedData,
			zippedSize: strconv.Itoa(len(zippedData)),

			unzippedData: unzippedData,
			unzippedSize: strconv.Itoa(len(unzippedData)),

			etag: etag,
			name: nameWithSum,
			mime: mime,
		}
		data = rest
	}
	return
}

func Get(name string) (*Asset, bool) {
	if assets == nil {
		panic("statik/fs: not registered")
	}
	f, ok := assets[name]
	if ok {
		return f, true
	}
	return nil, false
}

func Open(name string) (*bytes.Reader, error) {
	f, ok := Get(name)
	if ok {
		return f.Reader(), nil
	}
	return nil, os.ErrNotExist
}

func Foreach(predicate func(name string, f *Asset)) {
	for name, f := range assets {
		predicate(name, f)
	}
}
