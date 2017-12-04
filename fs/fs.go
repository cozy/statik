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
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"strconv"
	"strings"

	"camlistore.org/pkg/magic"
)

const sumLen = 9

// file holds unzipped read-only file contents and file metadata.
type file struct {
	infos os.FileInfo
	data  []byte
	size  string
	etag  string
	name  string
	mime  string
}

var files map[string]*file

// Register registers zip contents data, later used to initialize
// the statik file system.
func Register(zipData string) {
	if files != nil {
		panic("statik/fs: already registered")
	}
	if zipData == "" {
		panic("statik/fs: no zip data registered")
	}
	zipReader, err := zip.NewReader(strings.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		panic(fmt.Errorf("statik/fs: %s", err))
	}
	files = make(map[string]*file)
	for _, zipFile := range zipReader.File {
		f, err := unzip(zipFile)
		if err != nil {
			panic(fmt.Errorf("statik/fs: error unzipping file %q: %s", zipFile.Name, err))
		}
		files[zipFile.Name] = f
	}
}

func unzip(zf *zip.File) (*file, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	mime, r := magic.MIMETypeFromReader(rc)
	if mime == "" {
		mime = magic.MIMETypeByExtension(path.Ext(zf.Name))
	}
	if mime == "" {
		mime = "application/octet-stream"
	}

	h := md5.New()
	r = io.TeeReader(r, h)
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	sumx := hex.EncodeToString(h.Sum(nil))
	etag := fmt.Sprintf(`"%s"`, sumx)
	size := strconv.Itoa(len(data))

	name := zf.Name
	if off := strings.IndexByte(name, '.'); off >= 0 {
		name = name[:off] + "." + sumx[:sumLen] + name[off:]
	}

	return &file{
		infos: zf.FileInfo(),
		data:  data,
		etag:  etag,
		name:  name,
		size:  size,
		mime:  mime,
	}, nil
}

func Open(name string) (*bytes.Reader, error) {
	if files == nil {
		panic("statik/fs: not registered")
	}
	f, ok := files[name]
	if ok {
		return bytes.NewReader(f.data), nil
	}
	return nil, os.ErrNotExist
}

func Handler(prefix string, privates ...string) *StatikHandler {
	if files == nil {
		panic("statik/fs: not registered")
	}
	fs := make(map[string]*file)
	for n, f := range files {
		isPrivate := false
		for _, p := range privates {
			if strings.HasPrefix(n, p) {
				isPrivate = true
				break
			}
		}
		if !isPrivate {
			fs[n] = f
		}
	}
	return &StatikHandler{
		prefix: prefix,
		files:  fs,
	}
}

type StatikHandler struct {
	prefix string
	files  map[string]*file
}

func extractFileID(file string) (string, string) {
	var id string
	base := path.Base(file)
	off1 := strings.IndexByte(base, '.') + 1
	if off1 < len(base) {
		off2 := off1 + strings.IndexByte(base[off1:], '.')
		if off2-off1 == sumLen {
			id = base[off1:off2]
			file = path.Dir(file) + "/" + base[:off1-1] + base[off2:]
		}
	}
	return file, id
}

func (h *StatikHandler) AssetPath(file string) string {
	f, ok := h.files[file]
	if !ok {
		return h.prefix + file
	}
	return h.prefix + f.name
}

func (h *StatikHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var id string
	file := strings.TrimPrefix(r.URL.Path, h.prefix)
	file, id = extractFileID(file)
	if len(file) > 0 && file[0] != '/' {
		file = "/" + file
	}
	f, ok := h.files[file]
	if !ok {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if inm := r.Header.Get("If-None-Match"); inm != "" {
		var match bool
		for {
			inm = textproto.TrimString(inm)
			if len(inm) == 0 {
				break
			}
			if inm[0] == ',' {
				inm = inm[1:]
			}
			if inm[0] == '*' {
				match = true
				break
			}
			etag, remain := scanETag(inm)
			if etag == "" {
				break
			}
			if etagWeakMatch(etag, f.etag) {
				match = true
				break
			}
			inm = remain
		}
		if match {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	headers := w.Header()
	headers.Set("Content-Type", f.mime)
	headers.Set("Content-Length", f.size)
	headers.Set("Etag", f.etag)
	if id != "" {
		headers.Set("Cache-Control", "max-age=31557600")
	} else {
		headers.Set("Cache-Control", "no-cache")
	}

	if r.Method == http.MethodGet {
		io.Copy(w, bytes.NewReader(f.data))
	}
}

// scanETag determines if a syntactically valid ETag is present at s. If so,
// the ETag and remaining text after consuming ETag is returned. Otherwise,
// it returns "", "".
func scanETag(s string) (etag string, remain string) {
	start := 0

	if len(s) >= 2 && s[0] == 'W' && s[1] == '/' {
		start = 2
	}

	if len(s[start:]) < 2 || s[start] != '"' {
		return "", ""
	}

	// ETag is either W/"text" or "text".
	// See RFC 7232 2.3.
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		// Character values allowed in ETags.
		case c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80:
		case c == '"':
			return s[:i+1], s[i+1:]
		default:
			return "", ""
		}
	}

	return "", ""
}

// etagWeakMatch reports whether a and b match using weak ETag comparison.
// Assumes a and b are valid ETags.
func etagWeakMatch(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}
