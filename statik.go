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

// Package contains a program that generates code to register
// a directory and its contents as zip data for statik file system.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	humanize "github.com/dustin/go-humanize"
)

const (
	namePackage    = "statik"
	nameSourceFile = "statik.go"
)

var (
	flagSrc       = flag.String("src", path.Join(".", "public"), "The path of the source directory.")
	flagDest      = flag.String("dest", ".", "The destination path of the generated package.")
	flagExternals = flag.String("externals", "", "File containing a description of externals assets to download.")
	flagForce     = flag.Bool("f", false, "Overwrite destination file if it already exists.")
)

var (
	errExternalsMalformed = errors.New("assets externals file malformed")
	errZipMalformed       = errors.New("zip data could not be parsed")
)

type external struct {
	name   string
	url    string
	sha256 []byte
}

type file struct {
	name   string
	size   int64
	data   []byte
	sha256 []byte
}

func main() {
	flag.Parse()

	file, err := generateSource(*flagSrc, *flagExternals)
	if err != nil {
		exitWithError(err)
	}

	destDir := path.Join(*flagDest, namePackage)
	err = os.MkdirAll(destDir, 0755)
	if err != nil {
		exitWithError(err)
	}

	src := file.Name()
	dest := path.Join(destDir, nameSourceFile)

	hSrc, err := shasum(src)
	if err != nil {
		exitWithError(err)
	}
	hDest, err := shasum(dest)
	if err != nil {
		exitWithError(err)
	}

	if !bytes.Equal(hSrc, hDest) {
		err = rename(src, dest)
		if err != nil {
			exitWithError(err)
		}
		fmt.Println("asset file updated successfully")
	} else {
		fmt.Println("asset file left unchanged")
	}
}

func shasum(file string) ([]byte, error) {
	h := sha256.New()
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// rename tries to os.Rename, but fall backs to copying from src
// to dest and unlink the source if os.Rename fails.
func rename(src, dest string) error {
	// Try to rename generated source.
	if err := os.Rename(src, dest); err == nil {
		return nil
	}
	// If the rename failed (might do so due to temporary file residing on a
	// different device), try to copy byte by byte.
	rc, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		rc.Close()
		os.Remove(src) // ignore the error, source is in tmp.
	}()

	if _, err = os.Stat(dest); !os.IsNotExist(err) {
		if *flagForce {
			if err = os.Remove(dest); err != nil {
				return fmt.Errorf("file %q could not be deleted", dest)
			}
		} else {
			return fmt.Errorf("file %q already exists; use -f to overwrite", dest)
		}
	}

	wc, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer wc.Close()

	if _, err = io.Copy(wc, rc); err != nil {
		// Delete remains of failed copy attempt.
		os.Remove(dest)
	}
	return err
}

// Walks on the source path and generates source code
// that contains source directory's contents as zip contents.
// Generates source registers generated zip contents data to
// be read by the statik/fs HTTP file system.
func generateSource(srcPath, externalsFile string) (f *os.File, err error) {
	var files []*file

	if err = filepath.Walk(srcPath, func(name string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Ignore directories and hidden files.
		// No entry is needed for directories in a zip file.
		// Each file is represented with a path, no directory
		// entities are required to build the hierarchy.
		if fi.IsDir() || strings.HasPrefix(fi.Name(), ".") {
			return nil
		}
		relPath, err := filepath.Rel(srcPath, name)
		if err != nil {
			return err
		}
		b, err := ioutil.ReadFile(name)
		if err != nil {
			return err
		}
		h := sha256.New()
		h.Write(b)
		files = append(files, &file{
			name:   path.Join("/", filepath.ToSlash(relPath)),
			size:   fi.Size(),
			sha256: h.Sum(nil),
			data:   b,
		})
		return nil
	}); err != nil {
		return
	}

	if externalsFile != "" {
		var exts []*file
		exts, err = downloadExternals(externalsFile)
		if err != nil {
			return
		}
		files = append(files, exts...)
	}

	// then embed it as a quoted string
	var qb bytes.Buffer
	fmt.Fprintf(&qb, `// Code generated by statik. DO NOT EDIT.

package %s

import (
	"github.com/cozy/statik/fs"
)

func init() {
	data := `, namePackage)
	qb.WriteByte('`')
	FprintZipData(&qb, files)
	qb.WriteByte('`')
	fmt.Fprint(&qb, `
	fs.Register(data)
}
`)

	f, err = ioutil.TempFile("", namePackage)
	if err != nil {
		return
	}
	if err = ioutil.WriteFile(f.Name(), qb.Bytes(), 0644); err != nil {
		return
	}
	return
}

func downloadExternals(filename string) (exts []*file, err error) {
	destDir := path.Join(*flagDest, namePackage)
	statikFile, err := ioutil.ReadFile(path.Join(destDir, nameSourceFile))
	if err != nil && !os.IsNotExist(err) {
		return
	}

	var zippedData []byte
	if len(statikFile) > 0 {
		i := bytes.Index(statikFile, []byte("`"))
		if i >= 0 {
			j := bytes.Index(statikFile[i+1:], []byte("`"))
			if i >= 0 && j > i {
				zippedData = statikFile[i : i+j]
			}
		}
	}

	files := make(map[string]*file)
	if len(zippedData) > 0 {
		fs, err := FreadZipData(zippedData)
		if err == nil {
			for _, f := range fs {
				files[f.name] = f
			}
		}
	}

	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer func() {
		if errc := f.Close(); errc != nil && err == nil {
			err = errc
		}
	}()

	var ext *external
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && line[0] == '#' {
			continue
		}

		fields := strings.Fields(line)
		fieldsLen := len(fields)

		if fieldsLen == 0 {
			if ext != nil {
				return nil, errExternalsMalformed
			}
		} else if fieldsLen == 2 {
			if ext == nil {
				ext = new(external)
			}
			switch strings.ToLower(fields[0]) {
			case "name":
				ext.name = path.Join("/", fields[1])
			case "url":
				ext.url = fields[1]
			case "sha256":
				ext.sha256, err = hex.DecodeString(fields[1])
				if err != nil {
					return nil, errExternalsMalformed
				}
			}
		} else {
			return nil, errExternalsMalformed
		}

		if ext == nil || ext.name == "" || ext.url == "" || len(ext.sha256) == 0 {
			continue
		}

		var data []byte
		fmt.Printf("file %q... ", ext.name)
		if obj, ok := files[ext.name]; ok {
			if bytes.Equal(obj.sha256, ext.sha256) {
				data = obj.data
			}
		}

		var f *file
		if len(data) == 0 {
			f, err = downloadExternal(ext)
		} else {
			fmt.Println("skipped")
			f = &file{
				data:   data,
				name:   ext.name,
				size:   int64(len(data)),
				sha256: ext.sha256,
			}
		}
		if err != nil {
			return
		}
		exts = append(exts, f)
		ext = nil
	}

	return exts, scanner.Err()
}

func downloadExternal(ext *external) (f *file, err error) {
	var size int64

	fmt.Printf("downloading... ")
	defer func() {
		if err == nil {
			fmt.Printf("ok (%s)\n", humanize.Bytes(uint64(size)))
		}
	}()

	res, err := http.Get(ext.url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not fetch external assets %q: received status \"%d %s\"",
			ext.url, res.StatusCode, res.Status)
	}

	h := sha256.New()
	r := io.TeeReader(res.Body, h)

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not fetch external asset: %s", err)
	}

	if sum := h.Sum(nil); !bytes.Equal(sum, ext.sha256) {
		return nil, fmt.Errorf("shasum does not match: expected %x got %x",
			ext.sha256, sum)
	}

	size = int64(len(data))
	return &file{
		data:   data,
		name:   ext.name,
		size:   size,
		sha256: ext.sha256,
	}, nil
}

// FreadZipData converts string literal into a zip binary.
func FreadZipData(data []byte) (files []*file, err error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		var size int64
		size, err = strconv.ParseInt(block.Headers["Size"], 10, 64)
		if err != nil {
			return
		}
		var gr *gzip.Reader
		gr, err = gzip.NewReader(bytes.NewReader(block.Bytes))
		if err != nil {
			return
		}
		var b []byte
		h := sha256.New()
		r := io.TeeReader(gr, h)
		b, err = ioutil.ReadAll(r)
		if err != nil {
			return
		}
		if err = gr.Close(); err != nil {
			return
		}
		files = append(files, &file{
			name:   block.Headers["Name"],
			size:   size,
			data:   b,
			sha256: h.Sum(nil),
		})
		data = rest
	}
	return
}

// FprintZipData converts zip binary contents to a string literal.
func FprintZipData(dest *bytes.Buffer, files []*file) {
	for _, f := range files {
		b := new(bytes.Buffer)
		gw, err := gzip.NewWriterLevel(b, gzip.BestCompression)
		panicOnError(err)
		_, err = io.Copy(gw, bytes.NewReader(f.data))
		panicOnError(err)
		panicOnError(gw.Close())
		pem.Encode(dest, &pem.Block{
			Type:  "COZY ASSET",
			Bytes: b.Bytes(),
			Headers: map[string]string{
				"Name": f.name,
				"Size": strconv.FormatInt(f.size, 10),
			},
		})
	}
}

func panicOnError(err error) {
	if err != nil {
		panic(fmt.Errorf("Unexpected error: %s", err))
	}
}

// Prints out the error message and exists with a non-success signal.
func exitWithError(err error) {
	fmt.Println(err)
	os.Exit(1)
}
