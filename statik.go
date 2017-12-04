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
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"
)

const (
	namePackage    = "statik"
	nameSourceFile = "statik.go"
)

var (
	flagSrc        = flag.String("src", path.Join(".", "public"), "The path of the source directory.")
	flagDest       = flag.String("dest", ".", "The destination path of the generated package.")
	flagExternals  = flag.String("externals", "", "File containing a description of externals assets to download.")
	flagNoCompress = flag.Bool("Z", false, "Do not use compression to shrink the files.")
	flagForce      = flag.Bool("f", false, "Overwrite destination file if it already exists.")
)

// mtimeDate holds the arbitrary mtime that we assign to files when
// flagNoMtime is set.
var mtimeDate = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

var (
	errExternalsMalformed = errors.New("assets externals file malformed")
	errZipMalformed       = errors.New("zip data could not be parsed")
)

type external struct {
	name   string
	url    string
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
func generateSource(srcPath, externalsFile string) (file *os.File, err error) {
	var (
		buffer    bytes.Buffer
		zipWriter io.Writer
	)

	zipWriter = &buffer
	f, err := ioutil.TempFile("", namePackage)
	if err != nil {
		return
	}

	zipWriter = io.MultiWriter(zipWriter, f)
	defer f.Close()

	w := zip.NewWriter(zipWriter)
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
		fHeader, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}
		// Always use the same modification time so that
		// the output is deterministic with respect to the file contents.
		fHeader.SetModTime(mtimeDate)
		fHeader.Name = path.Join("/", filepath.ToSlash(relPath))
		if !*flagNoCompress {
			fHeader.Method = zip.Deflate
		}
		f, err := w.CreateHeader(fHeader)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		return err
	}); err != nil {
		return
	}

	if externalsFile != "" {
		if err = downloadExternals(externalsFile, w); err != nil {
			return
		}
	}

	if err = w.Close(); err != nil {
		return
	}

	// then embed it as a quoted string
	var qb bytes.Buffer
	fmt.Fprintf(&qb, `// Code generated by statik. DO NOT EDIT.

package %s

import (
	"github.com/cozy/statik/fs"
)

func init() {
	data := "`, namePackage)
	FprintZipData(&qb, buffer.Bytes())
	fmt.Fprint(&qb, `"
	fs.Register(data)
}
`)

	if err = ioutil.WriteFile(f.Name(), qb.Bytes(), 0644); err != nil {
		return
	}
	return f, nil
}

func downloadExternals(filename string, w *zip.Writer) (err error) {
	destDir := path.Join(*flagDest, namePackage)
	statikFile, err := ioutil.ReadFile(path.Join(destDir, nameSourceFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var zippedData []byte
	if len(statikFile) > 0 {
		i := bytes.Index(statikFile, []byte(`data := "`))
		if i >= 0 {
			i += len(`data := "`)
			j := bytes.IndexByte(statikFile[i:], '\n')
			if j >= 1 {
				zippedData = statikFile[i : i+j-1]
			}
		}
	}

	files := make(map[string]struct {
		sum  []byte
		data []byte
	})
	if len(zippedData) > 0 {
		zipData := new(bytes.Buffer)
		if err = FreadZipData(zipData, zippedData); err != nil {
			return fmt.Errorf("Could not read zip data from current file: %s", err)
		}
		var zipReader *zip.Reader
		zipReader, err = zip.NewReader(bytes.NewReader(zipData.Bytes()), int64(zipData.Len()))
		if err != nil {
			return fmt.Errorf("Could not read zip data from current file: %s", err)
		}
		for _, zipFile := range zipReader.File {
			var rc io.ReadCloser
			var data []byte
			rc, err = zipFile.Open()
			if err != nil {
				return fmt.Errorf("Could not read zip data from current file: %s", err)
			}
			h := sha256.New()
			r := io.TeeReader(rc, h)
			data, err = ioutil.ReadAll(r)
			if err != nil {
				return fmt.Errorf("Could not read zip data from current file: %s", err)
			}
			rc.Close()
			files[zipFile.Name] = struct {
				sum  []byte
				data []byte
			}{
				sum:  h.Sum(nil),
				data: data,
			}
		}
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
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
				return errExternalsMalformed
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
					return errExternalsMalformed
				}
			}
		} else {
			return errExternalsMalformed
		}

		if ext == nil || ext.name == "" || ext.url == "" || len(ext.sha256) == 0 {
			continue
		}

		var data []byte
		fmt.Printf("file %q... ", ext.name)
		if obj, ok := files[ext.name]; ok {
			if bytes.Equal(obj.sum, ext.sha256) {
				data = obj.data
			}
		}

		if len(data) == 0 {
			if err = downloadExternal(w, ext); err != nil {
				return
			}
		} else {
			if _, err = writeExternal(w, ext, data); err != nil {
				return
			}
			fmt.Println("skipped")
		}

		ext = nil
	}

	return scanner.Err()
}

func downloadExternal(w *zip.Writer, ext *external) (err error) {
	var size uint64

	fmt.Printf("downloading... ")
	defer func() {
		if err == nil {
			fmt.Printf("ok (%s)\n", humanize.Bytes(size))
		}
	}()

	res, err := http.Get(ext.url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("could not fetch external assets %q: received status \"%d %s\"",
			ext.url, res.StatusCode, res.Status)
	}

	h := sha256.New()
	r := io.TeeReader(res.Body, h)

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("could not fetch external asset: %s", err)
	}

	if sum := h.Sum(nil); !bytes.Equal(sum, ext.sha256) {
		return fmt.Errorf("shasum does not match: expected %x got %x",
			ext.sha256, sum)
	}

	size, err = writeExternal(w, ext, data)
	return
}

func writeExternal(w *zip.Writer, ext *external, data []byte) (size uint64, err error) {
	size = uint64(len(data))

	fh := &zip.FileHeader{
		Name:               ext.name,
		UncompressedSize64: size,
	}
	fh.SetModTime(mtimeDate)
	fh.SetMode(0644)
	if !*flagNoCompress {
		fh.Method = zip.Deflate
	}

	f, err := w.CreateHeader(fh)
	if err != nil {
		return
	}
	_, err = io.Copy(f, bytes.NewReader(data))
	return
}

// FprintZipData converts zip binary contents to a string literal.
func FprintZipData(dest *bytes.Buffer, zipData []byte) {
	for _, b := range zipData {
		if b == '\n' {
			dest.WriteString(`\n`)
			continue
		}
		if b == '\\' {
			dest.WriteString(`\\`)
			continue
		}
		if b == '"' {
			dest.WriteString(`\"`)
			continue
		}
		if (b >= 32 && b <= 126) || b == '\t' {
			dest.WriteByte(b)
			continue
		}
		fmt.Fprintf(dest, "\\x%02x", b)
	}
}

// FreadZipData converts string literal into a zip binary.
func FreadZipData(dest *bytes.Buffer, zippedData []byte) error {
	for i := 0; i < len(zippedData); i++ {
		b := zippedData[i]
		if b == '\\' {
			i++
			if i >= len(zippedData) {
				return errZipMalformed
			}
			switch zippedData[i] {
			case 'n':
				dest.WriteByte('\n')
			case '\\':
				dest.WriteByte('\\')
			case '"':
				dest.WriteByte('"')
			case 'x':
				i += 2
				if i >= len(zippedData) {
					return errZipMalformed
				}
				s, err := hex.DecodeString(string(zippedData[i-1 : i+1]))
				if err != nil {
					return err
				}
				dest.Write(s)
			}
		} else if (b >= 32 && b <= 126) || b == '\t' {
			dest.WriteByte(b)
		} else {
			return errZipMalformed
		}
	}
	return nil
}

// Prints out the error message and exists with a non-success signal.
func exitWithError(err error) {
	fmt.Println(err)
	os.Exit(1)
}
