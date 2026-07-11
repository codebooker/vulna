package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// archiveFiles returns the regular files inside a gzip+tar archive, keyed by
// their path (with any leading "./" stripped) and valued by byte size.
// Directory and non-regular entries are omitted so an archive that contains only
// directory records reports no files.
func archiveFiles(plaintext []byte) (map[string]int64, error) {
	gz, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, fmt.Errorf("not a valid gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	files := map[string]int64{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("not a valid tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		files[strings.TrimPrefix(hdr.Name, "./")] = hdr.Size
	}
	return files, nil
}

// verifyArchiveContents confirms the archive actually carries the payloads the
// manifest declares, so a manifest cannot certify content the archive lacks
// (e.g. an empty archive marked as containing a database + CA). Each mismatch is
// reported via fail; verified payloads via pass.
func verifyArchiveContents(m *Manifest, plaintext []byte, pass, fail func(name, detail string)) {
	files, err := archiveFiles(plaintext)
	if err != nil {
		fail("archive:format", err.Error())
		return
	}
	if len(files) == 0 {
		fail("archive:contents", "archive contains no files")
		return
	}
	// Verify EACH declared content class against its own distinct location, so a
	// single stray data/ file cannot vouch for CA, reports, presets, etc. at once.
	for _, class := range m.Contents {
		if classSatisfied(class, files) {
			pass("archive:"+class, "present")
		} else {
			fail("archive:"+class,
				fmt.Sprintf("manifest declares %q but the archive has no matching content", class))
		}
	}
}

// classSatisfied reports whether the archive actually carries a content class.
// Paths follow deploy/backup/backup.sh, which copies VULNA_DATA under data/
// (keys under data/keys, reports under data/reports, ...). Evidence lives in the
// database, so it is carried by db.dump.
func classSatisfied(class string, files map[string]int64) bool {
	switch class {
	case ClassDatabase, ClassEvidence:
		return files["db.dump"] > 0
	case ClassCA:
		// CA + signing keys live under data/keys (VULNA_CA_CERT_PATH); some
		// layouts use data/ca. Accept either.
		return anyFileUnder(files, "data/keys/") || anyFileUnder(files, "data/ca/")
	case ClassReports:
		return anyFileUnder(files, "data/reports/")
	case ClassBranding:
		return anyFileUnder(files, "data/branding/")
	case ClassPresets:
		return anyFileUnder(files, "data/presets/")
	case ClassConfig, ClassScoutState:
		// Config/scout-state files live loose under data/.
		return anyFileUnder(files, "data/")
	default:
		return anyFileUnder(files, "data/")
	}
}

// ClassesInArchive returns the content classes actually present in a plaintext
// archive, so a backup manifest describes what it really holds (rather than an
// operator-supplied claim). Uses the same predicates as verification, so a
// created backup always passes its own content check.
func ClassesInArchive(plaintext []byte) ([]string, error) {
	files, err := archiveFiles(plaintext)
	if err != nil {
		return nil, err
	}
	all := []string{
		ClassDatabase, ClassConfig, ClassCA, ClassScoutState,
		ClassReports, ClassEvidence, ClassBranding, ClassPresets,
	}
	out := make([]string, 0, len(all))
	for _, c := range all {
		if classSatisfied(c, files) {
			out = append(out, c)
		}
	}
	return out, nil
}

func anyFileUnder(files map[string]int64, prefix string) bool {
	for name, sz := range files {
		if sz > 0 && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
