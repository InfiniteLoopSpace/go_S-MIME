package mime

import (
	"bytes"
	"strings"
	"testing"
)

func TestParsing(t *testing.T) {

	mail := Parse([]byte(sampleMsg))

	full := mail.Full()

	if !bytes.Equal(full, []byte(sampleMsg)) {
		t.Error("Parsing mail changes the content!")
	}

	mediaType, _, err := mail.ParseMediaType()
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(mediaType, "multipart/signed") != 0 {
		t.Error("Mediatype parsed not corretly!")
	}

	parts, err := mail.MultipartGetParts()
	if err != nil {
		t.Error(err)
	}

	for i := range parts {
		if !bytes.Equal(parts[i].Bytes(nil), msgParts[i]) {
			t.Fatal("Parts not corretly parsed")
		}
	}
}

//3.4.3.3.  Sample multipart/signed Message https://tools.ietf.org/html/rfc5751#section-3.4
const sampleMsg = `Content-Type: multipart/signed;
 protocol="application/pkcs7-signature";
 micalg=sha1; boundary=boundary42

--boundary42
Content-Type: text/plain

This is a clear-signed message.

--boundary42
Content-Type: application/pkcs7-signature; name=smime.p7s
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=smime.p7s

ghyHhHUujhJhjH77n8HHGTrfvbnj756tbB9HG4VQpfyF467GhIGfHfYT6
4VQpfyF467GhIGfHfYT6jH77n8HHGghyHhHUujhJh756tbB9HGTrfvbnj
n8HHGTrfvhJhjH776tbB9HG4VQbnj7567GhIGfHfYT6ghyHhHUujpfyF4
7GhIGfHfYT64VQbnj756

--boundary42--`

var msgParts = [][]byte{[]byte(part1), []byte(part2)}

const part1 = `Content-Type: text/plain

This is a clear-signed message.
`

const part2 = `Content-Type: application/pkcs7-signature; name=smime.p7s
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=smime.p7s

ghyHhHUujhJhjH77n8HHGTrfvbnj756tbB9HG4VQpfyF467GhIGfHfYT6
4VQpfyF467GhIGfHfYT6jH77n8HHGghyHhHUujhJh756tbB9HGTrfvbnj
n8HHGTrfvhJhjH776tbB9HG4VQbnj7567GhIGfHfYT6ghyHhHUujpfyF4
7GhIGfHfYT64VQbnj756
`
