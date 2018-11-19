//Package MIME implemets parsing of MIME and MIME/multipart messages
//needed to verfiy multipart/signed messages
package mime

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"unicode"

	gomime "mime"
)

//A MIME message
type MIME struct {
	headerFld Lines
	interm    Line
	body      Lines
}

//Returns the header of the message
func (m *MIME) Header() []byte {
	return m.headerFld.bytes(nil)
}

//Sets the body of the message
func (m *MIME) SetBody(body []byte) {
	m.body = ParseLines((body))
}

//Gets the body of the message
func (m *MIME) Body() []byte {
	return m.body.bytes(nil)
}

//Gets the full message
func (m *MIME) Full(sep ...[]byte) []byte {

	if len(sep) == 0 {
		return m.FullLines().bytes(nil)
	}

	return m.FullLines().bytes(sep[0])
}

//Gets the full message as Lines
func (m *MIME) FullLines() (full Lines) {

	full = append(full, m.headerFld...)
	if m.interm.Line == nil && m.interm.endOfLine == nil {
		m.interm = Line{nil, LF}
	}
	full = append(full, m.interm)
	full = append(full, m.body...)

	return
}

//Adds a header field to the header of the message
func (m *MIME) AddHeaderField(key, value []byte) {

	var field []byte

	field = append(field, key...)
	field = append(field, []byte(": ")...)
	field = append(field, value...)

	newField := Line{field, []byte("\n")}

	m.headerFld = append(m.headerFld, newField)

}

//Removes a header fild from the header of the message
func (m *MIME) DeleteHeaderField(key []byte) {

	for i := 0; i < len(m.headerFld); i++ { //i := range m.headerFld {
		keyAndField := bytes.SplitN(m.headerFld[i].Line, []byte(":"), 2)

		if len(keyAndField) == 2 && bytes.Equal(bytes.ToLower(keyAndField[0]), bytes.ToLower(key)) {

			m.headerFld = append(m.headerFld[:i], m.headerFld[i+1:]...)
			for i < len(m.headerFld) && isContinuedLine(m.headerFld[i].Line) {
				m.headerFld = append(m.headerFld[:i], m.headerFld[i+1:]...)
			}
			i--
		}
	}

}

//Gets the header field with the given key
func (m *MIME) GetHeaderField(key []byte) (values [][]byte) {

	for i := range m.headerFld {
		keyAndField := bytes.SplitN(m.headerFld[i].Line, []byte(":"), 2)

		value := []byte{}
		if len(keyAndField) == 2 && bytes.Equal(bytes.ToLower(keyAndField[0]), bytes.ToLower(key)) {

			value = append(value, keyAndField[1][1:]...)
			for k := 1; i+k < len(m.headerFld) && isContinuedLine(m.headerFld[i+k].Line); k++ {
				value = append(value, m.headerFld[i+k-1].endOfLine...)
				value = append(value, m.headerFld[i+k].Line...)
			}

			values = append(values, value)
		}
	}

	return
}

//Sets the header field with the given key
func (m *MIME) SetHeaderField(key, value []byte) {

	m.DeleteHeaderField(key)

	var field []byte

	field = append(field, key...)
	field = append(field, []byte(": ")...)
	field = append(field, value...)

	newField := Line{field, []byte("\n")}

	m.headerFld = append(m.headerFld, newField)

}

//Parses the mediatype of the message
func (m *MIME) ParseMediaType() (mediatype string, params map[string]string, err error) {

	contentType := m.GetHeaderField([]byte("Content-Type"))
	if len(contentType) != 1 {
		err = errors.New("Multiple or no Content-Type field")
		return
	}

	mediatype, params, err = gomime.ParseMediaType(string(m.GetHeaderField([]byte("Content-Type"))[0]))

	return
}

//Get the parts of a multipart Message
func (m *MIME) MultipartGetParts() (parts []Lines, err error) {

	mediaType, params, err := m.ParseMediaType()

	if !strings.HasPrefix(mediaType, "multipart/") {
		err = errors.New("Message is not multipart")
		return
	}

	boundary := params["boundary"]
	if boundary == "" {
		err = errors.New("Mulitpart message has no boundary")
		return
	}

	var boundaryIndex []int

	for i := range m.body {
		if strings.HasPrefix(string(m.body[i].Line), "--"+boundary) {
			boundaryIndex = append(boundaryIndex, i)
		}

		if strings.HasPrefix(string(m.body[i].Line), "--"+boundary+"--") {
			break
		}
	}

	for i := 0; i < len(boundaryIndex)-1; i++ {
		part := make([]Line, boundaryIndex[i+1]-(boundaryIndex[i]+1))
		copy(part, m.body[boundaryIndex[i]+1:boundaryIndex[i+1]])
		parts = append(parts, part) //m.body[boundaryIndex[i]+1:boundaryIndex[i+1]])
	}

	for i := range parts {
		parts[i][len(parts[i])-1] = Line{parts[i][len(parts[i])-1].Line, nil}
	}

	return
}

var (
	CRLF = []byte("\r\n")
	CR   = []byte("\r")
	LF   = []byte("\n")

	SPACE = []byte(" ")[0]
	HTAB  = []byte("\t")[0]
)

//Parses a MIME message
func Parse(raw []byte) (m MIME) {

	rawLines := ParseLines(raw)

	return parseMIME(rawLines)
}

func parseMIME(rawLines Lines) (m MIME) {

	for i := range rawLines {

		// Empty line seprates header and body
		if isEmpty(rawLines[i].Line) {
			m.interm = rawLines[i]
			m.body = rawLines[i+1:]
			break
		}

		m.headerFld = append(m.headerFld, rawLines[i])

	}

	return
}

//Line of a MIME message
type Line struct {
	Line      []byte
	endOfLine []byte
}

//Multiple lines, needed for body and header
type Lines []Line

//Parsing linebreaks
func ParseLines(raw []byte) (lines Lines) {

	oneLine := Line{raw, nil}
	lines = Lines{oneLine}

	lines = lines.splitLine(CRLF)
	lines = lines.splitLine(CR)
	lines = lines.splitLine(LF)

	return
}

func (l Lines) splitLine(sep []byte) (newL Lines) {
	newL = Lines{}
	for _, line := range l {
		split := bytes.Split(line.Line, sep)
		if len(split) > 1 {
			for i := 0; i < len(split)-1; i++ {
				newL = append(newL, Line{split[i], sep})
			}
			newL = append(newL, Line{split[len(split)-1], line.endOfLine})
		} else {
			newL = append(newL, line)
		}
	}
	return
}

//Gives the bytes of the Lines with given linebreak. (e.g. for signed S/MIME use Bytes(mime.CRLF))
func (l Lines) Bytes(sep []byte) (raw []byte) {
	return l.bytes(sep)
}

func (l Lines) bytes(sep []byte) (raw []byte) {

	for i := range l {
		raw = append(raw, l[i].Line...)
		if len(l[i].endOfLine) != 0 && sep != nil {
			raw = append(raw, sep...)
		} else {
			raw = append(raw, l[i].endOfLine...)
		}
	}
	return raw
}

//Header field folding https://tools.ietf.org/html/rfc822#section-3.1.1
func isEmpty(s []byte) bool {
	return len(bytes.TrimSpace(s)) == 0
}

func isContinuedLine(s []byte) bool {
	if !(s[0] != ' ' && s[0] != '\t') {
		return true
	}

	if unicode.IsSpace(bytes.Runes(s[:2])[0]) {
		fmt.Println("Continued Line with unicode space found.")
		return true
	}

	return false
}

// SetMultipartBody makes a mulitpart messages with given parts and contentType
func (m *MIME) SetMultipartBody(contentType string, parts ...MIME) {

	body := Lines{}

	// Generate boundary
	bndry := make([]byte, 30)
	rand.Read(bndry)
	boundary := fmt.Sprintf("%x", bndry)

	// Fix header
	m.DeleteHeaderField([]byte("Content-Disposition"))
	m.DeleteHeaderField([]byte("Content-Transfer-Encoding"))
	m.SetHeaderField([]byte("Content-Type"), []byte(contentType+"; boundary="+boundary))

	for i := range parts {
		body = append(body, Line{[]byte("\n--" + boundary), LF})
		body = append(body, parts[i].FullLines()...)
	}

	body = append(body, Line{[]byte("--" + boundary + "--"), LF})

	m.body = body
}
