package timestamp

import (
	"crypto"
	"fmt"
	"testing"
)

func TestTimeStamp(t *testing.T) {

	testMSG := []byte("Hallo Welt!")

	timeStampServers := []string{"http://zeitstempel.dfn.de", "http://timestamp.digicert.com"}

	for _, url := range timeStampServers {
		resp, err := FetchTSToken(url, testMSG, crypto.SHA256)
		if err != nil {
			t.Error(err)
		}
		info, err := VerfiyTS(resp)
		if err != nil {
			t.Error(err)
		}
		fmt.Println(info.GenTime)
	}

}
