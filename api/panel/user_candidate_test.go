package panel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestUserETagCommitAfterApplication(t *testing.T) {
	for _, protobuf := range []bool{false, true} {
		t.Run(fmt.Sprint(protobuf), func(t *testing.T) {
			calls := 0
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls < 3 && r.Header.Get("If-None-Match") != "old" {
					t.Errorf("premature ETag: %q", r.Header.Get("If-None-Match"))
				}
				if calls == 3 {
					if r.Header.Get("If-None-Match") != "new" {
						t.Errorf("missing committed ETag: %q", r.Header.Get("If-None-Match"))
					}
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set("ETag", "new")
				if protobuf {
					writeProtobuf(t, w, &serverv1.GetServerUserListResponse{Code: 200, Data: &serverv1.ServerUserListData{}})
				} else {
					fmt.Fprint(w, `{"code":200,"data":{"users":[]}}`)
				}
			}))
			httpClient := server.Client()
			client, err := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless", UseProtobuf: protobuf})
			if err != nil {
				t.Fatal(err)
			}
			client.Client.SetTransport(httpClient.Transport)
			client.userEtag = "old"
			for i := 0; i < 2; i++ {
				users, err := client.GetUserList(t.Context())
				if err != nil || users == nil {
					t.Fatalf("attempt %d: %v %v", i, users, err)
				}
			}
			client.CommitUserList()
			users, err := client.GetUserList(t.Context())
			if err != nil || users != nil {
				t.Fatalf("304: %v %v", users, err)
			}
		})
	}
}
