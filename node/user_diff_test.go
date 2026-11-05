package node

import (
	"github.com/perfect-panel/ppanel-node/api/panel"
	"testing"
)

func TestCompareUserListIncludesAllFields(t *testing.T) {
	old := panel.UserInfo{Id: 1, Uuid: "u", SpeedLimit: 2, DeviceLimit: 3}
	for _, next := range []panel.UserInfo{
		{Id: 2, Uuid: "u", SpeedLimit: 2, DeviceLimit: 3},
		{Id: 1, Uuid: "u", SpeedLimit: 2, DeviceLimit: 4},
		{Id: 1, Uuid: "u", SpeedLimit: 3, DeviceLimit: 3},
	} {
		deleted, added := compareUserList([]panel.UserInfo{old}, []panel.UserInfo{next})
		if len(deleted) != 1 || len(added) != 1 || deleted[0] != old || added[0] != next {
			t.Fatalf("old=%+v next=%+v deleted=%+v added=%+v", old, next, deleted, added)
		}
	}
}
