package node

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/task"
)

func TestRequiredReportAndUserTasksFailClosed(t *testing.T) {
	n := &Node{traffic: newTrafficQueue(), reportPeriodic: &task.Task{}}
	if err := n.Start(); err == nil {
		t.Fatal("failed report task was ignored")
	}
	if n.reportPeriodic != nil {
		t.Fatal("failed report task not cleaned up")
	}
	c := &Controller{}
	for _, seconds := range []int{-1, 86401, int(^uint(0) >> 1)} {
		if err := c.startTasks(&panel.NodeInfo{PullInterval: seconds}); err == nil {
			t.Fatalf("bad user monitor interval %d accepted", seconds)
		}
	}
}
