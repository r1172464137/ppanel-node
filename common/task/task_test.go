package task

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestCloseCancelsAndWaitsForExecution(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cancelled, finish := make(chan struct{}), make(chan struct{})
		task := &Task{Interval: time.Hour, Execute: func(ctx context.Context) error {
			<-ctx.Done()
			close(cancelled)
			<-finish
			return ctx.Err()
		}}
		if err := task.Start(true); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		closed := make(chan struct{})
		go func() { task.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-cancelled:
		default:
			t.Fatal("execution not cancelled")
		}
		select {
		case <-closed:
			t.Fatal("Close returned while execution was still running")
		default:
		}
		close(finish)
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("Close did not finish")
		}
		task.Close()
	})
}

func TestHugeIntervalCannotOverflowExecutionTimeout(t *testing.T) {
	deadline := make(chan time.Duration, 1)
	task := &Task{Interval: time.Duration(math.MaxInt64), Execute: func(ctx context.Context) error {
		d, ok := ctx.Deadline()
		if !ok {
			t.Error("missing deadline")
			return nil
		}
		deadline <- time.Until(d)
		return nil
	}}
	if err := task.Start(true); err != nil {
		t.Fatal(err)
	}
	defer task.Close()
	select {
	case got := <-deadline:
		if got < 4*time.Minute || got > 5*time.Minute {
			t.Fatalf("overflowed timeout: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("task did not execute")
	}
}

func TestPeriodicTaskStopsAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		task := &Task{Interval: time.Minute, Execute: func(context.Context) error { calls.Add(1); return nil }}
		if err := task.Start(false); err != nil {
			t.Fatal(err)
		}
		defer task.Close()
		synctest.Sleep(59 * time.Second)
		if calls.Load() != 0 {
			t.Fatal("task ran before its interval")
		}
		synctest.Sleep(time.Second)
		if calls.Load() != 1 {
			t.Fatalf("first interval: calls = %d", calls.Load())
		}
		synctest.Sleep(time.Minute)
		if calls.Load() != 2 {
			t.Fatalf("second interval: calls = %d", calls.Load())
		}
		task.Close()
		synctest.Sleep(time.Hour)
		if calls.Load() != 2 {
			t.Fatal("task ran after Close")
		}
	})
}
