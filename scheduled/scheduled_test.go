package scheduled

import (
	"testing"
	"time"
)

func TestImmediateScheduler(t *testing.T) {
	now := time.Now().UnixNano()

	c := make(chan bool)

	go ExecuteImmediatelyAndSchedule(func() (string, time.Duration) {
		c <- true
		return "", time.Millisecond * 10
	})

	<-c

	firstDuration := time.Duration.Nanoseconds(time.Millisecond)
	elapsed := time.Now().UnixNano() - now
	if elapsed > firstDuration {
		t.Errorf("did not immediately execute within %v, took %v", firstDuration, elapsed)
	}

	<-c

	secondDuration := elapsed + time.Duration.Nanoseconds(time.Millisecond*10) + firstDuration
	elapsed = time.Now().UnixNano() - now
	if elapsed > secondDuration {
		t.Errorf("did not schedule second execute within %v nanoseconds, took %v", secondDuration, elapsed)
	}

	<-c

	thirdDuration := elapsed + time.Duration.Nanoseconds(time.Millisecond*10) + firstDuration
	elapsed = time.Now().UnixNano() - now
	if elapsed > thirdDuration {
		t.Errorf("did not schedule third execute within %v nanoseconds, took %v", thirdDuration, elapsed)
	}
}

func TestDelayedScheduler(t *testing.T) {
	now := time.Now().UnixNano()

	c := make(chan bool)

	go ExecuteWithDelayAndSchedule(func() (string, time.Duration) {
		c <- true
		return "", time.Millisecond * 10
	}, time.Millisecond*500)

	<-c

	firstDuration := time.Duration.Nanoseconds(time.Millisecond * 502)
	elapsed := time.Now().UnixNano() - now
	if elapsed > firstDuration {
		t.Errorf("did not immediately execute within %v, took %v", firstDuration, elapsed)
	}

	<-c

	secondDuration := elapsed + time.Duration.Nanoseconds(time.Millisecond*10) + firstDuration
	elapsed = time.Now().UnixNano() - now
	if elapsed > secondDuration {
		t.Errorf("did not schedule second execute within %v nanoseconds, took %v", secondDuration, elapsed)
	}

	<-c

	thirdDuration := elapsed + time.Duration.Nanoseconds(time.Millisecond*10) + firstDuration
	elapsed = time.Now().UnixNano() - now
	if elapsed > thirdDuration {
		t.Errorf("did not schedule third execute within %v nanoseconds, took %v", thirdDuration, elapsed)
	}
}
