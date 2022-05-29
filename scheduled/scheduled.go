package scheduled

import (
	"fmt"
	"time"
)

type Scheduled func() (string, time.Duration)

func ExecuteImmediatelyAndSchedule(f Scheduled) {
	print, wait := f()
	fmt.Println(print)

	go ExecuteWithDelayAndSchedule(f, wait)
}

func ExecuteWithDelayAndSchedule(f Scheduled, wait time.Duration) {
	time.Sleep(wait)

	print, nextWait := f()
	fmt.Println(print)

	go ExecuteWithDelayAndSchedule(f, nextWait)
}
