package scheduled

import (
	"log"
	"time"
)

type Scheduled func() (string, time.Duration)

func ExecuteImmediatelyAndSchedule(f Scheduled) {
	print, wait := f()
	log.Println(print)

	go ExecuteWithDelayAndSchedule(f, wait)
}

func ExecuteWithDelayAndSchedule(f Scheduled, wait time.Duration) {
	time.Sleep(wait)

	print, nextWait := f()
	log.Println(print)

	go ExecuteWithDelayAndSchedule(f, nextWait)
}
