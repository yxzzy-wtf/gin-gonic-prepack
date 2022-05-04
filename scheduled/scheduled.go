package scheduled

import (
	"fmt"
	"time"
)

type Scheduled func() (string, time.Duration)

func Schedule(f Scheduled) {
	print, wait := f()
	fmt.Println(print)

	go func(w time.Duration) {
		time.Sleep(w)
		Schedule(f)
	}(wait)
}
