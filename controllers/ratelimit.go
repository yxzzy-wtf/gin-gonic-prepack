package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yxzzy-wtf/gin-gonic-prepack/config"
	"github.com/yxzzy-wtf/gin-gonic-prepack/util"
)

type ruleDescription struct {
	seconds int
	max     int
}

type rule struct {
	duration time.Duration
	limit    int
}

type bucket struct {
	rules  *map[string]rule
	access map[string]int
}

func (b *bucket) take(resource string) bool {
	r, ex := (*b.rules)[resource]
	if !ex {
		// does not exist, forced to try match on regex?
		regexMatched := false
		for attemptMatch, attemptRes := range *b.rules {
			match, _ := regexp.MatchString("^"+attemptMatch+"$", resource)
			if match {
				resource = attemptMatch
				r = attemptRes
				regexMatched = true
				break
			}
		}

		if !regexMatched {
			// Default to Global
			log.Printf("defaulting %v to global\n", resource)
			resource = ""
			r = (*b.rules)[resource]
		}
	}
	max := r.limit
	duration := r.duration

	remaining, ex := b.access[resource]
	if !ex {
		b.access[resource] = max
		remaining = max
	}

	if remaining > 0 {
		remaining = remaining - 1
		b.access[resource] = remaining

		go func(b *bucket, res string, d time.Duration) {
			time.Sleep(d)
			b.access[resource] = b.access[resource] + 1
		}(b, resource, duration)

		return true
	}

	return false
}

type megabucket struct {
	buckets map[string]bucket
	rules   map[string]rule
}

func (m *megabucket) loadFromConfig(filename string) {
	file, _ := os.Open("conf.json")
	defer file.Close()
	dec := json.NewDecoder(file)
	ruleMap := map[string]ruleDescription{}
	if err := dec.Decode(&ruleMap); err != nil {
		panic(err)
	}

	for rkey, r := range ruleMap {
		m.rules[rkey] = rule{duration: time.Second * time.Duration(r.seconds), limit: r.max}
	}
}

func (m *megabucket) take(signature string, resource string) bool {
	b, ex := m.buckets[signature]
	if !ex {
		b = bucket{
			rules:  &m.rules,
			access: map[string]int{},
		}
		m.buckets[signature] = b
	}

	return b.take(resource)
}

var unauthed = megabucket{
	buckets: map[string]bucket{},
	rules:   map[string]rule{},
}
var unauthLoaded = false

/**
 * Applies rate limiting to unauthorized actors based on their IP address.
 * Imperfect, but better than a stab to the eye with a blunt pencil.
 */
func UnauthRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !unauthLoaded {
			unauthed.loadFromConfig(config.GetConfigPath(config.Config().UnauthedRateLimitConfig))
			unauthLoaded = true
		}

		ip := c.ClientIP()

		if !unauthed.take(ip, c.Request.Method+":"+c.FullPath()) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
	}
}

var authed = megabucket{
	buckets: map[string]bucket{},
	rules:   map[string]rule{},
}
var authLoaded = false

/**
 *  Authorized rate limit. Using the UID of the authorized user as the
 *  accessor signature, rate limit based on the preexisting rules.
 */
func AuthedRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !authLoaded {
			authed.loadFromConfig(config.GetConfigPath(config.Config().AuthedRateLimitConfig))
			authLoaded = true
		}

		pif, exists := c.Get("principal")
		p := pif.(util.PrincipalInfo)
		if !exists {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if !authed.take(p.Uid.String(), c.Request.Method+":"+c.FullPath()) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
	}
}
