package recoveryclient

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	settingInterval    = "backup_interval_sec"
	settingLastAttempt = "backup_last_attempt"
)

// MinInterval is the shortest schedule accepted: each run snapshots the whole database.
// MaxInterval is the longest: beyond a year the setting is a way of turning backups off
// without saying so.
const (
	MinInterval = 15 * time.Minute
	MaxInterval = 366 * 24 * time.Hour
)

// ErrBadInterval is returned for a schedule outside 0 (off) or [MinInterval, MaxInterval].
var ErrBadInterval = fmt.Errorf("recoveryclient: interval must be 0 (off) or between %s and %s", MinInterval, MaxInterval)

// Interval is the backup schedule: the admin's setting when one exists, else defaultInterval
// (the product's environment default). Zero means off.
func Interval(defaultInterval time.Duration, settings Settings) (time.Duration, error) {
	v, err := settings.Get(settingInterval)
	if errors.Is(err, ErrNotFound) {
		return defaultInterval, nil
	}
	if err != nil {
		return 0, err
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", settingInterval, err)
	}
	return time.Duration(sec) * time.Second, nil
}

// SetInterval stores the schedule in whole seconds. The bound is checked on the seconds
// before any conversion, so no value wraps to zero and reads as "off".
func SetInterval(settings Settings, sec int64) error {
	if sec != 0 && (sec < int64(MinInterval/time.Second) || sec > int64(MaxInterval/time.Second)) {
		return ErrBadInterval
	}
	return settings.Set(settingInterval, strconv.FormatInt(sec, 10))
}

// NextRun is when the scheduler will next back up, or ok=false when the schedule is off.
// It counts from the last attempt, successful or not, so a failing destination is retried
// once per interval rather than every tick.
func NextRun(defaultInterval time.Duration, settings Settings) (time.Time, bool, error) {
	interval, err := Interval(defaultInterval, settings)
	if err != nil || interval == 0 {
		return time.Time{}, false, err
	}
	last, err := lastAttempt(settings)
	if err != nil {
		return time.Time{}, false, err
	}
	if last.IsZero() {
		return time.Now().UTC(), true, nil
	}
	return last.Add(interval), true, nil
}

func lastAttempt(settings Settings) (time.Time, error) {
	v, err := settings.Get(settingLastAttempt)
	if errors.Is(err, ErrNotFound) || (err == nil && v == "") {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, v)
}

func markAttempt(settings Settings) error {
	return settings.Set(settingLastAttempt, time.Now().UTC().Format(time.RFC3339))
}
