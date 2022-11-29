// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Serving of pprof-like profiles.

package main

import (
	"bufio"
	"fmt"
	"internal/trace"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/google/pprof/profile"
)

func goCmd() string {
	var exeSuffix string
	if runtime.GOOS == "windows" {
		exeSuffix = ".exe"
	}
	path := filepath.Join(runtime.GOROOT(), "bin", "go"+exeSuffix)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return "go"
}

func init() {
	http.HandleFunc("/io", serveSVGProfile(pprofByGoroutine(computePprofIO)))
	http.HandleFunc("/block", serveSVGProfile(pprofByGoroutine(computePprofBlock)))
	http.HandleFunc("/syscall", serveSVGProfile(pprofByGoroutine(computePprofSyscall)))
	http.HandleFunc("/sched", serveSVGProfile(pprofByGoroutine(computePprofSched)))

	http.HandleFunc("/regionio", serveSVGProfile(pprofByRegion(computePprofIO)))
	http.HandleFunc("/regionblock", serveSVGProfile(pprofByRegion(computePprofBlock)))
	http.HandleFunc("/regionsyscall", serveSVGProfile(pprofByRegion(computePprofSyscall)))
	http.HandleFunc("/regionsched", serveSVGProfile(pprofByRegion(computePprofSched)))
}

// Record represents one entry in pprof-like profiles.
type Record struct {
	stk    []*trace.Frame
	n      uint64
	time   int64
	labels map[string][]string
}

// interval represents a time interval in the trace.
type interval struct {
	begin, end int64 // nanoseconds.
}

func pprofByGoroutine(compute func(io.Writer, map[uint64][]interval, []*trace.Event) error) func(w io.Writer, r *http.Request) error {
	return func(w io.Writer, r *http.Request) error {
		id := r.FormValue("id")
		events, err := parseEvents()
		if err != nil {
			return err
		}
		gToIntervals, err := pprofMatchingGoroutines(id, events)
		if err != nil {
			return err
		}
		return compute(w, gToIntervals, events)
	}
}

func pprofByRegion(compute func(io.Writer, map[uint64][]interval, []*trace.Event) error) func(w io.Writer, r *http.Request) error {
	return func(w io.Writer, r *http.Request) error {
		filter, err := newRegionFilter(r)
		if err != nil {
			return err
		}
		gToIntervals, err := pprofMatchingRegions(filter)
		if err != nil {
			return err
		}
		events, _ := parseEvents()

		return compute(w, gToIntervals, events)
	}
}

// pprofMatchingGoroutines parses the goroutine type id string (i.e. pc)
// and returns the ids of goroutines of the matching type and its interval.
// If the id string is empty, returns nil without an error.
func pprofMatchingGoroutines(id string, events []*trace.Event) (map[uint64][]interval, error) {
	if id == "" {
		return nil, nil
	}
	pc, err := strconv.ParseUint(id, 10, 64) // id is string
	if err != nil {
		return nil, fmt.Errorf("invalid goroutine type: %v", id)
	}
	analyzeGoroutines(events)
	var res map[uint64][]interval
	for _, g := range gs {
		if g.PC != pc {
			continue
		}
		if res == nil {
			res = make(map[uint64][]interval)
		}
		endTime := g.EndTime
		if g.EndTime == 0 {
			endTime = lastTimestamp() // the trace doesn't include the goroutine end event. Use the trace end time.
		}
		res[g.ID] = []interval{{begin: g.StartTime, end: endTime}}
	}
	if len(res) == 0 && id != "" {
		return nil, fmt.Errorf("failed to find matching goroutines for id: %s", id)
	}
	return res, nil
}

// pprofMatchingRegions returns the time intervals of matching regions
// grouped by the goroutine id. If the filter is nil, returns nil without an error.
func pprofMatchingRegions(filter *regionFilter) (map[uint64][]interval, error) {
	res, err := analyzeAnnotations()
	if err != nil {
		return nil, err
	}
	if filter == nil {
		return nil, nil
	}

	gToIntervals := make(map[uint64][]interval)
	for id, regions := range res.regions {
		for _, s := range regions {
			if filter.match(id, s) {
				gToIntervals[s.G] = append(gToIntervals[s.G], interval{begin: s.firstTimestamp(), end: s.lastTimestamp()})
			}
		}
	}

	for g, intervals := range gToIntervals {
		// in order to remove nested regions and
		// consider only the outermost regions,
		// first, we sort based on the start time
		// and then scan through to select only the outermost regions.
		sort.Slice(intervals, func(i, j int) bool {
			x := intervals[i].begin
			y := intervals[j].begin
			if x == y {
				return intervals[i].end < intervals[j].end
			}
			return x < y
		})
		var lastTimestamp int64
		var n int
		// select only the outermost regions.
		for _, i := range intervals {
			if lastTimestamp <= i.begin {
				intervals[n] = i // new non-overlapping region starts.
				lastTimestamp = i.end
				n++
			} // otherwise, skip because this region overlaps with a previous region.
		}
		gToIntervals[g] = intervals[:n]
	}
	return gToIntervals, nil
}

// computePprofIO generates IO pprof-like profile (time spent in IO wait, currently only network blocking event).
func computePprofIO(w io.Writer, gToIntervals map[uint64][]interval, events []*trace.Event) error {
	return buildProfileFromEvents(w, gToIntervals, events, trace.EvGoBlockNet)
}

// computePprofBlock generates blocking pprof-like profile (time spent blocked on synchronization primitives).
func computePprofBlock(w io.Writer, gToIntervals map[uint64][]interval, events []*trace.Event) error {
	return buildProfileFromEvents(w, gToIntervals, events,
		trace.EvGoBlockSend, trace.EvGoBlockRecv, trace.EvGoBlockSelect,
		trace.EvGoBlockSync, trace.EvGoBlockCond, trace.EvGoBlockGC,
		// TODO(hyangah): figure out why EvGoBlockGC should be here.
		// EvGoBlockGC indicates the goroutine blocks on GC assist, not
		// on synchronization primitives.
	)
}

// computePprofSyscall generates syscall pprof-like profile (time spent blocked in syscalls).
func computePprofSyscall(w io.Writer, gToIntervals map[uint64][]interval, events []*trace.Event) error {
	return buildProfileFromEvents(w, gToIntervals, events, trace.EvGoSysCall)
}

// computePprofSched generates scheduler latency pprof-like profile
// (time between a goroutine become runnable and actually scheduled for execution).
func computePprofSched(w io.Writer, gToIntervals map[uint64][]interval, events []*trace.Event) error {
	return buildProfileFromEvents(w, gToIntervals, events, trace.EvGoUnblock, trace.EvGoCreate)
}

// pprofOverlappingDuration returns the overlapping duration between
// the time intervals in gToIntervals and the specified event.
// If gToIntervals is nil, this simply returns the event's duration.
func pprofOverlappingDuration(gToIntervals map[uint64][]interval, ev *trace.Event) time.Duration {
	if gToIntervals == nil { // No filtering.
		return time.Duration(ev.Link.Ts-ev.Ts) * time.Nanosecond
	}
	intervals := gToIntervals[ev.G]
	if len(intervals) == 0 {
		return 0
	}

	var overlapping time.Duration
	for _, i := range intervals {
		if o := overlappingDuration(i.begin, i.end, ev.Ts, ev.Link.Ts); o > 0 {
			overlapping += o
		}
	}
	return overlapping
}

// serveSVGProfile serves pprof-like profile generated by prof as svg.
func serveSVGProfile(prof func(w io.Writer, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.FormValue("raw") != "" {
			w.Header().Set("Content-Type", "application/octet-stream")
			if err := prof(w, r); err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("X-Go-Pprof", "1")
				http.Error(w, fmt.Sprintf("failed to get profile: %v", err), http.StatusInternalServerError)
				return
			}
			return
		}

		blockf, err := os.CreateTemp("", "block")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create temp file: %v", err), http.StatusInternalServerError)
			return
		}
		defer func() {
			blockf.Close()
			os.Remove(blockf.Name())
		}()
		blockb := bufio.NewWriter(blockf)
		if err := prof(blockb, r); err != nil {
			http.Error(w, fmt.Sprintf("failed to generate profile: %v", err), http.StatusInternalServerError)
			return
		}
		if err := blockb.Flush(); err != nil {
			http.Error(w, fmt.Sprintf("failed to flush temp file: %v", err), http.StatusInternalServerError)
			return
		}
		if err := blockf.Close(); err != nil {
			http.Error(w, fmt.Sprintf("failed to close temp file: %v", err), http.StatusInternalServerError)
			return
		}
		svgFilename := blockf.Name() + ".svg"
		if output, err := exec.Command(goCmd(), "tool", "pprof", "-svg", "-output", svgFilename, blockf.Name()).CombinedOutput(); err != nil {
			http.Error(w, fmt.Sprintf("failed to execute go tool pprof: %v\n%s", err, output), http.StatusInternalServerError)
			return
		}
		defer os.Remove(svgFilename)
		w.Header().Set("Content-Type", "image/svg+xml")
		http.ServeFile(w, r, svgFilename)
	}
}

func buildProfile(prof map[uint64][]*Record) *profile.Profile {
	p := &profile.Profile{
		PeriodType: &profile.ValueType{Type: "trace", Unit: "count"},
		Period:     1,
		SampleType: []*profile.ValueType{
			{Type: "contentions", Unit: "count"},
			{Type: "delay", Unit: "nanoseconds"},
		},
	}
	locs := make(map[uint64]*profile.Location)
	funcs := make(map[string]*profile.Function)
	for _, recs := range prof {
		for _, r := range recs {
			var sloc []*profile.Location
			for _, frame := range r.stk {
				loc := locs[frame.PC]
				if loc == nil {
					fn := funcs[frame.File+frame.Fn]
					if fn == nil {
						fn = &profile.Function{
							ID:         uint64(len(p.Function) + 1),
							Name:       frame.Fn,
							SystemName: frame.Fn,
							Filename:   frame.File,
						}
						p.Function = append(p.Function, fn)
						funcs[frame.File+frame.Fn] = fn
					}
					loc = &profile.Location{
						ID:      uint64(len(p.Location) + 1),
						Address: frame.PC,
						Line: []profile.Line{
							{
								Function: fn,
								Line:     int64(frame.Line),
							},
						},
					}
					p.Location = append(p.Location, loc)
					locs[frame.PC] = loc
				}
				sloc = append(sloc, loc)
			}
			p.Sample = append(p.Sample, &profile.Sample{
				Value:    []int64{int64(r.n), r.time},
				Location: sloc,
				Label:    r.labels,
			})
		}
	}
	return p
}

// labelMap tracks the labels for goroutines
type labelMap map[uint64]map[string][]string

// update sets the current labels for the goroutine based on the given event,
// including new labels, inheriting labels, and removing labels when the
// goroutine ends.
func (lm labelMap) update(ev *trace.Event) {
	switch ev.Type {
	case trace.EvGoroutineLabels:
		if len(ev.SArgs) == 0 {
			delete(lm, ev.G)
		} else {
			m := make(map[string][]string)
			for i := 0; i < len(ev.SArgs); i += 2 {
				m[ev.SArgs[i]] = []string{ev.SArgs[i+1]}
			}
			lm[ev.G] = m
		}
	case trace.EvGoCreate:
		if l, ok := lm[ev.G]; ok {
			lm[ev.Args[0]] = l
		}
	case trace.EvGoEnd:
		delete(lm, ev.G)
	}
}

func labelsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		v2, ok := b[k]
		if !ok {
			return false
		}
		if v[0] != v2[0] {
			return false
		}
	}
	return true
}

func buildProfileFromEvents(w io.Writer, gToIntervals map[uint64][]interval, events []*trace.Event, eventTypes ...byte) error {
	filter := make(map[byte]bool)
	for _, t := range eventTypes {
		filter[t] = true
	}
	prof := make(map[uint64][]*Record)
	labels := make(labelMap)
	for _, ev := range events {
		labels.update(ev)
		if !filter[ev.Type] || ev.Link == nil || ev.StkID == 0 || len(ev.Stk) == 0 {
			continue
		}
		overlapping := pprofOverlappingDuration(gToIntervals, ev)
		if overlapping > 0 {
			recs := prof[ev.StkID]
			l := labels[ev.G]
			var rec *Record
			for _, r := range recs {
				if labelsEqual(l, r.labels) {
					rec = r
					break
				}
			}
			if rec == nil {
				rec = new(Record)
				rec.stk = ev.Stk
				rec.labels = l
				prof[ev.StkID] = append(recs, rec)
			}
			rec.n++
			rec.time += overlapping.Nanoseconds()
		}
	}
	return buildProfile(prof).Write(w)
}
