// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pathhealth

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// rejectedInfo is a string to log about dead paths.
	deadInfo = "dead (probes are not passing through)"
	// rejectedInfo is a string to log about paths rejected by path policies.
	rejectedInfo = "rejected by path policy"
)

// PathPolicy filters the set of paths.
type PathPolicy interface {
	Filter(paths []snet.Path) []snet.Path
}

// FilteringPathSelector selects the best paths from a filtered set of paths.
type FilteringPathSelector struct {
	// PathPolicy is used to determine which paths are eligible and which are not.
	PathPolicy PathPolicy
	// RevocationStore keeps track of the revocations.
	RevocationStore
	// PathCount is the max number of paths to return to the user. Defaults to 1.
	PathCount int
}

// Select selects the best paths.
func (f *FilteringPathSelector) Select(selectables []Selectable, current FingerprintSet) Selection {
	type Allowed struct {
		Fingerprint snet.PathFingerprint
		Path        snet.Path
		Selectable  Selectable
		IsCurrent   bool
		IsRevoked   bool
	}

	// Sort out the paths allowed by the path policy.
	var allowed []Allowed
	var dead []snet.Path
	var rejected []snet.Path
	for _, selectable := range selectables {
		path := selectable.Path()
		if !isPathAllowed(f.PathPolicy, path) {
			rejected = append(rejected, path)
			continue
		}

		state := selectable.State()
		if !state.IsAlive {
			dead = append(dead, path)
			continue
		}
		fingerprint := snet.Fingerprint(path)
		_, isCurrent := current[fingerprint]
		allowed = append(allowed, Allowed{
			Path:        path,
			Fingerprint: fingerprint,
			IsCurrent:   isCurrent,
			IsRevoked:   f.RevocationStore.IsRevoked(path),
		})
	}
	// fmt.Println("----[Debug]: Allowed paths", len(allowed))
	// Sort the allowed paths according the the perf policy.
	sort.SliceStable(allowed, func(i, j int) bool {
		// If some of the paths are alive (probes are passing through), yet still revoked
		// prefer the non-revoked paths as the revoked ones may be flaky.
		switch {
		case allowed[i].IsRevoked && !allowed[j].IsRevoked:
			return false
		case !allowed[i].IsRevoked && allowed[j].IsRevoked:
			return true
		}
		if shorter, ok := isShorter(allowed[i].Path, allowed[j].Path); ok {
			return shorter
		}
		return allowed[i].Fingerprint > allowed[j].Fingerprint
	})

	// Make the info string.
	var format = "      %-44s %s"
	info := make([]string, 0, len(selectables)+1)
	info = append(info, fmt.Sprintf(format, "STATE", "PATH"))
	for _, a := range allowed {
		var state string
		if a.IsCurrent {
			state = "-->"
		}
		info = append(info, fmt.Sprintf(format, state, a.Path))
	}
	for _, path := range dead {
		info = append(info, fmt.Sprintf(format, deadInfo, path))
	}
	for _, path := range rejected {
		info = append(info, fmt.Sprintf(format, rejectedInfo, path))
	}

	pathCount := f.PathCount
	if pathCount == 0 {
		pathCount = 1
	}
	if pathCount > len(allowed) {
		// panic(fmt.Sprintf("PathCount %d is larger than the number of allowed paths %d", pathCount, len(allowed)))
		pathCount = len(allowed)
	}

	if len(allowed) == 0 {
		fmt.Println("----[Warning]: No paths found")
		return Selection{
			Paths:         make([]snet.Path, 0),
			Info:          strings.Join(info, "\n"),
			PathsAlive:    len(allowed),
			PathsDead:     len(dead),
			PathsRejected: len(rejected),
		}
	}

	paths := make([]snet.Path, 0, len(allowed))
	for i := 0; i < len(allowed); i++ {
		paths = append(paths, allowed[i].Path)
	}
	selectedPaths := buildGraphAndFindPaths(paths, pathCount)

	return Selection{
		Paths:         selectedPaths,
		Info:          strings.Join(info, "\n"),
		PathsAlive:    len(allowed),
		PathsDead:     len(dead),
		PathsRejected: len(rejected),
	}
}

// isPathAllowed returns true is path is allowed by the policy.
func isPathAllowed(policy PathPolicy, path snet.Path) bool {
	if policy == nil {
		return true
	}
	return len(policy.Filter([]snet.Path{path})) > 0
}

func isShorter(a, b snet.Path) (bool, bool) {
	mA, mB := a.Metadata(), b.Metadata()
	if mA == nil || mB == nil {
		return false, false
	}
	if lA, lB := len(mA.Interfaces), len(mB.Interfaces); lA != lB {
		return lA < lB, true
	}
	return false, false
}

var prevSelectedPaths []snet.Path
var prevGivenPaths []snet.Path

func buildGraphAndFindPaths(paths []snet.Path, numberOfPaths int) []snet.Path {
	// fmt.Println("----[Debug]: Building graph using paths", len(paths), "numberOfPaths", numberOfPaths)
	g := NewGraph()
	for _, path := range paths {
		ifaces := path.Metadata().Interfaces
		for i := 0; i < len(ifaces)-1; i += 2 {
			ifaceString := fmt.Sprintf("%s>%s", ifaces[i].ID.String(), ifaces[i+1].ID.String())
			// fmt.Println("----[Debug]: Adding edge", ifaces[i].IA.String(), ifaces[i+1].IA.String(), ifaceString)
			g.AddEdge(ifaces[i].IA.String(), ifaces[i+1].IA.String(), ifaceString)
		}
	}
	sourceNode := paths[0].Metadata().Interfaces[0].IA.String()
	destinationNode := paths[0].Metadata().Interfaces[len(paths[0].Metadata().Interfaces)-1].IA.String()
	selectedPaths := findPaths(g, sourceNode, destinationNode, numberOfPaths)

	// Compare current selectedPaths with previous selectedPaths
	if !isSamePathSet(paths, prevGivenPaths) {
		returnedOriginalPaths := make([]snet.Path, 0, len(selectedPaths))

		for i, p := range selectedPaths {
			opath := matchPathWithOriginalPaths(p, paths)
			if opath == nil {
				fmt.Println("----[Warning]: Path generated by Graph does not exist in original paths.", len(paths))
				// fmt.Println("----[Error]: Path generated by Graph does not exist in original paths.", p, paths)
				// select a random path from paths. check if it is already used first
				for {
					opath = paths[i] // use a random path. I avoided 0 because i by chance, it is the same as the first path in paths we have not enough senders in sessions and that throws an error
					for _, p := range returnedOriginalPaths {
						if pathToString(p) == pathToString(opath) {
							opath = nil
							break
						}
					}
					if opath != nil {
						break
					}

				}
			}
			returnedOriginalPaths = append(returnedOriginalPaths, opath)
		}

		// fmt.Println("----[Debug]: Selected Pathset", selectedPaths)
		fmt.Println("----[Debug]: Selected", len(selectedPaths), "Paths with probability of compromise", CalcProbabilityOfCompromise(selectedPaths))

		// Update previous selectedPaths
		prevSelectedPaths = make([]snet.Path, len(returnedOriginalPaths))
		copy(prevSelectedPaths, returnedOriginalPaths)
		// Update previous selectedPaths
		prevGivenPaths = make([]snet.Path, len(paths))
		copy(prevGivenPaths, paths)

		return returnedOriginalPaths
	}

	return prevSelectedPaths
}

func isSamePathSet(paths1, paths2 []snet.Path) bool {
	// Convert paths1 and paths2 to sets
	set1 := make(map[string]struct{})
	set2 := make(map[string]struct{})

	for _, p := range paths1 {
		set1[pathToString(p)] = struct{}{}
	}

	for _, p := range paths2 {
		set2[pathToString(p)] = struct{}{}
	}

	// Check if the sets have the same size
	if len(set1) != len(set2) {
		return false
	}

	// Check if all paths in set1 are also in set2
	for path := range set1 {
		if _, ok := set2[path]; !ok {
			return false
		}
	}

	return true
}

// pathToString converts a path to a string representation
func pathToString(path snet.Path) string {
	var sb strings.Builder
	for _, hop := range path.Metadata().Interfaces {
		sb.WriteString(hop.String())
		sb.WriteString(" ")
	}
	return sb.String()
}

// match the returned path string with the original paths given to the Select() method, so that no
// information contained in the original variables is lost. This function returns nil if no original
// path is found.
func matchPathWithOriginalPaths(path []Edge, originalPaths []snet.Path) snet.Path {
Outerloop:
	for _, opath := range originalPaths {
		if len(opath.Metadata().Interfaces) != 2*len(path) {
			continue
		}
		for i, edge := range path {
			if edge.Source != opath.Metadata().Interfaces[2*i].IA.String() {
				continue Outerloop
			}
			if edge.Target != opath.Metadata().Interfaces[2*i+1].IA.String() {
				continue Outerloop
			}
			// interface is e.g. 1>551. split the string into a first and second part
			interfaces := strings.Split(edge.Interface, ">")
			if interfaces[0] != opath.Metadata().Interfaces[2*i].ID.String() {
				continue Outerloop
			}
			if interfaces[1] != opath.Metadata().Interfaces[2*i+1].ID.String() {
				continue Outerloop
			}
		}
		return opath
	}
	// fmt.Println("----[Error]: Could not match path with original paths. path:", path, "originalPaths:", originalPaths)
	return nil
}
