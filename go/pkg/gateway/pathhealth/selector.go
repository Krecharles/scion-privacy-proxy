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
	"math"
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

	// pathCount := f.PathCount
	pathCount := 3
	if pathCount == 0 {
		pathCount = 1
	}
	if pathCount > len(allowed) {
		pathCount = len(allowed)
	}

	if len(allowed) == 0 {
		fmt.Println("----[Debug]: No paths found")
		return Selection{
			Paths:         make([]snet.Path, 0, 0),
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

func buildGraphAndFindPaths(paths []snet.Path, numberOfPaths int) []snet.Path {
	// fmt.Println("----[Debug]: Building graph using paths", len(paths))
	g := NewGraph()
	for _, path := range paths {
		ifaces := path.Metadata().Interfaces
		for i := 0; i < len(ifaces)-1; i += 2 {
			g.AddEdge(ifaces[i].IA.String(), ifaces[i+1].IA.String())
		}
	}
	sourceNode := paths[0].Metadata().Interfaces[0].IA.String()
	destinationNode := paths[0].Metadata().Interfaces[len(paths[0].Metadata().Interfaces)-1].IA.String()
	selectedPaths := findPaths(g, sourceNode, destinationNode, numberOfPaths)
	returnedOriginalPaths := make([]snet.Path, 0, len(selectedPaths))

	for _, p := range selectedPaths {
		opath := matchPathWithOriginalPaths(p, paths)
		if opath == nil {
			panic("Path not found")
		}
		returnedOriginalPaths = append(returnedOriginalPaths, opath)

	}

	// for _, p := range returnedOriginalPaths {
	// 	fmt.Println(p)
	// }

	return returnedOriginalPaths

}

// match the returned path string with the original paths given to the Select() method, so that no
// information contained in the original variables is lost. This function returns nil if no original
// path is found.
func matchPathWithOriginalPaths(path []string, originalPaths []snet.Path) snet.Path {
Outerloop:
	for _, opath := range originalPaths {
		if len(opath.Metadata().Interfaces) != (len(path)-1)*2 {
			continue
		}
		for i, hop := range path {

			if i == len(path)-1 {
				if hop != opath.Metadata().Interfaces[2*i-1].IA.String() {
					continue Outerloop
				}
			} else {
				if hop != opath.Metadata().Interfaces[2*i].IA.String() {
					continue Outerloop
				}
			}
		}
		return opath

	}
	fmt.Println("----[Error]: Could not match path with original paths. path:", path, "originalPaths:", originalPaths)
	return nil
}

func findPaths(g *Graph, source, target string, n int) [][]string {
	var paths [][]string
	for i := 0; i < n; i++ {
		path, _ := g.Dijkstra(source, target)
		if len(path) == 0 {
			break
		}
		paths = append(paths, path)
		// Increase the weight of the edges in the current path
		for j := 0; j < len(path)-1; j++ {
			g.SetEdgeWeight(path[j], path[j+1], g.Edges[path[j]][path[j+1]]*100)
		}
	}
	return paths
}

type Edge struct {
	Source, Target string
	Weight         int
}

type Graph struct {
	Edges map[string]map[string]int
}

func NewGraph() *Graph {
	return &Graph{
		Edges: make(map[string]map[string]int),
	}
}

func (g *Graph) AddEdge(source, target string) {
	if _, exists := g.Edges[source]; !exists {
		g.Edges[source] = make(map[string]int)
	}
	g.Edges[source][target] = 1 // Default weight
}

func (g *Graph) SetEdgeWeight(source string, target string, weight int) {
	if _, exists := g.Edges[source]; exists {
		if _, exists := g.Edges[source][target]; exists {
			g.Edges[source][target] = weight
		}
	}
}

func (g *Graph) GetAllNodes() []string {
	var nodes []string
	for node := range g.Edges {
		nodes = append(nodes, node)
	}

	for _, targets := range g.Edges {
		for target := range targets {
			// Check if target node has any outgoing edges
			if _, exists := g.Edges[target]; !exists {
				nodes = append(nodes, target)
			}
		}
	}

	return nodes
}

func (g *Graph) Dijkstra(start, goal string) ([]string, int) {
	dist := make(map[string]int)
	prev := make(map[string]string)
	for _, node := range g.GetAllNodes() {
		dist[node] = math.MaxInt32
	}
	dist[start] = 0

	var unvisited []string
	for node := range g.Edges {
		unvisited = append(unvisited, node)
	}

	for len(unvisited) > 0 {
		// Find node with minimum distance
		minDist := math.MaxInt32
		var minNode string
		for _, node := range unvisited {
			if dist[node] < minDist {
				minDist = dist[node]
				minNode = node
			}
		}

		if minNode == goal {
			break
		}

		// Remove minNode from unvisited
		for i, node := range unvisited {
			if node == minNode {
				unvisited = append(unvisited[:i], unvisited[i+1:]...)
				break
			}
		}

		for neighbor, weight := range g.Edges[minNode] {
			alt := dist[minNode] + weight
			if alt < dist[neighbor] {
				dist[neighbor] = alt
				prev[neighbor] = minNode
			}
		}
	}

	// Construct the path
	var path []string
	for u := goal; u != ""; u = prev[u] {
		path = append([]string{u}, path...)
	}
	return path, dist[goal]
}
