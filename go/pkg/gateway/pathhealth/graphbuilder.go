package pathhealth

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/snet"
)

// Edge represents an edge in the graph, i.e. a connection between two nodes with a specific
// interface
type Edge struct {
	Source, Target, Interface string
}

func NewEdge(source, target, iface string) Edge {
	return Edge{
		Source:    source,
		Target:    target,
		Interface: iface,
	}
}

func (e Edge) String() string {
	return fmt.Sprintf("(%s - %s - %s)", e.Source, e.Interface, e.Target)
}

type Graph struct {
	// Paths is list of paths from which this graph is build. This is necessary as not every path in
	// the graph is valid
	Paths [][]Edge
	// Weights is a map of weights for each edge, where the key is edge.String()
	Weights map[string]float64
}

func NewGraph(pathsEdgeReprs [][]Edge) *Graph {
	g := Graph{
		Paths:   pathsEdgeReprs,
		Weights: make(map[string]float64),
	}

	for _, path := range pathsEdgeReprs {
		for _, e := range path {
			// add edge between nodes path[i] and path[i+2] with interface id path[i+1]
			g.Weights[e.String()] = 0.1
		}
	}

	return &g
}

// FindPathsGreedy finds the n paths with a low probability of compromise
func (g *Graph) FindPathsGreedy(source, target string, n int) [][]Edge {
	var paths [][]Edge

	for i := 0; i < n; i++ {
		// Find the path with the lowest score
		minScorePath := g.Paths[0]
		minScore := g.CalcPathScore(minScorePath)
		for _, p := range g.Paths {
			score := g.CalcPathScore(p)
			if score < minScore {
				minScore = score
				minScorePath = p
			}
		}

		// Add the path with lowest score to the list of selected paths
		paths = append(paths, minScorePath)

		// Increase the weight of the edges in the current path
		for _, e := range minScorePath {
			g.Weights[e.String()] *= 100.0
			// Increase the weight of other edges between the same nodes
			for _, p := range g.Paths {
				for _, e2 := range p {
					if e.Source == e2.Source && e.Target == e2.Target && e.Interface != e2.Interface {
						g.Weights[e2.String()] *= 10.0
					}
				}

			}
		}
	}

	return paths
}

// Calculates the sum of the weights of the edges in the given path.
func (g *Graph) CalcPathScore(path []Edge) float64 {
	score := 0.0
	for _, e := range path {
		score += g.Weights[e.String()]
	}
	return score
}

// Calculates the probability of compromise for a given set of paths with the constant edge
// probability of 0.10
func CalcProbabilityOfCompromiseConst(paths [][]Edge) float64 {
	const edgeProbability = 0.10

	var terms []float64
	// calculate the probability of compromise for each subset of paths using the
	// inclusion-exclusion principle
	for i := 1; i <= len(paths); i++ {
		for _, subset := range Combination(paths, i) {
			sharedEdges := make(map[string]bool)
			for _, path := range subset {
				for _, edge := range path {
					sharedEdges[edge.String()] = true
				}
			}
			prob := 1.0
			for range sharedEdges {
				prob *= (1 - edgeProbability)
			}
			if i%2 == 0 {
				prob = -prob
			}
			terms = append(terms, prob)
		}
	}

	// sum up the terms
	sum := 0.0
	for _, term := range terms {
		sum += term
	}

	return 1 - sum
}

var prevGivenPaths [][]Edge
var prevSelectedPaths [][]Edge
var prevSelectedOriginalPaths []snet.Path

// Takes a list of snet.Paths and returns a list of snet.Paths are selected greedily. The function
// is cached, i.e. if given paths have not changed since last call, the selected paths will not be
// computed anew.
func BuildGraphAndFindPaths(paths []snet.Path, numberOfPaths int) []snet.Path {

	// transform all paths into their string representation for easier processing
	pathsEdgeReprs := make([][]Edge, len(paths))
	for i, path := range paths {
		pathsEdgeReprs[i] = pathToEdgeRepresentation(path)
	}

	// Check if the given paths have changed since last call
	if isSamePathSet(pathsEdgeReprs, prevGivenPaths) {
		return prevSelectedOriginalPaths
	}

	// Build the graph
	g := NewGraph(pathsEdgeReprs)
	sourceNode := pathsEdgeReprs[0][0].Source
	destinationNode := pathsEdgeReprs[0][len(pathsEdgeReprs[0])-1].Target

	// Find paths
	selectedPaths := g.FindPathsGreedy(sourceNode, destinationNode, numberOfPaths)

	// Match the selectedPaths back to the original paths
	returnOriginalPaths := make([]snet.Path, 0, len(selectedPaths))
	for _, p := range selectedPaths {
		returnOriginalPaths = append(returnOriginalPaths, matchPathWithOriginalPaths(p, paths))
	}

	if !isSamePathSet(prevSelectedPaths, selectedPaths) {
		// print the selected paths
		fmt.Println("Selected paths:")
		for _, p := range returnOriginalPaths {
			fmt.Println(p.Metadata().Interfaces)
		}
	}

	// Cache the results
	prevGivenPaths = pathsEdgeReprs
	prevSelectedPaths = selectedPaths
	prevSelectedOriginalPaths = returnOriginalPaths

	return returnOriginalPaths
}

func isSamePathSet(paths1, paths2 [][]Edge) bool {

	if paths1 == nil || paths2 == nil {
		return false
	}

	// Convert paths1 and paths2 to sets
	set1 := make(map[string]struct{})
	set2 := make(map[string]struct{})
	for _, p := range paths1 {
		set1[pathEdgesToString(p)] = struct{}{}
	}
	for _, p := range paths2 {
		set2[pathEdgesToString(p)] = struct{}{}
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

// Converts an snet path to a list of edges (source, interface, target) for easier processing
// snet.Path are a list of ASes and interfaces, e.g. [("AS1, IF7"), ("AS2, IF11"), ("AS2, IF3"),
// ("AS3, IF1")]. The generated list of edges splits a node into an in-node and an out-node to also
// address node-disjointness in path selection. Innodes are represented by appending a "_in" to the
// end of the AS string, whereas outnodes are represented by appending "_out". Output for above
// example: [("AS1_out, "7>11", "AS2_in"), ("AS2_in", "edgesplit", "AS2_out"), ("AS2_out", "3>1"
// "AS3_in")]
func pathToEdgeRepresentation(path snet.Path) []Edge {
	var pathEdges []Edge
	for i := 0; i < len(path.Metadata().Interfaces); i += 2 {
		hop := path.Metadata().Interfaces[i]
		nextHop := path.Metadata().Interfaces[i+1]
		iface := hop.ID.String() + ">" + nextHop.ID.String()
		pathEdges = append(pathEdges, NewEdge(hop.IA.String()+"_out", iface, nextHop.IA.String()+"_in"))
		pathEdges = append(pathEdges, NewEdge(nextHop.IA.String()+"_in", "edgesplit", nextHop.IA.String()+"_out"))
	}
	return pathEdges
}

// Join the edge representation using ">" symbols
func pathEdgesToString(path []Edge) string {
	var pathString string
	for _, edge := range path {
		pathString += edge.String() + " > "
	}
	return pathString
}

// match the returned path string with the original paths given to the Select() method, so that no
// information contained in the original variables is lost. This function returns nil if no original
// path is found.
func matchPathWithOriginalPaths(path []Edge, originalPaths []snet.Path) snet.Path {
	for _, opath := range originalPaths {
		opathString := pathEdgesToString(pathToEdgeRepresentation(opath))
		if opathString == pathEdgesToString(path) {
			return opath
		}
	}
	return nil
}

// Combination generates all combinations of the given size from the input slice.
func Combination(input [][]Edge, size int) [][][]Edge {
	length := len(input)
	if size > length {
		return nil
	}

	indices := make([]int, size)
	for i := range indices {
		indices[i] = i
	}

	var combinations [][][]Edge
	for {
		combination := make([][]Edge, size)
		for i, index := range indices {
			combination[i] = input[index]
		}
		combinations = append(combinations, combination)

		// Generate the next combination
		i := size - 1
		for ; i >= 0 && indices[i] == i+length-size; i-- {
		}
		if i < 0 {
			break
		}

		indices[i]++
		for j := i + 1; j < size; j++ {
			indices[j] = indices[j-1] + 1
		}
	}

	return combinations
}
