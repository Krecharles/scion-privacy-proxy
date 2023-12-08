package pathhealth

import (
	"fmt"
	"math"
)

type Edge struct {
	Source, Target, Interface string
	Weight                    int
}

func (e Edge) String() string {
	return fmt.Sprintf("%s %s %s", e.Source, e.Interface, e.Target)
}

type Graph struct {
	Nodes map[string]bool
	Edges map[string][]Edge
}

func getPathString(path []Edge) string {
	if len(path) == 0 {
		return ""
	}
	str := path[0].Source
	for i, _ := range path {
		str += " " + path[i].Interface + " " + path[i].Target
	}
	return str
}

func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]bool),
		Edges: make(map[string][]Edge),
	}
}

func (g *Graph) AddEdge(source, target, iface string) {
	// Check if the edge already exists
	for _, edge := range g.Edges[source] {
		if edge.Target == target && edge.Interface == iface {
			// Edge already exists, so we return without adding it again
			return
		}
	}

	// If the edge does not exist, add it to the list of edges
	g.Edges[source] = append(g.Edges[source], Edge{
		Source:    source,
		Target:    target,
		Interface: iface,
		Weight:    1, // Default weight
	})

	// Make sure nodes are in the Nodes map
	g.Nodes[source] = true
	g.Nodes[target] = true
}

func (g *Graph) UpdateEdgeWeight(source, target, iface string, newWeight int) {
	for i, edge := range g.Edges[source] {
		if edge.Target == target && edge.Interface == iface {
			g.Edges[source][i].Weight = newWeight
			return
		}
	}
}

func (g *Graph) Dijkstra(start, goal string) ([]Edge, int) {
	dist := make(map[string]int)
	prev := make(map[string]Edge)
	for node := range g.Nodes {
		dist[node] = math.MaxInt32
	}
	dist[start] = 0

	visited := make(map[string]bool)

	for len(visited) < len(g.Nodes) {
		// Find the unvisited node with the smallest distance
		minNode := ""
		minDist := math.MaxInt32
		for node := range g.Nodes {
			if !visited[node] && dist[node] < minDist {
				minDist = dist[node]
				minNode = node
			}
		}

		if minNode == "" {
			break // All nodes visited or remaining nodes are inaccessible
		}

		visited[minNode] = true // Mark the node as visited

		for _, edge := range g.Edges[minNode] {
			if !visited[edge.Target] {
				newDist := dist[minNode] + edge.Weight
				if newDist < dist[edge.Target] {
					dist[edge.Target] = newDist
					prev[edge.Target] = edge // Store the edge leading to the target
				}
			}
		}
	}

	// Construct the path from the goal to the start using prev
	var path []Edge
	for at := goal; at != start && at != ""; {
		edge, exists := prev[at]
		if !exists {
			break // No path found
		}
		path = append([]Edge{edge}, path...)
		at = edge.Source
	}

	return path, dist[goal]
}

func findPaths(g *Graph, source, target string, n int) [][]Edge {
	var paths [][]Edge
	for i := 0; i < n; i++ {
		path, _ := g.Dijkstra(source, target)
		if len(path) == 0 {
			break
		}
		paths = append(paths, path)
		// Increase the weight of the edges in the current path
		for _, edge := range path {
			g.UpdateEdgeWeight(edge.Source, edge.Target, edge.Interface, edge.Weight*100)
		}
	}
	return paths
}

// Combination generates all combinations of the given size from the input slice.
func Combination(input [][]string, size int) [][][]string {
	length := len(input)
	if size > length {
		return nil
	}

	indices := make([]int, size)
	for i := range indices {
		indices[i] = i
	}

	var combinations [][][]string
	for {
		combination := make([][]string, size)
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

// Converts paths to a slice of edges
func pathsToEdges(paths [][]Edge) [][]string {
	var edges [][]string
	for _, path := range paths {
		pathEdgeStrings := make([]string, len(path))
		for i, edge := range path {
			pathEdgeStrings[i] = edge.String()
		}
		edges = append(edges, pathEdgeStrings)
	}
	return edges
}

// Calculates the probability of compromise for a given set of paths.
func CalcProbabilityOfCompromise(paths [][]Edge) float64 {
	const edgeProbability = 0.10
	edgeSets := pathsToEdges(paths)

	var terms []float64
	for i := 1; i <= len(edgeSets); i++ {
		for _, subset := range Combination(edgeSets, i) {
			sharedEdges := make(map[string]bool)
			for _, path := range subset {
				for _, edge := range path {
					sharedEdges[edge] = true
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

	sum := 0.0
	for _, term := range terms {
		sum += term
	}

	return 1 - sum
}
