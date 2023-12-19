package pathhealth_test

import (
	"testing"

	"github.com/scionproto/scion/go/pkg/gateway/pathhealth"
	"github.com/stretchr/testify/assert"
)

func TestGraphBuilder(t *testing.T) {

	path1 := []pathhealth.Edge{
		pathhealth.NewEdge("a", "b", "1"),
		pathhealth.NewEdge("b", "c", "2"),
	}
	path2 := []pathhealth.Edge{
		pathhealth.NewEdge("a", "b", "3"),
		pathhealth.NewEdge("b", "c", "2"),
	}

	pathsEdgeReprs := [][]pathhealth.Edge{path1, path2}
	g := pathhealth.NewGraph(pathsEdgeReprs)

	sourceNode := pathsEdgeReprs[0][0].Source
	destinationNode := pathsEdgeReprs[0][len(pathsEdgeReprs[0])-1].Target

	// Find paths
	selectedPaths := g.FindPathsGreedy(sourceNode, destinationNode, 2)

	assert.Equal(t, 2, len(selectedPaths))
	assert.Equal(t, path1, selectedPaths[0])
	assert.Equal(t, path2, selectedPaths[1])
	// calculated this probablity by hand and it is 0.109
	proba := pathhealth.CalcProbabilityOfCompromiseConst(selectedPaths)
	assert.InDelta(t, 0.109, proba, 0.0001) // Use assert.InDelta for floating-point comparison with a tolerance of 0.001

}
