package policy

import (
	"github.com/bmatcuk/doublestar/v4"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// newCELEnv builds the CEL environment shared by every rule's when-expression
// and sugar compilation. See docs/CEL-Ruels-Plan.md for the variable table.
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("tool_name", cel.StringType),
		cel.Variable("tool_input", cel.DynType),
		cel.Variable("segment", cel.DynType),
		cel.Variable("ps_segment", cel.DynType),
		cel.Variable("cwd", cel.StringType),
		cel.Variable("session_id", cel.StringType),

		cel.Function("glob",
			cel.Overload("glob_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(path, pattern ref.Val) ref.Val {
					// doublestar.Match takes (pattern, path); our CEL signature is
					// glob(path, pattern), so swap arguments here.
					ok, err := doublestar.Match(pattern.Value().(string), path.Value().(string))
					if err != nil {
						return types.Bool(false)
					}
					return types.Bool(ok)
				}),
			),
		),
	)
}
