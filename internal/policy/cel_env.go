package policy

import (
	"strconv"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"google.golang.org/protobuf/types/known/structpb"
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
		cel.Variable("model", cel.StringType),
		cel.Variable("permission_mode", cel.StringType),
		cel.Variable("turn_id", cel.StringType),
		cel.Variable("tool_use_id", cel.StringType),
		cel.Variable("transcript_path", cel.StringType),

		// input_glob(value, pattern) backs the input: sugar field. It globs
		// the string form of a scalar tool_input value; JSON numbers are
		// rendered without a decimal point when integral. null never matches
		// and maps/lists are an error (the rule then escalates per on_error).
		cel.Function("input_glob",
			cel.Overload("input_glob_dyn_string", []*cel.Type{cel.DynType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(value, pattern ref.Val) ref.Val {
					var s string
					switch v := value.Value().(type) {
					case string:
						s = v
					case bool:
						s = strconv.FormatBool(v)
					case float64:
						s = strconv.FormatFloat(v, 'f', -1, 64)
					case int64:
						s = strconv.FormatInt(v, 10)
					case uint64:
						s = strconv.FormatUint(v, 10)
					case structpb.NullValue:
						return types.Bool(false)
					default:
						return types.NewErr("input value of type %T cannot be matched against a glob", value.Value())
					}
					ok, err := doublestar.Match(pattern.Value().(string), s)
					if err != nil {
						return types.Bool(false)
					}
					return types.Bool(ok)
				}),
			),
		),

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
