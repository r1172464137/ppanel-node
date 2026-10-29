package panel

// FailureStage is the backend routingstatus wire vocabulary. Local config and
// monitor failures map to existing accepted stages until both ends extend it.
type FailureStage string

const (
	StageFetch     FailureStage = "fetch"
	StageValidate  FailureStage = "validate"
	StageBuild     FailureStage = "build"
	StageCoreStart FailureStage = "core_start"
	StagePrepare   FailureStage = "prepare"
	StageStop      FailureStage = "stop"
	StageBind      FailureStage = "bind"
	StageRestore   FailureStage = "restore"
	StageConfig                 = StageValidate
	StageMonitor                = StagePrepare
)

func (s FailureStage) valid() bool {
	switch s {
	case StageFetch, StageValidate, StageBuild, StageCoreStart, StagePrepare, StageStop, StageBind, StageRestore:
		return true
	}
	return false
}

// StageForOperation maps internal labels to the exact accepted wire set.
func StageForOperation(op string) FailureStage {
	switch op {
	case "config":
		return StageConfig
	case "monitor":
		return StageMonitor
	default:
		stage := FailureStage(op)
		if stage.valid() {
			return stage
		}
		return StageValidate
	}
}
