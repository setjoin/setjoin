package updater

import "testing"

func TestStateTransitionMatrix(t *testing.T) {
	t.Parallel()
	valid := [][2]State{
		{StateAwaitingApproval, StateApproved}, {StateApproved, StateScheduled},
		{StateApproved, StateClaimed}, {StateScheduled, StateClaimed},
		{StateClaimed, StatePreflight}, {StatePreflight, StateRecoveryPoint},
		{StateRecoveryPoint, StateStaged}, {StateStaged, StateMaintenance},
		{StateMaintenance, StateMigrations}, {StateMigrations, StateSwitched},
		{StateSwitched, StateReadiness}, {StateReadiness, StateCommitted},
		{StateCommitted, StateVerified}, {StateRollingBack, StateRolledBack},
		{StateMaintenance, StateRecoveryRequired}, {StateClaimed, StateFailed},
	}
	for _, edge := range valid {
		if err := ValidateTransition(edge[0], edge[1]); err != nil {
			t.Errorf("expected %s -> %s: %v", edge[0], edge[1], err)
		}
	}
	invalid := [][2]State{
		{StateVerified, StateClaimed}, {StateClaimed, StateMigrations},
		{StatePreflight, StateVerified}, {StateRollingBack, StateVerified},
		{State("future"), StateClaimed},
	}
	for _, edge := range invalid {
		if err := ValidateTransition(edge[0], edge[1]); err == nil {
			t.Errorf("expected %s -> %s to fail", edge[0], edge[1])
		}
	}
}

func TestTerminalStates(t *testing.T) {
	t.Parallel()
	for _, state := range []State{StateVerified, StateRolledBack, StateFailed,
		StateRecoveryRequired, StateCancelled, StateExpired} {
		if !state.Terminal() {
			t.Errorf("%s should be terminal", state)
		}
	}
	if StateCommitted.Terminal() {
		t.Fatal("committed is not terminal until verification")
	}
}
