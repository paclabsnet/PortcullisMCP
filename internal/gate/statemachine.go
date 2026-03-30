// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gate

import "sync"

// GateState represents the authentication state of the Gate.
type GateState int

const (
	StateUnauthenticated GateState = iota
	StateAuthenticating
	StateAuthenticated
	StateSystemError
)

// GateSubstate provides detail when State is StateSystemError.
type GateSubstate int

const (
	SubstateNone GateSubstate = iota
	SubstateInvalid
	SubstateRefreshFailed
)

// StateMachine holds the Gate's authentication state, protected by a mutex.
type StateMachine struct {
	mu               sync.RWMutex
	state            GateState
	substate         GateSubstate
	systemErrSummary string
	systemErrDetail  string
}

func NewStateMachine() *StateMachine {
	return &StateMachine{state: StateUnauthenticated}
}

func (sm *StateMachine) State() GateState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

func (sm *StateMachine) Substate() GateSubstate {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.substate
}

func (sm *StateMachine) SetAuthenticated() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = StateAuthenticated
	sm.substate = SubstateNone
	sm.systemErrSummary = ""
	sm.systemErrDetail = ""
}

func (sm *StateMachine) SetAuthenticating() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = StateAuthenticating
	sm.substate = SubstateNone
}

func (sm *StateMachine) SetUnauthenticated() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = StateUnauthenticated
	sm.substate = SubstateNone
	sm.systemErrSummary = ""
	sm.systemErrDetail = ""
}

func (sm *StateMachine) SetSystemError(sub GateSubstate, summary, detail string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state = StateSystemError
	sm.substate = sub
	sm.systemErrSummary = summary
	sm.systemErrDetail = detail
}

func (sm *StateMachine) SystemError() (summary, detail string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.systemErrSummary, sm.systemErrDetail
}

func (sm *StateMachine) StateLabel() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	switch sm.state {
	case StateUnauthenticated:
		return "unauthenticated"
	case StateAuthenticating:
		return "authenticating"
	case StateAuthenticated:
		return "authenticated"
	case StateSystemError:
		switch sm.substate {
		case SubstateInvalid:
			return "system-error:invalid"
		case SubstateRefreshFailed:
			return "system-error:refresh-failed"
		default:
			return "system-error"
		}
	}
	return "unknown"
}
