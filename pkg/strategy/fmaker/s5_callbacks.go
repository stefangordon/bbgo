// Code generated by "callbackgen -type S5"; DO NOT EDIT.

package fmaker

import ()

func (inc *S5) OnUpdate(cb func(val float64)) {
	inc.UpdateCallbacks = append(inc.UpdateCallbacks, cb)
}

func (inc *S5) EmitUpdate(val float64) {
	for _, cb := range inc.UpdateCallbacks {
		cb(val)
	}
}
