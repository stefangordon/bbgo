// Code generated by "callbackgen -type A18"; DO NOT EDIT.

package fmaker

import ()

func (inc *A18) OnUpdate(cb func(val float64)) {
	inc.UpdateCallbacks = append(inc.UpdateCallbacks, cb)
}

func (inc *A18) EmitUpdate(val float64) {
	for _, cb := range inc.UpdateCallbacks {
		cb(val)
	}
}
