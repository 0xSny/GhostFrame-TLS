//go:build !linux

package tproxy

func DetectConflicts() ConflictReport  { return ConflictReport{Resolved: true} }
func ResolveConflicts() ConflictReport { return ConflictReport{Resolved: true} }
