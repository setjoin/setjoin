package scim

// applyUserPatch keeps focused PATCH behavior tests independent from the
// production caller's changed-field bookkeeping.
func applyUserPatch(user *UserResource, ops []PatchOperation) error {
	_, err := applyUserPatchTracked(user, ops)
	return err
}
