package sshd

// SetBinaryPathsForTest replaces sshd binary lookup paths and returns a restore func.
func SetBinaryPathsForTest(paths []string) func() {
	prev := append([]string(nil), sshdBinaryPaths...)
	sshdBinaryPaths = append([]string(nil), paths...)
	return func() {
		sshdBinaryPaths = prev
	}
}
