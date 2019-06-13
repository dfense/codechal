package util

// ContainsInt - simple iterator to confirm string is a slice
func ContainsInt(a []int, x int) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
