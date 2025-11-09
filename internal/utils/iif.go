package utils

func IIF[T any](condition bool, then T, otherwise T) T {
	if condition {
		return then
	}

	return otherwise
}
