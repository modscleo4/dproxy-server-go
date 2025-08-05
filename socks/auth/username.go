package auth

type UsernameAuthReplyStatus uint8

const (
	AUTH_SUCCESS UsernameAuthReplyStatus = iota
	AUTH_FAILURE
)

type UsernameAuthRequest struct {
	Ver    uint8
	Uname  string
	Passwd string
}

type UsernameAuthReply struct {
	Ver    uint8
	Status UsernameAuthReplyStatus
}
