package packet

type UserIDPacket struct {
	userID []byte
}

func NewUserIDPacket(userID []byte) *UserIDPacket {
	return &UserIDPacket{userID: userID}
}

func (p *UserIDPacket) Type() byte         { return 13 }
func (p *UserIDPacket) EncodeBody() []byte { return p.userID }
func (p *UserIDPacket) String() string     { return string(p.userID) }
