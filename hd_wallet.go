package cardano

const (
	// see: CIP-1852. https://github.com/cardano-foundation/CIPs/tree/master/CIP-1852
	Hardened             uint32 = 0x80000000
	PurposeBip44Ed25519  uint32 = 1852 + Hardened
	CoinTypeBip44Ed25519 uint32 = 1815 + Hardened
	AccountBase          uint32 = Hardened
	ExternalChainRole    uint32 = 0x0
	InternalChainRole    uint32 = 0x1
	StakingRole          uint32 = 0x2
	DRepKeyRole          uint32 = 0x3
)
