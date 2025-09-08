package cardano

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/gosunuts/cardano-go/internal/bech32"
	"github.com/gosunuts/cardano-go/internal/cbor"
	"golang.org/x/crypto/blake2b"
)

type AddressType byte

const (
	Base       AddressType = 0x00
	Ptr        AddressType = 0x04
	Enterprise AddressType = 0x06
	Stake      AddressType = 0x0e

	BasicHrpMainnetAddress        string = "addr"
	BasicHrpTestnetAddress        string = "addr_test"
	BasicHrpMainnetStakingAddress string = "stake"
	BasicHrpTestnetStakingAddress string = "stake_test"
)

// Address represents a Cardano address.
type Address struct {
	Network Network
	Type    AddressType
	Pointer Pointer
	Hrp     string

	Payment StakeCredential
	Stake   StakeCredential
}

// NewAddress creates an Address from a bech32 encoded string.
func NewAddress(bech string) (Address, error) {
	hrp, bytes, err := bech32.DecodeToBase256(bech)
	if err != nil {
		return Address{}, err
	}
	addr, err := NewAddressFromBytes(bytes)
	if err != nil {
		return Address{}, err
	}
	addr.Hrp = hrp
	return addr, nil
}

// NewAddressFromBytes creates an Address from bytes.
func NewAddressFromBytes(bytes []byte) (Address, error) {
	addr := Address{
		Type:    AddressType(bytes[0] >> 4),
		Network: Network(bytes[0] & 0x01),
	}

	switch addr.Type {
	case Base, Base + 1, Base + 2, Base + 3:
		if len(bytes) != 57 {
			return addr, errors.New("base address length should be 29")
		}
		if addr.Type&0x01 == 0 {
			addr.Payment = NewKeyCredentialWithHash(bytes[1:29])
		} else {
			addr.Payment = NewScriptCredentialWithHash(bytes[1:29])
		}
		if addr.Type&0x02 == 0 {
			addr.Stake = NewKeyCredentialWithHash(bytes[29:57])
		} else {
			addr.Stake = NewScriptCredentialWithHash(bytes[29:57])
		}
	case Ptr, Ptr + 1:
		if len(bytes) <= 29 {
			return addr, errors.New("enterprise address length should be greater than 29")
		}

		index := uint(29)
		slot, sn, err := decodeFromNat(bytes[29:])
		if err != nil {
			return addr, err
		}
		index += sn
		txIndex, tn, err := decodeFromNat(bytes[index:])
		if err != nil {
			return addr, err
		}
		index += tn
		certIndex, _, err := decodeFromNat(bytes[index:])
		if err != nil {
			return addr, err
		}

		addr.Pointer = Pointer{Slot: slot, TxIndex: txIndex, CertIndex: certIndex}
		if addr.Type == Ptr {
			addr.Payment = NewKeyCredentialWithHash(bytes[1:29])
		} else {
			addr.Payment = NewScriptCredentialWithHash(bytes[1:29])
		}

	case Enterprise, Enterprise + 1:
		if len(bytes) != 29 {
			return addr, errors.New("enterprise address length should be 29")
		}
		if addr.Type == Enterprise {
			addr.Payment = NewKeyCredentialWithHash(bytes[1:29])
		} else {
			addr.Payment = NewScriptCredentialWithHash(bytes[1:29])
		}
	case Stake, Stake + 1:
		if len(bytes) != 29 {
			return addr, errors.New("stake address length should be 29")
		}
		if addr.Type == Stake {
			addr.Stake = NewKeyCredentialWithHash(bytes[1:29])
		} else {
			addr.Stake = NewScriptCredentialWithHash(bytes[1:29])
		}
	}

	addr.Hrp = addr.getDefaultHrp()
	return addr, nil
}

// NewAddressFromBytesAndHrp creates an Address from bytes and hrp.
func NewAddressFromBytesAndHrp(bytes []byte, hrp string) (Address, error) {
	addr, err := NewAddressFromBytes(bytes)
	if err != nil {
		return Address{}, err
	}
	addr.Hrp = hrp
	return addr, nil
}

// MarshalCBOR implements cbor.Marshaler.
func (addr *Address) MarshalCBOR() ([]byte, error) {
	em, _ := cbor.CanonicalEncOptions().EncMode()
	return em.Marshal(addr.Bytes())
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (addr *Address) UnmarshalCBOR(data []byte) error {
	bytes := []byte{}
	if err := cborDec.Unmarshal(data, &bytes); err != nil {
		return nil
	}
	decoded, err := NewAddressFromBytes(bytes)
	if err != nil {
		return err
	}

	addr.Network = decoded.Network
	addr.Type = decoded.Type
	addr.Payment = decoded.Payment
	addr.Stake = decoded.Stake
	addr.Pointer = decoded.Pointer

	addr.Hrp = addr.getDefaultHrp()
	return nil
}

func (addr *Address) MarshalJSON() ([]byte, error) {
	return []byte(addr.Bech32()), nil
}

func (addr *Address) UnmarshalJSON(b []byte) error {
	var addrStr string
	if err := json.Unmarshal(b, &addrStr); err != nil {
		return err
	}
	tmpAddr, err := NewAddress(addrStr)
	if err != nil {
		return err
	}
	*addr = tmpAddr
	return nil
}

// Bytes returns the CBOR encoding of the Address as bytes.
func (addr *Address) Bytes() []byte {
	var networkByte uint8
	switch addr.Network {
	case Testnet, Preprod:
		networkByte = 0
	case Mainnet:
		networkByte = 1
	}

	addrBytes := []byte{byte(addr.Type<<4) | (networkByte & 0xFF)}
	switch addr.Type {
	case Base, Base + 1, Base + 2, Base + 3:
		addrBytes = append(addrBytes, addr.Payment.Hash()...)
		addrBytes = append(addrBytes, addr.Stake.Hash()...)
	case Enterprise, Enterprise + 1:
		addrBytes = append(addrBytes, addr.Payment.Hash()...)
	case Ptr, Ptr + 1:
		addrBytes = append(addrBytes, addr.Payment.Hash()...)
		addrBytes = append(addrBytes, encodeToNat(addr.Pointer.Slot)...)
		addrBytes = append(addrBytes, encodeToNat(addr.Pointer.TxIndex)...)
		addrBytes = append(addrBytes, encodeToNat(addr.Pointer.CertIndex)...)
	case Stake, Stake + 1:
		addrBytes = append(addrBytes, addr.Stake.Hash()...)
	}

	return addrBytes
}

// Bech32 returns the Address encoded as bech32.
func (addr *Address) Bech32() string {
	hrp := addr.Hrp
	if hrp == "" {
		hrp = addr.getDefaultHrp()
	}
	addrStr, err := bech32.EncodeFromBase256(hrp, addr.Bytes())
	if err != nil {
		panic(err)
	}
	return addrStr
}

// SetHrp is set human-readable part (HRP) for address.
func (addr *Address) SetHrp(hrp string) {
	addr.Hrp = hrp
}

// String returns the Address encoded as bech32.
func (addr Address) String() string {
	return addr.Bech32()
}

func (addr Address) getDefaultHrp() string {
	hrp := BasicHrpMainnetAddress
	switch addr.Type {
	case Stake, Stake + 1:
		hrp = BasicHrpMainnetStakingAddress
		if addr.Network != Mainnet {
			hrp = BasicHrpTestnetStakingAddress
		}
	default:
		if addr.Network != Mainnet {
			hrp = BasicHrpTestnetAddress
		}
	}
	return hrp
}

// NewBaseAddress returns a new Base Address.
func NewBaseAddress(network Network, payment StakeCredential, stake StakeCredential) (Address, error) {
	addrType := Base
	switch {
	case payment.Type == ScriptCredential && stake.Type == KeyCredential:
		addrType = Base + 1
	case payment.Type == KeyCredential && stake.Type == ScriptCredential:
		addrType = Base + 2
	case payment.Type == ScriptCredential && stake.Type == ScriptCredential:
		addrType = Base + 3
	}
	addr := Address{Type: addrType, Network: network, Payment: payment, Stake: stake}
	addr.Hrp = addr.getDefaultHrp()
	return addr, nil
}

// NewEnterpriseAddress returns a new Enterprise Address.
func NewEnterpriseAddress(network Network, payment StakeCredential) (Address, error) {
	addrType := Enterprise
	if payment.Type == ScriptCredential {
		addrType = Enterprise + 1
	}
	addr := Address{Type: addrType, Network: network, Payment: payment}
	addr.Hrp = addr.getDefaultHrp()
	return addr, nil
}

// NewStakeAddress returns a new Stake Address.
func NewStakeAddress(network Network, stake StakeCredential) (Address, error) {
	addrType := Stake
	if stake.Type == ScriptCredential {
		addrType = Stake + 1
	}
	addr := Address{Type: addrType, Network: network, Stake: stake}
	addr.Hrp = addr.getDefaultHrp()
	return addr, nil
}

// Pointer is the location of the Stake Registration Certificate in the blockchain.
type Pointer struct {
	Slot      uint64
	TxIndex   uint64
	CertIndex uint64
}

// NewPointerAddress returns a new Pointer Address.
func NewPointerAddress(network Network, payment StakeCredential, ptr Pointer) (Address, error) {
	addrType := Ptr
	if payment.Type == ScriptCredential {
		addrType = Ptr + 1
	}
	addr := Address{Type: addrType, Network: network, Payment: payment, Pointer: ptr}
	addr.Hrp = addr.getDefaultHrp()
	return addr, nil
}

func decodeFromNat(data []byte) (uint64, uint, error) {
	out := big.NewInt(0)
	n := uint(0)
	for _, b := range data {
		out.Lsh(out, 7)
		out.Or(out, big.NewInt(int64(b&0x7F)))
		if !out.IsUint64() {
			return 0, 0, errors.New("too big to decode (> math.MaxUint64)")
		}
		n += 1
		if b&0x80 == 0 {
			return out.Uint64(), n, nil
		}
	}
	return 0, 0, errors.New("bad nat encoding")
}

func encodeToNat(n uint64) []byte {
	out := []byte{byte(n) & 0x7F}

	n >>= 7
	for n != 0 {
		out = append(out, byte(n)|0x80)
		n >>= 7
	}

	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out
}

func Blake224Hash(b []byte) ([]byte, error) {
	hash, err := blake2b.New(224/8, nil)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(b)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), err
}
