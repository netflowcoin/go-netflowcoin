// Copyright 2021 The sdvn Authors
// This file is part of the sdvn library.
//
// The sdvn library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The sdvn library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the sdvn library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/seaskycheng/sdvn/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main sdvn network.
var MainnetBootnodes = []string{
	// sdvn Foundation Go Bootnodes
	"enode://2ffed1bb6b475259c1448dc93b639569886999e51ade144451877a706d2a9b71eff8eb067d289fde48ba4807370034d851553746fac8816af27f5a922703e2e4@127.0.0.1:30311",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Testnet test network.
var TestnetBootnodes = []string{
	"enode://2ffed1bb6b475259c1448dc93b639569886999e51ade144451877a706d2a9b71eff8eb067d289fde48ba4807370034d851553746fac8816af27f5a922703e2e4@127.0.0.1:30311",
}

var V5Bootnodes = []string{
}

const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	var net string
	switch genesis {
	case MainnetGenesisHash:
		net = "mainnet"
	case TestnetGenesisHash:
		net = "testnet"
	default:
		return ""
	}
	return dnsPrefix + protocol + "." + net + ".ethdisco.net"
}
