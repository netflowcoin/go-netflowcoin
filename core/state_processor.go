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

package core

import (
	"fmt"
	"github.com/seaskycheng/sdvn/common"
	"github.com/seaskycheng/sdvn/consensus"
	"github.com/seaskycheng/sdvn/consensus/misc"
	"github.com/seaskycheng/sdvn/core/state"
	"github.com/seaskycheng/sdvn/core/types"
	"github.com/seaskycheng/sdvn/core/vm"
	"github.com/seaskycheng/sdvn/crypto"
	"github.com/seaskycheng/sdvn/log"
	"github.com/seaskycheng/sdvn/params"
	"math/big"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the sdvn rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
		txIndex  = 0
	)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	blockContext := NewEVMBlockContext(header, p.bc, nil)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := tx.AsMessage(types.MakeSigner(p.config, header.Number), header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, err := applyTransaction(msg, p.config, p.bc, nil, gp, statedb, header, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		//allLogs = append(allLogs, receipt.Logs...)
		txIndex++
	}
	grantProfit, payProfit := p.engine.GrantProfit(p.bc, header, statedb)
	if nil != grantProfit {
		nilHash := common.Address{}
		zeroHash := common.BigToAddress(big.NewInt(0))
		for _, item := range grantProfit {
			data := common.FromHex("0xeec31edf") //web3.sha3("GrantProfit(address)") //0xeec31edfe9a5655533e7991d096c3143d669dde6cd213b33851b6cd2fe23c420
			if nilHash == item.MultiSignature || zeroHash == item.MultiSignature {
				data = append(data, item.RevenueAddress.Hash().Bytes()...)
			} else {
				data = append(data, item.MultiSignature.Hash().Bytes()...)
			}
			gasPrice := new(big.Int).SetUint64(176190476190)
			gasLimit := uint64(200000)
			tx := types.NewTransaction(uint64(txIndex), item.RevenueContract, item.Amount, gasLimit, gasPrice, data)
			msg := types.NewMessage(item.MinerAddress, &item.RevenueContract, uint64(txIndex), item.Amount, gasLimit, gasPrice, gasPrice, gasPrice, data, nil,false)
			snap := statedb.Snapshot()
			statedb.Prepare(tx.Hash(), block.Hash(), txIndex)
			gasPool := new(GasPool).AddGas(header.GasLimit)
			receipt, err := GrantProfit(tx, msg, p.config, p.bc, nil, gasPool, statedb, header, usedGas, vmenv.Config)
			if err == nil {
				if nil == payProfit {
					payProfit = []consensus.GrantProfitRecord{}
				}
				payProfit = append(payProfit, item)
				receipts = append(receipts, receipt)
				txIndex++
			} else {
				statedb.RevertToSnapshot(snap)
				log.Warn("StateProcessor GrantProfit", "err", err)
			}
		}
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), receipts, payProfit, vmenv.GasReward)
	for _, receipt := range receipts {
		allLogs = append(allLogs, receipt.Logs...)
	}

	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, gasReward *big.Int) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	recript, err := applyTransaction(msg, config, bc, author, gp, statedb, header, tx, usedGas, vmenv)
	if nil == err && nil != gasReward {
		gasReward = new(big.Int).Add(gasReward, vmenv.GasReward)
	}
	return recript, err
}

func GrantProfit (tx *types.Transaction, msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	// Mutate the block and state according to any hard-fork specs
	blockContext := NewEVMBlockContext(header, bc, author)
	statedb.AddBalance(msg.From(), msg.Value())
	evm := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)
	// Apply the transaction to the current state (included in the env).
	result, err := ApplyInnerMessage(evm, msg, gp)
	if err != nil || result.Err != nil {
		statedb.SubBalance(msg.From(), msg.Value())
		if err != nil {
			return nil, err
		} else {
			return nil, result.Err
		}
	}
	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas
	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}
	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}
