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

// Package alien implements the delegated-proof-of-stake consensus engine.

package alien

import (
	"fmt"
	"github.com/seaskycheng/sdvn/common/hexutil"
	"github.com/seaskycheng/sdvn/crypto"
	"math/big"
	"strconv"
	"strings"

	"github.com/seaskycheng/sdvn/common"
	"github.com/seaskycheng/sdvn/consensus"
	"github.com/seaskycheng/sdvn/core/state"
	"github.com/seaskycheng/sdvn/core/types"
	"github.com/seaskycheng/sdvn/log"
	"github.com/seaskycheng/sdvn/params"
	"github.com/seaskycheng/sdvn/rlp"
)

const (
	ufoVersion            = "1"

	ufoPrefix             = "ufo"
	nfcPrefix             = "NFC"
	sscPrefix             = "SSC"

	ufoCategoryEvent      = "event"
	ufoCategoryLog        = "oplog"
	ufoCategorySC         = "sc"
	ufoEventVote          = "vote"
	ufoEventConfirm       = "confirm"
	ufoEventPorposal      = "proposal"
	ufoEventDeclare       = "declare"
	ufoEventSetCoinbase   = "setcb"
	ufoEventDelCoinbase   = "delcb"
	ufoEventFlowReport1   = "flwrpt"
	ufoEventFlowReport2   = "flwrptm"

	nfcCategoryExch       = "Exch"
	nfcCategoryMultiSign  = "Multi"
	nfcCategoryBind       = "Bind"
	nfcCategoryUnbind     = "Unbind"
	nfcCategoryRebind     = "Rebind"
	nfcCategoryCandReq    = "CandReq"
	nfcCategoryCandExit   = "CandExit"
	nfcCategoryCandPnsh   = "CandPnsh"
	nfcCategoryFlwReq     = "FlwReq"
	nfcCategoryFlwExit    = "FlwExit"

	sscCategoryExchRate   = "ExchRate"
	sscCategoryDeposit    = "Deposit"
	sscCategoryCndLock    = "CndLock"
	sscCategoryFlwLock    = "FlwLock"
	sscCategoryRwdLock    = "RwdLock"
	sscCategoryOffLine    = "OffLine"
	sscCategoryQOS        = "QOS"
	sscCategoryWdthPnsh   = "WdthPnsh"
	sscCategoryManager    = "Manager"

	ufoMinSplitLen        = 3

	posPrefix             = 0
	posVersion            = 1
	posCategory           = 2

	posEventVote          = 3
	posEventConfirm       = 3
	posEventProposal      = 3
	posEventDeclare       = 3
	posEventSetCoinbase   = 3
	posEventConfirmNumber = 4
	posEventFlowReport    = 3
	posEventFlowValue     = 4

	nfcPosExchAddress     = 3
	nfcPosExchValue       =	4
	nfcPosThreshold       = 3
	nfcPosMinerAddress    = 3
	nfcPosRevenueType     = 4
	nfcPosRevenueContract = 5
	nfcPosMiltiSign       = 6
	nfcPosRevenueAddress  = 7
	nfcPosISPQosID        = 4
	nfcPosBandwidth       = 5

	sscPosExchRate        = 3
	sscPosDeposit         = 3
	sscPosDepositWho      = 4
	sscPosLockPeriod      = 3
	sscPosRlsPeriod       = 4
	sscPosInterval        = 5
	sscPosOffLine         = 3
	sscPosQosID           = 3
	sscPosQosValue        = 4
	sscPosWdthPnsh        = 4
	sscPosManagerID       = 3
	sscPosManagerAddress  = 4

	sscEnumCndLock        = 0
	sscEnumFlwLock        = 1
	sscEnumRwdLock        = 2
	sscEnumMiner          = 10000
	sscEnumBndwdthClaimed = 0
	sscEnumBndwdthPunish  = 1
	sscEnumExchRate       = 0
	sscEnumSystem         = 1
	sscEnumWdthPnsh       = 2
	sscEnumFlowReport     = 3

	/*
	 *  proposal type
	 */
	proposalTypeCandidateAdd                  = 1
	proposalTypeCandidateRemove               = 2
	proposalTypeMinerRewardDistributionModify = 3 // count in one thousand
	proposalTypeSideChainAdd                  = 4
	proposalTypeSideChainRemove               = 5
	proposalTypeMinVoterBalanceModify         = 6
	proposalTypeProposalDepositModify         = 7
	proposalTypeRentSideChain                 = 8 // use TTC to buy coin on side chain

	/*
	 * proposal related
	 */
	maxValidationLoopCnt     = 12342                   // About one month if period = 10 & 21 super nodes
	minValidationLoopCnt     = 4                       // just for test, Note: 12350  About three days if seal each block per second & 21 super nodes
	defaultValidationLoopCnt = 2880                    // About one week if period = 10 & 21 super nodes
	maxProposalDeposit       = 100000                  // If no limit on max proposal deposit and 1 billion TTC deposit success passed, then no new proposal.
	minSCRentFee             = 100                     // 100 TTC
	minSCRentLength          = 259200                  // number of block about 1 month if period is 10
	defaultSCRentLength      = minSCRentLength * 3     // number of block about 3 month if period is 10
	maxSCRentLength          = defaultSCRentLength * 4 // number of block about 1 year if period is 10

	/*
	 * notice related
	 */
	noticeTypeGasCharging = 1
)

// RefundGas :
// refund gas to tx sender
type RefundGas map[common.Address]*big.Int

// RefundPair :
type RefundPair struct {
	Sender   common.Address
	GasPrice *big.Int
}

// RefundHash :
type RefundHash map[common.Hash]RefundPair

// Vote :
// vote come from custom tx which data like "ufo:1:event:vote"
// Sender of tx is Voter, the tx.to is Candidate
// Stake is the balance of Voter when create this vote
type Vote struct {
	Voter     common.Address `json:"voter"`
	Candidate common.Address `json:"candidate"`
	Stake     *big.Int       `json:"stake"`
}

// Confirmation :
// confirmation come  from custom tx which data like "ufo:1:event:confirm:123"
// 123 is the block number be confirmed
// Sender of tx is Signer only if the signer in the SignerQueue for block number 123
type Confirmation struct {
	Signer      common.Address
	BlockNumber *big.Int
}

// Proposal :
// proposal come from  custom tx which data like "ufo:1:event:proposal:candidate:add:address" or "ufo:1:event:proposal:percentage:60"
// proposal only come from the current candidates
// not only candidate add/remove , current signer can proposal for params modify like percentage of reward distribution ...
type Proposal struct {
	Hash                   common.Hash    `json:"hash"`                   // tx hash
	ReceivedNumber         *big.Int       `json:"receivenumber"`          // block number of proposal received
	CurrentDeposit         *big.Int       `json:"currentdeposit"`         // received deposit for this proposal
	ValidationLoopCnt      uint64         `json:"validationloopcount"`    // validation block number length of this proposal from the received block number
	ProposalType           uint64         `json:"proposaltype"`           // type of proposal 1 - add candidate 2 - remove candidate ...
	Proposer               common.Address `json:"proposer"`               // proposer
	TargetAddress          common.Address `json:"candidateaddress"`       // candidate need to add/remove if candidateNeedPD == true
	MinerRewardPerThousand uint64         `json:"minerrewardperthousand"` // reward of miner + side chain miner
	SCHash                 common.Hash    `json:"schash"`                 // side chain genesis parent hash need to add/remove
	SCBlockCountPerPeriod  uint64         `json:"scblockcountperpersiod"` // the number block sealed by this side chain per period, default 1
	SCBlockRewardPerPeriod uint64         `json:"scblockrewardperperiod"` // the reward of this side chain per period if SCBlockCountPerPeriod reach, default 0. SCBlockRewardPerPeriod/1000 * MinerRewardPerThousand/1000 * BlockReward is the reward for this side chain
	Declares               []*Declare     `json:"declares"`               // Declare this proposal received (always empty in block header)
	MinVoterBalance        uint64         `json:"minvoterbalance"`        // value of minVoterBalance , need to mul big.Int(1e+18)
	ProposalDeposit        uint64         `json:"proposaldeposit"`        // The deposit need to be frozen during before the proposal get final conclusion. (TTC)
	SCRentFee              uint64         `json:"screntfee"`              // number of TTC coin, not wei
	SCRentRate             uint64         `json:"screntrate"`             // how many coin you want for 1 TTC on main chain
	SCRentLength           uint64         `json:"screntlength"`           // minimize block number of main chain , the rent fee will be used as reward of side chain miner.
}

// Declare :
// declare come from custom tx which data like "ufo:1:event:declare:hash:yes"
// proposal only come from the current candidates
// hash is the hash of proposal tx
type Declare struct {
	ProposalHash common.Hash
	Declarer     common.Address
	Decision     bool
}

// SCConfirmation is the confirmed tx send by side chain super node
type SCConfirmation struct {
	Hash     common.Hash
	Coinbase common.Address // the side chain signer , may be diff from signer in main chain
	Number   uint64
	LoopInfo []string
}

// SCSetCoinbase is the tx send by main chain super node which can set coinbase for side chain
type SCSetCoinbase struct {
	Hash     common.Hash
	Signer   common.Address
	Coinbase common.Address
	Type     bool
}

type GasCharging struct {
	Target common.Address `json:"address"` // target address on side chain
	Volume uint64         `json:"volume"`  // volume of gas need charge (unit is ttc)
	Hash   common.Hash    `json:"hash"`    // the hash of proposal, use as id of this proposal
}

type ExchangeNFCRecord struct {
    Target common.Address
	Amount *big.Int
}

type DeviceBindRecord struct {
	Device    common.Address
	Revenue   common.Address
	Contract  common.Address
	MultiSign common.Address
	Type      uint32
	Bind      bool
}

type CandidatePledgeRecord struct {
	Target common.Address
	Amount *big.Int
}

type CandidatePunishRecord struct {
	Target common.Address
	Amount *big.Int
	Credit uint32
}

type ClaimedBandwidthRecord struct {
	Target    common.Address
	Amount    *big.Int
	ISPQosID  uint32
	Bandwidth uint32
}

type BandwidthPunishRecord struct {
	Target   common.Address
	WdthPnsh uint32
}

type ISPQOSRecord struct {
	ISPID uint32
	QOS   uint32
}

type ManagerAddressRecord struct {
	Target common.Address
	Who    uint32
}

type LockParameterRecord struct {
	LockPeriod uint32
	RlsPeriod  uint32
	Interval   uint32
	Who        uint32
}

type MinerStakeRecord struct {
	Target common.Address
	Stake  *big.Int
}

type LockRewardRecord struct {
	Target   common.Address
	Amount   *big.Int
	IsReward uint32
}

type MinerFlowReportItem struct {
	Target       common.Address
	ReportNumber uint32
	FlowValue1   uint64
	FlowValue2   uint64
}

type MinerFlowReportRecord struct {
	ChainHash     common.Hash
	ReportTime    uint64
	ReportContent []MinerFlowReportItem
}

type ConfigDepositRecord struct {
	Who    uint32
	Amount *big.Int
}

// HeaderExtra is the struct of info in header.Extra[extraVanity:len(header.extra)-extraSeal]
// HeaderExtra is the current struct
type HeaderExtra struct {
	CurrentBlockConfirmations []Confirmation
	CurrentBlockVotes         []Vote
	CurrentBlockProposals     []Proposal
	CurrentBlockDeclares      []Declare
	ModifyPredecessorVotes    []Vote
	LoopStartTime             uint64
	SignerQueue               []common.Address
	SignerMissing             []common.Address
	ConfirmedBlockNumber      uint64
	SideChainConfirmations    []SCConfirmation
	SideChainSetCoinbases     []SCSetCoinbase
	SideChainNoticeConfirmed  []SCConfirmation
	SideChainCharging         []GasCharging //This only exist in side chain's header.Extra

	ExchangeNFC               []ExchangeNFCRecord
	DeviceBind                []DeviceBindRecord
	CandidatePledge           []CandidatePledgeRecord
	CandidatePunish           []CandidatePunishRecord
	MinerStake                []MinerStakeRecord
	CandidateExit             []common.Address
	ClaimedBandwidth          []ClaimedBandwidthRecord
	FlowMinerExit             []common.Address
	BandwidthPunish           []BandwidthPunishRecord
	ConfigExchRate            uint32
	ConfigOffLine             uint32
	ConfigDeposit             []ConfigDepositRecord
	ConfigISPQOS              []ISPQOSRecord
	LockParameters            []LockParameterRecord
	ManagerAddress            []ManagerAddressRecord
	FlowHarvest               *big.Int
	LockReward                []LockRewardRecord
	GrantProfit               []consensus.GrantProfitRecord
	FlowReport                []MinerFlowReportRecord
}

//side chain related
var minSCSetCoinbaseValue = big.NewInt(5e+18)

func (p *Proposal) copy() *Proposal {
	cpy := &Proposal{
		Hash:                   p.Hash,
		ReceivedNumber:         new(big.Int).Set(p.ReceivedNumber),
		CurrentDeposit:         new(big.Int).Set(p.CurrentDeposit),
		ValidationLoopCnt:      p.ValidationLoopCnt,
		ProposalType:           p.ProposalType,
		Proposer:               p.Proposer,
		TargetAddress:          p.TargetAddress,
		MinerRewardPerThousand: p.MinerRewardPerThousand,
		SCHash:                 p.SCHash,
		SCBlockCountPerPeriod:  p.SCBlockCountPerPeriod,
		SCBlockRewardPerPeriod: p.SCBlockRewardPerPeriod,
		Declares:               make([]*Declare, len(p.Declares)),
		MinVoterBalance:        p.MinVoterBalance,
		ProposalDeposit:        p.ProposalDeposit,
		SCRentFee:              p.SCRentFee,
		SCRentRate:             p.SCRentRate,
		SCRentLength:           p.SCRentLength,
	}

	copy(cpy.Declares, p.Declares)
	return cpy
}

func (s *SCConfirmation) copy() *SCConfirmation {
	cpy := &SCConfirmation{
		Hash:     s.Hash,
		Coinbase: s.Coinbase,
		Number:   s.Number,
		LoopInfo: make([]string, len(s.LoopInfo)),
	}
	copy(cpy.LoopInfo, s.LoopInfo)
	return cpy
}

// Encode HeaderExtra
func encodeHeaderExtra(config *params.AlienConfig, number *big.Int, val HeaderExtra) ([]byte, error) {

	var headerExtra interface{}
	switch {
	//case config.IsTrantor(number):

	default:
		headerExtra = val
	}
	return rlp.EncodeToBytes(headerExtra)

}

// Decode HeaderExtra
func decodeHeaderExtra(config *params.AlienConfig, number *big.Int, b []byte, val *HeaderExtra) error {
	var err error
	switch {
	//case config.IsTrantor(number):
	default:
		err = rlp.DecodeBytes(b, val)
	}
	return err
}

// Build side chain confirm data
func (a *Alien) buildSCEventConfirmData(scHash common.Hash, headerNumber *big.Int, headerTime *big.Int, lastLoopInfo string, chargingInfo string) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s:%s:%s:%d:%d:%s:%s",
		ufoPrefix, ufoVersion, ufoCategorySC, ufoEventConfirm,
		scHash.Hex(), headerNumber.Uint64(), headerTime.Uint64(), lastLoopInfo, chargingInfo))

}

// Calculate Votes from transaction in this block, write into header.Extra
func (a *Alien) processCustomTx(headerExtra HeaderExtra, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) (HeaderExtra, RefundGas, error) {
	// if predecessor voter make transaction and vote in this block,
	// just process as vote, do it in snapshot.apply
	var (
		snap       *Snapshot
		snapCache  *Snapshot
		err        error
		number     uint64
		refundGas  RefundGas
		refundHash RefundHash
	)
	refundGas = make(map[common.Address]*big.Int)
	refundHash = make(map[common.Hash]RefundPair)
	number = header.Number.Uint64()
	if number >= 1 {
		snap, err = a.snapshot(chain, number-1, header.ParentHash, nil, nil, defaultLoopCntRecalculateSigners)
		if err != nil {
			return headerExtra, nil, err
		}
		snapCache = snap.copy()
	}

	for _, tx := range txs {
		txSender, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
		if err != nil {
			continue
		}

		if len(string(tx.Data())) >= len(ufoPrefix) {
			txData := string(tx.Data())
			txDataInfo := strings.Split(txData, ":")
			if len(txDataInfo) >= ufoMinSplitLen {
				if txDataInfo[posPrefix] == ufoPrefix {
					if txDataInfo[posVersion] == ufoVersion {
						// process vote event
						if txDataInfo[posCategory] == ufoCategoryEvent {
							if len(txDataInfo) > ufoMinSplitLen {
								// check is vote or not
								if txDataInfo[posEventVote] == ufoEventVote && (!candidateNeedPD || snap.isCandidate(*tx.To())) && state.GetBalance(txSender).Cmp(snap.MinVB) > 0 {
									headerExtra.CurrentBlockVotes = a.processEventVote(headerExtra.CurrentBlockVotes, state, tx, txSender)
								} else if txDataInfo[posEventConfirm] == ufoEventConfirm && snap.isCandidate(txSender) {
									headerExtra.CurrentBlockConfirmations, refundHash = a.processEventConfirm(headerExtra.CurrentBlockConfirmations, chain, txDataInfo, number, tx, txSender, refundHash)
								} else if txDataInfo[posEventProposal] == ufoEventPorposal {
									headerExtra.CurrentBlockProposals = a.processEventProposal(headerExtra.CurrentBlockProposals, txDataInfo, state, tx, txSender, snap)
								} else if txDataInfo[posEventDeclare] == ufoEventDeclare && snap.isCandidate(txSender) {
									headerExtra.CurrentBlockDeclares = a.processEventDeclare(headerExtra.CurrentBlockDeclares, txDataInfo, tx, txSender)
								}
							} else {
								// todo : something wrong, leave this transaction to process as normal transaction
							}
						} else if txDataInfo[posCategory] == ufoCategoryLog {
							// todo :
						} else if txDataInfo[posCategory] == ufoCategorySC {
							if len(txDataInfo) > ufoMinSplitLen {
								if txDataInfo[posEventConfirm] == ufoEventConfirm {
									if len(txDataInfo) > ufoMinSplitLen+5 {
										number := new(big.Int)
										if err := number.UnmarshalText([]byte(txDataInfo[ufoMinSplitLen+2])); err != nil {
											log.Trace("Side chain confirm info fail", "number", txDataInfo[ufoMinSplitLen+2])
											continue
										}
										if err := new(big.Int).UnmarshalText([]byte(txDataInfo[ufoMinSplitLen+3])); err != nil {
											log.Trace("Side chain confirm info fail", "time", txDataInfo[ufoMinSplitLen+3])
											continue
										}
										loopInfo := txDataInfo[ufoMinSplitLen+4]
										scHash := common.HexToHash(txDataInfo[ufoMinSplitLen+1])
										headerExtra.SideChainConfirmations, refundHash = a.processSCEventConfirm(headerExtra.SideChainConfirmations,
											scHash, number.Uint64(), loopInfo, tx, txSender, refundHash)

										chargingInfo := txDataInfo[ufoMinSplitLen+5]
										headerExtra.SideChainNoticeConfirmed = a.processSCEventNoticeConfirm(headerExtra.SideChainNoticeConfirmed,
											scHash, number.Uint64(), chargingInfo, txSender)

									}
								} else if txDataInfo[posEventSetCoinbase] == ufoEventSetCoinbase && snap.isCandidate(txSender) {
									if len(txDataInfo) > ufoMinSplitLen+1 {
										// the signer of main chain must send some value to coinbase of side chain for confirm tx of side chain
										if tx.Value().Cmp(minSCSetCoinbaseValue) >= 0 {
											headerExtra.SideChainSetCoinbases = a.processSCEventSetCoinbase(headerExtra.SideChainSetCoinbases,
												common.HexToHash(txDataInfo[ufoMinSplitLen+1]), txSender, *tx.To(), true)
										}
									}
								} else if txDataInfo[posEventSetCoinbase] == ufoEventDelCoinbase && snap.isCandidate(txSender) {
									if len(txDataInfo) > ufoMinSplitLen+1 {
										headerExtra.SideChainSetCoinbases = a.processSCEventSetCoinbase(headerExtra.SideChainSetCoinbases,
											common.HexToHash(txDataInfo[ufoMinSplitLen+1]), txSender, *tx.To(), false)
									}
								} else if ufoEventFlowReport1 == txDataInfo[posEventFlowReport] {
									ok := false
									headerExtra.FlowReport, ok = a.processFlowReport1 (headerExtra.FlowReport, txDataInfo, txSender, snap)
									if ok {
										refundHash[tx.Hash()] = RefundPair{txSender, tx.GasPrice()}
									}
								} else if ufoEventFlowReport2 == txDataInfo[posEventFlowReport] {
									if txSender.String() == snap.SystemConfig.ManagerAddress[sscEnumFlowReport].String() {
										headerExtra.FlowReport = a.processFlowReport2 (headerExtra.FlowReport, txDataInfo)
										refundHash[tx.Hash()] = RefundPair{txSender, tx.GasPrice()}
									}
								}
							}
						}
					}
				} else if txDataInfo[posPrefix] == nfcPrefix {
					if txDataInfo[posVersion] == ufoVersion {
						if txDataInfo[posCategory] == nfcCategoryExch {
							headerExtra.ExchangeNFC = a.processExchangeNFC (headerExtra.ExchangeNFC, txDataInfo, txSender, tx, receipts, state, snap)
						} else if txDataInfo[posCategory] == nfcCategoryMultiSign {
							a.processCreateMultiSignature (txDataInfo, txSender, tx, receipts, state)
						} else if txDataInfo[posCategory] == nfcCategoryBind {
							headerExtra.DeviceBind = a.processDeviceBind (headerExtra.DeviceBind, txDataInfo, txSender, tx, receipts, snapCache)
						} else if txDataInfo[posCategory] == nfcCategoryUnbind {
							headerExtra.DeviceBind = a.processDeviceUnbind (headerExtra.DeviceBind, txDataInfo, txSender, tx, receipts, state, snapCache)
						} else if txDataInfo[posCategory] == nfcCategoryRebind {
							headerExtra.DeviceBind = a.processDeviceRebind (headerExtra.DeviceBind, txDataInfo, txSender, tx, receipts, state, snapCache)
						} else if txDataInfo[posCategory] == nfcCategoryCandReq {
							headerExtra.CandidatePledge = a.processCandidatePledge (headerExtra.CandidatePledge, txDataInfo, txSender, tx, receipts, state, snapCache)
						} else if txDataInfo[posCategory] == nfcCategoryCandExit {
							headerExtra.CandidateExit = a.processCandidateExit (headerExtra.CandidateExit, txDataInfo, txSender, tx, receipts, state, snapCache)
						} else if txDataInfo[posCategory] == nfcCategoryCandPnsh {
							headerExtra.CandidatePunish = a.processCandidatePunish (headerExtra.CandidatePunish, txDataInfo, txSender, tx, receipts, state, snapCache)
						} else if txDataInfo[posCategory] == nfcCategoryFlwReq {
							headerExtra.ClaimedBandwidth = a.processMinerPledge (headerExtra.ClaimedBandwidth, txDataInfo, txSender, tx, receipts, state, snapCache)
						} else if txDataInfo[posCategory] == nfcCategoryFlwExit {
							headerExtra.FlowMinerExit = a.processMinerExit (headerExtra.FlowMinerExit, txDataInfo, txSender, tx, receipts, state, snapCache)
						}
					}
				}  else if txDataInfo[posPrefix] == sscPrefix {
					if txDataInfo[posVersion] == ufoVersion {
						if txDataInfo[posCategory] == sscCategoryExchRate {
							headerExtra.ConfigExchRate = a.processExchRate (txDataInfo, txSender, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryDeposit {
							headerExtra.ConfigDeposit = a.processCandidateDeposit (headerExtra.ConfigDeposit, txDataInfo, txSender, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryCndLock {
							headerExtra.LockParameters = a.processCndLockConfig (headerExtra.LockParameters, txDataInfo, txSender, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryFlwLock {
							headerExtra.LockParameters = a.processFlwLockConfig (headerExtra.LockParameters, txDataInfo, txSender, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryRwdLock {
							headerExtra.LockParameters = a.processRwdLockConfig (headerExtra.LockParameters, txDataInfo, txSender, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryOffLine {
							headerExtra.ConfigOffLine = a.processOffLine (txDataInfo, txSender, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryQOS {
							headerExtra.ConfigISPQOS = a.processISPQos (headerExtra.ConfigISPQOS, txDataInfo, txSender, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryWdthPnsh {
							headerExtra.BandwidthPunish = a.processBandwidthPunish (headerExtra.BandwidthPunish, txDataInfo, txSender, tx, receipts, snapCache)
						} else if txDataInfo[posCategory] == sscCategoryManager {
							headerExtra.ManagerAddress = a.processManagerAddress (headerExtra.ManagerAddress, txDataInfo, txSender, snapCache)
						}
					}
				}
			}
		}
		// check each address
		if number > 1 {
			headerExtra.ModifyPredecessorVotes = a.processPredecessorVoter(headerExtra.ModifyPredecessorVotes, state, tx, txSender, snap)
		}
	}

	for _, receipt := range receipts {
		if pair, ok := refundHash[receipt.TxHash]; ok && receipt.Status == 1 {
			pair.GasPrice.Mul(pair.GasPrice, big.NewInt(int64(receipt.GasUsed)))
			refundGas = a.refundAddGas(refundGas, pair.Sender, pair.GasPrice)
		}
	}
	return headerExtra, refundGas, nil
}

func (a *Alien) refundAddGas(refundGas RefundGas, address common.Address, value *big.Int) RefundGas {
	if _, ok := refundGas[address]; ok {
		refundGas[address].Add(refundGas[address], value)
	} else {
		refundGas[address] = value
	}

	return refundGas
}

func (a *Alien) processSCEventNoticeConfirm(scEventNoticeConfirm []SCConfirmation, hash common.Hash, number uint64, chargingInfo string, txSender common.Address) []SCConfirmation {
	if chargingInfo != "" {
		scEventNoticeConfirm = append(scEventNoticeConfirm, SCConfirmation{
			Hash:     hash,
			Coinbase: txSender,
			Number:   number,
			LoopInfo: strings.Split(chargingInfo, "#"),
		})
	}
	return scEventNoticeConfirm
}

func (a *Alien) processSCEventConfirm(scEventConfirmaions []SCConfirmation, hash common.Hash, number uint64, loopInfo string, tx *types.Transaction, txSender common.Address, refundHash RefundHash) ([]SCConfirmation, RefundHash) {
	scEventConfirmaions = append(scEventConfirmaions, SCConfirmation{
		Hash:     hash,
		Coinbase: txSender,
		Number:   number,
		LoopInfo: strings.Split(loopInfo, "#"),
	})
	refundHash[tx.Hash()] = RefundPair{txSender, tx.GasPrice()}
	return scEventConfirmaions, refundHash
}

func (a *Alien) processSCEventSetCoinbase(scEventSetCoinbases []SCSetCoinbase, hash common.Hash, signer common.Address, coinbase common.Address, optype bool) []SCSetCoinbase {
	scEventSetCoinbases = append(scEventSetCoinbases, SCSetCoinbase{
		Hash:     hash,
		Signer:   signer,
		Coinbase: coinbase,
		Type:     optype,
	})
	return scEventSetCoinbases
}

func (a *Alien) processEventProposal(currentBlockProposals []Proposal, txDataInfo []string, state *state.StateDB, tx *types.Transaction, proposer common.Address, snap *Snapshot) []Proposal {
	// sample for add side chain proposal
	// eth.sendTransaction({from:eth.accounts[0],to:eth.accounts[0],value:0,data:web3.toHex("ufo:1:event:proposal:proposal_type:4:sccount:2:screward:50:schash:0x3210000000000000000000000000000000000000000000000000000000000000:vlcnt:4")})
	// sample for declare
	// eth.sendTransaction({from:eth.accounts[0],to:eth.accounts[0],value:0,data:web3.toHex("ufo:1:event:declare:hash:0x853e10706e6b9d39c5f4719018aa2417e8b852dec8ad18f9c592d526db64c725:decision:yes")})
	if len(txDataInfo) <= posEventProposal+2 {
		return currentBlockProposals
	}

	proposal := Proposal{
		Hash:                   tx.Hash(),
		ReceivedNumber:         big.NewInt(0),
		CurrentDeposit:         proposalDeposit, // for all type of deposit
		ValidationLoopCnt:      defaultValidationLoopCnt,
		ProposalType:           proposalTypeCandidateAdd,
		Proposer:               proposer,
		TargetAddress:          common.Address{},
		SCHash:                 common.Hash{},
		SCBlockCountPerPeriod:  1,
		SCBlockRewardPerPeriod: 0,
		MinerRewardPerThousand: minerRewardPerThousand,
		Declares:               []*Declare{},
		MinVoterBalance:        new(big.Int).Div(minVoterBalance, big.NewInt(1e+18)).Uint64(),
		ProposalDeposit:        new(big.Int).Div(proposalDeposit, big.NewInt(1e+18)).Uint64(), // default value
		SCRentFee:              0,
		SCRentRate:             1,
		SCRentLength:           defaultSCRentLength,
	}

	for i := 0; i < len(txDataInfo[posEventProposal+1:])/2; i++ {
		k, v := txDataInfo[posEventProposal+1+i*2], txDataInfo[posEventProposal+2+i*2]
		switch k {
		case "vlcnt":
			// If vlcnt is missing then user default value, but if the vlcnt is beyond the min/max value then ignore this proposal
			if validationLoopCnt, err := strconv.Atoi(v); err != nil || validationLoopCnt < minValidationLoopCnt || validationLoopCnt > maxValidationLoopCnt {
				return currentBlockProposals
			} else {
				proposal.ValidationLoopCnt = uint64(validationLoopCnt)
			}
		case "schash":
			proposal.SCHash.UnmarshalText([]byte(v))
		case "sccount":
			if scBlockCountPerPeriod, err := strconv.Atoi(v); err != nil {
				return currentBlockProposals
			} else {
				proposal.SCBlockCountPerPeriod = uint64(scBlockCountPerPeriod)
			}
		case "screward":
			if scBlockRewardPerPeriod, err := strconv.Atoi(v); err != nil {
				return currentBlockProposals
			} else {
				proposal.SCBlockRewardPerPeriod = uint64(scBlockRewardPerPeriod)
			}
		case "proposal_type":
			if proposalType, err := strconv.Atoi(v); err != nil {
				return currentBlockProposals
			} else {
				proposal.ProposalType = uint64(proposalType)
			}
		case "candidate":
			// not check here
			proposal.TargetAddress.UnmarshalText([]byte(v))
		case "mrpt":
			// miner reward per thousand
			if mrpt, err := strconv.Atoi(v); err != nil || mrpt <= 0 || mrpt > 1000 {
				return currentBlockProposals
			} else {
				proposal.MinerRewardPerThousand = uint64(mrpt)
			}
		case "mvb":
			// minVoterBalance
			if mvb, err := strconv.Atoi(v); err != nil || mvb <= 0 {
				return currentBlockProposals
			} else {
				proposal.MinVoterBalance = uint64(mvb)
			}
		case "mpd":
			// proposalDeposit
			if mpd, err := strconv.Atoi(v); err != nil || mpd <= 0 || mpd > maxProposalDeposit {
				return currentBlockProposals
			} else {
				proposal.ProposalDeposit = uint64(mpd)
			}
		case "scrt":
			// target address on side chain to charge gas
			proposal.TargetAddress.UnmarshalText([]byte(v))
		case "scrf":
			// side chain rent fee
			if scrf, err := strconv.Atoi(v); err != nil || scrf < minSCRentFee {
				return currentBlockProposals
			} else {
				proposal.SCRentFee = uint64(scrf)
			}
		case "scrr":
			// side chain rent rate
			if scrr, err := strconv.Atoi(v); err != nil || scrr <= 0 {
				return currentBlockProposals
			} else {
				proposal.SCRentRate = uint64(scrr)
			}
		case "scrl":
			// side chain rent length
			if scrl, err := strconv.Atoi(v); err != nil || scrl < minSCRentLength || scrl > maxSCRentLength {
				return currentBlockProposals
			} else {
				proposal.SCRentLength = uint64(scrl)
			}
		}
	}
	// now the proposal is built
	currentProposalPay := new(big.Int).Set(proposalDeposit)
	if proposal.ProposalType == proposalTypeRentSideChain {
		// check if the proposal target side chain exist
		if !snap.isSideChainExist(proposal.SCHash) {
			return currentBlockProposals
		}
		if (proposal.TargetAddress == common.Address{}) {
			return currentBlockProposals
		}
		currentProposalPay.Add(currentProposalPay, new(big.Int).Mul(new(big.Int).SetUint64(proposal.SCRentFee), big.NewInt(1e+18)))
	}
	// check enough balance for deposit
	if state.GetBalance(proposer).Cmp(currentProposalPay) < 0 {
		return currentBlockProposals
	}
	// collection the fee for this proposal (deposit and other fee , sc rent fee ...)
	state.SetBalance(proposer, new(big.Int).Sub(state.GetBalance(proposer), currentProposalPay))

	return append(currentBlockProposals, proposal)
}

func (a *Alien) processEventDeclare(currentBlockDeclares []Declare, txDataInfo []string, tx *types.Transaction, declarer common.Address) []Declare {
	if len(txDataInfo) <= posEventDeclare+2 {
		return currentBlockDeclares
	}
	declare := Declare{
		ProposalHash: common.Hash{},
		Declarer:     declarer,
		Decision:     true,
	}
	for i := 0; i < len(txDataInfo[posEventDeclare+1:])/2; i++ {
		k, v := txDataInfo[posEventDeclare+1+i*2], txDataInfo[posEventDeclare+2+i*2]
		switch k {
		case "hash":
			declare.ProposalHash.UnmarshalText([]byte(v))
		case "decision":
			if v == "yes" {
				declare.Decision = true
			} else if v == "no" {
				declare.Decision = false
			} else {
				return currentBlockDeclares
			}
		}
	}

	return append(currentBlockDeclares, declare)
}

func (a *Alien) processEventVote(currentBlockVotes []Vote, state *state.StateDB, tx *types.Transaction, voter common.Address) []Vote {

	a.lock.RLock()
	stake := state.GetBalance(voter)
	a.lock.RUnlock()

	currentBlockVotes = append(currentBlockVotes, Vote{
		Voter:     voter,
		Candidate: *tx.To(),
		Stake:     stake,
	})

	return currentBlockVotes
}

func (a *Alien) processEventConfirm(currentBlockConfirmations []Confirmation, chain consensus.ChainHeaderReader, txDataInfo []string, number uint64, tx *types.Transaction, confirmer common.Address, refundHash RefundHash) ([]Confirmation, RefundHash) {
	if len(txDataInfo) > posEventConfirmNumber {
		confirmedBlockNumber := new(big.Int)
		err := confirmedBlockNumber.UnmarshalText([]byte(txDataInfo[posEventConfirmNumber]))
		if err != nil || number-confirmedBlockNumber.Uint64() > a.config.MaxSignerCount || number-confirmedBlockNumber.Uint64() < 0 {
			return currentBlockConfirmations, refundHash
		}
		// check if the voter is in block
		confirmedHeader := chain.GetHeaderByNumber(confirmedBlockNumber.Uint64())
		if confirmedHeader == nil {
			//log.Info("Fail to get confirmedHeader")
			return currentBlockConfirmations, refundHash
		}
		confirmedHeaderExtra := HeaderExtra{}
		if extraVanity+extraSeal > len(confirmedHeader.Extra) {
			return currentBlockConfirmations, refundHash
		}
		err = decodeHeaderExtra(a.config, confirmedBlockNumber, confirmedHeader.Extra[extraVanity:len(confirmedHeader.Extra)-extraSeal], &confirmedHeaderExtra)
		if err != nil {
			log.Info("Fail to decode parent header", "err", err)
			return currentBlockConfirmations, refundHash
		}
		for _, s := range confirmedHeaderExtra.SignerQueue {
			if s == confirmer {
				currentBlockConfirmations = append(currentBlockConfirmations, Confirmation{
					Signer:      confirmer,
					BlockNumber: new(big.Int).Set(confirmedBlockNumber),
				})
				refundHash[tx.Hash()] = RefundPair{confirmer, tx.GasPrice()}
				break
			}
		}
	}

	return currentBlockConfirmations, refundHash
}

func (a *Alien) processPredecessorVoter(modifyPredecessorVotes []Vote, state *state.StateDB, tx *types.Transaction, voter common.Address, snap *Snapshot) []Vote {
	// process normal transaction which relate to voter
	if tx.Value().Cmp(big.NewInt(0)) > 0 && tx.To() != nil {
		if snap.isVoter(voter) {
			a.lock.RLock()
			stake := state.GetBalance(voter)
			a.lock.RUnlock()
			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
				Voter:     voter,
				Candidate: common.Address{},
				Stake:     stake,
			})
		}
		if snap.isVoter(*tx.To()) {
			a.lock.RLock()
			stake := state.GetBalance(*tx.To())
			a.lock.RUnlock()
			modifyPredecessorVotes = append(modifyPredecessorVotes, Vote{
				Voter:     *tx.To(),
				Candidate: common.Address{},
				Stake:     stake,
			})
		}

	}
	return modifyPredecessorVotes
}

func (a *Alien) addCustomerTxLog (tx *types.Transaction, receipts []*types.Receipt, topics []common.Hash, data []byte) bool {
	for _, receipt := range receipts {
		if receipt.TxHash != tx.Hash() {
			continue
		}
		if receipt.Status == types.ReceiptStatusFailed {
			return false
		}
		log := &types.Log{
			Address: common.Address{},
			Topics:  topics,
			Data:    data,
			BlockNumber: receipt.BlockNumber.Uint64(),
			TxHash: tx.Hash(),
			TxIndex: receipt.TransactionIndex,
			BlockHash: receipt.BlockHash,
			Index: uint(len(receipt.Logs)),
			Removed: false,
		}
		receipt.Logs = append(receipt.Logs, log)
		receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
		return true
	}
	return false
}

func (a *Alien) verifyMultiSignatureAddress(state *state.StateDB, address common.Address, signers []common.Address) bool {
	if state.Empty(address) {
		return false
	}
	contractHash := state.GetCodeHash(address)
	if state.GetNonce(address) != 1 || contractHash == (common.Hash{}) || contractHash == crypto.Keccak256Hash(nil) {
		return false
	}
	var parameter consensus.MultiSignatureData
	if err := rlp.DecodeBytes(state.GetCode(address), &parameter); nil != err {
		return false
	}
	assistAddress := make(map[common.Address]bool)
	for _, assist := range parameter.MultiSigners {
		assistAddress[assist] = true
	}
	okNumber := 0
	okAddress := make(map[common.Address]bool)
	for _, signer := range signers {
		if _, ok := okAddress[signer]; !ok {
			if _, ok = assistAddress[signer]; ok {
				okNumber++
				okAddress[signer] = true
			}
		}
	}
	return okNumber >= int(parameter.Threshold)
}

func (a *Alien) processCreateMultiSignature (txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB) {
	if len(txDataInfo) <= nfcPosThreshold + 2 {
		log.Warn("Create Multi-Signature fail", "parameter number", len(txDataInfo))
		return
	}
	parameter := consensus.MultiSignatureData{
		Threshold: 0,
		MultiSigners: []common.Address{},
	}
	if threshold, err := strconv.ParseUint(txDataInfo[nfcPosThreshold], 10, 32); err == nil {
		if 2 > threshold || 10 < threshold {
			log.Warn("Create Multi-Signature", "threshold", txDataInfo[nfcPosThreshold])
			return
		} else {
			if len(txDataInfo) < nfcPosThreshold + 2 + int(threshold) || len(txDataInfo) > nfcPosThreshold + 1000 {
				log.Warn("Create Multi-Signature fail", "parameter number", len(txDataInfo))
				return
			}
		}
		parameter.Threshold = uint32(threshold)
	} else {
		log.Warn("Create Multi-Signature", "threshold", txDataInfo[nfcPosThreshold])
		return
	}
	signers := make(map[common.Address]bool)
	i := nfcPosThreshold + 1
	for i < len(txDataInfo) {
		var address common.Address
		if err := address.UnmarshalText1([]byte(txDataInfo[i])); err != nil {
			log.Warn("Create Multi-Signature", "address", txDataInfo[i])
			return
		}
		i++
		if _, ok := signers[address]; !ok {
			signers[address] = true
			parameter.MultiSigners = append(parameter.MultiSigners, address)
		}
	}
	if len(parameter.MultiSigners) <= int(parameter.Threshold) {
		log.Warn("Create Multi-Signature fail", "Owner number", len(parameter.MultiSigners), "threshold", parameter.Threshold)
		return
	}
	data, err := rlp.EncodeToBytes(parameter)
	if nil != err {
		log.Warn("Create Multi-Signature fail", "err", err)
		return
	}
	if len(data) > params.MaxCodeSize {
		log.Warn("Create Multi-Signature fail for max code size exceeded")
		return
	}
	snapshot := state.Snapshot()
	contractAddr := crypto.CreateAddress(txSender, tx.Nonce())
	state.AddAddressToAccessList(contractAddr)
	contractHash := state.GetCodeHash(contractAddr)
	if state.GetNonce(contractAddr) != 0 || (contractHash != (common.Hash{}) && contractHash != crypto.Keccak256Hash(nil)) {
		state.RevertToSnapshot(snapshot)
		log.Warn("Create Multi-Signature fail", "err", err)
		return
	}
	state.CreateAccount(contractAddr)
	state.SetNonce(contractAddr, 1)
	state.SetCode(contractAddr, data)
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0x19e4c26736d9757bc4f6391599c8c577e3ce9de291219ff3f84242af8b6c6d59")) //web3.sha3("CreateMultiSignature(uint256,address[])")
	topics[1].SetBytes(txSender.Bytes())
	topics[2].SetBytes(big.NewInt(int64(tx.Nonce())).Bytes())
	a.addCustomerTxLog (tx, receipts, topics, contractAddr.Hash().Bytes())
}

func (a *Alien) processExchangeNFC (currentExchangeNFC []ExchangeNFCRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []ExchangeNFCRecord {
	if len(txDataInfo) <= nfcPosExchValue {
		log.Warn("Exchange NFC to FUL fail", "parameter number", len(txDataInfo))
		return currentExchangeNFC
	}
	exchangeNFC := ExchangeNFCRecord {
		Target: common.Address{},
		Amount: big.NewInt(0),
	}
	if err := exchangeNFC.Target.UnmarshalText1([]byte(txDataInfo[nfcPosExchAddress])); err != nil {
		log.Warn("Exchange NFC to FUL fail", "address", txDataInfo[nfcPosExchAddress])
		return currentExchangeNFC
	}
	amount := big.NewInt(0)
	var err error
	if amount, err = hexutil.UnmarshalText1([]byte(txDataInfo[nfcPosExchValue])); err != nil {
		log.Warn("Exchange NFC to FUL fail", "number", txDataInfo[nfcPosExchValue])
		return currentExchangeNFC
	}
	if state.GetBalance(txSender).Cmp(amount) < 0 {
		log.Warn("Exchange NFC to FUL fail", "balance", state.GetBalance(txSender))
		return currentExchangeNFC
	}
	exchangeNFC.Amount = new(big.Int).Div(new(big.Int).Mul(amount, big.NewInt(int64(snap.SystemConfig.ExchRate))), new(big.Int).Mul(big.NewInt(10000), big.NewInt(1e+18)))
	state.SetBalance(txSender, new(big.Int).Sub(state.GetBalance(txSender), amount))
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0xdd6398517e51250c7ea4c550bdbec4246ce3cd80eac986e8ebbbb0eda27dcf4c")) //web3.sha3("ExchangeNFC(address,uint256)")
	//topics[0].SetBytes([]byte("0xd30e03ff18434d05879ab70ed87b24c4b0ea30dd23d5a44260011be7cc1f212a"))
	topics[1].SetBytes(txSender.Bytes())
	topics[2].SetBytes(exchangeNFC.Target.Bytes())
	dataList := make([]common.Hash, 2)
	dataList[0].SetBytes(amount.Bytes())
	dataList[1].SetBytes(exchangeNFC.Amount.Bytes())
	data := dataList[0].Bytes()
	data = append(data, dataList[1].Bytes()...)
	a.addCustomerTxLog (tx, receipts, topics, data)
	currentExchangeNFC = append(currentExchangeNFC, exchangeNFC)
	return currentExchangeNFC
}

func (a *Alien) processDeviceBind (currentDeviceBind []DeviceBindRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, snap *Snapshot) []DeviceBindRecord {
	if len(txDataInfo) <= nfcPosMiltiSign {
		log.Warn("Device bind revenue", "parameter number", len(txDataInfo))
		return currentDeviceBind
	}
	deviceBind := DeviceBindRecord {
		Device: common.Address{},
		Revenue: txSender,
		Contract: common.Address{},
		MultiSign: common.Address{},
		Type: 0,
		Bind: true,
	}
	if err := deviceBind.Device.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Device bind revenue", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentDeviceBind
	}
	if revenueType, err := strconv.ParseUint(txDataInfo[nfcPosRevenueType], 10, 32); err == nil {
		if revenueType == 0 {
			if _, ok := snap.RevenueNormal[deviceBind.Device]; ok {
				log.Warn("Device bind revenue", "device already bond", txDataInfo[nfcPosMinerAddress])
				return currentDeviceBind
			}
		} else {
			if _, ok := snap.RevenueFlow[deviceBind.Device]; ok {
				log.Warn("Device bind revenue", "device already bond", txDataInfo[nfcPosMinerAddress])
				return currentDeviceBind
			}
		}
		deviceBind.Type = uint32(revenueType)
	} else {
		log.Warn("Device bind revenue", "type", txDataInfo[nfcPosRevenueType])
		return currentDeviceBind
	}
	if 0 < len(txDataInfo[nfcPosRevenueContract]) {
		if err := deviceBind.Contract.UnmarshalText1([]byte(txDataInfo[nfcPosRevenueContract])); err != nil {
			log.Warn("Device bind revenue", "contract address", txDataInfo[nfcPosRevenueContract])
			return currentDeviceBind
		}
	}
	if 0 < len(txDataInfo[nfcPosMiltiSign]) {
		if err := deviceBind.MultiSign.UnmarshalText1([]byte(txDataInfo[nfcPosMiltiSign])); err != nil {
			log.Warn("Device bind revenue", "milti-signature address", txDataInfo[nfcPosRevenueContract])
			return currentDeviceBind
		}
	}
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0xf061654231b0035280bd8dd06084a38aa871445d0b7311be8cc2605c5672a6e3")) //web3.sha3("DeviceBind(uint32,byte32,byte32,address)")
	//topics[0].SetBytes([]byte("0x33400159405eff48ec6605a3edb3038722f1cb3a49f577526660be92904f02a2"))
	topics[1].SetBytes(deviceBind.Device.Bytes())
	topics[2].SetBytes(big.NewInt(int64(deviceBind.Type)).Bytes())
	dataList := make([]common.Hash, 3)
	dataList[0].SetBytes(deviceBind.Revenue.Bytes())
	dataList[1] = deviceBind.Contract.Hash()
	dataList[2] = deviceBind.MultiSign.Hash()
	data := dataList[0].Bytes()
	data = append(data, dataList[1].Bytes()...)
	data = append(data, dataList[2].Bytes()...)
	a.addCustomerTxLog (tx, receipts, topics, data)
	currentDeviceBind = append (currentDeviceBind, deviceBind)
	if deviceBind.Type == 0 {
		snap.RevenueNormal[deviceBind.Device] = &RevenueParameter{
			RevenueAddress: deviceBind.Revenue,
			RevenueContract: deviceBind.Contract,
			MultiSignature: deviceBind.MultiSign,
		}
	} else {
		snap.RevenueFlow[deviceBind.Device] = &RevenueParameter{
			RevenueAddress: deviceBind.Revenue,
			RevenueContract: deviceBind.Contract,
			MultiSignature: deviceBind.MultiSign,
		}
	}
	return currentDeviceBind
}

func (a *Alien) processDeviceUnbind (currentDeviceBind []DeviceBindRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []DeviceBindRecord {
	if len(txDataInfo) <= nfcPosRevenueType {
		log.Warn("Device unbind revenue", "parameter number", len(txDataInfo))
		return currentDeviceBind
	}
	nilHash := common.Address{}
	zeroHash := common.BigToAddress(big.NewInt(0))
	deviceBind := DeviceBindRecord {
		Device: common.Address{},
		Revenue: common.Address{},
		Contract: common.Address{},
		MultiSign: common.Address{},
		Type: 0,
		Bind: false,
	}
	if err := deviceBind.Device.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Device unbind revenue", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentDeviceBind
	}
	if revenueType, err := strconv.ParseUint(txDataInfo[nfcPosRevenueType], 10, 32); err == nil {
		if revenueType == 0 {
			if oldBind, ok := snap.RevenueNormal[deviceBind.Device]; !ok {
				log.Warn("Device unbind revenue", "device never bond", txDataInfo[nfcPosMinerAddress])
				return currentDeviceBind
			} else {
				if oldBind.MultiSignature == nilHash || oldBind.MultiSignature == zeroHash {
					if oldBind.RevenueAddress != txSender {
						log.Warn("Device unbind revenue", "revenue address", oldBind.RevenueAddress)
						return currentDeviceBind
					}
				} else {
					if !a.verifyMultiSignatureAddress(state, oldBind.MultiSignature, tx.AllSigners()) {
						log.Warn("Device unbind revenue failed to verify multi-signature")
						return currentDeviceBind
					}
				}
			}
		} else {
			if oldBind, ok := snap.RevenueFlow[deviceBind.Device]; !ok {
				log.Warn("Device unbind revenue", "device never bond", txDataInfo[nfcPosMinerAddress])
				return currentDeviceBind
			} else {
				if oldBind.MultiSignature == nilHash || oldBind.MultiSignature == zeroHash {
					if oldBind.RevenueAddress != txSender {
						log.Warn("Device unbind revenue", "revenue address", oldBind.RevenueAddress)
						return currentDeviceBind
					}
				} else {
					if !a.verifyMultiSignatureAddress(state, oldBind.MultiSignature, tx.AllSigners()) {
						log.Warn("Device unbind revenue failed to verify multi-signature")
						return currentDeviceBind
					}
				}
			}
		}
		deviceBind.Type = uint32(revenueType)
	} else {
		log.Warn("Device unbind revenue", "type", txDataInfo[nfcPosRevenueType])
		return currentDeviceBind
	}
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0xf061654231b0035280bd8dd06084a38aa871445d0b7311be8cc2605c5672a6e3")) //web3.sha3("DeviceBind(uint32,byte32,byte32,address)")
	//topics[0].SetBytes([]byte("0x33400159405eff48ec6605a3edb3038722f1cb3a49f577526660be92904f02a2"))
	topics[1].SetBytes(deviceBind.Device.Bytes())
	topics[2].SetBytes(big.NewInt(int64(deviceBind.Type)).Bytes())
	a.addCustomerTxLog (tx, receipts, topics, nil)
	currentDeviceBind = append (currentDeviceBind, deviceBind)
	if deviceBind.Type == 0 {
		delete(snap.RevenueNormal, deviceBind.Device)
	} else {
		delete(snap.RevenueFlow, deviceBind.Device)
	}
	return currentDeviceBind
}

func (a *Alien) processDeviceRebind (currentDeviceBind []DeviceBindRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []DeviceBindRecord {
	if len(txDataInfo) <= nfcPosRevenueAddress {
		log.Warn("Device rebind revenue", "parameter number", len(txDataInfo))
		return currentDeviceBind
	}
	nilHash := common.Address{}
	zeroHash := common.BigToAddress(big.NewInt(0))
	deviceBind := DeviceBindRecord {
		Device: common.Address{},
		Revenue: txSender,
		Contract: common.Address{},
		MultiSign: common.Address{},
		Type: 0,
		Bind: true,
	}
	if err := deviceBind.Device.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Device rebind revenue", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentDeviceBind
	}
	if err := deviceBind.Revenue.UnmarshalText1([]byte(txDataInfo[nfcPosRevenueAddress])); err != nil {
		log.Warn("Device rebind revenue", "revenue address", txDataInfo[nfcPosMinerAddress])
		return currentDeviceBind
	}
	if revenueType, err := strconv.ParseUint(txDataInfo[nfcPosRevenueType], 10, 32); err == nil {
		if revenueType == 0 {
			if oldBind, ok := snap.RevenueNormal[deviceBind.Device]; ok {
				if oldBind.MultiSignature == nilHash || oldBind.MultiSignature == zeroHash {
					if oldBind.RevenueAddress != txSender {
						log.Warn("Device rebind revenue", "revenue address", oldBind.RevenueAddress)
						return currentDeviceBind
					}
				} else {
					if !a.verifyMultiSignatureAddress(state, oldBind.MultiSignature, tx.AllSigners()) {
						log.Warn("Device rebind revenue failed to verify multi-signature")
						return currentDeviceBind
					}
				}
			} else if deviceBind.Revenue != txSender {
				log.Warn("Device rebind revenue", "device cnnnot bind", deviceBind.Revenue)
				return currentDeviceBind
			}
		} else {
			if oldBind, ok := snap.RevenueFlow[deviceBind.Device]; ok {
				if oldBind.MultiSignature == nilHash || oldBind.MultiSignature == zeroHash {
					if oldBind.RevenueAddress != txSender {
						log.Warn("Device rebind revenue", "revenue address", oldBind.RevenueAddress)
						return currentDeviceBind
					}
				} else {
					if !a.verifyMultiSignatureAddress(state, oldBind.MultiSignature, tx.AllSigners()) {
						log.Warn("Device rebind revenue failed to verify multi-signature")
						return currentDeviceBind
					}
				}
			} else if deviceBind.Revenue != txSender {
				log.Warn("Device rebind revenue", "device cnnnot bind", deviceBind.Revenue)
				return currentDeviceBind
			}
		}
		deviceBind.Type = uint32(revenueType)
	} else {
		log.Warn("Device rebind revenue", "type", txDataInfo[nfcPosRevenueType])
		return currentDeviceBind
	}
	if 0 < len(txDataInfo[nfcPosRevenueContract]) {
		if err := deviceBind.Contract.UnmarshalText1([]byte(txDataInfo[nfcPosRevenueContract])); err != nil {
			log.Warn("Device rebind revenue", "contract address", txDataInfo[nfcPosRevenueContract])
			return currentDeviceBind
		}
	}
	if 0 < len(txDataInfo[nfcPosMiltiSign]) {
		if err := deviceBind.MultiSign.UnmarshalText1([]byte(txDataInfo[nfcPosMiltiSign])); err != nil {
			log.Warn("Device rebind revenue", "milti-signature address", txDataInfo[nfcPosRevenueContract])
			return currentDeviceBind
		}
	}
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0xf061654231b0035280bd8dd06084a38aa871445d0b7311be8cc2605c5672a6e3")) //web3.sha3("DeviceBind(uint32,byte32,byte32,address)")
	//topics[0].SetBytes([]byte("0x33400159405eff48ec6605a3edb3038722f1cb3a49f577526660be92904f02a2"))
	topics[1].SetBytes(deviceBind.Device.Bytes())
	topics[2].SetBytes(big.NewInt(int64(deviceBind.Type)).Bytes())
	dataList := make([]common.Hash, 3)
	dataList[0].SetBytes(deviceBind.Revenue.Bytes())
	dataList[1] = deviceBind.Contract.Hash()
	dataList[2] = deviceBind.MultiSign.Hash()
	data := dataList[0].Bytes()
	data = append(data, dataList[1].Bytes()...)
	data = append(data, dataList[2].Bytes()...)
	a.addCustomerTxLog (tx, receipts, topics, data)
	currentDeviceBind = append (currentDeviceBind, deviceBind)
	if deviceBind.Type == 0 {
		snap.RevenueNormal[deviceBind.Device] = &RevenueParameter{
			RevenueAddress: deviceBind.Revenue,
			RevenueContract: deviceBind.Contract,
			MultiSignature: deviceBind.MultiSign,
		}
	} else {
		snap.RevenueFlow[deviceBind.Device] = &RevenueParameter{
			RevenueAddress: deviceBind.Revenue,
			RevenueContract: deviceBind.Contract,
			MultiSignature: deviceBind.MultiSign,
		}
	}
	return currentDeviceBind
}

func (a *Alien) processCandidatePledge (currentCandidatePledge []CandidatePledgeRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []CandidatePledgeRecord {
	if len(txDataInfo) <= nfcPosMinerAddress {
		log.Warn("Candidate pledge", "parameter number", len(txDataInfo))
		return currentCandidatePledge
	}
	candidatePledge := CandidatePledgeRecord{
		Target: common.Address{},
		Amount: new(big.Int).Set(minCndPledgeBalance),
	}
	if deposit, ok := snap.SystemConfig.Deposit[0]; ok {
		candidatePledge.Amount = new(big.Int).Set(deposit)
	}
	if err := candidatePledge.Target.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Candidate pledge", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentCandidatePledge
	}
	if state.GetBalance(txSender).Cmp(candidatePledge.Amount) < 0 {
		log.Warn("Candidate pledge", "balance", state.GetBalance(txSender))
		return currentCandidatePledge
	}
	if pledgeItem, ok := snap.CandidatePledge[candidatePledge.Target]; ok {
		if pledgeItem.StartHigh > 0 {
			log.Warn("Candidate pledge", "candidate already exit", pledgeItem.StartHigh)
			return currentCandidatePledge
		}
		pledgeItem.Amount = new(big.Int).Add(pledgeItem.Amount, candidatePledge.Amount)
	} else {
		pledgeItem := &PledgeItem{
			Amount: new(big.Int).Set(candidatePledge.Amount),
			Playment: big.NewInt(0),
			LockPeriod: 0,
			RlsPeriod: 0,
			Interval: 0,
			StartHigh: 0,
			RevenueAddress: common.Address{},
			RevenueContract: common.Address{},
			MultiSignature: common.Address{},
		}
		snap.CandidatePledge[candidatePledge.Target] = pledgeItem
	}
	state.SubBalance(txSender, candidatePledge.Amount)
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0x61edf63329be99ab5b931ab93890ea08164175f1bce7446645ba4c1c7bdae3a8")) //web3.sha3("PledgeLock(address,uint256)")
	//topics[0].SetBytes([]byte("0xc00244e69a701450fb8a264608a08e4bc0c88aafb506c4892c341ea76153a567"))
	topics[1].SetBytes(candidatePledge.Target.Bytes())
	topics[2].SetBytes(big.NewInt(sscEnumCndLock).Bytes())
	data := common.Hash{}
	data.SetBytes(candidatePledge.Amount.Bytes())
	a.addCustomerTxLog (tx, receipts, topics, data.Bytes())
	currentCandidatePledge = append(currentCandidatePledge, candidatePledge)
	return currentCandidatePledge
}

func (a *Alien) processCandidateExit (currentCandidateExit []common.Address, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []common.Address {
	if len(txDataInfo) <= nfcPosMinerAddress {
		log.Warn("Candidate exit", "parameter number", len(txDataInfo))
		return currentCandidateExit
	}
	minerAddress := common.Address{}
	nilHash := common.Address{}
	zeroHash := common.BigToAddress(big.NewInt(0))
	if err := minerAddress.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Candidate exit", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentCandidateExit
	}
	if oldBind, ok := snap.RevenueNormal[minerAddress]; ok {
		if oldBind.MultiSignature == nilHash || oldBind.MultiSignature == zeroHash {
			if oldBind.RevenueAddress != txSender {
				log.Warn("Candidate exit", "revenue address", oldBind.RevenueAddress)
				return currentCandidateExit
			}
		} else {
			if !a.verifyMultiSignatureAddress(state, oldBind.MultiSignature, tx.AllSigners()) {
				log.Warn("Candidate exit failed to verify multi-signature")
				return currentCandidateExit
			}
		}
	}
	if pledgeItem, ok := snap.CandidatePledge[minerAddress]; ok {
		if pledgeItem.StartHigh > 0 {
			log.Warn("Candidate exit", "candidate already exit", pledgeItem.StartHigh)
			return currentCandidateExit
		}
		pledgeItem.StartHigh = snap.Number + 1
	} else {
		log.Warn("Candidate exit", "candidate isnot exist", minerAddress)
		return currentCandidateExit
	}
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0x9489b96ebcb056332b79de467a2645c56a999089b730c99fead37b20420d58e7")) //web3.sha3("PledgeExit(address)")
	//topics[0].SetBytes([]byte("0xfb967d1450f2a5c9c05e41dd6e611dfa46d9dd87376c7e4d9776842e83375ed6"))
	topics[1].SetBytes(minerAddress.Bytes())
	topics[2].SetBytes(big.NewInt(sscEnumCndLock).Bytes())
	a.addCustomerTxLog (tx, receipts, topics, nil)
	currentCandidateExit = append(currentCandidateExit, minerAddress)
	return currentCandidateExit
}

func (a *Alien) processCandidatePunish (currentCandidatePunish []CandidatePunishRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []CandidatePunishRecord {
	if len(txDataInfo) <= nfcPosMinerAddress {
		log.Warn("Candidate punish", "parameter number", len(txDataInfo))
		return currentCandidatePunish
	}
	candidatePunish := CandidatePunishRecord{
		Target: common.Address{},
		Amount: big.NewInt(0),
		Credit: 0,
	}
	if err := candidatePunish.Target.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Candidate punish", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentCandidatePunish
	}
	if candidateCredit, ok := snap.Punished[candidatePunish.Target]; !ok {
		log.Warn("Candidate punish", "not punish", candidatePunish.Target)
		return currentCandidatePunish
	} else {
		candidatePunish.Credit = uint32(candidateCredit)
	    deposit := new(big.Int).Set(minCndPledgeBalance)
		if _, ok := snap.SystemConfig.Deposit[0]; ok {
			deposit = new(big.Int).Set(snap.SystemConfig.Deposit[0])
		}
		candidatePunish.Amount = new(big.Int).Div(new(big.Int).Mul(deposit, big.NewInt(int64(candidateCredit))), big.NewInt(int64(defaultFullCredit)))
	}
	if state.GetBalance(txSender).Cmp(candidatePunish.Amount) < 0 {
		log.Warn("Candidate punish", "balance", state.GetBalance(txSender))
		return currentCandidatePunish
	}
	if pledgeItem, ok := snap.CandidatePledge[candidatePunish.Target]; !ok {
		log.Warn("Candidate punish", "candidate isnot exist", candidatePunish.Target)
		return currentCandidatePunish
	} else {
		if pledgeItem.StartHigh > 0 {
			log.Warn("Candidate punish", "candidate already exit", pledgeItem.StartHigh)
			return currentCandidatePunish
		}
		pledgeItem.Amount = new(big.Int).Add(pledgeItem.Amount, candidatePunish.Amount)
	}
	state.SetBalance(txSender, new(big.Int).Sub(state.GetBalance(txSender), candidatePunish.Amount))
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0xd67fe14bb06aa8656e0e7c3230831d68e8ce49bb4a4f71448f98a998d2674621")) //web3.sha3("PledgePunish(address,uint32)")
	//topics[0].SetBytes([]byte("0xdf4d90e24a37f33947f5ab2aed37f938062b1b3dc6c7aa02fa5a2dcc8b8f5cf0"))
	topics[1].SetBytes(candidatePunish.Target.Bytes())
	topics[2].SetBytes(big.NewInt(sscEnumCndLock).Bytes())
	dataList := make([]common.Hash, 2)
	dataList[0].SetBytes(big.NewInt(int64(candidatePunish.Credit)).Bytes())
	dataList[1].SetBytes(candidatePunish.Amount.Bytes())
	data := dataList[0].Bytes()
	data = append(data, dataList[1].Bytes()...)
	a.addCustomerTxLog (tx, receipts, topics, data)
	currentCandidatePunish = append(currentCandidatePunish, candidatePunish)
	return currentCandidatePunish
}

func (a *Alien) processMinerPledge (currentClaimedBandwidth []ClaimedBandwidthRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []ClaimedBandwidthRecord {
	if len(txDataInfo) <= nfcPosBandwidth {
		log.Warn("Claimed bandwidth", "parameter number", len(txDataInfo))
		return currentClaimedBandwidth
	}
	claimedBandwidth := ClaimedBandwidthRecord{
		Target: common.Address{},
		Amount: big.NewInt(0),
		ISPQosID: 0,
		Bandwidth: 0,
	}
	if err := claimedBandwidth.Target.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Claimed bandwidth", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentClaimedBandwidth
	}
	if pledge, ok := snap.FlowPledge[claimedBandwidth.Target]; ok && 0 < pledge.StartHigh {
		log.Warn("Claimed bandwidth", "miner exiting", claimedBandwidth.Target)
		return currentClaimedBandwidth
	}
	if ISPQosID, err := strconv.ParseUint(txDataInfo[nfcPosISPQosID], 16, 32); err != nil {
		log.Warn("Claimed bandwidth", "ISP qos id", txDataInfo[nfcPosISPQosID])
		return currentClaimedBandwidth
	} else {
		claimedBandwidth.ISPQosID = uint32(ISPQosID)
	}
	if bandwidth, err := strconv.ParseUint(txDataInfo[nfcPosBandwidth], 16, 32); err != nil {
		log.Warn("Claimed bandwidth", "bandwidth", txDataInfo[nfcPosBandwidth])
		return currentClaimedBandwidth
	} else {
		claimedBandwidth.Bandwidth = uint32(bandwidth)
	}
	total := big.NewInt(0)
	for _, bandwidthItem := range snap.Bandwidth {
		total = new(big.Int).Add(total, big.NewInt(int64(bandwidthItem.BandwidthClaimed)))
	}
	bandwidth := claimedBandwidth.Bandwidth
	if oldBandwidth, ok := snap.Bandwidth[claimedBandwidth.Target]; ok {
		if claimedBandwidth.Bandwidth < oldBandwidth.BandwidthClaimed {
			log.Warn("Claimed bandwidth", "bandwidth reduce", oldBandwidth.BandwidthClaimed)
			return currentClaimedBandwidth
		}
		bandwidth -= oldBandwidth.BandwidthClaimed
	}
	scale := 3
	if claimedBandwidth.Bandwidth > 1500 {
		scale = 160
	} else if claimedBandwidth.Bandwidth > 800 {
		scale = 120
	} else if claimedBandwidth.Bandwidth > 300 {
		scale = 80
	}
	if 0 < snap.FlowTotal.Cmp(big.NewInt(1073741824 * 1024)) {
		claimedBandwidth.Amount = new(big.Int).Div(new(big.Int).Div(new(big.Int).Mul(new(big.Int).Mul(big.NewInt(int64(bandwidth)), snap.FlowHarvest), big.NewInt(int64(scale))), total), big.NewInt(100))
	} else {
		claimedBandwidth.Amount = new(big.Int).Div(new(big.Int).Div(new(big.Int).Mul(new(big.Int).Mul(big.NewInt(int64(bandwidth)), new(big.Int).Mul(big.NewInt(3660208594), big.NewInt(1e+16))), big.NewInt(int64(scale))), big.NewInt(570480)), big.NewInt(100))
	}
	if state.GetBalance(txSender).Cmp(claimedBandwidth.Amount) < 0 {
		log.Warn("Claimed bandwidth", "balance", state.GetBalance(txSender))
		return currentClaimedBandwidth
	}
	if pledgeItem, ok := snap.FlowPledge[claimedBandwidth.Target]; !ok {
		pledgeItem := &PledgeItem{
			Amount: new(big.Int).Set(claimedBandwidth.Amount),
			Playment: big.NewInt(0),
			LockPeriod: 0,
			RlsPeriod: 0,
			Interval: 0,
			StartHigh: 0,
			RevenueAddress: common.Address{},
			RevenueContract: common.Address{},
			MultiSignature: common.Address{},
		}
		snap.FlowPledge[claimedBandwidth.Target] = pledgeItem
	} else {
		if pledgeItem.StartHigh > 0 {
			log.Warn("Claimed bandwidth", "miner already exit", pledgeItem.StartHigh)
			return currentClaimedBandwidth
		}
		pledgeItem.Amount = new(big.Int).Add(pledgeItem.Amount, claimedBandwidth.Amount)
	}
	if oldBandwidth, ok := snap.Bandwidth[claimedBandwidth.Target]; ok {
		oldBandwidth.ISPQosID = claimedBandwidth.ISPQosID
		oldBandwidth.BandwidthClaimed = claimedBandwidth.Bandwidth
	} else {
		oldBandwidth := &ClaimedBandwidth{
			ISPQosID: claimedBandwidth.ISPQosID,
			BandwidthClaimed: claimedBandwidth.Bandwidth,
		}
		snap.Bandwidth[claimedBandwidth.Target] = oldBandwidth
	}
	state.SetBalance(txSender, new(big.Int).Sub(state.GetBalance(txSender), claimedBandwidth.Amount))
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0x041e56787332f2495a47171278fa0f1ddb21961f702d0ba53c2bb2c079ccd418")) //web3.sha3("ClaimedBandwidth(address,uint32,uint32)")
	//topics[0].SetBytes([]byte("0xb630b6b7ef41a65bd1f02f3f60b509e85f33a4607e15f4161807241d493ddd6a"))
	topics[1].SetBytes(claimedBandwidth.Target.Bytes())
	topics[2].SetBytes(big.NewInt(sscEnumBndwdthClaimed).Bytes())
	dataList := make([]common.Hash, 2)
	dataList[0].SetBytes(big.NewInt(int64(claimedBandwidth.ISPQosID)).Bytes())
	dataList[1].SetBytes(big.NewInt(int64(claimedBandwidth.Bandwidth)).Bytes())
	data := dataList[0].Bytes()
	data = append(data, dataList[1].Bytes()...)
	a.addCustomerTxLog (tx, receipts, topics, data)
	topics = make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0x61edf63329be99ab5b931ab93890ea08164175f1bce7446645ba4c1c7bdae3a8")) //web3.sha3("PledgeLock(address,uint256)")
	//topics[0].SetBytes([]byte("0xc00244e69a701450fb8a264608a08e4bc0c88aafb506c4892c341ea76153a567"))
	topics[1].SetBytes(claimedBandwidth.Target.Bytes())
	topics[2].SetBytes(big.NewInt(sscEnumFlwLock).Bytes())
	dataList = make([]common.Hash, 2)
	dataList[0].SetBytes(big.NewInt(int64(claimedBandwidth.Bandwidth)).Bytes())
	dataList[1].SetBytes(claimedBandwidth.Amount.Bytes())
	data = dataList[0].Bytes()
	data = append(data, dataList[1].Bytes()...)
	a.addCustomerTxLog (tx, receipts, topics, data)
	currentClaimedBandwidth = append(currentClaimedBandwidth, claimedBandwidth)
	return currentClaimedBandwidth
}

func (a *Alien) processMinerExit (currentFlowMinerExit []common.Address, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, state *state.StateDB, snap *Snapshot) []common.Address {
	if len(txDataInfo) <= nfcPosMinerAddress {
		log.Warn("Flow miner exit", "parameter number", len(txDataInfo))
		return currentFlowMinerExit
	}
	minerAddress := common.Address{}
	nilHash := common.Address{}
	zeroHash := common.BigToAddress(big.NewInt(0))
	if err := minerAddress.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Flow miner exit", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentFlowMinerExit
	}
	if oldBind, ok := snap.RevenueFlow[minerAddress]; ok {
		if oldBind.MultiSignature == nilHash || oldBind.MultiSignature == zeroHash {
			if oldBind.RevenueAddress != txSender {
				log.Warn("Flow miner exit", "revenue address", oldBind.RevenueAddress)
				return currentFlowMinerExit
			}
		} else {
			if !a.verifyMultiSignatureAddress(state, oldBind.MultiSignature, tx.AllSigners()) {
				log.Warn("Flow miner exit failed to verify multi-signature")
				return currentFlowMinerExit
			}
		}
	}
	if pledgeItem, ok := snap.FlowPledge[minerAddress]; ok {
		if pledgeItem.StartHigh > 0 {
			log.Warn("Flow miner exit", "miner already exit", pledgeItem.StartHigh)
			return currentFlowMinerExit
		}
		pledgeItem.StartHigh = snap.Number + 1
	} else {
		log.Warn("Flow miner exit", "miner isnot exist", minerAddress)
		return currentFlowMinerExit
	}
	delete(snap.Bandwidth, minerAddress)
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0x9489b96ebcb056332b79de467a2645c56a999089b730c99fead37b20420d58e7")) //web3.sha3("PledgeExit(address)")
	//topics[0].SetBytes([]byte("0xfb967d1450f2a5c9c05e41dd6e611dfa46d9dd87376c7e4d9776842e83375ed6"))
	topics[1].SetBytes(minerAddress.Bytes())
	topics[2].SetBytes(big.NewInt(sscEnumFlwLock).Bytes())
	a.addCustomerTxLog (tx, receipts, topics, nil)
	currentFlowMinerExit = append(currentFlowMinerExit, minerAddress)
	return currentFlowMinerExit
}

func (a *Alien) processBandwidthPunish (currentBandwidthPunish []BandwidthPunishRecord, txDataInfo []string, txSender common.Address, tx *types.Transaction, receipts []*types.Receipt, snap *Snapshot) []BandwidthPunishRecord {
	if len(txDataInfo) <= sscPosWdthPnsh {
		log.Warn("Bandwidth punish", "parameter number", len(txDataInfo))
		return currentBandwidthPunish
	}
	if snap.SystemConfig.ManagerAddress[sscEnumWdthPnsh].String() != txSender.String() {
		log.Warn("Bandwidth punish", "manager address", txSender)
		return currentBandwidthPunish
	}
	bandwidthPunish := BandwidthPunishRecord{
		Target: common.Address{},
		WdthPnsh: 0,
	}
	if err := bandwidthPunish.Target.UnmarshalText1([]byte(txDataInfo[nfcPosMinerAddress])); err != nil {
		log.Warn("Bandwidth punish", "miner address", txDataInfo[nfcPosMinerAddress])
		return currentBandwidthPunish
	}
	if _, ok := snap.Bandwidth[bandwidthPunish.Target]; !ok {
		log.Warn("Bandwidth punish", "miner hasnot claimed bandwidth", bandwidthPunish.Target)
		return currentBandwidthPunish
	}
	if bandwidth, err := strconv.ParseUint(txDataInfo[sscPosWdthPnsh], 16, 32); err != nil {
		log.Warn("Bandwidth punish", "bandwidth", txDataInfo[sscPosWdthPnsh])
		return currentBandwidthPunish
	} else {
		bandwidthPunish.WdthPnsh = uint32(bandwidth)
	}
	topics := make([]common.Hash, 3)
	topics[0].UnmarshalText([]byte("0x041e56787332f2495a47171278fa0f1ddb21961f702d0ba53c2bb2c079ccd418")) //web3.sha3("ClaimedBandwidth(address,uint32,uint32)")
	//topics[0].SetBytes([]byte("0xb630b6b7ef41a65bd1f02f3f60b509e85f33a4607e15f4161807241d493ddd6a"))
	topics[1].SetBytes(bandwidthPunish.Target.Bytes())
	topics[2].SetBytes(big.NewInt(sscEnumBndwdthPunish).Bytes())
	dataList := make([]common.Hash, 2)
	dataList[0].SetBytes(big.NewInt(int64(snap.Bandwidth[bandwidthPunish.Target].ISPQosID)).Bytes())
	dataList[1].SetBytes(big.NewInt(int64(bandwidthPunish.WdthPnsh)).Bytes())
	data := dataList[0].Bytes()
	data = append(data, dataList[1].Bytes()...)
	a.addCustomerTxLog (tx, receipts, topics, data)
	snap.Bandwidth[bandwidthPunish.Target].BandwidthClaimed = bandwidthPunish.WdthPnsh
	currentBandwidthPunish = append(currentBandwidthPunish, bandwidthPunish)
	return currentBandwidthPunish
}

func (a *Alien) processExchRate (txDataInfo []string, txSender common.Address, snap *Snapshot) uint32 {
	if len(txDataInfo) <= sscPosExchRate {
		log.Warn("Config exchrate", "parameter number", len(txDataInfo))
		return 0
	}
	if exchRate, err := strconv.ParseUint(txDataInfo[sscPosExchRate], 10, 32); err != nil {
		log.Warn("Config exchrate", "exchrate", txDataInfo[sscPosExchRate])
		return 0
	} else {
		if snap.SystemConfig.ManagerAddress[sscEnumExchRate].String() != txSender.String() {
			log.Warn("Config exchrate", "manager address", txSender)
			return 0
		}
		return uint32(exchRate)
	}
}

func (a *Alien) processCandidateDeposit (currentDeposit []ConfigDepositRecord, txDataInfo []string, txSender common.Address, snap *Snapshot) []ConfigDepositRecord {
	if len(txDataInfo) <= sscPosDepositWho {
		log.Warn("Config candidate deposit", "parameter number", len(txDataInfo))
		return currentDeposit
	}
	deposit := ConfigDepositRecord{
		Who: 0,
		Amount: big.NewInt(0),
	}
	var err error
	if deposit.Amount, err = hexutil.UnmarshalText1([]byte(txDataInfo[sscPosDeposit])); err != nil {
		log.Warn("Config candidate deposit", "deposit", txDataInfo[sscPosDeposit])
		return currentDeposit
	}
	if id, err := strconv.ParseUint(txDataInfo[sscPosDepositWho], 10, 32); err != nil {
		log.Warn("Config manager", "id", txDataInfo[sscPosDepositWho])
		return currentDeposit
	} else {
		deposit.Who = uint32(id)
	}
	if snap.SystemConfig.ManagerAddress[sscEnumSystem].String() != txSender.String() {
		log.Warn("Config candidate deposit", "manager address", txSender)
		return currentDeposit
	}
	currentDeposit = append(currentDeposit, deposit)
	return currentDeposit
}

func (a *Alien) processCndLockConfig (currentLockParameters []LockParameterRecord, txDataInfo []string, txSender common.Address, snap *Snapshot) []LockParameterRecord {
	if len(txDataInfo) <= sscPosInterval {
		log.Warn("Config candidate lock", "parameter number", len(txDataInfo))
		return currentLockParameters
	}
	lockParameter := LockParameterRecord{
		Who: sscEnumCndLock,
		LockPeriod: uint32(180 * 24 * 60 * 60 / a.config.Period),
		RlsPeriod: 0,
		Interval: 0,
	}
	if lockPeriod, err := strconv.ParseUint(txDataInfo[sscPosLockPeriod], 16, 32); err != nil {
		log.Warn("Config candidate lock", "lock period", txDataInfo[sscPosLockPeriod])
		return currentLockParameters
	} else {
		lockParameter.LockPeriod = uint32(lockPeriod)
	}
	if releasePeriod, err := strconv.ParseUint(txDataInfo[sscPosRlsPeriod], 16, 32); err != nil {
		log.Warn("Config candidate lock", "release period", txDataInfo[sscPosRlsPeriod])
		return currentLockParameters
	} else {
		lockParameter.RlsPeriod = uint32(releasePeriod)
	}
	if interval, err := strconv.ParseUint(txDataInfo[sscPosInterval], 16, 32); err != nil {
		log.Warn("Config candidate lock", "release interval", txDataInfo[sscPosInterval])
		return currentLockParameters
	} else {
		lockParameter.Interval = uint32(interval)
	}
	if snap.SystemConfig.ManagerAddress[sscEnumSystem].String() != txSender.String() {
		log.Warn("Config candidate lock", "manager address", txSender)
		return currentLockParameters
	}
	currentLockParameters = append(currentLockParameters, lockParameter)
	return currentLockParameters
}

func (a *Alien) processFlwLockConfig (currentLockParameters []LockParameterRecord, txDataInfo []string, txSender common.Address, snap *Snapshot) []LockParameterRecord {
	if len(txDataInfo) <= sscPosInterval {
		log.Warn("Config miner lock", "parameter number", len(txDataInfo))
		return currentLockParameters
	}
	lockParameter := LockParameterRecord{
		Who: sscEnumFlwLock,
		LockPeriod: uint32(180 * 24 * 60 * 60 / a.config.Period),
		RlsPeriod: 0,
		Interval: 0,
	}
	if lockPeriod, err := strconv.ParseUint(txDataInfo[sscPosLockPeriod], 16, 32); err != nil {
		log.Warn("Config miner lock", "lock period", txDataInfo[sscPosLockPeriod])
		return currentLockParameters
	} else {
		lockParameter.LockPeriod = uint32(lockPeriod)
	}
	if releasePeriod, err := strconv.ParseUint(txDataInfo[sscPosRlsPeriod], 16, 32); err != nil {
		log.Warn("Config miner lock", "release period", txDataInfo[sscPosRlsPeriod])
		return currentLockParameters
	} else {
		lockParameter.RlsPeriod = uint32(releasePeriod)
	}
	if interval, err := strconv.ParseUint(txDataInfo[sscPosInterval], 16, 32); err != nil {
		log.Warn("Config miner lock", "release interval", txDataInfo[sscPosInterval])
		return currentLockParameters
	} else {
		lockParameter.Interval = uint32(interval)
	}
	if snap.SystemConfig.ManagerAddress[sscEnumSystem].String() != txSender.String() {
		log.Warn("Config miner lock", "manager address", txSender)
		return currentLockParameters
	}
	currentLockParameters = append(currentLockParameters, lockParameter)
	return currentLockParameters
}

func (a *Alien) processRwdLockConfig (currentLockParameters []LockParameterRecord, txDataInfo []string, txSender common.Address, snap *Snapshot) []LockParameterRecord {
	if len(txDataInfo) <= sscPosInterval {
		log.Warn("Config reward lock", "parameter number", len(txDataInfo))
		return currentLockParameters
	}
	lockParameter := LockParameterRecord{
		Who: sscEnumRwdLock,
		LockPeriod: uint32(180 * 24 * 60 * 60 / a.config.Period),
		RlsPeriod: 0,
		Interval: 0,
	}
	if lockPeriod, err := strconv.ParseUint(txDataInfo[sscPosLockPeriod], 16, 32); err != nil {
		log.Warn("Config reward lock", "lock period", txDataInfo[sscPosLockPeriod])
		return currentLockParameters
	} else {
		lockParameter.LockPeriod = uint32(lockPeriod)
	}
	if releasePeriod, err := strconv.ParseUint(txDataInfo[sscPosRlsPeriod], 16, 32); err != nil {
		log.Warn("Config reward lock", "release period", txDataInfo[sscPosRlsPeriod])
		return currentLockParameters
	} else {
		lockParameter.RlsPeriod = uint32(releasePeriod)
	}
	if interval, err := strconv.ParseUint(txDataInfo[sscPosInterval], 16, 32); err != nil {
		log.Warn("Config reward lock", "release interval", txDataInfo[sscPosInterval])
		return currentLockParameters
	} else {
		lockParameter.Interval = uint32(interval)
	}
	if snap.SystemConfig.ManagerAddress[sscEnumSystem].String() != txSender.String() {
		log.Warn("Config reward lock", "manager address", txSender)
		return currentLockParameters
	}
	currentLockParameters = append(currentLockParameters, lockParameter)
	return currentLockParameters
}

func (a *Alien) processOffLine (txDataInfo []string, txSender common.Address, snap *Snapshot) uint32 {
	if len(txDataInfo) <= sscPosOffLine {
		log.Warn("Config offLine", "parameter number", len(txDataInfo))
		return 0
	}
	if offline, err := strconv.ParseUint(txDataInfo[sscPosOffLine], 10, 32); err != nil {
		log.Warn("Config offline", "offline", txDataInfo[sscPosOffLine])
		return 0
	} else {
		if snap.SystemConfig.ManagerAddress[sscEnumSystem].String() != txSender.String() {
			log.Warn("Config offLine", "manager address", txSender)
			return 0
		}
		return uint32(offline)
	}
}

func (a *Alien) processISPQos (currentISPQOS []ISPQOSRecord, txDataInfo []string, txSender common.Address, snap *Snapshot) []ISPQOSRecord {
	if len(txDataInfo) <= sscPosQosValue {
		log.Warn("Config isp qos", "parameter number", len(txDataInfo))
		return currentISPQOS
	}
	ISPQOS := ISPQOSRecord{
		ISPID: 0,
		QOS: 0,
	}
	if id, err := strconv.ParseUint(txDataInfo[sscPosQosID], 10, 32); err != nil {
		log.Warn("Config isp qos", "isp id", txDataInfo[sscPosQosID])
		return currentISPQOS
	} else {
		ISPQOS.ISPID = uint32(id)
	}
	if qos, err := strconv.ParseUint(txDataInfo[sscPosQosValue], 10, 32); err != nil {
		log.Warn("Config isp qos", "qos", txDataInfo[sscPosQosValue])
		return currentISPQOS
	} else {
		ISPQOS.QOS = uint32(qos)
	}
	if snap.SystemConfig.ManagerAddress[sscEnumSystem].String() != txSender.String() {
		log.Warn("Config isp qos", "manager address", txSender)
		return currentISPQOS
	}
	currentISPQOS = append(currentISPQOS, ISPQOS)
	return currentISPQOS
}

func (a *Alien) processManagerAddress (currentManagerAddress []ManagerAddressRecord, txDataInfo []string, txSender common.Address, snap *Snapshot) []ManagerAddressRecord {
	if len(txDataInfo) <= sscPosManagerAddress {
		log.Warn("Config manager", "parameter number", len(txDataInfo))
		return currentManagerAddress
	}
	if txSender.String() != managerAddressManager.String() {
		log.Warn("Config manager", "manager", txSender)
		return currentManagerAddress
	}
	managerAddress := ManagerAddressRecord{
		Target: common.Address{},
		Who: 0,
	}
	if id, err := strconv.ParseUint(txDataInfo[sscPosManagerID], 10, 32); err != nil {
		log.Warn("Config manager", "id", txDataInfo[sscPosManagerID])
		return currentManagerAddress
	} else {
		managerAddress.Who = uint32(id)
	}
	if err := managerAddress.Target.UnmarshalText1([]byte(txDataInfo[sscPosManagerAddress])); err != nil {
		log.Warn("Config manager", "address", txDataInfo[sscPosManagerAddress])
		return currentManagerAddress
	}
	snap.SystemConfig.ManagerAddress[managerAddress.Who] = managerAddress.Target
	currentManagerAddress = append(currentManagerAddress, managerAddress)
	return currentManagerAddress
}

func (a *Alien) processFlowReport1 (flowReport []MinerFlowReportRecord, txDataInfo []string, txSender common.Address, snap *Snapshot) ([]MinerFlowReportRecord, bool) {
	if len(txDataInfo) <= posEventFlowValue {
		log.Warn("Flow report", "parameter number", len(txDataInfo))
		return flowReport, false
	}
	ok := false
	var report MinerFlowReportRecord
	if err := rlp.DecodeBytes(common.FromHex(txDataInfo[posEventFlowValue]), &report); err == nil {
		if snap.isSideChainCoinbase (report.ChainHash, txSender, true) {
			flowReport = append(flowReport, report)
			ok = true
		}
	} else {
		log.Warn("processFlowReport1", "err", err)
	}
	return flowReport, ok
}

func (a *Alien) processFlowReport2 (flowReport []MinerFlowReportRecord, txDataInfo []string) []MinerFlowReportRecord {
	if len(txDataInfo) <= posEventFlowValue {
		log.Warn("Flow report", "parameter number", len(txDataInfo))
		return flowReport
	}
	buffer := common.Hex2Bytes(txDataInfo[posEventFlowValue])
	reportTime := new(big.Int).SetBytes(buffer[:8]).Uint64()
	census := MinerFlowReportRecord{
		ChainHash: common.Hash{},
		ReportTime: reportTime,
		ReportContent: []MinerFlowReportItem{},
	}
	post := 8
	for post + 40 <= len(buffer) {
		address := common.Address{}
		address.SetBytes(buffer[post:post+20])
		post += 20
		census.ReportContent = append(census.ReportContent, MinerFlowReportItem{
			Target: address,
			FlowValue1: new(big.Int).SetBytes(buffer[post:post+8]).Uint64(),
			FlowValue2: new(big.Int).SetBytes(buffer[post+8:post+16]).Uint64(),
			ReportNumber: uint32(new(big.Int).SetBytes(buffer[post+16:post+20]).Uint64()),
		})
		post += 20
	}
	flowReport = append(flowReport, census)
	return flowReport
}
