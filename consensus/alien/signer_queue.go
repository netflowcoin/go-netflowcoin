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
	"bytes"
	"math/big"
	"sort"

	"github.com/seaskycheng/sdvn/common"
)

type MinerSlice []common.Address

func (s MinerSlice) Len() int      { return len(s) }
func (s MinerSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s MinerSlice) Less(i, j int) bool {
	return bytes.Compare(s[i].Bytes(), s[j].Bytes()) > 0
}

type TallyItem struct {
	addr  common.Address
	stake *big.Int
}
type TallySlice []TallyItem

func (s TallySlice) Len() int      { return len(s) }
func (s TallySlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s TallySlice) Less(i, j int) bool {
	//we need sort reverse, so ...
	isLess := s[i].stake.Cmp(s[j].stake)
	if isLess > 0 {
		return true

	} else if isLess < 0 {
		return false
	}
	// if the stake equal
	return bytes.Compare(s[i].addr.Bytes(), s[j].addr.Bytes()) > 0
}

type SignerItem struct {
	addr common.Address
	hash common.Hash
}
type SignerSlice []SignerItem

func (s SignerSlice) Len() int      { return len(s) }
func (s SignerSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s SignerSlice) Less(i, j int) bool {
	return bytes.Compare(s[i].hash.Bytes(), s[j].hash.Bytes()) > 0
}

// verify the SignerQueue base on block hash
func (s *Snapshot) verifySignerQueue(signerQueue []common.Address) error {

	if len(signerQueue) > int(s.config.MaxSignerCount) {
		return errInvalidSignerQueue
	}
	sq, err := s.createSignerQueue()
	if err != nil {
		return err
	}
	if len(sq) == 0 || len(sq) != len(signerQueue) {
		return errInvalidSignerQueue
	}
	for i, signer := range signerQueue {
		if signer != sq[i] {
			return errInvalidSignerQueue
		}
	}

	return nil
}

func (s *Snapshot) buildTallySlice() TallySlice {
	var tallySlice TallySlice
	for address, stake := range s.Tally {
		if !candidateNeedPD || s.isCandidate(address) {
			if _, ok := s.Punished[address]; ok {
				var creditWeight uint64
				if s.Punished[address] > defaultFullCredit-minCalSignerQueueCredit {
					creditWeight = minCalSignerQueueCredit
				} else {
					creditWeight = defaultFullCredit - s.Punished[address]
				}
				tallySlice = append(tallySlice, TallyItem{address, new(big.Int).Mul(stake, big.NewInt(int64(creditWeight)))})
			} else {
				tallySlice = append(tallySlice, TallyItem{address, new(big.Int).Mul(stake, big.NewInt(defaultFullCredit))})
			}
		}
	}
	return tallySlice
}

func (s *Snapshot) buildTallyMiner() TallySlice {
	var tallySlice TallySlice
	for address, stake := range s.TallyMiner {
		if pledge, ok := s.CandidatePledge[address]; !ok || 0 < pledge.StartHigh {
			continue
		}
		if _, ok := s.Punished[address]; ok {
			var creditWeight uint64
			if s.Punished[address] > defaultFullCredit-minCalSignerQueueCredit {
				creditWeight = minCalSignerQueueCredit
			} else {
				creditWeight = defaultFullCredit - s.Punished[address]
			}
			tallySlice = append(tallySlice, TallyItem{address, new(big.Int).Mul(stake.Stake, big.NewInt(int64(creditWeight)))})
		} else {
			tallySlice = append(tallySlice, TallyItem{address, new(big.Int).Mul(stake.Stake, big.NewInt(defaultFullCredit))})
		}
	}
	return tallySlice
}

func (s *Snapshot) rebuildTallyMiner(miners TallySlice) TallySlice {
	var tallySlice TallySlice
	for _, item := range miners {
		if status, ok := s.TallyMiner[item.addr]; ok {
			tallySlice = append(tallySlice, TallyItem{item.addr, new(big.Int).Div(item.stake, big.NewInt(int64(status.SignerNumber + 1)))})
		}
	}
	sort.Sort(tallySlice)
	return tallySlice
}

func (s *Snapshot) createSignerQueue() ([]common.Address, error) {

	if (s.Number+1)%s.config.MaxSignerCount != 0 || s.Hash != s.HistoryHash[len(s.HistoryHash)-1] {
		return nil, errCreateSignerQueueNotAllowed
	}

	var signerSlice SignerSlice
	var topStakeAddress []common.Address

	if (s.Number+1)%(s.config.MaxSignerCount*s.LCRS) == 0 {
		// before recalculate the signers, clear the candidate is not in snap.Candidates

		// only recalculate signers from to tally per 10 loop,
		// other loop end just reset the order of signers by block hash (nearly random)
		tallySlice := s.buildTallySlice()
		sort.Sort(TallySlice(tallySlice))
		tallyMiner := s.buildTallyMiner()
		sort.Sort(TallySlice(tallyMiner))
		queueLength := int(s.config.MaxSignerCount)
		if queueLength >= defaultOfficialMaxSignerCount {
			mainNumber := (9 * queueLength + defaultOfficialMaxSignerCount - 1) / defaultOfficialMaxSignerCount
			minerNumber := 12 * queueLength / defaultOfficialMaxSignerCount
			if minerNumber > len(tallyMiner) {
				minerNumber = len(tallyMiner)
				mainNumber = queueLength - minerNumber
				for i, tallyItem := range tallyMiner {
					signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i]})
					tallyItem.stake = new(big.Int).Add(tallyItem.stake, big.NewInt(1))
				}
			} else {
				mainNumber = queueLength - minerNumber
				needMiner := (9 * minerNumber + 3) / 4
				if needMiner > len(tallyMiner) {
					tallyMiner = s.rebuildTallyMiner (tallyMiner)
					for i, tallyItem := range tallyMiner[:minerNumber] {
						signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i]})
						tallyItem.stake = new(big.Int).Add(tallyItem.stake, big.NewInt(1))
					}
				} else {
					var LevelSlice TallySlice
					index := int(0)
					firstNumber := minerNumber / 2
					firstTotal := 2 * len(tallyMiner) / 9
					for _, tallyItem := range tallyMiner[:firstTotal] {
						LevelSlice = append(LevelSlice, TallyItem{tallyItem.addr, tallyItem.stake})
					}
					LevelSlice = s.rebuildTallyMiner(LevelSlice)
					for i, tallyItem := range LevelSlice[:firstNumber] {
						signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i-index]})
						tallyItem.stake = new(big.Int).Add(tallyItem.stake, big.NewInt(1))
					}
					index += firstNumber
					secondNumber := minerNumber / 3
					secondTotal := 5 * len(tallyMiner) / 9
					for _, tallyItem := range tallyMiner[firstTotal:secondTotal] {
						LevelSlice = append(LevelSlice, TallyItem{tallyItem.addr, tallyItem.stake})
					}
					LevelSlice = s.rebuildTallyMiner(LevelSlice)
					for i, tallyItem := range LevelSlice[:secondNumber] {
						signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i-index]})
						tallyItem.stake = new(big.Int).Add(tallyItem.stake, big.NewInt(1))
					}
					index += secondNumber
					lastNumber := minerNumber - index
					for _, tallyItem := range tallyMiner[secondTotal:] {
						LevelSlice = append(LevelSlice, TallyItem{tallyItem.addr, tallyItem.stake})
					}
					LevelSlice = s.rebuildTallyMiner(LevelSlice)
					for i, tallyItem := range LevelSlice[:lastNumber] {
						signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i-index]})
						tallyItem.stake = new(big.Int).Add(tallyItem.stake, big.NewInt(1))
					}
				}
			}
			levelTotal := (10 * mainNumber + 6) / 7
			if mainNumber > len(tallySlice) {
				mainSigner := len(tallySlice)
				for i := 0; i < mainNumber; i++ {
					signerSlice = append(signerSlice, SignerItem{tallySlice[i % mainSigner].addr, s.HistoryHash[len(s.HistoryHash)-1-i-minerNumber]})
				}
			} else if levelTotal >= len(tallySlice) || 21 > mainNumber {
				for i := 0; i < mainNumber; i++ {
					signerSlice = append(signerSlice, SignerItem{tallySlice[i].addr, s.HistoryHash[len(s.HistoryHash)-1-i-minerNumber]})
				}
			} else {
				index := minerNumber
				levelNumber := levelTotal / 3
				firstLevelNumber := levelTotal - 2 * levelNumber
				secondLevelNumber := (16 * mainNumber + 11) / 21 - firstLevelNumber
				secondLevelTotal := firstLevelNumber + levelNumber
				thirdLevelNumber := (20 * mainNumber + 11) / 21 - firstLevelNumber - secondLevelNumber
				lastLevelNumber := mainNumber - firstLevelNumber - secondLevelNumber - thirdLevelNumber
				for i, tallyItem := range tallySlice[:firstLevelNumber] {
					signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i-index]})
				}
				index += firstLevelNumber
				var signerSecondLevelSlice, signerThirdLevelSlice, signerLastLevelSlice SignerSlice
				// 60%
				for i, tallyItem := range tallySlice[firstLevelNumber:secondLevelTotal] {
					signerSecondLevelSlice = append(signerSecondLevelSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i-index]})
				}
				sort.Sort(SignerSlice(signerSecondLevelSlice))
				signerSlice = append(signerSlice, signerSecondLevelSlice[:secondLevelNumber]...)
				index += secondLevelNumber
				// 40%
				for i, tallyItem := range tallySlice[secondLevelTotal:levelTotal] {
					signerThirdLevelSlice = append(signerThirdLevelSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i-index]})
				}
				sort.Sort(SignerSlice(signerThirdLevelSlice))
				signerSlice = append(signerSlice, signerThirdLevelSlice[:thirdLevelNumber]...)
				index += thirdLevelNumber
				// choose 1 from last
				maxValidCount := queueLength
				if maxValidCount > len(tallySlice) {
					maxValidCount = len(tallySlice)
				}
				for i, tallyItem := range tallySlice[levelTotal:maxValidCount] {
					signerLastLevelSlice = append(signerLastLevelSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i-index]})
				}
				sort.Sort(SignerSlice(signerLastLevelSlice))
				signerSlice = append(signerSlice, signerLastLevelSlice[:lastLevelNumber]...)
			}
		} else {
			if queueLength > len(tallySlice) {
				queueLength = len(tallySlice)
			}
			for i, tallyItem := range tallySlice[:queueLength] {
				signerSlice = append(signerSlice, SignerItem{tallyItem.addr, s.HistoryHash[len(s.HistoryHash)-1-i]})
			}
		}
	} else {
		for i, signer := range s.Signers {
			signerSlice = append(signerSlice, SignerItem{*signer, s.HistoryHash[len(s.HistoryHash)-1-i]})
		}
	}
	sort.Sort(SignerSlice(signerSlice))
	// Set the top candidates in random order base on block hash
	if len(signerSlice) == 0 {
		return nil, errSignerQueueEmpty
	}
	for i := 0; i < int(s.config.MaxSignerCount); i++ {
		topStakeAddress = append(topStakeAddress, signerSlice[i%len(signerSlice)].addr)
	}

	return topStakeAddress, nil
}
