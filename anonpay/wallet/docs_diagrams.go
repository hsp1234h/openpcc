// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

// The sequence diagrams below give an overview of how the Paid API, User, Wallet and Pipeline
// all work together to facilitate payments.
//
// First begin a payment:
//
//                                       User           Wallet w            Pipeline
//
//                                        │                │                    │
//                                        │ w.BeginPayment │                    │
//                                        ├────────────────►                    │
//                                        │                │ create new payment │
//                                        │                │ request req        │
//                                        │                │                    │
//                                        │                │ w.requests <- req  │
//                                        │                ├────────────────────►
//                                        │                │                    │
//                                        │                │                    ├───┐
//                                        │         p.WaitForResponse           │   │ Receive bank batch b
//                                        │                │                    ◄───┘
//                                        │                │                    │
//                                        │                │                    ├───┐
//                                        │                │                    │   │ Transfer credit c
//                                        │                │                    ◄───┘ from b to req
//                                        │                │     on deposit:    │
//                                        │                │  req.response <- c │
//                                        │      payment p ◄────────────────────┤
//                                        ◄────────────────┤                    │
//                                        │                │
//
//
//  Then, do a successful request with the returned credit:
//
//                       Paid API       User            Wallet w             Pipeline
//
//                       │                │                │                    │
//                       │                ├───┐            │                    │
//                       │                │   │ p.Credit   │                    │
//                       │                ◄───┘            │                    │
//                       │ request with c │                │                    │
//                       ◄────────────────┤                │                    │
//                       │                │                │                    │
//                   ┌───┤                │                │                    │
// calculate unspend │   │                │                │                    │
//         credit uc └───►                │                │                    │
//                       │ unspend uc     │                │                    │
//                       ├────────────────►                │                    │
//                       │                │ p.Success(uc)  │                    │
//                                        ├────────────────►                    │
//                                        │                │ create new payment │
//                                        │                │ result res for uc  │
//                                        │                │                    │
//                                        │                │ w.results <- res   │
//                                        │                ┼────────────────────►
//                                        ◄────────────────┤                    │
//                                        │                │                    ├───┐
//                                                                              │   │ Create or reuse
//                                                                              ◄───┘ consolidation account a
//                                                                              │
//                                                                              ├───┐
//                                                                              │   │ Tranfer credit uc
//                                                                              ◄───┘ from res to a
//                                                                              │
//                                                                              │     on withdraw from res:
//                                                                              │     uc will be exchanged via blindbank
//
// Or, cancel the payment (if the request fails for example):
//
//                       Paid API       User            Wallet w             Pipeline
//
//                       │                │                │                    │
//                       │                ├───┐            │                    │
//                       │                │   │ p.Credit   │                    │
//                       │                ◄───┘            │                    │
//                       │ request with c │                │                    │
//                       ◄────────X───────┤                │                    │
//                       │      fails     │ p.Cancel       │                    │
//                                        ├────────────────►                    │
//                                        │                  create new payment │
//                                        │                  result res for c   │
//                                        │                                     │
//                                        │                │ w.results <- res   │
//                                        │                ├────────────────────►
//                                        ◄────────────────┤                    │
//                                        │                │                    ├───┐
//                                                                              │   │ Create or reuse
//                                                                              ◄───┘ consolidation account a
//                                                                              │
//                                                                              ├───┐
//                                                                              │   │ Tranfer credit c
//                                                                              ◄───┘ from
//                                                                              │
//                                                                              │     before withdraw from res:
//                                                                              │     c will be exchanged via blindbank
