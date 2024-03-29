/**
 * Copyright (c) woodser
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Parts of this file are originally copyright (c) 2014-2019, The Monero Project
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * All rights reserved.
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
 */

#pragma once

#ifndef monero_utils_h
#define monero_utils_h

#include "wallet/monero_wallet_model.h"
#include "wallet/wallet_rpc_server_commands_defs.h"
#include "wallet/wallet_errors.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "serialization/keyvalue_serialization.h" // TODO: consolidate with other binary deps?
#include "storages/portable_storage.h"
#include "wallet/wallet2.h"

/**
 * Collection of utilities for the Monero library.
 */
namespace monero_utils
{
  using namespace cryptonote;

  // ------------------------------ CONSTANTS ---------------------------------

  static const int RING_SIZE = 12;  // network-enforced ring size

  // -------------------------------- UTILS -----------------------------------

  struct key_image_list
  {
    std::list<std::string> key_images;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(key_images)
    END_KV_SERIALIZE_MAP()
  };
  
// ----------------------- INTERNAL PRIVATE HELPERS -----------------------

/**
 * Remove query criteria which require looking up other transfers/outputs to
 * fulfill query.
 *
 * @param query the query to decontextualize
 * @return a reference to the query for convenience
 */
std::shared_ptr<monero_tx_query> decontextualize(std::shared_ptr<monero_tx_query> query) {
  query->m_is_incoming = boost::none;
  query->m_is_outgoing = boost::none;
  query->m_transfer_query = boost::none;
  query->m_input_query = boost::none;
  query->m_output_query = boost::none;
  return query;
}

bool is_contextual(const monero_transfer_query& query) {
  if (query.m_tx_query == boost::none) return false;
  if (query.m_tx_query.get()->m_is_incoming != boost::none) return true;    // requires context of all transfers
  if (query.m_tx_query.get()->m_is_outgoing != boost::none) return true;
  if (query.m_tx_query.get()->m_input_query != boost::none) return true;    // requires context of inputs
  if (query.m_tx_query.get()->m_output_query != boost::none) return true;   // requires context of outputs
  return false;
}

bool is_contextual(const monero_output_query& query) {
  if (query.m_tx_query == boost::none) return false;
  if (query.m_tx_query.get()->m_is_incoming != boost::none) return true;    // requires context of all transfers
  if (query.m_tx_query.get()->m_is_outgoing != boost::none) return true;
  if (query.m_tx_query.get()->m_transfer_query != boost::none) return true; // requires context of transfers
  return false;
}

bool bool_equals(bool val, const boost::optional<bool>& opt_val) {
  return opt_val == boost::none ? false : val == *opt_val;
}

// compute m_num_confirmations TODO monero-project: this logic is based on wallet_rpc_server.cpp `set_confirmations` but it should be encapsulated in wallet2
void set_num_confirmations(std::shared_ptr<monero_tx_wallet>& tx, uint64_t blockchain_height) {
  std::shared_ptr<monero_block>& block = tx->m_block.get();
  if (block->m_height.get() >= blockchain_height || (block->m_height.get() == 0 && !tx->m_in_tx_pool.get())) tx->m_num_confirmations = 0;
  else tx->m_num_confirmations = blockchain_height - block->m_height.get();
}

// compute m_num_suggested_confirmations  TODO monero-project: this logic is based on wallet_rpc_server.cpp `set_confirmations` but it should be encapsulated in wallet2
void set_num_suggested_confirmations(std::shared_ptr<monero_incoming_transfer>& incoming_transfer, uint64_t blockchain_height, uint64_t block_reward, uint64_t unlock_time) {
  if (block_reward == 0) incoming_transfer->m_num_suggested_confirmations = 0;
  else incoming_transfer->m_num_suggested_confirmations = (incoming_transfer->m_amount.get() + block_reward - 1) / block_reward;
  if (unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER) {
    if (unlock_time > blockchain_height) incoming_transfer->m_num_suggested_confirmations = std::max(incoming_transfer->m_num_suggested_confirmations.get(), unlock_time - blockchain_height);
  } else {
    const uint64_t now = time(NULL);
    if (unlock_time > now) incoming_transfer->m_num_suggested_confirmations = std::max(incoming_transfer->m_num_suggested_confirmations.get(), (unlock_time - now + DIFFICULTY_TARGET_V2 - 1) / DIFFICULTY_TARGET_V2);
  }
}

std::shared_ptr<monero_tx_wallet> build_tx_with_incoming_transfer(tools::wallet2& m_w2, uint64_t height, const crypto::hash &payment_id, const tools::wallet2::payment_details &pd) {

  // construct block
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_height = pd.m_block_height;
  block->m_timestamp = pd.m_timestamp;

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_block = block;
  block->m_txs.push_back(tx);
  tx->m_hash = epee::string_tools::pod_to_hex(pd.m_tx_hash);
  tx->m_is_incoming = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_unlock_time;
  tx->m_is_locked = !m_w2.is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height);
  tx->m_fee = pd.m_fee;
  tx->m_note = m_w2.get_tx_note(pd.m_tx_hash);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = pd.m_coinbase ? true : false;
  tx->m_is_confirmed = true;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = false;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = false;
  set_num_confirmations(tx, height);

  // construct transfer
  std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();
  incoming_transfer->m_tx = tx;
  tx->m_incoming_transfers.push_back(incoming_transfer);
  incoming_transfer->m_amount = pd.m_amount;
  incoming_transfer->m_account_index = pd.m_subaddr_index.major;
  incoming_transfer->m_subaddress_index = pd.m_subaddr_index.minor;
  incoming_transfer->m_address = m_w2.get_subaddress_as_str(pd.m_subaddr_index);
  set_num_suggested_confirmations(incoming_transfer, height, m_w2.get_last_block_reward(), pd.m_unlock_time);

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> build_tx_with_outgoing_transfer(tools::wallet2& m_w2, uint64_t height, const crypto::hash &txid, const tools::wallet2::confirmed_transfer_details &pd) {

  // construct block
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_height = pd.m_block_height;
  block->m_timestamp = pd.m_timestamp;

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_block = block;
  block->m_txs.push_back(tx);
  tx->m_hash = epee::string_tools::pod_to_hex(txid);
  tx->m_is_outgoing = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(pd.m_payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_unlock_time;
  tx->m_is_locked = !m_w2.is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height);
  tx->m_fee = pd.m_amount_in - pd.m_amount_out;
  tx->m_note = m_w2.get_tx_note(txid);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = false;
  tx->m_is_confirmed = true;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = false;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = false;
  set_num_confirmations(tx, height);

  // construct transfer
  std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
  outgoing_transfer->m_tx = tx;
  tx->m_outgoing_transfer = outgoing_transfer;
  uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change; // change may not be known
  outgoing_transfer->m_amount = pd.m_amount_in - change - *tx->m_fee;
  outgoing_transfer->m_account_index = pd.m_subaddr_account;
  std::vector<uint32_t> subaddress_indices;
  std::vector<std::string> addresses;
  for (uint32_t i: pd.m_subaddr_indices) {
    subaddress_indices.push_back(i);
    addresses.push_back(m_w2.get_subaddress_as_str({pd.m_subaddr_account, i}));
  }
  outgoing_transfer->m_subaddress_indices = subaddress_indices;
  outgoing_transfer->m_addresses = addresses;

  // initialize destinations
  for (const auto &d: pd.m_dests) {
    std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
    destination->m_amount = d.amount;
    destination->m_address = d.address(m_w2.nettype(), pd.m_payment_id);
    outgoing_transfer->m_destinations.push_back(destination);
  }

  // replace transfer amount with destination sum
  // TODO monero-project: confirmed tx from/to same account has amount 0 but cached transfer destinations
  if (*outgoing_transfer->m_amount == 0 && !outgoing_transfer->m_destinations.empty()) {
    uint64_t amount = 0;
    for (const std::shared_ptr<monero_destination>& destination : outgoing_transfer->m_destinations) amount += *destination->m_amount;
    outgoing_transfer->m_amount = amount;
  }

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> build_tx_with_incoming_transfer_unconfirmed(const tools::wallet2& m_w2, uint64_t height, const crypto::hash &payment_id, const tools::wallet2::pool_payment_details &ppd) {

  // construct tx
  const tools::wallet2::payment_details &pd = ppd.m_pd;
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_hash = epee::string_tools::pod_to_hex(pd.m_tx_hash);
  tx->m_is_incoming = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_unlock_time;
  tx->m_is_locked = true;
  tx->m_fee = pd.m_fee;
  tx->m_note = m_w2.get_tx_note(pd.m_tx_hash);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = false;
  tx->m_is_confirmed = false;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = true;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = ppd.m_double_spend_seen;
  tx->m_num_confirmations = 0;

  // construct transfer
  std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();
  incoming_transfer->m_tx = tx;
  tx->m_incoming_transfers.push_back(incoming_transfer);
  incoming_transfer->m_amount = pd.m_amount;
  incoming_transfer->m_account_index = pd.m_subaddr_index.major;
  incoming_transfer->m_subaddress_index = pd.m_subaddr_index.minor;
  incoming_transfer->m_address = m_w2.get_subaddress_as_str(pd.m_subaddr_index);
  set_num_suggested_confirmations(incoming_transfer, height, m_w2.get_last_block_reward(), pd.m_unlock_time);

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> build_tx_with_outgoing_transfer_unconfirmed(const tools::wallet2& m_w2, const crypto::hash &txid, const tools::wallet2::unconfirmed_transfer_details &pd) {

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_details::failed;
  tx->m_hash = epee::string_tools::pod_to_hex(txid);
  tx->m_is_outgoing = true;
  tx->m_payment_id = epee::string_tools::pod_to_hex(pd.m_payment_id);
  if (tx->m_payment_id->substr(16).find_first_not_of('0') == std::string::npos) tx->m_payment_id = tx->m_payment_id->substr(0, 16);  // TODO monero-project: this should be part of core wallet
  if (tx->m_payment_id == monero_tx::DEFAULT_PAYMENT_ID) tx->m_payment_id = boost::none;  // clear default payment id
  tx->m_unlock_time = pd.m_tx.unlock_time;
  tx->m_is_locked = true;
  tx->m_fee = pd.m_amount_in - pd.m_amount_out;
  tx->m_note = m_w2.get_tx_note(txid);
  if (tx->m_note->empty()) tx->m_note = boost::none; // clear empty note
  tx->m_is_miner_tx = false;
  tx->m_is_confirmed = false;
  tx->m_is_relayed = !tx->m_is_failed.get();
  tx->m_in_tx_pool = !tx->m_is_failed.get();
  tx->m_relay = true;
  if (!tx->m_is_failed.get() && tx->m_is_relayed.get()) tx->m_is_double_spend_seen = false;  // TODO: test and handle if true
  tx->m_num_confirmations = 0;

  // construct transfer
  std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
  outgoing_transfer->m_tx = tx;
  tx->m_outgoing_transfer = outgoing_transfer;
  outgoing_transfer->m_amount = pd.m_amount_in - pd.m_change - tx->m_fee.get();
  outgoing_transfer->m_account_index = pd.m_subaddr_account;
  std::vector<uint32_t> subaddress_indices;
  std::vector<std::string> addresses;
  for (uint32_t i: pd.m_subaddr_indices) {
    subaddress_indices.push_back(i);
    addresses.push_back(m_w2.get_subaddress_as_str({pd.m_subaddr_account, i}));
  }
  outgoing_transfer->m_subaddress_indices = subaddress_indices;
  outgoing_transfer->m_addresses = addresses;

  // initialize destinations
  for (const auto &d: pd.m_dests) {
    std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
    destination->m_amount = d.amount;
    destination->m_address = d.address(m_w2.nettype(), pd.m_payment_id);
    outgoing_transfer->m_destinations.push_back(destination);
  }

  // replace transfer amount with destination sum
  // TODO monero-project: confirmed tx from/to same account has amount 0 but cached transfer destinations
  if (*outgoing_transfer->m_amount == 0 && !outgoing_transfer->m_destinations.empty()) {
    uint64_t amount = 0;
    for (const std::shared_ptr<monero_destination>& destination : outgoing_transfer->m_destinations) amount += *destination->m_amount;
    outgoing_transfer->m_amount = amount;
  }

  // return pointer to new tx
  return tx;
}

std::shared_ptr<monero_tx_wallet> build_tx_with_vout(tools::wallet2& m_w2, const tools::wallet2::transfer_details& td) {

  // construct block
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_height = td.m_block_height;

  // construct tx
  std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
  tx->m_block = block;
  block->m_txs.push_back(tx);
  tx->m_hash = epee::string_tools::pod_to_hex(td.m_txid);
  tx->m_is_confirmed = true;
  tx->m_is_failed = false;
  tx->m_is_relayed = true;
  tx->m_in_tx_pool = false;
  tx->m_relay = true;
  tx->m_is_double_spend_seen = false;
  tx->m_is_locked = !m_w2.is_transfer_unlocked(td);

  // construct output
  std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
  output->m_tx = tx;
  tx->m_outputs.push_back(output);
  output->m_amount = td.amount();
  output->m_index = td.m_global_output_index;
  output->m_account_index = td.m_subaddr_index.major;
  output->m_subaddress_index = td.m_subaddr_index.minor;
  output->m_is_spent = td.m_spent;
  output->m_is_frozen = td.m_frozen;
  output->m_stealth_public_key = epee::string_tools::pod_to_hex(td.get_public_key());
  if (td.m_key_image_known) {
    output->m_key_image = std::make_shared<monero_key_image>();
    output->m_key_image.get()->m_hex = epee::string_tools::pod_to_hex(td.m_key_image);
  }

  // return pointer to new tx
  return tx;
}

/**
 * Merges a transaction into a unique set of transactions.
 *
 * @param tx is the transaction to merge into the existing txs
 * @param tx_map maps tx hashes to txs
 * @param block_map maps block heights to blocks
 */
void merge_tx(const std::shared_ptr<monero_tx_wallet>& tx, std::map<std::string, std::shared_ptr<monero_tx_wallet>>& tx_map, std::map<uint64_t, std::shared_ptr<monero_block>>& block_map) {
  if (tx->m_hash == boost::none) throw std::runtime_error("Tx hash is not initialized");

  // merge tx
  std::map<std::string, std::shared_ptr<monero_tx_wallet>>::const_iterator tx_iter = tx_map.find(*tx->m_hash);
  if (tx_iter == tx_map.end()) {
    tx_map[*tx->m_hash] = tx; // cache new tx
  } else {
    std::shared_ptr<monero_tx_wallet>& a_tx = tx_map[*tx->m_hash];
    a_tx->merge(a_tx, tx); // merge with existing tx
  }

  // merge tx's block if confirmed
  if (tx->get_height() != boost::none) {
    std::map<uint64_t, std::shared_ptr<monero_block>>::const_iterator block_iter = block_map.find(tx->get_height().get());
    if (block_iter == block_map.end()) {
      block_map[tx->get_height().get()] = tx->m_block.get(); // cache new block
    } else {
      std::shared_ptr<monero_block>& a_block = block_map[tx->get_height().get()];
      a_block->merge(a_block, tx->m_block.get()); // merge with existing block
    }
  }
}

/**
 * Returns true iff tx1's height is known to be less than tx2's height for sorting.
 */
bool tx_height_less_than(const std::shared_ptr<monero_tx>& tx1, const std::shared_ptr<monero_tx>& tx2) {
  if (tx1->m_block != boost::none && tx2->m_block != boost::none) return tx1->get_height() < tx2->get_height();
  else if (tx1->m_block == boost::none) return false;
  else return true;
}

/**
 * Returns true iff transfer1 is ordered before transfer2 by ascending account and subaddress indices.
 */
bool incoming_transfer_before(const std::shared_ptr<monero_incoming_transfer>& transfer1, const std::shared_ptr<monero_incoming_transfer>& transfer2) {

  // compare by height
  if (tx_height_less_than(transfer1->m_tx, transfer2->m_tx)) return true;

  // compare by account and subaddress index
  if (transfer1->m_account_index.get() < transfer2->m_account_index.get()) return true;
  else if (transfer1->m_account_index.get() == transfer2->m_account_index.get()) return transfer1->m_subaddress_index.get() < transfer2->m_subaddress_index.get();
  else return false;
}

/**
 * Returns true iff wallet vout1 is ordered before vout2 by ascending account and subaddress indices then index.
 */
bool vout_before(const std::shared_ptr<monero_output>& o1, const std::shared_ptr<monero_output>& o2) {
  if (o1 == o2) return false; // ignore equal references
  std::shared_ptr<monero_output_wallet> ow1 = std::static_pointer_cast<monero_output_wallet>(o1);
  std::shared_ptr<monero_output_wallet> ow2 = std::static_pointer_cast<monero_output_wallet>(o2);

  // compare by height
  if (tx_height_less_than(ow1->m_tx, ow2->m_tx)) return true;

  // compare by account index, subaddress index, output index, then key image hex
  if (ow1->m_account_index.get() < ow2->m_account_index.get()) return true;
  if (ow1->m_account_index.get() == ow2->m_account_index.get()) {
    if (ow1->m_subaddress_index.get() < ow2->m_subaddress_index.get()) return true;
    if (ow1->m_subaddress_index.get() == ow2->m_subaddress_index.get()) {
      if (ow1->m_index.get() < ow2->m_index.get()) return true;
      if (ow1->m_index.get() == ow2->m_index.get()) throw std::runtime_error("Should never sort outputs with duplicate indices");
    }
  }
  return false;
}

std::string get_default_ringdb_path(cryptonote::network_type nettype)
{
  boost::filesystem::path dir = tools::get_default_data_dir();
  // remove .bitmonero, replace with .shared-ringdb
  dir = dir.remove_filename();
  dir /= ".shared-ringdb";
  if (nettype == cryptonote::TESTNET)
    dir /= "testnet";
  else if (nettype == cryptonote::STAGENET)
    dir /= "stagenet";
  return dir.string();
}

/**
 * ---------------- DUPLICATED WALLET RPC TRANSFER CODE ---------------------
 *
 * These functions are duplicated from private functions in wallet rpc
 * on_transfer/on_transfer_split, with minor modifications to not be class members.
 *
 * This code is used to generate and send transactions with equivalent functionality as
 * wallet rpc.
 *
 * Duplicated code is not ideal.  Solutions considered:
 *
 * (1) Duplicate wallet rpc code as done here.
 * (2) Modify monero-wallet-rpc on_transfer() / on_transfer_split() to be public.
 * (3) Modify monero-wallet-rpc to make this class a friend.
 * (4) Move all logic in monero-wallet-rpc to wallet2 so all users can access.
 *
 * Options 2-4 require modification of monero-project C++.  Of those, (4) is probably ideal.
 * TODO: open patch on monero-project which moves common wallet rpc logic (e.g. on_transfer, on_transfer_split) to m_w2.
 *
 * Until then, option (1) is used because it allows monero-project binaries to be used without modification, it's easy, and
 * anything other than (4) is temporary.
 */
//------------------------------------------------------------------------------------------------------------------------------
bool validate_transfer(tools::wallet2* m_w2, const std::list<tools::wallet_rpc::transfer_destination>& destinations, const std::string& payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, bool at_least_one_destination, epee::json_rpc::error& er)
{
  crypto::hash8 integrated_payment_id = crypto::null_hash8;
  std::string extra_nonce;
  for (auto it = destinations.begin(); it != destinations.end(); it++)
  {
    cryptonote::address_parse_info info;
    cryptonote::tx_destination_entry de;
    er.message = "";
    if(!get_account_address_from_str_or_url(info, m_w2->nettype(), it->address,
      [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
        if (!dnssec_valid)
        {
          er.message = std::string("Invalid DNSSEC for ") + url;
          return {};
        }
        if (addresses.empty())
        {
          er.message = std::string("No Monero address found at ") + url;
          return {};
        }
        return addresses[0];
      }))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
      if (er.message.empty())
        er.message = std::string("Invalid destination address");
      return false;
    }

    de.original = it->address;
    de.addr = info.address;
    de.is_subaddress = info.is_subaddress;
    de.amount = it->amount;
    de.is_integrated = info.has_payment_id;
    dsts.push_back(de);

    if (info.has_payment_id)
    {
      if (!payment_id.empty() || integrated_payment_id != crypto::null_hash8)
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "A single payment id is allowed per transaction";
        return false;
      }
      integrated_payment_id = info.payment_id;
      cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, integrated_payment_id);

      /* Append Payment ID data into extra */
      if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Something went wrong with integrated payment_id.";
        return false;
      }
    }
  }

  if (at_least_one_destination && dsts.empty())
  {
    er.code = WALLET_RPC_ERROR_CODE_ZERO_DESTINATION;
    er.message = "No destinations for this transfer";
    return false;
  }

  if (!payment_id.empty())
  {
    er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
    er.message = "Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead";
    return false;
  }
  return true;
}
//------------------------------------------------------------------------------------------------------------------------------
static std::string ptx_to_string(const tools::wallet2::pending_tx &ptx)
{
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  try
  {
    ar << ptx;
  }
  catch (...)
  {
    return "";
  }
  return epee::string_tools::buff_to_hex_nodelimer(oss.str());
}
//------------------------------------------------------------------------------------------------------------------------------
template<typename T> bool is_error_value(const T &val) { return false; }
bool is_error_value(const std::string &s) { return s.empty(); }
//------------------------------------------------------------------------------------------------------------------------------
template<typename T, typename V>
static bool fill(T &where, V s)
{
  if (is_error_value(s)) return false;
  where = std::move(s);
  return true;
}
//------------------------------------------------------------------------------------------------------------------------------
template<typename T, typename V>
static bool fill(std::list<T> &where, V s)
{
  if (is_error_value(s)) return false;
  where.emplace_back(std::move(s));
  return true;
}
//------------------------------------------------------------------------------------------------------------------------------
static uint64_t total_amount(const tools::wallet2::pending_tx &ptx)
{
  uint64_t amount = 0;
  for (const auto &dest: ptx.dests) amount += dest.amount;
  return amount;
}
//------------------------------------------------------------------------------------------------------------------------------
template<typename Ts, typename Tu, typename Tk, typename Ta>
static bool fill_response(tools::wallet2* m_w2, std::vector<tools::wallet2::pending_tx> &ptx_vector,
    bool get_tx_key, Ts& tx_key, Tu &amount, Ta &amounts_by_dest, Tu &fee, Tu &weight, std::string &multisig_txset, std::string &unsigned_txset, bool do_not_relay,
    Ts &tx_hash, bool get_tx_hex, Ts &tx_blob, bool get_tx_metadata, Ts &tx_metadata, Tk &spent_key_images, epee::json_rpc::error &er)
{
  for (const auto & ptx : ptx_vector)
  {
    if (get_tx_key)
    {
      epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
      for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys)
        s += epee::to_hex::wipeable_string(additional_tx_key);
      fill(tx_key, std::string(s.data(), s.size()));
    }
    // Compute amount leaving wallet in tx. By convention dests does not include change outputs
    fill(amount, total_amount(ptx));
    fill(fee, ptx.fee);
    fill(weight, cryptonote::get_transaction_weight(ptx.tx));

    // add amounts by destination
    tools::wallet_rpc::amounts_list abd;
    for (const auto& dst : ptx.dests)
      abd.amounts.push_back(dst.amount);
    fill(amounts_by_dest, abd);

    // add spent key images
    key_image_list key_image_list;
    bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool
    {
      CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
      key_image_list.key_images.push_back(epee::string_tools::pod_to_hex(in.k_image));
      return true;
    });
    THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, tools::error::unexpected_txin_type, ptx.tx);
    fill(spent_key_images, key_image_list);
  }

  if (m_w2->multisig())
  {
    multisig_txset = epee::string_tools::buff_to_hex_nodelimer(m_w2->save_multisig_tx(ptx_vector));
    if (multisig_txset.empty())
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "Failed to save multisig tx set after creation";
      return false;
    }
  }
  else
  {
    if (m_w2->watch_only()){
      unsigned_txset = epee::string_tools::buff_to_hex_nodelimer(m_w2->dump_tx_to_str(ptx_vector));
      if (unsigned_txset.empty())
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Failed to save unsigned tx set after creation";
        return false;
      }
    }
    else if (!do_not_relay)
      m_w2->commit_tx(ptx_vector);

    // populate response with tx hashes
    for (auto & ptx : ptx_vector)
    {
      bool r = fill(tx_hash, epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
      r = r && (!get_tx_hex || fill(tx_blob, epee::string_tools::buff_to_hex_nodelimer(tx_to_blob(ptx.tx))));
      r = r && (!get_tx_metadata || fill(tx_metadata, ptx_to_string(ptx)));
      if (!r)
      {
        er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
        er.message = "Failed to save tx info";
        return false;
      }
    }
  }
  return true;
}

static std::string tx_hex_to_hash(std::string hex) {
  cryptonote::blobdata blob;
  if (!epee::string_tools::parse_hexstr_to_binbuff(hex, blob))
  {
    throw std::runtime_error("Failed to parse hex.");
  }

  bool loaded = false;
  tools::wallet2::pending_tx ptx;

  try
  {
    binary_archive<false> ar{epee::strspan<std::uint8_t>(blob)};
    if (::serialization::serialize(ar, ptx))
      loaded = true;
  }
  catch(...) {}

  if (!loaded)
  {
    try
    {
      std::istringstream iss(blob);
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> ptx;
    }
    catch (...) {
      throw std::runtime_error("Failed to parse tx metadata.");
    }
  }

  return epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
}


  static bool is_uint64_t(const std::string& str) {
    try {
      uint64_t sz;
      std::stol(str, &sz);
      return sz == str.size();
    } 
    catch (const std::invalid_argument&) {
      // if no conversion could be performed.
      return false;   
    } 
    catch (const std::out_of_range&) {
      //  if the converted value would fall out of the range of the result type.
      return false;
    }
  }

  static uint64_t uint64_t_cast(const std::string& str) {
    if (!is_uint64_t(str)) {
      throw std::out_of_range("String provided is not a valid uint64_t");
    }

    uint64_t value;
    
    std::istringstream itr(str);

    itr >> value;

    return value;
  }
  static std::string tx_hex_to_hash(std::string hex);

  void set_log_level(int level);
  void configure_logging(const std::string& path, bool console);
  monero_integrated_address get_integrated_address(monero_network_type network_type, const std::string& standard_address, const std::string& payment_id);
  bool is_valid_address(const std::string& address, monero_network_type network_type);
  bool is_valid_private_view_key(const std::string& private_view_key);
  bool is_valid_private_spend_key(const std::string& private_spend_key);
  bool generate_key_image(const crypto::public_key& account_pub_spend_key, const crypto::secret_key& account_sec_spend_key, const crypto::secret_key& account_sec_view_key, const crypto::public_key& tx_public_key, uint64_t out_index, crypto::key_image &key_image);
  void validate_address(const std::string& address, monero_network_type network_type);
  void validate_private_view_key(const std::string& private_view_key);
  void validate_private_spend_key(const std::string& private_spend_key);
  void json_to_binary(const std::string &json, std::string &bin);
  void binary_to_json(const std::string &bin, std::string &json);
  void binary_blocks_to_json(const std::string &bin, std::string &json);
  template<typename Ts, typename Tu, typename Tk, typename Ta>
  static bool fill_response(tools::wallet2* m_w2, std::vector<tools::wallet2::pending_tx> &ptx_vector,
    bool get_tx_key, Ts& tx_key, Tu &amount, Ta &amounts_by_dest, Tu &fee, Tu &weight, std::string &multisig_txset, std::string &unsigned_txset, bool do_not_relay,
    Ts &tx_hash, bool get_tx_hex, Ts &tx_blob, bool get_tx_metadata, Ts &tx_metadata, Tk &spent_key_images, epee::json_rpc::error &er);

  // ------------------------------ RAPIDJSON ---------------------------------

  std::string serialize(const rapidjson::Document& doc);

  /**
   * Add number, string, and boolean json members using template specialization.
   *
   * TODO: add_json_member("key", "val", ...) treated as integer instead of string literal
   */
  template <class T>
  void add_json_member(std::string key, T val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root, rapidjson::Value& field) {
    rapidjson::Value field_key(key.c_str(), key.size(), allocator);
    field.SetInt64((uint64_t) val);
    root.AddMember(field_key, field, allocator);
  }
  void add_json_member(std::string key, std::string val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root, rapidjson::Value& field);
  void add_json_member(std::string key, bool val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root);

  // TODO: template implementation here, could move to monero_utils.hpp per https://stackoverflow.com/questions/3040480/c-template-function-compiles-in-header-but-not-implementation
  template <class T> rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<std::shared_ptr<T>>& vals) {
    rapidjson::Value value_arr(rapidjson::kArrayType);
    for (const auto& val : vals) {
      value_arr.PushBack(val->to_rapidjson_val(allocator), allocator);
    }
    return value_arr;
  }

  // TODO: template implementation here, could move to monero_utils.hpp per https://stackoverflow.com/questions/3040480/c-template-function-compiles-in-header-but-not-implementation
  template <class T> rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<T>& vals) {
    rapidjson::Value value_arr(rapidjson::kArrayType);
    for (const auto& val : vals) {
      value_arr.PushBack(val.to_rapidjson_val(allocator), allocator);
    }
    return value_arr;
  }

  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<std::string>& strs);
  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint8_t>& nums);
  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint32_t>& nums);
  rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint64_t>& nums);

  // ------------------------ PROPERTY TREES ---------------------------

  // TODO: fully switch from property trees to rapidjson

  std::string serialize(const boost::property_tree::ptree& node);
  void deserialize(const std::string& json, boost::property_tree::ptree& root);

  // --------------------------------------------------------------------------

  /**
   * Indicates if the given language is valid.
   *
   * @param language is the language to validate
   * @return true if the language is valid, false otherwise
   */
  bool is_valid_language(const std::string& language);

  /**
   * Convert a cryptonote::block to a block in this library's native model.
   *
   * @param cn_block is the block to convert
   * @return a block in this library's native model
   */
  std::shared_ptr<monero_block> cn_block_to_block(const cryptonote::block& cn_block);

  /**
   * Convert a cryptonote::transaction to a transaction in this library's
   * native model.
   *
   * @param cn_tx is the transaction to convert
   * @param init_as_tx_wallet specifies if a monero_tx xor monero_tx_wallet should be initialized
   */
  std::shared_ptr<monero_tx> cn_tx_to_tx(const cryptonote::transaction& cn_tx, bool init_as_tx_wallet = false);

  /**
   * Modified from core_rpc_server.cpp to return a std::string.
   *
   * TODO: remove this duplicate, use core_rpc_server instead
   */
  static std::string get_pruned_tx_json(cryptonote::transaction &tx)
  {
    std::stringstream ss;
    json_archive<true> ar(ss);
    bool r = tx.serialize_base(ar);
    CHECK_AND_ASSERT_MES(r, std::string(), "Failed to serialize rct signatures base");
    return ss.str();
  }

  // ----------------------------- GATHER BLOCKS ------------------------------

  static std::vector<std::shared_ptr<monero_block>> get_blocks_from_txs(std::vector<std::shared_ptr<monero_tx_wallet>> txs) {
    std::shared_ptr<monero_block> unconfirmed_block = nullptr; // placeholder for unconfirmed txs
    std::vector<std::shared_ptr<monero_block>> blocks;
    std::unordered_set<std::shared_ptr<monero_block>> seen_block_ptrs;
    for (const std::shared_ptr<monero_tx_wallet>& tx : txs) {
      if (tx->m_block == boost::none) {
        if (unconfirmed_block == nullptr) unconfirmed_block = std::make_shared<monero_block>();
        tx->m_block = unconfirmed_block;
        unconfirmed_block->m_txs.push_back(tx);
      }
      std::unordered_set<std::shared_ptr<monero_block>>::const_iterator got = seen_block_ptrs.find(tx->m_block.get());
      if (got == seen_block_ptrs.end()) {
        seen_block_ptrs.insert(tx->m_block.get());
        blocks.push_back(tx->m_block.get());
      }
    }
    return blocks;
  }

  static std::vector<std::shared_ptr<monero_block>> get_blocks_from_transfers(std::vector<std::shared_ptr<monero_transfer>> transfers) {
    std::shared_ptr<monero_block> unconfirmed_block = nullptr; // placeholder for unconfirmed txs in return json
    std::vector<std::shared_ptr<monero_block>> blocks;
    std::unordered_set<std::shared_ptr<monero_block>> seen_block_ptrs;
    for (auto const& transfer : transfers) {
      std::shared_ptr<monero_tx_wallet> tx = transfer->m_tx;
      if (tx->m_block == boost::none) {
        if (unconfirmed_block == nullptr) unconfirmed_block = std::make_shared<monero_block>();
        tx->m_block = unconfirmed_block;
        unconfirmed_block->m_txs.push_back(tx);
      }
      std::unordered_set<std::shared_ptr<monero_block>>::const_iterator got = seen_block_ptrs.find(tx->m_block.get());
      if (got == seen_block_ptrs.end()) {
        seen_block_ptrs.insert(tx->m_block.get());
        blocks.push_back(tx->m_block.get());
      }
    }
    return blocks;
  }

  static std::vector<std::shared_ptr<monero_block>> get_blocks_from_outputs(std::vector<std::shared_ptr<monero_output_wallet>> outputs) {
    std::vector<std::shared_ptr<monero_block>> blocks;
    std::unordered_set<std::shared_ptr<monero_block>> seen_block_ptrs;
    for (auto const& output : outputs) {
      std::shared_ptr<monero_tx_wallet> tx = std::static_pointer_cast<monero_tx_wallet>(output->m_tx);
      if (tx->m_block == boost::none) throw std::runtime_error("Need to handle unconfirmed output");
      std::unordered_set<std::shared_ptr<monero_block>>::const_iterator got = seen_block_ptrs.find(*tx->m_block);
      if (got == seen_block_ptrs.end()) {
        seen_block_ptrs.insert(*tx->m_block);
        blocks.push_back(*tx->m_block);
      }
    }
    return blocks;
  }

  // ------------------------------ FREE MEMORY -------------------------------

  static void free(std::shared_ptr<monero_block> block) {
    for (std::shared_ptr<monero_tx>& tx : block->m_txs) {
      tx->m_block->reset();
      monero_tx_wallet* tx_wallet = dynamic_cast<monero_tx_wallet*>(tx.get());
      if (tx_wallet != nullptr) {
        if (tx_wallet->m_tx_set != boost::none) tx_wallet->m_tx_set->reset();
        if (tx_wallet->m_outgoing_transfer != boost::none) tx_wallet->m_outgoing_transfer.get()->m_tx.reset();
        for (std::shared_ptr<monero_transfer> transfer : tx_wallet->m_incoming_transfers) transfer->m_tx.reset();
        for (std::shared_ptr<monero_output> output : tx_wallet->m_outputs) output->m_tx.reset();
        for (std::shared_ptr<monero_output> input : tx_wallet->m_inputs) {
          input->m_key_image.reset();
          input->m_tx.reset();
        }
      }
      monero_tx_query* tx_query = dynamic_cast<monero_tx_query*>(tx.get());
      if (tx_query != nullptr) {
        if (tx_query->m_transfer_query != boost::none) {
          tx_query->m_transfer_query.get()->m_tx_query->reset();
          tx_query->m_transfer_query.get().reset();
        }
        if (tx_query->m_output_query != boost::none) {
          tx_query->m_output_query.get()->m_tx_query->reset();
          tx_query->m_output_query.get().reset();
        }
      }
    }
    block.reset();
  }

  static void free(std::vector<std::shared_ptr<monero_block>> blocks) {
    for (std::shared_ptr<monero_block>& block : blocks) free(block);
  }

  static void free(std::shared_ptr<monero_tx> tx) {
    if (tx->m_block == boost::none) {
      std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
      tx->m_block = block;
      block->m_txs.push_back(tx);
    }
    free(tx->m_block.get());
  }

  static void free(std::vector<std::shared_ptr<monero_tx_wallet>> txs) {
    return free(get_blocks_from_txs(txs));
  }

  static void free(std::vector<std::shared_ptr<monero_transfer>> transfers) {
    return free(get_blocks_from_transfers(transfers));
  }

  static void free(std::vector<std::shared_ptr<monero_output_wallet>> outputs) {
    return free(get_blocks_from_outputs(outputs));
  }
}
#endif /* monero_utils_h */
