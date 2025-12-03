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

#include "daemon/monero_daemon_model.h"
#include "wallet/monero_wallet_model.h"
#include "wallet/monero_wallet_keys.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "wallet/wallet2.h"
#include <map>

using namespace monero;

namespace monero {


  // ------------------------------- LIGHT WALLET DATA STRUCTURES -------------------------------

  struct monero_light_version {
    boost::optional<std::string> m_server_type;
    boost::optional<std::string> m_server_version;
    boost::optional<std::string> m_last_git_commit_hash;
    boost::optional<std::string> m_last_git_commit_date;
    boost::optional<std::string> m_git_branch_name;
    boost::optional<std::string> m_monero_version_full;
    boost::optional<uint64_t> m_blockchain_height;
    boost::optional<uint32_t> m_api;
    boost::optional<uint32_t> m_max_subaddresses;
    boost::optional<monero_network_type> m_network_type;
    boost::optional<bool> m_testnet;

    static std::shared_ptr<monero_light_version> deserialize(const std::string& version_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_version>& version);
  };

  struct monero_light_address_meta {
    boost::optional<uint32_t> m_maj_i;
    boost::optional<uint32_t> m_min_i;

    static std::shared_ptr<monero_light_address_meta> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_address_meta>& address_meta);
  };

  struct monero_light_output {
    boost::optional<uint64_t> m_tx_id;
    boost::optional<std::string> m_amount;
    boost::optional<uint64_t> m_index;
    boost::optional<std::string> m_global_index;
    boost::optional<std::string> m_rct;
    boost::optional<std::string> m_tx_hash;
    boost::optional<std::string> m_tx_prefix_hash;
    boost::optional<std::string> m_public_key;
    boost::optional<std::string> m_tx_pub_key;
    boost::optional<std::vector<std::string>> m_spend_key_images;
    boost::optional<std::string> m_timestamp;
    boost::optional<uint64_t> m_height;
    boost::optional<monero_light_address_meta> m_recipient;

    // custom members
    boost::optional<std::string> m_key_image;
    boost::optional<bool> m_frozen;

    bool key_image_is_known() const { return m_key_image != boost::none && !m_key_image->empty(); };

    bool rct() const { return m_rct != boost::none && !m_rct->empty(); };

    bool is_spent() const {
      if (!key_image_is_known() || m_spend_key_images == boost::none || m_spend_key_images->empty()) return false;
      for(const auto& spend_key_image : m_spend_key_images.get()) {
        if (spend_key_image == m_key_image.get()) return true;
      }
      return false;
    };

    static std::shared_ptr<monero_light_output> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output);
  };

  struct monero_light_rates {
    boost::optional<float> m_aud;
    boost::optional<float> m_brl;
    boost::optional<float> m_btc;
    boost::optional<float> m_cad;
    boost::optional<float> m_chf;
    boost::optional<float> m_cny;
    boost::optional<float> m_eur;
    boost::optional<float> m_gbp;
    boost::optional<float> m_hkd;
    boost::optional<float> m_inr;
    boost::optional<float> m_jpy;
    boost::optional<float> m_krw;
    boost::optional<float> m_mxn;
    boost::optional<float> m_nok;
    boost::optional<float> m_nzd;
    boost::optional<float> m_sek;
    boost::optional<float> m_sgd;
    boost::optional<float> m_try;
    boost::optional<float> m_usd;
    boost::optional<float> m_rub;
    boost::optional<float> m_zar;

    static std::shared_ptr<monero_light_rates> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_rates>& rates);
  };

  struct monero_light_spend {
    boost::optional<std::string> m_amount;
    boost::optional<std::string> m_key_image;
    boost::optional<std::string> m_tx_pub_key;
    boost::optional<uint64_t> m_out_index;
    boost::optional<uint32_t> m_mixin;
    boost::optional<monero_light_address_meta> m_sender;

    static std::shared_ptr<monero_light_spend> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_spend>& spend);
    std::shared_ptr<monero_light_spend> copy(const std::shared_ptr<monero_light_spend>& src, const std::shared_ptr<monero_light_spend>& tgt) const;
  };

  struct monero_light_tx {
    boost::optional<uint64_t> m_id;
    boost::optional<std::string> m_hash;
    boost::optional<std::string> m_timestamp;
    boost::optional<std::string> m_total_received;
    boost::optional<std::string> m_total_sent;
    boost::optional<std::string> m_fee;
    boost::optional<uint64_t> m_unlock_time;
    boost::optional<uint64_t> m_height;
    boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
    boost::optional<std::string> m_payment_id;
    boost::optional<bool> m_coinbase;
    boost::optional<bool> m_mempool;
    boost::optional<uint32_t> m_mixin;
    boost::optional<monero_light_address_meta> m_recipient;

    static std::shared_ptr<monero_light_tx> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_tx>& transaction);
    std::shared_ptr<monero_light_tx> copy(const std::shared_ptr<monero_light_tx>& src, const std::shared_ptr<monero_light_tx>& tgt, bool exclude_spend = false) const;
  };

  struct monero_light_random_output {
    boost::optional<std::string> m_global_index;
    boost::optional<std::string> m_public_key;
    boost::optional<std::string> m_rct;

    static std::shared_ptr<monero_light_random_output> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output);
  };

  struct monero_light_random_outputs {
    boost::optional<std::string> m_amount;
    boost::optional<std::vector<monero_light_random_output>> m_outputs;

    static std::shared_ptr<monero_light_random_outputs> deserialize(const std::string& config_json);
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_outputs>& random_outputs);
  };
  
  struct monero_tx_wallet_light {
    boost::optional<cryptonote::transaction> m_tx; // for block weight
    boost::optional<crypto::secret_key> m_tx_key;
    boost::optional<std::vector<crypto::secret_key>> m_additional_tx_keys;
    boost::optional<std::string> m_signed_serialized_tx_string;
    boost::optional<std::string> m_tx_hash_string;
    boost::optional<std::string> m_tx_key_string; // this includes additional_tx_keys
    boost::optional<std::string> m_tx_pub_key_string; // from get_tx_pub_key_from_extra()
    boost::optional<tools::wallet2::tx_construction_data> m_construction_data;
    boost::optional<std::vector<std::string>> m_spent_key_images;
    boost::optional<size_t> m_tx_blob_byte_length;
    boost::optional<uint64_t> m_fee;
    boost::optional<uint64_t> m_weight;
  };

  typedef std::unordered_map<std::string/*public_key*/, std::vector<monero_light_random_output>> monero_light_spendable_random_outputs;

  struct tied_spendable_to_random_outs {
    // Success parameters
    std::vector<monero_light_random_outputs> m_mix_outs;
    monero_light_spendable_random_outputs m_prior_attempt_unspent_outs_to_mix_outs_new;
  };

  struct monero_light_get_random_outs_params {
    // for display / information purposes on errCode=needMoreMoneyThanFound during step1:
    uint64_t m_spendable_balance; //  (effectively but not the same as spendable_balance)
    uint64_t m_required_balance; // for display / information purposes on errCode=needMoreMoneyThanFound during step1
    // Success case return values
    uint32_t m_mixin;
    std::vector<monero_light_output> m_using_outs;
    uint64_t m_using_fee;
    uint64_t m_final_total_wo_fee;
    uint64_t m_change_amount;
  };

  // ------------------------------- REQUEST/RESPONSE DATA STRUCTURES -------------------------------

  struct monero_light_wallet_request : public serializable_struct {
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_view_key;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_address_info_response {
    boost::optional<std::string> m_locked_funds;
    boost::optional<std::string> m_total_received;
    boost::optional<std::string> m_total_sent;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_transaction_height;
    boost::optional<uint64_t> m_blockchain_height;
    boost::optional<std::vector<monero_light_spend>> m_spent_outputs;
    boost::optional<monero_light_rates> m_rates;
    
    static std::shared_ptr<monero_light_get_address_info_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_address_txs_response {
    boost::optional<std::string> m_total_received;
    boost::optional<uint64_t> m_scanned_height;
    boost::optional<uint64_t> m_scanned_block_height;
    boost::optional<uint64_t> m_start_height;
    boost::optional<uint64_t> m_blockchain_height;
    boost::optional<std::vector<monero_light_tx>> m_transactions;

    static std::shared_ptr<monero_light_get_address_txs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_random_outs_request : public serializable_struct {
    boost::optional<uint32_t> m_count;
    boost::optional<std::vector<std::string>> m_amounts;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_random_outs_response {
    boost::optional<std::vector<monero_light_random_outputs>> m_amount_outs;
    
    static std::shared_ptr<monero_light_get_random_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_unspent_outs_request : public monero_light_wallet_request {
    boost::optional<std::string> m_amount;
    boost::optional<uint32_t> m_mixin;
    boost::optional<bool> m_use_dust;
    boost::optional<std::string> m_dust_threshold;
    
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_get_unspent_outs_response {
    boost::optional<std::string> m_per_byte_fee;
    boost::optional<std::string> m_fee_mask;
    boost::optional<std::string> m_amount;
    boost::optional<std::vector<monero_light_output>> m_outputs;
    
    static std::shared_ptr<monero_light_get_unspent_outs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_import_wallet_request : public monero_light_wallet_request {
    boost::optional<uint64_t> m_from_height;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_import_request_response {
    boost::optional<std::string> m_payment_address;
    boost::optional<std::string> m_payment_id;
    boost::optional<std::string> m_import_fee;
    boost::optional<bool> m_new_request;
    boost::optional<bool> m_request_fullfilled;
    boost::optional<std::string> m_status;
      
    static std::shared_ptr<monero_light_import_request_response> deserialize(const std::string& config_json);
  };

  struct monero_light_login_request : public monero_light_wallet_request {
    boost::optional<bool> m_create_account;
    boost::optional<bool> m_generated_locally;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_login_response {
    boost::optional<bool> m_new_address;
    boost::optional<bool> m_generated_locally;
    boost::optional<uint64_t> m_start_height;
      
    static std::shared_ptr<monero_light_login_response> deserialize(const std::string& config_json);
  };

  struct monero_light_submit_raw_tx_request : public serializable_struct {
    boost::optional<std::string> m_tx;
      
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_submit_raw_tx_response {
    boost::optional<std::string> m_status;
    
    static std::shared_ptr<monero_light_submit_raw_tx_response> deserialize(const std::string& config_json);
  };

  struct monero_light_provision_subaddrs_request : public monero_light_wallet_request {
    boost::optional<uint32_t> m_maj_i;
    boost::optional<uint32_t> m_min_i;
    boost::optional<uint32_t> m_n_maj;
    boost::optional<uint32_t> m_n_min;
    boost::optional<bool> m_get_all;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;    
  };

  class monero_light_index_range : public std::vector<uint32_t> {
  public:
    monero_light_index_range() { 
      std::vector<uint32_t>();
    };

    monero_light_index_range(const uint32_t min_i, const uint32_t maj_i) {
      push_back(min_i);
      push_back(maj_i);
    };

    bool in_range(uint32_t subaddress_idx) const {
      if (empty() || size() != 2) return false;
      return at(0) <= subaddress_idx && subaddress_idx <= at(1);
    };

    std::vector<uint32_t> to_subaddress_indices() const {
      std::vector<uint32_t> indices;

      if (size() != 2) {
        return indices;
      }

      uint32_t min_i = at(0);
      uint32_t maj_i = at(1);

      for(uint32_t i = min_i; i <= maj_i; i++) {
        indices.push_back(i);
      }

      return indices;
    }
    
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_index_range>& index_range);
  };

  class monero_light_subaddrs : public std::map<uint32_t, std::vector<monero_light_index_range>>, public serializable_struct {
  public:

    bool contains(const uint32_t account_index) const {
      auto it = find(account_index);
      return it != end();
    }

    bool contains(const uint32_t account_index, const uint32_t subaddress_index) const {
      auto it = find(account_index);
      if (it == end()) return false;
      for(const auto& index_range : it->second) {
        if (index_range.in_range(subaddress_index)) return true;
      }
      return false;
    }

    bool is_upsert(const uint32_t account_idx) const {
      if (account_idx == 0) return true;
      auto it = find(account_idx);
      return it != end();
    }

    std::vector<uint32_t> get_subaddresses_indices(const uint32_t account_idx) const {
      std::vector<uint32_t> subaddress_idxs;
      auto it = find(account_idx);
      if (it != end()) {
        for (const auto& index_range : it->second) {
          const auto& idxs = index_range.to_subaddress_indices();
          subaddress_idxs.insert(subaddress_idxs.begin(), idxs.begin(), idxs.end());
        }
      }
      return subaddress_idxs;
    }

    uint32_t get_last_account_index() const {
      uint32_t last_account_idx = 0;
      for(const auto &kv : *this) {
        if (kv.first > last_account_idx) last_account_idx = kv.first;
      }
      return last_account_idx;
    }

    uint32_t get_last_subaddress_index(const uint32_t account_idx) const {
      uint32_t last_subaddress_idx = 0;
      auto it = find(account_idx);
      if (it == end()) throw std::runtime_error("account not found");
      for(const auto& index_range : it->second) {
        last_subaddress_idx = index_range.at(1);
      }
      return last_subaddress_idx;
    }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_subaddrs>& subaddrs);
  };

  struct monero_light_provision_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_new_subaddrs;
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_provision_subaddrs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_upsert_subaddrs_request : public monero_light_wallet_request {
    boost::optional<monero_light_subaddrs> m_subaddrs;
    boost::optional<bool> m_get_all;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
  };

  struct monero_light_upsert_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_new_subaddrs;
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_upsert_subaddrs_response> deserialize(const std::string& config_json);
  };

  struct monero_light_get_subaddrs_response {
    boost::optional<monero_light_subaddrs> m_all_subaddrs;

    static std::shared_ptr<monero_light_get_subaddrs_response> deserialize(const std::string& config_json);
  };

  class monero_light_tx_container {
  public:
    monero_light_tx get(const std::string& hash) const;
    monero_light_tx get(const monero_light_output& output) const;
    uint64_t get_unlock_time(const std::string& hash) const;
    void set(const monero_light_get_address_txs_response& response, const monero_light_get_address_info_response& addr_info_response);
    void set(const monero_light_tx& tx);
    void set_unconfirmed(const std::shared_ptr<monero_tx_wallet>& tx);
    void remove_unconfirmed(const std::string& hash);
    void set_relayed(const std::string& hash);
    serializable_unordered_map<std::string, std::shared_ptr<monero_tx_wallet>> get_unconfirmed_txs() const { return m_unconfirmed_txs; };
    bool is_key_image_in_pool(const std::string& key_image) const;
    bool is_key_image_spent(const std::string& key_image) const;
    bool is_key_image_spent(const crypto::key_image& key_image) const;
    bool is_key_image_spent(const std::shared_ptr<monero_key_image>& key_image) const;
    bool is_key_image_spent(const monero_key_image& key_image) const;
    void set(const std::vector<monero_light_tx>& txs, bool clear_txs = false);
    uint64_t calculate_num_blocks_to_unlock(const monero_light_output& output, uint64_t current_height) const;
    uint64_t calculate_num_blocks_to_unlock(const std::vector<monero_light_output>& outputs, uint64_t current_height) const;
    uint64_t calculate_num_blocks_to_unlock(const std::vector<std::string>& hashes, uint64_t current_height) const;
    uint64_t calculate_num_blocks_to_unlock(const std::string& hash, uint64_t current_height) const;
    bool is_locked(const std::string& hash, uint64_t current_height) const;
    bool is_locked(const monero_light_output& output, uint64_t current_height) const;
    bool is_confirmed(const std::string& hash) const;
    void add_tx_key(const crypto::secret_key &tx_key, const crypto::hash &tx_id, const std::vector<crypto::secret_key>& additional_tx_keys);
    bool get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const;
    void clear();
    void clear_unconfirmed();
  private:
    serializable_unordered_map<std::string, monero_light_tx> m_txs;
    serializable_unordered_map<std::string, std::shared_ptr<monero_tx_wallet>> m_unconfirmed_txs;
    serializable_unordered_map<std::string, bool> m_spent_key_images;
    serializable_unordered_map<std::string, std::vector<std::string>> m_pool_key_images;
    serializable_unordered_map<crypto::hash, crypto::secret_key> m_tx_keys;
    serializable_unordered_map<crypto::hash, std::vector<crypto::secret_key>> m_additional_tx_keys;

    mutable boost::recursive_mutex m_mutex;

    void add_key_images_to_pool(const std::shared_ptr<monero_tx_wallet>& tx);
  };

  // TODO insert "unconfirmed" output change for correct balance calculation after tx sent
  class monero_light_output_container {
  public:
    std::vector<monero_light_output> get(uint32_t account_idx) const;
    std::vector<monero_light_output> get(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<monero_light_output> get_spent(uint32_t account_idx) const;
    std::vector<monero_light_output> get_spent(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<monero_light_output> get_unspent(uint32_t account_idx) const;
    std::vector<monero_light_output> get_unspent(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<monero_light_output> get_by_tx_hash(const std::string& tx_hash, bool filter_spent = false) const;
    void set(const monero_light_tx_container& tx_container, const monero_light_get_unspent_outs_response& response);
    void set(const std::vector<monero_light_output>& spent, const std::vector<monero_light_output>& unspent);
    void set_spent(const std::vector<monero_light_output>& outputs);
    void set_unspent(const std::vector<monero_light_output>& outputs);
    void set_key_image(const std::string& key_image, size_t index);
    bool is_used(uint32_t account_idx, uint32_t subaddress_idx) const;
    size_t get_num() const { return m_num_spent + m_num_unspent; }
    size_t get_num_spent() const { return m_num_spent; }
    size_t get_num_unspent() const { return m_num_unspent; }
    uint64_t get_num_unspent(uint32_t account_idx, uint32_t subaddress_idx) const;
    std::vector<size_t> get_indexes(const std::vector<monero_light_output>& outputs) const;
    void calculate_balance(const monero_light_tx_container& tx_container, uint64_t current_height);
    uint64_t get_balance() const { return m_balance; };
    uint64_t get_balance(uint32_t account_idx) const;
    uint64_t get_balance(uint32_t account_idx, uint32_t subaddress_idx) const;
    uint64_t get_unlocked_balance() const { return m_unlocked_balance; };
    uint64_t get_unlocked_balance(uint32_t account_idx) const;
    uint64_t get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const;
    bool is_frozen(const std::string& key_image) const;
    bool is_frozen(const monero_light_output& output) const;
    void freeze(const std::string& key_image);
    void thaw(const std::string& key_image);
    void clear();
    void clear_frozen();
    void set_key_image_spent(const std::string& key_image, bool spent = true);
    bool is_key_image_spent(const std::string& key_image) const;
    std::tuple<uint64_t, uint64_t, std::vector<tools::wallet2::exported_transfer_details>> export_outputs(const monero_light_tx_container& tx_container, monero_key_image_cache& key_image_cache, bool all, uint32_t start, uint32_t count = 0xffffffff) const;

  private:
    mutable boost::recursive_mutex m_mutex;
    // cache
    mutable serializable_unordered_map<std::string, size_t> m_index;
    mutable serializable_unordered_map<std::string, std::vector<monero_light_output>> m_tx_hash_index;
    mutable serializable_unordered_map<std::string, size_t> m_key_image_index;
    mutable serializable_unordered_map<std::string, bool> m_key_image_status_index;

    mutable serializable_unordered_map<size_t, bool> m_frozen_key_image_index;
    mutable serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::vector<monero_light_output>>> m_spent;
    mutable serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, std::vector<monero_light_output>>> m_unspent;
    std::vector<monero_light_output> m_all;
    size_t m_num_spent = 0;
    size_t m_num_unspent = 0;
    // balance info
    uint64_t m_balance = 0;
    uint64_t m_unlocked_balance = 0;
    serializable_unordered_map<uint32_t, uint64_t> m_account_balance;
    serializable_unordered_map<uint32_t, uint64_t> m_account_unlocked_balance;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, uint64_t>> m_subaddress_balance;
    serializable_unordered_map<uint32_t, serializable_unordered_map<uint32_t, uint64_t>> m_subaddress_unlocked_balance;

    void clear_balance();
  };

}