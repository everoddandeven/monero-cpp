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

#include "monero_light_model.h"

#include "utils/gen_utils.h"
#include "utils/monero_utils.h"
#include <iostream>

namespace monero {

  // ------------------------------- DESERIALIZE UTILS -------------------------------

  std::shared_ptr<monero_light_version> monero_light_version::deserialize(const std::string& version_json) {
    std::istringstream iss = version_json.empty() ? std::istringstream() : std::istringstream(version_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    std::shared_ptr<monero_light_version> version = std::make_shared<monero_light_version>();
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("server_type")) version->m_server_type = it->second.data();
      else if (key == std::string("server_version")) version->m_server_version = it->second.data();
      else if (key == std::string("last_git_commit_hash")) version->m_last_git_commit_hash = it->second.data();
      else if (key == std::string("last_git_commit_date")) version->m_last_git_commit_date = it->second.data();
      else if (key == std::string("git_branch_name")) version->m_git_branch_name = it->second.data();
      else if (key == std::string("monero_version_full")) version->m_monero_version_full = it->second.data();
      else if (key == std::string("blockchain_height")) version->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("api")) version->m_api = it->second.get_value<uint32_t>();
      else if (key == std::string("max_subaddresses")) version->m_max_subaddresses = it->second.get_value<uint32_t>();
      else if (key == std::string("testnet")) version->m_testnet = it->second.get_value<bool>();
      else if (key == std::string("network")) {
        std::string network_str = it->second.data();
        if (network_str == std::string("mainnet") || network_str == "fakechain") version->m_network_type = monero_network_type::MAINNET;
        else if (network_str == std::string("testnet")) version->m_network_type = monero_network_type::TESTNET;
        else if (network_str == std::string("stagenet")) version->m_network_type = monero_network_type::STAGENET;
        throw std::runtime_error("Cannot deserialize lws version: invalid network provided " + network_str);
      }
    }

    return version;
  }

  std::shared_ptr<monero_light_address_meta> monero_light_address_meta::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_address_meta> address_meta = std::make_shared<monero_light_address_meta>();
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
      else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
    }

    return address_meta;
  }

  std::shared_ptr<monero_light_output> monero_light_output::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_output> output = std::make_shared<monero_light_output>();
    output->m_spend_key_images = std::vector<std::string>();
    std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
      else if (key == std::string("amount")) output->m_amount = it->second.data();
      else if (key == std::string("index")) output->m_index = it->second.get_value<uint64_t>();
      else if (key == std::string("global_index")) output->m_global_index = it->second.data();
      else if (key == std::string("rct")) output->m_rct = it->second.data();
      else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
      else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
      else if (key == std::string("public_key")) output->m_public_key = it->second.data();
      else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
      else if (key == std::string("spend_key_images")) for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
      else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
      else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("recipient")) {
        monero_light_address_meta::from_property_tree(it->second, recipient);
      }
    }
    
    output->m_recipient = *recipient;

    return output;
  }

  std::shared_ptr<monero_light_rates> monero_light_rates::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_rates> rates = std::make_shared<monero_light_rates>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("AUD")) rates->m_aud = it->second.get_value<float>();
      else if (key == std::string("BRL")) rates->m_brl = it->second.get_value<float>();
      else if (key == std::string("BTC")) rates->m_btc = it->second.get_value<float>();
      else if (key == std::string("CAD")) rates->m_cad = it->second.get_value<float>();
      else if (key == std::string("CHF")) rates->m_chf = it->second.get_value<float>();
      else if (key == std::string("CNY")) rates->m_cny = it->second.get_value<float>();
      else if (key == std::string("EUR")) rates->m_eur = it->second.get_value<float>();
      else if (key == std::string("GBP")) rates->m_gbp = it->second.get_value<float>();
      else if (key == std::string("HKD")) rates->m_hkd = it->second.get_value<float>();
      else if (key == std::string("INR")) rates->m_inr = it->second.get_value<float>();
      else if (key == std::string("JPY")) rates->m_jpy = it->second.get_value<float>();
      else if (key == std::string("KRW")) rates->m_krw = it->second.get_value<float>();
      else if (key == std::string("MXN")) rates->m_mxn = it->second.get_value<float>();
      else if (key == std::string("NOK")) rates->m_nok = it->second.get_value<float>();
      else if (key == std::string("NZD")) rates->m_nzd = it->second.get_value<float>();
      else if (key == std::string("SEK")) rates->m_sek = it->second.get_value<float>();
      else if (key == std::string("SGD")) rates->m_sgd = it->second.get_value<float>();
      else if (key == std::string("TRY")) rates->m_try = it->second.get_value<float>();
      else if (key == std::string("USD")) rates->m_usd = it->second.get_value<float>();
      else if (key == std::string("RUB")) rates->m_rub = it->second.get_value<float>();
      else if (key == std::string("ZAR")) rates->m_zar = it->second.get_value<float>();
    }

    return rates;
  }

  std::shared_ptr<monero_light_spend> monero_light_spend::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_spend> spend = std::make_shared<monero_light_spend>();
    std::shared_ptr<monero_light_address_meta> sender = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount")) spend->m_amount = it->second.data();
      else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
      else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
      else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint64_t>();
      else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("sender")) {
        monero_light_address_meta::from_property_tree(it->second, sender);
      }
    }
    
    spend->m_sender = *sender;

    return spend;
  }

  std::shared_ptr<monero_light_tx> monero_light_tx::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_tx> transaction = std::make_shared<monero_light_tx>();
    transaction->m_spent_outputs = std::vector<monero_light_spend>();
    transaction->m_coinbase = false;
    transaction->m_total_received = "0";
    transaction->m_total_sent = "0";

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("id")) transaction->m_id = it->second.get_value<uint64_t>();
      else if (key == std::string("hash")) transaction->m_hash = it->second.data();
      else if (key == std::string("timestamp")) transaction->m_timestamp = it->second.data();
      else if (key == std::string("total_received")) transaction->m_total_received = it->second.data();
      else if (key == std::string("total_sent")) transaction->m_total_sent = it->second.data();
      else if (key == std::string("fee")) transaction->m_fee = it->second.data();
      else if (key == std::string("unlock_time")) transaction->m_unlock_time = it->second.get_value<uint64_t>();
      else if (key == std::string("height")) transaction->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent_outputs")) {
        // deserialize monero_light_spend
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_spend> out = std::make_shared<monero_light_spend>();
          monero_light_spend::from_property_tree(it2->second, out);
          transaction->m_spent_outputs->push_back(*out);
        }
      }
      else if (key == std::string("payment_id")) transaction->m_payment_id = it->second.data();
      else if (key == std::string("coinbase")) transaction->m_coinbase = it->second.get_value<bool>();
      else if (key == std::string("mempool")) transaction->m_mempool = it->second.get_value<bool>();
      else if (key == std::string("mixin")) transaction->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("recipient")) {
        std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();
        monero_light_address_meta::from_property_tree(it->second, recipient);
        transaction->m_recipient = *recipient;
      }
    }

    return transaction;
  }

  std::shared_ptr<monero_light_random_output> monero_light_random_output::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_random_output> random_output = std::make_shared<monero_light_random_output>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("global_index")) random_output->m_global_index = it->second.data();
      else if (key == std::string("public_key")) random_output->m_public_key = it->second.data();
      else if (key == std::string("rct")) random_output->m_rct = it->second.data();
    }

    return random_output;
  }

  std::shared_ptr<monero_light_random_outputs> monero_light_random_outputs::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_random_outputs> random_outputs = std::make_shared<monero_light_random_outputs>();
    random_outputs->m_outputs = std::vector<monero_light_random_output>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount")) random_outputs->m_amount = it->second.data();
      else if (key == std::string("outputs")) {
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_random_output> out = std::make_shared<monero_light_random_output>();
          monero_light_random_output::from_property_tree(it2->second, out);
          random_outputs->m_outputs->push_back(*out);
        }
      }
    }

    return random_outputs;
  }

  std::shared_ptr<monero_light_get_address_info_response> monero_light_get_address_info_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_address_info_response> address_info = std::make_shared<monero_light_get_address_info_response>();
    address_info->m_spent_outputs = std::vector<monero_light_spend>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("locked_funds")) address_info->m_locked_funds = it->second.data();
      else if (key == std::string("total_received")) address_info->m_total_received = it->second.data();
      else if (key == std::string("total_sent")) address_info->m_total_sent = it->second.data();
      else if (key == std::string("scanned_height")) address_info->m_scanned_height = it->second.get_value<uint64_t>();
      else if (key == std::string("scanned_block_height")) address_info->m_scanned_block_height = it->second.get_value<uint64_t>();
      else if (key == std::string("start_height")) address_info->m_start_height = it->second.get_value<uint64_t>();
      else if (key == std::string("transaction_height")) address_info->m_transaction_height = it->second.get_value<uint64_t>();
      else if (key == std::string("blockchain_height")) address_info->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent_outputs")) {
        boost::property_tree::ptree spent_outputs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = spent_outputs_node.begin(); it2 != spent_outputs_node.end(); ++it2) {
          std::shared_ptr<monero_light_spend> spent_output = std::make_shared<monero_light_spend>();
          monero_light_spend::from_property_tree(it2->second, spent_output);
          address_info->m_spent_outputs->push_back(*spent_output);
        }
      } else if (key == std::string("rates")) {
        std::shared_ptr<monero_light_rates> rates = std::make_shared<monero_light_rates>();
        monero_light_rates::from_property_tree(it->second, rates);
        address_info->m_rates = *rates;
      }
    }

    return address_info;
  }

  std::shared_ptr<monero_light_get_address_txs_response> monero_light_get_address_txs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_address_txs_response> address_txs = std::make_shared<monero_light_get_address_txs_response>();  
    address_txs->m_transactions = std::vector<monero_light_tx>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("total_received")) address_txs->m_total_received = it->second.data();
      else if (key == std::string("scanned_height")) address_txs->m_scanned_height = it->second.get_value<uint64_t>();
      else if (key == std::string("scanned_block_height")) address_txs->m_scanned_block_height = it->second.get_value<uint64_t>();
      else if (key == std::string("start_height")) address_txs->m_start_height = it->second.get_value<uint64_t>();
      else if (key == std::string("blockchain_height")) address_txs->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("transactions")) {
        boost::property_tree::ptree transactions_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = transactions_node.begin(); it2 != transactions_node.end(); ++it2) {
          std::shared_ptr<monero_light_tx> transaction = std::make_shared<monero_light_tx>();
          monero_light_tx::from_property_tree(it2->second, transaction);
          address_txs->m_transactions->push_back(*transaction);
        }
      }
    }

    return address_txs;
  }

  std::shared_ptr<monero_light_get_random_outs_response> monero_light_get_random_outs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_random_outs_response> random_outs = std::make_shared<monero_light_get_random_outs_response>();
    random_outs->m_amount_outs = std::vector<monero_light_random_outputs>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount_outs")) {
        boost::property_tree::ptree outs_node = it->second;

        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_random_outputs> out = std::make_shared<monero_light_random_outputs>();
          monero_light_random_outputs::from_property_tree(it2->second, out);
          random_outs->m_amount_outs->push_back(*out);
        }
      }
    }

    return random_outs;
  }

  std::shared_ptr<monero_light_get_unspent_outs_response> monero_light_get_unspent_outs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_unspent_outs_response> unspent_outs = std::make_shared<monero_light_get_unspent_outs_response>();
    unspent_outs->m_outputs = std::vector<monero_light_output>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("per_byte_fee")) unspent_outs->m_per_byte_fee = it->second.data();
      else if (key == std::string("fee_mask")) unspent_outs->m_fee_mask = it->second.data();
      else if (key == std::string("amount")) unspent_outs->m_amount = it->second.data();
      else if (key == std::string("outputs")) {
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_output> out = std::make_shared<monero_light_output>();
          monero_light_output::from_property_tree(it2->second, out);
          unspent_outs->m_outputs->push_back(*out);
        }
      }
    }

    return unspent_outs;
  }

  std::shared_ptr<monero_light_import_request_response> monero_light_import_request_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_import_request_response> import_request = std::make_shared<monero_light_import_request_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("payment_address")) import_request->m_payment_address = it->second.data();
      else if (key == std::string("payment_id")) import_request->m_payment_id = it->second.data();
      else if (key == std::string("import_fee")) import_request->m_import_fee = it->second.data();
      else if (key == std::string("new_request")) import_request->m_new_request = it->second.get_value<bool>();
      else if (key == std::string("request_fulfilled")) import_request->m_request_fullfilled = it->second.get_value<bool>();
      else if (key == std::string("status")) import_request->m_status = it->second.data();
    }

    return import_request;
  }

  std::shared_ptr<monero_light_login_response> monero_light_login_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_login_response> login = std::make_shared<monero_light_login_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("new_address")) login->m_new_address = it->second.get_value<bool>();
      else if (key == std::string("generated_locally")) login->m_generated_locally = it->second.get_value<bool>();
      else if (key == std::string("start_height")) login->m_start_height = it->second.get_value<uint64_t>();
    }

    return login;
  }

  std::shared_ptr<monero_light_submit_raw_tx_response> monero_light_submit_raw_tx_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_submit_raw_tx_response> tx = std::make_shared<monero_light_submit_raw_tx_response>();
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("status")) tx->m_status = it->second.data();
    }

    return tx;
  }

  std::shared_ptr<monero_light_provision_subaddrs_response> monero_light_provision_subaddrs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_provision_subaddrs_response> response = std::make_shared<monero_light_provision_subaddrs_response>();
    response->m_all_subaddrs = monero_light_subaddrs();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("new_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> new_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, new_subaddrs);
        response->m_new_subaddrs = *new_subaddrs;
      } else if (key == std::string("all_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> all_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, all_subaddrs);
        response->m_all_subaddrs = *all_subaddrs;
      }
    }

    return response;
  }

  std::shared_ptr<monero_light_upsert_subaddrs_response> monero_light_upsert_subaddrs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_upsert_subaddrs_response> response = std::make_shared<monero_light_upsert_subaddrs_response>();
    response->m_all_subaddrs = monero_light_subaddrs();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("new_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> new_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, new_subaddrs);
        response->m_new_subaddrs = *new_subaddrs;
      } else if (key == std::string("all_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> all_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, all_subaddrs);
        response->m_all_subaddrs = *all_subaddrs;
      }
    }

    return response;
  }

  std::shared_ptr<monero_light_get_subaddrs_response> monero_light_get_subaddrs_response::deserialize(const std::string& config_json) {
    // deserialize monero output json to property node
    std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
    boost::property_tree::ptree node;
    boost::property_tree::read_json(iss, node);

    // convert config property tree to monero_wallet_config
    std::shared_ptr<monero_light_get_subaddrs_response> response = std::make_shared<monero_light_get_subaddrs_response>();
    response->m_all_subaddrs = monero_light_subaddrs();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      
      if (key == std::string("all_subaddrs")) {
        std::shared_ptr<monero_light_subaddrs> all_subaddrs = std::make_shared<monero_light_subaddrs>();
        monero_light_subaddrs::from_property_tree(it->second, all_subaddrs);
        response->m_all_subaddrs = *all_subaddrs;
      }
    }

    return response;
  }

  // ------------------------------- PROPERTY TREE UTILS -------------------------------

  void monero_light_version::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_version>& version) {
    // convert config property tree to monero_light_version
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("server_type")) version->m_server_type = it->second.data();
      else if (key == std::string("server_version")) version->m_server_version = it->second.data();
      else if (key == std::string("last_git_commit_hash")) version->m_last_git_commit_hash = it->second.data();
      else if (key == std::string("last_git_commit_date")) version->m_last_git_commit_date = it->second.data();
      else if (key == std::string("git_branch_name")) version->m_git_branch_name = it->second.data();
      else if (key == std::string("monero_version_full")) version->m_monero_version_full = it->second.data();
      else if (key == std::string("blockchain_height")) version->m_blockchain_height = it->second.get_value<uint64_t>();
      else if (key == std::string("api")) version->m_api = it->second.get_value<uint32_t>();
      else if (key == std::string("max_subaddresses")) version->m_max_subaddresses = it->second.get_value<uint32_t>();
      else if (key == std::string("testnet")) version->m_testnet = it->second.get_value<bool>();
      else if (key == std::string("network")) {
        std::string network_str = it->second.data();
        if (network_str == std::string("mainnet") || network_str == "fakechain") version->m_network_type = monero_network_type::MAINNET;
        else if (network_str == std::string("testnet")) version->m_network_type = monero_network_type::TESTNET;
        else if (network_str == std::string("stagenet")) version->m_network_type = monero_network_type::STAGENET;
        throw std::runtime_error("Cannot deserialize lws version: invalid network provided " + network_str);
      }
    }
  }

  void monero_light_address_meta::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_address_meta>& address_meta) {
    // convert config property tree to monero_light_address_meta
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
      else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
    }
  }

  void monero_light_index_range::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_index_range>& index_range) {
    // convert config property tree to monero_wallet_config
    int length = 0;
    
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      uint32_t value = it->second.get_value<uint32_t>();
      index_range->push_back(value);
      
      length++;
      if (length > 2) throw std::runtime_error("Invalid index range length");
      //if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
      //else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
    }

    if (length != 2) throw std::runtime_error("Invalid index range length");
  }

  void monero_light_subaddrs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_subaddrs>& subaddrs) {  
    // convert config property tree to monero_wallet_config
    boost::optional<uint32_t> _key = boost::none;
    boost::optional<monero_light_index_range> _index_range = boost::none;

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      boost::property_tree::ptree key_value_node = it->second;
      boost::optional<uint32_t> _key;
      std::vector<monero_light_index_range> index_ranges;
      
      for (boost::property_tree::ptree::const_iterator it2 = key_value_node.begin(); it2 != key_value_node.end(); ++it2) {
        std::string key = it2->first;
        if (key == std::string("key")) _key = it2->second.get_value<uint32_t>();
        else if (key == std::string("value")) {
          for (boost::property_tree::ptree::const_iterator it3 = it2->second.begin(); it3 != it2->second.end(); ++it3) {
            std::shared_ptr<monero_light_index_range> ir = std::make_shared<monero_light_index_range>();
            monero_light_index_range::from_property_tree(it3->second, ir);
            index_ranges.push_back(*ir);
          }
        }
      }

      if (_key == boost::none) throw std::runtime_error("Invalid subaddress");
      
      subaddrs->emplace(_key.get(), index_ranges);
    }
  }

  void monero_light_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_output>& output) {
    output->m_spend_key_images = std::vector<std::string>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("tx_id")) output->m_tx_id = it->second.get_value<uint64_t>();
      else if (key == std::string("amount")) output->m_amount = it->second.data();
      else if (key == std::string("index")) output->m_index = it->second.get_value<uint64_t>();
      else if (key == std::string("global_index")) output->m_global_index = it->second.data();
      else if (key == std::string("rct")) output->m_rct = it->second.data();
      else if (key == std::string("tx_hash")) output->m_tx_hash = it->second.data();
      else if (key == std::string("tx_prefix_hash")) output->m_tx_prefix_hash = it->second.data();
      else if (key == std::string("public_key")) output->m_public_key = it->second.data();
      else if (key == std::string("tx_pub_key")) output->m_tx_pub_key = it->second.data();
      else if (key == std::string("spend_key_images")) {
        output->m_spend_key_images = std::vector<std::string>();
        for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
      }
      else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
      else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("recipient")) {
        std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();
        monero_light_address_meta::from_property_tree(it->second, recipient);
        output->m_recipient = *recipient;
      }
    }
  }

  void monero_light_rates::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_rates>& rates) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("AUD")) rates->m_aud = it->second.get_value<float>();
      else if (key == std::string("BRL")) rates->m_brl = it->second.get_value<float>();
      else if (key == std::string("BTC")) rates->m_btc = it->second.get_value<float>();
      else if (key == std::string("CAD")) rates->m_cad = it->second.get_value<float>();
      else if (key == std::string("CHF")) rates->m_chf = it->second.get_value<float>();
      else if (key == std::string("CNY")) rates->m_cny = it->second.get_value<float>();
      else if (key == std::string("EUR")) rates->m_eur = it->second.get_value<float>();
      else if (key == std::string("GBP")) rates->m_gbp = it->second.get_value<float>();
      else if (key == std::string("HKD")) rates->m_hkd = it->second.get_value<float>();
      else if (key == std::string("INR")) rates->m_inr = it->second.get_value<float>();
      else if (key == std::string("JPY")) rates->m_jpy = it->second.get_value<float>();
      else if (key == std::string("KRW")) rates->m_krw = it->second.get_value<float>();
      else if (key == std::string("MXN")) rates->m_mxn = it->second.get_value<float>();
      else if (key == std::string("NOK")) rates->m_nok = it->second.get_value<float>();
      else if (key == std::string("NZD")) rates->m_nzd = it->second.get_value<float>();
      else if (key == std::string("SEK")) rates->m_sek = it->second.get_value<float>();
      else if (key == std::string("SGD")) rates->m_sgd = it->second.get_value<float>();
      else if (key == std::string("TRY")) rates->m_try = it->second.get_value<float>();
      else if (key == std::string("USD")) rates->m_usd = it->second.get_value<float>();
      else if (key == std::string("RUB")) rates->m_rub = it->second.get_value<float>();
      else if (key == std::string("ZAR")) rates->m_zar = it->second.get_value<float>();
    }
  }

  void monero_light_spend::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_spend>& spend) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount")) spend->m_amount = it->second.data();
      else if (key == std::string("key_image")) spend->m_key_image = it->second.data();
      else if (key == std::string("tx_pub_key")) spend->m_tx_pub_key = it->second.data();
      else if (key == std::string("out_index")) spend->m_out_index = it->second.get_value<uint64_t>();
      else if (key == std::string("mixin")) spend->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("sender")) {
        std::shared_ptr<monero_light_address_meta> sender = std::make_shared<monero_light_address_meta>();
        monero_light_address_meta::from_property_tree(it->second, sender);
        spend->m_sender = *sender;
      }
    }
  }

  void monero_light_tx::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_tx>& transaction) {
    transaction->m_spent_outputs = std::vector<monero_light_spend>();
    std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("id")) transaction->m_id = it->second.get_value<uint64_t>();
      else if (key == std::string("hash")) transaction->m_hash = it->second.data();
      else if (key == std::string("timestamp")) transaction->m_timestamp = it->second.data();
      else if (key == std::string("total_received")) transaction->m_total_received = it->second.data();
      else if (key == std::string("total_sent")) transaction->m_total_sent = it->second.data();
      else if (key == std::string("fee")) transaction->m_fee = it->second.data();
      else if (key == std::string("unlock_time")) transaction->m_unlock_time = it->second.get_value<uint64_t>();
      else if (key == std::string("height")) transaction->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("spent_outputs")) {
        // deserialize monero_light_spend          
        boost::property_tree::ptree outs = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs.begin(); it2 != outs.end(); ++it2) {
          std::shared_ptr<monero_light_spend> out = std::make_shared<monero_light_spend>();
          monero_light_spend::from_property_tree(it2->second, out);
          transaction->m_spent_outputs->push_back(*out);
        }
      }
      else if (key == std::string("payment_id")) transaction->m_payment_id = it->second.data();
      else if (key == std::string("coinbase")) transaction->m_coinbase = it->second.get_value<bool>();
      else if (key == std::string("mempool")) transaction->m_mempool = it->second.get_value<bool>();
      else if (key == std::string("mixin")) transaction->m_mixin = it->second.get_value<uint32_t>();
      else if (key == std::string("recipient")) {
        monero_light_address_meta::from_property_tree(it->second, recipient);
      }
    }
    
    transaction->m_recipient = *recipient;
  }

  void monero_light_random_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output) {
    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("global_index")) random_output->m_global_index = it->second.data();
      else if (key == std::string("public_key")) random_output->m_public_key = it->second.data();
      else if (key == std::string("rct")) random_output->m_rct = it->second.data();
    }
  }

  void monero_light_random_outputs::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_outputs>& random_outputs) {
    // convert config property tree to monero_wallet_config
    random_outputs->m_outputs = std::vector<monero_light_random_output>();

    for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount")) random_outputs->m_amount = it->second.data();
      else if (key == std::string("outputs")) {
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_random_output> out = std::make_shared<monero_light_random_output>();
          monero_light_random_output::from_property_tree(it2->second, out);
          random_outputs->m_outputs->push_back(*out);
        }
      }
    }
  }

  // ------------------------------- SERIALIZE UTILS -------------------------------

  rapidjson::Value monero_light_subaddrs::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    rapidjson::Value root(rapidjson::kArrayType);
    rapidjson::Value value_num(rapidjson::kNumberType);
    rapidjson::Value value_arr(rapidjson::kArrayType);

    for(auto subaddr : *this) {
      rapidjson::Value obj_value(rapidjson::kObjectType);
      monero_utils::add_json_member("key", subaddr.first, allocator, obj_value, value_num);
      std::vector<monero_light_index_range> index_ranges = subaddr.second;
      //obj_value.AddMember("value", monero_utils::to_rapidjson_val(allocator, index_ranges), allocator);
      rapidjson::Value obj_index_ranges(rapidjson::kArrayType);

      for (monero_light_index_range index_range : index_ranges) {
        obj_index_ranges.PushBack(monero_utils::to_rapidjson_val(allocator, (std::vector<uint32_t>)index_range), allocator);
      }

      obj_value.AddMember("value", obj_index_ranges, allocator);

      root.PushBack(obj_value, allocator);
    }

    return root;
  }

  rapidjson::Value monero_light_wallet_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
    if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_get_random_outs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_count != boost::none) monero_utils::add_json_member("count", m_count.get(), allocator, root, value_num);

    // set sub-arrays
    if (m_amounts != boost::none) root.AddMember("amounts", monero_utils::to_rapidjson_val(allocator, m_amounts.get()), allocator);

    // return root
    return root;
  }

  rapidjson::Value monero_light_import_wallet_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    // set number values
    rapidjson::Value value_num(rapidjson::kNumberType);
    if (m_from_height != boost::none) monero_utils::add_json_member("from_height", m_from_height.get(), allocator, root, value_num);

    // return root
    return root;
  }

  rapidjson::Value monero_light_get_unspent_outs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    rapidjson::Value value_num(rapidjson::kNumberType);

    if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_str);
    if (m_mixin != boost::none) monero_utils::add_json_member("mixin", m_mixin.get(), allocator, root, value_num);
    if (m_use_dust != boost::none) monero_utils::add_json_member("use_dust", m_use_dust.get(), allocator, root);
    if (m_dust_threshold != boost::none) monero_utils::add_json_member("dust_threshold", m_dust_threshold.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_login_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    if (m_create_account != boost::none) monero_utils::add_json_member("create_account", m_create_account.get(), allocator, root);
    if (m_generated_locally != boost::none) monero_utils::add_json_member("generated_locally", m_generated_locally.get(), allocator, root);

    // return root
    return root;
  }

  rapidjson::Value monero_light_submit_raw_tx_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

    // create root
    rapidjson::Value root(rapidjson::kObjectType);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_tx != boost::none) monero_utils::add_json_member("tx", m_tx.get(), allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_provision_subaddrs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    
    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    // set string values
    rapidjson::Value value_str(rapidjson::kStringType);
    if (m_maj_i != boost::none) monero_utils::add_json_member("maj_i", m_maj_i.get(), allocator, root, value_str);
    if (m_min_i != boost::none) monero_utils::add_json_member("min_i", m_min_i.get(), allocator, root, value_str);
    if (m_n_maj != boost::none) monero_utils::add_json_member("n_maj", m_n_maj.get(), allocator, root, value_str);
    if (m_n_min != boost::none) monero_utils::add_json_member("n_min", m_n_min.get(), allocator, root, value_str);
    if (m_get_all != boost::none) monero_utils::add_json_member("get_all", m_get_all.get(), allocator, root, value_str);
    else monero_utils::add_json_member("get_all", true, allocator, root, value_str);

    // return root
    return root;
  }

  rapidjson::Value monero_light_upsert_subaddrs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    
    // create root
    rapidjson::Value root = monero_light_wallet_request::to_rapidjson_val(allocator);

    if (m_subaddrs != boost::none) root.AddMember("subaddrs", m_subaddrs.get().to_rapidjson_val(allocator), allocator);
    if (m_get_all != boost::none) monero_utils::add_json_member("get_all", m_get_all.get(), allocator, root);

    // return root
    return root;
  }

  // ------------------------------- COPY UTILS -------------------------------

  std::shared_ptr<monero_light_spend> monero_light_spend::copy(const std::shared_ptr<monero_light_spend>& src, const std::shared_ptr<monero_light_spend>& tgt) const {
    if (this != src.get()) throw std::runtime_error("this spend != src");
    // copy wallet extensions
    tgt->m_amount = src->m_amount;
    tgt->m_key_image = src->m_key_image;
    tgt->m_tx_pub_key = src->m_tx_pub_key;
    tgt->m_out_index = src->m_out_index;
    tgt->m_mixin = src->m_mixin;
    tgt->m_sender = src->m_sender;

    return tgt;
  }

  std::shared_ptr<monero_light_tx> monero_light_tx::copy(const std::shared_ptr<monero_light_tx>& src, const std::shared_ptr<monero_light_tx>& tgt, bool exclude_spend) const {
    if (this != src.get()) throw std::runtime_error("this light_tx != src");

    // copy wallet extensions
    tgt->m_id = src->m_id;
    tgt->m_hash = src->m_hash;
    tgt->m_timestamp = src->m_timestamp;
    tgt->m_total_received = src->m_total_received;
    tgt->m_total_sent = src->m_total_sent;
    tgt->m_fee = src->m_fee;
    tgt->m_unlock_time = src->m_unlock_time;
    tgt->m_height = src->m_height;
    tgt->m_payment_id = src->m_payment_id;
    tgt->m_coinbase = src->m_coinbase;
    tgt->m_mempool = src->m_mempool;
    tgt->m_mixin = src->m_mixin;
    tgt->m_recipient = src->m_recipient;
    tgt->m_spent_outputs = std::vector<monero_light_spend>();

    if (exclude_spend) {
      return tgt;
    }

    if (!src->m_spent_outputs.get().empty()) {
      for (const monero_light_spend& spent_output : src->m_spent_outputs.get()) {
        std::shared_ptr<monero_light_spend> spent_output_ptr = std::make_shared<monero_light_spend>(spent_output);
        std::shared_ptr<monero_light_spend> spent_output_copy = spent_output_ptr->copy(spent_output_ptr, std::make_shared<monero_light_spend>());
        tgt->m_spent_outputs.get().push_back(*spent_output_copy);
      }
    }

    return tgt;
  }

  // ------------------------------- OUTPUT CONTAINER UTILS -------------------------------

  std::vector<size_t> monero_light_output_container::get_indexes(const std::vector<monero_light_output> &outputs) const {
    std::vector<size_t> indexes;

    for (const auto &output : outputs) {
      std::string public_key = output.m_public_key.get();
      auto it = m_index.find(public_key);

      if (it == m_index.end()) throw std::runtime_error("output doesn't belong to the wallet");

      indexes.push_back(it->second);
    }

    return indexes;
  }

  std::vector<monero_light_output> monero_light_output_container::get(uint32_t account_idx) const {
    auto all = get_spent(account_idx);
    auto unspent = get_unspent(account_idx);
    all.insert(all.end(), unspent.begin(), unspent.end());
    return all;
  }

  std::vector<monero_light_output> monero_light_output_container::get(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto all = get_spent(account_idx, subaddress_idx);
    auto unspent = get_unspent(account_idx, subaddress_idx);
    all.insert(all.end(), unspent.begin(), unspent.end());
    return all;
  }

  std::vector<monero_light_output> monero_light_output_container::get_unspent(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_unspent.find(account_idx);
    if (it1 == m_unspent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      m_unspent[account_idx][subaddress_idx] = empty_result;
      return empty_result;
    }
    else {
      // account found
      auto subaddresses_map = it1->second;
      auto it2 = subaddresses_map.find(subaddress_idx);

      if (it2 == subaddresses_map.end()) {
        // subaddress not found
        std::vector<monero_light_output> empty_result;
        m_unspent[account_idx][subaddress_idx] = empty_result;
        return empty_result;
      }

      // subaddress found
      return it2->second;
    }
  }

  std::vector<monero_light_output> monero_light_output_container::get_spent(uint32_t account_idx, uint32_t subaddress_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_spent.find(account_idx);
    if (it1 == m_spent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      m_spent[account_idx][subaddress_idx] = empty_result;
      return empty_result;
    }
    else {
      // account found
      auto subaddresses_map = it1->second;
      auto it2 = subaddresses_map.find(subaddress_idx);

      if (it2 == subaddresses_map.end()) {
        // subaddress not found
        std::vector<monero_light_output> empty_result;
        m_spent[account_idx][subaddress_idx] = empty_result;
        return empty_result;
      }

      // subaddress found
      return it2->second;
    }
  }

  std::vector<monero_light_output> monero_light_output_container::get_spent(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_spent.find(account_idx);
    if (it1 == m_spent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      return empty_result;
    }
    else {
      // account found
      auto subaddresses_map = it1->second;
      std::vector<monero_light_output> result;

      for (const auto &kv : subaddresses_map) {
        result.insert(result.end(), kv.second.begin(), kv.second.end());
      }
      
      return result;
    }
  }

  std::vector<monero_light_output> monero_light_output_container::get_unspent(uint32_t account_idx) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it1 = m_unspent.find(account_idx);
    if (it1 == m_unspent.end()) {
      // account not found
      std::vector<monero_light_output> empty_result;
      return empty_result;
    }
    else {
      // account found
      auto subaddresses_map = it1->second;
      std::vector<monero_light_output> result;

      for (const auto &kv : subaddresses_map) {
        result.insert(result.end(), kv.second.begin(), kv.second.end());
      }
      
      return result;
    }
  }

  std::vector<monero_light_output> monero_light_output_container::get_by_tx_hash(const std::string& tx_hash, bool filter_spent) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_tx_hash_index.find(tx_hash);
    if (it == m_tx_hash_index.end()) return std::vector<monero_light_output>();
    if (!filter_spent) {
      if (tx_hash == std::string("38fc273b709053bf5bf28c945e130627e11d28ec4983c39c7a373e1add7a4ee7")) std::cout << "monero_light_output_container::get_by_tx_hash(): returning saved " << it->second.size() << " outputs" << std::endl;
      return it->second;
    }
    std::vector<monero_light_output> outputs;
    for (const auto &output : it->second) {
      if (!output.is_spent()) outputs.push_back(output);
    }
    std::cout << "monero_light_output_container::get_by_tx_hash(): returning filtered " << outputs.size() << " outputs" << std::endl;

    return outputs;
  }

  void monero_light_output_container::set(const monero_light_tx_container& tx_container, const monero_light_get_unspent_outs_response& response) {
    clear();
    if (response.m_outputs == boost::none) return;
    std::vector<monero_light_output> outputs = response.m_outputs.get();
    std::vector<monero_light_output> spent;
    std::vector<monero_light_output> unspent;
    size_t index = 0;
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);

    for (const auto &output : outputs) {
      if (output.is_spent() || (output.key_image_is_known() && tx_container.is_key_image_in_pool(output.m_key_image.get()))) spent.push_back(output);
      else unspent.push_back(output);
      m_index[output.m_public_key.get()] = index;
      
      if (output.key_image_is_known()) {
        std::string output_key_image = output.m_key_image.get();
        m_key_image_index[output_key_image] = index;
      }

      std::string tx_hash = output.m_tx_hash.get();

      auto tx_hash_it = m_tx_hash_index.find(tx_hash);

      if (tx_hash_it == m_tx_hash_index.end()) {
        m_tx_hash_index[tx_hash] = std::vector<monero_light_output>();
        tx_hash_it = m_tx_hash_index.find(tx_hash);
      }

      tx_hash_it->second.push_back(output);
      index++;
    }

    set(spent, unspent);
    m_all = outputs;
  }

  void monero_light_output_container::set(const std::vector<monero_light_output>& spent, const std::vector<monero_light_output>& unspent) {
    set_spent(spent);
    set_unspent(unspent);
  }

  void monero_light_output_container::set_spent(const std::vector<monero_light_output>& outputs) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto &output : outputs) {
      auto address_meta = output.m_recipient;
      uint32_t account_idx = address_meta == boost::none ? 0 : address_meta->m_maj_i.get();
      uint32_t subaddress_idx = address_meta == boost::none ? 0 : address_meta->m_min_i.get();

      auto account_it = m_spent.find(account_idx);
      if (account_it == m_spent.end()) {
        m_spent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        account_it = m_spent.find(account_idx);
      }

      auto subaddress_it = account_it->second.find(subaddress_idx);
      if (subaddress_it == account_it->second.end()) {
        m_spent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        subaddress_it = account_it->second.find(subaddress_idx);
      }

      subaddress_it->second.push_back(output);
    }
    m_num_spent = outputs.size();
  }

  void monero_light_output_container::set_key_image_spent(const std::string& key_image, bool spent) {
    m_key_image_status_index[key_image] = spent;
  }

  void monero_light_output_container::set_unspent(const std::vector<monero_light_output>& outputs) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto &output : outputs) {
      auto address_meta = output.m_recipient;
      uint32_t account_idx = address_meta == boost::none ? 0 : address_meta->m_maj_i.get();
      uint32_t subaddress_idx = address_meta == boost::none ? 0 : address_meta->m_min_i.get();

      auto account_it = m_unspent.find(account_idx);
      if (account_it == m_unspent.end()) {
        m_unspent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        account_it = m_unspent.find(account_idx);
      }

      auto subaddress_it = account_it->second.find(subaddress_idx);
      if (subaddress_it == account_it->second.end()) {
        m_unspent[account_idx][subaddress_idx] = std::vector<monero_light_output>();
        subaddress_it = account_it->second.find(subaddress_idx);
      }

      subaddress_it->second.push_back(output);
    }
    m_num_unspent = outputs.size();
  }

  bool monero_light_output_container::is_used(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto outputs = get(account_idx, subaddress_idx);
    return !outputs.empty();
  }

  uint64_t monero_light_output_container::get_num_unspent(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto unspent = get_unspent(account_idx, subaddress_idx);
    return unspent.size();
  }

  void monero_light_output_container::clear_balance() {
    m_account_balance.clear();
    m_account_unlocked_balance.clear();
    m_subaddress_balance.clear();
    m_subaddress_unlocked_balance.clear();
    m_balance = 0;
    m_unlocked_balance = 0;
  }

  void monero_light_output_container::clear() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_index.clear();
    m_key_image_index.clear();
    m_tx_hash_index.clear();
    m_unspent.clear();
    m_spent.clear();
    clear_balance();
  }

  void monero_light_output_container::clear_frozen() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_frozen_key_image_index.clear();
  }

  void monero_light_output_container::calculate_balance(const monero_light_tx_container& tx_container, uint64_t current_height) {
    clear_balance();
    for (const auto &kv : m_unspent) {
      uint32_t account_idx = kv.first;
      uint64_t account_balance = 0;
      uint64_t account_unlocked_balance = 0;
      
      for (const auto &kv2 : kv.second) {
        uint32_t subaddress_idx = kv2.first;
        uint64_t subaddress_balance = 0;
        uint64_t subaddress_unlocked_balance = 0;
      
        for(const auto &output : kv2.second) {
          if (output.key_image_is_known() && tx_container.is_key_image_in_pool(output.m_key_image.get())) continue;
          bool is_locked = tx_container.is_locked(output, current_height);
          uint64_t amount = gen_utils::uint64_t_cast(output.m_amount.get());
          subaddress_balance += amount;
          if (!is_locked) subaddress_unlocked_balance += amount;
        }

        account_balance += subaddress_balance;
        account_unlocked_balance += subaddress_unlocked_balance;

        m_subaddress_balance[account_idx][subaddress_idx] = subaddress_balance;
        m_subaddress_unlocked_balance[account_idx][subaddress_idx] = subaddress_unlocked_balance;
      }

      m_balance += account_balance;
      m_unlocked_balance += account_unlocked_balance;

      m_account_balance[account_idx] = account_balance;
      m_account_unlocked_balance[account_idx] = account_unlocked_balance;
    }

    // consider also unconfirmed txs
    for (const auto &kv : tx_container.get_unconfirmed_txs()) {
      const auto &tx = kv.second;

      if (tx->m_is_relayed != true || tx->m_is_failed == true) continue;

      uint64_t change_amount = 0;

      if (tx->m_change_amount != boost::none) change_amount = tx->m_change_amount.get();

      m_balance += change_amount;
      m_account_balance[0] += change_amount;
      m_subaddress_balance[0][0] += change_amount;

      for (const std::shared_ptr<monero_output> &out : tx->m_outputs) {
        std::shared_ptr<monero_output_wallet> output = std::dynamic_pointer_cast<monero_output_wallet>(out);
        if (output == nullptr) {
          std::cout << "could not dynamic cast output monero_output* to monero_output_wallet*" << std::endl;
          continue;
        }
        
        if (output->m_account_index == boost::none) throw std::runtime_error("output account index is none");
        if (output->m_subaddress_index == boost::none) throw std::runtime_error("output subaddress index is none");
        if (output->m_amount == boost::none) throw std::runtime_error("output amount is none");

        uint32_t account_idx = output->m_account_index.get();
        uint32_t subaddress_idx = output->m_subaddress_index.get();
        uint64_t output_amount = output->m_amount.get();

        std::cout << "casted output to monero_output_wallet*, amount: " << output_amount << ", account idx: " << account_idx << ", subaddress idx: " << subaddress_idx << std::endl;

        auto account_it = m_account_balance.find(account_idx);
        if (account_it == m_account_balance.end()) {
          m_account_balance[account_idx] = output_amount;
          m_account_unlocked_balance[account_idx] = 0;
          m_subaddress_balance[account_idx][subaddress_idx] = output_amount;
        }
        else {
          m_account_balance[account_idx] += output_amount;

          auto subaddr_it = m_subaddress_balance[account_idx].find(subaddress_idx);
          if (subaddr_it == m_subaddress_balance[account_idx].end()) {
            m_subaddress_balance[account_idx][subaddress_idx] = output_amount;
          }
          else m_subaddress_balance[account_idx][subaddress_idx] += output_amount;
        }
        m_balance += output_amount;
      }
    }
  }

  uint64_t monero_light_output_container::get_balance(uint32_t account_idx) const {
    auto it = m_account_balance.find(account_idx);
    if (it == m_account_balance.end()) return 0;
    return it->second;
  }

  uint64_t monero_light_output_container::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto it = m_subaddress_balance.find(account_idx);
    if (it == m_subaddress_balance.end()) return 0;
    auto it2 = it->second.find(subaddress_idx);
    if (it2 == it->second.end()) return 0;
    return it2->second;
  }

  uint64_t monero_light_output_container::get_unlocked_balance(uint32_t account_idx) const {
    auto it = m_account_unlocked_balance.find(account_idx);
    if (it == m_account_unlocked_balance.end()) return 0;
    return it->second;
  }

  uint64_t monero_light_output_container::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto it = m_subaddress_unlocked_balance.find(account_idx);
    if (it == m_subaddress_unlocked_balance.end()) return 0;
    auto it2 = it->second.find(subaddress_idx);
    if (it2 == it->second.end()) return 0;
    return it2->second;
  }

  void validate_key_image(const std::string& key_image) {
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key image: " + key_image);
  }

  void monero_light_output_container::freeze(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to freeze");
    validate_key_image(key_image);
    auto key_it = m_key_image_index.find(key_image);
    if (key_it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    size_t index = key_it->second;
    m_frozen_key_image_index[index] = true;
  }

  void monero_light_output_container::thaw(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to thaw");
    validate_key_image(key_image);
    auto key_it = m_key_image_index.find(key_image);
    if (key_it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    size_t index = key_it->second;
    m_frozen_key_image_index[index] = false;
  }

  bool monero_light_output_container::is_frozen(const std::string& key_image) const {
    validate_key_image(key_image);
    auto key_it = m_key_image_index.find(key_image);
    if (key_it == m_key_image_index.end()) throw std::runtime_error("Key image not found");
    size_t index = key_it->second;
    auto frozen_it = m_frozen_key_image_index.find(index);
    if (frozen_it == m_frozen_key_image_index.end()) return false;
    return frozen_it->second;
  }

  bool monero_light_output_container::is_frozen(const monero_light_output& output) const {
    return is_frozen(output.m_key_image == boost::none ? "" : output.m_key_image.get());
  }

  void monero_light_output_container::set_key_image(const std::string& key_image, size_t index) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_key_image_index[key_image] = index;
  }

  std::tuple<uint64_t, uint64_t, std::vector<tools::wallet2::exported_transfer_details>> monero_light_output_container::export_outputs(const monero_light_tx_container& tx_container, monero_key_image_cache& key_image_cache, bool all, uint32_t start, uint32_t count) const {
    std::vector<tools::wallet2::exported_transfer_details> outs;

    // invalid cases
    if(count == 0) throw std::runtime_error("Nothing requested");
    if(!all && start > 0) throw std::runtime_error("Incremental mode is incompatible with non-zero start");

    // valid cases:
    // all: all outputs, subject to start/count
    // !all: incremental, subject to count
    // for convenience, start/count are allowed to go past the valid range, then nothing is returned
    const auto &unspent_outs = m_all;

    size_t offset = 0;    
    if (!all)
      while (offset < unspent_outs.size() && (unspent_outs[offset].key_image_is_known() && !key_image_cache.request(unspent_outs[offset].m_tx_pub_key.get(), unspent_outs[offset].m_index.get(), unspent_outs[offset].m_recipient->m_maj_i.get(), unspent_outs[offset].m_recipient->m_min_i.get())))
        ++offset;
    else
      offset = start;

    outs.reserve(unspent_outs.size() - offset);
    for (size_t n = offset; n < unspent_outs.size() && n - offset < count; ++n)
    {
      const auto &out = unspent_outs[n];
      uint64_t out_amount = gen_utils::uint64_t_cast(*out.m_amount);
      auto internal_output_index = *out.m_index;
      std::string tx_hash = out.m_tx_hash.get();

      uint64_t unlock_time = tx_container.get_unlock_time(tx_hash);

      tools::wallet2::exported_transfer_details etd;
      
      crypto::public_key public_key;
      crypto::public_key tx_pub_key;

      epee::string_tools::hex_to_pod(*out.m_public_key, public_key);
      epee::string_tools::hex_to_pod(*out.m_tx_pub_key, tx_pub_key);

      cryptonote::transaction_prefix tx_prefix;

      add_tx_pub_key_to_extra(tx_prefix, tx_pub_key);

      cryptonote::tx_out txout;
      txout.target = cryptonote::txout_to_key(public_key);
      txout.amount = out_amount;
      tx_prefix.vout.resize(internal_output_index + 1);
      tx_prefix.vout[internal_output_index] = txout;
      tx_prefix.unlock_time = unlock_time;

      etd.m_pubkey = public_key;
      etd.m_tx_pubkey = tx_pub_key; // pk_index?
      etd.m_internal_output_index = internal_output_index;
      etd.m_global_output_index = gen_utils::uint64_t_cast(*out.m_global_index);
      etd.m_flags.flags = 0;
      etd.m_flags.m_spent = out.is_spent();
      etd.m_flags.m_frozen = false;
      etd.m_flags.m_rct = out.rct();
      etd.m_flags.m_key_image_known = out.key_image_is_known();
      etd.m_flags.m_key_image_request = false; //td.m_key_image_request;
      etd.m_flags.m_key_image_partial = false;
      etd.m_amount = out_amount;
      etd.m_additional_tx_keys = get_additional_tx_pub_keys_from_extra(tx_prefix);
      etd.m_subaddr_index_major = *out.m_recipient->m_maj_i;
      etd.m_subaddr_index_minor = *out.m_recipient->m_min_i;

      outs.push_back(etd);
    }

    return std::make_tuple(offset, unspent_outs.size(), outs);
  }

  // ------------------------------- TX CONTAINER UTILS -------------------------------

  monero_light_tx monero_light_tx_container::get(const std::string& hash) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_txs.find(hash);
    if (it == m_txs.end()) throw std::runtime_error("tx not found in container");
    return it->second;
  }

  monero_light_tx monero_light_tx_container::get(const monero_light_output& output) const {
    return get(output.m_tx_hash.get());
  }

  uint64_t monero_light_tx_container::get_unlock_time(const std::string& hash) const {
    const auto &tx = get(hash);
    return tx.m_unlock_time.get();
  }

  void monero_light_tx_container::set(const monero_light_get_address_txs_response& response, const monero_light_get_address_info_response& addr_info_response) {
    clear();
    if (response.m_transactions == boost::none) return;
    set(response.m_transactions.get());

    if (addr_info_response.m_spent_outputs == boost::none)

    for (const auto &spend : addr_info_response.m_spent_outputs.get()) {
      if (spend.m_key_image != boost::none) {
        m_spent_key_images[spend.m_key_image.get()] = true;
      }
    }
  }

  void monero_light_tx_container::set(const monero_light_tx& tx) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_txs[tx.m_hash.get()] = tx;
  }

  void monero_light_tx_container::add_key_images_to_pool(const std::shared_ptr<monero_tx_wallet>& tx) {
    if (tx->m_is_relayed != true) {
      std::cout << "monero_light_tx_container::add_key_images_to_pool(): skipping non relayed tx" << std::endl;
      return;
    }
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    std::string tx_hash = tx->m_hash.get();
    m_pool_key_images.erase(tx_hash);
    std::vector<std::string> key_images;

    for(const auto &in : tx->m_inputs) {
      std::shared_ptr<monero_output_wallet> input = std::static_pointer_cast<monero_output_wallet>(in);
        
      if (input == nullptr) {
        throw std::runtime_error("Expected input monero_output_wallet");
      }

      if (input->m_key_image == boost::none || input->m_key_image.get()->m_hex == boost::none || input->m_key_image.get()->m_hex->empty()) throw std::runtime_error("Input key image is none");
      std::string key_image = input->m_key_image.get()->m_hex.get();
      key_images.push_back(key_image);
      std::cout << "monero_light_tx_container::add_key_images_to_pool(): added key image " << key_image << std::endl;
    }

    if (key_images.size() > 0) m_pool_key_images[tx_hash] = key_images;
  }

  void monero_light_tx_container::set_unconfirmed(const std::shared_ptr<monero_tx_wallet>& tx) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    if (tx->m_hash == boost::none) throw std::runtime_error("Cannot set none unconfirmed tx hash");
    std::string tx_hash = tx->m_hash.get();
    if (tx_hash.empty()) throw std::runtime_error("Cannot set empty unconfirmed tx hash");
    std::cout << "monero_light_tx_container::set_unconfirmed(" << tx_hash << "): setting unconfirmed" << std::endl;
    m_unconfirmed_txs[tx_hash] = tx;
    add_key_images_to_pool(tx);
  }

  void monero_light_tx_container::remove_unconfirmed(const std::string& hash) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_unconfirmed_txs.erase(hash);
    m_pool_key_images.erase(hash);
  }

  void monero_light_tx_container::set_relayed(const std::string& hash) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    auto it = m_unconfirmed_txs.find(hash);
    if (it == m_unconfirmed_txs.end()) {
      std::cout << "monero_light_tx_container::set_relayed(" << hash << "): not found" << std::endl;
      return;
    }
    it->second->m_in_tx_pool = true;
    it->second->m_is_locked = true;
    it->second->m_is_relayed = true;
    it->second->m_relay = true;
    it->second->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));
    it->second->m_is_failed = false;
    it->second->m_is_double_spend_seen = false;
    add_key_images_to_pool(it->second);
    std::cout << "monero_light_tx_container::set_relayed(" << hash << "): set relayed" << std::endl;
  }

  void monero_light_tx_container::set(const std::vector<monero_light_tx>& txs, bool clear_txs) {
    if (clear_txs) clear();
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for(const auto &tx : txs) {
      std::string tx_hash = tx.m_hash.get();
      bool confirmed = !tx.m_mempool.get();
      m_txs[tx_hash] = tx;
      if (confirmed) remove_unconfirmed(tx_hash);
    }
  }

  uint64_t monero_light_tx_container::calculate_num_blocks_to_unlock(const std::string& hash, uint64_t current_height) const {
    monero_light_tx tx = get(hash);
    uint64_t tx_height = tx.m_mempool.get() ? current_height : tx.m_height.get();
    uint64_t unlock_time = tx.m_unlock_time.get();
    uint64_t default_spendable_age = tx_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
    uint64_t confirmations_needed = default_spendable_age > current_height ? default_spendable_age - current_height : 0;
    uint64_t num_blocks_to_unlock = unlock_time <= current_height ? 0 : unlock_time - current_height;
    return num_blocks_to_unlock > confirmations_needed ? num_blocks_to_unlock : confirmations_needed;
  }

  uint64_t monero_light_tx_container::calculate_num_blocks_to_unlock(const std::vector<std::string>& hashes, uint64_t current_height) const {
    uint64_t num_blocks = 0;
    for(const std::string& hash : hashes) {
      uint64_t blocks = calculate_num_blocks_to_unlock(hash, current_height);
      if (blocks > num_blocks) num_blocks = blocks;
    }
    return num_blocks;
  }

  uint64_t monero_light_tx_container::calculate_num_blocks_to_unlock(const std::vector<monero_light_output>& outputs, uint64_t current_height) const {
    std::vector<std::string> hashes;

    for(const auto &output : outputs) {
      if (output.m_tx_hash == boost::none) continue;
      hashes.push_back(output.m_tx_hash.get());
    }

    return calculate_num_blocks_to_unlock(hashes, current_height);
  }

  uint64_t monero_light_tx_container::calculate_num_blocks_to_unlock(const monero_light_output& output, uint64_t current_height) const {
    return calculate_num_blocks_to_unlock(output.m_tx_hash.get(), current_height);
  }

  bool monero_light_tx_container::is_locked(const std::string& hash, uint64_t current_height) const {
    return calculate_num_blocks_to_unlock(hash, current_height) > 0;
  }

  bool monero_light_tx_container::is_locked(const monero_light_output& output, uint64_t current_height) const {
    return is_locked(output.m_tx_hash.get(), current_height);
  }

  bool monero_light_tx_container::is_confirmed(const std::string& hash) const {
    monero_light_tx tx = get(hash);
    return tx.m_mempool == false;
  }

  void monero_light_tx_container::add_tx_key(const crypto::secret_key &tx_key, const crypto::hash &tx_id, const std::vector<crypto::secret_key>& additional_tx_keys) {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_tx_keys[tx_id] = tx_key;
    m_additional_tx_keys[tx_id] = additional_tx_keys;
  }

  bool monero_light_tx_container::get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const {
    additional_tx_keys.clear();
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    const std::unordered_map<crypto::hash, crypto::secret_key>::const_iterator i = m_tx_keys.find(txid);
    if (i == m_tx_keys.end())
      return false;
    tx_key = i->second;
    if (tx_key == crypto::null_skey)
      return false;
    const auto j = m_additional_tx_keys.find(txid);
    if (j != m_additional_tx_keys.end())
      additional_tx_keys = j->second;
    return true;
  }

  bool monero_light_tx_container::is_key_image_in_pool(const std::string& key_image) const {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    for (const auto &kv : m_pool_key_images) {
      for(const std::string &pool_key_image : kv.second) {
        if (key_image == pool_key_image) return true;
      }
    }
    return false;
  }

  bool monero_light_tx_container::is_key_image_spent(const std::string& key_image) const {
    if (is_key_image_in_pool(key_image)) return true;
    auto it = m_spent_key_images.find(key_image);
    if (it == m_spent_key_images.end()) return false;
    return it->second;
  }

  bool monero_light_tx_container::is_key_image_spent(const crypto::key_image& key_image) const {
    std::string key_image_str = epee::string_tools::pod_to_hex(key_image);
    return is_key_image_spent(key_image_str);
  }

  bool monero_light_tx_container::is_key_image_spent(const std::shared_ptr<monero_key_image>& key_image) const {
    if (key_image == nullptr) throw std::runtime_error("key image is null");
    return is_key_image_spent(*key_image);
  }

  bool monero_light_tx_container::is_key_image_spent(const monero_key_image& key_image) const {
    if (key_image.m_hex == boost::none) return false;
    return is_key_image_spent(key_image.m_hex.get());
  }

  void monero_light_tx_container::clear_unconfirmed() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_unconfirmed_txs.clear();
    m_pool_key_images.clear();
  }

  void monero_light_tx_container::clear() {
    boost::lock_guard<boost::recursive_mutex> lock(m_mutex);
    m_txs.clear();
    m_spent_key_images.clear();
  }

}