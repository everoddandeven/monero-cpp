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

#include "wallet/wallet_rpc_server_commands_defs.h"
#include "monero_wallet_light.h"
#include "utils/monero_utils.h"
#include <thread>
#include <chrono>
#include <iostream>
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "string_tools.h"
#include "device/device.hpp"
#include "common/threadpool.h"
#define KEY_IMAGE_EXPORT_FILE_MAGIC "Monero key image export\003"

#define MULTISIG_EXPORT_FILE_MAGIC "Monero multisig export\001"

#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\004"

#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\005"

using namespace epee;
using namespace tools;
using namespace crypto;

/**
 * Public library interface.
 */
namespace monero {

// ------------------------------- DESERIALIZE UTILS -------------------------------

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
};

std::shared_ptr<monero_light_output> monero_light_output::deserialize(const std::string& config_json) {
  // deserialize monero output json to property node
  std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);

  // convert config property tree to monero_wallet_config
  std::shared_ptr<monero_light_output> output = std::make_shared<monero_light_output>();
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
      else if (key == std::string("spend_key_images")) for (boost::property_tree::ptree::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) output->m_spend_key_images.get().push_back(it2->second.data());
      else if (key == std::string("timestamp")) output->m_timestamp = it->second.data();
      else if (key == std::string("height")) output->m_height = it->second.get_value<uint64_t>();
      else if (key == std::string("recipient")) {
        std::shared_ptr<monero_light_address_meta> recipient = std::make_shared<monero_light_address_meta>();
        monero_light_address_meta::from_property_tree(it->second, recipient);
        output->m_recipient = *recipient;
      }
  }

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

  return spend;
}

std::shared_ptr<monero_light_transaction> monero_light_transaction::deserialize(const std::string& config_json) {
  // deserialize monero output json to property node
  std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);

  // convert config property tree to monero_wallet_config
  std::shared_ptr<monero_light_transaction> transaction = std::make_shared<monero_light_transaction>();
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
      else if (key == std::string("mixin")) transaction->m_height = it->second.get_value<uint32_t>();
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
  address_txs->m_transactions = std::vector<monero_light_transaction>();

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
          std::shared_ptr<monero_light_transaction> transaction = std::make_shared<monero_light_transaction>();
          monero_light_transaction::from_property_tree(it2->second, transaction);
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
  random_outs->m_amount_outs = std::vector<monero_light_random_output>();
  
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("amount_outs")) {
        boost::property_tree::ptree outs_node = it->second;
        for (boost::property_tree::ptree::const_iterator it2 = outs_node.begin(); it2 != outs_node.end(); ++it2) {
          std::shared_ptr<monero_light_random_output> out = std::make_shared<monero_light_random_output>();
          monero_light_random_output::from_property_tree(it2->second, out);
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

std::shared_ptr<monero_light_account> monero_light_account::deserialize(const std::string& config_json) {
  // deserialize monero output json to property node
  std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);

  // convert config property tree to monero_wallet_config
  std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
  
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("address")) account->m_address = it->second.data();
      else if (key == std::string("scan_height")) account->m_scan_height = it->second.get_value<uint64_t>();
      else if (key == std::string("access_time")) account->m_access_time = it->second.get_value<uint64_t>();
  }

  return account;
}

std::shared_ptr<monero_light_list_accounts_response> monero_light_list_accounts_response::deserialize(const std::string& config_json) {
  // deserialize monero output json to property node
  std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);

  // convert config property tree to monero_wallet_config
  std::shared_ptr<monero_light_list_accounts_response> accounts = std::make_shared<monero_light_list_accounts_response>();
  accounts->m_active = std::vector<monero_light_account>();
  accounts->m_inactive = std::vector<monero_light_account>();
  accounts->m_hidden = std::vector<monero_light_account>();

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("active")) {
          boost::property_tree::ptree accounts_node = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
            std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
            monero_light_account::from_property_tree(it2->second, account);
            accounts->m_active->push_back(*account);
          }
      }
      else if (key == std::string("inactive")) {
          boost::property_tree::ptree accounts_node = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
            std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
            monero_light_account::from_property_tree(it2->second, account);
            accounts->m_inactive->push_back(*account);
          }
      }
      else if (key == std::string("hidden")) {
          boost::property_tree::ptree accounts_node = it->second;
          for (boost::property_tree::ptree::const_iterator it2 = accounts_node.begin(); it2 != accounts_node.end(); ++it2) {
            std::shared_ptr<monero_light_account> account = std::make_shared<monero_light_account>();
            monero_light_account::from_property_tree(it2->second, account);
            accounts->m_hidden->push_back(*account);
          }
      }
  }

  return accounts;
}

std::shared_ptr<monero_light_list_requests_response> monero_light_list_requests_response::deserialize(const std::string& config_json) {
  // deserialize monero output json to property node
  std::istringstream iss = config_json.empty() ? std::istringstream() : std::istringstream(config_json);
  boost::property_tree::ptree node;
  boost::property_tree::read_json(iss, node);

  // convert config property tree to monero_wallet_config
  std::shared_ptr<monero_light_list_requests_response> requests = std::make_shared<monero_light_list_requests_response>();
  requests->m_create = std::vector<monero_light_create_account_request>();
  requests->m_import = std::vector<monero_light_import_account_request>();
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      
      if (key == std::string("create")) {
        std::shared_ptr<monero_light_create_account_request> request;
        monero_light_create_account_request::from_property_tree(it->second, request);
        requests->m_create->push_back(*request);
      }
      else if (key == std::string("import")) {
        std::shared_ptr<monero_light_import_account_request> request;
        monero_light_import_account_request::from_property_tree(it->second, request);
        requests->m_import->push_back(*request);
      }
  }

  return requests;
}

// ------------------------------- PROPERTY TREE UTILS -------------------------------

monero_lws_connection monero_lws_connection::from_property_tree(const boost::property_tree::ptree& node) {
  monero_lws_connection *connection = new monero_lws_connection();

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("uri")) connection->m_uri = it->second.data();
      else if (key == std::string("port")) connection->m_port = it->second.data();
  }

  return *connection;
}

monero_lws_admin_connection monero_lws_admin_connection::from_property_tree(const boost::property_tree::ptree& node) {
  monero_lws_admin_connection *connection = new monero_lws_admin_connection();

  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("uri")) connection->m_uri = it->second.data();
      else if (key == std::string("port")) connection->m_port = it->second.data();
      else if (key == std::string("admin_uri")) connection->m_admin_uri = it->second.data();
      else if (key == std::string("admin_port")) connection->m_admin_port = it->second.data();
      else if (key == std::string("token")) connection->m_token = it->second.data();
  }

  return *connection;
}

void monero_light_address_meta::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_address_meta>& address_meta) {
  // convert config property tree to monero_wallet_config
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
    std::string key = it->first;

    if (key == std::string("maj_i")) address_meta->m_maj_i = it->second.get_value<uint32_t>();
    else if (key == std::string("min_i")) address_meta->m_min_i = it->second.get_value<uint32_t>();
  }
};

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
};

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
        for (boost::property_tree::ptree::const_iterator it3 = it2->second.begin(); it3 != it2->second.end(); ++it2) {
          std::shared_ptr<monero_light_index_range> ir = std::make_shared<monero_light_index_range>();
          monero_light_index_range::from_property_tree(it3->second, ir);
          index_ranges.push_back(*ir);
        }
      }
    }

    if (_key == boost::none) throw std::runtime_error("Invalid subaddress");

    subaddrs->emplace(_key.get(), index_ranges);
  }
};

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
  }
}

void monero_light_transaction::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_transaction>& transaction) {
  transaction->m_spent_outputs = std::vector<monero_light_spend>();
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
      else if (key == std::string("mixin")) transaction->m_height = it->second.get_value<uint32_t>();
  }
}

void monero_light_random_output::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_random_output>& random_output) {
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;

      if (key == std::string("global_index")) random_output->m_global_index = it->second.data();
      else if (key == std::string("public_key")) random_output->m_public_key = it->second.data();
      else if (key == std::string("rct")) random_output->m_rct = it->second.data();
  }
}

void monero_light_account::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_account>& account) {
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("address")) account->m_address = it->second.data();
      else if (key == std::string("scan_height")) account->m_scan_height = it->second.get_value<uint64_t>();
      else if (key == std::string("access_time")) account->m_access_time = it->second.get_value<uint64_t>();
  }
}

void monero_light_create_account_request::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_create_account_request>& request) {
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("address")) request->m_address = it->second.data();
      else if (key == std::string("start_height")) request->m_start_height = it->second.get_value<uint64_t>();
  }
}

void monero_light_import_account_request::from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_light_import_account_request>& request) {
  for (boost::property_tree::ptree::const_iterator it = node.begin(); it != node.end(); ++it) {
      std::string key = it->first;
      if (key == std::string("address")) request->m_address = it->second.data();
  }
}

// ------------------------------- SERIALIZE UTILS -------------------------------

rapidjson::Value monero_lws_connection::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);
  if (m_port != boost::none) monero_utils::add_json_member("port", m_port.get(), allocator, root, value_str);

  
  // return root
  return root;
}

rapidjson::Value monero_lws_admin_connection::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_uri != boost::none) monero_utils::add_json_member("uri", m_uri.get(), allocator, root, value_str);
  if (m_port != boost::none) monero_utils::add_json_member("port", m_port.get(), allocator, root, value_str);
  if (m_admin_uri != boost::none) monero_utils::add_json_member("admin_uri", m_admin_uri.get(), allocator, root, value_str);
  if (m_admin_port != boost::none) monero_utils::add_json_member("admin_port", m_admin_port.get(), allocator, root, value_str);
  if (m_token != boost::none) monero_utils::add_json_member("token", m_token.get(), allocator, root, value_str);
  
  // return root
  return root;
}

rapidjson::Value monero_light_get_address_info_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
  if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

  
  // return root
  return root;
}

rapidjson::Value monero_light_get_address_txs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

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

rapidjson::Value monero_light_import_request_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
  if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

  
  // return root
  return root;
}

rapidjson::Value monero_light_get_unspent_outs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
  if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
  if (m_amount != boost::none) monero_utils::add_json_member("amount", m_amount.get(), allocator, root, value_str);
  if (m_mixin != boost::none) monero_utils::add_json_member("mixin", m_mixin.get(), allocator, root, value_num);
  if (m_use_dust != boost::none) monero_utils::add_json_member("use_dust", m_use_dust.get(), allocator, root);
  if (m_dust_threshold != boost::none) monero_utils::add_json_member("dust_threshold", m_dust_threshold.get(), allocator, root, value_str);

  // return root
  return root;
}

rapidjson::Value monero_light_login_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, root, value_str);
  if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
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
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_address != boost::none) monero_utils::add_json_member("tx", m_address.get(), allocator, root, value_str);
  if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
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
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_address != boost::none) monero_utils::add_json_member("tx", m_address.get(), allocator, root, value_str);
  if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);
  
  // return root
  return root;
}

rapidjson::Value monero_light_get_subaddrs_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {
    // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  if (m_address != boost::none) monero_utils::add_json_member("tx", m_address.get(), allocator, root, value_str);
  if (m_view_key != boost::none) monero_utils::add_json_member("view_key", m_view_key.get(), allocator, root, value_str);

  // return root
  return root;
}

rapidjson::Value monero_light_accept_requests_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);
  rapidjson::Value parameters(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  rapidjson::Value value_obj(rapidjson::kObjectType);
  rapidjson::Value value_arr(rapidjson::kArrayType);

  if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
  if (m_type != boost::none) monero_utils::add_json_member("type", m_type.get(), allocator, parameters, value_str);
  if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
  
  //monero_utils::add_json_member("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator, parameters, value_arr);

  root.AddMember("parameters", parameters, allocator);

  // return root
  return root;
}

rapidjson::Value monero_light_add_account_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);
  rapidjson::Value parameters(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  rapidjson::Value value_obj(rapidjson::kObjectType);

  if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
  if (m_address != boost::none) monero_utils::add_json_member("address", m_address.get(), allocator, parameters, value_str);
  if (m_key != boost::none) monero_utils::add_json_member("key", m_key.get(), allocator, parameters, value_str);

  root.AddMember("parameters", parameters, allocator);

  // return root
  return root;
}

rapidjson::Value monero_light_list_accounts_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);

  if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);

  // return root
  return root;
}

rapidjson::Value monero_light_list_requests_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);

  if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);

  // return root
  return root;
}

rapidjson::Value monero_light_modify_account_status_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);
  rapidjson::Value parameters(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  rapidjson::Value value_obj(rapidjson::kObjectType);

  if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
  if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
  if (m_status != boost::none) monero_utils::add_json_member("key", m_status.get(), allocator, parameters, value_str);

  root.AddMember("parameters", parameters, allocator);

  // return root
  return root;
}

rapidjson::Value monero_light_reject_requests_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);
  rapidjson::Value parameters(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  rapidjson::Value value_obj(rapidjson::kObjectType);

  if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
  if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
  if (m_type != boost::none) monero_utils::add_json_member("type", m_type.get(), allocator, parameters, value_str);

  root.AddMember("parameters", parameters, allocator);

  // return root
  return root;
}

rapidjson::Value monero_light_rescan_request::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const {

  // create root
  rapidjson::Value root(rapidjson::kObjectType);
  rapidjson::Value parameters(rapidjson::kObjectType);

  // set string values
  rapidjson::Value value_str(rapidjson::kStringType);
  rapidjson::Value value_obj(rapidjson::kObjectType);

  if (m_token != boost::none) monero_utils::add_json_member("auth", m_token.get(), allocator, root, value_str);
  if (m_addresses != boost::none && !m_addresses.get().empty()) parameters.AddMember("addresses", monero_utils::to_rapidjson_val(allocator, m_addresses.get()), allocator);
  if (m_height != boost::none) monero_utils::add_json_member("height", m_height.get(), allocator, parameters, value_str);

  root.AddMember("parameters", parameters, allocator);

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

  return tgt;
}

std::shared_ptr<monero_light_transaction> monero_light_transaction::copy(const std::shared_ptr<monero_light_transaction>& src, const std::shared_ptr<monero_light_transaction>& tgt, bool exclude_spend) const {
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


  // --------------------------- STATIC WALLET UTILS --------------------------

  bool monero_wallet_light::wallet_exists(const std::string& path) {
    MTRACE("wallet_exists(" << path << ")");
    bool key_file_exists;
    bool wallet_file_exists;
    tools::wallet2::wallet_exists(path, key_file_exists, wallet_file_exists);
    return key_file_exists;
  }

  monero_wallet_light* monero_wallet_light::open_wallet(const std::string& path, const std::string& password, const monero_network_type network_type) {
    MTRACE("open_wallet(" << path << ", ***, " << network_type << ")");
    monero_wallet_light* wallet = new monero_wallet_light();
    wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(network_type), 1, true));
    wallet->m_w2->load(path, password);
    wallet->m_w2->init("");
    wallet->init_common();
    return wallet;
  }

  monero_wallet_light* monero_wallet_light::open_wallet_data(const std::string& password, const monero_network_type network_type, const std::string& keys_data, const std::string& cache_data, const monero_rpc_connection& daemon_connection, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("open_wallet_data(...)");
    monero_wallet_light* wallet = new monero_wallet_light();
    if (http_client_factory == nullptr) wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(network_type), 1, true));
    else wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(network_type), 1, true, std::move(http_client_factory)));
    wallet->m_w2->load("", password, keys_data, cache_data);
    wallet->m_w2->init("");
    wallet->set_daemon_connection(daemon_connection);
    wallet->init_common();
    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet(config)");

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config.m_path == boost::none) config_normalized.m_path = std::string("");
    if (config.m_password == boost::none) config_normalized.m_password = std::string("");
    if (config.m_language == boost::none) config_normalized.m_language = std::string("");
    if (config.m_seed == boost::none) config_normalized.m_seed = std::string("");
    if (config.m_primary_address == boost::none) config_normalized.m_primary_address = std::string("");
    if (config.m_private_spend_key == boost::none) config_normalized.m_private_spend_key = std::string("");
    if (config.m_private_view_key == boost::none) config_normalized.m_private_view_key = std::string("");
    if (config.m_seed_offset == boost::none) config_normalized.m_seed_offset = std::string("");
    if (config.m_is_multisig == boost::none) config_normalized.m_is_multisig = false;
    if (config.m_account_lookahead != boost::none && config.m_subaddress_lookahead == boost::none) throw std::runtime_error("No subaddress lookahead provided with account lookahead");
    if (config.m_account_lookahead == boost::none && config.m_subaddress_lookahead != boost::none) throw std::runtime_error("No account lookahead provided with subaddress lookahead");
    if (config_normalized.m_language.get().empty()) config_normalized.m_language = std::string("English");
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");

    // create wallet
    if (!config_normalized.m_seed.get().empty()) {
      return create_wallet_from_seed(config_normalized, std::move(http_client_factory));
    } else if (!config_normalized.m_primary_address.get().empty() || !config_normalized.m_private_spend_key.get().empty() || !config_normalized.m_private_view_key.get().empty()) {
      return create_wallet_from_keys(config_normalized, std::move(http_client_factory));
    } else {
      return create_wallet_random(config_normalized, std::move(http_client_factory));
    }
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_seed(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet_from_seed(...)");

    // normalize config
    if (config.m_restore_height == boost::none) config.m_restore_height = 0;

    // validate mnemonic and get recovery key and language if not multisig
    crypto::secret_key recovery_key;
    std::string language = config.m_language.get();
    if (!config.m_is_multisig.get()) {
      bool is_valid = crypto::ElectrumWords::words_to_bytes(config.m_seed.get(), recovery_key, language);
      if (!is_valid) throw std::runtime_error("Invalid mnemonic");
      if (language == crypto::ElectrumWords::old_language_name) language = config.m_language.get();
    }

    // validate language
    if (!crypto::ElectrumWords::is_valid_language(language)) throw std::runtime_error("Invalid language: " + language);

    // apply offset if given
    if (!config.m_seed_offset.get().empty()) recovery_key = cryptonote::decrypt_key(recovery_key, config.m_seed_offset.get());

    // initialize wallet
    monero_wallet_light* wallet = new monero_wallet_light();
    if (http_client_factory == nullptr) wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true));
    else wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true, std::move(http_client_factory)));
    wallet->set_daemon_connection(config.m_server);
    wallet->m_w2->set_seed_language(language);
    if (config.m_account_lookahead != boost::none) wallet->m_w2->set_subaddress_lookahead(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());

    // generate wallet
    if (config.m_is_multisig.get()) {

      // parse multisig data
      epee::wipeable_string multisig_data;
      multisig_data.resize(config.m_seed.get().size() / 2);
      if (!epee::from_hex::to_buffer(epee::to_mut_byte_span(multisig_data), config.m_seed.get())) throw std::runtime_error("Multisig seed not represented as hexadecimal string");

      // generate multisig wallet
      wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), multisig_data, false);
      wallet->m_w2->enable_multisig(true);
    } else {

      // generate normal wallet
      crypto::secret_key recovery_val = wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), recovery_key, true, false);

      // validate mnemonic
      epee::wipeable_string electrum_words;
      if (!crypto::ElectrumWords::bytes_to_words(recovery_val, electrum_words, language)) throw std::runtime_error("Failed to encode seed");
    }
    wallet->m_w2->set_refresh_from_block_height(config.m_restore_height.get());
    wallet->m_start_height = config.m_restore_height.get();
    wallet->init_common();
    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_keys(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet_from_keys(...)");

    // validate and normalize config
    if (config.m_restore_height == boost::none) config.m_restore_height = 0;
    if (!config.m_seed_offset.get().empty()) throw std::runtime_error("Cannot specify seed offset when creating wallet from keys");

    // parse and validate private spend key
    crypto::secret_key spend_key_sk;
    bool has_spend_key = false;
    if (!config.m_private_spend_key.get().empty()) {
      cryptonote::blobdata spend_key_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(config.m_private_spend_key.get(), spend_key_data) || spend_key_data.size() != sizeof(crypto::secret_key)) {
        throw std::runtime_error("failed to parse secret spend key");
      }
      has_spend_key = true;
      spend_key_sk = *reinterpret_cast<const crypto::secret_key*>(spend_key_data.data());
    }

    // parse and validate private view key
    bool has_view_key = true;
    crypto::secret_key view_key_sk;
    if (config.m_private_view_key.get().empty()) {
      if (has_spend_key) has_view_key = false;
      else throw std::runtime_error("Neither spend key nor view key supplied");
    }
    if (has_view_key) {
      cryptonote::blobdata view_key_data;
      if (!epee::string_tools::parse_hexstr_to_binbuff(config.m_private_view_key.get(), view_key_data) || view_key_data.size() != sizeof(crypto::secret_key)) {
        throw std::runtime_error("failed to parse secret view key");
      }
      view_key_sk = *reinterpret_cast<const crypto::secret_key*>(view_key_data.data());
    }

    // parse and validate address
    cryptonote::address_parse_info address_info;
    if (config.m_primary_address.get().empty()) {
      if (has_view_key) throw std::runtime_error("must provide primary address if providing private view key");
    } else {
      if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(config.m_network_type.get()), config.m_primary_address.get())) throw std::runtime_error("failed to parse address");

      // check the spend and view keys match the given address
      crypto::public_key pkey;
      if (has_spend_key) {
        if (!crypto::secret_key_to_public_key(spend_key_sk, pkey)) throw std::runtime_error("failed to verify secret spend key");
        if (address_info.address.m_spend_public_key != pkey) throw std::runtime_error("spend key does not match address");
      }
      if (has_view_key) {
        if (!crypto::secret_key_to_public_key(view_key_sk, pkey)) throw std::runtime_error("failed to verify secret view key");
        if (address_info.address.m_view_public_key != pkey) throw std::runtime_error("view key does not match address");
      }
    }

    // validate language
    if (!monero_utils::is_valid_language(config.m_language.get())) throw std::runtime_error("Unknown language: " + config.m_language.get());

    // initialize wallet
    // TODO: delete wallet pointer if exception
    monero_wallet_light* wallet = new monero_wallet_light();
    if (http_client_factory == nullptr) wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true));
    else wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true, std::move(http_client_factory)));
    if (config.m_account_lookahead != boost::none) wallet->m_w2->set_subaddress_lookahead(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
    if (has_spend_key && has_view_key) wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), address_info.address, spend_key_sk, view_key_sk);
    else if (has_spend_key) wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), spend_key_sk, true, false);
    else wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), address_info.address, view_key_sk);
    wallet->set_daemon_connection(config.m_server);
    wallet->m_w2->set_refresh_from_block_height(config.m_restore_height.get());
    wallet->m_start_height = config.m_restore_height.get();
    wallet->m_w2->set_seed_language(config.m_language.get());
    wallet->init_common();
    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_random(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet_random(...)");

    // validate config
    if (!config.m_seed_offset.get().empty()) throw std::runtime_error("Cannot specify seed offset when creating random wallet");
    if (config.m_restore_height != boost::none) throw std::runtime_error("Cannot specify restore height when creating random wallet");
    if (config.m_path == boost::none) throw std::runtime_error("Must specify wallet path");

    // initialize wallet
    monero_wallet_light* wallet = new monero_wallet_light();
    if (http_client_factory == nullptr) wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true));
    else wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(config.m_network_type.get()), 1, true, std::move(http_client_factory)));
    wallet->set_daemon_connection(config.m_server);
    wallet->m_w2->set_seed_language(config.m_language.get());
    crypto::secret_key secret_key;
    if (config.m_account_lookahead != boost::none) wallet->m_w2->set_subaddress_lookahead(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
    wallet->m_w2->generate(config.m_path.get(), config.m_password.get(), secret_key, false, false);
    wallet->init_common();
    if (wallet->is_connected_to_daemon()) {
      uint64_t daemon_height = wallet->get_daemon_height();
      wallet->m_w2->set_refresh_from_block_height(daemon_height);
      wallet->m_start_height = daemon_height;
    }
    return wallet;
  }


// ----------------------------- WALLET METHODS -----------------------------

monero_wallet_light::~monero_wallet_light() {
  MTRACE("~monero_wallet_light()");
  close();
}

void monero_wallet_light::set_daemon_connection(const boost::optional<monero_rpc_connection>& connection) {
  if (connection == boost::none) {
    set_daemon_connection("");
    return;
  }

  m_lws_uri = connection.get().m_uri.get();
}

void monero_wallet_light::set_daemon_connection(std::string host, std::string port, std::string admin_uri, std::string admin_port, std::string token) {
  m_host = host;
  m_port = port;
  m_lws_uri = host + ":" + port;
  m_admin_uri = admin_uri;
  m_admin_port = admin_port;
  m_lws_admin_uri = admin_uri + ":" + admin_port;
  m_token = token;

  if (m_http_client != nullptr) {
    if (m_http_client->is_connected()) m_http_client->disconnect();

    if (!m_http_client->set_server(m_lws_uri, boost::none)) throw std::runtime_error("Could not server: " + host);
    if (!m_http_client->connect(m_timeout)) throw std::runtime_error("Could not connect to server: " + host);
  }
}

boost::optional<monero_rpc_connection> monero_wallet_light::get_daemon_connection() const {
  MTRACE("monero_wallet_light::get_daemon_connection()");
  if (m_w2->get_daemon_address().empty()) return boost::none;
  boost::optional<monero_rpc_connection> connection = monero_rpc_connection();
  connection->m_uri = m_w2->get_daemon_address();
  if (m_w2->get_daemon_login()) {
    if (!m_w2->get_daemon_login()->username.empty()) connection->m_username = m_w2->get_daemon_login()->username;
    epee::wipeable_string wipeablePassword = m_w2->get_daemon_login()->password;
    std::string password = std::string(wipeablePassword.data(), wipeablePassword.size());
    if (!password.empty()) connection->m_password = password;
  }
  return connection;
}

void monero_wallet_light::set_daemon_proxy(const std::string& uri) {
  if (m_http_client == nullptr) throw std::runtime_error("Cannot set daemon proxy");
  m_http_client->set_proxy(uri);
  m_http_admin_client->set_proxy(uri);
}

bool monero_wallet_light::is_connected_to_daemon() const {
  if (m_http_client == nullptr) return false;

  return m_http_client->is_connected();
}

bool monero_wallet_light::is_connected_to_admin_daemon() const {
  if (m_http_admin_client == nullptr) return false;
  return m_http_admin_client->is_connected();
}

bool monero_wallet_light::is_synced() const {
  if (!is_connected_to_daemon()) return false;
  
  monero_light_get_address_info_response address_info = get_address_info();

  return address_info.m_blockchain_height.get() == m_scanned_block_height;
}

bool monero_wallet_light::is_daemon_synced() const {
  monero_light_get_address_info_response address_info = get_address_info();

  return address_info.m_blockchain_height.get() == address_info.m_scanned_height.get();
}

void monero_wallet_light::set_restore_height(uint64_t restore_height) {
  monero_wallet_full::set_restore_height(restore_height);
  if (is_connected_to_admin_daemon()) rescan(restore_height);
}

uint64_t monero_wallet_light::get_height_by_date(uint16_t year, uint8_t month, uint8_t day) const {
  throw std::runtime_error("get_height_by_date(year, month, day) not supported");
}

monero_sync_result monero_wallet_light::sync_aux() {
  MTRACE("sync_aux()");
  if (!is_connected_to_daemon()) throw std::runtime_error("sync_aux(): Wallet is not connected to daemon");
  
  monero_sync_result result(0, false);
  monero_light_get_address_txs_response response = get_address_txs();
  m_start_height = response.m_start_height.get();

  if(m_scanned_block_height == 0) m_scanned_block_height = m_start_height;
  uint64_t old_scanned_height = m_scanned_block_height;
  
  m_scanned_block_height = response.m_scanned_block_height.get();
  m_blockchain_height = response.m_blockchain_height.get();

  if (response.m_transactions == boost::none) m_raw_transactions = std::vector<monero_light_transaction>();
  else m_raw_transactions = response.m_transactions.get();

  m_transactions = std::vector<monero_light_transaction>();
  for (const monero_light_transaction& raw_transaction : m_raw_transactions) {

    std::shared_ptr<monero_light_transaction> transaction_ptr = std::make_shared<monero_light_transaction>(raw_transaction);
    std::shared_ptr<monero_light_transaction> transaction = transaction_ptr->copy(transaction_ptr, std::make_shared<monero_light_transaction>(), false);
    uint64_t total_received = monero_utils::uint64_t_cast(transaction->m_total_received.get());
    
    if (!result.m_received_money) result.m_received_money = total_received > 0;

    if (!transaction_is_ours(raw_transaction)) {
      continue;
    } else {
      m_transactions.push_back(*transaction);
      continue;
    }

    for(monero_light_spend spent_output : raw_transaction.m_spent_outputs.get()) {
      bool is_spent = key_image_is_ours(spent_output.m_key_image.get(), spent_output.m_tx_pub_key.get(), spent_output.m_out_index.get());
      if (is_spent) transaction->m_spent_outputs.get().push_back(spent_output);
      else {
        uint64_t total_sent = monero_utils::uint64_t_cast(transaction->m_total_sent.get());
        uint64_t spent_amount = monero_utils::uint64_t_cast(spent_output.m_amount.get());
        uint64_t recalc_sent = total_sent - spent_amount;
        transaction->m_total_sent = boost::lexical_cast<std::string>(recalc_sent);
      }
    
      uint64_t final_sent = monero_utils::uint64_t_cast(transaction->m_total_sent.get());
      m_transactions.push_back(*transaction);
      uint64_t total_sent = monero_utils::uint64_t_cast(transaction->m_total_sent.get());
      bool incoming = (total_received > total_sent);
      crypto::hash payment_id = null_hash;
      crypto::hash tx_hash;
      
      //THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, transaction->m_payment_id.get()), error::wallet_internal_error, "Invalid payment_id field");
      //THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, transaction->m_hash.get()), error::wallet_internal_error, "Invalid hash field");
      string_tools::hex_to_pod(transaction->m_payment_id.get(), payment_id);
      string_tools::hex_to_pod(transaction->m_hash.get(), tx_hash);

      tools::wallet2::address_tx address_tx;
      address_tx.m_tx_hash = tx_hash;
      address_tx.m_incoming = incoming;
      address_tx.m_amount  =  incoming ? total_received - total_sent : total_sent - total_received;
      address_tx.m_fee = 0;                 // TODO
      address_tx.m_block_height = transaction->m_height.get();
      address_tx.m_unlock_time  = transaction->m_unlock_time.get();
      //address_tx.m_timestamp = transaction->m_timestamp.get();
      address_tx.m_coinbase  = transaction->m_coinbase.get();
      address_tx.m_mempool  = transaction->m_mempool.get();
      m_light_wallet_address_txs.emplace(tx_hash,address_tx);
    }
  }
  
  monero_light_get_unspent_outs_response unspent_outs_response = get_unspent_outs();

  m_unspent_outputs = std::vector<monero_light_output>();

  if (unspent_outs_response.m_outputs != boost::none) m_unspent_outputs = unspent_outs_response.m_outputs.get();

  calculate_balances();

  result.m_num_blocks_fetched = m_scanned_block_height - old_scanned_height;
  result.m_received_money = false; // to do
  
  try {
    get_subaddrs();
    m_daemon_supports_subaddresses = true;
  } catch (...) {
    MINFO("Light wallet server doesn't support subaddresses");
    m_daemon_supports_subaddresses = false;
  }

  // attempt to refresh wallet2 which may throw exception
  try {
    m_w2->refresh(m_w2->is_trusted_daemon(), m_start_height, result.m_num_blocks_fetched, result.m_received_money, true);
    // find and save rings
    m_w2->find_and_save_rings(false);
  } catch (...) {
    MINFO("Error occurred while wallet2 refresh");
  }
  return result;
}

void monero_wallet_light::set_unspent(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfer_container.size(), "Invalid index");
  tools::wallet2::transfer_details &td = m_transfer_container[idx];
  LOG_PRINT_L2("Setting UNSPENT: ki " << td.m_key_image << ", amount ");
  td.m_spent = false;
  td.m_spent_height = 0;
}

monero_sync_result monero_wallet_light::sync() {
  MTRACE("sync()");
  if(!is_connected_to_daemon()) throw std::runtime_error("sync(): Wallet is not connected to daemon");

  monero_sync_result result = sync_aux();
  monero_sync_result last_sync(m_start_height, false);

  uint64_t last_scanned_height = m_scanned_block_height;

  while(!is_synced()) {
    last_sync = sync_aux();
    result.m_num_blocks_fetched += last_sync.m_num_blocks_fetched;
    if (last_sync.m_received_money) result.m_received_money = true;
  }
  
  return result;
}

monero_sync_result monero_wallet_light::sync(uint64_t start_height) {
  MTRACE("sync(" << start_height << ")");
  if (!is_connected_to_daemon()) throw std::runtime_error("sync(uint64_t): Wallet is not connected to daemon");
  if (start_height < m_start_height) {
    if (!is_connected_to_admin_daemon()) throw std::runtime_error("Wallet is not connected to admin daemon");
    rescan(start_height, get_primary_address());
  }

  monero_sync_result last_sync = sync_aux();

  while(!is_synced()) {
    std::this_thread::sleep_for(std::chrono::seconds(120));
    last_sync = sync_aux();
  }

  monero_sync_result result;
  uint64_t height = get_height();

  result.m_num_blocks_fetched = (start_height > height) ? 0 : height - start_height;
  result.m_received_money = last_sync.m_received_money;

  return result;
}

bool monero_wallet_light::parse_rct_str(const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt) const
{
  // rct string is empty if output is non RCT
  if (rct_string.empty())
    return false;
  // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  rct::key encrypted_mask;
  std::string rct_commit_str = rct_string.substr(0,64);
  std::string encrypted_mask_str = rct_string.substr(64,64);
  THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
  THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, encrypted_mask_str), error::wallet_internal_error, "Invalid rct mask: " + encrypted_mask_str);
  string_tools::hex_to_pod(rct_commit_str, rct_commit);
  string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
  if (decrypt) {
    // Decrypt the mask
    crypto::key_derivation derivation;
    bool r = generate_key_derivation(tx_pub_key, m_w2->get_account().get_keys().m_view_secret_key, derivation);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
    crypto::secret_key scalar;
    crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
    sc_sub(decrypted_mask.bytes,encrypted_mask.bytes,rct::hash_to_scalar(rct::sk2rct(scalar)).bytes);
  }
  return true;
}

bool monero_wallet_light::key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index) const
{
  return m_w2->light_wallet_key_image_is_ours(key_image, tx_public_key, out_index);
}

bool monero_wallet_light::key_image_is_ours(const std::string& key_image, const std::string& tx_public_key, const std::string& out_index) const {
  uint64_t oi = monero_utils::uint64_t_cast(out_index);

  return key_image_is_ours(key_image, tx_public_key, oi);
}

bool monero_wallet_light::key_images_are_ours(const std::vector<key_image> key_images, const std::vector<crypto::public_key> tx_public_keys, const std::vector<uint64_t> out_indices) const {
  if (!(key_images.size() == tx_public_keys.size() == out_indices.size())) throw std::runtime_error("key_images, tx_pub_keys and out_indices must have same size.");

  bool are_ours = true;
  size_t n = key_images.size();

  for(size_t i = 0; i < n; i++) {
    const crypto::key_image& ki = key_images[i];
    const crypto::public_key& tpk = tx_public_keys[i];
    uint64_t oi = out_indices[i];

    are_ours &= m_w2->light_wallet_key_image_is_ours(ki, tpk, oi);
  }

  return are_ours;
}

bool monero_wallet_light::output_is_spent(const monero_light_output spend_output) const {
  if (spend_output.m_spend_key_images == boost::none || spend_output.m_spend_key_images.get().empty()) return true;

  std::string tx_pub_key = spend_output.m_tx_pub_key.get();
  
  for(auto spend_key_image : spend_output.m_spend_key_images.get()) {
    if(key_image_is_ours(spend_key_image, tx_pub_key, spend_output.m_index.get())) return true;
  }

  return false;
}

bool monero_wallet_light::spend_object_is_ours(const monero_light_spend spend_object) const {
  return key_image_is_ours(spend_object.m_key_image.get(), spend_object.m_tx_pub_key.get(), spend_object.m_out_index.get());
}

bool monero_wallet_light::spend_objects_are_ours(const std::vector<monero_light_spend> spend_objects) const {
  bool are_ours = true;

  for(auto spend_object : spend_objects) {
    are_ours &= spend_object_is_ours(spend_object);
  }

  return are_ours;
}

bool monero_wallet_light::transaction_is_ours(const monero_light_transaction& tx) const {  
  uint64_t total_received = monero_utils::uint64_t_cast(tx.m_total_received.get());
  uint64_t total_sent = monero_utils::uint64_t_cast(tx.m_total_sent.get());
  
  // pure incoming tx always ours
  if(total_sent == 0 && total_received > 0 && tx.m_spent_outputs.get().empty()) return true;
  else if(!tx.m_spent_outputs.get().empty()) {
    // outgoing txs
    return spend_objects_are_ours(tx.m_spent_outputs.get());
  }

  return false;
}

monero_sync_result monero_wallet_light::sync(monero_wallet_listener& listener) {
  MTRACE("sync(listener)");
  if (!is_connected_to_daemon()) throw std::runtime_error("sync(monero_wallet_listener&): Wallet is not connected to daemon");
  uint64_t last_scanned_block_height = m_scanned_block_height;
  monero_sync_result last_sync = sync_aux();
  
  while(!is_synced()) {
    
    uint64_t last_balance = m_balance;
    uint64_t last_unlocked_balance = m_balance_unlocked;

    std::this_thread::sleep_for(std::chrono::seconds(120));
    last_sync = sync_aux();
    std::string message = "Sync progress (" + boost::lexical_cast<std::string>(m_scanned_block_height) + "/" + boost::lexical_cast<std::string>(m_blockchain_height) + ")";
    double percentage = m_scanned_block_height / m_blockchain_height;
    listener.on_sync_progress(m_scanned_block_height, m_start_height, m_blockchain_height, percentage, message);

    if (m_balance != last_balance || last_unlocked_balance != m_balance_unlocked) listener.on_balances_changed(m_balance, m_balance_unlocked);
    listener.on_new_block(m_scanned_block_height);
    
    // to do on_output_spent, on_output_received between last_scanned_block_height and m_scanned_block_height

    last_scanned_block_height = m_scanned_block_height;
  }

  monero_sync_result result;

  result.m_num_blocks_fetched = m_scanned_block_height - last_scanned_block_height;
  result.m_received_money = last_sync.m_received_money;

  return result;
}

void monero_wallet_light::start_syncing(uint64_t sync_period_in_ms) {
  if (!is_connected_to_daemon()) throw std::runtime_error("Wallet is not connected to daemon");
  m_syncing_interval = sync_period_in_ms;
  if (!m_syncing_enabled) {
    m_syncing_enabled = true;
    run_sync_loop(); // sync wallet on loop in background
  }
}

void monero_wallet_light::scan_txs(const std::vector<std::string>& tx_hashes) {
  throw std::runtime_error("scan_txs() not supported");
}

void monero_wallet_light::rescan_spent() {
  throw std::runtime_error("rescan_spent() not supported");
}

void monero_wallet_light::run_sync_loop() {
  if (m_sync_loop_running) return;  // only run one loop at a time
  m_sync_loop_running = true;

  // start sync loop thread
  // TODO: use global threadpool, background sync wasm wallet in c++ thread
  m_syncing_thread = boost::thread([this]() {

    // sync while enabled
    while (m_syncing_enabled) {
      auto start = std::chrono::system_clock::now();
      try { lock_and_sync(); }
      catch (std::exception const& e) { std::cout << "monero_wallet_light failed to background synchronize: " << e.what() << std::endl; }
      catch (...) { std::cout << "monero_wallet_light failed to background synchronize" << std::endl; }

      // only wait if syncing still enabled
      if (m_syncing_enabled) {
        boost::mutex::scoped_lock lock(m_syncing_mutex);
        boost::posix_time::milliseconds wait_for_ms(m_syncing_interval.load());
        boost::posix_time::milliseconds elapsed_time = boost::posix_time::milliseconds(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start).count());
        m_sync_cv.timed_wait(lock, elapsed_time > wait_for_ms ? boost::posix_time::milliseconds(0) : wait_for_ms - elapsed_time); // target regular sync period by accounting for sync time
      }
    }

    m_sync_loop_running = false;
  });
}

monero_sync_result monero_wallet_light::lock_and_sync(boost::optional<uint64_t> start_height) {
  bool rescan = m_rescan_on_sync.exchange(false);
  boost::lock_guard<boost::mutex> guarg(m_sync_mutex); // synchronize sync() and syncAsync()
  monero_sync_result result;
  result.m_num_blocks_fetched = 0;
  result.m_received_money = false;
  do {
    // skip if daemon is not connected or synced
    if (m_is_connected && is_daemon_synced()) {

      // rescan blockchain if requested
      if (rescan) m_w2->rescan_blockchain(false);

      // sync wallet
      //result = sync_aux(start_height);
      result = sync_aux();
    }
  } while (!rescan && (rescan = m_rescan_on_sync.exchange(false))); // repeat if not rescanned and rescan was requested
  return result;
}

void monero_wallet_light::rescan_blockchain() {       
  if (is_connected_to_admin_daemon())
  {
    rescan();
    return;
  }
  else if(!is_connected_to_daemon()) throw std::runtime_error("rescan_blockchain(): Wallet is not connected to daemon");
  monero_light_import_request_response response = import_request();

  if (response.m_import_fee != boost::none) {
    uint64_t import_fee = monero_utils::uint64_t_cast(response.m_import_fee.get());

    if (import_fee > 0) throw std::runtime_error("Current light wallet server requires a payment to rescan the blockchain.");
  }
}

uint64_t monero_wallet_light::get_balance() const { 
  uint64_t total_balance = 0;

  for(monero_account account : get_accounts(false, std::string(""))) {
    total_balance += get_balance(account.m_index.get());
  }
  
  return total_balance;
}

uint64_t monero_wallet_light::get_balance(uint32_t account_idx) const { 
  if (account_idx == 0) return m_balance;

  monero_account account = get_account(account_idx, true);
  uint64_t account_balance = get_balance(account_idx, 0);

  for(monero_subaddress subaddress : account.m_subaddresses) {
    account_balance += get_balance(account_idx, subaddress.m_index.get());
  }

  return account_balance;
}

uint64_t monero_wallet_light::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const { 
  uint64_t balance = 0;

  monero_output_query output_query;
  output_query.m_account_index = account_idx;
  output_query.m_subaddress_index = subaddress_idx;
  output_query.m_is_spent = false;

  std::vector<std::shared_ptr<monero_output_wallet>> outputs = get_outputs(output_query);

  for(std::shared_ptr<monero_output_wallet> output : outputs) balance += output->m_amount.get();

  return balance;
};

uint64_t monero_wallet_light::get_unlocked_balance() const { 
  uint64_t total_balance = 0;

  for(monero_account account : get_accounts(false, std::string(""))) total_balance += get_unlocked_balance(account.m_index.get());
  
  return total_balance;
}

uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_idx) const { 
  if (account_idx == 0) return m_balance;

  monero_account account = get_account(account_idx, true);
  uint64_t account_balance = get_unlocked_balance(account_idx, 0);

  for(monero_subaddress subaddress : account.m_subaddresses) account_balance += get_unlocked_balance(account_idx, subaddress.m_index.get());

  return account_balance;
}

uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const { 
  uint64_t balance = 0;

  monero_output_query output_query;
  output_query.m_account_index = account_idx;
  output_query.m_subaddress_index = subaddress_idx;
  output_query.m_is_spent = false;
  output_query.m_tx_query = std::make_shared<monero_tx_query>();
  output_query.m_tx_query.get()->m_is_confirmed = true;

  std::vector<std::shared_ptr<monero_output_wallet>> outputs = get_outputs(output_query);

  for(std::shared_ptr<monero_output_wallet> output : outputs) {    
    balance += output->m_amount.get();
  }

  return balance;
};

monero_account monero_wallet_light::create_account(const std::string& label) {
  monero_account account = monero_wallet_full::create_account(label);
  if(!m_daemon_supports_subaddresses) return account;
  monero_light_index_range index_range(0, 0);
  std::vector<monero_light_index_range> index_ranges;
  index_ranges.push_back(index_range);
  monero_light_subaddrs subaddrs;
  subaddrs.emplace(account.m_index.get(), index_ranges);

  upsert_subaddrs(subaddrs);
  return account;
}

monero_subaddress monero_wallet_light::create_subaddress(const uint32_t account_idx, const std::string& label) {
  // initialize and return result
  monero_subaddress subaddress = monero_wallet_full::create_subaddress(account_idx, label);
  if(!m_daemon_supports_subaddresses) return subaddress;
  uint32_t subaddr_idx = subaddress.m_index.get();
  monero_light_index_range index_range(subaddr_idx, subaddr_idx);
  std::vector<monero_light_index_range> index_ranges;
  index_ranges.push_back(index_range);
  monero_light_subaddrs subaddrs;
  subaddrs.emplace(account_idx, index_ranges);

  upsert_subaddrs(subaddrs);

  return subaddress;
}

std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs()  const {
  return get_txs(monero_tx_query());
}

std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs(const monero_tx_query& query) const {
  std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();

  for (monero_light_transaction light_tx : m_transactions) {
    std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();
    if (tx_wallet->m_block == boost::none) tx_wallet->m_block = std::make_shared<monero_block>();
    tx_wallet->m_block.get()->m_height = light_tx.m_height;
    tx_wallet->m_block.get()->m_txs = std::vector<std::shared_ptr<monero::monero_tx>>();

    tx_wallet->m_hash = light_tx.m_hash;
    tx_wallet->m_is_relayed = true;

    std::string total_sent_str = light_tx.m_total_sent.get();
    std::string total_received_str = light_tx.m_total_received.get();

    uint64_t total_sent = monero_utils::uint64_t_cast(total_sent_str);
    uint64_t total_received = monero_utils::uint64_t_cast(total_received_str);

    if (total_sent == 0 && total_received > 0) {
      // pure incoming tx
      tx_wallet->m_is_incoming = true;
      tx_wallet->m_is_outgoing = false;
    } else if (total_received == 0 && total_sent > 0) {
      // pure outgoing tx
      tx_wallet->m_is_outgoing = true;
      tx_wallet->m_is_incoming = false;
    } else if (light_tx.m_coinbase != boost::none && light_tx.m_coinbase.get()) {
      tx_wallet->m_is_incoming = true;
      tx_wallet->m_is_outgoing = false;
    } else if(total_received < total_sent) {
      if(light_tx.m_spent_outputs == boost::none || light_tx.m_spent_outputs.get().empty()) throw std::runtime_error("could not determine tx direction: spent outputs are empty");
      // outgoing tx with change
      tx_wallet->m_is_outgoing = true;
      tx_wallet->m_is_incoming = false;
      tx_wallet->m_change_address = get_primary_address();
      tx_wallet->m_change_amount = total_received;
    }

    tx_wallet->m_inputs = std::vector<std::shared_ptr<monero::monero_output>>();
    uint64_t inputs_sum = 0;

    if (tx_wallet->m_is_outgoing == boost::none) throw std::runtime_error("Could not determine tx direction! total sent:" + total_sent_str + ", total received: " + total_received_str);

    if(tx_wallet->m_is_outgoing.get()) {
      bool append_tx = false;
      for(auto spent_output : light_tx.m_spent_outputs.get())
      {        
        if(key_image_is_ours(spent_output.m_key_image.get(), spent_output.m_tx_pub_key.get(), spent_output.m_out_index.get())) {
          append_tx = true;
          std::shared_ptr<monero::monero_output_wallet> s_output = std::make_shared<monero::monero_output_wallet>();
          s_output->m_amount = monero_utils::uint64_t_cast(spent_output.m_amount.get());
          s_output->m_index = spent_output.m_out_index.get();
          s_output->m_key_image = std::make_shared<monero::monero_key_image>();
          s_output->m_key_image.get()->m_hex = spent_output.m_key_image.get();

          if (spent_output.m_sender != boost::none) {
            monero_light_address_meta sender = spent_output.m_sender.get();
            s_output->m_account_index = sender.m_maj_i.get();
            s_output->m_subaddress_index = sender.m_min_i.get();
          } else {
            s_output->m_account_index = 0;
            s_output->m_subaddress_index = 0;
          }

          tx_wallet->m_inputs.push_back(s_output);
          s_output->m_tx = tx_wallet;
          inputs_sum += s_output->m_amount.get();
        }
      }

      if(!append_tx) continue;
      tx_wallet->m_input_sum = inputs_sum;
    }
    
    tx_wallet->m_unlock_time = light_tx.m_unlock_time;
    tx_wallet->m_payment_id = light_tx.m_payment_id;
    tx_wallet->m_in_tx_pool = light_tx.m_mempool;
    tx_wallet->m_is_miner_tx = light_tx.m_coinbase;
    tx_wallet->m_is_locked = light_tx.m_unlock_time.get() != 0;
  
    uint64_t num_confirmations = m_blockchain_height - light_tx.m_height.get();
  
    tx_wallet->m_num_confirmations = num_confirmations;
    tx_wallet->m_is_confirmed = num_confirmations > 0;

    tx_wallet->m_fee = monero_utils::uint64_t_cast(light_tx.m_fee.get());
    tx_wallet->m_is_failed = false;    
    tx_wallet->m_block.get()->m_txs.push_back(tx_wallet);
    if (query.meets_criteria(tx_wallet.get())) txs.push_back(tx_wallet);
  }

  return txs;
}

/**
 * Get incoming and outgoing transfers to and from this wallet.  An outgoing
 * transfer represents a total amount sent from primary address to
 * individual destination addresses, each with their own amount.
 * An incoming transfer represents a total amount received into
 * primary address account. Transfers belong to transactions which
 * are stored on the blockchain.
 *
 * Query results can be filtered by passing in a monero_transfer_query.
 * Transfers must meet every criteria defined in the query in order to be
 * returned.  All filtering is optional and no filtering is applied when not
 * defined.
 *
 * @param query filters query results (optional)
 * @return wallet transfers per the query (free memory using monero_utils::free)
 */
std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers(const monero_transfer_query& query) const {
  std::vector<std::shared_ptr<monero_transfer>> transfers = std::vector<std::shared_ptr<monero_transfer>>();

  for (monero_light_transaction light_tx : m_transactions) {
    // incoming txs doesn't have spent_outputs

    std::shared_ptr<monero_transfer> transfer;

    uint64_t total_received = monero_utils::uint64_t_cast(light_tx.m_total_received.get());
    uint64_t total_sent = monero_utils::uint64_t_cast(light_tx.m_total_sent.get());

    bool is_incoming = light_tx.m_spent_outputs == boost::none || light_tx.m_spent_outputs.get().empty();

    if(is_incoming) transfer = std::make_shared<monero_incoming_transfer>();
    else transfer = std::make_shared<monero_outgoing_transfer>();

    transfer->m_amount = is_incoming ? total_received : total_sent - total_received;
    transfer->m_account_index = 0;
    transfer->m_tx = std::make_shared<monero_tx_wallet>();
    transfer->m_tx->m_is_incoming = is_incoming;
    if (transfer->m_tx->m_block == boost::none) transfer->m_tx->m_block = std::make_shared<monero_block>();
    transfer->m_tx->m_block.get()->m_height = light_tx.m_height;
    transfer->m_tx->m_block.get()->m_txs = std::vector<std::shared_ptr<monero::monero_tx>>();
    
    transfer->m_tx->m_hash = light_tx.m_hash;
    transfer->m_tx->m_is_relayed = true;
    transfer->m_tx->m_unlock_time = light_tx.m_unlock_time;
    transfer->m_tx->m_payment_id = light_tx.m_payment_id;
    transfer->m_tx->m_in_tx_pool = light_tx.m_mempool;
    transfer->m_tx->m_is_miner_tx = light_tx.m_coinbase;
    transfer->m_tx->m_is_locked = light_tx.m_unlock_time.get() != 0;
    uint64_t num_confirmations = m_blockchain_height - light_tx.m_height.get();
    transfer->m_tx->m_num_confirmations = num_confirmations;
    transfer->m_tx->m_is_confirmed = num_confirmations > 0;
    transfer->m_tx->m_fee = monero_utils::uint64_t_cast(light_tx.m_fee.get());
    transfer->m_tx->m_is_failed = false;

    transfer->m_tx->m_outputs = std::vector<std::shared_ptr<monero::monero_output>>();

    if(light_tx.m_spent_outputs != boost::none) {
      for(auto light_spent_output : light_tx.m_spent_outputs.get()) {
        if (spend_object_is_ours(light_spent_output)) {
          std::shared_ptr<monero_output_wallet> spent_output = std::make_shared<monero_output_wallet>();
          
          if (light_spent_output.m_sender != boost::none) {
            monero_light_address_meta sender = light_spent_output.m_sender.get();

            spent_output->m_account_index = sender.m_maj_i.get();
            spent_output->m_subaddress_index = sender.m_min_i.get();
          }
          else {
            spent_output->m_account_index = 0;
            spent_output->m_subaddress_index = 0;
          }
          //spent_output->m_index = light_spent_output.m_out_index.get();
          spent_output->m_is_spent = true;
          spent_output->m_amount = monero_utils::uint64_t_cast(light_spent_output.m_amount.get());
          transfer->m_tx->m_outputs.push_back(spent_output);
        }
      }
    }

    transfer->m_tx->m_block.get()->m_txs.push_back(transfer->m_tx);
    if (query.meets_criteria(transfer.get())) transfers.push_back(transfer);
  }

  return transfers;
}

std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs() const {  
  return get_outputs(monero_output_query());
}

std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs(const monero_output_query& query) const {
  std::vector<std::shared_ptr<monero_output_wallet>> outputs = std::vector<std::shared_ptr<monero_output_wallet>>();

  for(monero_light_output light_output : m_unspent_outputs) {
    bool valid_tx_hex = string_tools::validate_hex(64, light_output.m_tx_pub_key.get());
    std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
    
    if (light_output.m_recipient != boost::none) {
      monero_light_address_meta recipient = light_output.m_recipient.get();

      output->m_account_index = recipient.m_maj_i.get();
      output->m_subaddress_index = recipient.m_min_i.get();
    }

    else output->m_account_index = 0;
    output->m_index = monero_utils::uint64_t_cast(light_output.m_global_index.get());
    output->m_subaddress_index = 0;
    output->m_amount = monero_utils::uint64_t_cast(light_output.m_amount.get());
    output->m_stealth_public_key = light_output.m_public_key;
    output->m_key_image = std::make_shared<monero_key_image>();
    output->m_key_image.get()->m_hex = "0100000000000000000000000000000000000000000000000000000000000000";
    output->m_is_spent = false;
    
    if (light_output.m_spend_key_images != boost::none) {
      crypto::public_key tx_pub_key;
      if(!string_tools::validate_hex(64, light_output.m_tx_pub_key.get())) throw std::runtime_error("Invalid tx public key field.");
      string_tools::hex_to_pod(light_output.m_tx_pub_key.get(), tx_pub_key);

      for (std::string light_spend_key_image : light_output.m_spend_key_images.get()){
        crypto::key_image l_spend_key_image;
        if(!string_tools::validate_hex(64, light_spend_key_image)) throw std::runtime_error("Invalid spend key image.");  
        string_tools::hex_to_pod(light_spend_key_image, l_spend_key_image);
        if(m_w2->light_wallet_key_image_is_ours(l_spend_key_image, tx_pub_key, light_output.m_index.get())) {
          output->m_key_image.get()->m_hex = light_spend_key_image;
          output->m_is_spent = true;
          break;
        }
      }
    }

    output->m_tx = std::make_shared<monero_tx>();
    output->m_tx->m_block = std::make_shared<monero_block>();
    output->m_tx->m_block.get()->m_height = light_output.m_height.get();
    output->m_tx->m_hash = light_output.m_tx_hash;
    output->m_tx->m_key = light_output.m_tx_pub_key;
    output->m_tx->m_rct_signatures = light_output.m_rct;
    output->m_tx->m_outputs = std::vector<std::shared_ptr<monero::monero_output>>();
    if(query.meets_criteria(output.get())) output->m_tx->m_outputs.push_back(output);
    output->m_tx->m_block.get()->m_txs = std::vector<std::shared_ptr<monero::monero_tx>>();
    output->m_tx->m_block.get()->m_txs.push_back(output->m_tx);

    if(query.meets_criteria(output.get())) outputs.push_back(output);
  }

  return outputs;
}

std::string monero_wallet_light::export_outputs(bool all) const {
  m_w2->light_wallet_get_address_txs();
  m_w2->light_wallet_get_unspent_outs();
  return epee::string_tools::buff_to_hex_nodelimer(m_w2->export_outputs_to_str(all));
}

std::vector<std::shared_ptr<monero_key_image>> monero_wallet_light::export_key_images(bool all) const {
  if (all) {
    //m_exported_key_images = m_imported_key_images;
    return m_imported_key_images;
  }

  std::vector<std::shared_ptr<monero_key_image>> result = std::vector<std::shared_ptr<monero_key_image>>();

  for(std::shared_ptr<monero_key_image> imported_key_image : m_imported_key_images) {
    bool append = true;

    for (std::shared_ptr<monero_key_image> exported_key_image : m_exported_key_images) {
      if (imported_key_image->m_hex == exported_key_image->m_hex) {
        append = false;
        break;
      }
    }

    if (append) {
      result.push_back(imported_key_image);
    }
  }

  //for (std::shared_ptr<monero_key_image> exported_key_image : result) {
    
    //m_exported_key_images.push_back(exported_key_image);
  //}

  return result;
}

std::shared_ptr<monero_key_image_import_result> monero_wallet_light::import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) {
  bool append_key_image = true;
  bool has_changes = false;

  for (std::shared_ptr<monero_key_image> key_image : key_images) {
    append_key_image = true;

    for (std::shared_ptr<monero_key_image> imported_key_image : m_imported_key_images) {
      if (imported_key_image->m_hex == key_image->m_hex) {
        append_key_image = false;
        break;
      }
    }

    if (append_key_image) {
      m_imported_key_images.push_back(key_image);
      has_changes = true;
    }
  }

  // validate and prepare key images for wallet2
  std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
  ski.resize(key_images.size());
  for (uint64_t n = 0; n < ski.size(); ++n) {
    if (!epee::string_tools::hex_to_pod(key_images[n]->m_hex.get(), ski[n].first)) {
      throw std::runtime_error("failed to parse key image");
    }
    if (!epee::string_tools::hex_to_pod(key_images[n]->m_signature.get(), ski[n].second)) {
      throw std::runtime_error("failed to parse signature");
    }
  }

  // import key images
  uint64_t spent = 0, unspent = 0;
  m_w2->light_wallet_get_unspent_outs();
  uint64_t height = m_w2->import_key_images(ski, 0, spent, unspent, false); // TODO: use offset? refer to wallet_rpc_server::on_import_key_images() req.offset
  //uint64_t height = 0;
  // to do
  // translate results
  std::shared_ptr<monero_key_image_import_result> result = std::make_shared<monero_key_image_import_result>();
  result->m_height = height;
  result->m_spent_amount = spent;
  result->m_unspent_amount = unspent;
  return result;
};

std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::create_txs(const monero_tx_config& config) {
  MTRACE("monero_wallet_light::create_txs");
  //std::cout << "monero_tx_config: " << config.serialize()  << std::endl;

  // validate config
  if (config.m_relay != boost::none && config.m_relay.get() && is_view_only()) throw std::runtime_error("Cannot relay tx in view wallet");
  if (config.m_account_index == boost::none) throw std::runtime_error("Must specify account index to send from");
  if (config.m_account_index.get() != 0) throw std::runtime_error("Must specify exactly account index 0 to send from");

  // prepare parameters for wallet rpc's validate_transfer()
  std::string payment_id = config.m_payment_id == boost::none ? std::string("") : config.m_payment_id.get();
  std::list<tools::wallet_rpc::transfer_destination> tr_destinations;
  for (const std::shared_ptr<monero_destination>& destination : config.get_normalized_destinations()) {
    tools::wallet_rpc::transfer_destination tr_destination;
    if (destination->m_amount == boost::none) throw std::runtime_error("Destination amount not defined");
    if (destination->m_address == boost::none) throw std::runtime_error("Destination address not defined");
    tr_destination.amount = destination->m_amount.get();
    tr_destination.address = destination->m_address.get();
    tr_destinations.push_back(tr_destination);
  }

  // validate the requested txs and populate dsts & extra
  std::vector<cryptonote::tx_destination_entry> dsts;
  std::vector<uint8_t> extra;
  epee::json_rpc::error err;
  MTRACE("monero_wallet_light::create_txs before validate transfer");
  if (!monero_utils::validate_transfer(m_w2.get(), tr_destinations, payment_id, dsts, extra, true, err)) {
    throw std::runtime_error(err.message);
  }
  MTRACE("monero_wallet_light::create_txs after validate transfer");

  // prepare parameters for wallet2's create_transactions_2()
  uint64_t mixin = m_w2->adjust_mixin(0); // get mixin for call to 'create_transactions_2'
  uint32_t priority = m_w2->adjust_priority(config.m_priority == boost::none ? 0 : config.m_priority.get());
  uint64_t unlock_time = config.m_unlock_time == boost::none ? 0 : config.m_unlock_time.get();
  uint32_t account_index = config.m_account_index.get();
  std::set<uint32_t> subaddress_indices;
  for (const uint32_t& subaddress_idx : config.m_subaddress_indices) subaddress_indices.insert(subaddress_idx);
  std::set<uint32_t> subtract_fee_from;
  for (const uint32_t& subtract_fee_from_idx : config.m_subtract_fee_from) subtract_fee_from.insert(subtract_fee_from_idx);
  m_w2->set_light_wallet(true);
  // prepare transactions
  MTRACE("monero_wallet_light::create_txs before create transactions 2");
  std::vector<wallet2::pending_tx> ptx_vector = m_w2->create_transactions_2(dsts, mixin, unlock_time, priority, extra, account_index, subaddress_indices, subtract_fee_from);
  MTRACE("monero_wallet_light::create_txs after create transactions 2");
  if (ptx_vector.empty()) throw std::runtime_error("No transaction created");

  // check if request cannot be fulfilled due to splitting
  if (ptx_vector.size() > 1) {
    if (config.m_can_split != boost::none && !config.m_can_split.get()) {
      throw std::runtime_error("Transaction would be too large.  Try create_txs()");
    }
    if (subtract_fee_from.size() > 0 && config.m_can_split != boost::none && config.m_can_split.get()) {
      throw std::runtime_error("subtractfeefrom transfers cannot be split over multiple transactions yet");
    }
  }
  // config for fill_response()
  bool get_tx_keys = true;
  bool get_tx_hex = true;
  bool get_tx_metadata = true;
  bool relay = config.m_relay != boost::none && config.m_relay.get();
  if (config.m_relay != boost::none && config.m_relay.get() == true && is_multisig()) throw std::runtime_error("Cannot relay multisig transaction until co-signed");

  // commit txs (if relaying) and get response using wallet rpc's fill_response()
  std::list<std::string> tx_keys;
  std::list<uint64_t> tx_amounts;
  std::list<tools::wallet_rpc::amounts_list> tx_amounts_by_dest;
  std::list<uint64_t> tx_fees;
  std::list<uint64_t> tx_weights;
  std::string multisig_tx_hex;
  std::string unsigned_tx_hex;
  std::list<std::string> tx_hashes;
  std::list<std::string> tx_blobs;
  std::list<std::string> tx_metadatas;
  std::list<monero_utils::key_image_list> input_key_images_list;
  MTRACE("monero_wallet_light::create_txs before fill response");
  if (!monero_utils::fill_response(m_w2.get(), ptx_vector, get_tx_keys, tx_keys, tx_amounts, tx_amounts_by_dest, tx_fees, tx_weights, multisig_tx_hex, unsigned_tx_hex, !relay, tx_hashes, get_tx_hex, tx_blobs, get_tx_metadata, tx_metadatas, input_key_images_list, err)) {
    throw std::runtime_error("need to handle error filling response!");  // TODO
  }
  MTRACE("monero_wallet_light::create_txs after fill response");
  // build sent txs from results  // TODO: break this into separate utility function
  std::vector<std::shared_ptr<monero_tx_wallet>> txs;
  auto tx_hashes_iter = tx_hashes.begin();
  auto tx_keys_iter = tx_keys.begin();
  auto tx_amounts_iter = tx_amounts.begin();
  auto tx_amounts_by_dest_iter = tx_amounts_by_dest.begin();
  auto tx_fees_iter = tx_fees.begin();
  auto tx_weights_iter = tx_weights.begin();
  auto tx_blobs_iter = tx_blobs.begin();
  auto tx_metadatas_iter = tx_metadatas.begin();
  auto input_key_images_list_iter = input_key_images_list.begin();
  std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
  auto destinations_iter = destinations.begin();
  while (tx_fees_iter != tx_fees.end()) {
    // init tx with outgoing transfer from filled values
    std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
    txs.push_back(tx);
    tx->m_hash = *tx_hashes_iter;
    tx->m_key = *tx_keys_iter;
    tx->m_fee = *tx_fees_iter;
    tx->m_weight = *tx_weights_iter;
    tx->m_full_hex = *tx_blobs_iter;
    tx->m_metadata = *tx_metadatas_iter;
    std::shared_ptr<monero_outgoing_transfer> out_transfer = std::make_shared<monero_outgoing_transfer>();
    tx->m_outgoing_transfer = out_transfer;
    out_transfer->m_amount = *tx_amounts_iter;

    // init inputs with key images
    std::list<std::string> input_key_images = (*input_key_images_list_iter).key_images;
    for (const std::string& input_key_image : input_key_images) {
      std::shared_ptr<monero_output_wallet> input = std::make_shared<monero_output_wallet>();
      input->m_tx = tx;
      tx->m_inputs.push_back(input);
      input->m_key_image = std::make_shared<monero_key_image>();
      input->m_key_image.get()->m_hex = input_key_image;
    }

    // init destinations
    for (const uint64_t tx_amount_by_dest : (*tx_amounts_by_dest_iter).amounts) {
      std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
      destination->m_address = (*destinations_iter)->m_address;
      destination->m_amount = tx_amount_by_dest;
      tx->m_outgoing_transfer.get()->m_destinations.push_back(destination);
      destinations_iter++;
    }

    // init other known fields
    tx->m_is_outgoing = true;
    tx->m_payment_id = config.m_payment_id;
    tx->m_is_confirmed = false;
    tx->m_is_miner_tx = false;
    tx->m_is_failed = false;   // TODO: test and handle if true
    tx->m_relay = config.m_relay != boost::none && config.m_relay.get();
    tx->m_is_relayed = tx->m_relay.get();
    tx->m_in_tx_pool = tx->m_relay.get();
    if (!tx->m_is_failed.get() && tx->m_is_relayed.get()) tx->m_is_double_spend_seen = false;  // TODO: test and handle if true
    tx->m_num_confirmations = 0;
    tx->m_ring_size = monero_utils::RING_SIZE;
    tx->m_unlock_time = config.m_unlock_time == boost::none ? 0 : config.m_unlock_time.get();
    tx->m_is_locked = true;
    if (tx->m_is_relayed.get()) tx->m_last_relayed_timestamp = static_cast<uint64_t>(time(NULL));  // set last relayed timestamp to current time iff relayed  // TODO monero-project: this should be encapsulated in wallet2
    out_transfer->m_account_index = config.m_account_index;
    if (config.m_subaddress_indices.size() == 1) out_transfer->m_subaddress_indices.push_back(config.m_subaddress_indices[0]);  // subaddress index is known iff 1 requested  // TODO: get all known subaddress indices here

    // iterate to next element
    tx_keys_iter++;
    tx_amounts_iter++;
    tx_amounts_by_dest_iter++;
    tx_fees_iter++;
    tx_hashes_iter++;
    tx_blobs_iter++;
    tx_metadatas_iter++;
    input_key_images_list_iter++;
  }

  // build tx set
  std::shared_ptr<monero_tx_set> tx_set = std::make_shared<monero_tx_set>();
  tx_set->m_txs = txs;
  for (int i = 0; i < txs.size(); i++) txs[i]->m_tx_set = tx_set;
  if (!multisig_tx_hex.empty()) tx_set->m_multisig_tx_hex = multisig_tx_hex;
  if (!unsigned_tx_hex.empty()) 
  {
    tx_set->m_unsigned_tx_hex = unsigned_tx_hex;
  }

  // notify listeners of spent funds
  //if (relay) m_w2_listener->on_spend_txs(txs);

  return txs;
}

uint64_t monero_wallet_light::wait_for_next_block() {
  uint64_t last_block = get_daemon_height();
      
  while(true) {
    uint64_t current_block = get_daemon_height();

    if (current_block > last_block) {
      last_block = current_block;
      break;
    }

    std::this_thread::sleep_for(std::chrono::seconds(120));
  }

  return last_block;
}

void monero_wallet_light::close(bool save) {
  MTRACE("monero_wallet_light::close()");
  stop_syncing();
  if (save) this->save();
  if (m_http_client != nullptr && m_http_client->is_connected()) {
    m_http_client->disconnect();
    epee::net_utils::http::abstract_http_client *release_client = m_http_client.release();
    delete release_client;
  }

  if (m_http_admin_client != nullptr && m_http_admin_client->is_connected()) {
    m_http_admin_client->disconnect();
    epee::net_utils::http::abstract_http_client *release_admin_client = m_http_admin_client.release();
    delete release_admin_client;
  }

  if (m_http_client != nullptr) {
    epee::net_utils::http::abstract_http_client *release_client = m_http_client.release();
    delete release_client;
  }

  if (m_http_admin_client != nullptr) {
    epee::net_utils::http::abstract_http_client *release_admin_client = m_http_admin_client.release();
    delete release_admin_client;
  }

  m_w2->stop();
  m_w2->deinit();
  m_w2->callback(nullptr);

  // no pointers to destroy
}

// ------------------------------- PROTECTED HELPERS ----------------------------

void monero_wallet_light::init_common() {
  monero_wallet_full::init_common();

  m_w2->set_light_wallet(true);
  wallet2_listener *default_listener = new wallet2_listener(*this, *m_w2);
  m_w2->callback(default_listener);

  m_request_pending = false;
  m_request_accepted = false;
  m_scanned_block_height = get_restore_height();

  m_http_client = net::http::client_factory().create();
  m_http_admin_client = net::http::client_factory().create();

  if (m_lws_uri != "") {
    epee::net_utils::ssl_support_t ssl = m_lws_uri.rfind("https", 0) == 0 ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;

    if(!m_http_client->set_server(m_lws_uri, boost::none)) throw std::runtime_error("Invalid lws address");
    if(!m_http_client->connect(m_timeout)) throw std::runtime_error("Could not connect to lws");
    if(!m_w2->init(m_lws_uri, boost::none, {}, 0, false, ssl)) throw std::runtime_error("Failed to initialize light wallet with daemon connection");
    login();
  } else {
    throw std::runtime_error("Must provide a lws address");
  }

  if (m_lws_admin_uri != "") {
    if (!m_http_admin_client->set_server(m_lws_admin_uri, boost::none)) throw std::runtime_error("Invalid admin lws address");
    if (!m_http_admin_client->connect(m_timeout)) throw std::runtime_error("Could not connect to admin lws");
  } else {
    m_http_admin_client = nullptr;
  }
}

void monero_wallet_light::calculate_balances() {
  uint64_t total_received = 0;
  uint64_t total_sent = 0;
  uint64_t total_pending_received = 0;

  uint64_t total_pending_sent = 0;
  uint64_t total_locked_received = 0;
  uint64_t total_locked_sent = 0;

  for (monero_light_transaction transaction : m_transactions) {
    if (transaction.m_mempool != boost::none && transaction.m_mempool.get()) {
      total_pending_sent += monero_utils::uint64_t_cast(transaction.m_total_sent.get());
      total_pending_received += monero_utils::uint64_t_cast(transaction.m_total_received.get());
    } else {
      // transaction has confirmations

      if (transaction.m_height == boost::none) throw std::runtime_error("transaction height is null!");
      uint64_t tx_confirmations = m_scanned_block_height - transaction.m_height.get();

      if (tx_confirmations < 10) {
        if (!is_view_only()) total_locked_sent += monero_utils::uint64_t_cast(transaction.m_total_sent.get());
        total_locked_received += monero_utils::uint64_t_cast(transaction.m_total_received.get());
      }

      total_received += monero_utils::uint64_t_cast(transaction.m_total_received.get());
      if (m_w2 == nullptr) throw std::runtime_error("calculate_balances(): wallet2 is null");

      if (!is_view_only()) total_sent += monero_utils::uint64_t_cast(transaction.m_total_sent.get());
    }
  }

  m_balance = total_received - total_sent;
  m_balance_pending = total_pending_received - total_pending_sent;
  m_balance_unlocked = m_balance - total_locked_received - total_locked_sent;
}

bool monero_wallet_light::is_output_spent(monero_light_output output) const {
  if (output.m_spend_key_images == boost::none || output.m_spend_key_images.get().empty()) return false;

  for (std::string spend_key_image : output.m_spend_key_images.get()) {
    if (key_image_is_ours(spend_key_image, output.m_tx_pub_key.get(), output.m_index.get())) {
      return true;
    }
  }

  return false;
}

bool monero_wallet_light::is_mined_output(monero_light_output output) const {
  bool is_mined = false;
  // to do
  return is_mined;
}

// ------------------------------- PROTECTED LWS HELPERS ----------------------------

const epee::net_utils::http::http_response_info* monero_wallet_light::post(std::string method, std::string &body, bool admin) const {
  const epee::net_utils::http::http_response_info *response = nullptr;
  
  if (admin) {
    if (m_http_admin_client == nullptr || m_admin_uri == "") {
      throw std::runtime_error("Must set admin lws address before calling admin methods");
    }
    if (!m_http_admin_client->invoke_post(method, body, m_timeout, &response)) {
      throw std::runtime_error("Network error");
    }    
  }
  else {
    if (!m_http_client->invoke_post(method, body, m_timeout, &response)) {
      throw std::runtime_error("Network error");
    }
  }

  return response;
}

monero_light_get_address_info_response monero_wallet_light::get_address_info(monero_light_get_address_info_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/get_address_info", body);
  int status_code = response->m_response_code;

  if (status_code == 403) {
    if (m_request_pending) {
      throw std::runtime_error("Authorization request is pending");
    }

    throw std::runtime_error("Not authorized");
  }

  else if (status_code == 200) {
    return *monero_light_get_address_info_response::deserialize(response->m_body);
  }

  throw std::runtime_error("Unknown error");
}

monero_light_get_address_txs_response monero_wallet_light::get_address_txs(monero_light_get_address_txs_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/get_address_txs", body);
  int status_code = response->m_response_code;

  if (status_code == 403) {
    if (m_request_pending) {
      throw std::runtime_error("Authorization request is pending");
    }

    throw std::runtime_error("Not authorized");
  }

  else if (status_code == 200) {
    return *monero_light_get_address_txs_response::deserialize(response->m_body);
  }

  throw std::runtime_error("Unknown error");
}

monero_light_get_random_outs_response monero_wallet_light::get_random_outs(monero_light_get_random_outs_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/get_random_outs", body);
  int status_code = response->m_response_code;
  if (status_code == 200) {
    return *monero_light_get_random_outs_response::deserialize(response->m_body);
  }

  throw std::runtime_error("Unknown error");
}

monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(monero_light_get_unspent_outs_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/get_unspent_outs", body);
  int status_code = response->m_response_code;
  if (status_code == 403) {
    if (m_request_pending) {
      throw std::runtime_error("Authorization request is pending");
    }

    throw std::runtime_error("Not authorized");
  }
  else if (status_code == 400) {
    throw std::runtime_error("Outputs are less than amount");
  }
  else if (status_code == 200) {
    return *monero_light_get_unspent_outs_response::deserialize(response->m_body);
  }

  throw std::runtime_error("Unknown error");
}

monero_light_import_request_response monero_wallet_light::import_request(monero_light_import_request_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/import_wallet_request", body);
  int status_code = response->m_response_code;

  if (status_code != 200) {
    throw std::runtime_error("Unknown error");
  }

  return *monero_light_import_request_response::deserialize(response->m_body);
}

monero_light_submit_raw_tx_response monero_wallet_light::submit_raw_tx(monero_light_submit_raw_tx_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/submit_raw_tx", body);
  int status_code = response->m_response_code;
  
  if (status_code != 200) {
    throw std::runtime_error("Unknown error while submit tx");
  }

  return *monero_light_submit_raw_tx_response::deserialize(response->m_body);
}

monero_light_login_response monero_wallet_light::login(monero_light_login_request request) {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();
  const epee::net_utils::http::http_response_info *response = post("/login", body);
  int status_code = response->m_response_code;

  if (status_code == 501) {
    throw std::runtime_error("Server does not allow account creations");
  }
  else if (status_code == 403) {
    m_request_pending = true;
    m_request_accepted = false;
    throw std::runtime_error("Authorization request is pending");
  } else if (status_code != 200) {
    throw std::runtime_error("Unknown error on login: " + std::to_string(status_code));
  }

  if(m_request_pending) {
    m_request_pending = false;
    m_request_accepted = true;
  } else if (!m_request_pending && !m_request_accepted) {
    // first time?
    const epee::net_utils::http::http_response_info *info = post("/login", body);
    int status_code_info = info->m_response_code;

    if (status_code_info == 403) {
      m_request_pending = true;
      m_request_accepted = false;
    } else if (status_code_info == 200) {
      m_request_pending = false;
      m_request_accepted = true;
    } else {
      throw std::runtime_error("Unknown error while checking login request");
    }
  }

  return *monero_light_login_response::deserialize(response->m_body);
}

monero_light_provision_subaddrs_response monero_wallet_light::provision_subaddrs(monero_light_provision_subaddrs_request request) {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();
  const epee::net_utils::http::http_response_info *response = post("/provision_subaddrs", body);
  int status_code = response->m_response_code;

  if (status_code != 200) {
    throw std::runtime_error("Unknown error on provision subaddrs: " + std::to_string(status_code));
  }

  return *monero_light_provision_subaddrs_response::deserialize(response->m_body);
}

monero_light_upsert_subaddrs_response monero_wallet_light::upsert_subaddrs(monero_light_upsert_subaddrs_request request) {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();
  const epee::net_utils::http::http_response_info *response = post("/upsert_subaddrs", body);
  int status_code = response->m_response_code;

  if (status_code != 200) {
    throw std::runtime_error("Unknown error on upsert subaddrs: " + std::to_string(status_code));
  }

  return *monero_light_upsert_subaddrs_response::deserialize(response->m_body);
}

monero_light_get_subaddrs_response monero_wallet_light::get_subaddrs(monero_light_get_subaddrs_request request) {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();
  const epee::net_utils::http::http_response_info *response = post("/get_subaddrs", body);
  int status_code = response->m_response_code;

  if (status_code != 200) {
    throw std::runtime_error("Unknown error on upsert subaddrs: " + std::to_string(status_code));
  }

  return *monero_light_get_subaddrs_response::deserialize(response->m_body);
}

// ------------------------------- PROTECTED LWS ADMIN HELPERS ----------------------------

void monero_wallet_light::accept_requests(monero_light_accept_requests_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/accept_requests", body, true);
  int status_code = response->m_response_code;

  if (status_code == 403) throw std::runtime_error("Not authorized");
  if (status_code != 200) throw std::runtime_error("Unknown error");
}

void monero_wallet_light::reject_requests(monero_light_reject_requests_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/reject_requests", body, true);
  int status_code = response->m_response_code;

  if (status_code == 403) throw std::runtime_error("Not authorized");
  if (status_code != 200) throw std::runtime_error("Unknown error");
}

void monero_wallet_light::add_account(monero_light_add_account_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/add_account", body, true);
  int status_code = response->m_response_code;

  if (status_code == 403) throw std::runtime_error("Not authorized");
  if (status_code != 200) throw std::runtime_error("Unknown error");
}

monero_light_list_accounts_response monero_wallet_light::list_accounts(monero_light_list_accounts_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/list_accounts", body, true);
  int status_code = response->m_response_code;

  if (status_code == 403) throw std::runtime_error("Not authorized");
  if (status_code != 200) throw std::runtime_error("Unknown error");

  return *monero_light_list_accounts_response::deserialize(response->m_body);
}

monero_light_list_requests_response monero_wallet_light::list_requests(monero_light_list_requests_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/list_requests", body, true);
  int status_code = response->m_response_code;

  if (status_code == 403) throw std::runtime_error("Not authorized");
  if (status_code != 200) throw std::runtime_error("Unknown error");

  return *monero_light_list_requests_response::deserialize(response->m_body);
}

void monero_wallet_light::modify_account_status(monero_light_modify_account_status_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/modify_account_status", body, true);
  int status_code = response->m_response_code;

  if (status_code == 403) throw std::runtime_error("Not authorized");
  if (status_code != 200) throw std::runtime_error("Unknown error");
}

void monero_wallet_light::rescan(monero_light_rescan_request request) const {
  rapidjson::Document document(rapidjson::Type::kObjectType);
  rapidjson::Value req = request.to_rapidjson_val(document.GetAllocator());
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  req.Accept(writer);
  std::string body = sb.GetString();

  const epee::net_utils::http::http_response_info *response = post("/rescan", body, true);
  int status_code = response->m_response_code;

  if (status_code == 403) throw std::runtime_error("Not authorized");
  if (status_code != 200) throw std::runtime_error("Unknown error");
}

}