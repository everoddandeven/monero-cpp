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
  // --------------------------- STATIC WALLET UTILS --------------------------

  bool monero_wallet_light::wallet_exists(const std::string& path) {
    bool key_file_exists;
    bool wallet_file_exists;
    tools::wallet2::wallet_exists(path, key_file_exists, wallet_file_exists);
    return key_file_exists;
  }

  monero_wallet_light* monero_wallet_light::open_wallet(const std::string& path, const std::string& password, const monero_network_type network_type) {
    monero_wallet_light* wallet = new monero_wallet_light();
    wallet->m_w2 = std::unique_ptr<tools::wallet2>(new tools::wallet2(static_cast<cryptonote::network_type>(network_type), 1, true));
    wallet->m_w2->load(path, password);
    wallet->m_w2->init("");
    wallet->init_common();
    return wallet;
  }

  monero_wallet_light* monero_wallet_light::open_wallet_data(const std::string& password, const monero_network_type network_type, const std::string& keys_data, const std::string& cache_data, const monero_rpc_connection& daemon_connection, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
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

    if (m_http_client != nullptr && m_lws_uri != std::string("")) {
      if (m_http_client->is_connected()) m_http_client->disconnect();

      if (!m_http_client->set_server(m_lws_uri, boost::none)) throw std::runtime_error("Could not server: " + m_lws_uri);
      if (!m_http_client->connect(m_timeout)) throw std::runtime_error("Could not connect to server: " + m_lws_uri);

      m_w2->set_daemon(m_lws_uri);
    }
  }

  void monero_wallet_light::set_daemon_connection(std::string host, std::string port, std::string admin_uri, std::string admin_port, std::string token) {
    m_host = host;
    m_port = port;
    m_lws_uri = host + ":" + port;
    m_admin_uri = admin_uri;
    m_admin_port = admin_port;
    m_lws_admin_uri = admin_uri + ":" + admin_port;
    m_token = token;

    if (m_http_client != nullptr && host != std::string("")) {
      if (m_http_client->is_connected()) m_http_client->disconnect();

      if (!m_http_client->set_server(m_lws_uri, boost::none)) throw std::runtime_error("Could not server: " + host);
      if (!m_http_client->connect(m_timeout)) throw std::runtime_error("Could not connect to server: " + host);

      m_w2->set_daemon(m_lws_uri);
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
    try {
      m_is_connected = (m_http_client == nullptr) ? false : m_http_client->is_connected();
    }
    catch (const std::exception &e) {
      MWARNING("monero_wallet_light::is_connected_to_daemon(): " << std::string(e.what()));
      m_is_connected = false;
    }

    return m_is_connected;
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

  monero_sync_result monero_wallet_light::sync_aux(boost::optional<uint64_t> start_height) {
    MTRACE("sync_aux()");
    if (!is_connected_to_daemon()) throw std::runtime_error("sync_aux(): Wallet is not connected to daemon");
    cryptonote::block cn_block;
    // determine sync start height
    uint64_t sync_start_height = start_height == boost::none ? std::max(get_height(), get_restore_height()) : *start_height;
    
    m_w2_listener->on_sync_start(sync_start_height);

    monero_sync_result result(0, false);

    if (is_synced()) {
      return result;
      m_w2_listener->on_sync_end();
    }

    // attempt to refresh wallet2 which may throw exception
    try {
      m_w2->refresh(m_w2->is_trusted_daemon(), m_start_height, result.m_num_blocks_fetched, result.m_received_money, true);
      m_w2->light_wallet_get_address_txs();
      m_w2->light_wallet_get_unspent_outs();
      // find and save rings
      m_w2->find_and_save_rings(false);
    } catch (...) {
      MWARNING("Error occurred while wallet2 refresh");
    }

    monero_light_get_address_txs_response response = get_address_txs();
    m_start_height = response.m_start_height.get();

    uint64_t old_scanned_height = m_scanned_block_height;
    
    m_scanned_block_height = response.m_scanned_block_height.get();
    m_blockchain_height = response.m_blockchain_height.get();

    if (response.m_transactions == boost::none) m_raw_transactions = std::vector<monero_light_transaction>();
    else m_raw_transactions = response.m_transactions.get();

    monero_light_get_unspent_outs_response unspent_outs_response = get_unspent_outs();

    m_unspent_outputs = std::vector<monero_light_output>();

    if (unspent_outs_response.m_outputs != boost::none) m_unspent_outputs = unspent_outs_response.m_outputs.get();

    for(monero_light_output light_output : m_unspent_outputs) {
      bool valid_tx_hex = string_tools::validate_hex(64, light_output.m_tx_pub_key.get());
      std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();

      if (light_output.m_recipient != boost::none) {
        monero_light_address_meta recipient = light_output.m_recipient.get();

        output->m_account_index = recipient.m_maj_i.get();
        output->m_subaddress_index = recipient.m_min_i.get();
      }
      else {
        output->m_account_index = 0;
        output->m_subaddress_index = 0;
      }

      if (light_output.m_global_index == boost::none) {
        MWARNING("global index is none");
      }
      else output->m_index = monero_utils::uint64_t_cast(light_output.m_global_index.get());
      
      if (light_output.m_amount == boost::none) {
        MWARNING("amount is none!");
      }
      else output->m_amount = monero_utils::uint64_t_cast(light_output.m_amount.get());

      output->m_stealth_public_key = light_output.m_public_key;
      output->m_key_image = std::make_shared<monero_key_image>();
      output->m_key_image.get()->m_hex = "0100000000000000000000000000000000000000000000000000000000000000";
      output->m_is_spent = false;
      output->m_is_frozen = false;

      if (!m_w2->watch_only()) {
        output->m_is_spent = m_w2->light_wallet_is_output_spent(light_output.m_public_key.get(), light_output.m_tx_pub_key.get(), light_output.m_index.get());
        if (output->m_is_spent) {
          crypto::key_image output_key_image;
          m_w2->generate_output_key_image(light_output.m_public_key.get(), light_output.m_tx_pub_key.get(), light_output.m_index.get(), output_key_image);
          output->m_key_image.get()->m_hex = string_tools::pod_to_hex(output_key_image);
        }
      }

      output->m_tx = std::make_shared<monero_tx>();
      output->m_tx->m_block = std::make_shared<monero_block>();
      output->m_tx->m_block.get()->m_height = light_output.m_height.get();
      output->m_tx->m_hash = light_output.m_tx_hash;
      output->m_tx->m_key = light_output.m_tx_pub_key;
      output->m_tx->m_rct_signatures = light_output.m_rct;
      output->m_tx->m_outputs = std::vector<std::shared_ptr<monero::monero_output>>();
      output->m_tx->m_block.get()->m_txs = std::vector<std::shared_ptr<monero::monero_tx>>();
      output->m_tx->m_is_confirmed = true;
      output->m_tx->m_is_double_spend_seen = false;
      output->m_tx->m_is_failed = false;
      output->m_tx->m_is_relayed = true;
      output->m_tx->m_relay = true;
      output->m_tx->m_in_tx_pool = false;
      output->m_tx->m_block.get()->m_txs.push_back(output->m_tx);

      m_outputs.push_back(output);
    }
    
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
        cryptonote::subaddress_index subaddress_index;
        subaddress_index.major = 0;
        subaddress_index.minor = 0;

        if (spent_output.m_sender != boost::none) {
          subaddress_index.major = spent_output.m_sender.get().m_maj_i.get();
          subaddress_index.minor = spent_output.m_sender.get().m_min_i.get();
        }
        bool is_spent = key_image_is_ours(spent_output.m_key_image.get(), spent_output.m_tx_pub_key.get(), spent_output.m_out_index.get(), subaddress_index);
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
    
    calculate_balances();
    m_subaddrs.clear();

    try {
      monero_light_get_subaddrs_response response = get_subaddrs();
      
      if (response.m_all_subaddrs != boost::none) m_subaddrs = response.m_all_subaddrs.get();
      m_daemon_supports_subaddresses = true;

      
      for (auto kv : m_subaddrs) {
        uint32_t account_idx = kv.first;
        
        uint32_t num_subaddress_accounts = m_w2->get_num_subaddress_accounts();

        while (num_subaddress_accounts <= account_idx) {
          m_w2->add_subaddress_account(std::string(""));
          num_subaddress_accounts++;
        }

        std::vector<monero_light_index_range> index_ranges = kv.second;
        uint32_t maj_i = 0;

        for (monero_light_index_range index_range : index_ranges) {
          if (index_range.at(1) > maj_i) {
            maj_i = index_range.at(1);
          }
        }
        
        size_t num_subaddresses = m_w2->get_num_subaddresses(account_idx);

        while (num_subaddresses < maj_i) {
          m_w2->add_subaddress(account_idx, std::string(""));
          num_subaddresses++;
        }
      }
      //upsert_subaddr(0, 10);
    } catch (...) {
      MWARNING("Light wallet server doesn't support subaddresses");
      m_daemon_supports_subaddresses = false;
    }

    if (old_scanned_height == 0 && m_scanned_block_height > 0) {
      m_w2_listener->on_new_block(1, cn_block);
    }

    m_w2_listener->on_new_block(m_scanned_block_height, cn_block);

    m_w2_listener->update_listening();
    m_w2_listener->on_sync_end();

    return result;
  }

  //-------------------------------------------------------------------------------------
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

  bool monero_wallet_light::key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index, cryptonote::subaddress_index subaddress_index) const
  {
    return m_w2->light_wallet_key_image_is_ours(key_image, tx_public_key, out_index, subaddress_index);
  }

  bool monero_wallet_light::key_image_is_ours(const std::string& key_image, const std::string& tx_public_key, const std::string& out_index, cryptonote::subaddress_index subaddress_index) const {
    uint64_t oi = monero_utils::uint64_t_cast(out_index);

    return key_image_is_ours(key_image, tx_public_key, oi, subaddress_index);
  }

  bool monero_wallet_light::key_images_are_ours(const std::vector<key_image> key_images, const std::vector<crypto::public_key> tx_public_keys, const std::vector<uint64_t> out_indices, const std::vector<cryptonote::subaddress_index> subaddress_idxs) const {
    if (!(key_images.size() == tx_public_keys.size() == out_indices.size())) throw std::runtime_error("key_images, tx_pub_keys and out_indices must have same size.");

    bool are_ours = true;
    size_t n = key_images.size();

    for(size_t i = 0; i < n; i++) {
      const crypto::key_image& ki = key_images[i];
      const crypto::public_key& tpk = tx_public_keys[i];
      const cryptonote::subaddress_index subaddress_index = subaddress_idxs[i];
      uint64_t oi = out_indices[i];

      are_ours &= m_w2->light_wallet_key_image_is_ours(ki, tpk, oi, subaddress_index);
    }

    return are_ours;
  }

  bool monero_wallet_light::output_is_spent(const monero_light_output spend_output) const {
    if (spend_output.m_spend_key_images == boost::none || spend_output.m_spend_key_images.get().empty()) return true;

    std::string tx_public_key = spend_output.m_tx_pub_key.get();
    return m_w2->light_wallet_is_output_spent(spend_output.m_public_key.get(), tx_public_key, spend_output.m_index.get());
  }

  bool monero_wallet_light::spend_object_is_ours(const monero_light_spend spend_object) const {
    cryptonote::subaddress_index subaddress_index;
    subaddress_index.major = 0;
    subaddress_index.minor = 0;

    if (spend_object.m_sender != boost::none) {
      subaddress_index.major = spend_object.m_sender.get().m_maj_i.get();
      subaddress_index.minor = spend_object.m_sender.get().m_min_i.get();
    }
    return key_image_is_ours(spend_object.m_key_image.get(), spend_object.m_tx_pub_key.get(), spend_object.m_out_index.get(), subaddress_index);
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
  //--------------------------------------------------------------------------------------

  void monero_wallet_light::scan_txs(const std::vector<std::string>& tx_hashes) {
    throw std::runtime_error("scan_txs() not supported");
  }

  monero_sync_result monero_wallet_light::lock_and_sync(boost::optional<uint64_t> start_height) {
    bool rescan = m_rescan_on_sync.exchange(false);
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex); // synchronize sync() and syncAsync()
    monero_sync_result result;
    result.m_num_blocks_fetched = 0;
    result.m_received_money = false;
    do {
      // skip if daemon is not connected or synced
      if (m_is_connected && is_daemon_synced()) {

        // sync wallet
        result = sync_aux(start_height);
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

    for(monero_account account : get_accounts(true, std::string(""))) {
      uint64_t account_balance = account.m_balance.get();
      total_balance += account_balance;
    }
    
    return total_balance;
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_idx) const {
    monero_account account = get_account(account_idx, true);
    uint64_t account_balance = get_balance(account_idx, 0);

    for(monero_subaddress subaddress : account.m_subaddresses) {
      if (account_idx == 0 && subaddress.m_index.get() == 0) continue;

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

    for(std::shared_ptr<monero_output_wallet> output : outputs) {
      //MWARNING("monero_wallet_light::get_balance(" << account_idx << "," << subaddress_idx << ") GOT OUTPUT " << output->m_stealth_public_key.get() << ", ACCOUNT (" << output->m_account_index.get() << "," << output->m_subaddress_index.get() << "), AMOUNT " << output->m_amount.get() << ", " << ", SPENT: " << output->m_is_spent.get() << ", CONFIRMED: " << output->m_tx->m_is_confirmed.get());

      balance += output->m_amount.get(); 
    }

    return balance;
  };

  uint64_t monero_wallet_light::get_unlocked_balance() const { 
    uint64_t total_balance = 0;

    for(monero_account account : get_accounts(true, std::string(""))) {
      total_balance += account.m_unlocked_balance.get();
    }
    
    return total_balance;
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_idx) const { 
    monero_account account = get_account(account_idx, true);
    uint64_t account_balance = get_unlocked_balance(account_idx, 0);

    for(monero_subaddress subaddress : account.m_subaddresses){
      if (account_idx == 0 && subaddress.m_index.get() == 0) continue;

      account_balance += get_unlocked_balance(account_idx, subaddress.m_index.get());
    }
    
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
      //MWARNING("monero_wallet_light::get_unlocked_balance(" << account_idx << "," << subaddress_idx << ") GOT OUTPUT " << output->m_stealth_public_key.get() << ", ACCOUNT (" << output->m_account_index.get() << "," << output->m_subaddress_index.get() << "), AMOUNT " << output->m_amount.get() << ", " << ", SPENT: " << output->m_is_spent.get()  << ", CONFIRMED: " << output->m_tx->m_is_confirmed.get());
 
      balance += output->m_amount.get();
    }
    
    return balance;
  };

  monero_account monero_wallet_light::get_account(uint32_t account_idx, bool include_subaddresses) const {
    // need transfers to inform if subaddresses used
    std::vector<tools::wallet2::transfer_details> transfers;
    if (include_subaddresses) m_w2->get_transfers(transfers);

    // build and return account
    monero_account account;
    account.m_index = account_idx;
    account.m_primary_address = get_address(account_idx, 0);
    account.m_balance = get_balance(account_idx, 0);  
    account.m_unlocked_balance = get_unlocked_balance(account_idx, 0);

    if (include_subaddresses) {
      account.m_subaddresses = get_subaddresses_aux(account_idx, std::vector<uint32_t>(), transfers);

      for(monero_subaddress subaddress : account.m_subaddresses) {
        if (subaddress.m_index.get() == 0) continue; 
        account.m_balance = account.m_balance.get() + get_balance(subaddress.m_account_index.get(), subaddress.m_index.get());
        account.m_unlocked_balance = account.m_unlocked_balance.get() + get_unlocked_balance(subaddress.m_account_index.get(), subaddress.m_index.get());
      }
    }

    return account;
  }

  monero_account monero_wallet_light::create_account(const std::string& label) {
    monero_account account = monero_wallet_full::create_account(label);
    if(!m_daemon_supports_subaddresses) return account;

    std::vector<monero_account> accounts = get_accounts(false, std::string(""));

    while (account.m_index.get() < accounts.size()) {
      account = monero_wallet_full::create_account(label);
    }

    monero_light_index_range index_range(0,0);
    
    std::vector<monero_light_index_range> index_ranges;
    index_ranges.push_back(index_range);

    monero_light_subaddrs subaddrs;
    subaddrs.emplace(account.m_index.get(), index_ranges);

    auto response = upsert_subaddrs(subaddrs);

    if (response.m_all_subaddrs != boost::none) {
      // do not refresh while updating m_subaddrs
      boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex);
      m_subaddrs = response.m_all_subaddrs.get();
    }

    return account;
  }

  std::vector<monero_account> monero_wallet_light::get_accounts(bool include_subaddresses, const std::string& tag) const {
    // do not refresh while getting accounts
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex);

    if (!m_daemon_supports_subaddresses) return monero_wallet_full::get_accounts(include_subaddresses, tag);
    std::vector<monero_account> accounts;
    bool primary_found = false;

    for (auto kv : m_subaddrs) {
      if (kv.first == 0) primary_found = true;
      monero_account account = get_account(kv.first, include_subaddresses);
      accounts.push_back(account);
    }

    if (!primary_found) {
      monero_account primary_account = get_account(0,include_subaddresses);
      accounts.push_back(primary_account);
    }

    return accounts;
  }

  monero_subaddress monero_wallet_light::create_subaddress(const uint32_t account_idx, const std::string& label) {
    // initialize and return result
    monero_subaddress subaddress = monero_wallet_full::create_subaddress(account_idx, label);
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex);

    if(!m_daemon_supports_subaddresses) return subaddress;

    uint32_t subaddr_idx = subaddress.m_index.get();
    
    while(is_address_upsert(account_idx, subaddr_idx)) {
      subaddress = monero_wallet_full::create_subaddress(account_idx, label);
      subaddr_idx = subaddress.m_index.get();
    }

    monero_light_index_range index_range(subaddr_idx, subaddr_idx);
    std::vector<monero_light_index_range> index_ranges;
    index_ranges.push_back(index_range);
    monero_light_subaddrs subaddrs;
    subaddrs.emplace(account_idx, index_ranges);

    auto response = upsert_subaddrs(subaddrs);

    if(response.m_all_subaddrs != boost::none) {
      
      m_subaddrs = response.m_all_subaddrs.get();
    }

    return subaddress;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs()  const {
    return get_txs(monero_tx_query());
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs(const monero_tx_query& query) const {
    std::vector<std::shared_ptr<monero_tx_wallet>> txs = std::vector<std::shared_ptr<monero_tx_wallet>>();

    // do not refresh while getting txs
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex);

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
      tx_wallet->m_outputs = std::vector<std::shared_ptr<monero::monero_output>>();

      uint64_t inputs_sum = 0;
      uint64_t outputs_sum = 0;

      if (tx_wallet->m_is_outgoing == boost::none) throw std::runtime_error("Could not determine tx direction! total sent:" + total_sent_str + ", total received: " + total_received_str);

      if(tx_wallet->m_is_outgoing.get()) {
        bool append_tx = false;

        for(auto spent_output : light_tx.m_spent_outputs.get())
        {
          cryptonote::subaddress_index subaddress_index;
          subaddress_index.major = 0;
          subaddress_index.minor = 0;

          if (spent_output.m_sender != boost::none) {
            subaddress_index.major = spent_output.m_sender.get().m_maj_i.get();
            subaddress_index.minor = spent_output.m_sender.get().m_min_i.get();
          }

          if(key_image_is_ours(spent_output.m_key_image.get(), spent_output.m_tx_pub_key.get(), spent_output.m_out_index.get(), subaddress_index)) {
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
      else if (tx_wallet->m_is_outgoing.get()) {
        for (auto output : m_outputs) {
          if(output->m_tx && output->m_tx->m_hash != boost::none && output->m_tx->m_hash == light_tx.m_hash.get()) {
            tx_wallet->m_outputs.push_back(output);
            outputs_sum = output->m_amount.get();
          }
        }
      }
      tx_wallet->m_unlock_time = light_tx.m_unlock_time;
      
      if (light_tx.m_payment_id != boost::none && light_tx.m_payment_id.get() != "0000000000000000") tx_wallet->m_payment_id = light_tx.m_payment_id;
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

    // do not refresh while getting transgers
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex);

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
    
    // do not refresh while getting outputs
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex);

    for (std::shared_ptr<monero_output_wallet> output : m_outputs) {
      if(!query.meets_criteria(std::static_pointer_cast<monero_output_wallet>(output).get(), false)) continue;
      
      std::shared_ptr<monero_output_wallet> clone = std::make_shared<monero_output_wallet>();
      output->copy(output, clone);
      outputs.push_back(clone);
    }

    return outputs;
  }

  std::string monero_wallet_light::export_outputs(bool all) const {
    m_w2->light_wallet_get_address_txs();
    m_w2->light_wallet_get_unspent_outs();
    return epee::string_tools::buff_to_hex_nodelimer(m_w2->export_outputs_to_str(all));
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
    uint64_t height = m_w2->import_key_images(ski, 0, spent, unspent, true); // TODO: use offset? refer to wallet_rpc_server::on_import_key_images() req.offset
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
    if (!monero_utils::validate_transfer(m_w2.get(), tr_destinations, payment_id, dsts, extra, true, err)) {
      throw std::runtime_error(err.message);
    }

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
    std::vector<wallet2::pending_tx> ptx_vector = m_w2->create_transactions_2(dsts, mixin, unlock_time, priority, extra, account_index, subaddress_indices, subtract_fee_from);
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
    if (!monero_utils::fill_response(m_w2.get(), ptx_vector, get_tx_keys, tx_keys, tx_amounts, tx_amounts_by_dest, tx_fees, tx_weights, multisig_tx_hex, unsigned_tx_hex, !relay, tx_hashes, get_tx_hex, tx_blobs, get_tx_metadata, tx_metadatas, input_key_images_list, err)) {
      throw std::runtime_error("need to handle error filling response!");  // TODO
    }
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
      if (m_syncing_enabled) {
        std::this_thread::sleep_for(std::chrono::milliseconds(m_syncing_interval));
      } else {
        sync();
      }
      
      uint64_t current_block = get_daemon_height();

      if (current_block > last_block) {
        last_block = current_block;
        break;
      }

      std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    return last_block;
  }

  void monero_wallet_light::close(bool save) {
    if (save) this->save();
    
    if (m_sync_loop_running) {
      m_sync_cv.notify_one();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));  // TODO: in emscripten, m_sync_cv.notify_one() returns without waiting, so sleep; bug in emscripten upstream llvm?
      m_syncing_thread.join();
    }
    
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
    m_w2_listener.reset();
    // no pointers to destroy
  }

  // ------------------------------- PROTECTED HELPERS ----------------------------

  void monero_wallet_light::init_common() {
    monero_wallet_full::init_common();
    m_w2->set_light_wallet(true);
    //wallet2_listener *default_listener = new wallet2_listener(*this, *m_w2);
    //m_w2->callback(default_listener);

    m_request_pending = false;
    m_request_accepted = false;
    m_scanned_block_height = 0;

    m_http_client = net::http::client_factory().create();
    m_http_admin_client = net::http::client_factory().create();

    if (m_lws_uri != "") {
      try {
        epee::net_utils::ssl_support_t ssl = m_lws_uri.rfind("https", 0) == 0 ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;

        if(!m_http_client->set_server(m_lws_uri, boost::none)) throw std::runtime_error("Invalid lws address");
        if(!m_http_client->connect(m_timeout)) throw std::runtime_error("Could not connect to lws");
        if(!m_w2->init(m_lws_uri, boost::none, {}, 0, false, ssl)) throw std::runtime_error("Failed to initialize light wallet with daemon connection");
        login();
        m_is_connected = true;
      }
      catch (...) {
        m_is_connected = false;
      }
    } else {
      m_is_connected = false;
    }

    if (m_lws_admin_uri != "") {
      if (!m_http_admin_client->set_server(m_lws_admin_uri, boost::none)) throw std::runtime_error("Invalid admin lws address");
      if (!m_http_admin_client->connect(m_timeout)) throw std::runtime_error("Could not connect to admin lws");
    }
  }

  void monero_wallet_light::calculate_balances() {
    boost::lock_guard<boost::recursive_mutex> guarg(m_sync_mutex); // synchronize sync() and syncAsync()

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

    return m_w2->light_wallet_is_output_spent(output.m_public_key.get(), output.m_tx_pub_key.get(), output.m_index.get());
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

  monero_light_provision_subaddrs_response monero_wallet_light::provision_subaddrs(monero_light_provision_subaddrs_request request) const {
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

  // private helper to initialize subaddresses using transfer details
  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses_aux(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices, const std::vector<tools::wallet2::transfer_details>& transfers) const {
    if (!m_daemon_supports_subaddresses) return monero_wallet_full::get_subaddresses_aux(account_idx, subaddress_indices, transfers);
    std::vector<monero_subaddress> subaddresses;

    // get balances per subaddress as maps
    std::map<uint32_t, uint64_t> balance_per_subaddress = m_w2->balance_per_subaddress(account_idx, STRICT_);
    std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress = m_w2->unlocked_balance_per_subaddress(account_idx, STRICT_);

    // get all indices if no indices given
    std::vector<uint32_t> subaddress_indices_req;
    if (subaddress_indices.empty()) {
      for (uint32_t subaddress_idx = 0; subaddress_idx < m_w2->get_num_subaddresses(account_idx); subaddress_idx++) {
        subaddress_indices_req.push_back(subaddress_idx);
      }
      try
      {
        std::vector<monero_light_index_range> index_ranges = m_subaddrs.at(account_idx);
        for(monero_light_index_range index_range : index_ranges) {
          for(uint32_t subaddr_idx = index_range[0]; subaddr_idx <= index_range[1]; subaddr_idx++) {
            if(std::count(subaddress_indices_req.begin(), subaddress_indices_req.end(), subaddr_idx) > 0) continue;

            subaddress_indices_req.push_back(subaddr_idx);
          }
          
        }
      } catch (...) {}

    } else {
      subaddress_indices_req = subaddress_indices;
    }

    // initialize subaddresses at indices
    for (uint32_t subaddressIndicesIdx = 0; subaddressIndicesIdx < subaddress_indices_req.size(); subaddressIndicesIdx++) {
      monero_subaddress subaddress;
      subaddress.m_account_index = account_idx;
      uint32_t subaddress_idx = subaddress_indices_req.at(subaddressIndicesIdx);
      subaddress.m_index = subaddress_idx;
      subaddress.m_address = get_address(account_idx, subaddress_idx);
      subaddress.m_label = m_w2->get_subaddress_label({account_idx, subaddress_idx});
      auto iter1 = balance_per_subaddress.find(subaddress_idx);
      subaddress.m_balance = iter1 == balance_per_subaddress.end() ? 0 : iter1->second;
      auto iter2 = unlocked_balance_per_subaddress.find(subaddress_idx);
      subaddress.m_unlocked_balance = iter2 == unlocked_balance_per_subaddress.end() ? 0 : iter2->second.first;
      cryptonote::subaddress_index index = {account_idx, subaddress_idx};
      subaddress.m_num_unspent_outputs = count_if(transfers.begin(), transfers.end(), [&](const tools::wallet2::transfer_details& td) { return !td.m_spent && td.m_subaddr_index == index; });
      subaddress.m_is_used = find_if(transfers.begin(), transfers.end(), [&](const tools::wallet2::transfer_details& td) { return td.m_subaddr_index == index; }) != transfers.end();
      subaddress.m_num_blocks_to_unlock = iter1 == balance_per_subaddress.end() ? 0 : iter2->second.second.first;
      subaddresses.push_back(subaddress);
    }

    return subaddresses;
  }

  bool monero_wallet_light::is_address_upsert(const uint32_t account_index, const uint32_t subaddress_index) const {

    for(auto kv : m_subaddrs) {
      if (!kv.first == account_index) continue;
      
    }

    return m_subaddrs.contains(account_index, subaddress_index);
  }

}