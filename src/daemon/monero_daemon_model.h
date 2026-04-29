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

#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "net/http.h"

/**
 * Public interface for libmonero-cpp library.
 */
namespace monero {

  class thread_poller {
  public:
    ~thread_poller();

    bool is_polling() const { return m_is_polling; }
    void set_is_polling(bool is_polling);
    void set_period_in_ms(uint64_t period_ms) { m_poll_period_ms = period_ms; }
    virtual void poll() = 0;

  protected:
    std::string m_name;
    boost::recursive_mutex m_mutex;
    boost::mutex m_polling_mutex;
    boost::thread m_thread;
    std::atomic<bool> m_is_polling;
    std::atomic<bool> m_poll_loop_running;
    std::atomic<uint64_t> m_poll_period_ms;
    boost::condition_variable m_poll_cv;

    void init_common(const std::string& name);
    void run_poll_loop();
  };

  class monero_error : public std::exception {
  public:
    std::string message;

    monero_error() {}
    monero_error(const std::string& msg) : message(msg) {}

    const char* what() const noexcept override {
      return message.c_str();
    }
  };

  class monero_rpc_error : public monero_error {
  public:
    int code;

    monero_rpc_error(int error_code, const std::string& msg) : code(error_code) { message = msg; }
    monero_rpc_error(const std::string& msg) : code(-1) { message = msg; }
  };

  /**
   * Base struct which can be serialized.
   */
  struct serializable_struct {

    virtual ~serializable_struct() {}

    /**
     * Serializes the struct to a json std::string.
     *
     * @return the struct serialized to a json std::string
     */
    std::string serialize() const;

    /**
     * Converts the struct to a rapidjson Value.
     *
     * @param allocator is the rapidjson document allocator
     * @return the struct as a rapidjson Value
     */
    virtual rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const = 0;
  };

  /**
   * key-value struct which can be serialized.
   */
  struct key_value : public monero::serializable_struct {
  public:
    boost::optional<std::string> m_key;
    boost::optional<std::string> m_value;

    key_value() { }
    key_value(const std::string& key): m_key(key) { }
    key_value(const std::string& key, const std::string& value): m_key(key), m_value(value) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<key_value>& attributes);
  };

  /**
   * Models connection ssl options.
   */
  struct ssl_options : public monero::serializable_struct {
  public:
    boost::optional<std::string> m_ssl_private_key_path;
    boost::optional<std::string> m_ssl_certificate_path;
    boost::optional<std::string> m_ssl_ca_file;
    std::vector<std::string> m_ssl_allowed_fingerprints;
    boost::optional<bool> m_ssl_allow_any_cert;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Enumerates Monero connection types.
   */
  enum monero_connection_type : uint8_t {
    INVALID = 0,
    IPV4,
    IPV6,
    TOR,
    I2P
  };

  /**
   * Models connection bandwith limits.
   */
  struct monero_bandwidth_limits : public monero::serializable_struct {
  public:
    boost::optional<int> m_up;
    boost::optional<int> m_down;

    monero_bandwidth_limits() { }
    monero_bandwidth_limits(int up, int down): m_up(up), m_down(down) { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_bandwidth_limits>& limits);
  };

  /**
   * Enumerates Monero network types.
   */
  enum monero_network_type : uint8_t {
      MAINNET = 0,
      TESTNET,
      STAGENET
  };

  /**
   * Models a Monero version.
   */
  struct monero_version : public serializable_struct {
    boost::optional<uint32_t> m_number;
    boost::optional<bool> m_is_release;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_version>& version);
  };

  /**
   * Models a request to a RPC server.
   */
  struct monero_rpc_request : public monero::serializable_struct {
  public:
    boost::optional<std::string> m_id;
    boost::optional<std::string> m_version;
    boost::optional<std::string> m_method;
    boost::optional<std::shared_ptr<monero::serializable_struct>> m_params;

    monero_rpc_request() { }
    monero_rpc_request(const std::string& method, const std::shared_ptr<monero::serializable_struct>& params, bool json_rpc = true);

    bool is_json_rpc() const { return m_id != boost::none && m_version != boost::none; }

    std::string to_binary_val() const;
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
   * Models a response from a RPC server.
   */
  struct monero_rpc_response {
  public:
    boost::optional<std::string> m_jsonrpc;
    boost::optional<boost::property_tree::ptree> m_result;
    boost::optional<boost::property_tree::ptree> m_response;
    boost::optional<std::string> m_binary;

    monero_rpc_response() { }
    monero_rpc_response(const std::string &binary): m_binary(binary) { }

    static std::shared_ptr<monero_rpc_response> deserialize(const std::string& response_json);
    static void raise_rpc_error(const boost::property_tree::ptree& error_node);
  };

  /**
   * Models parameters for a request to a RPC server.
   */
  struct monero_request_params : public monero::serializable_struct {
  public:
    monero_request_params() { }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
  * Models paramaters for monerod-rpc `/get_blocks_by_height.bin` method.
  */
  struct monero_get_blocks_by_height_request : public monero_rpc_request {
  public:
    std::vector<uint64_t> m_heights;

    monero_get_blocks_by_height_request(uint64_t num_blocks);
    monero_get_blocks_by_height_request(const std::vector<uint64_t>& heights): m_heights(heights) { m_method = "get_blocks_by_height.bin"; }

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  /**
  * Maintains a connection and sends requests to a Monero RPC API.
  */
  class monero_rpc_connection : public serializable_struct {
  public:
    boost::optional<std::string> m_uri;
    boost::optional<std::string> m_username;
    boost::optional<std::string> m_password;
    boost::optional<std::string> m_proxy_uri;
    boost::optional<std::string> m_zmq_uri;  // TODO implement zmq listener
    int m_priority;                          // priority relative to other connections. 1 is highest, then priority 2, etc. Default prorioty is 0, lowest priority.
    uint64_t m_timeout;                      // RPC request timeout in milliseconds.
    boost::optional<long> m_response_time;   // automatically set by calling check_connection()

    static std::shared_ptr<monero_rpc_connection> from_property_tree(const boost::property_tree::ptree& node);

    /**
    * Checks rpc connection order.
    *
    * @param c1 first RPC connection to compare.
    * @param c2 second RPC connection to compare.
    * @param current_connection connection with highest priority.
    */
    static bool before(const std::shared_ptr<monero_rpc_connection>& c1, const std::shared_ptr<monero_rpc_connection>& c2, const std::shared_ptr<monero_rpc_connection>& current_connection);

    /**
    * Checks connection priority order.
    *
    * @param c1 first priority to compare.
    * @param c2 second priority to compare.
    */
    static bool compare(int p1, int p2);

    /**
    * Initialize a new RPC connection.
    *
    * @param uri RPC connection uri.
    * @param username RPC connection authentication username.
    * @param password RPC connection authentication password.
    * @param proxy_uri RPC connection proxy uri.
    * @param zmq_uri RPC connection zmq uri.
    * @param priority RPC connection priority.
    * @param timeout RPC connection timeout in milliseconds.
    */
    monero_rpc_connection(const std::string& uri = "", const std::string& username = "", const std::string& password = "", const std::string& proxy_uri = "", const std::string& zmq_uri = "", int priority = 0, uint64_t timeout = 20000);

    /**
    * Copy a RPC connection.
    *
    * @param rpc RPC connection to copy.
    */
    monero_rpc_connection(const monero::monero_rpc_connection& rpc);

    /**
    * Indicates if the connection uri is a TOR server.
    *
    * @return true or false to indicate if connection uri is a TOR server.
    */
    bool is_onion() const;

    /**
    * Indicates if the connection uri is a I2P server.
    *
    * @return true or false to indicate if connection uri is a I2P server.
    */
    bool is_i2p() const;

    /**
    * Set connection credentials.
    *
    * @param username username to use in RPC authentication.
    * @param password password to use in RPC authentication.
    */
    void set_credentials(const std::string& username, const std::string& password);

    /**
    * Set connection attribute.
    *
    * @param key is the attribute key
    * @param val is the attribute value
    */
    void set_attribute(const std::string& key, const std::string& val);

    /**
    * Get connection attribute.
    *
    * @param key is the attribute to get the value of
    * @return key's value if set
    */
    std::string get_attribute(const std::string& key) const;

    /**
    * Indicates if the connection is online, which is set automatically by calling check_connection().
    *
    * @return true or false to indicate if online, or null if check_connection() has not been called
    */
    boost::optional<bool> is_online() const { return m_is_online; }

    /**
    * Indicates if the connection is authenticated, which is set automatically by calling check_connection().
    *
    * @return true if authenticated or no authentication, false if not authenticated, or null if not set
    */
    boost::optional<bool> is_authenticated() const { return m_is_authenticated; }

    /**
    * Indicates if the connection is connected, which is set automatically by calling check_connection().
    *
    * @return true or false to indicate if connected, or null if check_connection() has not been called
    */
    boost::optional<bool> is_connected() const;

    /**
    * Check the connection and update online, authentication, and response time status.
    *
    * @param timeout_ms the maximum response time before considered offline
    * @return
    */
    bool check_connection(const boost::optional<int>& timeout_ms = boost::none);

    /**
    * Resets the current connection.
    */
    void reset();

    /**
    * Send a request to the RPC API.
    *
    * @param path specifies the method to request
    * @param params are the request's input parameters
    * @return the RPC API response as a map
    */
    const boost::property_tree::ptree send_json_request(const std::string& path, const std::shared_ptr<monero::serializable_struct>& params = nullptr);

    /**
    * Send a request to the RPC API.
    *
    * @param request specifies the method to request with parameters
    * @param timeout request timeout in milliseconds
    * @return the RPC API response as a map
    */
    const monero_rpc_response send_json_request(const monero_rpc_request &request, std::chrono::milliseconds timeout = std::chrono::seconds(15));

    /**
    * Send a RPC request to the given path and with the given paramters.
    *
    * E.g. "/get_transactions" with params
    *
    * @param path is the url path of the request to invoke
    * @param params are request parameters sent in the body
    * @return the RPC API response as a map
    */
    const boost::property_tree::ptree send_path_request(const std::string& path, const std::shared_ptr<monero::serializable_struct>& params = nullptr);

    /**
    * Send a RPC request to the given path and with the given paramters.
    *
    * @param request specifies the method to request with parameters
    * @param timeout request timeout in milliseconds
    * @return the request's deserialized response
    */
    const monero_rpc_response send_path_request(const monero_rpc_request &request, std::chrono::milliseconds timeout = std::chrono::seconds(15));

    /**
    * Send a binary RPC request.
    *
    * @param request specifies the method to request with paramesters
    * @param timeout request timeout in milliseconds
    * @return the request's deserialized response
    */
    const monero_rpc_response send_binary_request(const monero_rpc_request &request, std::chrono::milliseconds timeout = std::chrono::seconds(15));

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;

  protected:
    // instance variables
    mutable boost::recursive_mutex m_mutex;
    std::string m_server;
    boost::optional<epee::net_utils::http::login> m_credentials;
    std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
    std::unordered_map<std::string, std::string> m_attributes;
    boost::optional<bool> m_is_online;
    boost::optional<bool> m_is_authenticated;

    const epee::net_utils::http::http_response_info* invoke_post(const boost::string_ref uri, const std::string& body, std::chrono::milliseconds timeout = std::chrono::seconds(15)) const;

    template<class t_request, class t_response>
    inline int invoke_post(const boost::string_ref uri, const t_request& request, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15)) const {
      std::string body = request.serialize();
      const epee::net_utils::http::http_response_info* response = invoke_post(uri, body, timeout);
      if (response->m_response_code == 200) {
        res = *t_response::deserialize(response->m_body);
      }
      return response->m_response_code;
    }

  };

  // forward declarations
  struct monero_tx;
  struct monero_output;

  /**
   * Models a Monero block header which contains information about the block.
   *
   * TODO: a header that is transmitted may have fewer fields like cryptonote::block_header; separate?
   */
  struct monero_block_header : public serializable_struct {
    boost::optional<std::string> m_hash;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_timestamp;
    boost::optional<uint64_t> m_size;
    boost::optional<uint64_t> m_weight;
    boost::optional<uint64_t> m_long_term_weight;
    boost::optional<uint64_t> m_depth;
    boost::optional<uint64_t> m_difficulty;
    boost::optional<uint64_t> m_cumulative_difficulty;
    boost::optional<uint32_t> m_major_version;
    boost::optional<uint32_t> m_minor_version;
    boost::optional<uint32_t> m_nonce;
    boost::optional<std::string> m_miner_tx_hash;
    boost::optional<uint32_t> m_num_txs;
    boost::optional<bool> m_orphan_status;
    boost::optional<std::string> m_prev_hash;
    boost::optional<uint64_t> m_reward;
    boost::optional<std::string> m_pow_hash;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    std::shared_ptr<monero_block_header> copy(const std::shared_ptr<monero_block_header>& src, const std::shared_ptr<monero_block_header>& tgt) const;
    virtual void merge(const std::shared_ptr<monero_block_header>& self, const std::shared_ptr<monero_block_header>& other);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero::monero_block_header>& header);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero::monero_block_header>>& headers);
  };

  /**
   * Models a Monero block in the blockchain.
   */
  struct monero_block : public monero_block_header {
    boost::optional<std::string> m_hex;
    boost::optional<std::shared_ptr<monero_tx>> m_miner_tx;
    std::vector<std::shared_ptr<monero_tx>> m_txs;
    std::vector<std::string> m_tx_hashes;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    std::shared_ptr<monero_block> copy(const std::shared_ptr<monero_block>& src, const std::shared_ptr<monero_block>& tgt) const;
    void merge(const std::shared_ptr<monero_block_header>& self, const std::shared_ptr<monero_block_header>& other);
    void merge(const std::shared_ptr<monero_block>& self, const std::shared_ptr<monero_block>& other);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero::monero_block>& block);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, const std::vector<uint64_t>& heights, std::vector<std::shared_ptr<monero::monero_block>>& blocks);
  };

  /**
   * Models a Monero transaction on the blockchain.
   */
  struct monero_tx : public serializable_struct {
    static const std::string DEFAULT_PAYMENT_ID;  // default payment id "0000000000000000"
    static const std::string DEFAULT_ID;

    boost::optional<std::shared_ptr<monero_block>> m_block;
    boost::optional<std::string> m_hash;
    boost::optional<uint32_t> m_version;
    boost::optional<bool> m_is_miner_tx;
    boost::optional<std::string> m_payment_id;
    boost::optional<uint64_t> m_fee;
    boost::optional<uint32_t> m_ring_size;
    boost::optional<bool> m_relay;
    boost::optional<bool> m_is_relayed;
    boost::optional<bool> m_is_confirmed;
    boost::optional<bool> m_in_tx_pool;
    boost::optional<uint64_t> m_num_confirmations;
    boost::optional<uint64_t> m_unlock_time;
    boost::optional<uint64_t> m_last_relayed_timestamp;
    boost::optional<uint64_t> m_received_timestamp;
    boost::optional<bool> m_is_double_spend_seen;
    boost::optional<std::string> m_key;
    boost::optional<std::string> m_full_hex;
    boost::optional<std::string> m_pruned_hex;
    boost::optional<std::string> m_prunable_hex;
    boost::optional<std::string> m_prunable_hash;
    boost::optional<uint64_t> m_size;
    boost::optional<uint64_t> m_weight;
    std::vector<std::shared_ptr<monero_output>> m_inputs;
    std::vector<std::shared_ptr<monero_output>> m_outputs;
    std::vector<uint64_t> m_output_indices;
    boost::optional<std::string> m_metadata;
    boost::optional<std::string> m_common_tx_sets;
    std::vector<uint8_t> m_extra;
    boost::optional<std::string> m_rct_signatures;   // TODO: implement
    boost::optional<std::string> m_rct_sig_prunable;  // TODO: implement
    boost::optional<bool> m_is_kept_by_block;
    boost::optional<bool> m_is_failed;
    boost::optional<uint64_t> m_last_failed_height;
    boost::optional<std::string> m_last_failed_hash;
    boost::optional<uint64_t> m_max_used_block_height;
    boost::optional<std::string> m_max_used_block_hash;
    std::vector<std::string> m_signatures;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, std::shared_ptr<monero_tx> tx);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero::monero_tx>& tx);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero::monero_tx>>& txs);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, std::vector<std::string>& tx_hashes);
    std::shared_ptr<monero_tx> copy(const std::shared_ptr<monero_tx>& src, const std::shared_ptr<monero_tx>& tgt) const;
    virtual void merge(const std::shared_ptr<monero_tx>& self, const std::shared_ptr<monero_tx>& other);
    boost::optional<uint64_t> get_height() const;
  };

  /**
   * Models a Monero key image.
   */
  struct monero_key_image : public serializable_struct {
    boost::optional<std::string> m_hex;
    boost::optional<std::string> m_signature;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_key_image>& key_image);
    static std::vector<std::shared_ptr<monero_key_image>> deserialize_key_images(const std::string& key_images_json);  // TODO: remove this specialty util used once
    std::shared_ptr<monero_key_image> copy(const std::shared_ptr<monero_key_image>& src, const std::shared_ptr<monero_key_image>& tgt) const;
    void merge(const std::shared_ptr<monero_key_image>& self, const std::shared_ptr<monero_key_image>& other);
  };

  /**
   * Models a Monero transaction output.
   */
  struct monero_output : public serializable_struct {
    std::shared_ptr<monero_tx> m_tx;
    boost::optional<std::shared_ptr<monero_key_image>> m_key_image;
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_index;
    std::vector<uint64_t> m_ring_output_indices;
    boost::optional<std::string> m_stealth_public_key;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output>& output);
    std::shared_ptr<monero_output> copy(const std::shared_ptr<monero_output>& src, const std::shared_ptr<monero_output>& tgt) const;
    virtual void merge(const std::shared_ptr<monero_output>& self, const std::shared_ptr<monero_output>& other);
    static void from_rpc_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output>& output);
  };

  /**
  * Models the status of a Monero key image.
  */
  enum monero_key_image_spent_status : uint8_t {
    NOT_SPENT = 0,
    CONFIRMED,
    TX_POOL
  };

  /**
  * Models a Monero RPC payment information.
  */
  struct monero_rpc_payment_info : public monero::serializable_struct {
  public:
    boost::optional<uint64_t> m_credits;
    boost::optional<std::string> m_top_block_hash;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_rpc_payment_info>& rpc_payment_info);
  };

  struct monero_alt_chain : public monero::serializable_struct {
  public:
    std::vector<std::string> m_block_hashes;
    boost::optional<uint64_t> m_difficulty;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_length;
    boost::optional<std::string> m_main_chain_parent_block_hash;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_alt_chain>& alt_chain);
  };

  struct monero_ban : public monero::serializable_struct {
  public:
    boost::optional<std::string> m_host;
    boost::optional<int> m_ip;
    boost::optional<bool> m_is_banned;
    boost::optional<uint64_t> m_seconds;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_ban>& ban);
    static void from_property_tree(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_ban>>& bans);
  };

  struct monero_prune_result : public monero::serializable_struct {
  public:
    boost::optional<bool> m_is_pruned;
    boost::optional<int> m_pruning_seed;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_prune_result>& result);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_mining_status : public monero::serializable_struct {
  public:
    boost::optional<bool> m_is_active;
    boost::optional<bool> m_is_background;
    boost::optional<std::string> m_address;
    boost::optional<uint64_t> m_speed;
    boost::optional<int> m_num_threads;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_mining_status>& status);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_miner_tx_sum : public monero::serializable_struct {
  public:
    boost::optional<uint64_t> m_emission_sum;
    boost::optional<uint64_t> m_fee_sum;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_miner_tx_sum>& sum);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_block_template : public monero::serializable_struct {
  public:
    boost::optional<std::string> m_block_template_blob;
    boost::optional<std::string> m_block_hashing_blob;
    boost::optional<std::string> m_prev_hash;
    boost::optional<std::string> m_seed_hash;
    boost::optional<std::string> m_next_seed_hash;
    boost::optional<uint64_t> m_difficulty;
    boost::optional<uint64_t> m_expected_reward;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_reserved_offset;
    boost::optional<uint64_t> m_seed_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_block_template>& tmplt);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_connection_span : public monero::serializable_struct {
  public:
    boost::optional<std::string> m_connection_id;
    boost::optional<std::string> m_remote_address;
    boost::optional<uint64_t> m_num_blocks;
    boost::optional<uint64_t> m_rate;
    boost::optional<uint64_t> m_speed;
    boost::optional<uint64_t> m_size;
    boost::optional<uint64_t> m_start_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_connection_span>& span);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_peer : public monero::serializable_struct {
  public:
    boost::optional<std::string> m_id;
    boost::optional<std::string> m_address;
    boost::optional<std::string> m_host;
    boost::optional<int> m_port;
    boost::optional<bool> m_is_online;
    boost::optional<uint64_t> m_last_seen_timestamp;
    boost::optional<int> m_pruning_seed;
    boost::optional<int> m_rpc_port;
    boost::optional<uint64_t> m_rpc_credits_per_hash;
    boost::optional<std::string> m_hash;
    boost::optional<uint64_t> m_avg_download;
    boost::optional<uint64_t> m_avg_upload;
    boost::optional<uint64_t> m_current_download;
    boost::optional<uint64_t> m_current_upload;
    boost::optional<uint64_t> m_height;
    boost::optional<bool> m_is_incoming;
    boost::optional<uint64_t> m_live_time;
    boost::optional<bool> m_is_local_ip;
    boost::optional<bool> m_is_local_host;
    boost::optional<int> m_num_receives;
    boost::optional<int> m_num_sends;
    boost::optional<uint64_t> m_receive_idle_time;
    boost::optional<uint64_t> m_send_idle_time;
    boost::optional<std::string> m_state;
    boost::optional<int> m_num_support_flags;
    boost::optional<monero_connection_type> m_connection_type;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_peer>& peer);
    static void from_property_tree(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_peer>>& peers);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_submit_tx_result : public monero_rpc_payment_info {
  public:
    boost::optional<bool> m_has_invalid_input;
    boost::optional<bool> m_has_invalid_output;
    boost::optional<bool> m_has_too_few_outputs;
    boost::optional<bool> m_is_good;
    boost::optional<bool> m_is_relayed;
    boost::optional<bool> m_is_double_spend;
    boost::optional<bool> m_is_fee_too_low;
    boost::optional<bool> m_is_mixin_too_low;
    boost::optional<bool> m_is_overspend;
    boost::optional<bool> m_is_too_big;
    boost::optional<bool> m_sanity_check_failed;
    boost::optional<bool> m_is_tx_extra_too_big;
    boost::optional<bool> m_is_nonzero_unlock_time;
    boost::optional<std::string> m_reason;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_submit_tx_result>& result);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_tx_backlog_entry {
    // TODO
  };

  struct monero_output_distribution_entry : public monero::serializable_struct {
  public:
    boost::optional<uint64_t> m_amount;
    boost::optional<int> m_base;
    std::vector<int> m_distribution;
    boost::optional<uint64_t> m_start_height;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_distribution_entry>& entry);
    static void from_property_tree(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_output_distribution_entry>>& entries);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_output_histogram_entry : public monero::serializable_struct {
  public:
    boost::optional<uint64_t> m_amount;
    boost::optional<uint64_t> m_num_instances;
    boost::optional<uint64_t> m_unlocked_instances;
    boost::optional<uint64_t> m_recent_instances;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_output_histogram_entry>& entry);
    static void from_property_tree(const boost::property_tree::ptree& node, std::vector<std::shared_ptr<monero_output_histogram_entry>>& entries);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_tx_pool_stats : public monero::serializable_struct {
  public:
    boost::optional<int> m_num_txs;
    boost::optional<int> m_num_not_relayed;
    boost::optional<int> m_num_failing;
    boost::optional<int> m_num_double_spends;
    boost::optional<int> m_num10m;
    boost::optional<uint64_t> m_fee_total;
    boost::optional<uint64_t> m_bytes_max;
    boost::optional<uint64_t> m_bytes_med;
    boost::optional<uint64_t> m_bytes_min;
    boost::optional<uint64_t> m_bytes_total;
    std::map<uint64_t, uint64_t> m_histo;
    boost::optional<uint64_t> m_histo98pc;
    boost::optional<uint64_t> m_oldest_timestamp;

    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_tx_pool_stats>& stats);
  };

  struct monero_daemon_update_check_result : public monero::serializable_struct {
  public:
    boost::optional<bool> m_is_update_available;
    boost::optional<std::string> m_version;
    boost::optional<std::string> m_hash;
    boost::optional<std::string> m_auto_uri;
    boost::optional<std::string> m_user_uri;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_check_result>& check);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_daemon_update_download_result : public monero_daemon_update_check_result {
  public:
    boost::optional<std::string> m_download_path;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_update_download_result>& check);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_fee_estimate : public monero::serializable_struct {
  public:
    boost::optional<uint64_t> m_quantization_mask;
    boost::optional<uint64_t> m_fee;
    std::vector<uint64_t> m_fees;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_fee_estimate>& estimate);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_daemon_info : public monero_rpc_payment_info {
  public:
    boost::optional<std::string> m_version;
    boost::optional<uint64_t> m_num_alt_blocks;
    boost::optional<uint64_t> m_block_size_limit;
    boost::optional<uint64_t> m_block_size_median;
    boost::optional<uint64_t> m_block_weight_limit;
    boost::optional<uint64_t> m_block_weight_median;
    boost::optional<std::string> m_bootstrap_daemon_address;
    boost::optional<uint64_t> m_difficulty;
    boost::optional<uint64_t> m_cumulative_difficulty;
    boost::optional<uint64_t> m_free_space;
    boost::optional<int> m_num_offline_peers;
    boost::optional<int> m_num_online_peers;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_height_without_bootstrap;
    boost::optional<monero::monero_network_type> m_network_type;
    boost::optional<bool> m_is_offline;
    boost::optional<int> m_num_incoming_connections;
    boost::optional<int> m_num_outgoing_connections;
    boost::optional<int> m_num_rpc_connections;
    boost::optional<uint64_t> m_start_timestamp;
    boost::optional<uint64_t> m_adjusted_timestamp;
    boost::optional<uint64_t> m_target;
    boost::optional<uint64_t> m_target_height;
    boost::optional<int> m_num_txs;
    boost::optional<int> m_num_txs_pool;
    boost::optional<bool> m_was_bootstrap_ever_used;
    boost::optional<uint64_t> m_database_size;
    boost::optional<bool> m_update_available;
    boost::optional<bool> m_is_busy_syncing;
    boost::optional<bool> m_is_synchronized;
    boost::optional<bool> m_is_restricted;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_info>& info);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_daemon_sync_info : public monero_rpc_payment_info {
  public:
    boost::optional<std::string> m_overview;
    boost::optional<uint64_t> m_height;
    boost::optional<uint64_t> m_target_height;
    boost::optional<int> m_next_needed_pruning_seed;
    std::vector<monero_peer> m_peers;
    std::vector<monero_connection_span> m_spans;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_daemon_sync_info>& info);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

  struct monero_hard_fork_info : public monero_rpc_payment_info {
  public:
    boost::optional<bool> m_is_enabled;
    boost::optional<uint64_t> m_earliest_height;
    boost::optional<int> m_state;
    boost::optional<int> m_threshold;
    boost::optional<int> m_version;
    boost::optional<int> m_num_votes;
    boost::optional<int> m_window;
    boost::optional<int> m_voting;

    static void from_property_tree(const boost::property_tree::ptree& node, const std::shared_ptr<monero_hard_fork_info>& info);
    rapidjson::Value to_rapidjson_val(rapidjson::Document::AllocatorType& allocator) const override;
  };

}
