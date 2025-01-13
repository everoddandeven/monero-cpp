#include "monero_wallet_light.h"
#include "utils/gen_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "common/threadpool.h"
#include "net/jsonrpc_structs.h"
#include "string_tools.h"
#include "serialization/serialization.h"

#define APPROXIMATE_INPUT_BYTES 80
#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\004"
#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\005"
#define SIGNED_TX_PREFIX "Monero signed tx set\005"
#define MULTISIG_UNSIGNED_TX_PREFIX "Monero multisig unsigned tx set\001"

namespace
{
	template<typename T>
	T pop_index(std::vector<T>& vec, size_t idx)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

		T res = std::move(vec[idx]);
		if (idx + 1 != vec.size()) {
			vec[idx] = std::move(vec.back());
		}
		vec.resize(vec.size() - 1);
		
		return res;
	}
	//
	template<typename T>
	T pop_random_value(std::vector<T>& vec)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		
		size_t idx = crypto::rand<size_t>() % vec.size();
		return pop_index (vec, idx);
	}
}

namespace monero {

  struct wallet_light_listener : public monero_wallet_listener {

  public:

    wallet_light_listener(monero_wallet_light &wallet): m_wallet(wallet) {
      this->m_sync_start_height = boost::none;
      this->m_sync_end_height = boost::none;
      m_prev_balance = wallet.get_balance();
      m_prev_unlocked_balance = wallet.get_unlocked_balance();
      m_notification_pool = std::unique_ptr<tools::threadpool>(tools::threadpool::getNewForUnitTests(1));  // TODO (monero-project): utility can be for general use
    }

    ~wallet_light_listener() {
      MTRACE("~wallet_light_listener()");
      m_notification_pool->recycle();
    }

    /**
      * Invoked when sync progress is made.
      *
      * @param height - height of the synced block
      * @param start_height - starting height of the sync request
      * @param end_height - ending height of the sync request
      * @param percent_done - sync progress as a percentage
      * @param message - human-readable description of the current progress
      */
    void on_sync_progress(uint64_t height, uint64_t start_height, uint64_t end_height, double percent_done, const std::string& message) {
      if (m_wallet.get_listeners().empty()) return;

      // ignore notifications before sync start height, irrelevant to clients
      //if (m_sync_start_height == boost::none || height < *m_sync_start_height) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, height, start_height, end_height, percent_done, message]() {
        // notify listeners of sync progress

        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_sync_progress(height, start_height, end_height, percent_done, message);
        }

        // notify if balances change
        //bool balances_changed = check_for_changed_balances();

        // notify when txs unlock after wallet is synced
        //if (balances_changed && m_wallet.is_synced()) check_for_changed_unlocked_txs();
      });
      waiter.wait();
    }

    /**
      * Invoked when a new block is processed.
      *
      * @param block - the newly processed block
      */
    void on_new_block(uint64_t height) {
      if (m_wallet.get_listeners().empty()) return;

      // ignore notifications before sync start height, irrelevant to clients
      if (m_sync_start_height == boost::none || height < *m_sync_start_height) return;

      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, height]() {

        // notify listeners of new block
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_new_block(height);
        }

        // notify listeners of sync progress
        if (height >= *m_sync_end_height) m_sync_end_height = height + 1; // increase end height if necessary
        double percent_done = (double) (height - *m_sync_start_height + 1) / (double) (*m_sync_end_height - *m_sync_start_height);
        std::string message = std::string("Synchronizing");
        for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
          listener->on_sync_progress(height, *m_sync_start_height, *m_sync_end_height, percent_done, message);
        }

        // notify if balances change
        //bool balances_changed = check_for_changed_balances();

        // notify when txs unlock after wallet is synced
        //if (balances_changed && m_wallet.is_synced()) check_for_changed_unlocked_txs();
      });
      waiter.wait();
    };

    /**
      * Invoked when the wallet's balances change.
      *
      * @param new_balance - new balance
      * @param new_unlocked_balance - new unlocked balance
      */
    void on_balances_changed(uint64_t new_balance, uint64_t new_unlocked_balance) {
      if (m_wallet.get_listeners().empty()) return;
      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, new_balance, new_unlocked_balance]() {
        try {
          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_balances_changed(new_balance, new_unlocked_balance);
          }
        } catch (std::exception& e) {
          std::cout << "Error processing balance change: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    };

    /**
      * Invoked when the wallet receives an output.
      *
      * @param output - the received output
      */
    void on_output_received(const monero_output_wallet& output) {
      if (m_wallet.get_listeners().empty()) return;
      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, output]() {
        try {
          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_output_received(output);
          }

          // watch for unlock
          //m_prev_locked_tx_hashes.insert(tx->m_hash.get());

          // free memory
        } catch (std::exception& e) {
          std::cout << "Error processing confirmed output received: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    };

    /**
      * Invoked when the wallet spends an output.
      *
      * @param output - the spent output
      */
    void on_output_spent(const monero_output_wallet& output) {
      if (m_wallet.get_listeners().empty()) return;
      // queue notification processing off main thread
      tools::threadpool::waiter waiter(*m_notification_pool);
      m_notification_pool->submit(&waiter, [this, output]() {
        try {
          // notify listeners of output
          for (monero_wallet_listener* listener : m_wallet.get_listeners()) {
            listener->on_output_spent(output);
          }
        } catch (std::exception& e) {
          std::cout << "Error processing spent output: " << std::string(e.what()) << std::endl;
        }
      });
      waiter.wait();
    };

  private:
    monero_wallet_light& m_wallet;
    boost::optional<uint64_t> m_sync_start_height;
    boost::optional<uint64_t> m_sync_end_height;
    boost::mutex m_listener_mutex;
    uint64_t m_prev_balance;
    uint64_t m_prev_unlocked_balance;
    std::unique_ptr<tools::threadpool> m_notification_pool;
  };

  bool _rct_hex_to_rct_commit(const std::string &rct_string, rct::key &rct_commit) {
    // rct string is empty if output is non RCT
    if (rct_string.empty()) {
      return false;
    }
    // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
    std::string rct_commit_str = rct_string.substr(0,64);
    if(!epee::string_tools::validate_hex(64, rct_commit_str)) throw std::runtime_error("Invalid rct commit hash: " + rct_commit_str);
    epee::string_tools::hex_to_pod(rct_commit_str, rct_commit);
    return true;
  }

  bool _rct_hex_to_decrypted_mask(const std::string &rct_string, const crypto::secret_key &view_secret_key, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key &decrypted_mask) {
    // rct string is empty if output is non RCT
    if (rct_string.empty()) {
      return false;
    }
    // rct_string is a magic value if output is RCT and coinbase
    if (rct_string == "coinbase") {
      decrypted_mask = rct::identity();
      return true;
    }
    auto make_key_derivation = [&]() {
      crypto::key_derivation derivation;
      bool r = generate_key_derivation(tx_pub_key, view_secret_key, derivation);
      if(!r) throw std::runtime_error("Failed to generate key derivation");
      crypto::secret_key scalar;
      crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
      return rct::sk2rct(scalar);
    };
    rct::key encrypted_mask;
    // rct_string is a string with length 64+16 (<rct commit> + <amount>) if RCT version 2
    if (rct_string.size() < 64 * 2) {
      decrypted_mask = rct::genCommitmentMask(make_key_derivation());
      return true;
    }
    // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
    std::string encrypted_mask_str = rct_string.substr(64,64);
    if(!epee::string_tools::validate_hex(64, encrypted_mask_str)) throw std::runtime_error("Invalid rct mask: " + encrypted_mask_str);
    epee::string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
    //
    if (encrypted_mask == rct::identity()) {
      // backward compatibility; should no longer be needed after v11 mainnet fork
      decrypted_mask = encrypted_mask;
      return true;
    }
    //
    // Decrypt the mask
    sc_sub(decrypted_mask.bytes,
      encrypted_mask.bytes,
      rct::hash_to_scalar(make_key_derivation()).bytes);
    
    return true;
  }

  void _add_pid_to_tx_extra(const boost::optional<std::string>& payment_id_string, std::vector<uint8_t> &extra) { // Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
    bool r = false;
    if (payment_id_string != boost::none && payment_id_string->size() > 0) {
      crypto::hash payment_id;
      r = monero_utils::parse_long_payment_id(*payment_id_string, payment_id);
      if (r) {
        std::string extra_nonce;
        cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
        r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
        if (!r) {
          throw std::runtime_error("Couldn't add pid nonce to tx extra");
        }
      } else {
        crypto::hash8 payment_id8;
        r = monero_utils::parse_short_payment_id(*payment_id_string, payment_id8);
        if (!r) { // a PID has been specified by the user but the last resort in validating it fails; error
          throw std::runtime_error("Invalid pid");
        }
        std::string extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
        r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
        if (!r) {
          throw std::runtime_error("Couldn't add pid nonce to tx extra");
        }
      }
    }
  }

  monero_light_get_random_outs_params monero_wallet_light::prepare_get_random_outs_params(const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, bool is_sweeping, uint32_t simple_priority, const std::vector<monero_light_output> &unspent_outs, uint64_t fee_per_b, uint64_t fee_quantization_mask, boost::optional<uint64_t> prior_attempt_size_calcd_fee, boost::optional<monero_light_spendable_random_outputs> prior_attempt_unspent_outs_to_mix_outs) {
    monero_light_get_random_outs_params params;

    if (!is_sweeping) {
      for (uint64_t sending_amount : sending_amounts) {
        if (sending_amount == 0) {
          throw std::runtime_error("entered amount is too low");
        }
      }
    }
    
    uint32_t fake_outs_count = get_mixin_size();
    params.m_mixin = fake_outs_count;

    bool use_rct = true;
    bool bulletproof = true;
    bool clsag = true;
    
    std::vector<uint8_t> extra;
    _add_pid_to_tx_extra(payment_id_string, extra);

    const uint64_t base_fee = get_base_fee(fee_per_b); // in other words, fee_per_b
    const uint64_t fee_multiplier = get_fee_multiplier(simple_priority, get_default_priority(), get_fee_algorithm());
    
    uint64_t attempt_at_min_fee;
    if (prior_attempt_size_calcd_fee == boost::none) {
      attempt_at_min_fee = estimate_fee(true/*use_per_byte_fee*/, true/*use_rct*/, 1/*est num inputs*/, fake_outs_count, 2, extra.size(), bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask);
      // use a minimum viable estimate_fee() with 1 input. It would be better to under-shoot this estimate, and then need to use a higher fee  from calculate_fee() because the estimate is too low,
      // versus the worse alternative of over-estimating here and getting stuck using too high of a fee that leads to fingerprinting
    } else {
      attempt_at_min_fee = *prior_attempt_size_calcd_fee;
    }
    // fee may get changed as follows…
    uint64_t sum_sending_amounts;
    uint64_t potential_total; // aka balance_required

    if (is_sweeping) {
      potential_total = sum_sending_amounts = UINT64_MAX; // balance required: all
    } else {
      sum_sending_amounts = 0;
      for (uint64_t amount : sending_amounts) {
        sum_sending_amounts += amount;
      }
      potential_total = sum_sending_amounts + attempt_at_min_fee;
    }
    //
    // Gather outputs and amount to use for getting decoy outputs…
    uint64_t using_outs_amount = 0;
    std::vector<monero_light_output>  remaining_unusedOuts = unspent_outs; // take copy so not to modify original

    // start by using all the passed in outs that were selected in a prior tx construction attempt
    if (prior_attempt_unspent_outs_to_mix_outs != boost::none) {
      for (size_t i = 0; i < remaining_unusedOuts.size(); ++i) {
        monero_light_output &out = remaining_unusedOuts[i];

        // search for out by public key to see if it should be re-used in an attempt
        if (prior_attempt_unspent_outs_to_mix_outs->find(*out.m_public_key) != prior_attempt_unspent_outs_to_mix_outs->end()) {
          using_outs_amount += gen_utils::uint64_t_cast(*out.m_amount);
          params.m_using_outs.push_back(std::move(pop_index(remaining_unusedOuts, i)));
        }
      }
    }

    // TODO: factor this out to get spendable balance for display in the MM wallet:
    while (using_outs_amount < potential_total && remaining_unusedOuts.size() > 0) {
      auto out = pop_random_value(remaining_unusedOuts);
      if (!use_rct && (out.m_rct != boost::none && (*out.m_rct).empty() == false)) {
        // out.rct is set by the server
        continue; // skip rct outputs if not creating rct tx
      }
      if (gen_utils::uint64_t_cast(*out.m_amount) < get_dust_threshold()) { // amount is dusty..
        if (out.m_rct == boost::none || (*out.m_rct).empty()) {
          //cout << "Found a dusty but unmixable (non-rct) output... skipping it!" << endl;
          continue;
        } else {
          //cout << "Found a dusty but mixable (rct) amount... keeping it!" << endl;
        }
      }
      using_outs_amount += gen_utils::uint64_t_cast(*out.m_amount);
      //cout << "Using output: " << out.amount << " - " << out.public_key << endl;
      params.m_using_outs.push_back(std::move(out));
    }

    params.m_spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
    // Note: using_outs and using_outs_amount may still get modified below (so retVals.spendable_balance gets updated)
    
    //if (/*using_outs.size() > 1*/ && use_rct) { // FIXME? see original core js
    uint64_t needed_fee = estimate_fee(
      true/*use_per_byte_fee*/, use_rct,
      params.m_using_outs.size(), fake_outs_count, /*tx.dsts.size()*/1+1, extra.size(),
      bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask
    );
    // if newNeededFee < neededFee, use neededFee instead (should only happen on the 2nd or later times through (due to estimated fee being too low))
    if (prior_attempt_size_calcd_fee != boost::none && needed_fee < attempt_at_min_fee) {
      needed_fee = attempt_at_min_fee;
    }
    //
    // NOTE: needed_fee may get further modified below when !is_sweeping if using_outs_amount < total_incl_fees and gets finalized (for this function's scope) as using_fee
    //
    params.m_required_balance = is_sweeping ? needed_fee : potential_total; // must store for needMoreMoneyThanFound return .... NOTE: this is set to needed_fee for is_sweeping because that's literally the required balance, which an caller may want to print in case they get needMoreMoneyThanFound - note this gets updated below when !is_sweeping
    //
    uint64_t total_wo_fee = is_sweeping
      ? /*now that we know outsAmount>needed_fee*/(using_outs_amount - needed_fee)
      : sum_sending_amounts;
    params.m_final_total_wo_fee = total_wo_fee;
    //
    uint64_t total_incl_fees;
    if (is_sweeping) {
      if (using_outs_amount < needed_fee) { // like checking if the result of the following total_wo_fee is < 0
        // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point
        throw std::runtime_error("need more money than found");
      }
      total_incl_fees = using_outs_amount;
    } else {
      total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed because using_outs.size() was updated
      while (using_outs_amount < total_incl_fees && remaining_unusedOuts.size() > 0) { // add outputs 1 at a time till we either have them all or can meet the fee
        {
          auto out = pop_random_value(remaining_unusedOuts);
          //cout << "Using output: " << out.amount << " - " << out.public_key << endl;
          using_outs_amount += gen_utils::uint64_t_cast(*out.m_amount);
          params.m_using_outs.push_back(std::move(out));
        }
        params.m_spendable_balance = using_outs_amount; // must store for needMoreMoneyThanFound return
        //
        // Recalculate fee, total incl fees
        needed_fee = estimate_fee(
          true/*use_per_byte_fee*/, use_rct,
          params.m_using_outs.size(), fake_outs_count, /*tx.dsts.size()*/1+1, extra.size(),
          bulletproof, clsag, base_fee, fee_multiplier, fee_quantization_mask
        );
        total_incl_fees = sum_sending_amounts + needed_fee; // because fee changed
      }
      params.m_required_balance = total_incl_fees; // update required_balance b/c total_incl_fees changed
    }
    params.m_using_fee = needed_fee;
    //
    //cout << "Final attempt at fee: " << needed_fee << " for " << retVals.using_outs.size() << " inputs" << endl;
    //cout << "Balance to be used: " << total_incl_fees << endl;
    if (using_outs_amount < total_incl_fees) {
      // sufficiently up-to-date (for this return case) required_balance and using_outs_amount (spendable balance) will have been stored for return by this point.
      throw std::runtime_error("need more money than found");
    }
    //
    // Change can now be calculated
    uint64_t change_amount = 0; // to initialize
    if (using_outs_amount > total_incl_fees) {
      if(is_sweeping) throw std::runtime_error("Unexpected total_incl_fees > using_outs_amount while sweeping");
      change_amount = using_outs_amount - total_incl_fees;
    }
    //cout << "Calculated change amount:" << change_amount << endl;
    params.m_change_amount = change_amount;
    //
    //uint64_t tx_estimated_weight = estimate_tx_weight(true/*use_rct*/, retVals.using_outs.size(), fake_outs_count, 1+1, extra.size(), true/*bulletproof*/);
    //if (tx_estimated_weight >= TX_WEIGHT_TARGET(get_upper_transaction_weight_limit(0, use_fork_rules_fn))) {
    // TODO?
    //}

    return params;
  }

  tied_spendable_to_random_outs tie_unspent_to_mix_outs(const std::vector<monero_light_output> &using_outs, std::vector<monero_light_random_outputs> mix_outs_from_server, const boost::optional<monero_light_spendable_random_outputs> &prior_attempt_unspent_outs_to_mix_outs) {
    // combine newly requested mix outs returned from the server, with the already known decoys from prior tx construction attempts,
    // so that the same decoys will be re-used with the same outputs in all tx construction attempts. This ensures fee returned
    // by calculate_fee() will be correct in the final tx, and also reduces number of needed trips to the server during tx construction.
    monero_light_spendable_random_outputs prior_attempt_unspent_outs_to_mix_outs_new;
    if (prior_attempt_unspent_outs_to_mix_outs) {
      prior_attempt_unspent_outs_to_mix_outs_new = *prior_attempt_unspent_outs_to_mix_outs;
    }

    std::vector<monero_light_random_outputs> mix_outs;
    mix_outs.reserve(using_outs.size());

    for (size_t i = 0; i < using_outs.size(); ++i) {
      auto out = using_outs[i];

      // if we don't already know of a particular out's mix outs (from a prior attempt),
      // then tie out to a set of mix outs retrieved from the server
      if (prior_attempt_unspent_outs_to_mix_outs_new.find(*out.m_public_key) == prior_attempt_unspent_outs_to_mix_outs_new.end()) {
        for (size_t j = 0; j < mix_outs_from_server.size(); ++j) {
          if ((out.m_rct != boost::none && gen_utils::uint64_t_cast(*mix_outs_from_server[j].m_amount) != 0) ||
            (out.m_rct == boost::none && mix_outs_from_server[j].m_amount != out.m_amount)) {
            continue;
          }

          monero_light_random_outputs output_mix_outs = pop_index(mix_outs_from_server, j);

          // if we need to retry constructing tx, will remember to use same mix outs for this out on subsequent attempt(s)
          prior_attempt_unspent_outs_to_mix_outs_new[*out.m_public_key] = *output_mix_outs.m_outputs;
          mix_outs.push_back(std::move(output_mix_outs));

          break;
        }
      } else {
        monero_light_random_outputs output_mix_outs;
        output_mix_outs.m_outputs = prior_attempt_unspent_outs_to_mix_outs_new[*out.m_public_key];
        output_mix_outs.m_amount = out.m_amount;
        mix_outs.push_back(std::move(output_mix_outs));
      }
    }

    // we expect to have a set of mix outs for every output in the tx
    if (mix_outs.size() != using_outs.size()) {
      throw std::runtime_error("not enough usable decoys found");
    }

    // we expect to use up all mix outs returned by the server
    if (!mix_outs_from_server.empty()) {
      throw std::runtime_error("too many decoy remaining");
    }

    tied_spendable_to_random_outs result;
    result.m_mix_outs = std::move(mix_outs);
    result.m_prior_attempt_unspent_outs_to_mix_outs_new = std::move(prior_attempt_unspent_outs_to_mix_outs_new);

    return result;
  }

  monero_wallet_light::monero_wallet_light(std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory)
  {
    m_light_client = new monero_light_client(std::move(http_client_factory));
  }

  monero_wallet_light::~monero_wallet_light() {
    MTRACE("~monero_wallet_light()");
    close(false);
  }

  void monero_wallet_light::set_daemon_connection(const std::string& uri, const std::string& username, const std::string& password) {
    m_light_client->set_server(uri);
    m_light_client->set_credentials(username, password);

    if (!uri.empty()) login();
  }

  void monero_wallet_light::set_daemon_connection(const boost::optional<monero_rpc_connection> &connection) {
    m_light_client->set_connection(connection);

    if (connection->m_uri != boost::none && !connection->m_uri->empty()) login();
  }

  void monero_wallet_light::set_daemon_proxy(const std::string& uri) {
    m_light_client->set_proxy(uri);
  }

  boost::optional<monero_rpc_connection> monero_wallet_light::get_daemon_connection() const {
    return m_light_client->get_connection();
  }

  bool monero_wallet_light::is_connected_to_daemon() const {
    m_is_connected = m_light_client->is_connected();

    if (!m_is_connected) return false;

    return m_is_connected;
  }

  uint64_t monero_wallet_light::get_daemon_height() const {
    const auto resp = get_address_info();

    if (resp.m_blockchain_height == boost::none) return 0;

    uint64_t height = *resp.m_blockchain_height;

    return height == 0 ? 0 : height + 1;
  }

  uint64_t monero_wallet_light::get_daemon_max_peer_height() const {
    return get_daemon_height();
  }

  void monero_wallet_light::add_listener(monero_wallet_listener& listener) {
    m_listeners.insert(&listener);
  }

  void monero_wallet_light::remove_listener(monero_wallet_listener& listener) {
    m_listeners.erase(&listener);
  }

  std::set<monero_wallet_listener*> monero_wallet_light::get_listeners() {
    return m_listeners;
  }

  monero_sync_result monero_wallet_light::sync() {
    MTRACE("sync()");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return lock_and_sync();
  }

  monero_sync_result monero_wallet_light::sync(monero_wallet_listener& listener) {
    MTRACE("sync(listener)");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // register listener
    add_listener(listener);

    // sync wallet
    monero_sync_result result = lock_and_sync(boost::none);

    // unregister listener
    remove_listener(listener);

    // return sync result
    return result;
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height) {
    MTRACE("sync(" << start_height << ")");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    return lock_and_sync(start_height);
  }

  monero_sync_result monero_wallet_light::sync(uint64_t start_height, monero_wallet_listener& listener) {
    MTRACE("sync(" << start_height << ", listener)");
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");

    // wrap and register sync listener as wallet listener
    add_listener(listener);

    // sync wallet
    monero_sync_result result = lock_and_sync(start_height);

    // unregister sync listener
    remove_listener(listener);

    // return sync result
    return result;
  }

  void monero_wallet_light::start_syncing(uint64_t sync_period_in_ms) {
    if (!m_is_connected) throw std::runtime_error("Wallet is not connected to daemon");
    m_syncing_interval = sync_period_in_ms;
    if (!m_syncing_enabled) {
      m_syncing_enabled = true;
      run_sync_loop(); // sync wallet on loop in background
    }
  }

  void monero_wallet_light::stop_syncing() {
    m_syncing_enabled = false;
    //m_w2->stop();
  }

  void monero_wallet_light::scan_txs(const std::vector<std::string>& tx_ids) {
    sync();
  }

  void monero_wallet_light::rescan_spent() {
    sync();
  }

  void monero_wallet_light::rescan_blockchain() {
    const auto response = import_request();

    if (response.m_payment_address != boost::none) {
      throw std::runtime_error("Payment required");
    }

    if (!response.m_request_fullfilled) {
      throw std::runtime_error("Could not fullfill rescan request");
    }
  }

  bool monero_wallet_light::is_daemon_synced() const {
    return true;
  }

  bool monero_wallet_light::is_daemon_trusted() const {
    return true;
  }

  bool monero_wallet_light::is_synced() const {
    if (!is_connected_to_daemon()) return false;

    const auto resp = get_address_info();

    if (*resp.m_blockchain_height <= 1) {
      return false;
    }

    return *resp.m_scanned_block_height == *resp.m_blockchain_height;
  }

  monero_subaddress monero_wallet_light::get_address_index(const std::string& address) const {
    auto subaddresses = get_subaddresses();

    for (auto subaddress : subaddresses) {
      if (address == *subaddress.m_address) {
        return subaddress;
      }
    }

    throw std::runtime_error("Address doesn't belong to this wallet");
  }

  uint64_t monero_wallet_light::get_height() const {
    const auto resp = get_address_info();

    if (resp.m_scanned_block_height == boost::none) return 0;

    uint64_t height = *resp.m_scanned_block_height;

    return height == 0 ? 0 : height + 1;
  }

  uint64_t monero_wallet_light::get_restore_height() const {
    const auto resp = get_address_info();

    if (resp.m_start_height == boost::none) return 0;

    uint64_t height = *resp.m_start_height;

    return height;
  }

  uint64_t monero_wallet_light::get_balance() const {
    const auto resp = get_address_info();

    uint64_t total_received = gen_utils::uint64_t_cast(*resp.m_total_received);
    uint64_t total_sent = gen_utils::uint64_t_cast(*resp.m_total_sent);

    return total_received - total_sent;
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_index) const {
    const auto resp = get_unspent_outs(true);

    uint64_t balance = 0;

    for (auto const &output : *resp.m_outputs) {
      if(*output.m_recipient->m_maj_i == account_index) {
        balance += gen_utils::uint64_t_cast(*output.m_amount);
      }
    }

    return balance;
  }

  uint64_t monero_wallet_light::get_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    const auto resp = get_unspent_outs(true);

    uint64_t balance = 0;

    for (auto const &output : *resp.m_outputs) {
      if(*output.m_recipient->m_maj_i == account_idx && *output.m_recipient->m_min_i == subaddress_idx) {
        balance += gen_utils::uint64_t_cast(*output.m_amount);
      }
    }

    return balance;
  }

  uint64_t monero_wallet_light::get_unlocked_balance() const {
    const auto resp = get_address_info();

    uint64_t total_received = gen_utils::uint64_t_cast(*resp.m_total_received);
    uint64_t total_sent = gen_utils::uint64_t_cast(*resp.m_total_sent);
    uint64_t total_locked = gen_utils::uint64_t_cast(*resp.m_locked_funds);

    return total_received - total_sent - total_locked;
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_index) const {
    const auto resp = get_unspent_outs();

    uint64_t balance = 0;

    for (auto const &output : *resp.m_outputs) {
      if(*output.m_recipient->m_maj_i == account_index) {
        if (!output_is_locked(output)) balance += gen_utils::uint64_t_cast(*output.m_amount);
      }
    }

    return balance;
  }

  uint64_t monero_wallet_light::get_unlocked_balance(uint32_t account_idx, uint32_t subaddress_idx) const {
    const auto resp = get_unspent_outs();

    uint64_t balance = 0;

    for (auto const &output : *resp.m_outputs) {
      if(*output.m_recipient->m_maj_i == account_idx && *output.m_recipient->m_min_i == subaddress_idx) {
        if (!output_is_locked(output)) balance += gen_utils::uint64_t_cast(*output.m_amount);
      }
    }

    return balance;
  }

  std::vector<monero_account> monero_wallet_light::get_accounts(bool include_subaddresses, const std::string& tag) const {
    std::vector<monero_account> result;
    bool default_found = false;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      for (auto kv : *m_subaddrs.m_all_subaddrs) {
        if (kv.first == 0) default_found = true;
        monero_account account = monero_wallet_keys::get_account(kv.first, false);
        account.m_balance = get_balance(kv.first);
        account.m_unlocked_balance = get_unlocked_balance(kv.first);

        if (include_subaddresses) {
          for(auto index_range : kv.second) {

            auto subaddresses = monero_wallet_keys::get_subaddresses(kv.first, index_range.to_subaddress_indices());

            for (auto subaddress : subaddresses) {
              subaddress.m_balance = get_balance(kv.first, *subaddress.m_index);
              subaddress.m_unlocked_balance = get_unlocked_balance(kv.first, *subaddress.m_index);
              subaddress.m_label = get_subaddress_label(kv.first, *subaddress.m_index);
              account.m_subaddresses.push_back(subaddress);
            }
          }
        }

        result.push_back(account);
      }
    }

    if (!default_found) {
      monero_account primary_account = monero_wallet_keys::get_account(0, false);
      primary_account.m_balance = get_balance(0);
      primary_account.m_unlocked_balance = get_unlocked_balance(0);

      result.push_back(primary_account);
    }

    return result;
  }

  monero_account monero_wallet_light::get_account(const uint32_t account_idx, bool include_subaddresses) const {
    monero_account account = monero_wallet_keys::get_account(account_idx, false);

    account.m_balance = get_balance(account_idx);
    account.m_unlocked_balance = get_unlocked_balance(account_idx);

    if (include_subaddresses) {
      account.m_subaddresses = monero_wallet::get_subaddresses(account_idx);
    }

    return account;
  }

  monero_account monero_wallet_light::create_account(const std::string& label) {
    uint32_t last_account_idx = 0;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      for (auto kv : *m_subaddrs.m_all_subaddrs) {
        if (kv.first > last_account_idx) {
          last_account_idx = kv.first;
        }
      }
    }

    uint32_t account_idx = last_account_idx + 1;

    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(0, 0);

    subaddrs[account_idx] = std::vector<monero_light_index_range>();
    subaddrs[account_idx].push_back(index_range);

    upsert_subaddrs(subaddrs, true);

    monero_account account = monero_wallet_keys::get_account(account_idx, false);

    account.m_balance = 0;
    account.m_unlocked_balance = 0;

    return account;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses(const uint32_t account_idx, const std::vector<uint32_t>& subaddress_indices) const {
    // must provide subaddress indices
    std::vector<uint32_t> subaddress_idxs;

    if (subaddress_indices.empty() && m_subaddrs.m_all_subaddrs != boost::none) {
      for (auto kv : *m_subaddrs.m_all_subaddrs) {
        if (kv.first != account_idx) continue;

        for (auto index_range : kv.second) {
          for (auto subaddress_idx : index_range.to_subaddress_indices()) {
            subaddress_idxs.push_back(subaddress_idx);
          }
        }
      }
    }
    else {
      subaddress_idxs = subaddress_indices;
    }

    if (subaddress_idxs.empty()) {
      return std::vector<monero_subaddress>();
    }

    // initialize subaddresses at indices
    std::vector<monero_subaddress> subaddresses = monero_wallet_keys::get_subaddresses(account_idx, subaddress_idxs);
    
    for (auto subaddress : subaddresses) {
      subaddress.m_label = get_subaddress_label(account_idx, *subaddress.m_index);
      subaddress.m_balance = get_balance(account_idx, *subaddress.m_index);
      subaddress.m_unlocked_balance = get_unlocked_balance(account_idx, *subaddress.m_index);
    }

    return subaddresses;
  }

  monero_subaddress monero_wallet_light::create_subaddress(uint32_t account_idx, const std::string& label) {
    bool account_found = false;
    uint32_t last_subaddress_idx = 0;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      for (auto kv : *m_subaddrs.m_all_subaddrs) {
        if (kv.first != account_idx) continue;

        account_found = true;

        for (auto index_range : kv.second) {
          last_subaddress_idx = index_range.at(1);
        }

        break;
      }
    }

    if (!account_found) {
      throw std::runtime_error("create_subaddress(): account index out of bounds");
    }

    uint32_t subaddress_idx = last_subaddress_idx + 1;

    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(last_subaddress_idx, subaddress_idx);

    subaddrs[account_idx] = std::vector<monero_light_index_range>();
    subaddrs[account_idx].push_back(index_range);

    upsert_subaddrs(subaddrs, true);

    monero_subaddress subaddress = monero_wallet_keys::get_subaddress(account_idx, subaddress_idx);

    set_subaddress_label(account_idx, subaddress_idx, label);
    subaddress.m_label = label;
    subaddress.m_balance = 0;
    subaddress.m_unlocked_balance = 0;

    return subaddress;
  }

  void monero_wallet_light::set_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx, const std::string& label) {
    //get_subaddress(account_idx, subaddr_account_idx);
    m_subaddress_labels[account_idx][subaddress_idx] = label;
  }

  std::vector<std::string> monero_wallet_light::relay_txs(const std::vector<std::string>& tx_metadatas) {
    std::vector<std::string> hashes;

    for (const auto &tx : tx_metadatas) {
      const auto res = m_light_client->submit_raw_tx(tx);

      if (!res.m_status) throw std::runtime_error("Could not relay tx" + tx);
    }

    return hashes;
  }

  monero_tx_set monero_wallet_light::describe_tx_set(const monero_tx_set& tx_set) {

    // get unsigned and multisig tx sets
    std::string unsigned_tx_hex = tx_set.m_unsigned_tx_hex == boost::none ? "" : tx_set.m_unsigned_tx_hex.get();
    std::string multisig_tx_hex = tx_set.m_multisig_tx_hex == boost::none ? "" : tx_set.m_multisig_tx_hex.get();

    // validate request
    if (key_on_device()) throw std::runtime_error("command not supported by HW wallet");
    if (is_view_only()) throw std::runtime_error("command not supported by view-only wallet");
    if (unsigned_tx_hex.empty() && multisig_tx_hex.empty()) throw std::runtime_error("no txset provided");

    std::vector <tools::wallet2::tx_construction_data> tx_constructions;
    if (!unsigned_tx_hex.empty()) {
      try {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(unsigned_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");
        tools::wallet2::unsigned_tx_set exported_txs = parse_unsigned_tx(blob);
        tx_constructions = exported_txs.txes;
      }
      catch (const std::exception &e) {
        throw std::runtime_error("failed to parse unsigned transfers: " + std::string(e.what()));
      }
    } else if (!multisig_tx_hex.empty()) {
      throw std::runtime_error("monero_wallet_light::describe_tx_set(): multisign not supported");
      /*
      try {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(multisig_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");
        tools::wallet2::multisig_tx_set exported_txs = parse_multisig_tx(blob, exported_txs);
        for (uint64_t n = 0; n < exported_txs.m_ptx.size(); ++n) {
          tx_constructions.push_back(exported_txs.m_ptx[n].construction_data);
        }
      }
      catch (const std::exception &e) {
        throw std::runtime_error("failed to parse multisig transfers: " + std::string(e.what()));
      }
      */
    }

    std::vector<tools::wallet2::pending_tx> ptx;  // TODO wallet_rpc_server: unused variable
    try {

      // gather info for each tx
      std::vector<std::shared_ptr<monero_tx_wallet>> txs;
      std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> dests;
      int first_known_non_zero_change_index = -1;
      for (int64_t n = 0; n < tx_constructions.size(); ++n)
      {
        // init tx
        std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
        tx->m_is_outgoing = true;
        tx->m_input_sum = 0;
        tx->m_output_sum = 0;
        tx->m_change_amount = 0;
        tx->m_num_dummy_outputs = 0;
        tx->m_ring_size = std::numeric_limits<uint32_t>::max(); // smaller ring sizes will overwrite

        const tools::wallet2::tx_construction_data &cd = tx_constructions[n];
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        bool has_encrypted_payment_id = false;
        crypto::hash8 payment_id8 = crypto::null_hash8;
        if (cryptonote::parse_tx_extra(cd.extra, tx_extra_fields))
        {
          cryptonote::tx_extra_nonce extra_nonce;
          if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
          {
            crypto::hash payment_id;
            if(cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
            {
              if (payment_id8 != crypto::null_hash8)
              {
                tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id8);
                has_encrypted_payment_id = true;
              }
            }
            else if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
            {
              tx->m_payment_id = epee::string_tools::pod_to_hex(payment_id);
            }
          }
        }

        for (uint64_t s = 0; s < cd.sources.size(); ++s)
        {
          tx->m_input_sum = tx->m_input_sum.get() + cd.sources[s].amount;
          uint64_t ring_size = cd.sources[s].outputs.size();
          if (ring_size < tx->m_ring_size.get())
            tx->m_ring_size = ring_size;
        }
        for (uint64_t d = 0; d < cd.splitted_dsts.size(); ++d)
        {
          const cryptonote::tx_destination_entry &entry = cd.splitted_dsts[d];
          std::string address = cryptonote::get_account_address_as_str(get_nettype(), entry.is_subaddress, entry.addr);
          if (has_encrypted_payment_id && !entry.is_subaddress && address != entry.original)
            address = cryptonote::get_account_integrated_address_as_str(get_nettype(), entry.addr, payment_id8);
          auto i = dests.find(entry.addr);
          if (i == dests.end())
            dests.insert(std::make_pair(entry.addr, std::make_pair(address, entry.amount)));
          else
            i->second.second += entry.amount;
          tx->m_output_sum = tx->m_output_sum.get() + entry.amount;
        }
        if (cd.change_dts.amount > 0)
        {
          auto it = dests.find(cd.change_dts.addr);
          if (it == dests.end()) throw std::runtime_error("Claimed change does not go to a paid address");
          if (it->second.second < cd.change_dts.amount) throw std::runtime_error("Claimed change is larger than payment to the change address");
          if (cd.change_dts.amount > 0)
          {
            if (first_known_non_zero_change_index == -1)
              first_known_non_zero_change_index = n;
            const tools::wallet2::tx_construction_data &cdn = tx_constructions[first_known_non_zero_change_index];
            if (memcmp(&cd.change_dts.addr, &cdn.change_dts.addr, sizeof(cd.change_dts.addr))) throw std::runtime_error("Change goes to more than one address");
          }
          tx->m_change_amount = tx->m_change_amount.get() + cd.change_dts.amount;
          it->second.second -= cd.change_dts.amount;
          if (it->second.second == 0)
            dests.erase(cd.change_dts.addr);
        }

        tx->m_outgoing_transfer = std::make_shared<monero_outgoing_transfer>();
        uint64_t n_dummy_outputs = 0;
        for (auto i = dests.begin(); i != dests.end(); )
        {
          if (i->second.second > 0)
          {
            std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
            destination->m_address = i->second.first;
            destination->m_amount = i->second.second;
            tx->m_outgoing_transfer.get()->m_destinations.push_back(destination);
          }
          else
            tx->m_num_dummy_outputs = tx->m_num_dummy_outputs.get() + 1;
          ++i;
        }

        if (tx->m_change_amount.get() > 0)
        {
          const tools::wallet2::tx_construction_data &cd0 = tx_constructions[0];
          tx->m_change_address = get_account_address_as_str(get_nettype(), cd0.subaddr_account > 0, cd0.change_dts.addr);
        }

        tx->m_fee = tx->m_input_sum.get() - tx->m_output_sum.get();
        tx->m_unlock_time = cd.unlock_time;
        tx->m_extra_hex = epee::to_hex::string({cd.extra.data(), cd.extra.size()});
        txs.push_back(tx);
      }

      // build and return tx set
      monero_tx_set tx_set;
      tx_set.m_txs = txs;
      return tx_set;
    }
    catch (const std::exception &e)
    {
      throw std::runtime_error("failed to parse unsigned transfers");
    }
  }

  // implementation based on monero-project wallet_rpc_server.cpp::on_sign_transfer()
  monero_tx_set monero_wallet_light::sign_txs(const std::string& unsigned_tx_hex) {
    if (key_on_device()) throw std::runtime_error("command not supported by HW wallet");
    if (is_view_only()) throw std::runtime_error("command not supported by view-only wallet");

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(unsigned_tx_hex, blob)) throw std::runtime_error("Failed to parse hex.");

    tools::wallet2::unsigned_tx_set exported_txs = parse_unsigned_tx(blob);

    std::vector<tools::wallet2::pending_tx> ptxs;
    std::vector<std::shared_ptr<monero_tx_wallet>> txs;
    try {
      tools::wallet2::signed_tx_set signed_txs;
      std::string ciphertext = sign_tx(exported_txs, ptxs, signed_txs);
      if (ciphertext.empty()) throw std::runtime_error("Failed to sign unsigned tx");

      // init tx set
      monero_tx_set tx_set;
      tx_set.m_signed_tx_hex = epee::string_tools::buff_to_hex_nodelimer(ciphertext);
      for (auto &ptx : ptxs) {

        // init tx
        std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
        tx->m_is_outgoing = true;
        tx->m_hash = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(ptx.tx));
        tx->m_key = epee::string_tools::pod_to_hex(unwrap(unwrap(ptx.tx_key)));
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys) {
            tx->m_key = tx->m_key.get() += epee::string_tools::pod_to_hex(unwrap(unwrap(additional_tx_key)));
        }
        tx_set.m_txs.push_back(tx);
      }
      return tx_set;
    } catch (const std::exception &e) {
      throw std::runtime_error(std::string("Failed to sign unsigned tx: ") + e.what());
    }
  }

  std::vector<std::string> monero_wallet_light::submit_txs(const std::string& signed_tx_hex) {
    std::vector<std::string> hashes;
    
    const auto res = m_light_client->submit_raw_tx(signed_tx_hex);

    if (!res.m_status) throw std::runtime_error("Could not relay tx" + signed_tx_hex);

    return hashes;
  }

  void monero_wallet_light::freeze_output(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to freeze");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key imge");

    auto found = std::find(m_frozen_key_images.begin(), m_frozen_key_images.end(), key_image);

    if (found == m_frozen_key_images.end()) {
      m_frozen_key_images.push_back(key_image);
    }
  }

  void monero_wallet_light::thaw_output(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to thaw");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key imge");
    
    m_frozen_key_images.erase(std::find(m_frozen_key_images.begin(), m_frozen_key_images.end(), key_image));
  }

  bool monero_wallet_light::is_output_frozen(const std::string& key_image) {
    if (key_image.empty()) throw std::runtime_error("Must specify key image to thaw");
    crypto::key_image ki;
    if (!epee::string_tools::hex_to_pod(key_image, ki)) throw std::runtime_error("failed to parse key imge");
    
    const auto found = std::find(m_frozen_key_images.begin(), m_frozen_key_images.end(), key_image);

    return found != m_frozen_key_images.end();
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::create_txs(const monero_tx_config& config) {
    std::cout << "monero_wallet_light::create_txs()" << std::endl;

    std::vector<std::shared_ptr<monero_tx_wallet>> result;
    uint64_t amount = 0;
    std::vector<uint64_t> sending_amounts;
    std::vector<std::string> dests;

    for(auto &dest : config.get_normalized_destinations()) {
      dests.push_back(*dest->m_address);
      sending_amounts.push_back(*dest->m_amount);
      amount += *dest->m_amount;
    }

    const auto unspent_outs_res = get_unspent_outs(amount, get_mixin_size());

    uint64_t fee_per_b = gen_utils::uint64_t_cast(*unspent_outs_res.m_per_byte_fee);
    uint64_t fee_mask = gen_utils::uint64_t_cast(*unspent_outs_res.m_fee_mask);
    if (unspent_outs_res.m_outputs == boost::none) throw std::runtime_error("none unspent outputs found");

    const auto unspent_outs = *unspent_outs_res.m_outputs;

    if (unspent_outs.empty()) throw std::runtime_error("0 unspent outputs found");

    auto payment_id = config.m_payment_id;
    bool is_sweeping = config.m_sweep_each_subaddress != boost::none ? *config.m_sweep_each_subaddress : false;
    auto simple_priority = config.m_priority == boost::none ? 0 : config.m_priority.get();
    
    m_prior_attempt_size_calcd_fee = boost::none;
    m_prior_attempt_unspent_outs_to_mix_outs = boost::none;
    m_construction_attempt = 0;
    
    const auto random_outs_params = prepare_get_random_outs_params(payment_id, sending_amounts, is_sweeping, simple_priority, unspent_outs, fee_per_b, fee_mask, m_prior_attempt_size_calcd_fee, m_prior_attempt_unspent_outs_to_mix_outs);

    if(random_outs_params.m_using_outs.size() == 0) throw std::runtime_error("Expected non-0 using_outs");

    const auto random_outs_res = get_random_outs(random_outs_params.m_using_outs);

    auto tied_outs = tie_unspent_to_mix_outs(random_outs_params.m_using_outs, *random_outs_res.m_amount_outs, m_prior_attempt_unspent_outs_to_mix_outs);

    monero_light_constructed_transaction constructed_tx;

    if (!is_view_only()) {
      constructed_tx = create_transaction(get_primary_address(), get_private_view_key(), get_private_spend_key(), dests, config.m_payment_id, sending_amounts, random_outs_params.m_change_amount, random_outs_params.m_using_fee, random_outs_params.m_using_outs, tied_outs.m_mix_outs, 0);
      std::cout << "monero_wallet_light::create_txs(): 4" << std::endl;
    }
    else {
      throw std::runtime_error("monero_wallet_light::create_txs(): not implemented for view only wallet");
    }
    
    std::shared_ptr<monero_tx_wallet> tx = std::make_shared<monero_tx_wallet>();
    
    bool relayed = false;
    if (config.m_relay) {
      std::cout << "monero_wallet_light::create_txs(): 5" << std::endl;
      auto submit_res = m_light_client->submit_raw_tx(*constructed_tx.m_signed_serialized_tx_string);

      if (submit_res.m_status) {
        relayed = true;
      }
    }

    tx->m_in_tx_pool = relayed;
    tx->m_is_relayed = relayed;
    tx->m_is_outgoing = true;
    tx->m_is_failed = config.m_relay && !relayed;
    tx->m_payment_id = config.m_payment_id;
    tx->m_hash = constructed_tx.m_tx_hash_string;
    tx->m_num_confirmations = 0;
    tx->m_key = constructed_tx.m_tx_key_string;
    tx->m_unlock_time = constructed_tx.m_tx->unlock_time;
    tx->m_extra = constructed_tx.m_tx->extra;
    tx->m_prunable_hash = epee::string_tools::pod_to_hex(constructed_tx.m_tx->prunable_hash);
    tx->m_version = constructed_tx.m_tx->version;
    tx->m_full_hex = constructed_tx.m_signed_serialized_tx_string;

    std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();

    outgoing_transfer->m_destinations = config.m_destinations;
    outgoing_transfer->m_amount = config.m_amount;
    outgoing_transfer->m_tx = tx;

    tx->m_outgoing_transfer = outgoing_transfer;

    result.push_back(tx);

    return result;
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs() const {
    return get_txs(monero_tx_query());
  }

  std::vector<std::shared_ptr<monero_tx_wallet>> monero_wallet_light::get_txs(const monero_tx_query& query) const {
    std::vector<std::shared_ptr<monero_tx_wallet>> result;

    const auto transfers = get_transfers_aux();

    for (const auto transfer : transfers) {
      auto tx_hash = transfer->m_tx->m_hash;

      auto it = std::find_if(result.begin(), result.end(), [tx_hash](const std::shared_ptr<monero_tx_wallet>& p) {
        return p->m_hash == tx_hash;
      });

      if (it == result.end() && query.meets_criteria(transfer->m_tx.get())) result.push_back(transfer->m_tx);
    }

    return result;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers(const monero_transfer_query& query) const {
    return get_transfers_aux(query);
  }

  std::vector<std::shared_ptr<monero_output_wallet>> monero_wallet_light::get_outputs(const monero_output_query& query) const {
    auto res = get_unspent_outs(false);
    std::vector<std::shared_ptr<monero_output_wallet>> result;
    
    for (auto &output : *res.m_outputs) {
      std::shared_ptr<monero_output_wallet> out = std::make_shared<monero_output_wallet>();

      out->m_index = gen_utils::uint64_t_cast(*output.m_global_index);
      out->m_account_index = output.m_recipient->m_maj_i;
      out->m_subaddress_index = output.m_recipient->m_min_i;
      out->m_amount = gen_utils::uint64_t_cast(*output.m_amount);
      out->m_stealth_public_key = output.m_public_key;
      out->m_is_spent = output_is_spent(output);

      if (query.meets_criteria(out.get())) result.push_back(out);
    }

    return result;
  }

  std::string monero_wallet_light::export_outputs(bool all) const {
    uint32_t start = 0;
    uint32_t count = 0xffffffff;
    std::stringstream oss;
    binary_archive<true> ar(oss);

    auto outputs = export_outputs(all, start, count);
    if(!serialization::serialize(ar, outputs)) throw std::runtime_error("Failed to serialize output data");

    std::string magic(OUTPUT_EXPORT_FILE_MAGIC, strlen(OUTPUT_EXPORT_FILE_MAGIC));
    const cryptonote::account_public_address &keys = m_account.get_keys().m_account_address;
    std::string header;
    header += std::string((const char *)&keys.m_spend_public_key, sizeof(crypto::public_key));
    header += std::string((const char *)&keys.m_view_public_key, sizeof(crypto::public_key));

    std::string ciphertext = encrypt_with_private_view_key(header + oss.str());
    std::string outputs_str = magic + ciphertext;
    return epee::string_tools::buff_to_hex_nodelimer(outputs_str);
  }

  int monero_wallet_light::import_outputs(const std::string& outputs_hex) {
    throw std::runtime_error("monero_wallet_light::import_key_images(): not supported");
  }

  std::vector<std::shared_ptr<monero_key_image>> monero_wallet_light::export_key_images(bool all) const {
    if (!all) throw std::runtime_error("must export all key images");
    std::vector<std::shared_ptr<monero_key_image>> key_images;
    
    const auto outputs_res = get_unspent_outs(false);
    const auto outputs = *outputs_res.m_outputs;

    for(const auto &output : outputs) {
      std::shared_ptr<monero_key_image> key_image = std::make_shared<monero_key_image>();
      cryptonote::subaddress_index subaddr;
      subaddr.major = *output.m_recipient->m_maj_i;
      subaddr.minor = *output.m_recipient->m_min_i;

      *key_image = generate_key_image(*output.m_tx_pub_key, *output.m_index, subaddr);

      key_images.push_back(key_image);
    }

    return key_images;
  }

  std::shared_ptr<monero_key_image_import_result> monero_wallet_light::import_key_images(const std::vector<std::shared_ptr<monero_key_image>>& key_images) {
    throw std::runtime_error("monero_wallet_light::import_key_images(): not implemented");
  }

  std::string monero_wallet_light::get_tx_note(const std::string& tx_hash) const {
    MTRACE("monero_wallet_light::get_tx_note()");
    cryptonote::blobdata tx_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(tx_hash, tx_blob) || tx_blob.size() != sizeof(crypto::hash)) {
      throw std::runtime_error("TX hash has invalid format");
    }
    crypto::hash _tx_hash = *reinterpret_cast<const crypto::hash*>(tx_blob.data());
    return get_tx_note(_tx_hash);
  }

  std::vector<std::string> monero_wallet_light::get_tx_notes(const std::vector<std::string>& tx_hashes) const {
    MTRACE("monero_wallet_light::get_tx_notes()");
    std::vector<std::string> notes;
    for (const auto& tx_hash : tx_hashes) notes.push_back(get_tx_note(tx_hash));
    return notes;
  }

  void monero_wallet_light::set_tx_note(const std::string& tx_hash, const std::string& note) {
    MTRACE("monero_wallet_light::set_tx_note()");
    cryptonote::blobdata tx_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(tx_hash, tx_blob) || tx_blob.size() != sizeof(crypto::hash)) {
      throw std::runtime_error("TX hash has invalid format");
    }
    crypto::hash _tx_hash = *reinterpret_cast<const crypto::hash*>(tx_blob.data());
    set_tx_note(_tx_hash, note);
  }

  void monero_wallet_light::set_tx_notes(const std::vector<std::string>& tx_hashes, const std::vector<std::string>& notes) {
    MTRACE("monero_wallet_light::set_tx_notes()");
    if (tx_hashes.size() != notes.size()) throw std::runtime_error("Different amount of txids and notes");
    for (int i = 0; i < tx_hashes.size(); i++) {
      set_tx_note(tx_hashes[i], notes[i]);
    }
  }

  std::vector<monero_address_book_entry> monero_wallet_light::get_address_book_entries(const std::vector<uint64_t>& indices) const {
    if (indices.empty()) return m_address_book;
    std::vector<monero_address_book_entry> result;

    for (uint64_t idx : indices) {
      if (idx >= m_address_book.size()) throw std::runtime_error("Index out of range: " + std::to_string(idx));
      const auto &entry = m_address_book[idx];
      result.push_back(entry);
    }

    return result;
  }

  uint64_t monero_wallet_light::add_address_book_entry(const std::string& address, const std::string& description) {
    MTRACE("monero_wallet_light::add_address_book_entry()");
    cryptonote::address_parse_info info;
    epee::json_rpc::error er;
    if(!get_account_address_from_str_or_url(info, get_nettype(), address,
      [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
        if (!dnssec_valid) throw std::runtime_error(std::string("Invalid DNSSEC for ") + url);
        if (addresses.empty()) throw std::runtime_error(std::string("No Monero address found at ") + url);
        return addresses[0];
      }))
    {
      throw std::runtime_error(std::string("Invalid address: ") + address);
    }

    const auto old_size = m_address_book.size();

    monero_address_book_entry entry(old_size, address, description);
    m_address_book.push_back(entry);

    if (!m_address_book.size() != old_size + 1) throw std::runtime_error("Failed to add address book entry");
    return m_address_book.size() - 1;
  }

  void monero_wallet_light::edit_address_book_entry(uint64_t index, bool set_address, const std::string& address, bool set_description, const std::string& description) {
    MTRACE("monero_wallet_light::edit_address_book_entry()");

    auto ab = m_address_book;
    if (index >= ab.size()) throw std::runtime_error("Index out of range: " + std::to_string(index));

    monero_address_book_entry entry;

    entry.m_index = index;

    cryptonote::address_parse_info info;
    epee::json_rpc::error er;
    if (set_address) {
      er.message = "";
      if(!get_account_address_from_str_or_url(info, get_nettype(), address,
        [&er](const std::string &url, const std::vector<std::string> &addresses, bool dnssec_valid)->std::string {
          if (!dnssec_valid) throw std::runtime_error(std::string("Invalid DNSSEC for ") + url);
          if (addresses.empty()) throw std::runtime_error(std::string("No Monero address found at ") + url);
          return addresses[0];
        }))
      {
        throw std::runtime_error("Invalid address: " + address);
      }

      if (info.has_payment_id) { 
        entry.m_address = cryptonote::get_account_integrated_address_as_str(get_nettype(), info.address, info.payment_id);    }
      else entry.m_address = address;
    }

    if (set_description) entry.m_description = description;
    
    ab[index] = entry;
  }

  void monero_wallet_light::delete_address_book_entry(uint64_t index) {  
    if (index >= m_address_book.size()) throw std::runtime_error("Index out of range: " + std::to_string(index));
    m_address_book.erase(m_address_book.begin()+index);
  }

  std::string monero_wallet_light::get_payment_uri(const monero_tx_config& config) const {
    MTRACE("get_payment_uri()");

    // validate config
    std::vector<std::shared_ptr<monero_destination>> destinations = config.get_normalized_destinations();
    if (destinations.size() != 1) throw std::runtime_error("Cannot make URI from supplied parameters: must provide exactly one destination to send funds");
    if (destinations.at(0)->m_address == boost::none) throw std::runtime_error("Cannot make URI from supplied parameters: must provide destination address");
    if (destinations.at(0)->m_amount == boost::none) throw std::runtime_error("Cannot make URI from supplied parameters: must provide destination amount");

    // prepare wallet2 params
    std::string address = destinations.at(0)->m_address.get();
    std::string payment_id = config.m_payment_id == boost::none ? "" : config.m_payment_id.get();
    uint64_t amount = destinations.at(0)->m_amount.get();
    std::string note = config.m_note == boost::none ? "" : config.m_note.get();
    std::string m_recipient_name = config.m_recipient_name == boost::none ? "" : config.m_recipient_name.get();

    // make uri using wallet2
    std::string error;
    std::string uri = make_uri(address, payment_id, amount, note, m_recipient_name, error);
    if (uri.empty()) throw std::runtime_error("Cannot make URI from supplied parameters: " + error);
    return uri;
  }

  std::shared_ptr<monero_tx_config> monero_wallet_light::parse_payment_uri(const std::string& uri) const {
    MTRACE("parse_payment_uri(" << uri << ")");

    // decode uri to parameters
    std::string address;
    std::string payment_id;
    uint64_t amount = 0;
    std::string note;
    std::string m_recipient_name;
    std::vector<std::string> unknown_parameters;
    std::string error;
    if (!parse_uri(uri, address, payment_id, amount, note, m_recipient_name, unknown_parameters, error)) {
      throw std::runtime_error("Error parsing URI: " + error);
    }

    // initialize config
    std::shared_ptr<monero_tx_config> config = std::make_shared<monero_tx_config>();
    std::shared_ptr<monero_destination> destination = std::make_shared<monero_destination>();
    config->m_destinations.push_back(destination);
    if (!address.empty()) destination->m_address = address;
    destination->m_amount = amount;
    if (!payment_id.empty()) config->m_payment_id = payment_id;
    if (!note.empty()) config->m_note = note;
    if (!m_recipient_name.empty()) config->m_recipient_name = m_recipient_name;
    if (!unknown_parameters.empty()) MWARNING("WARNING in monero_wallet_full::parse_payment_uri: URI contains unknown parameters which are discarded"); // TODO: return unknown parameters?
    return config;
  }

  void monero_wallet_light::set_attribute(const std::string &key, const std::string &value)
  {
    m_attributes[key] = value;
  }

  bool monero_wallet_light::get_attribute(const std::string &key, std::string &value) const
  {
    std::unordered_map<std::string, std::string>::const_iterator i = m_attributes.find(key);
    if (i == m_attributes.end())
      return false;
    value = i->second;
    return true;
  }

  uint64_t monero_wallet_light::wait_for_next_block() {
    // use mutex and condition variable to wait for block
    boost::mutex temp;
    boost::condition_variable cv;

    // create listener which notifies condition variable when block is added
    struct block_notifier : monero_wallet_listener {
      boost::mutex* temp;
      boost::condition_variable* cv;
      uint64_t last_height;
      block_notifier(boost::mutex* temp, boost::condition_variable* cv) { this->temp = temp; this->cv = cv; }
      void on_new_block(uint64_t height) {
        last_height = height;
        cv->notify_one();
      }
    } block_listener(&temp, &cv);

    // register the listener
    add_listener(block_listener);

    // wait until condition variable is notified
    boost::mutex::scoped_lock lock(temp);
    cv.wait(lock);

    // unregister the listener
    remove_listener(block_listener);

    // return last height
    return block_listener.last_height;
  }

  monero_multisig_info monero_wallet_light::get_multisig_info() const {
    monero_multisig_info info;

    info.m_is_multisig = false;

    return info;
  };

  void monero_wallet_light::close(bool save) {
    MTRACE("monero_wallet_light::close()");
    if (save) throw std::runtime_error("MoneroWalletLight does not support saving");
    stop_syncing();
    if (m_sync_loop_running) {
      m_sync_cv.notify_one();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));  // TODO: in emscripten, m_sync_cv.notify_one() returns without waiting, so sleep; bug in emscripten upstream llvm?
      m_syncing_thread.join();
    }

    m_account.deinit();
    m_wallet_listener.reset();
  }

  // --------------------------- PRIVATE UTILS --------------------------

  void monero_wallet_light::init_common() {
    monero_wallet_keys::init_common();

    m_load_deprecated_formats = false;
    m_is_synced = false;
    m_rescan_on_sync = false;
    m_syncing_enabled = false;
    m_sync_loop_running = false;

    m_address_info.m_locked_funds = "0";
    m_address_info.m_total_received = "0";
    m_address_info.m_total_sent = "0";
    m_address_info.m_scanned_height = 0;
    m_address_info.m_scanned_block_height = 0;
    m_address_info.m_start_height = 0;
    m_address_info.m_transaction_height = 0;
    m_address_info.m_blockchain_height = 0;
    m_address_info.m_spent_outputs = std::vector<monero_light_spend>();

    m_address_txs.m_total_received = "0";
    m_address_txs.m_scanned_height = 0;
    m_address_txs.m_scanned_block_height = 0;
    m_address_txs.m_start_height = 0;
    m_address_txs.m_blockchain_height = 0;
    m_address_txs.m_transactions = std::vector<monero_light_transaction>();

    m_unspent_outs.m_per_byte_fee = "0";
    m_unspent_outs.m_fee_mask = "0";
    m_unspent_outs.m_amount = "0";
    m_unspent_outs.m_outputs = std::vector<monero_light_output>();

    monero_light_subaddrs subaddrs;
    m_subaddrs.m_all_subaddrs = subaddrs;

    m_wallet_listener = std::unique_ptr<wallet_light_listener>(new wallet_light_listener(*this));
  }

  monero_light_partial_constructed_transaction monero_wallet_light::create_partial_transaction(const cryptonote::account_keys& sender_account_keys, const uint32_t subaddr_account_idx, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses, const std::vector<cryptonote::address_parse_info> &to_addrs, const std::vector<uint64_t>& sending_amounts, uint64_t change_amount, uint64_t fee_amount, const std::vector<monero_light_output> &outputs, std::vector<monero_light_random_outputs> &mix_outs, const std::vector<uint8_t> &extra, uint64_t unlock_time, bool rct) {
    std::cout << "monero_wallet_light::create_partial_transaction()" << std::endl;
    // TODO: do we need to sort destinations by amount, here, according to 'decompose_destinations'?
    
    uint32_t fake_outputs_count = get_mixin_size();
    rct::RangeProofType range_proof_type = rct::RangeProofPaddedBulletproof;
    int bp_version = 1;
    if (use_fork_rules(HF_VERSION_BULLETPROOF_PLUS, -10)) {
      bp_version = 4;
    }
    else if (use_fork_rules(HF_VERSION_CLSAG, -10)) {
      bp_version = 3;
    }
    else if (use_fork_rules(HF_VERSION_SMALLER_BP, -10)) {
      bp_version = 2;
    }
    const rct::RCTConfig rct_config {
      range_proof_type,
      bp_version,
    };
    if (mix_outs.size() != outputs.size() && fake_outputs_count != 0) {
      throw std::runtime_error("wrong number of mix outs provided: " + std::to_string(mix_outs.size()) + ", outputs: " + std::to_string(outputs.size()));
    }
    for (size_t i = 0; i < mix_outs.size(); i++) {
      if (mix_outs[i].m_outputs->size() < fake_outputs_count) {
        throw std::runtime_error("not enough outputs for mixing");
      }
    }
    if (!sender_account_keys.get_device().verify_keys(sender_account_keys.m_spend_secret_key, sender_account_keys.m_account_address.m_spend_public_key)
      || !sender_account_keys.get_device().verify_keys(sender_account_keys.m_view_secret_key, sender_account_keys.m_account_address.m_view_public_key)) {
      throw std::runtime_error("Invalid secret keys");
    }
    /*
  XXX: need overflow check?
    if (sending_amount > std::numeric_limits<uint64_t>::max() - change_amount
      || sending_amount + change_amount > std::numeric_limits<uint64_t>::max() - fee_amount) {
      retVals.errCode = outputAmountOverflow;
      return;
    }
  */
    uint64_t needed_money = fee_amount + change_amount;
    for (uint64_t amount : sending_amounts) {
      needed_money += amount;
    }
    
    uint64_t found_money = 0;
    std::vector<cryptonote::tx_source_entry> sources;
    // TODO: log: "Selected transfers: " << outputs
    for (size_t out_index = 0; out_index < outputs.size(); out_index++) {
      found_money += gen_utils::uint64_t_cast(*outputs[out_index].m_amount);
      if (found_money > UINT64_MAX) {
        throw std::runtime_error("input amount overflow");
      }
      auto src = cryptonote::tx_source_entry{};
      src.amount = gen_utils::uint64_t_cast(*outputs[out_index].m_amount);
      src.rct = outputs[out_index].m_rct != boost::none && (*(outputs[out_index].m_rct)).empty() == false;
      
      typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
      if (mix_outs.size() != 0) {
        // Sort fake outputs by global index
        std::sort(mix_outs[out_index].m_outputs->begin(), mix_outs[out_index].m_outputs->end(), [] (
          monero_light_random_output const& a,
          monero_light_random_output const& b
        ) {
          return gen_utils::uint64_t_cast(*a.m_global_index) < gen_utils::uint64_t_cast(*b.m_global_index);
        });
        for (
          size_t j = 0;
          src.outputs.size() < fake_outputs_count && j < mix_outs[out_index].m_outputs->size();
          j++
        ) {
          auto mix_out__output = mix_outs[out_index].m_outputs.get()[j];
          if (mix_out__output.m_global_index == outputs[out_index].m_global_index) {
            MDEBUG("got mixin the same as output, skipping");
            continue;
          }
          auto oe = tx_output_entry{};
          oe.first = gen_utils::uint64_t_cast(*mix_out__output.m_global_index);
          
          crypto::public_key public_key = AUTO_VAL_INIT(public_key);
          if(!epee::string_tools::hex_to_pod(*mix_out__output.m_public_key, public_key)) {
            throw std::runtime_error("given an invalid publick key");
          }
          oe.second.dest = rct::pk2rct(public_key);
          
          if (mix_out__output.m_rct != boost::none && (*(mix_out__output.m_rct)).empty() == false) {
            rct::key commit;
            _rct_hex_to_rct_commit(*mix_out__output.m_rct, commit);
            oe.second.mask = commit;
          } else {
            if (outputs[out_index].m_rct != boost::none && (*(outputs[out_index].m_rct)).empty() == false) {
              throw std::runtime_error("mix RCT outs missing commit");
            }
            oe.second.mask = rct::zeroCommit(src.amount); //create identity-masked commitment for non-rct mix input
          }
          src.outputs.push_back(oe);
        }
      }
      auto real_oe = tx_output_entry{};
      real_oe.first = gen_utils::uint64_t_cast(*outputs[out_index].m_global_index);
      

      crypto::public_key public_key = AUTO_VAL_INIT(public_key);
      if(!epee::string_tools::validate_hex(64, *outputs[out_index].m_public_key)) {
        throw std::runtime_error("given an invalid public key");
      }
      if (!epee::string_tools::hex_to_pod(*outputs[out_index].m_public_key, public_key)) {
        throw std::runtime_error("given an invalid public key");

      }
      real_oe.second.dest = rct::pk2rct(public_key);
      
      if (outputs[out_index].m_rct != boost::none
          && outputs[out_index].m_rct->empty() == false
          && *outputs[out_index].m_rct != "coinbase") {
        rct::key commit;
        _rct_hex_to_rct_commit(*(outputs[out_index].m_rct), commit);
        real_oe.second.mask = commit; //add commitment for real input
      } else {
        real_oe.second.mask = rct::zeroCommit(src.amount/*aka outputs[out_index].amount*/); //create identity-masked commitment for non-rct input
      }
      
      // Add real_oe to outputs
      uint64_t real_output_index = src.outputs.size();
      for (size_t j = 0; j < src.outputs.size(); j++) {
        if (real_oe.first < src.outputs[j].first) {
          real_output_index = j;
          break;
        }
      }
      src.outputs.insert(src.outputs.begin() + real_output_index, real_oe);
      crypto::public_key tx_pub_key = AUTO_VAL_INIT(tx_pub_key);
      if(!epee::string_tools::validate_hex(64, *outputs[out_index].m_tx_pub_key)) {
        throw std::runtime_error("given an invalid public key");
      }
      epee::string_tools::hex_to_pod(*outputs[out_index].m_tx_pub_key, tx_pub_key);
      src.real_out_tx_key = tx_pub_key;
      
      src.real_out_additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(extra);
      
      src.real_output = real_output_index;
      uint64_t internal_output_index = *outputs[out_index].m_index;
      src.real_output_in_tx_index = internal_output_index;
      
      src.rct = outputs[out_index].m_rct != boost::none && (*(outputs[out_index].m_rct)).empty() == false;
      if (src.rct) {
        rct::key decrypted_mask;
        bool r = _rct_hex_to_decrypted_mask(
          *(outputs[out_index].m_rct),
          sender_account_keys.m_view_secret_key,
          tx_pub_key,
          internal_output_index,
          decrypted_mask
        );
        if (!r) {
          throw std::runtime_error("can't get decrypted mask from RCT hex");
        }
        src.mask = decrypted_mask;
        /*
        rct::key calculated_commit = rct::commit(outputs[out_index].amount, decrypted_mask);
        rct::key parsed_commit;
        _rct_hex_to_rct_commit(*(outputs[out_index].rct), parsed_commit);
        if (!(real_oe.second.mask == calculated_commit)) { // real_oe.second.mask==parsed_commit(outputs[out_index].rct)
          retVals.errCode = invalidCommitOrMaskOnOutputRCT;
          return;
        }

        */
      } else {
        rct::identity(src.mask); // in the original cn_utils impl this was left as null for generate_key_image_helper_rct to fill in with identity I
      }
      // not doing multisig here yet
      src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
      sources.push_back(src);
    }
    
    // TODO: if this is a multisig wallet, create a list of multisig signers we can use
    std::vector<cryptonote::tx_destination_entry> splitted_dsts;
    if(to_addrs.size() != sending_amounts.size()) throw std::runtime_error("Amounts don't match destinations");
    for (size_t i = 0; i < to_addrs.size(); ++i) {
      cryptonote::tx_destination_entry to_dst = AUTO_VAL_INIT(to_dst);
      to_dst.addr = to_addrs[i].address;
      to_dst.amount = sending_amounts[i];
      to_dst.is_subaddress = to_addrs[i].is_subaddress;
      splitted_dsts.push_back(to_dst);
    }
    //
    cryptonote::tx_destination_entry change_dst = AUTO_VAL_INIT(change_dst);
    change_dst.amount = change_amount;
    
    if (change_dst.amount == 0) {
      if (splitted_dsts.size() == 1) {
        /**
        * If the change is 0, send it to a random address, to avoid confusing
        * the sender with a 0 amount output. We send a 0 amount in order to avoid
        * letting the destination be able to work out which of the inputs is the
        * real one in our rings
        */

        MDEBUG("generating dummy address for 0 change");
        cryptonote::account_base dummy;
        dummy.generate();
        change_dst.addr = dummy.get_keys().m_account_address;
        MDEBUG("generated dummy address for 0 change");
        splitted_dsts.push_back(change_dst);
      }
    } else {
      change_dst.addr = sender_account_keys.m_account_address;
      splitted_dsts.push_back(change_dst);
    }
    
    // TODO: log: "sources: " << sources
    if (found_money > needed_money) {
      if (change_dst.amount != fee_amount) {
        throw std::runtime_error("result fee not equal to given");
      }
    } else if (found_money < needed_money) {
        throw std::runtime_error("need more money than found");
    }
    
    cryptonote::transaction tx;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    
    if (sources.empty()) throw std::runtime_error("sources is empty");

    // unlock time not supported here...
    bool r = cryptonote::construct_tx_and_get_tx_key(
      sender_account_keys, subaddresses,
      sources, splitted_dsts, change_dst.addr, extra,
      tx, tx_key, additional_tx_keys,
      true, rct_config, true);

    std::cout << "constructed tx, r=" << r << std::endl;
    if (!r) {
      // TODO: return error::tx_not_constructed, sources, dsts, unlock_time, nettype
      throw std::runtime_error("transaction not constructed");
    }
    if (get_upper_transaction_weight_limit(0) <= get_transaction_weight(tx)) {
      // TODO: return error::tx_too_big, tx, upper_transaction_weight_limit
      throw std::runtime_error("transaction too big");
    }
    bool use_bulletproofs = !tx.rct_signatures.p.bulletproofs_plus.empty();
    if(use_bulletproofs != true) throw std::runtime_error("Expected tx use_bulletproofs to equal bulletproof flag");
    
    monero_light_partial_constructed_transaction result;

    result.m_tx = tx;
    result.m_tx_key = tx_key;
    result.m_additional_tx_keys = additional_tx_keys;

    return result;
  }

  monero_light_constructed_transaction monero_wallet_light::create_transaction(const std::string &from_address_string, const std::string &sec_viewKey_string, const std::string &sec_spendKey_string, const std::vector<std::string> &to_address_strings, const boost::optional<std::string>& payment_id_string, const std::vector<uint64_t>& sending_amounts, uint64_t change_amount, uint64_t fee_amount, const std::vector<monero_light_output> &outputs, std::vector<monero_light_random_outputs> &mix_outs, uint64_t unlock_time) {
    std::cout << "monero_wallet_light::create_transaction()" << std::endl;

    auto nettype = get_nettype();

    cryptonote::address_parse_info from_addr_info;
    if(!cryptonote::get_account_address_from_str(from_addr_info, nettype, from_address_string)) throw std::runtime_error("couldn't parse from-address");
    cryptonote::account_keys account_keys;
    {
      account_keys.m_account_address = from_addr_info.address;
      
      crypto::secret_key sec_viewKey;
      if(!epee::string_tools::hex_to_pod(sec_viewKey_string, sec_viewKey)) throw std::runtime_error("couldn't parse view key");
      account_keys.m_view_secret_key = sec_viewKey;
      
      crypto::secret_key sec_spendKey;
      if(!epee::string_tools::hex_to_pod(sec_spendKey_string, sec_spendKey)) throw std::runtime_error("couldn't parse spend key");
      account_keys.m_spend_secret_key = sec_spendKey;
    }
    std::vector<cryptonote::address_parse_info> to_addr_infos(to_address_strings.size());
    size_t to_addr_idx = 0;
    for (const auto& addr : to_address_strings) {
      // assumed to be an OA address asXMR addresses do not have periods and OA addrs must
      if(addr.find(".") != std::string::npos) throw std::runtime_error("integrators must resolve OA addresses before calling Send"); // This would be an app code fault
      if (!cryptonote::get_account_address_from_str(to_addr_infos[to_addr_idx++], nettype, addr)) {
        throw std::runtime_error("couldn't decode to-address");
      }
    }

    std::vector<uint8_t> extra;
    _add_pid_to_tx_extra(payment_id_string, extra);

    bool payment_id_seen = payment_id_string != boost::none; // logically this is true since payment_id_string has passed validation (or we'd have errored)
    for (const auto& to_addr_info : to_addr_infos) {
      if (to_addr_info.is_subaddress && payment_id_seen) {
        throw std::runtime_error("cant use pid with subaddress");
      }
      if (to_addr_info.has_payment_id) {
        if (payment_id_seen) {
          // can't use int addr at same time as supplying manual pid
          throw std::runtime_error("non zero pid with int address");
        }
        if (to_addr_info.is_subaddress) {
          if(false) throw std::runtime_error("unexpected is_subaddress && has_payment_id"); // should never happen
        }
        std::string extra_nonce;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, to_addr_info.payment_id);
        bool r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
        if (!r) {
          throw std::runtime_error("couldn't add pid nonce to tx extra");
        }
        payment_id_seen = true;
      }
    }

    uint32_t subaddr_account_idx = 0;
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses = get_subaddresses_map();
    //subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};
    
    auto partial_tx = create_partial_transaction(
      account_keys, subaddr_account_idx, subaddresses,
      to_addr_infos,
      sending_amounts, change_amount, fee_amount,
      outputs, mix_outs,
      extra, // TODO: move to after address
      unlock_time, true/*rct*/
    );

    auto txBlob = t_serializable_object_to_blob(*partial_tx.m_tx);
    size_t txBlob_byteLength = txBlob.size();
    //	cout << "txBlob: " << txBlob << endl;
    //	cout << "txBlob_byteLength: " << txBlob_byteLength << endl;
    
    if(txBlob_byteLength <= 0) throw std::runtime_error("Expected tx blob byte length > 0");
    
    // tx hash
    monero_light_constructed_transaction result;
    result.m_tx_hash_string = epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(*partial_tx.m_tx));
    // signed serialized tx
    result.m_signed_serialized_tx_string = epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(*partial_tx.m_tx));
    // (concatenated) tx key
    /* TODO is throwing Type must be trivially copiable
    auto _tx_key = *partial_tx.m_tx_key;
    std::string tx_key = epee::string_tools::pod_to_hex(_tx_key);
    std::ostringstream oss;
    oss << tx_key;
    for (size_t i = 0; i < (*partial_tx.m_additional_tx_keys).size(); ++i) {
      oss << epee::string_tools::pod_to_hex((*partial_tx.m_additional_tx_keys)[i]);
    }
    result.m_tx_key_string = oss.str();
    */
    std::ostringstream oss2;
    oss2 << epee::string_tools::pod_to_hex(cryptonote::get_tx_pub_key_from_extra(*partial_tx.m_tx));
    result.m_tx_pub_key_string = oss2.str();
    
    result.m_tx = *partial_tx.m_tx; // for calculating block weight; FIXME: std::move?
    
    //	cout << "out 0: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[0].target).key) << endl;
    //	cout << "out 1: " << string_tools::pod_to_hex(boost::get<txout_to_key>((*(actualCall_retVals.tx)).vout[1].target).key) << endl;
    
    result.m_tx_blob_byte_length = txBlob_byteLength;
    return result;
  }

  std::vector<monero_light_output> get_tx_unspent_outs(std::string &tx_hash, std::vector<monero_light_output> &unspent_outputs) {
    std::vector<monero_light_output> found;

    for (const auto &output : unspent_outputs) {
      if (*output.m_tx_hash == tx_hash) {
        found.push_back(output);
      }
    }

    return found;
  }

  std::vector<monero_light_output> get_tx_unspent_outs(std::string &tx_hash, monero_light_get_unspent_outs_response res) {
    std::vector<monero_light_output> unspent_outputs = *res.m_outputs;

    return get_tx_unspent_outs(tx_hash, unspent_outputs);
  }

  cryptonote::subaddress_index get_transaction_sender(const monero_light_transaction &tx) {
    cryptonote::subaddress_index si;
    bool has_default = false;
    si.major = 0;
    si.minor = 0;

    for (const auto &output : *tx.m_spent_outputs) {
      if (*output.m_sender->m_maj_i == 0) {
        si.minor = *output.m_sender->m_min_i;
        has_default = true;
        break;
      }
    }

    if (!has_default) {
      for (const auto &output : *tx.m_spent_outputs) {
        si.major = *output.m_sender->m_maj_i;
        si.minor = *output.m_sender->m_min_i;
        break;
      }
    }

    return si;
  }

  std::vector<std::shared_ptr<monero_transfer>> monero_wallet_light::get_transfers_aux(const monero_transfer_query& query) const {
    std::cout << "monero_wallet_light::get_transfers_aux()" << std::endl;

    std::vector<std::shared_ptr<monero_transfer>> transfers;
    std::vector<std::shared_ptr<monero_block>> blocks;

    const auto address_txs_res = get_address_txs();
    const auto unspent_outs_res = get_unspent_outs(false);

    const auto current_height = *address_txs_res.m_blockchain_height;
    const auto txs = *address_txs_res.m_transactions;

    for (const auto &tx : txs) {
      const uint64_t total_sent = gen_utils::uint64_t_cast(*tx.m_total_sent);    
      const uint64_t total_received = gen_utils::uint64_t_cast(*tx.m_total_received);
      
      const uint64_t fee = gen_utils::uint64_t_cast(*tx.m_fee);
      
      const bool is_incoming = total_received > 0;
      const bool is_outgoing = total_sent > 0;
      const bool is_change = is_incoming && is_outgoing;
      const bool is_locked = *tx.m_unlock_time > current_height;
      const bool is_confirmed = !tx.m_mempool;
      const bool is_miner_tx = *tx.m_coinbase == true;
            
      const uint64_t timestamp = gen_utils::timestamp_to_epoch(*tx.m_timestamp);
      const uint64_t tx_height = is_confirmed ? *tx.m_height : 0;
      const uint64_t num_confirmations = is_confirmed ? current_height - tx_height : 0;
      const uint64_t change_amount =  is_change ? total_sent - total_received : 0;
      std::string tx_hash = *tx.m_hash;

      std::shared_ptr<monero_tx_wallet> tx_wallet = std::make_shared<monero_tx_wallet>();

      tx_wallet->m_is_incoming = is_incoming;
      tx_wallet->m_is_outgoing = is_outgoing;
      tx_wallet->m_is_locked = is_locked;
      tx_wallet->m_is_relayed = true;
      tx_wallet->m_is_failed = false;
      tx_wallet->m_is_double_spend_seen = false;
      tx_wallet->m_is_confirmed = is_confirmed;
      tx_wallet->m_is_kept_by_block = false;
      tx_wallet->m_is_miner_tx = is_miner_tx;
      tx_wallet->m_unlock_time = *tx.m_unlock_time;
      tx_wallet->m_last_relayed_timestamp = timestamp;
      tx_wallet->m_received_timestamp = timestamp;
      tx_wallet->m_in_tx_pool = !is_confirmed;
      tx_wallet->m_hash = *tx.m_hash;
      tx_wallet->m_num_confirmations = num_confirmations;
      tx_wallet->m_fee = fee;
      tx_wallet->m_payment_id = tx.m_payment_id;
      tx_wallet->m_num_dummy_outputs = tx.m_mixin;
      tx_wallet->m_ring_size = *tx.m_mixin + 1;

      if (is_confirmed) {
        auto it = std::find_if(blocks.begin(), blocks.end(), [tx_height](const std::shared_ptr<monero_block>& p) {
            return *p->m_height == tx_height; // Dereferenziamento del unique_ptr
        });

        std::shared_ptr<monero_block> block = nullptr;

        if (it != blocks.end()) {
          block = (*it);  
        } else {
          block = std::make_shared<monero_block>();
          block->m_height = tx_height;
          block->m_timestamp = timestamp;

          blocks.push_back(block);
        }

        block->m_txs.push_back(tx_wallet);
        block->m_tx_hashes.push_back(*tx_wallet->m_hash);

        if (is_miner_tx) {
          block->m_miner_tx = tx_wallet;
        }

        tx_wallet->m_block = block;
      }

      if (is_incoming) {
        for (auto &out : get_tx_unspent_outs(tx_hash, unspent_outs_res)) {
          std::shared_ptr<monero_incoming_transfer> incoming_transfer = std::make_shared<monero_incoming_transfer>();

          incoming_transfer->m_tx = tx_wallet;
          incoming_transfer->m_account_index = *out.m_recipient->m_maj_i;
          incoming_transfer->m_subaddress_index = *out.m_recipient->m_min_i;
          incoming_transfer->m_address = get_address(*out.m_recipient->m_maj_i, *out.m_recipient->m_min_i);
          incoming_transfer->m_amount = gen_utils::uint64_t_cast(*out.m_amount);
          incoming_transfer->m_num_suggested_confirmations = 10 - num_confirmations;

          tx_wallet->m_incoming_transfers.push_back(incoming_transfer);

          std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
          auto out_key_image = std::make_shared<monero_key_image>();

          if (out.m_key_image != boost::none) out_key_image->m_hex = *out.m_key_image;
          
          output->m_account_index = *out.m_recipient->m_maj_i;
          output->m_subaddress_index = *out.m_recipient->m_min_i;
          output->m_amount = gen_utils::uint64_t_cast(*out.m_amount);
          output->m_is_spent = output_is_spent(out);
          output->m_key_image = out_key_image;
          output->m_index = gen_utils::uint64_t_cast(*out.m_global_index);
          
          output->m_tx = tx_wallet;
          output->m_stealth_public_key = out.m_public_key;

          tx_wallet->m_outputs.push_back(output);

          transfers.push_back(incoming_transfer);
        }
      }

      if (is_outgoing) {
        std::shared_ptr<monero_outgoing_transfer> outgoing_transfer = std::make_shared<monero_outgoing_transfer>();

        const auto sender = get_transaction_sender(tx);
        outgoing_transfer->m_tx = tx_wallet;
        
        outgoing_transfer->m_amount = total_sent;
        outgoing_transfer->m_account_index = sender.major;

        for (const auto spent_output : *tx.m_spent_outputs) {
          uint32_t account_idx = *spent_output.m_sender->m_maj_i;
          uint32_t subaddress_idx = *spent_output.m_sender->m_min_i;
          uint64_t out_amount = gen_utils::uint64_t_cast(*spent_output.m_amount);

          outgoing_transfer->m_account_index = account_idx;
          outgoing_transfer->m_addresses.push_back(get_address(account_idx, subaddress_idx));
          outgoing_transfer->m_subaddress_indices.push_back(subaddress_idx);

          if (is_change) {
            for (auto &out : get_tx_unspent_outs(tx_hash, unspent_outs_res)) {
              std::shared_ptr<monero_destination> dest = std::make_shared<monero_destination>();
              uint32_t account_idx = *out.m_recipient->m_maj_i;
              uint32_t subaddress_idx = *out.m_recipient->m_min_i;

              dest->m_address = get_address(account_idx, subaddress_idx);
              dest->m_amount = gen_utils::uint64_t_cast(*out.m_amount);

              outgoing_transfer->m_destinations.push_back(dest);
            }
          }

          std::shared_ptr<monero_output_wallet> output = std::make_shared<monero_output_wallet>();
          auto out_key_image = std::make_shared<monero_key_image>();
          out_key_image->m_hex = spent_output.m_key_image;
          
          output->m_account_index = account_idx;
          output->m_subaddress_index = subaddress_idx;
          output->m_amount = out_amount;
          output->m_is_spent = true;
          output->m_key_image = out_key_image;
          output->m_index = spent_output.m_out_index;
          output->m_tx = tx_wallet;
          //output->m_stealth_public_key = spent_output.m_

          tx_wallet->m_inputs.push_back(output);
        }

        tx_wallet->m_outgoing_transfer = outgoing_transfer;

        transfers.push_back(outgoing_transfer);
      }

    }
    
    return transfers;
  }

  uint64_t monero_wallet_light::estimated_tx_network_fee(uint64_t base_fee, uint32_t priority) {
    uint64_t fee_multiplier = get_fee_multiplier(priority, get_default_priority(), get_fee_algorithm());
    std::vector<uint8_t> extra; // blank extra
    size_t est_tx_size = estimate_rct_tx_size(2, get_mixin_size(), 2, extra.size(), true/*bulletproof*/, true/*clsag*/); // typically ~14kb post-rct, pre-bulletproofs
    uint64_t estimated_fee = calculate_fee_from_size(base_fee, est_tx_size, fee_multiplier);
    
    return estimated_fee;
  }

  uint64_t monero_wallet_light::get_upper_transaction_weight_limit(uint64_t upper_transaction_weight_limit__or_0_for_default) {
    if (upper_transaction_weight_limit__or_0_for_default > 0)
      return upper_transaction_weight_limit__or_0_for_default;

    uint64_t full_reward_zone = use_fork_rules(5, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 : use_fork_rules(2, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;

    if (use_fork_rules(8, 10))
      return full_reward_zone / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    else
      return full_reward_zone - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
  }

  uint64_t monero_wallet_light::get_fee_multiplier(uint32_t priority, uint32_t default_priority, int fee_algorithm) {
    static const struct
    {
      size_t count;
      uint64_t multipliers[4];
    }
    multipliers[] =
    {
      { 3, {1, 2, 3} },
      { 3, {1, 20, 166} },
      { 4, {1, 4, 20, 166} },
      { 4, {1, 5, 25, 1000} },
    };
    
    if (fee_algorithm == -1)
      fee_algorithm = get_fee_algorithm();
    
    // 0 -> default (here, x1 till fee algorithm 2, x4 from it)
    if (priority == 0)
      priority = default_priority;
    if (priority == 0)
    {
      if (fee_algorithm >= 2)
        priority = 2;
      else
        priority = 1;
    }
    
    if(fee_algorithm < 0 || fee_algorithm > 3) throw std::runtime_error("Invalid priority");
    
    // 1 to 3/4 are allowed as priorities
    const uint32_t max_priority = multipliers[fee_algorithm].count;
    if (priority >= 1 && priority <= max_priority)
    {
      return multipliers[fee_algorithm].multipliers[priority-1];
    }
    
    return 1;
  }

  int monero_wallet_light::get_fee_algorithm()
  {
    // changes at v3, v5, v8
    if (use_fork_rules(HF_VERSION_PER_BYTE_FEE, 0))
      return 3;
    if (use_fork_rules(5, 0))
      return 2;
    if (use_fork_rules(3, -720 * 14))
      return 1;
    return 0;
  }

  size_t monero_wallet_light::estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag)
  {
    size_t size = 0;
    
    // tx prefix
    
    // first few bytes
    size += 1 + 6;
    
    // vin
    size += n_inputs * (1+6+(mixin+1)*2+32);
    
    // vout
    size += n_outputs * (6+32);
    
    // extra
    size += extra_size;
    
    // rct signatures
    
    // type
    size += 1;
    
    // rangeSigs
    if (bulletproof)
    {
      size_t log_padded_outputs = 0;
      while ((1<<log_padded_outputs) < n_outputs)
        ++log_padded_outputs;
      size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;
    }
    else
      size += (2*64*32+32+64*32) * n_outputs;
    
    // MGs/CLSAGs
    if (clsag)
      size += n_inputs * (32 * (mixin+1) + 64);
    else
      size += n_inputs * (64 * (mixin+1) + 32);
    
    // mixRing - not serialized, can be reconstructed
    /* size += 2 * 32 * (mixin+1) * n_inputs; */
    
    // pseudoOuts
    size += 32 * n_inputs;
    // ecdhInfo
    size += 8 * n_outputs;
    // outPk - only commitment is saved
    size += 32 * n_outputs;
    // txnFee
    size += 4;
    
    MDEBUG("estimated " << (bulletproof ? "bulletproof" : "borromean") << " rct tx size for " << n_inputs << " inputs with ring size " << (mixin+1) << " and " << n_outputs << " outputs: " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
    return size;
  }

  size_t monero_wallet_light::estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag)
  {
    if (use_rct)
      return estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
    else
      return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES + extra_size;
  }

  uint64_t monero_wallet_light::estimate_tx_weight(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag)
  {
    size_t size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
    if (use_rct && bulletproof && n_outputs > 2)
    {
      const uint64_t bp_base = 368;
      size_t log_padded_outputs = 2;
      while ((1<<log_padded_outputs) < n_outputs)
        ++log_padded_outputs;
      uint64_t nlr = 2 * (6 + log_padded_outputs);
      const uint64_t bp_size = 32 * (9 + nlr);
      const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
      MDEBUG("clawback on size " << size << ": " << bp_clawback);
      size += bp_clawback;
    }
    return size;
  }

  uint64_t monero_wallet_light::estimate_fee(bool use_per_byte_fee, bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, bool clsag, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
  {
    if (use_per_byte_fee)
    {
      const size_t estimated_tx_weight = estimate_tx_weight(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
      return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
    }
    else
    {
      const size_t estimated_tx_size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag);
      return calculate_fee_from_size(base_fee, estimated_tx_size, fee_multiplier);
    }
  }

  uint64_t monero_wallet_light::calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
  {
    uint64_t fee = weight * base_fee * fee_multiplier;
    fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
    return fee;
  }

  uint64_t monero_wallet_light::calculate_fee(bool use_per_byte_fee, const cryptonote::transaction &tx, size_t blob_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
  {
    if (use_per_byte_fee) {
      return calculate_fee_from_weight(base_fee, cryptonote::get_transaction_weight(tx, blob_size), fee_multiplier, fee_quantization_mask);
    } else {
      return calculate_fee_from_size(base_fee, blob_size, fee_multiplier);
    }
  }

  bool monero_wallet_light::key_image_is_spent(crypto::key_image &key_image) const { 
    std::string ki = epee::string_tools::pod_to_hex(key_image);
    return key_image_is_spent(ki);
  }

  bool monero_wallet_light::key_image_is_spent(std::string &key_image) const {
    const auto res = get_address_info(false);
    const auto spends = *res.m_spent_outputs;

    for (const auto &spend : spends) {
      if (*spend.m_key_image == key_image) {
        return true;
      }
    }

    return false;
  }

  bool monero_wallet_light::output_is_spent(monero_light_output &output) const {
    auto key_images = *output.m_spend_key_images;

    for (auto key_image : key_images) {
      const auto rcpt = *output.m_recipient;
      cryptonote::subaddress_index received_subaddr;

      received_subaddr.major = *rcpt.m_maj_i;
      received_subaddr.minor = *rcpt.m_min_i;

      if (key_image_is_ours(key_image, *output.m_tx_pub_key, *output.m_index, received_subaddr)) {
        output.m_key_image = key_image;

        return true;
      }
    }

    return false;
  }

  bool monero_wallet_light::output_is_spent(monero_light_spend &spend) const {
    if (spend.m_key_image == boost::none) return false;
    std::string key_image = *spend.m_key_image;
    const auto rcpt = *spend.m_sender;
    cryptonote::subaddress_index received_subaddr;

    received_subaddr.major = *rcpt.m_maj_i;
    received_subaddr.minor = *rcpt.m_min_i;

    return key_image_is_ours(key_image, *spend.m_tx_pub_key, *spend.m_out_index, received_subaddr);
  }

  bool monero_wallet_light::output_is_locked(monero_light_output output) const {
    return false;  
  }

  void monero_wallet_light::calculate_balance() {
    
  }

  void monero_wallet_light::run_sync_loop() {
    if (m_sync_loop_running) return;  // only run one loop at a time
    m_sync_loop_running = true;

    // start sync loop thread
    // TODO: use global threadpool, background sync wasm wallet in c++ thread
    m_syncing_thread = boost::thread([this]() {

      // sync while enabled
      while (m_syncing_enabled) {
        try { lock_and_sync(); }
        catch (std::exception const& e) { std::cout << "monero_wallet_full failed to background synchronize: " << e.what() << std::endl; }
        catch (...) { std::cout << "monero_wallet_full failed to background synchronize" << std::endl; }

        // only wait if syncing still enabled
        if (m_syncing_enabled) {
          boost::mutex::scoped_lock lock(m_syncing_mutex);
          boost::posix_time::milliseconds wait_for_ms(m_syncing_interval.load());
          m_sync_cv.timed_wait(lock, wait_for_ms);
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
        if (rescan) rescan_blockchain();

        // sync wallet
        result = sync_aux(start_height);
      }
    } while (!rescan && (rescan = m_rescan_on_sync.exchange(false))); // repeat if not rescanned and rescan was requested
    return result;
  }

  monero_sync_result monero_wallet_light::sync_aux(boost::optional<uint64_t> start_height) {
    MTRACE("sync_aux()");
    uint64_t last_height = get_height();
    bool received_money = false;
    // determine sync start height
    uint64_t sync_start_height = last_height;
    //if (sync_start_height < get_restore_height()) set_restore_height(sync_start_height); // TODO monero-project: start height processed > requested start height unless sync height manually set

    // notify listeners of sync start
    //m_w2_listener->on_sync_start(sync_start_height);
    monero_sync_result result;

    // attempt to refresh wallet2 which may throw exception
    try {
      const std::string address = get_primary_address();
      const std::string view_key = get_private_view_key();
      //m_w2->refresh(m_w2->is_trusted_daemon(), sync_start_height, result.m_num_blocks_fetched, result.m_received_money, true);
      m_address_info = m_light_client->get_address_info(address, view_key);
      m_address_txs = m_light_client->get_address_txs(address, view_key);
      m_unspent_outs = m_light_client->get_unspent_outs(address, view_key, "0", 0);
      m_subaddrs = m_light_client->get_subaddrs(address, view_key);

      if (!m_is_synced) m_is_synced = is_synced();
      //m_w2_listener->update_listening();  // cannot unregister during sync which would segfault
    } catch (std::exception& e) {
      //m_w2_listener->on_sync_end(); // signal end of sync to reset listener's start and end heights
      throw;
    }

    // find and save rings
    //m_w2->find_and_save_rings(false);
    uint64_t current_height = get_height();
    uint64_t daemon_height = get_daemon_height();

    result.m_num_blocks_fetched = current_height - last_height;

    if (result.m_num_blocks_fetched > 0) {
      for(auto listener : get_listeners()) {
        listener->on_sync_progress(current_height, last_height, daemon_height, current_height / daemon_height, "Syncing");
        listener->on_new_block(current_height);
      }
    }

    result.m_received_money = received_money;
    // notify listeners of sync end and check for updated funds
    //m_w2_listener->on_sync_end();
    return result;
  }

  std::string monero_wallet_light::make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const
  {
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, get_nettype(), address))
    {
      error = std::string("wrong address: ") + address;
      return std::string();
    }

    // we want only one payment id
    if (info.has_payment_id && !payment_id.empty())
    {
      error = "A single payment id is allowed";
      return std::string();
    }

    if (!payment_id.empty())
    {
      error = "Standalone payment id deprecated, use integrated address instead";
      return std::string();
    }

    std::string uri = "monero:" + address;
    unsigned int n_fields = 0;

    if (!payment_id.empty())
    {
      uri += (n_fields++ ? "&" : "?") + std::string("tx_payment_id=") + payment_id;
    }

    if (amount > 0)
    {
      // URI encoded amount is in decimal units, not atomic units
      uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
    }

    if (!recipient_name.empty())
    {
      uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
    }

    if (!tx_description.empty())
    {
      uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
    }

    return uri;
  }

  bool monero_wallet_light::parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error) const
  {
    if (uri.substr(0, 7) != "monero:")
    {
      error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
      return false;
    }

    std::string remainder = uri.substr(7);
    const char *ptr = strchr(remainder.c_str(), '?');
    address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, get_nettype(), address))
    {
      error = std::string("URI has wrong address: ") + address;
      return false;
    }
    if (!strchr(remainder.c_str(), '?'))
      return true;

    std::vector<std::string> arguments;
    std::string body = remainder.substr(address.size() + 1);
    if (body.empty())
      return true;
    boost::split(arguments, body, boost::is_any_of("&"));
    std::set<std::string> have_arg;
    for (const auto &arg: arguments)
    {
      std::vector<std::string> kv;
      boost::split(kv, arg, boost::is_any_of("="));
      if (kv.size() != 2)
      {
        error = std::string("URI has wrong parameter: ") + arg;
        return false;
      }
      if (have_arg.find(kv[0]) != have_arg.end())
      {
        error = std::string("URI has more than one instance of " + kv[0]);
        return false;
      }
      have_arg.insert(kv[0]);

      if (kv[0] == "tx_amount")
      {
        amount = 0;
        if (!cryptonote::parse_amount(amount, kv[1]))
        {
          error = std::string("URI has invalid amount: ") + kv[1];
          return false;
        }
      }
      else if (kv[0] == "tx_payment_id")
      {
        if (info.has_payment_id)
        {
          error = "Separate payment id given with an integrated address";
          return false;
        }
        crypto::hash hash;
        if (!monero_utils::parse_long_payment_id(kv[1], hash))
        {
          error = "Invalid payment id: " + kv[1];
          return false;
        }
        payment_id = kv[1];
      }
      else if (kv[0] == "recipient_name")
      {
        recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
      }
      else if (kv[0] == "tx_description")
      {
        tx_description = epee::net_utils::convert_from_url_format(kv[1]);
      }
      else
      {
        unknown_parameters.push_back(arg);
      }
    }
    return true;
  }

  std::vector<monero_subaddress> monero_wallet_light::get_subaddresses() const {
    std::vector<monero_subaddress> result;

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      for (auto kv : *m_subaddrs.m_all_subaddrs) {
        for(auto index_range : kv.second) {

          auto subaddresses = monero_wallet_keys::get_subaddresses(kv.first, index_range.to_subaddress_indices());

          for (auto subaddress : subaddresses) {
            subaddress.m_balance = get_balance(kv.first, *subaddress.m_index);
            subaddress.m_unlocked_balance = get_unlocked_balance(kv.first, *subaddress.m_index);
            subaddress.m_label = get_subaddress_label(kv.first, *subaddress.m_index);
            result.push_back(subaddress);
          }
        }
      }
    }

    return result;
  }

  void monero_wallet_light::set_tx_note(const crypto::hash &txid, const std::string &note)
  {
    m_tx_notes[txid] = note;
  }

  std::string monero_wallet_light::get_tx_note(const crypto::hash &txid) const
  {
    std::unordered_map<crypto::hash, std::string>::const_iterator i = m_tx_notes.find(txid);
    if (i == m_tx_notes.end())
      return std::string();
    return i->second;
  }

  boost::optional<std::string> monero_wallet_light::get_subaddress_label(uint32_t account_idx, uint32_t subaddress_idx) const {
    auto subs = m_subaddress_labels.find(account_idx);
    if (subs == m_subaddress_labels.end()) return boost::none;
    auto sub = subs->second.find(subaddress_idx);
    if (sub == subs->second.end()) return boost::none;

    boost::optional<std::string> result = sub->second;

    return result;
  }

  std::tuple<uint64_t, uint64_t, std::vector<tools::wallet2::exported_transfer_details>> monero_wallet_light::export_outputs(bool all, uint32_t start, uint32_t count) const
  {
    std::vector<tools::wallet2::exported_transfer_details> outs;

    // invalid cases
    if(count == 0) throw std::runtime_error("Nothing requested");
    if(!all && start > 0) throw std::runtime_error("Incremental mode is incompatible with non-zero start");

    // valid cases:
    // all: all outputs, subject to start/count
    // !all: incremental, subject to count
    // for convenience, start/count are allowed to go past the valid range, then nothing is returned
    auto unspent_outs_res = get_unspent_outs(true);
    auto unspent_outs = *unspent_outs_res.m_outputs;

    size_t offset = 0;
    if (!all)
      while (offset < unspent_outs.size() && (unspent_outs[offset].key_image_is_known()))
        ++offset;
    else
      offset = start;

    outs.reserve(unspent_outs.size() - offset);
    for (size_t n = offset; n < unspent_outs.size() && n - offset < count; ++n)
    {
      const auto &out = unspent_outs[n];

      tools::wallet2::exported_transfer_details etd;
      
      crypto::public_key public_key;
      crypto::public_key tx_pub_key;

      epee::string_tools::hex_to_pod(*out.m_public_key, public_key);
      epee::string_tools::hex_to_pod(*out.m_tx_pub_key, tx_pub_key);

      cryptonote::transaction_prefix tx_prefix;

      add_tx_pub_key_to_extra(tx_prefix, tx_pub_key);

      etd.m_pubkey = public_key;
      etd.m_tx_pubkey = tx_pub_key; // pk_index?
      etd.m_internal_output_index = *out.m_index;
      etd.m_global_output_index = gen_utils::uint64_t_cast(*out.m_global_index);
      etd.m_flags.flags = 0;
      etd.m_flags.m_spent = out.is_spent();
      etd.m_flags.m_frozen = false;
      etd.m_flags.m_rct = out.rct();
      etd.m_flags.m_key_image_known = out.key_image_is_known();
      etd.m_flags.m_key_image_request = 0; //td.m_key_image_request;
      etd.m_flags.m_key_image_partial = is_multisig();
      etd.m_amount = gen_utils::uint64_t_cast(*out.m_amount);
      etd.m_additional_tx_keys = get_additional_tx_pub_keys_from_extra(tx_prefix);
      etd.m_subaddr_index_major = *out.m_recipient->m_maj_i;
      etd.m_subaddr_index_minor = *out.m_recipient->m_min_i;

      outs.push_back(etd);
    }

    return std::make_tuple(offset, unspent_outs.size(), outs);
  }

  tools::wallet2::unsigned_tx_set monero_wallet_light::parse_unsigned_tx(const std::string &unsigned_tx_st) const
  {
    tools::wallet2::unsigned_tx_set exported_txs;

    std::string s = unsigned_tx_st;
    const size_t magiclen = strlen(UNSIGNED_TX_PREFIX) - 1;
    if (strncmp(s.c_str(), UNSIGNED_TX_PREFIX, magiclen))
    {
      throw std::runtime_error("Bad magic from unsigned tx");
    }
    s = s.substr(magiclen);
    const char version = s[0];
    s = s.substr(1);
    if (version == '\003')
    {
      if (!m_load_deprecated_formats)
      {
        throw std::runtime_error("Not loading deprecated format");
      }
      try
      {
        std::istringstream iss(s);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> exported_txs;
      }
      catch (...)
      {
        throw std::runtime_error("Failed to parse data from unsigned tx");
      }
    }
    else if (version == '\004')
    {
      if (!m_load_deprecated_formats)
      {
        throw std::runtime_error("Not loading deprecated format");
      }
      try
      {
        s = decrypt_with_private_view_key(s);
        try
        {
          std::istringstream iss(s);
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> exported_txs;
        }
        catch (...)
        {
          throw std::runtime_error("Failed to parse data from unsigned tx");
        }
      }
      catch (const std::exception &e)
      {
        std::string msg = std::string("Failed to decrypt unsigned tx: ") + e.what();
        throw std::runtime_error(msg);
      }
    }
    else if (version == '\005')
    {
      try { s = decrypt_with_private_view_key(s); }
      catch(const std::exception &e) { 
        std::string msg = std::string("Failed to decrypt unsigned tx: ") + e.what();
        throw std::runtime_error(msg); 
      }
      try
      {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(s)};
        if (!::serialization::serialize(ar, exported_txs))
        {
          throw std::runtime_error("Failed to parse data from unsigned tx");
        }
      }
      catch (...)
      {
        throw std::runtime_error("Failed to parse data from unsigned tx");
      }
    }
    else
    {
      throw std::runtime_error("Unsupported version in unsigned tx");
    }

    std::cout << "Loaded tx unsigned data from binary: " << exported_txs.txes.size() << " transactions" << std::endl;
  
    return exported_txs;
  }

  std::string monero_wallet_light::sign_tx(tools::wallet2::unsigned_tx_set &exported_txs, std::vector<tools::wallet2::pending_tx> &txs, tools::wallet2::signed_tx_set &signed_txes)
  {
    //if (!std::get<2>(exported_txs.new_transfers).empty())
    //  import_outputs(exported_txs.new_transfers);
    //else if (!std::get<2>(exported_txs.transfers).empty())
    //  import_outputs(exported_txs.transfers);

    auto subaddresses = get_subaddresses_map();

    // sign the transactions
    for (size_t n = 0; n < exported_txs.txes.size(); ++n)
    {
      tools::wallet2::tx_construction_data &sd = exported_txs.txes[n];
      if(sd.sources.empty()) throw std::runtime_error("empty sources");
      if(sd.unlock_time) throw std::runtime_error("unlock time is non-zero");
      std::cout << " " << (n+1) << ": " << sd.sources.size() << " inputs, ring size " << sd.sources[0].outputs.size() << std::endl;
      signed_txes.ptx.push_back(tools::wallet2::pending_tx());
      tools::wallet2::pending_tx &ptx = signed_txes.ptx.back();
      rct::RCTConfig rct_config = sd.rct_config;
      crypto::secret_key tx_key;
      std::vector<crypto::secret_key> additional_tx_keys;
      
      bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), subaddresses, sd.sources, sd.splitted_dsts, sd.change_dts.addr, sd.extra, ptx.tx, tx_key, additional_tx_keys, sd.use_rct, rct_config, sd.use_view_tags);
      if(!r) throw std::runtime_error("tx not constructed");
      // we don't test tx size, because we don't know the current limit, due to not having a blockchain,
      // and it's a bit pointless to fail there anyway, since it'd be a (good) guess only. We sign anyway,
      // and if we really go over limit, the daemon will reject when it gets submitted. Chances are it's
      // OK anyway since it was generated in the first place, and rerolling should be within a few bytes.

      // normally, the tx keys are saved in commit_tx, when the tx is actually sent to the daemon.
      // we can't do that here since the tx will be sent from the compromised wallet, which we don't want
      // to see that info, so we save it here
      //if (store_tx_info() && tx_key != crypto::null_skey)
      //{
      //  const crypto::hash txid = get_transaction_hash(ptx.tx);
      //  m_tx_keys[txid] = tx_key;
      //  m_additional_tx_keys[txid] = additional_tx_keys;
      //}

      std::string key_images;
      bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const cryptonote::txin_v& s_e) -> bool
      {
        CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
        key_images += boost::to_string(in.k_image) + " ";
        return true;
      });
      if(!all_are_txin_to_key) throw std::runtime_error("unexpected txin type");

      ptx.key_images = key_images;
      ptx.fee = 0;
      for (const auto &i: sd.sources) ptx.fee += i.amount;
      for (const auto &i: sd.splitted_dsts) ptx.fee -= i.amount;
      ptx.dust = 0;
      ptx.dust_added_to_fee = false;
      ptx.change_dts = sd.change_dts;
      ptx.selected_transfers = sd.selected_transfers;
      ptx.tx_key = rct::rct2sk(rct::identity()); // don't send it back to the untrusted view wallet
      ptx.dests = sd.dests;
      ptx.construction_data = sd;

      txs.push_back(ptx);

      // add tx keys only to ptx
      txs.back().tx_key = tx_key;
      txs.back().additional_tx_keys = additional_tx_keys;
    }

    // add key image mapping for these txes
    const auto &keys = m_account.get_keys();
    hw::device &hwdev = m_account.get_device();
    for (size_t n = 0; n < exported_txs.txes.size(); ++n)
    {
      const cryptonote::transaction &tx = signed_txes.ptx[n].tx;

      crypto::key_derivation derivation;
      std::vector<crypto::key_derivation> additional_derivations;

      // compute public keys from out secret keys
      crypto::public_key tx_pub_key;
      crypto::secret_key_to_public_key(txs[n].tx_key, tx_pub_key);
      std::vector<crypto::public_key> additional_tx_pub_keys;
      for (const crypto::secret_key &skey: txs[n].additional_tx_keys)
      {
        additional_tx_pub_keys.resize(additional_tx_pub_keys.size() + 1);
        crypto::secret_key_to_public_key(skey, additional_tx_pub_keys.back());
      }

      // compute derivations
      hwdev.set_mode(hw::device::TRANSACTION_PARSE);
      if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation))
      {
        std::cout << "Failed to generate key derivation from tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping" << std::endl;
        static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
      }
      for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
      {
        additional_derivations.push_back({});
        if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back()))
        {
          std::cout << "Failed to generate key derivation from additional tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping" << std::endl;
          memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
        }
      }

      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        crypto::public_key output_public_key;
        if (!get_output_public_key(tx.vout[i], output_public_key))
          continue;

        // if this output is back to this wallet, we can calculate its key image already
        if (!is_out_to_acc_precomp(subaddresses, output_public_key, derivation, additional_derivations, i, hwdev, get_output_view_tag(tx.vout[i])))
          continue;
        crypto::key_image ki;
        cryptonote::keypair in_ephemeral;
        if (cryptonote::generate_key_image_helper(keys, subaddresses, output_public_key, tx_pub_key, additional_tx_pub_keys, i, in_ephemeral, ki, hwdev))
          signed_txes.tx_key_images[output_public_key] = ki;
        else
          std::cout << "Failed to calculate key image" << std::endl;
      }
    }

    // add key images
    auto unspent_outs_res = get_unspent_outs();
    auto unspent_outs = *unspent_outs_res.m_outputs;
    signed_txes.key_images.resize(unspent_outs.size());

    for (size_t i = 0; i < unspent_outs.size(); ++i)
    {
      auto unspent_out = unspent_outs[i];
      
      //if (!m_transfers[i].m_key_image_known || m_transfers[i].m_key_image_partial)
      if (!unspent_out.key_image_is_known())
        std::cout << "WARNING: key image not known in signing wallet at index " << i << std::endl;

      crypto::key_image ski;
      epee::string_tools::hex_to_pod(*unspent_out.m_key_image, ski);
      
      signed_txes.key_images[i] = ski;
    }

    // save as binary
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    try
    {
      if (!::serialization::serialize(ar, signed_txes))
        return std::string();
    }
    catch(...)
    {
      return std::string();
    }
    std::cout << "Saving signed tx data (with encryption): " << oss.str() << std::endl;
    std::string ciphertext = encrypt_with_private_view_key(oss.str());
    return std::string(SIGNED_TX_PREFIX) + ciphertext;
  }

  // --------------------------- LWS UTILS --------------------------

  monero_light_get_address_info_response monero_wallet_light::get_address_info(bool filter_outputs) const {
    auto result = m_address_info;

    if (!filter_outputs) return result;

    monero_light_get_address_info_response res;

    uint64_t total_sent = gen_utils::uint64_t_cast(*result.m_total_sent);

    res.m_blockchain_height = result.m_blockchain_height;
    res.m_locked_funds = result.m_locked_funds;
    res.m_scanned_block_height = result.m_scanned_block_height;
    res.m_scanned_height = result.m_scanned_height;
    res.m_transaction_height = result.m_transaction_height;
    res.m_start_height = result.m_start_height;
    res.m_total_received = result.m_total_received;
    res.m_total_sent = result.m_total_sent;
    res.m_rates = result.m_rates;
    res.m_spent_outputs = std::vector<monero_light_spend>();

    for (auto &output : *result.m_spent_outputs) {
      if (!output_is_spent(output)) {
        total_sent -= gen_utils::uint64_t_cast(*output.m_amount);
      }

      res.m_spent_outputs->push_back(output);
    }

    return res;
  }

  monero_light_get_address_txs_response monero_wallet_light::get_address_txs() const {
    monero_light_get_address_txs_response result = m_address_txs;
    monero_light_get_address_txs_response res;

    res.m_blockchain_height = result.m_blockchain_height;
    res.m_scanned_block_height = result.m_scanned_block_height;
    res.m_scanned_height = result.m_scanned_height;
    res.m_start_height = result.m_start_height;
    res.m_total_received = result.m_total_received;
    res.m_transactions = std::vector<monero_light_transaction>();

    for(auto &_tx : *result.m_transactions) {
      auto tx = std::make_shared<monero_light_transaction>();
      const auto __tx = std::make_shared<monero_light_transaction>(_tx);

      __tx.get()->copy(__tx, tx, true);
      uint64_t tx_total_sent = gen_utils::uint64_t_cast(*__tx->m_total_sent);
      uint64_t tx_total_received = gen_utils::uint64_t_cast(*__tx->m_total_received);
      
      for (auto spend : *__tx->m_spent_outputs) {
        if(!output_is_spent(spend)) {
          tx_total_sent -= gen_utils::uint64_t_cast(*spend.m_amount);
        }
      }

      if (tx_total_received == 0 && tx_total_sent == 0) {
        continue;
      }

      tx->m_total_sent = std::to_string(tx_total_sent);
      res.m_transactions->push_back(*tx);
    }

    return res;
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(std::string amount, uint32_t mixin, bool use_dust, std::string dust_threshold, bool filter_spent) const {
    auto result = m_light_client->get_unspent_outs(get_primary_address(), get_private_view_key(), amount, mixin == 0 ? get_mixin_size() : mixin, use_dust, dust_threshold);

    if (!filter_spent) {
      return result;
    }

    monero_light_get_unspent_outs_response response;

    uint64_t _amount = gen_utils::uint64_t_cast(*result.m_amount);

    response.m_fee_mask = result.m_fee_mask;
    response.m_per_byte_fee = result.m_per_byte_fee;
    response.m_outputs = std::vector<monero_light_output>();

    if (result.m_outputs == boost::none) {
      std::cout << "result outputs is none!" << std::endl;
      return response;
    }

    for (auto output : *result.m_outputs) {
      if (output_is_spent(output)) {
        _amount -= gen_utils::uint64_t_cast(*output.m_amount);
        continue;
      }

      response.m_outputs->push_back(output);
    }

    response.m_amount = std::to_string(_amount);

    return response;
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(uint64_t amount, uint32_t mixin, bool use_dust, uint64_t dust_threshold, bool filter_spent) const {
    std::string _amount = std::to_string(amount);
    std::string _dust_threshold = std::to_string(dust_threshold);

    return get_unspent_outs(_amount, mixin, use_dust, _dust_threshold, filter_spent);
  }

  monero_light_get_unspent_outs_response monero_wallet_light::get_unspent_outs(bool filter_spent) const {
    std::cout << "monero_wallet_light::get_unspent_outs(" << filter_spent << ")" << std::endl;
    auto result = m_unspent_outs;

    if (!filter_spent) {
      return result;
    }

    monero_light_get_unspent_outs_response response;

    uint64_t _amount = gen_utils::uint64_t_cast(*result.m_amount);

    response.m_fee_mask = result.m_fee_mask;
    response.m_per_byte_fee = result.m_per_byte_fee;
    response.m_outputs = std::vector<monero_light_output>();

    for (auto output : *result.m_outputs) {
      if (output_is_spent(output)) {
        _amount -= gen_utils::uint64_t_cast(*output.m_amount);
        continue;
      }

      response.m_outputs->push_back(output);
    }

    response.m_amount = std::to_string(_amount);

    return response;
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(uint32_t count, std::vector<uint64_t> &amounts) const {
    std::vector<std::string> _amounts;

    for (auto amount : amounts) {
      _amounts.push_back(std::to_string(amount));
    }

    return get_random_outs(count, _amounts);
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(uint32_t count, std::vector<std::string> &amounts) const {
    return m_light_client->get_random_outs(count, amounts);
  }

  monero_light_get_random_outs_response monero_wallet_light::get_random_outs(const std::vector<monero_light_output> &using_outs) const {
      // request decoys for any newly selected inputs
    std::vector<monero_light_output> decoy_requests;
    if (m_prior_attempt_unspent_outs_to_mix_outs) {
      for (size_t i = 0; i < using_outs.size(); ++i) {
        // only need to request decoys for outs that were not already passed in
        if (m_prior_attempt_unspent_outs_to_mix_outs->find(*using_outs[i].m_public_key) == m_prior_attempt_unspent_outs_to_mix_outs->end()) {
          decoy_requests.push_back(using_outs[i]);
        }
      }
    } else {
      decoy_requests = using_outs;
    }

    std::vector<std::string> decoy_req__amounts;
    for (auto &using_out : decoy_requests) {
      if (using_out.m_rct != boost::none && (*(using_out.m_rct)).size() > 0) {
        decoy_req__amounts.push_back("0");
      } else {
        std::ostringstream amount_ss;
        amount_ss << using_out.m_amount;
        decoy_req__amounts.push_back(amount_ss.str());
      }
    }

    return get_random_outs(get_mixin_size() + 1, decoy_req__amounts);
  }

  monero_light_get_subaddrs_response monero_wallet_light::get_subaddrs() const {
    return m_light_client->get_subaddrs(get_primary_address(), get_private_view_key());
  }

  monero_light_upsert_subaddrs_response monero_wallet_light::upsert_subaddrs(monero_light_subaddrs subaddrs, bool get_all) const {
    return m_light_client->upsert_subaddrs(get_primary_address(), get_private_view_key(), subaddrs, get_all);
  }

  monero_light_upsert_subaddrs_response monero_wallet_light::upsert_subaddrs(uint32_t account_idx, uint32_t subaddress_idx, bool get_all) const {
    std::cout << "monero_wallet_light::upsert_subaddrs(" << account_idx << ", " << subaddress_idx << ")" << std::endl;
    monero_light_subaddrs subaddrs;
    monero_light_index_range index_range(0, subaddress_idx);
    
    for(uint32_t i = 0; i <= account_idx; i++) {
      subaddrs[i] = std::vector<monero_light_index_range>();
      subaddrs[i].push_back(index_range);
    }

    return upsert_subaddrs(subaddrs, get_all);
  }

  monero_light_provision_subaddrs_response monero_wallet_light::provision_subaddrs(uint32_t n_maj_i, uint32_t n_min_i, uint32_t n_maj, uint32_t n_min, bool get_all) const {
    return m_light_client->provision_subaddrs(get_primary_address(), get_private_view_key(), n_maj_i, n_min_i, n_maj, n_min, get_all);
  }

  monero_light_login_response monero_wallet_light::login(bool create_account, bool generated_locally) const {
    return m_light_client->login(get_primary_address(), get_private_view_key());
  }

  monero_light_import_request_response monero_wallet_light::import_request() const {
    return m_light_client->import_request(get_primary_address(), get_private_view_key());
  }

  monero_light_submit_raw_tx_response monero_wallet_light::submit_raw_tx(const std::string tx) const {
    return m_light_client->submit_raw_tx(tx);
  }

  // --------------------------- STATIC WALLET UTILS --------------------------

  bool monero_wallet_light::wallet_exists(const std::string& primary_address, const std::string& private_view_key, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("monero_wallet_light::wallet_exists(" << primary_address << ")");

    monero_light_client client(std::move(http_client_factory));

    try {
      const auto address_info = client.get_address_info(primary_address, private_view_key);

      return true;
    }
    catch (...) {
      return false;
    }
  }

  bool monero_wallet_light::wallet_exists(const monero_wallet_config& config, const std::string& server_uri, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    if (config.m_primary_address == boost::none || config.m_primary_address.get().empty()) throw std::runtime_error("must provide a valid primary address");
    if (config.m_private_view_key == boost::none || config.m_private_view_key.get().empty()) throw std::runtime_error("must provide a valid private view key");
    if (config.m_server == boost::none || config.m_server->m_uri == boost::none || config.m_server->m_uri->empty()) throw std::runtime_error("must provide a lws connection");

    return wallet_exists(config.m_primary_address.get(), config.m_private_view_key.get(), *config.m_server->m_uri, std::move(http_client_factory));
  }

  monero_wallet_light* monero_wallet_light::open_wallet(const monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    monero_wallet_config _config = config.copy();
    return create_wallet_from_keys(_config, std::move(http_client_factory));
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
    if (config.m_restore_height != boost::none) throw std::runtime_error("Cannot specify restore height for light wallet");

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

    // validate config
    if (config.m_is_multisig != boost::none && config.m_is_multisig.get()) throw std::runtime_error("Restoring from multisig seed not supported");
    if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config.m_seed == boost::none || config.m_seed.get().empty()) throw std::runtime_error("Must provide wallet seed");

    // validate mnemonic and get recovery key and language
    crypto::secret_key spend_key_sk;
    std::string language;
    bool is_valid = crypto::ElectrumWords::words_to_bytes(config.m_seed.get(), spend_key_sk, language);
    if (!is_valid) throw std::runtime_error("Invalid mnemonic");
    if (language == crypto::ElectrumWords::old_language_name) language = Language::English().get_language_name();

    // apply offset if given
    if (config.m_seed_offset != boost::none && !config.m_seed_offset.get().empty()) spend_key_sk = cryptonote::decrypt_key(spend_key_sk, config.m_seed_offset.get());

    // initialize wallet account
    monero_wallet_light* wallet = new monero_wallet_light();
    wallet->m_account = cryptonote::account_base{};
    wallet->m_account.generate(spend_key_sk, true, false);

    // initialize remaining wallet
    wallet->m_network_type = config.m_network_type.get();
    wallet->m_language = language;
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    wallet->init_common();

    wallet->set_daemon_connection(config.m_server);
    if (config.m_account_lookahead != boost::none && wallet->is_connected_to_daemon()) {
      wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      wallet->m_subaddrs = wallet->get_subaddrs();
    }

    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_from_keys(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("monero_wallet_light::create_wallet_from_keys(...)");

      // validate and normalize config
      monero_wallet_config config_normalized = config.copy();
      if (config.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
      if (config.m_language == boost::none || config_normalized.m_language.get().empty()) config_normalized.m_language = "English";
      if (config.m_private_spend_key == boost::none) config_normalized.m_private_spend_key = std::string("");
      if (config.m_private_view_key == boost::none) config_normalized.m_private_view_key = std::string("");
      if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());

      // parse and validate private spend key
      crypto::secret_key spend_key_sk;
      bool has_spend_key = false;
      if (!config_normalized.m_private_spend_key.get().empty()) {
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
      if (config_normalized.m_private_view_key.get().empty()) {
        if (has_spend_key) has_view_key = false;
        else throw std::runtime_error("Neither spend key nor view key supplied");
      }
      if (has_view_key) {
        cryptonote::blobdata view_key_data;
        if (!epee::string_tools::parse_hexstr_to_binbuff(config_normalized.m_private_view_key.get(), view_key_data) || view_key_data.size() != sizeof(crypto::secret_key)) {
          throw std::runtime_error("failed to parse secret view key");
        }
        view_key_sk = *reinterpret_cast<const crypto::secret_key*>(view_key_data.data());
      }

      // parse and validate address
      cryptonote::address_parse_info address_info;
      if (config_normalized.m_primary_address.get().empty()) {
        if (has_view_key) throw std::runtime_error("must provide address if providing private view key");
      } else {
        if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(config_normalized.m_network_type.get()), config_normalized.m_primary_address.get())) throw std::runtime_error("failed to parse address");

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

      // initialize wallet account
      monero_wallet_light* wallet = new monero_wallet_light();
      if (has_spend_key && has_view_key) {
        wallet->m_account.create_from_keys(address_info.address, spend_key_sk, view_key_sk);
      } else if (has_spend_key) {
        wallet->m_account.generate(spend_key_sk, true, false);
      } else {
        wallet->m_account.create_from_viewkey(address_info.address, view_key_sk);
      }

      // initialize remaining wallet
      wallet->m_is_view_only = !has_spend_key;
      wallet->m_network_type = config_normalized.m_network_type.get();
      if (!config_normalized.m_private_spend_key.get().empty()) {
        wallet->m_language = config_normalized.m_language.get();
        epee::wipeable_string wipeable_mnemonic;
        if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) {
          throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
        }
        wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
      }
      wallet->init_common();
    wallet->set_daemon_connection(config.m_server);

    if (config.m_account_lookahead != boost::none && wallet->is_connected_to_daemon()) {
      wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      wallet->m_subaddrs = wallet->get_subaddrs();
    }

    return wallet;
  }

  monero_wallet_light* monero_wallet_light::create_wallet_random(monero_wallet_config& config, std::unique_ptr<epee::net_utils::http::http_client_factory> http_client_factory) {
    MTRACE("create_wallet_random(...)");

    // validate and normalize config
    monero_wallet_config config_normalized = config.copy();
    if (config_normalized.m_network_type == boost::none) throw std::runtime_error("Must provide wallet network type");
    if (config_normalized.m_language == boost::none || config_normalized.m_language.get().empty()) config_normalized.m_language = "English";
    if (!monero_utils::is_valid_language(config_normalized.m_language.get())) throw std::runtime_error("Unknown language: " + config_normalized.m_language.get());

    // initialize random wallet account
    monero_wallet_light* wallet = new monero_wallet_light();
    crypto::secret_key spend_key_sk = wallet->m_account.generate();

    // initialize remaining wallet
    wallet->m_network_type = config_normalized.m_network_type.get();
    wallet->m_language = config_normalized.m_language.get();
    epee::wipeable_string wipeable_mnemonic;
    if (!crypto::ElectrumWords::bytes_to_words(spend_key_sk, wipeable_mnemonic, wallet->m_language)) {
      throw std::runtime_error("Failed to create mnemonic from private spend key for language: " + std::string(wallet->m_language));
    }
    wallet->m_seed = std::string(wipeable_mnemonic.data(), wipeable_mnemonic.size());
    wallet->init_common();
    wallet->set_daemon_connection(config.m_server);

    if (config.m_account_lookahead != boost::none && wallet->is_connected_to_daemon()) {
      wallet->upsert_subaddrs(config.m_account_lookahead.get(), config.m_subaddress_lookahead.get());
      wallet->m_subaddrs = wallet->get_subaddrs();
    }

    return wallet;
  }

  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> monero_wallet_light::get_subaddresses_map() const {
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;

    auto account_keys = m_account.get_keys();
    hw::device &hwdev = m_account.get_device();

    subaddresses[account_keys.m_account_address.m_spend_public_key] = {0,0};

    if (m_subaddrs.m_all_subaddrs != boost::none) {
      for (auto kv : *m_subaddrs.m_all_subaddrs) {

        for (auto index_range : kv.second) {
          for (uint32_t i = index_range.at(0); i <= index_range.at(1); i++) {
            if (kv.first == 0 && i == 0) continue;

            auto subaddress_spend_pub_key = hwdev.get_subaddress_spend_public_key(account_keys, {kv.first, i});

            subaddresses[subaddress_spend_pub_key] = {kv.first, i};
          }
        }
      }
    }

    return subaddresses;
  }

}