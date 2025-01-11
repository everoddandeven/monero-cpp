#include <stdio.h>
#include <iostream>
#include "wallet/monero_wallet_light.h"
#include "utils/gen_utils.h"
#include "utils/monero_utils.h"

int main(int argc, const char* argv[]) {

//  // configure logging
  mlog_configure("log_cpp_monero_light_tests.txt", true);
  mlog_set_log_level(4);

  // create a wallet from a seed phrase
  try {
    monero_wallet_config wallet_config;
    wallet_config.m_seed = "iris roared pause certain fuzzy himself usual nestle alkaline altitude hijack piano navy sequence educated keyboard tapestry oxidant cuffs yeti awesome system morsel older pause";
    wallet_config.m_network_type = monero_network_type::TESTNET;
    wallet_config.m_server = monero_rpc_connection("http://localhost:8443");
    wallet_config.m_account_lookahead = 0;
    wallet_config.m_subaddress_lookahead = 10;
    wallet_config.m_seed_offset = "";

    std::cout << "Creating wallet" << std::endl;
    monero_wallet_light* wallet_restored = monero_wallet_light::create_wallet(wallet_config);
    std::cout << "Created wallet" << std::endl;

    std::cout << "Connected to daemon: " << wallet_restored->is_connected_to_daemon() << std::endl;

    std::cout << "Wallet is synced: " << wallet_restored->is_synced() << std::endl;

    wallet_restored->sync();
    
    std::cout << "Wallet is synced: " << wallet_restored->is_synced() << std::endl;
    std::cout << "Daemon is synced: " << wallet_restored->is_daemon_synced() << std::endl;
    std::cout << "Daemon height: " << wallet_restored->get_daemon_height() << std::endl;

    std::cout << "Wallet height: " << wallet_restored->get_height() << std::endl;
    std::cout << "Wallet restore height: " << wallet_restored->get_restore_height() << std::endl;

    uint64_t balance = wallet_restored->get_balance();

    std::cout << "Wallet balance: " << balance << std::endl;

    balance = wallet_restored->get_balance(0);

    std::cout << "Account 0 balance: " << balance << std::endl;

    balance = wallet_restored->get_balance(0, 1);

    std::cout << "Subaddress 1 balance: " << balance << std::endl;

    std::cout << "Getting txs..." << std::endl;

    const auto txs = wallet_restored->get_txs();

    std::cout << "Found " << txs.size() << " transactions" << std::endl;

    for (const auto tx : txs) {
      uint64_t amount_received = 0;
      uint64_t amount_sent = 0;

      for (auto incoming_transf : tx->m_incoming_transfers) {
        amount_received = *incoming_transf->m_amount;
      }

      if (tx->m_outgoing_transfer) {
        auto outgoing_transfer = *tx->m_outgoing_transfer;

        amount_sent = *outgoing_transfer->m_amount;
      }

      std::cout << "Receieved: " << amount_received << ", sent: " << amount_sent << ", tx hash: " << tx->m_hash.get() << std::endl;
    }

    const auto outs = wallet_restored->get_outputs();

    std::cout << "Found " << outs.size() << " outputs" << std::endl;
    for (const auto out : outs) {
      std::string spent = *out->m_is_spent ? "true" : "false";
      std::cout << "Amount: " << *out->m_amount << ", spent: " << spent << ", public key: " << *out->m_stealth_public_key << std::endl;
    }

    std::cout << "Exporting outputs..." << std::endl;

    const auto exported_outputs = wallet_restored->export_outputs(true);

    std::cout << "Exported outputs: " << exported_outputs << std::endl;

    std::cout << "Creating tx..." << std::endl;

    monero_tx_config tx_config;

    tx_config.m_account_index = 0;
    tx_config.m_address = "BavK1UWTizrKL3eBz36dm4bnqL4i6NkyG61CMkia3Wp3BWJNFZTMRHK4SD8CetB4GaXM9f7Z5sarpVdhEVWb4JpeGQMSw8i";
    tx_config.m_amount = 5000000;
    tx_config.m_relay = true;

    std::shared_ptr<monero_tx_wallet> sent_tx = wallet_restored->create_tx(tx_config);

    bool in_pool = sent_tx->m_in_tx_pool.get();  // true
    std::string tx_hash = sent_tx->m_hash.get();

    std::cout << "Created tx: " << tx_hash << ", in pool: " << in_pool << std::endl;

    monero_wallet_config view_only_config;

    view_only_config.m_primary_address = "9ujWV5hT8x5Matb2smBVChDt7XEATCL7V9cRzmt8hdx9JcMG6MxX2dSEFiK1qb6CFWAFKnPPz7yKMdZQAAhc7vEm5gDjFxh";
    view_only_config.m_private_view_key = "7d546d0101f242617310815b38b0754407b2da55c0369c420573946261f5e50d";
    view_only_config.m_network_type = monero_network_type::TESTNET;
    view_only_config.m_server = monero_rpc_connection("http://localhost:8443");
  }
  catch (std::exception &ex) {
    std::cout << "An error occured: " << ex.what() << std::endl;
  }
  catch (...) {
    std::cout << "An unknown error occured" << std::endl;
  }

  return 0;
}