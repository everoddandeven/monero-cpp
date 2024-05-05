#include <stdio.h>
#include <iostream>
#include "wallet2.h"
#include "wallet/monero_wallet_light.h"
#include "wallet/monero_wallet_full.h"
#include "utils/monero_utils.h"

using namespace std;

const std::string DEFAULT_PRIMARY_ADDRESS = "A2sHbJxpEkvMkxM7hyQ3c89gAfCjpZvcaNpG4HSrgdUc8W4WeRiRdvY5FRzHkBWzR5fVj3tMnQbTxgZru5gz1N9ePhv5GSB";
const std::string DEFAULT_PRIVATE_VIEW_KEY = "b774f4f72d4f3c202a47926f5233e0ab5922a0b4e3d4d49a3c58f333e42c780e";
const std::string DEFAULT_SPEND_KEY = "ca77112364c9b489e42db8d84a0b371de637688636d1bc9ee0278f352cfc250c";
const std::string DEFAULT_SEED = "eavesdrop september unplugs aztec vary kickoff adjust emerge batch dialect nowhere ramped ringing oust circle pockets whipped nudged ripped oasis sovereign awkward cupcake dude pockets";
const std::string LWS_URI = "http://localhost:8443";

bool FUNDS_RECEIVED = false;
const bool TEST_RELAYS = true;

void test_view_only_and_offline_wallets(monero_wallet* view_only_wallet, monero_wallet* offline_wallet) {
  MTRACE("test_view_only_and_offline_wallets()");

  if (view_only_wallet->get_txs().empty()) {
    throw std::runtime_error("View only wallet has no transactions");
  }

  if (view_only_wallet->get_transfers().empty()) {
    throw std::runtime_error("View only wallet has no transfers");
  }

  if (view_only_wallet->get_outputs(monero_output_query()).empty()) {
    throw std::runtime_error("View only wallet has no outputs");
  }

  std::string primary_address = offline_wallet->get_primary_address();
  std::string private_view_key = offline_wallet->get_private_view_key();
  
  if (view_only_wallet->get_primary_address() != primary_address) {
    throw std::runtime_error("Primary address check failed");
  }

  if (view_only_wallet->get_private_view_key() != private_view_key) {
    throw std::runtime_error("Private view key check failed");
  }

  std::string error_msg = "Should have failed";

  try {
    view_only_wallet->get_seed();
    throw std::runtime_error(error_msg);
  } catch (std::exception& ex) {
    MWARNING(ex.what());
  }

  try {
    view_only_wallet->get_seed_language();
    throw std::runtime_error(error_msg);
  } catch (std::exception& ex) {
    MWARNING(ex.what());
  }

  try {
    view_only_wallet->get_private_spend_key();
    throw std::runtime_error(error_msg);
  } catch (std::exception& ex) {
    MWARNING(ex.what());
  }

  if (!view_only_wallet->is_connected_to_daemon()) {
    throw std::runtime_error("View only wallet is not connected to daemon");
  }

  view_only_wallet->sync();

  if (view_only_wallet->get_txs().empty()) {
    throw std::runtime_error("View only wallet has no txs");
  }

  // export outputs from view-only wallet
  std::string outputs_hex = view_only_wallet->export_outputs();

  // test offline wallet
  if(offline_wallet->is_connected_to_daemon()) throw std::runtime_error("Offline wallet is connected to daemon");
  if(offline_wallet->is_view_only()) throw std::runtime_error("Offline wallet is view only");
  monero_tx_query offline_tx_query;
  offline_tx_query.m_in_tx_pool = false;
  if (!offline_wallet->get_txs(offline_tx_query).empty()) throw std::runtime_error("Offline wallet has unconfirmed transactions");

  // import outputs to offline wallet
  int num_outputs_imported = offline_wallet->import_outputs(outputs_hex);

  if (num_outputs_imported == 0) throw std::runtime_error("No outputs imported");
  MINFO("Imported " << num_outputs_imported << " outputs in offline wallet");
  auto key_images = offline_wallet->export_key_images();
  MINFO("Exported " << key_images.size() << " from offline wallet");
  for (auto key_image : key_images) {
    MINFO("Export key image: " << key_image->m_hex.get());
  }

  if (!view_only_wallet->is_connected_to_daemon()) throw std::runtime_error("View only wallet is not connected to daemon");
  auto import_result = view_only_wallet->import_key_images(key_images);

  if (view_only_wallet->get_balance() != offline_wallet->get_balance()) throw std::runtime_error("View only - Offline wallet balance mismatch");
  
  monero_tx_config tx_config;
  tx_config.m_account_index = 0;
  tx_config.m_address = primary_address;
  tx_config.m_amount = 500000000;
  
  auto unsigned_tx = view_only_wallet->create_tx(tx_config);
  auto signed_tx_set = offline_wallet->sign_txs(unsigned_tx->m_tx_set.get()->m_unsigned_tx_hex.get());

  if (TEST_RELAYS) {
    auto tx_hashes = view_only_wallet->submit_txs(signed_tx_set.m_signed_tx_hex.get());
    if (tx_hashes.size() != 1) throw std::runtime_error("No transaction relayed");

  }
}

/*
  protected void testViewOnlyAndOfflineWallets(MoneroWallet viewOnlyWallet, MoneroWallet offlineWallet) {
    
    // create unsigned tx using view-only wallet
    MoneroTxWallet unsignedTx = viewOnlyWallet.createTx(new MoneroTxConfig()
    .setAccountIndex(0).setAddress(primaryAddress).setAmount(TestUtils.MAX_FEE.multiply(new BigInteger("3"))));
    assertNotNull(unsignedTx.getTxSet().getUnsignedTxHex());
    
    // sign tx using offline wallet
    MoneroTxSet signedTxSet = offlineWallet.signTxs(unsignedTx.getTxSet().getUnsignedTxHex());
    assertFalse(signedTxSet.getSignedTxHex().isEmpty());
    assertEquals(1, signedTxSet.getTxs().size());
    assertFalse(signedTxSet.getTxs().get(0).getHash().isEmpty());
    
    // parse or "describe" unsigned tx set
    MoneroTxSet describedTxSet = offlineWallet.describeUnsignedTxSet(unsignedTx.getTxSet().getUnsignedTxHex());
    testDescribedTxSet(describedTxSet);
    
    // submit signed tx using view-only wallet
    if (TEST_RELAYS) {
      List<String> txHashes = viewOnlyWallet.submitTxs(signedTxSet.getSignedTxHex());
      assertEquals(1, txHashes.size());
      assertEquals(64, txHashes.get(0).length());
      TestUtils.WALLET_TX_TRACKER.waitForWalletTxsToClearPool(viewOnlyWallet); // wait for confirmation for other tests
    }
  }
*/

monero_rpc_connection create_connection() {
  return monero_rpc_connection(LWS_URI, "superuser", "abctesting123");
}

monero_wallet_config create_base_wallet_config() {
  monero_wallet_config config;
  config.m_network_type = monero_network_type::TESTNET;
  config.m_server = create_connection();
  config.m_seed_offset = "";
  config.m_restore_height = 2338081;
  config.m_path = "MyLightWalletRestored";
  config.m_password = "supersecretpassword123";

  return config;
}

monero_wallet_config create_wallet_config(std::string primary_address, std::string private_view_key, std::string private_spend_key) {
  monero_wallet_config config = create_base_wallet_config();
  config.m_primary_address = primary_address;
  config.m_private_view_key = private_view_key;
  config.m_private_spend_key = private_spend_key;

  return config;
}

monero_wallet_config create_wallet_config(std::string primary_address, std::string private_view_key) {
  return create_wallet_config(primary_address, private_view_key, std::string(""));
}

monero_wallet_config create_wallet_config(std::string seed) {
  monero_wallet_config config = create_base_wallet_config();
  config.m_seed = seed;

  return config; 
}

monero_wallet_config create_view_only_config() {
  return create_wallet_config(DEFAULT_PRIMARY_ADDRESS, DEFAULT_PRIVATE_VIEW_KEY);
}

monero_wallet_config create_offline_config() {
  monero_wallet_config offline_config = create_wallet_config(DEFAULT_SEED);
  offline_config.m_server = monero_rpc_connection("offline_server_uri");
  offline_config.m_path = "MyOfflineWalletRestored";

  return offline_config;
}


/**
 * This code introduces the API.
 *
 * NOTE: depending on feedback, fields might change to become private and accessible only
 * through public accessors/mutators for pure object-oriented, etc.
 */
int main(int argc, const char* argv[]) {

//  // configure logging
  mlog_configure("log_cpp_light_tests.txt", true);
  mlog_set_log_level(4);
  // create a wallet from keys
  MINFO("===== Light Tests =====");
  MINFO("===== Create wallet from keys =====");
  monero_wallet_config view_only_config = create_view_only_config();
  monero_wallet_config offline_config = create_offline_config();

  monero_wallet* wallet_view_only = monero_wallet_light::create_wallet(view_only_config);
  monero_wallet* offline_wallet = monero_wallet_full::create_wallet(offline_config);

  MINFO("===== Wallet Light created successfully =====");
  MINFO("===== Syncing wallet light... =====");
  // start syncing the wallet continuously in the background
  wallet_view_only->sync();
  //wallet_restored->start_syncing(10000);
  if (!wallet_view_only->is_synced()) {
    MERROR("===== Wallet not synced =====");
    return 0;
  }

  MINFO("===== Wallet synced =====");
  bool view_only = wallet_view_only->is_view_only();

  MINFO("View only: " << view_only);
  test_view_only_and_offline_wallets(wallet_view_only, offline_wallet);
  wallet_view_only->close(true);
  return 0;
}