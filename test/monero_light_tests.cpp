#include <stdio.h>
#include <iostream>
#include "wallet2.h"
#include "wallet/monero_wallet_light.h"
#include "wallet/monero_wallet_full.h"
#include "utils/monero_utils.h"

using namespace std;

bool FUNDS_RECEIVED = false;

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
  monero_wallet_config wallet_config;
  //wallet_config.m_seed = "hefty value later extra artistic firm radar yodel talent future fungal nutshell because sanity awesome nail unjustly rage unafraid cedar delayed thumbs comb custom sanity";
  //wallet_config.m_seed = "silk mocked cucumber lettuce hope adrenalin aching lush roles fuel revamp baptism wrist long tender teardrop midst pastry pigment equip frying inbound pinched ravine frying";
  //wallet_config.m_seed = "akin mobile observant polar farming abducts casket regular jeers sickness cuffs decay video exotic blip dove towel vapidly viking greater reinvest jackets jaws lesson video";
  //wallet_config.m_primary_address = "A1y9sbVt8nqhZAVm3me1U18rUVXcjeNKuBd1oE2cTs8biA9cozPMeyYLhe77nPv12JA3ejJN3qprmREriit2fi6tJDi99RR";
  //wallet_config.m_private_view_key = "198820da9166ee114203eb38c29e00b0e8fc7df508aa632d56ead849093d3808";
  //wallet_config.m_private_spend_key = "930755a1918de1a087e68c37accc8160de9f625712425f1b276e7d0dd305120b";
  wallet_config.m_primary_address = "A2sHbJxpEkvMkxM7hyQ3c89gAfCjpZvcaNpG4HSrgdUc8W4WeRiRdvY5FRzHkBWzR5fVj3tMnQbTxgZru5gz1N9ePhv5GSB";
  wallet_config.m_private_view_key = "b774f4f72d4f3c202a47926f5233e0ab5922a0b4e3d4d49a3c58f333e42c780e";
  wallet_config.m_private_spend_key = "ca77112364c9b489e42db8d84a0b371de637688636d1bc9ee0278f352cfc250c";
  wallet_config.m_path = "MyLightWalletRestored";
  wallet_config.m_password = "supersecretpassword123";
  wallet_config.m_network_type = monero_network_type::TESTNET;
  wallet_config.m_server = monero_rpc_connection("http://localhost:8443", "superuser", "abctesting123");
  //wallet_config.m_server = monero_rpc_connection("http://localhost:28081");
  wallet_config.m_restore_height = 2338081;
  wallet_config.m_seed_offset = "";
  monero_wallet* wallet_restored = monero_wallet_light::create_wallet(wallet_config);
  MINFO("===== Wallet Light created successfully =====");  
  MINFO("===== Syncing wallet light... =====");
  // start syncing the wallet continuously in the background
  wallet_restored->sync();
  //wallet_restored->start_syncing(10000);
  if (!wallet_restored->is_synced()) {
    MERROR("===== Wallet not synced =====");
    return 0;
  }

  MINFO("===== Wallet synced =====");

  monero_output_query output_query;
  output_query.m_account_index = 0;
  output_query.m_subaddress_index = 0;
  output_query.m_is_spent = false;


  std::vector<std::shared_ptr<monero_output_wallet>> outputs = wallet_restored->get_outputs(output_query);
  uint64_t balance = 0;
  uint64_t unlocked_balance = 0;

  for (auto output : outputs) balance += output->m_amount.get();

  MINFO("GOT " << outputs.size()<< " OUTPUTS FOR BALANCE: " << balance);

  output_query.m_tx_query = std::make_shared<monero_tx_query>();
  output_query.m_tx_query.get()->m_is_confirmed = true;

  outputs = wallet_restored->get_outputs(output_query);

  for (auto output : outputs) unlocked_balance += output->m_amount.get();

  MINFO("GOT " << outputs.size()<< " OUTPUTS FOR UNLOCKED BALANCE: " << unlocked_balance);

  return 0;
}