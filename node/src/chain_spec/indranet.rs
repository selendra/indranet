// Copyright 2019-2022 Parity Technologies (UK) Ltd.
// This file is part of Forest.

// Forest is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Forest is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Forest.  If not, see <http://www.gnu.org/licenses/>.

use crate::chain_spec::{
	get_account_id_from_seed, get_collator_keys_from_seed, Extensions, SAFE_XCM_VERSION,
};
use forest_primitives_core::ParaId;
use parachains_common::{AccountId, AuraId, Balance as IndranetBalance};
use sc_service::ChainType;
use sp_core::sr25519;
use indranet_runtime::evm::evm_config::Precompiles;

/// Specialized `ChainSpec` for the normal parachain runtime.
pub type IndranetChainSpec =
	sc_service::GenericChainSpec<indranet_runtime::GenesisConfig, Extensions>;


const INDRANET_ED: IndranetBalance = indranet_runtime::constants::currency::EXISTENTIAL_DEPOSIT;

/// Generate the session keys from individual elements.
///
/// The input must be a tuple of individual keys (a single arg for now since we have just one key).
pub fn indranet_session_keys(keys: AuraId) -> indranet_runtime::SessionKeys {
	indranet_runtime::SessionKeys { aura: keys }
}

pub fn indranet_development_config() -> IndranetChainSpec {
	let mut properties = sc_chain_spec::Properties::new();
	properties.insert("ss58Format".into(), 204.into());
	properties.insert("tokenSymbol".into(), "SEL".into());
	properties.insert("tokenDecimals".into(), 12.into());
    let sudo_key = get_account_id_from_seed::<sr25519::Public>("Alice");

	IndranetChainSpec::from_genesis(
		// Name
		"Indranet Development",
		// ID
		"indranet_dev",
		ChainType::Local,
		move || {
			indranet_genesis(
				// initial collators.
				vec![(
					get_account_id_from_seed::<sr25519::Public>("Alice"),
					get_collator_keys_from_seed::<AuraId>("Alice"),
				)],
				vec![
					get_account_id_from_seed::<sr25519::Public>("Alice"),
					get_account_id_from_seed::<sr25519::Public>("Bob"),
					get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
					get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
				],
                sudo_key.clone(),
				1000.into(),
			)
		},
		Vec::new(),
		None,
		None,
		None,
		Some(properties),
		Extensions { relay_chain: "kusama-dev".into(), para_id: 1000 },
	)
}

fn indranet_genesis(
	invulnerables: Vec<(AccountId, AuraId)>,
	endowed_accounts: Vec<AccountId>,
    root_key: AccountId,
	id: ParaId,
) -> indranet_runtime::GenesisConfig {

    // This is supposed the be the simplest bytecode to revert without returning any data.
    // We will pre-deploy it under all of our precompiles to ensure they can be called from
    // within contracts.
    // (PUSH1 0x00 PUSH1 0x00 REVERT)
    let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

	indranet_runtime::GenesisConfig {
		system: indranet_runtime::SystemConfig {
			code: indranet_runtime::WASM_BINARY
				.expect("WASM binary was not build, please build it!")
				.to_vec(),
		},
		balances: indranet_runtime::BalancesConfig {
			balances: endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, INDRANET_ED * 524_288))
				.collect(),
		},
		parachain_info: indranet_runtime::ParachainInfoConfig { parachain_id: id },
		collator_selection: indranet_runtime::CollatorSelectionConfig {
			invulnerables: invulnerables.iter().cloned().map(|(acc, _)| acc).collect(),
			candidacy_bond: INDRANET_ED * 16,
			..Default::default()
		},
		session: indranet_runtime::SessionConfig {
			keys: invulnerables
				.into_iter()
				.map(|(acc, aura)| {
					(
						acc.clone(),                  // account id
						acc,                          // validator id
						indranet_session_keys(aura), // session keys
					)
				})
				.collect(),
		},
		aura: Default::default(),
		aura_ext: Default::default(),
		parachain_system: Default::default(),
		selendra_xcm: indranet_runtime::SelendraXcmConfig {
			safe_xcm_version: Some(SAFE_XCM_VERSION),
		},
        evm: indranet_runtime::EVMConfig {
            // We need _some_ code inserted at the precompile address so that
            // the evm will actually call the address.
            accounts: Precompiles::used_addresses()
                .map(|addr| {
                    (
                        addr,
                        fp_evm::GenesisAccount {
                            nonce: Default::default(),
                            balance: Default::default(),
                            storage: Default::default(),
                            code: revert_bytecode.clone(),
                        },
                    )
                })
                .collect(),
        },
        base_fee: indranet_runtime::BaseFeeConfig::new(
            sp_core::U256::from(1_000_000_000),
            sp_runtime::Permill::zero(),
        ),
        ethereum: Default::default(),
        sudo: indranet_runtime::SudoConfig {
            key: Some(root_key),
        },
	}
}
