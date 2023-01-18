// Copyright (C) 2021-2022 Indranet.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Indranet chain specifications.

use super::{get_account_id_from_seed, get_from_seed, Extensions};

use forests_primitives_core::ParaId;
use indranet_primitive::{AccountId, AuraId, Balance};
use indranet_runtime::{evm_config::Precompiles, UNITS};
use sc_service::ChainType;
use sc_telemetry::TelemetryEndpoints;
use sp_core::sr25519;

const INDRANET_STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";
const DEFAULT_PROTOCOL_ID: &str = "sel";

/// Returns the properties for the [`IndranetChainSpec`].
pub fn indranet_chain_spec_properties() -> serde_json::map::Map<String, serde_json::Value> {
	serde_json::json!({
		"tokenDecimals": 18,
		"tokenSymbol": "SEL",
	})
	.as_object()
	.expect("Map given; qed")
	.clone()
}

/// Specialized `ChainSpec` for Indranet Network.
pub type IndranetChainSpec =
	sc_service::GenericChainSpec<indranet_runtime::GenesisConfig, Extensions>;

/// Gen Indranet chain specification for given parachain id.
pub fn get_chain_spec(para_id: u32) -> IndranetChainSpec {
	// Alice as default
	let sudo_key = get_account_id_from_seed::<sr25519::Public>("Alice");
	let endowned = vec![
		(get_account_id_from_seed::<sr25519::Public>("Alice"), 1_000 * UNITS),
		(get_account_id_from_seed::<sr25519::Public>("Bob"), 1_000 * UNITS),
	];

	IndranetChainSpec::from_genesis(
		"Indranet Testnet",
		"indranet",
		ChainType::Development,
		move || make_genesis(endowned.clone(), sudo_key.clone(), para_id.into()),
		vec![],
		Some(
			TelemetryEndpoints::new(vec![(INDRANET_STAGING_TELEMETRY_URL.to_string(), 0)])
				.expect("Selendra Staging telemetry url is valid; qed"),
		),
		Some(DEFAULT_PROTOCOL_ID),
		None,
		Some(indranet_chain_spec_properties()),
		Extensions { bad_blocks: Default::default(), relay_chain: "selendra".into(), para_id },
	)
}

fn session_keys(aura: AuraId) -> indranet_runtime::SessionKeys {
	indranet_runtime::SessionKeys { aura }
}

/// Helper function to create GenesisConfig.
fn make_genesis(
	balances: Vec<(AccountId, Balance)>,
	root_key: AccountId,
	parachain_id: ParaId,
) -> indranet_runtime::GenesisConfig {
	let authorities = vec![
		(get_account_id_from_seed::<sr25519::Public>("Alice"), get_from_seed::<AuraId>("Alice")),
		(get_account_id_from_seed::<sr25519::Public>("Bob"), get_from_seed::<AuraId>("Bob")),
	];

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
		sudo: indranet_runtime::SudoConfig { key: Some(root_key) },
		parachain_info: indranet_runtime::ParachainInfoConfig { parachain_id },
		balances: indranet_runtime::BalancesConfig { balances },
		session: indranet_runtime::SessionConfig {
			keys: authorities
				.iter()
				.map(|x| (x.0.clone(), x.0.clone(), session_keys(x.1.clone())))
				.collect::<Vec<_>>(),
		},
		aura: indranet_runtime::AuraConfig { authorities: vec![] },
		aura_ext: Default::default(),
		collator_selection: indranet_runtime::CollatorSelectionConfig {
			desired_candidates: 200,
			candidacy_bond: 3_200_000 * UNITS,
			invulnerables: authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		evm: indranet_runtime::EVMConfig {
			// We need _some_ code inserted at the precompile address so that
			// the evm will actually call the address.
			accounts: Precompiles::used_addresses()
				.into_iter()
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
		selendra_xcm: Default::default(),
		parachain_system: Default::default(),
	}
}
