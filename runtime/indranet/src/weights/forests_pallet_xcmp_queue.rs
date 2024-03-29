// Copyright 2022 Selendra.

// Forests is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Forests is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Forests.  If not, see <http://www.gnu.org/licenses/>.

//! Autogenerated weights for `forests_pallet_xcmp_queue`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-05-25, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("indranet-dev"), DB CACHE: 1024

// Executed Command:
// ./target/production/indranet
// benchmark
// pallet
// --chain=indranet-dev
// --execution=wasm
// --wasm-execution=compiled
// --pallet=forests_pallet_xcmp_queue
// --extrinsic=*
// --steps=50
// --repeat=20
// --json-file=./bench-indranet.json
// --output=./runtime/indranet/src/weights

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `forests_pallet_xcmp_queue`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> forests_pallet_xcmp_queue::WeightInfo for WeightInfo<T> {
	// Storage: XcmpQueue QueueConfig (r:1 w:1)
	fn set_config_with_u32() -> Weight {
		Weight::from_ref_time(5_192_000 as u64)
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: XcmpQueue QueueConfig (r:1 w:1)
	fn set_config_with_weight() -> Weight {
		Weight::from_ref_time(5_363_000 as u64)
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
}
