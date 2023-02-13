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

use crate::{mock::*, *};

use codec::Encode;
use precompile_utils::{testing::*, EvmDataWriter};

fn precompiles() -> TestPrecompileSet<Runtime> {
	PrecompilesValue::get()
}

#[test]
fn wrong_argument_reverts() {
	ExtBuilder::default().build().execute_with(|| {
		precompiles()
			.prepare_test(
				TestAccount::Alice,
				PRECOMPILE_ADDRESS,
				EvmDataWriter::new_with_selector(Action::XvmCall).write(42u64).build(),
			)
			.expect_no_logs()
			.execute_reverts(|output| output == b"input doesn't match expected length");

		precompiles()
			.prepare_test(
				TestAccount::Alice,
				PRECOMPILE_ADDRESS,
				EvmDataWriter::new_with_selector(Action::XvmCall)
					.write(0u8)
					.write(Bytes(b"".to_vec()))
					.write(Bytes(b"".to_vec()))
					.write(Bytes(b"".to_vec()))
					.build(),
			)
			.expect_no_logs()
			.execute_reverts(|output| output == b"can not decode XVM context");
	})
}

#[test]
fn correct_arguments_works() {
	let context: XvmContext = Default::default();
	ExtBuilder::default().build().execute_with(|| {
		precompiles()
			.prepare_test(
				TestAccount::Alice,
				PRECOMPILE_ADDRESS,
				EvmDataWriter::new_with_selector(Action::XvmCall)
					.write(Bytes(context.encode()))
					.write(Bytes(b"".to_vec()))
					.write(Bytes(b"".to_vec()))
					.write(Bytes(b"".to_vec()))
					.build(),
			)
			.expect_no_logs()
			.execute_returns(EvmDataWriter::new().write(true).build());
	})
}
