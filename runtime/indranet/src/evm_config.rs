use super::{
	precompiles::SelendraPrecompiles, Aura, Balances, BaseFee, Call, Event, Origin, Runtime,
	UncheckedExtrinsic, MAXIMUM_BLOCK_WEIGHT, MILLICENTS, NORMAL_DISPATCH_RATIO, UNITS,
};
use codec::{Decode, Encode};
use indranet_primitive::{opaque, AccountId, Balance, Signature};

use sp_core::{H160, U256};
use sp_runtime::{
	traits::{BlakeTwo256, DispatchInfoOf, Dispatchable, PostDispatchInfoOf, Verify},
	transaction_validity::{TransactionPriority, TransactionValidity, TransactionValidityError},
	Permill,
};

use frame_support::{
	parameter_types,
	traits::FindAuthor,
	weights::{constants::WEIGHT_PER_SECOND, Weight},
	ConsensusEngineId,
};

pub type Precompiles = SelendraPrecompiles<Runtime>;

/// Current approximation of the gas/s consumption considering
/// EVM execution over compiled WASM (on 4.4Ghz CPU).
/// Given the 500ms Weight, from which 75% only are used for transactions,
/// the total EVM execution gas limit is: GAS_PER_SECOND * 0.500 * 0.75 ~= 15_000_000.
pub const GAS_PER_SECOND: u64 = 40_000_000;

/// Approximate ratio of the amount of Weight per Gas.
/// u64 works for approximations because Weight is a very small unit compared to gas.
pub const WEIGHT_PER_GAS: u64 = WEIGHT_PER_SECOND / GAS_PER_SECOND;

pub struct GasWeightMapping;
impl pallet_evm::GasWeightMapping for GasWeightMapping {
	fn gas_to_weight(gas: u64) -> Weight {
		gas.saturating_mul(WEIGHT_PER_GAS)
	}

	fn weight_to_gas(weight: Weight) -> u64 {
		weight.wrapping_div(WEIGHT_PER_GAS)
	}
}

pub struct FindAuthorTruncated<F>(sp_std::marker::PhantomData<F>);
impl<F: FindAuthor<u32>> FindAuthor<H160> for FindAuthorTruncated<F> {
	fn find_author<'a, I>(digests: I) -> Option<H160>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		if let Some(author_index) = F::find_author(digests) {
			let authority_id = Aura::authorities()[author_index as usize].clone();
			return Some(H160::from_slice(&authority_id.encode()[4..24]))
		}

		None
	}
}

parameter_types! {
	/// Ethereum-compatible chain_id:
	/// * Selendra:  256
	pub ChainId: u64 = 0x100;
	/// EVM gas limit
	pub BlockGasLimit: U256 = U256::from(
		NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT / WEIGHT_PER_GAS
	);
	pub PrecompilesValue: Precompiles = SelendraPrecompiles::<_>::new();
	pub WeightPerGas: u64 = WEIGHT_PER_GAS;
}

impl pallet_evm::Config for Runtime {
	type FeeCalculator = BaseFee;
	type GasWeightMapping = GasWeightMapping;
	type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Runtime>;
	type CallOrigin = pallet_evm::EnsureAddressRoot<AccountId>;
	type WithdrawOrigin = pallet_evm::EnsureAddressTruncated;
	type AddressMapping = pallet_evm::HashedAddressMapping<BlakeTwo256>;
	type Currency = Balances;
	type Event = Event;
	type Runner = pallet_evm::runner::stack::Runner<Self>;
	type PrecompilesType = SelendraPrecompiles<Self>;
	type PrecompilesValue = PrecompilesValue;
	type ChainId = ChainId;
	type OnChargeTransaction = ();
	type BlockGasLimit = BlockGasLimit;
	type FindAuthor = FindAuthorTruncated<Aura>;
}

impl pallet_ethereum::Config for Runtime {
	type Event = Event;
	type StateRoot = pallet_ethereum::IntermediateStateRoot<Self>;
}

parameter_types! {
	pub const EcdsaUnsignedPriority: TransactionPriority = TransactionPriority::MAX / 2;
	pub const CallFee: Balance = UNITS / 10;
	pub const CallMagicNumber: u16 = 0x0250;
}

impl pallet_custom_signatures::Config for Runtime {
	type Event = Event;
	type Call = Call;
	type Signature = pallet_custom_signatures::ethereum::EthereumSignature;
	type Signer = <Signature as Verify>::Signer;
	type CallMagicNumber = CallMagicNumber;
	type Currency = Balances;
	type CallFee = CallFee;
	type OnChargeTransaction = ();
	type UnsignedPriority = EcdsaUnsignedPriority;
}

parameter_types! {
	pub DefaultBaseFeePerGas: U256 = (MILLICENTS / 1_000_000).into();
	 // At the moment, we don't use dynamic fee calculation for Astar by default
	 pub DefaultElasticity: Permill = Permill::zero();
}

pub struct BaseFeeThreshold;
impl pallet_base_fee::BaseFeeThreshold for BaseFeeThreshold {
	fn lower() -> Permill {
		Permill::zero()
	}
	fn ideal() -> Permill {
		Permill::from_parts(500_000)
	}
	fn upper() -> Permill {
		Permill::from_parts(1_000_000)
	}
}

impl pallet_base_fee::Config for Runtime {
	type Event = Event;
	type Threshold = BaseFeeThreshold;
	type DefaultBaseFeePerGas = DefaultBaseFeePerGas;
	type DefaultElasticity = DefaultElasticity;
}

pub struct TransactionConverter;

impl fp_rpc::ConvertTransaction<UncheckedExtrinsic> for TransactionConverter {
	fn convert_transaction(&self, transaction: pallet_ethereum::Transaction) -> UncheckedExtrinsic {
		UncheckedExtrinsic::new_unsigned(
			pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
		)
	}
}

impl fp_rpc::ConvertTransaction<opaque::UncheckedExtrinsic> for TransactionConverter {
	fn convert_transaction(
		&self,
		transaction: pallet_ethereum::Transaction,
	) -> opaque::UncheckedExtrinsic {
		let extrinsic = UncheckedExtrinsic::new_unsigned(
			pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
		);
		let encoded = extrinsic.encode();
		opaque::UncheckedExtrinsic::decode(&mut &encoded[..])
			.expect("Encoded extrinsic is always valid")
	}
}

impl fp_self_contained::SelfContainedCall for Call {
	type SignedInfo = H160;

	fn is_self_contained(&self) -> bool {
		match self {
			Call::Ethereum(call) => call.is_self_contained(),
			_ => false,
		}
	}

	fn check_self_contained(&self) -> Option<Result<Self::SignedInfo, TransactionValidityError>> {
		match self {
			Call::Ethereum(call) => call.check_self_contained(),
			_ => None,
		}
	}

	fn validate_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Option<TransactionValidity> {
		match self {
			Call::Ethereum(call) => call.validate_self_contained(info, dispatch_info, len),
			_ => None,
		}
	}

	fn pre_dispatch_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<Call>,
		len: usize,
	) -> Option<Result<(), TransactionValidityError>> {
		match self {
			Call::Ethereum(call) => call.pre_dispatch_self_contained(info, dispatch_info, len),
			_ => None,
		}
	}

	fn apply_self_contained(
		self,
		info: Self::SignedInfo,
	) -> Option<sp_runtime::DispatchResultWithInfo<PostDispatchInfoOf<Self>>> {
		match self {
			call @ Call::Ethereum(pallet_ethereum::Call::transact { .. }) => Some(
				call.dispatch(Origin::from(pallet_ethereum::RawOrigin::EthereumTransaction(info))),
			),
			_ => None,
		}
	}
}
