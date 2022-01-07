//! Manta Pay Circuit Description

/// Asset
pub mod asset {
    /// Asset Id
    #[derive(Default, Eq)]
    pub struct AssetId(field);

    /// Asset Value
    #[derive(Default, Eq)]
    pub struct AssetValue(field);

    /// Asset
    #[derive(Default, Eq)]
    pub struct Asset {
        /// Asset Id
        pub id: AssetId,

        /// Asset Value
        pub value: AssetValue,
    }
}

/// Cryptographic Primitives
pub mod crypto {
    /// Key Agreement Scheme
    pub trait KeyAgreementScheme {
        /// Secret Key Type
        type SecretKey;

        /// Public Key Type
        type PublicKey;

        /// Shared Secret Type
        type SharedSecret;

        /// Derives a public key corresponding to `secret_key`. This public key should be sent to the
        /// other party involved in the shared computation.
        fn derive(self, secret_key: Self::SecretKey) -> Self::PublicKey;

        /// Computes the shared secret given the known `secret_key` and the given `public_key`.
        fn agree(
            self,
            secret_key: Self::SecretKey,
            public_key: Self::PublicKey,
        ) -> Self::SharedSecret;
    }

    /// Commitment Scheme
    pub trait CommitmentScheme {
        /// Trapdoor Type
        type Trapdoor;

        /// Input Type
        type Input;

        /// Output Type
        type Output;

        /// Commits to the `input` value using the randomness `trapdoor`.
        fn commit(self, trapdoor: Self::Trapdoor, input: Self::Input) -> Self::Output;
    }

    /// Binary Hash Function
    pub trait BinaryHashFunction {
        /// Left Input Type
        type Left;

        /// Right Input Type
        type Right;

        /// Output Type
        type Output;

        /// Computes the hash over `lhs` and `rhs`.
        fn hash(self, lhs: Self::Left, rhs: Self::Right) -> Self::Output;
    }

    /// Cryptographic Accumulators
    pub mod accumulator {
        /// Accumulator Model
        pub trait Model {
            /// Item Type
            type Item;

            /// Secret Witness Type
            type Witness;

            /// Output Type
            type Output;

            /// Verifies that `item` is stored in a known accumulator with accumulated `output` and
            /// membership `witness`.
            fn verify(self, item: Self::Item, witness: Self::Witness, output: Self::Output)
                -> bool;
        }

        /// Membership Proof
        pub struct MembershipProof<M>
        where
            M: Model,
        {
            /// Item Proof Witness
            witness: M::Witness,

            /// Accumulator Output
            output: M::Output,
        }

        impl<M> MembershipProof<M>
        where
            M: Model,
        {
            /// Verifies that `self` is a proof that `item` is contained in an accumulator governed
            /// by `model`.
            #[inline]
            pub fn verify(model: M, item: M::Item) -> bool {
                model.verify(item, self.witness, self.output)
            }
        }
    }
}

/// Transfer Protocol
pub mod transfer {
    use asset::*;
    use crypto::*;

    /// Transfer Specification
    pub trait Specification {
        /// Key Agreement Scheme Type
        type KeyAgreementScheme: KeyAgreementScheme;

        /// UTXO Commitment Scheme Type
        type UtxoCommitmentScheme: CommitmentScheme<Trapdoor = PublicKey<Self>, Input = Asset>;

        /// Void Number Hash Function Type
        type VoidNumberHashFunction: BinaryHashFunction<Left = Utxo<Self>, Right = SecretKey<Self>>;

        /// UTXO Set Model Type
        type UtxoSetModel: accumulator::Model<Item = Utxo<Self>>;
    }

    /// Secret Key Type
    pub type SecretKey<S> =
        <<S as Specification>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

    /// Public Key Type
    pub type PublicKey<S> =
        <<S as Specification>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

    /// Unspent Transaction Output Type
    pub type Utxo<S> = <<S as Specification>::UtxoCommitmentScheme as CommitmentScheme>::Output;

    /// UTXO Membership Proof
    pub type UtxoMembershipProof<S> =
        accumulator::MembershipProof<<S as Specification>::UtxoSetModel>;

    /// Void Number Type
    pub type VoidNumber<S> =
        <<S as Specification>::VoidNumberHashFunction as BinaryHashFunction>::Output;

    /// Transfer Parameters
    pub struct Parameters<S>
    where
        S: Specification,
    {
        /// Key Agreement Scheme Parameters
        key_agreement: S::KeyAgreementScheme,

        /// UTXO Commitment Scheme Parameters
        utxo_commitment: S::UtxoCommitmentScheme,

        /// Void Number Hash Function Parameters
        void_number_hash: S::VoidNumberHashFunction,

        /// UTXO Set Model Parameters
        utxo_set_model: S::UtxoSetModel,
    }

    impl<S> Parameters<S>
    where
        S: Specification,
    {
        /// Computes the Ephemeral Public Key from the `ephemeral_secret_key`.
        #[inline]
        pub fn ephemeral_public_key(self, ephemeral_secret_key: SecretKey<S>) -> PublicKey<S> {
            self.key_agreement.derive(ephemeral_secret_key)
        }

        /// Computes the UTXO trapdoor from `spend` and `ephemeral_public_key`.
        #[inline]
        fn trapdoor(self, spend: SecretKey<S>, ephemeral_public_key: PublicKey<S>) -> PublicKey<S> {
            self.key_agreement.agree(spend, ephemeral_public_key)
        }

        /// Computes the UTXO from `spend`, `ephemeral_public_key`, and `asset`.
        #[inline]
        pub fn utxo(
            self,
            spend: SecretKey<S>,
            ephemeral_public_key: PublicKey<S>,
            asset: Asset,
        ) -> Utxo<S> {
            self.utxo_commitment
                .commit(self.trapdoor(spend, ephemeral_public_key), asset)
        }

        /// Verifies that `utxo_membership_proof` is a proof that `utxo` is contained in the
        /// relevant accumulator.
        #[inline]
        pub fn verify_membership(
            self,
            utxo_membership_proof: UtxoMembershipProof<S>,
            utxo: Utxo<S>,
        ) -> bool {
            self.utxo_membership_proof.verify(self.utxo_set_model, utxo)
        }

        /// Computes the Void Number from `utxo` and `spend`.
        #[inline]
        pub fn void_number(self, utxo: Utxo<S>, spend: SecretKey<S>) -> VoidNumber<S> {
            self.void_number_hash.hash(utxo, spend)
        }
    }

    /// Sender
    pub struct Sender<S>
    where
        S: Specification,
    {
        /// Secret Spend Key
        spend: SecretKey<S>,

        /// Ephemeral Public Spend Key
        ephemeral_public_key: PublicKey<S>,

        /// Asset
        asset: Asset,

        /// UTXO Membership Proof
        utxo_membership_proof: UtxoMembershipProof<S>,

        /// Void Number
        void_number: VoidNumber<S>,
    }

    impl<S> Sender<S>
    where
        S: Specification,
    {
        /// Returns the [`Asset`] corresponding to this [`Sender`] after checking
        /// that `self` is well-formed.
        #[inline]
        pub fn get_well_formed_asset(self, parameters: Parameters<S>) -> Asset {
            let utxo = parameters.utxo(self.spend, self.ephemeral_public_key, self.asset);
            assert!(parameters.verify_membership(self.utxo_membership_proof, utxo));
            assert_eq!(self.void_number, parameters.void_number(utxo, self.spend));
            self.asset
        }
    }

    /// Receiver
    pub struct Receiver<S>
    where
        S: Specification,
    {
        /// Ephemeral Secret Spend Key
        ephemeral_secret_key: SecretKey<S>,

        /// Ephemeral Public Spend Key
        ephemeral_public_key: PublicKey<S>,

        /// Public Spend Key
        spend: PublicKey<S>,

        /// Asset
        asset: Asset,

        /// Unspent Transaction Output
        utxo: Utxo<S>,
    }

    impl<S> Receiver<S>
    where
        S: Specification,
    {
        /// Returns the [`Asset`] corresponding to this [`Receiver`] after checking
        /// that `self` is well-formed.
        #[inline]
        pub fn get_well_formed_asset(self, parameters: Parameters<S>) -> Asset {
            assert_eq!(
                self.ephemeral_public_key,
                parameters.ephemeral_public_key(self.ephemeral_secret_key)
            );
            assert_eq!(
                self.utxo,
                parameters.utxo(self.ephemeral_secret_key, self.spend, self.asset)
            );
            self.asset
        }
    }

    /// Transfer
    pub struct Transfer<S>
    where
        S: Specification,
    {
        /// Public Asset Id
        asset_id: Option<AssetId>,

        /// Sources
        sources: Vec<AssetValue>,

        /// Senders
        senders: Vec<Sender<S>>,

        /// Receivers
        receivers: Vec<Receiver<S>>,

        /// Sinks
        sinks: Vec<AssetValue>,
    }

    impl<S> Transfer<S>
    where
        S: Specification,
    {
        /// Asserts that a [`Transfer`] is valid, by checking that every participant is well-formed
        /// and that the transfer has a unique [`AssetId`] and the sum of input [`AssetValue`]
        /// is equal to the sum of output [`AssetValue`].
        #[inline]
        pub fn assert_valid(self) {
            let mut secret_asset_ids = Vec::new();

            assert_eq!(
                self.senders
                    .into_iter()
                    .map(|s| {
                        let asset = s.get_well_formed_asset(parameters);
                        secret_asset_ids.push(asset.id);
                        asset.value
                    })
                    .chain(self.sources)
                    .sum(),
                self.receivers
                    .into_iter()
                    .map(|r| {
                        let asset = r.get_well_formed_asset(parameters);
                        secret_asset_ids.push(asset.id);
                        asset.value
                    })
                    .chain(self.sinks)
                    .sum(),
            );

            assert_eq!(input_sum, output_sum);

            match self.asset_id {
                Some(asset_id) => assert_all_eq_to_base!(asset_id, secret_asset_ids.iter()),
                _ => assert_all_eq!(secret_asset_ids.iter()),
            }
        }
    }
}
