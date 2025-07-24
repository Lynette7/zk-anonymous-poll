#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::prelude::{vec::Vec, string::String};
use ink::storage::Mapping;


#[ink::contract]
mod contracts {

    use super::*;

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        PollNotFound,
        PollAlreadyExists,
        PollEnded,
        InvalidProof,
        NullifierAlreadyUsed,
        NotPollCreator,
        InvalidVoteChoice,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct ZKPoll {
        /// A counter for generating unique poll ids
        next_poll_id: u32,
        /// Stores all active and past polls, mapped by their unique id
        polls: Mapping<u32, Poll>,
        /// Stores nullifiers that have been used for each poll
        /// The key is a tuple(poll_id, nullifier_hash), and the value is a boolean(true if used)
        used_nullifiers: Mapping<(u32, [u8; 32]), bool>,
        /// Poll results (poll_id, option_index) -> vote_count
        poll_results: Mapping<(u32, u32), u32>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Poll {
        /// Unique identifier for the poll
        pub id: u32,
        pub title: String,
        pub description: String,
        /// List of possible options for the poll
        pub options: Vec<String>,
        /// The merkle root of eligible voters for this poll
        pub merkle_root: [u8; 32],
        pub creator: AccountId,
        /// Indicates if the poll is currently active for voting
        pub is_active: bool,
        /// Total number of votes cast in the poll
        pub total_votes: u32,
        pub end_block: BlockNumber,
    }

    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ProofData {
        /// Serialized ZK proof
        pub proof: Vec<u8>,
        pub nullifier: [u8; 32],
        pub vote_choice: u32,
    }

    #[ink(event)]
    pub struct PollCreated {
        #[ink(topic)]
        poll_id: u32,
        #[ink(topic)]
        creator: AccountId,
        title: String,
    }

    #[ink(event)]
    pub struct VoteCast {
        #[ink(topic)]
        poll_id: u32,
        nullifier: [u8; 32],
        vote_choice: u32,
    }

    #[ink(event)]
    pub struct PollEnded {
        #[ink(topic)]
        poll_id: u32,
        total_votes: u32,
    }

    impl ZKPoll {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                polls: Mapping::new(),
                used_nullifiers: Mapping::new(),
                next_poll_id: 1,
                poll_results: Mapping::new(),
             }
        }

        /// Create a new poll
        #[ink(message)]
        pub fn create_poll(
            &mut self,
            title: String,
            description: String,
            options: Vec<String>,
            merkle_root: [u8; 32],
            duration_blocks: BlockNumber,
        ) -> Result<u32> {
            let caller = self.env().caller();
            let current_block = self.env().block_number();
            let poll_id = self.next_poll_id;

            let poll = Poll {
                id: poll_id,
                title: title.clone(),
                description,
                options,
                merkle_root,
                creator: caller,
                end_block: current_block + duration_blocks,
                is_active: true,
                total_votes: 0,
            };

            self.polls.insert(poll_id, &poll);
            self.next_poll_id += 1;

            self.env().emit_event(PollCreated {
                poll_id,
                creator: caller,
                title,
            });

            Ok(poll_id)
        }

        /// Submit a vote with ZK proof
        #[ink(message)]
        pub fn vote(&mut self, poll_id: u32, proof_data: ProofData) -> Result<()> {
            // Get poll and verify it's active
            let mut poll = self.polls.get(poll_id).ok_or(Error::PollNotFound)?;

            if !poll.is_active || self.env().block_number() > poll.end_block {
                return Err(Error::PollEnded);
            }

            // Check if nullifier has been used
            if self.used_nullifiers.get((poll_id, proof_data.nullifier)).unwrap_or(false) {
                return  Err(Error::NullifierAlreadyUsed);
            }

            // Validate vote choice
            if proof_data.vote_choice as usize >= poll.options.len() {
                return Err(Error::InvalidVoteChoice);
            }

            // Verify ZK Proof
            if !self.verify_zk_proof(&poll, &proof_data) {
                return Err(Error::InvalidProof);
            }

            // Mark nullifier as used
            self.used_nullifiers.insert((poll_id, proof_data.nullifier), &true);

            // Update vote Count
            let current_votes = self.poll_results.get((poll_id, proof_data.vote_choice)).unwrap_or(0);
            self.poll_results.insert((poll_id, proof_data.vote_choice), &(current_votes + 1));

            // Update total votes
            poll.total_votes += 1;
            self.polls.insert(poll_id, &poll);

            self.env().emit_event(VoteCast {
                poll_id,
                nullifier: proof_data.nullifier,
                vote_choice: proof_data.vote_choice,
            });
            
            Ok(())
        }

        /// End a poll
        #[ink(message)]
        pub fn end_poll(&mut self, poll_id: u32) -> Result<()> {
            let mut poll = self.polls.get(poll_id).ok_or(Error::PollNotFound)?;

            if poll.creator != self.env().caller() {
                return Err(Error::NotPollCreator);
            }

            poll.is_active = false;
            self.polls.insert(poll_id, &poll);

            self.env().emit_event(PollEnded {
                poll_id,
                total_votes: poll.total_votes,
            });

            Ok(())
        }

        // Get poll information
        #[ink(message)]
        pub fn get_poll(&self, poll_id: u32) -> Option<Poll> {
            self.polls.get(poll_id)
        }

        // get poll results
        #[ink(message)]
        pub fn get_results(&self, poll_id: u32) -> Option<Vec<u32>> {
            let poll = self.polls.get(poll_id)?;
            let mut results = Vec::new();

            for i in 0..poll.options.len() {
                let votes = self.poll_results.get((poll_id, i as u32)).unwrap_or(0);
                results.push(votes);
            }

            Some(results)
        }

        // Check if a nullifier has been used
        #[ink(message)]
        pub fn is_nullifier_used(&self, poll_id: u32, nullifier: [u8; 32]) -> bool {
            self.used_nullifiers.get((poll_id, nullifier)).unwrap_or(false)
        }

        #[ink(message)]
        pub fn verify_zk_proof(&self, _poll: &Poll, _proof_data: &ProofData) -> bool {
            // To be implemented
            true
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {
            let contracts = Contracts::default();
            assert_eq!(contracts.get(), false);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {
            let mut contracts = Contracts::new(false);
            assert_eq!(contracts.get(), false);
            contracts.flip();
            assert_eq!(contracts.get(), true);
        }
    }


    /// This is how you'd write end-to-end (E2E) or integration tests for ink! contracts.
    ///
    /// When running these you need to make sure that you:
    /// - Compile the tests with the `e2e-tests` feature flag enabled (`--features e2e-tests`)
    /// - Are running a Substrate node which contains `pallet-contracts` in the background
    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// A helper function used for calling contract messages.
        use ink_e2e::ContractsBackend;

        /// The End-to-End test `Result` type.
        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        /// We test that we can upload and instantiate the contract using its default constructor.
        #[ink_e2e::test]
        async fn default_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let mut constructor = ContractsRef::default();

            // When
            let contract = client
                .instantiate("contracts", &ink_e2e::alice(), &mut constructor)
                .submit()
                .await
                .expect("instantiate failed");
            let call_builder = contract.call_builder::<Contracts>();

            // Then
            let get = call_builder.get();
            let get_result = client.call(&ink_e2e::alice(), &get).dry_run().await?;
            assert!(matches!(get_result.return_value(), false));

            Ok(())
        }

        /// We test that we can read and write a value from the on-chain contract.
        #[ink_e2e::test]
        async fn it_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // Given
            let mut constructor = ContractsRef::new(false);
            let contract = client
                .instantiate("contracts", &ink_e2e::bob(), &mut constructor)
                .submit()
                .await
                .expect("instantiate failed");
            let mut call_builder = contract.call_builder::<Contracts>();

            let get = call_builder.get();
            let get_result = client.call(&ink_e2e::bob(), &get).dry_run().await?;
            assert!(matches!(get_result.return_value(), false));

            // When
            let flip = call_builder.flip();
            let _flip_result = client
                .call(&ink_e2e::bob(), &flip)
                .submit()
                .await
                .expect("flip failed");

            // Then
            let get = call_builder.get();
            let get_result = client.call(&ink_e2e::bob(), &get).dry_run().await?;
            assert!(matches!(get_result.return_value(), true));

            Ok(())
        }
    }
}
