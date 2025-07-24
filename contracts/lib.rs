#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::prelude::{vec::Vec, string::String};
use ink::storage::Mapping;


#[ink::contract]
mod contracts {

    use super::*;

    #[derive(Debug, PartialEq, Eq, parity_scale_codec::Encode, parity_scale_codec::Decode)]
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

    #[derive(Debug, Clone, PartialEq, Eq, parity_scale_codec::Encode, parity_scale_codec::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
    pub struct Poll {
        /// Unique identifier for the poll
        pub id: u32,
        pub title: String,
        pub description: String,
        /// List of possible options for the poll
        pub options: Vec<String>,
        /// The merkle root of eligible voters for this poll
        pub merkle_root: [u8; 32],
        pub creator: Address,
        /// Indicates if the poll is currently active for voting
        pub is_active: bool,
        /// Total number of votes cast in the poll
        pub total_votes: u32,
        pub end_block: BlockNumber,
    }

    #[derive(Debug, Clone, PartialEq, Eq, parity_scale_codec::Encode, parity_scale_codec::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
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
        creator: Address,
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
            if !self.verify_zk_proof() {
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
        pub fn verify_zk_proof(&self) -> bool {
            // todo!()
            true
        }
    }
}
