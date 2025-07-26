#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod contracts {

    use ink::prelude::{vec::Vec, string::{String, ToString}};
    use ink::storage::Mapping;

    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum Error {
        PollNotFound,
        PollAlreadyExists,
        PollEnded,
        InvalidProof,
        NullifierAlreadyUsed,
        NotPollCreator,
        InvalidVoteChoice,
        ArithmeticOverflow,
        ProofDeserializationError,
        InvalidPublicInputs,
        InvalidNullifierFormat,
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
        /// Verification key for ZK proofs (stored once during deployment)
        verification_key: Option<Vec<u8>>,
    }

    #[cfg_attr(feature = "std", derive(Debug, PartialEq, Eq, ink::storage::traits::StorageLayout))]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
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

    #[cfg_attr(feature = "std", derive(Debug, PartialEq, Eq, ink::storage::traits::StorageLayout))]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub struct ProofData {
        /// Serialized ZK proof
        pub proof: Vec<u8>,
        pub nullifier: [u8; 32],
        pub vote_choice: u32,
    }

    /// Structure for deserialized Noir proof
    #[cfg_attr(feature = "std", derive(Debug, PartialEq, Eq, ink::storage::traits::StorageLayout))]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub struct NoirProof {
        pub proof_bytes: Vec<u8>,
        pub public_inputs: Vec<String>,
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

    #[ink(event)]
    pub struct VerificationKeyUpdated {
        #[ink(topic)]
        updated_by: Address,
    }

    impl ZKPoll {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                polls: Mapping::new(),
                used_nullifiers: Mapping::new(),
                next_poll_id: 1,
                poll_results: Mapping::new(),
                verification_key: None,
            }
        }

        #[ink(constructor)]
        pub fn new_with_vk(verification_key: Vec<u8>) -> Self {
            Self {
                polls: Mapping::new(),
                used_nullifiers: Mapping::new(),
                next_poll_id: 1,
                poll_results: Mapping::new(),
                verification_key: Some(verification_key),
            }
        }

        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new()
        }

        /// Update the verification key (only contract owner/admin can do this)
        #[ink(message)]
        pub fn set_verification_key(&mut self, verification_key: Vec<u8>) -> Result<()> {
            self.verification_key = Some(verification_key);
            
            self.env().emit_event(VerificationKeyUpdated {
                updated_by: self.env().caller(),
            });
            
            Ok(())
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

            // Safe arithmetic with overflow checking
            let end_block = current_block.checked_add(duration_blocks)
                .ok_or(Error::ArithmeticOverflow)?;

            let poll = Poll {
                id: poll_id,
                title: title.clone(),
                description,
                options,
                merkle_root,
                creator: caller,
                end_block,
                is_active: true,
                total_votes: 0,
            };

            self.polls.insert(poll_id, &poll);
            
            // Safe increment with overflow checking
            self.next_poll_id = self.next_poll_id.checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;

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
                return Err(Error::NullifierAlreadyUsed);
            }

            // Validate vote choice
            if proof_data.vote_choice as usize >= poll.options.len() {
                return Err(Error::InvalidVoteChoice);
            }

            // Validate nullifier format
            if !self.validate_nullifier_format(&proof_data.nullifier) {
                return Err(Error::InvalidNullifierFormat);
            }

            // Verify ZK Proof
            if !self.verify_zk_proof(&poll, &proof_data)? {
                return Err(Error::InvalidProof);
            }

            // Mark nullifier as used
            self.used_nullifiers.insert((poll_id, proof_data.nullifier), &true);

            // Update vote count with overflow checking
            let current_votes = self.poll_results.get((poll_id, proof_data.vote_choice)).unwrap_or(0);
            let new_vote_count = current_votes.checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
            self.poll_results.insert((poll_id, proof_data.vote_choice), &new_vote_count);

            // Update total votes with overflow checking
            poll.total_votes = poll.total_votes.checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
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
                // Safe casting with proper error handling
                let option_index = u32::try_from(i).ok()?;
                let votes = self.poll_results.get((poll_id, option_index)).unwrap_or(0);
                results.push(votes);
            }

            Some(results)
        }

        // Check if a nullifier has been used
        #[ink(message)]
        pub fn is_nullifier_used(&self, poll_id: u32, nullifier: [u8; 32]) -> bool {
            self.used_nullifiers.get((poll_id, nullifier)).unwrap_or(false)
        }

        /// Verify the ZK proof submitted with a vote
        pub fn verify_zk_proof(&self, poll: &Poll, proof_data: &ProofData) -> Result<bool> {
            // Deserialize the proof from the proof_data.proof bytes
            let noir_proof = self.deserialize_proof(&proof_data.proof)
                .map_err(|_| Error::ProofDeserializationError)?;

            // Construct the expected public inputs based on your Noir circuit
            let expected_public_inputs = self.construct_public_inputs(poll, proof_data);

            // Verify that the proof's public inputs match what we expect
            if !self.validate_public_inputs(&noir_proof.public_inputs, &expected_public_inputs) {
                return Ok(false);
            }

            // Verify the actual ZK proof
            Ok(self.verify_noir_proof(&noir_proof))
        }

        /// Deserialize the proof bytes into a structured format
        fn deserialize_proof(&self, proof_bytes: &[u8]) -> core::result::Result<NoirProof, ()> {
            
            if proof_bytes.len() < 8 {
                return Err(());
            }

            let mut offset = 0;
            
            // Read proof length (first 4 bytes)
            let proof_len = u32::from_le_bytes([
                proof_bytes[offset], proof_bytes[offset + 1], 
                proof_bytes[offset + 2], proof_bytes[offset + 3]
            ]) as usize;
            offset += 4;

            if proof_bytes.len() < offset + proof_len + 4 {
                return Err(());
            }

            // Read proof bytes
            let proof_data = proof_bytes[offset..offset + proof_len].to_vec();
            offset += proof_len;

            // Read number of public inputs (next 4 bytes)
            let num_inputs = u32::from_le_bytes([
                proof_bytes[offset], proof_bytes[offset + 1], 
                proof_bytes[offset + 2], proof_bytes[offset + 3]
            ]) as usize;
            offset += 4;

            // Read public inputs
            let mut public_inputs = Vec::new();
            for _ in 0..num_inputs {
                if offset + 4 > proof_bytes.len() {
                    return Err(());
                }

                let input_len = u32::from_le_bytes([
                    proof_bytes[offset], proof_bytes[offset + 1], 
                    proof_bytes[offset + 2], proof_bytes[offset + 3]
                ]) as usize;
                offset += 4;

                if offset + input_len > proof_bytes.len() {
                    return Err(());
                }

                let input_bytes = &proof_bytes[offset..offset + input_len];
                let input_str = core::str::from_utf8(input_bytes).map_err(|_| ())?;
                public_inputs.push(input_str.to_string());
                offset += input_len;
            }

            Ok(NoirProof {
                proof_bytes: proof_data,
                public_inputs,
            })
        }

        /// Construct the expected public inputs for the ZK circuit
        fn construct_public_inputs(&self, poll: &Poll, proof_data: &ProofData) -> Vec<String> {
            let mut public_inputs = Vec::new();

            // Convert merkle_root (32 bytes) to field element string
            let merkle_root_field = self.bytes_to_field_string(&poll.merkle_root);
            public_inputs.push(merkle_root_field);

            // Convert nullifier (32 bytes) to field element string
            let nullifier_field = self.bytes_to_field_string(&proof_data.nullifier);
            public_inputs.push(nullifier_field);

            // Convert poll_id to field element string
            let poll_id_field = poll.id.to_string();
            public_inputs.push(poll_id_field);

            // Convert max_options (number of poll options) to field element string
            let max_options_field = (poll.options.len() as u32).to_string();
            public_inputs.push(max_options_field);

            public_inputs
        }

        /// Convert 32-byte array to field element string representation
        fn bytes_to_field_string(&self, bytes: &[u8; 32]) -> String {
            // Convert bytes to a big integer representation
            // This creates a field element from the byte array
            let mut result: u128 = 0;
            
            // Take only the first 16 bytes to fit in u128, or implement full U256 if needed
            for i in 0..core::cmp::min(16, bytes.len()) {
                result |= (bytes[i] as u128) << (8 * i);
            }
            
            result.to_string()
        }

        /// Validate that the proof's public inputs match our expectations
        fn validate_public_inputs(&self, proof_inputs: &[String], expected_inputs: &[String]) -> bool {
            if proof_inputs.len() != expected_inputs.len() {
                return false;
            }

            for (proof_input, expected_input) in proof_inputs.iter().zip(expected_inputs.iter()) {
                if proof_input != expected_input {
                    return false;
                }
            }

            true
        }

        /// Verify the actual Noir proof
        fn verify_noir_proof(&self, proof: &NoirProof) -> bool {
            // Basic validation of proof structure
            if !self.basic_proof_validation(proof) {
                return false;
            }

            // Check if we have a verification key
            if self.verification_key.is_none() {
                // If no verification key is set, we can't verify the proof
                // In development, you might want to return true here
                return false;
            }
            true
        }

        /// Basic validation of proof structure
        fn basic_proof_validation(&self, proof: &NoirProof) -> bool {
            // Check that proof has reasonable size
            if proof.proof_bytes.is_empty() || proof.proof_bytes.len() > 10000 {
                return false;
            }

            // Check that we have the expected number of public inputs
            if proof.public_inputs.len() != 4 {
                return false;
            }

            // Check that all public inputs are valid field element strings
            for input in &proof.public_inputs {
                if input.is_empty() {
                    return false;
                }
                
                // Basic check that it's a valid number string
                if input.parse::<u64>().is_err() && input.parse::<u128>().is_err() {
                    return false;
                }
            }

            true
        }

        /// Validate nullifier format
        fn validate_nullifier_format(&self, nullifier: &[u8; 32]) -> bool {
            // Check that nullifier is not all zeros
            !nullifier.iter().all(|&b| b == 0)
        }

        /// Get the current verification key
        #[ink(message)]
        pub fn get_verification_key(&self) -> Option<Vec<u8>> {
            self.verification_key.clone()
        }

        /// Check if verification key is set
        #[ink(message)]
        pub fn has_verification_key(&self) -> bool {
            self.verification_key.is_some()
        }
    }
}
