use std::collections::HashMap;
use std::path::Path;

use clap::{Parser, Subcommand};
use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists,
    keygen::{SecretKey, SecretShare},
    DistributedKeyGeneration, GroupKey, Parameters, Participant, SignatureAggregator,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

const KEYS_DIRECTORY: &str = "./keys";
const PARAMETERS_FILE: &str = "params";

const CONTEXT: &[u8] = b"wwwwwwww";

/// Denotes the number of commitments published at a time
const NUMBER_OF_SHARES: usize = 1;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    CreateMultisig {
        /// The number of participants in the scheme.
        #[arg(long)]
        n: u32,
        /// The threshold required for a successful signature.
        #[arg(long)]
        t: u32,
        /// Name of the multisig group
        #[arg(long)]
        group_name: String,
    },
    Sign {
        /// Multisig group name
        #[arg(long)]
        group_name: String,
        /// Indexes of signers
        #[arg(long, num_args = 1.., value_delimiter = ',')]
        signers: Vec<u32>,
        /// Path to the file with message to sign
        #[arg(long)]
        message_file: String,
    },
}

#[derive(Serialize, Deserialize)]
struct ParticipantKeys {
    /// Signer index
    index: u32,
    /// Multisig public key
    group_key: [u8; 32],
    /// Multisig participant's private key
    secret: [u8; 32],
}

impl Into<SecretKey> for ParticipantKeys {
    fn into(self) -> SecretKey {
        SecretKey::new_from_index_and_secret(self.index, self.secret)
    }
}

#[derive(Serialize, Deserialize)]
struct MultisigParameters {
    /// Group public key
    group_key: [u8; 32],
    /// The number of participants in the scheme.
    n: u32,
    /// The threshold required for a successful signature.
    t: u32,
}

impl Into<Parameters> for MultisigParameters {
    fn into(self) -> Parameters {
        Parameters {
            n: self.n,
            t: self.t,
        }
    }
}

fn main() {
    let args = Args::parse();

    match args.cmd {
        Commands::CreateMultisig { n, t, group_name } => {
            if t > n || n == 0 {
                panic!("Wrong configuration received");
            }

            let params = Parameters { t, n };

            let mut participant_coefficient = HashMap::new();

            // Each participant generates their secret polynomial coefficients
            // and commitments to them.
            for i in 1..n + 1 {
                let (p, coefficients) = Participant::new(&params, i);

                participant_coefficient.insert(i, (p, coefficients));
            }

            let mut dist_keys_generated = HashMap::new();

            let mut general_their_sec_shares: HashMap<u32, Vec<SecretShare>> = HashMap::new();

            // Round one of the distributed key generation protocol.
            //
            // Each participant generates its own private state and then using that state
            // creates secret shares which will be shared with other participants to enter round two of key generation.
            for (outer_index, (_outer_participant, outer_coefficients)) in
                participant_coefficient.iter()
            {
                let mut other_participants = Vec::new();

                for (index, (participant, _coefficients)) in participant_coefficient.iter() {
                    if index == outer_index {
                        continue;
                    }

                    other_participants.push(participant.clone());
                }

                let state = DistributedKeyGeneration::<_>::new(
                    &params,
                    outer_index,
                    outer_coefficients,
                    &mut other_participants,
                )
                .unwrap();

                let their_secret_shares = state.their_secret_shares().unwrap();

                for s in their_secret_shares.iter() {
                    if let Some(v) = general_their_sec_shares.get_mut(&s.index) {
                        v.push(s.clone());
                    } else {
                        general_their_sec_shares.insert(s.index, vec![s.clone()]);
                    }
                }

                dist_keys_generated.insert(outer_index.clone(), state);
            }

            let mut final_keys = HashMap::new();

            // Round two of the distributed key generation protocol.
            //
            // Each participant now has a vector of secret shares given to them
            // by the other participants(general_their_sec_shares stores all the shared shares).
            // Each participant can now derive their long-lived, personal secret keys and the group’s public key.
            // They should all derive the same group public key.
            // They also derive their IndividualPublicKeys from their IndividualSecretKeys.
            for (index, state) in dist_keys_generated.iter() {
                let other_participant_shares = general_their_sec_shares.get(index).unwrap();

                let final_state = state
                    .clone()
                    .to_round_two(other_participant_shares.clone())
                    .unwrap();

                let (participant, _) = participant_coefficient.get(index).unwrap();

                // group_key should be same for all the participants here
                // secret_key is unique key for each participant
                let (group_key, secret_key) = final_state
                    .finish(participant.public_key().unwrap())
                    .unwrap();

                final_keys.insert(index.clone(), (group_key, secret_key));
            }

            // Below dump keys and params to the files

            if !Path::new(KEYS_DIRECTORY).exists() {
                std::fs::create_dir(KEYS_DIRECTORY).unwrap();
            }

            let dir_path = format!("{}/{}", KEYS_DIRECTORY, group_name);

            std::fs::create_dir(dir_path.clone()).unwrap();

            let mut group_k = None;

            for (index, (group_key, secret_key)) in final_keys.iter() {
                let p_k = ParticipantKeys {
                    index: index.clone(),
                    group_key: group_key.to_bytes(),
                    secret: secret_key.to_bytes(),
                };

                let s = serde_json::to_string(&p_k).unwrap();

                std::fs::write(format!("{}/{}", dir_path, index.to_string()), s).unwrap();

                if group_k.is_none() {
                    group_k = Some(group_key.to_bytes());
                }
            }

            let params = MultisigParameters {
                n,
                t,
                group_key: group_k.unwrap(),
            };
            std::fs::write(
                format!("{}/{}", dir_path, PARAMETERS_FILE),
                serde_json::to_string(&params).unwrap(),
            )
            .unwrap();
        }
        Commands::Sign {
            group_name,
            signers,
            message_file,
        } => {
            if signers.is_empty() {
                panic!("Signers indexes were not passed");
            }

            // Read group parameters
            let raw_params = std::fs::read(format!(
                "{}/{}/{}",
                KEYS_DIRECTORY, group_name, PARAMETERS_FILE
            ))
            .unwrap();
            let params: MultisigParameters = serde_json::from_slice(&raw_params).unwrap();
            let group_pub_key = GroupKey::from_bytes(params.group_key).unwrap();

            let params: Parameters = params.into();

            let mut participants_sec_keys = HashMap::new();

            let mut comshares = HashMap::new();

            // Each participant pre-compute (using generate_commitment_share_lists) and publish a list of commitment shares.
            //
            // Also here we read secret keys for each participant and save it to participants_sec_keys.
            for i in signers.iter() {
                let (public_comshares, secret_comshares) =
                    generate_commitment_share_lists(&mut OsRng, i.clone(), NUMBER_OF_SHARES);

                comshares.insert(i.clone(), (public_comshares, secret_comshares));

                let raw = std::fs::read(format!(
                    "{}/{}/{}",
                    KEYS_DIRECTORY,
                    group_name,
                    i.to_string()
                ))
                .unwrap();
                let key: ParticipantKeys = serde_json::from_slice(&raw).unwrap();
                let sec_key: SecretKey = key.into();
                participants_sec_keys.insert(i.clone(), sec_key);
            }

            // Prepare message to sign
            let message = std::fs::read(message_file).unwrap();
            let message_hash = compute_message_hash(&CONTEXT[..], &message[..]);

            let mut aggregator =
                SignatureAggregator::new(params, group_pub_key.clone(), &CONTEXT[..], &message[..]);

            // Aggregator takes note of each expected signer for this run of the protocol.
            for (i, (pub_comshares, _sec_comshares)) in comshares.iter() {
                let signer_public_key = participants_sec_keys.get(i).unwrap().to_public();
                aggregator.include_signer(
                    i.clone(),
                    pub_comshares.commitments[0],
                    signer_public_key,
                );
            }

            let signers = aggregator.get_signers().clone();

            // Each participant compute their partial signatures, and send these to the signature aggregator.
            for (i, sec_key) in participants_sec_keys.iter() {
                let (_, secret_comshares) = comshares.get_mut(i).unwrap();

                let partial_signature = sec_key
                    .sign(
                        &message_hash,
                        &group_pub_key,
                        secret_comshares,
                        0,
                        signers.as_ref(),
                    )
                    .unwrap();

                aggregator.include_partial_signature(partial_signature);
            }

            // Finalize signature.
            let aggregator = aggregator.finalize().unwrap();
            let threshold_signature = aggregator.aggregate().unwrap();

            if let Err(_) = threshold_signature.verify(&group_pub_key, &message_hash) {
                println!("Signature was NOT verified. Meaning there may be not enough signers or wrong keys signed the message");
            } else {
                println!(
                    "Signature is verified: {:?}",
                    bs58::encode(threshold_signature.to_bytes()).into_string()
                );
            }
        }
    }
}
