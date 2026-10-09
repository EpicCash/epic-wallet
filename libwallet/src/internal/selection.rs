// Copyright 2019 The Epic Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Selection of inputs for building transactions

use crate::address;
use crate::epic_core::consensus;
use crate::epic_core::core::amount_to_hr_string;
use crate::epic_core::libtx::{
    build,
    proof::{ProofBuild, ProofBuilder},
    tx_fee,
};
use crate::epic_keychain::{Identifier, Keychain};
use crate::epic_util::secp::key::SecretKey;
use crate::error::Error;
use crate::internal::keys;
use crate::slate::Slate;
use crate::types::*;
use std::collections::HashMap;

// Leave room in a maximum-weight block for its coinbase and for the
// transaction's input, recipient output, and kernel.
const MAX_CHANGE_OUTPUTS: usize = (consensus::MAX_BLOCK_WEIGHT
    - consensus::BLOCK_OUTPUT_WEIGHT
    - consensus::BLOCK_KERNEL_WEIGHT
    - consensus::BLOCK_INPUT_WEIGHT
    - consensus::BLOCK_OUTPUT_WEIGHT
    - consensus::BLOCK_KERNEL_WEIGHT)
    / consensus::BLOCK_OUTPUT_WEIGHT;

// generic needed here, removing it only hides the behavior
fn checked_sum<I>(values: I) -> Result<u64, Error>
where
    I: IntoIterator<Item = u64>,
{
    values.into_iter().try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| Error::Arithmetic("amount sum overflow".to_owned()))
    })
}

fn checked_amount_with_fee(amount: u64, fee: u64) -> Result<u64, Error> {
    amount
        .checked_add(fee)
        .ok_or_else(|| Error::Arithmetic("amount plus fee overflow".to_owned()))
}

fn validate_change_output_count(num_change_outputs: usize) -> Result<(), Error> {
    if num_change_outputs == 0 || num_change_outputs > MAX_CHANGE_OUTPUTS {
        return Err(Error::ArgumentError(format!(
            "number of change outputs must be between 1 and {}",
            MAX_CHANGE_OUTPUTS
        )));
    }
    Ok(())
}

fn calculate_change_amounts(
    total: u64,
    amount: u64,
    fee: u64,
    num_change_outputs: usize,
) -> Result<Vec<u64>, Error> {
    let amount_with_fee = checked_amount_with_fee(amount, fee)?;
    let change = total
        .checked_sub(amount_with_fee)
        .ok_or_else(|| Error::NotEnoughFunds {
            available: total,
            available_disp: amount_to_hr_string(total, false),
            needed: amount_with_fee,
            needed_disp: amount_to_hr_string(amount_with_fee, false),
        })?;

    if change == 0 {
        return Ok(vec![]);
    }

    validate_change_output_count(num_change_outputs)?;
    let output_count = num_change_outputs as u64;
    if output_count > change {
        return Err(Error::ArgumentError(
            "number of change outputs exceeds the change amount".to_owned(),
        ));
    }

    let part_change = change / output_count;
    let remainder_change = change % output_count;
    let final_amount = part_change
        .checked_add(remainder_change)
        .ok_or_else(|| Error::Arithmetic("change output value overflow".to_owned()))?;
    let mut amounts = vec![part_change; num_change_outputs - 1];
    amounts.push(final_amount);
    Ok(amounts)
}

fn derive_change_outputs<F>(
    amounts: Vec<u64>,
    mut next_child: F,
) -> Result<Vec<(u64, Identifier, Option<u64>)>, Error>
where
    F: FnMut() -> Result<Identifier, Error>,
{
    // derive one fresh wallet key for each change output
    amounts
        .into_iter()
        .map(|amount| next_child().map(|key| (amount, key, None)))
        .collect()
}

/// Initialize a transaction on the sender side, returns a corresponding
/// libwallet transaction slate with the appropriate inputs selected,
/// and saves the private wallet identifiers of our selected outputs
/// into our transaction context

pub fn build_send_tx<'a, T: ?Sized, C, K>(
    wallet: &mut T,
    keychain: &K,
    keychain_mask: Option<&SecretKey>,
    slate: &mut Slate,
    minimum_confirmations: u64,
    max_outputs: usize,
    change_outputs: usize,
    selection_strategy_is_use_all: bool,
    parent_key_id: Identifier,
    use_test_nonce: bool,
) -> Result<Context, Error>
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
{
    let (elems, inputs, change_amounts_derivations, fee) = select_send_tx(
        wallet,
        keychain_mask,
        slate.amount,
        slate.height,
        minimum_confirmations,
        max_outputs,
        change_outputs,
        selection_strategy_is_use_all,
        &parent_key_id,
    )?;

    // Update the fee on the slate so we account for this when building the tx.
    slate.fee = fee;

    let blinding = slate.add_transaction_elements(keychain, &ProofBuilder::new(keychain), elems)?;

    // Create our own private context
    let mut context = Context::new(
        keychain.secp(),
        blinding.secret_key(&keychain.secp()).unwrap(),
        &parent_key_id,
        use_test_nonce,
        0,
    );

    context.fee = fee;

    // Store our private identifiers for each input
    for input in inputs {
        context.add_input(&input.key_id, &input.mmr_index, input.value);
    }

    let mut commits: HashMap<Identifier, Option<String>> = HashMap::new();

    // Store change output(s) and cached commits
    for (change_amount, id, mmr_index) in &change_amounts_derivations {
        context.add_output(&id, &mmr_index, *change_amount);
        commits.insert(
            id.clone(),
            wallet.calc_commit_for_cache(keychain_mask, *change_amount, &id)?,
        );
    }

    Ok(context)
}

/// Locks all corresponding outputs in the context, creates
/// change outputs and tx log entry
pub fn lock_tx_context<'a, T: ?Sized, C, K>(
    wallet: &mut T,
    keychain_mask: Option<&SecretKey>,
    slate: &Slate,
    context: &Context,
    addr_to: Option<String>,
) -> Result<(), Error>
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
{
    let mut output_commits: HashMap<Identifier, (Option<String>, u64)> = HashMap::new();
    // Store cached commits before locking wallet
    let mut total_change = 0;
    for (id, _, change_amount) in &context.get_outputs() {
        output_commits.insert(
            id.clone(),
            (
                wallet.calc_commit_for_cache(keychain_mask, *change_amount, &id)?,
                *change_amount,
            ),
        );
        total_change += change_amount;
    }

    debug!("Change amount is: {}", total_change);

    let keychain = wallet.keychain(keychain_mask)?;

    let tx_entry = {
        let lock_inputs = context.get_inputs().clone();
        let messages = Some(slate.participant_messages());
        let slate_id = slate.id;
        let height = slate.height;
        let parent_key_id = context.parent_key_id.clone();
        let mut batch = wallet.batch(keychain_mask)?;
        let log_id = batch.next_tx_log_id(&parent_key_id)?;
        let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSentCreated, log_id);

        t.tx_slate_id = Some(slate_id.clone());
        let filename = format!("{}.epictx", slate_id);
        t.stored_tx = Some(filename);
        t.fee = Some(slate.fee);
        t.ttl_cutoff_height = slate.ttl_cutoff_height;

        match slate.calc_excess(&keychain) {
            Ok(e) => t.kernel_excess = Some(e),
            Err(_) => {}
        }
        t.kernel_lookup_min_height = Some(slate.height);

        let mut amount_debited = 0;
        t.num_inputs = lock_inputs.len();
        for id in lock_inputs {
            let mut coin = batch.get(&id.0, &id.1).unwrap();
            coin.tx_log_entry = Some(log_id);
            amount_debited = amount_debited + coin.value;
            batch.lock_output(&mut coin)?;
        }

        t.amount_debited = amount_debited;
        t.messages = messages;
        t.public_addr = addr_to;

        // store extra payment proof info, if required
        if let Some(ref p) = slate.payment_proof {
            let sender_address_path = match context.payment_proof_derivation_index {
                Some(p) => p,
                None => {
                    return Err(Error::PaymentProof(
                        "Payment proof derivation index required".to_owned(),
                    ))?;
                }
            };
            let sender_key = address::address_from_derivation_path(
                &keychain,
                &parent_key_id,
                sender_address_path,
            )?;
            let sender_address = address::ed25519_keypair(&sender_key)?.1;
            t.payment_proof = Some(StoredProofInfo {
                receiver_address: p.receiver_address.clone(),
                receiver_signature: p.receiver_signature.clone(),
                sender_address,
                sender_address_path,
                sender_signature: None,
            });
        };

        // write the output representing our change
        for (id, _, _) in &context.get_outputs() {
            t.num_outputs += 1;
            let (commit, change_amount) = output_commits.get(&id).unwrap().clone();
            t.amount_credited += change_amount;
            batch.save(OutputData {
                root_key_id: parent_key_id.clone(),
                key_id: id.clone(),
                n_child: id.to_path().last_path_index(),
                commit,
                mmr_index: None,
                value: change_amount.clone(),
                status: OutputStatus::Unconfirmed,
                height,
                lock_height: 0,
                is_coinbase: false,
                tx_log_entry: Some(log_id),
            })?;
        }
        batch.save_tx_log_entry(t.clone(), &parent_key_id)?;
        batch.commit()?;
        t
    };
    wallet.store_tx(&format!("{}", tx_entry.tx_slate_id.unwrap()), &slate.tx)?;
    Ok(())
}

/// Creates a new output in the wallet for the recipient,
/// returning the key of the fresh output
/// Also creates a new transaction containing the output
pub fn build_recipient_output<'a, T: ?Sized, C, K, F>(
    wallet: &mut T,
    keychain_mask: Option<&SecretKey>,
    slate: &mut Slate,
    parent_key_id: Identifier,
    use_test_rng: bool,
    complete_slate: F,
) -> Result<(Identifier, Context), Error>
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
    F: FnOnce(&K, &mut Slate, &mut Context) -> Result<(), Error>,
{
    // Create a potential output for this transaction
    let key_id = keys::next_available_key(wallet, keychain_mask).unwrap();
    let keychain = wallet.keychain(keychain_mask)?;
    let key_id_inner = key_id.clone();
    let amount = slate.amount;
    let height = slate.height;

    let slate_id = slate.id.clone();
    let blinding = slate.add_transaction_elements(
        &keychain,
        &ProofBuilder::new(&keychain),
        vec![build::output(amount, key_id.clone())],
    )?;

    // Add blinding sum to our context
    let mut context = Context::new(
        keychain.secp(),
        blinding
            .secret_key(wallet.keychain(keychain_mask)?.secp())
            .unwrap(),
        &parent_key_id,
        use_test_rng,
        1,
    );

    context.add_output(&key_id, &None, amount);
    let messages = Some(slate.participant_messages());
    let commit = wallet.calc_commit_for_cache(keychain_mask, amount, &key_id_inner)?;
    complete_slate(&keychain, slate, &mut context)?;
    let mut batch = wallet.batch(keychain_mask)?;
    let log_id = batch.next_tx_log_id(&parent_key_id)?;
    let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);

    t.tx_slate_id = Some(slate_id);
    t.amount_credited = amount;
    t.num_outputs = 1;
    t.messages = messages;
    t.ttl_cutoff_height = slate.ttl_cutoff_height;
    // when invoicing, this will be invalid
    match slate.calc_excess(&keychain) {
        Ok(e) => t.kernel_excess = Some(e),
        Err(_) => {}
    }
    t.kernel_lookup_min_height = Some(slate.height);
    batch.save(OutputData {
        root_key_id: parent_key_id.clone(),
        key_id: key_id_inner.clone(),
        mmr_index: None,
        n_child: key_id_inner.to_path().last_path_index(),
        commit,
        value: amount,
        status: OutputStatus::Unconfirmed,
        height,
        lock_height: 0,
        is_coinbase: false,
        tx_log_entry: Some(log_id),
    })?;
    batch.save_tx_log_entry(t, &parent_key_id)?;
    batch.commit()?;

    Ok((key_id, context))
}

/// Builds a transaction to send to someone from the HD seed associated with the
/// wallet and the amount to send. Handles reading through the wallet data file,
/// selecting outputs to spend and building the change.
pub fn select_send_tx<'a, T: ?Sized, C, K, B>(
    wallet: &mut T,
    keychain_mask: Option<&SecretKey>,
    amount: u64,
    current_height: u64,
    minimum_confirmations: u64,
    max_outputs: usize,
    change_outputs: usize,
    selection_strategy_is_use_all: bool,
    parent_key_id: &Identifier,
) -> Result<
    (
        Vec<Box<build::Append<K, B>>>,
        Vec<OutputData>,
        Vec<(u64, Identifier, Option<u64>)>, // change amounts and derivations
        u64,                                 // fee
    ),
    Error,
>
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
    B: ProofBuild,
{
    let (coins, _total, amount, fee) = select_coins_and_fee(
        wallet,
        amount,
        current_height,
        minimum_confirmations,
        max_outputs,
        change_outputs,
        selection_strategy_is_use_all,
        &parent_key_id,
    )?;

    // build transaction skeleton with inputs and change
    let (parts, change_amounts_derivations) =
        inputs_and_change(&coins, wallet, keychain_mask, amount, fee, change_outputs)?;

    Ok((parts, coins, change_amounts_derivations, fee))
}

/// Select outputs and calculating fee.
pub fn select_coins_and_fee<'a, T: ?Sized, C, K>(
    wallet: &mut T,
    amount: u64,
    current_height: u64,
    minimum_confirmations: u64,
    max_outputs: usize,
    change_outputs: usize,
    selection_strategy_is_use_all: bool,
    parent_key_id: &Identifier,
) -> Result<
    (
        Vec<OutputData>,
        u64, // total
        u64, // amount
        u64, // fee
    ),
    Error,
>
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
{
    // select some spendable coins from the wallet
    let (max_outputs, mut coins) = select_coins(
        wallet,
        amount,
        current_height,
        minimum_confirmations,
        max_outputs,
        selection_strategy_is_use_all,
        parent_key_id,
    );

    // sender is responsible for setting the fee on the partial tx
    // recipient should double check the fee calculation and not blindly trust the
    // sender

    // TODO - Is it safe to spend without a change output? (1 input -> 1 output)
    // TODO - Does this not potentially reveal the senders private key?
    //
    // First attempt to spend without change
    let mut fee = tx_fee(coins.len(), 1, 1, None);
    let mut total = checked_sum(coins.iter().map(|c| c.value))?;
    let mut amount_with_fee = checked_amount_with_fee(amount, fee)?;

    if total == 0 {
        return Err(Error::NotEnoughFunds {
            available: 0,
            available_disp: amount_to_hr_string(0, false),
            needed: amount_with_fee,
            needed_disp: amount_to_hr_string(amount_with_fee, false),
        })?;
    }

    // The amount with fee is more than the total values of our max outputs
    if total < amount_with_fee && coins.len() == max_outputs {
        return Err(Error::NotEnoughFunds {
            available: total,
            available_disp: amount_to_hr_string(total, false),
            needed: amount_with_fee,
            needed_disp: amount_to_hr_string(amount_with_fee, false),
        })?;
    }

    // We need to add a change address or amount with fee is more than total
    if total != amount_with_fee {
        validate_change_output_count(change_outputs)?;
        let num_outputs = change_outputs + 1;
        fee = tx_fee(coins.len(), num_outputs, 1, None);
        amount_with_fee = checked_amount_with_fee(amount, fee)?;

        // Here check if we have enough outputs for the amount including fee otherwise
        // look for other outputs and check again
        while total < amount_with_fee {
            // End the loop if we have selected all the outputs and still not enough funds
            if coins.len() == max_outputs {
                return Err(Error::NotEnoughFunds {
                    available: total,
                    available_disp: amount_to_hr_string(total, false),
                    needed: amount_with_fee,
                    needed_disp: amount_to_hr_string(amount_with_fee, false),
                })?;
            }

            // select some spendable coins from the wallet
            coins = select_coins(
                wallet,
                amount_with_fee,
                current_height,
                minimum_confirmations,
                max_outputs,
                selection_strategy_is_use_all,
                parent_key_id,
            )
            .1;
            fee = tx_fee(coins.len(), num_outputs, 1, None);
            total = checked_sum(coins.iter().map(|c| c.value))?;
            amount_with_fee = checked_amount_with_fee(amount, fee)?;
        }
    }
    Ok((coins, total, amount, fee))
}

/// Selects inputs and change for a transaction
pub fn inputs_and_change<'a, T: ?Sized, C, K, B>(
    coins: &Vec<OutputData>,
    wallet: &mut T,
    keychain_mask: Option<&SecretKey>,
    amount: u64,
    fee: u64,
    num_change_outputs: usize,
) -> Result<
    (
        Vec<Box<build::Append<K, B>>>,
        Vec<(u64, Identifier, Option<u64>)>,
    ),
    Error,
>
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
    B: ProofBuild,
{
    let mut parts = vec![];

    // calculate the total across all inputs, and how much is left
    let total = checked_sum(coins.iter().map(|c| c.value))?;
    let change_output_amounts =
        calculate_change_amounts(total, amount, fee, num_change_outputs)?;

    // build inputs using the appropriate derived key_ids
    for coin in coins {
        if coin.is_coinbase {
            parts.push(build::coinbase_input(coin.value, coin.key_id.clone()));
        } else {
            parts.push(build::input(coin.value, coin.key_id.clone()));
        }
    }

    if change_output_amounts.is_empty() {
        debug!("No change (sending exactly amount + fee), no change outputs to build");
        return Ok((parts, vec![]));
    }

    let change = checked_sum(change_output_amounts.iter().copied())?;
    debug!(
        "Building change outputs: total change: {} ({} outputs)",
        change, num_change_outputs
    );

    let change_amounts_derivations = derive_change_outputs(change_output_amounts, || {
        wallet.next_child(keychain_mask)
    })?;
    for (change_amount, change_key, _) in &change_amounts_derivations {
        parts.push(build::output(*change_amount, change_key.clone()));
    }

    Ok((parts, change_amounts_derivations))
}

/// Select spendable coins from a wallet.
/// Default strategy is to spend the maximum number of outputs (up to
/// max_outputs). Alternative strategy is to spend smallest outputs first
/// but only as many as necessary. When we introduce additional strategies
/// we should pass something other than a bool in.
/// TODO: Possibly move this into another trait to be owned by a wallet?

pub fn select_coins<'a, T: ?Sized, C, K>(
    wallet: &mut T,
    amount: u64,
    current_height: u64,
    minimum_confirmations: u64,
    max_outputs: usize,
    select_all: bool,
    parent_key_id: &Identifier,
) -> (usize, Vec<OutputData>)
//    max_outputs_available, Outputs
where
    T: WalletBackend<'a, C, K>,
    C: NodeClient + 'a,
    K: Keychain + 'a,
{
    // first find all eligible outputs based on number of confirmations
    let mut eligible = wallet
        .iter()
        .filter(|out| {
            out.root_key_id == *parent_key_id
                && out.eligible_to_spend(current_height, minimum_confirmations)
        })
        .collect::<Vec<OutputData>>();

    let max_available = eligible.len();

    // sort eligible outputs by increasing value
    eligible.sort_by_key(|out| out.value);

    // use a sliding window to identify potential sets of possible outputs to spend
    // Case of amount > total amount of max_outputs(500):
    // The limit exists because by default, we always select as many inputs as
    // possible in a transaction, to reduce both the Output set and the fees.
    // But that only makes sense up to a point, hence the limit to avoid being too
    // greedy. But if max_outputs(500) is actually not enough to cover the whole
    // amount, the wallet should allow going over it to satisfy what the user
    // wants to send. So the wallet considers max_outputs more of a soft limit.
    if eligible.len() > max_outputs {
        for window in eligible.windows(max_outputs) {
            let windowed_eligibles = window.iter().cloned().collect::<Vec<_>>();
            if let Some(outputs) = select_from(amount, select_all, windowed_eligibles) {
                return (max_available, outputs);
            }
        }
        // Not exist in any window of which total amount >= amount.
        // Then take coins from the smallest one up to the total amount of selected
        // coins = the amount.
        if let Some(outputs) = select_from(amount, false, eligible.clone()) {
            debug!(
                "Extending maximum number of outputs. {} outputs selected.",
                outputs.len()
            );
            return (max_available, outputs);
        }
    } else {
        if let Some(outputs) = select_from(amount, select_all, eligible.clone()) {
            return (max_available, outputs);
        }
    }

    // we failed to find a suitable set of outputs to spend,
    // so return the largest amount we can so we can provide guidance on what is
    // possible
    eligible.reverse();
    (
        max_available,
        eligible.iter().take(max_outputs).cloned().collect(),
    )
}

fn select_from(amount: u64, select_all: bool, outputs: Vec<OutputData>) -> Option<Vec<OutputData>> {
    let amount = u128::from(amount);
    let total: u128 = outputs
        .iter()
        .map(|output| u128::from(output.value))
        .sum();
    if total < amount {
        return None;
    }

    if select_all {
        return Some(outputs);
    }

    let mut selected_amount = 0u128;
    Some(
        outputs
            .into_iter()
            .take_while(|output| {
                if selected_amount >= amount {
                    return false;
                }
                selected_amount += u128::from(output.value);
                true
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_change_amounts_if_correct(change: u64, output_count: usize) -> Option<Vec<u64>> {
        let part_change = change.checked_div(output_count as u64)?;
        if part_change == 0 {
            return None;
        }

        let remainder_change = change % part_change;
        let mut amounts = vec![part_change; output_count];
        amounts[output_count - 1] = part_change.checked_add(remainder_change)?;
        let total: u128 = amounts.iter().map(|amount| u128::from(*amount)).sum();
        (total == u128::from(change)).then_some(amounts)
    }

    fn mock_output(value: u64) -> OutputData {
        OutputData {
            root_key_id: Identifier::zero(),
            key_id: Identifier::zero(),
            n_child: 0,
            commit: None,
            mmr_index: None,
            value,
            status: OutputStatus::Unspent,
            height: 0,
            lock_height: 0,
            is_coinbase: false,
            tx_log_entry: None,
        }
    }

    fn legacy_select_values(amount: u64, select_all: bool, values: &[u64]) -> Option<Vec<u64>> {
        let total = values.iter().copied().sum::<u64>();
        if total < amount {
            return None;
        }
        if select_all {
            return Some(values.to_vec());
        }

        let mut selected_amount = 0u64;
        Some(
            values
                .iter()
                .copied()
                .take_while(|value| {
                    let take = selected_amount < amount;
                    selected_amount += *value;
                    take
                })
                .collect(),
        )
    }

    fn selected_values(amount: u64, select_all: bool, values: &[u64]) -> Option<Vec<u64>> {
        select_from(
            amount,
            select_all,
            values.iter().copied().map(mock_output).collect(),
        )
        .map(|outputs| outputs.into_iter().map(|output| output.value).collect())
    }

    #[test]
    fn change_distribution_is_positive_and_conserves_value() {
        for change in 1..=256u64 {
            for output_count in 1..=usize::min(change as usize, 32) {
                let amounts = calculate_change_amounts(change, 0, 0, output_count).unwrap();
                assert_eq!(amounts.len(), output_count);
                assert!(amounts.iter().all(|amount| *amount > 0));
                assert_eq!(checked_sum(amounts).unwrap(), change);
            }
        }
    }

    #[test]
    fn valid_legacy_change_distributions_are_unchanged() {
        let mut comparisons = 0;
        for change in 1..=4096u64 {
            for output_count in 1..=usize::min(change as usize, 64) {
                if let Some(legacy) = legacy_change_amounts_if_correct(change, output_count) {
                    assert_eq!(
                        calculate_change_amounts(change, 0, 0, output_count).unwrap(),
                        legacy,
                        "change={change}, output_count={output_count}",
                    );
                    comparisons += 1;
                }
            }
        }
        assert_eq!(comparisons, 216_448);

        for (total, amount, fee, output_count) in [
            (10, 1, 1, 1),
            (10, 1, 1, 2),
            (1_000_000, 123_456, 789, 7),
            (u64::MAX, u64::MAX - 100, 50, 2),
        ] {
            let change = total - amount - fee;
            if let Some(legacy) = legacy_change_amounts_if_correct(change, output_count) {
                assert_eq!(
                    calculate_change_amounts(total, amount, fee, output_count).unwrap(),
                    legacy,
                );
            }
        }
    }

    #[test]
    fn exact_spend_does_not_require_change_outputs() {
        assert!(calculate_change_amounts(10, 9, 1, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn invalid_change_output_counts_are_rejected() {
        assert!(matches!(
            calculate_change_amounts(10, 0, 0, 0),
            Err(Error::ArgumentError(_))
        ));
        assert!(matches!(
            calculate_change_amounts(2, 0, 0, 3),
            Err(Error::ArgumentError(_))
        ));
        assert!(matches!(
            calculate_change_amounts(u64::MAX, 0, 0, MAX_CHANGE_OUTPUTS + 1),
            Err(Error::ArgumentError(_))
        ));
    }

    #[test]
    fn maximum_value_change_is_conserved() {
        let amounts = calculate_change_amounts(u64::MAX, 0, 0, 17).unwrap();
        assert!(amounts.iter().all(|amount| *amount > 0));
        assert_eq!(checked_sum(amounts).unwrap(), u64::MAX);

        let maximum_count_amounts =
            calculate_change_amounts(u64::MAX, 0, 0, MAX_CHANGE_OUTPUTS).unwrap();
        assert_eq!(maximum_count_amounts.len(), MAX_CHANGE_OUTPUTS);
        assert!(maximum_count_amounts.iter().all(|amount| *amount > 0));
        assert_eq!(checked_sum(maximum_count_amounts).unwrap(), u64::MAX);
    }

    #[test]
    fn arithmetic_failures_are_reported() {
        assert!(matches!(
            checked_amount_with_fee(u64::MAX, 1),
            Err(Error::Arithmetic(_))
        ));
        assert!(matches!(
            checked_sum([u64::MAX, 1]),
            Err(Error::Arithmetic(_))
        ));
        assert!(matches!(
            calculate_change_amounts(9, 9, 1, 1),
            Err(Error::NotEnoughFunds { .. })
        ));
    }

    #[test]
    fn change_key_derivation_failure_is_propagated() {
        let mut calls = 0;
        let result = derive_change_outputs(vec![2, 3, 5, 7], || {
            calls += 1;
            if calls == 3 {
                Err(Error::Backend("injected key derivation failure".to_owned()))
            } else {
                Ok(Identifier::zero())
            }
        });
        assert!(matches!(result, Err(Error::Backend(_))));
        assert_eq!(calls, 3);
    }

    #[test]
    fn change_derivation_preserves_amount_order_and_cardinality() {
        let amounts = vec![3, 5, 8, 13];
        let mut calls = 0;
        let outputs = derive_change_outputs(amounts.clone(), || {
            calls += 1;
            Ok(Identifier::zero())
        })
        .unwrap();

        assert_eq!(calls, amounts.len());
        assert_eq!(outputs.len(), amounts.len());
        assert_eq!(
            outputs.iter().map(|output| output.0).collect::<Vec<_>>(),
            amounts,
        );
        assert!(outputs.iter().all(|output| output.2.is_none()));
    }

    #[test]
    fn ordinary_coin_selection_matches_legacy_iterator_behavior() {
        let mut data_sets = vec![
            vec![],
            vec![0],
            vec![1],
            vec![1, 2, 3],
            vec![10, 1, 7, 3],
            vec![0, 5, 0, 4],
            vec![u64::MAX],
            vec![u64::MAX - 1, 1],
        ];

        for seed in 1..=256u64 {
            let mut state = seed;
            let mut values = Vec::new();
            for _ in 0..seed as usize % 17 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                values.push(state % 1_000_000);
            }
            data_sets.push(values);
        }

        for values in data_sets {
            let total = values.iter().copied().sum::<u64>();
            let mut amounts = vec![0, 1, total / 2, total];
            if total < u64::MAX {
                amounts.push(total + 1);
            }

            for amount in amounts {
                for select_all in [false, true] {
                    assert_eq!(
                        selected_values(amount, select_all, &values),
                        legacy_select_values(amount, select_all, &values),
                        "amount={amount}, select_all={select_all}, values={values:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn overflowing_coin_totals_are_selected_without_wraparound() {
        let values = [u64::MAX, 1, 7];
        assert_eq!(
            selected_values(u64::MAX, false, &values),
            Some(vec![u64::MAX]),
        );
        assert_eq!(
            selected_values(u64::MAX, true, &values),
            Some(values.to_vec()),
        );
    }

    #[test]
    fn checked_sum_stops_at_the_first_overflow() {
        let mut consumed = 0;
        let result = checked_sum(vec![1, u64::MAX, 9].into_iter().inspect(|_| consumed += 1));
        assert!(matches!(result, Err(Error::Arithmetic(_))));
        assert_eq!(consumed, 2);
    }
}
