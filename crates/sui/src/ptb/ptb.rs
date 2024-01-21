// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::client_commands::SuiClientCommandResult;
use crate::ptb::ptb_parser::build_ptb::PTBBuilder;
use crate::ptb::ptb_parser::parser::ParsedPTBCommand;
use anyhow::anyhow;
use clap::parser::ValuesRef;
use clap::ArgMatches;
use clap::CommandFactory;
use clap::Id;
use clap::Parser;
use petgraph::prelude::DiGraphMap;
use serde::Serialize;
use shared_crypto::intent::Intent;
use std::clone::Clone;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::fmt::Formatter;
use sui_json_rpc_types::SuiTransactionBlockResponse;
use sui_json_rpc_types::SuiTransactionBlockResponseOptions;
use sui_keys::keystore::AccountKeystore;
use sui_sdk::wallet_context::WalletContext;
use sui_types::quorum_driver_types::ExecuteTransactionRequestType;
use sui_types::transaction::ProgrammableTransaction;
use sui_types::transaction::Transaction;
use sui_types::transaction::TransactionData;

use json_to_table::json_to_table;
use tabled::{
    builder::Builder as TableBuilder,
    settings::{style::HorizontalLine, Panel as TablePanel, Style as TableStyle},
};

#[cfg(test)]
#[path = "../unit_tests/ptb_tests.rs"]
mod ptb_tests;

/// The ProgrammableTransactionBlock structure used in the CLI ptb command
#[derive(Parser, Debug, Default)]
pub struct PTB {
    /// The path to the file containing the PTBs
    #[clap(long, num_args(1), required = false)]
    file: Vec<String>,
    /// An input for the PTB, defined as the variable name and value, e.g: --input recipient 0x321
    #[clap(long, num_args(1..3))]
    assign: Vec<String>,
    /// The object ID of the gas coin
    #[clap(long, required = false)]
    gas: String,
    /// The gas budget to be used to execute this PTB
    #[clap(long)]
    gas_budget: Option<String>,
    /// Given n-values of the same type, it constructs a vector.
    /// For non objects or an empty vector, the type tag must be specified.
    /// For example, --make-move-vec "<u64>" "[]"
    #[clap(long, num_args(2))]
    make_move_vec: Vec<String>,
    /// Merge N coins into the provided coin: --merge-coins into_coin "[coin1,coin2,coin3]"
    #[clap(long, num_args(2))]
    merge_coins: Vec<String>,
    /// Make a move call to a function
    #[clap(long, num_args(2..))]
    move_call: Vec<String>,
    /// Split the coin into N coins as per the given amount.
    /// On zsh, the vector needs to be given in quotes: --split-coins coin_to_split "[amount1,amount2]"
    #[clap(long, num_args(2))]
    split_coins: Vec<String>,
    /// Transfer objects to the address. E.g., --transfer-objects to_address "[obj1, obj2]"
    #[clap(long, num_args(2))]
    transfer_objects: Vec<String>,
    /// Publish the move package. It takes as input the folder where the package exists.
    #[clap(long, num_args(0..2), required=false)]
    publish: String,
    /// Upgrade the move package. It takes as input the folder where the package exists.
    #[clap(long, num_args(0..2), required=false)]
    upgrade: String,
    /// Preview the PTB instead of executing it
    #[clap(long)]
    preview: bool,
    /// Enable shadown warning when including other PTB files.
    /// Off by default.
    #[clap(long)]
    warn_shadows: bool,
    /// Pick gas budget strategy if multiple gas-budgets are provided.
    #[clap(long)]
    pick_gas_budget: Option<PTBGas>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PTBCommand {
    pub name: String,
    pub values: Vec<String>,
}

pub struct PTBPreview {
    cmds: Vec<PTBCommand>,
}

#[derive(clap::ValueEnum, Clone, Debug, Serialize, Default)]
enum PTBGas {
    MIN,
    #[default]
    MAX,
    SUM,
}

impl PTB {
    /// Get the passed arguments for this PTB and construct
    /// a map where the key is the command index,
    /// and the value is the name of the command and the values passed
    /// This is ordered as per how these args are given at the command line
    pub fn from_matches(
        &self,
        matches: &ArgMatches,
        parent_file: Option<String>,
        included_files: &mut BTreeMap<String, Vec<String>>,
    ) -> Result<BTreeMap<usize, PTBCommand>, anyhow::Error> {
        let mut order = BTreeMap::<usize, PTBCommand>::new();
        for arg_name in matches.ids() {
            if matches.try_get_many::<clap::Id>(arg_name.as_str()).is_ok() {
                continue;
            }

            // we need to skip the json as this is handled in the execute fn
            if arg_name.as_str() == "json" {
                continue;
            }

            if arg_name.as_str() == "pick_gas_budget" {
                insert_value::<PTBGas>(arg_name, &matches, &mut order)?;
                continue;
            }
            if arg_name.as_str() == "preview" || arg_name.as_str() == "warn_shadows" {
                insert_value::<bool>(arg_name, &matches, &mut order)?;
            } else {
                insert_value::<String>(arg_name, &matches, &mut order)?;
            }
        }
        Ok(self.build_ptb_for_parsing(order, &parent_file, included_files)?)
    }

    /// Builds a sequential list of ptb commands that should be fed into the parser
    pub fn build_ptb_for_parsing(
        &self,
        ptb: BTreeMap<usize, PTBCommand>,
        parent_file: &Option<String>,
        included_files: &mut BTreeMap<String, Vec<String>>,
    ) -> Result<BTreeMap<usize, PTBCommand>, anyhow::Error> {
        // the ptb input is a list of commands  and values, where the key is the index
        // of that value / command as it appearead in the args list on the CLI.
        // A command can have multiple values, and these values will appear sequential
        // with their indexes being consecutive (for that same command),
        // so we need to build the list of values for that specific command.
        // e.g., 1 [vals], 2 [vals], 4 [vals], 6 [vals], 1 + 2's value are
        // for the same command, 4 and 6 are different commands
        let mut output = BTreeMap::<usize, PTBCommand>::new();
        let mut curr_idx = 0;
        let mut cmd_idx = 0;

        // println!("{:?}", ptb);
        for (idx, val) in ptb.iter() {
            // these bool commands do not take any values
            // so handle them separately
            if val.name == "preview" || val.name == "warn-shadows" {
                cmd_idx += 1;
                output.insert(cmd_idx, val.clone());
                continue;
            }

            // the current value is for the current command we're building
            // so add it to the output's value at key cmd_idx
            if idx == &(curr_idx + 1) {
                output
                    .get_mut(&cmd_idx)
                    .unwrap()
                    .values
                    .extend(val.values.clone());
                curr_idx += 1;
            } else {
                // we have a new command, so insert the value and increment curr_idx
                cmd_idx += 1;
                curr_idx = *idx;
                // check if the command is a file inclusion, as we need to sequentially
                // insert that in the array of PTBCommands
                if val.name == "file" {
                    let new_index = self.resolve_file(
                        parent_file,
                        val.values.clone(),
                        included_files,
                        val.values.get(0).unwrap().to_string(),
                        cmd_idx,
                        &mut output,
                    )?;
                    cmd_idx = new_index;
                } else {
                    output.insert(cmd_idx, val.clone());
                }
            }
        }
        Ok(output)
    }

    /// Resolve the passed file into the existing array of PTB commands (output)
    /// It will flatly include the list of PTBCommands from the given file
    /// into the existing data holding the PTBs, and return the new index for the
    /// next command
    fn resolve_file(
        &self,
        parent_file: &Option<String>,
        filename: Vec<String>,
        included_files: &mut BTreeMap<String, Vec<String>>,
        current_file: String,
        start_index: usize,
        output: &mut BTreeMap<usize, PTBCommand>,
    ) -> Result<usize, anyhow::Error> {
        if filename.len() != 1 {
            return Err(anyhow!("The --file options should only pass one filename"));
        }
        let filename = filename.get(0).unwrap();
        let file_path = std::path::Path::new(filename);
        if !file_path.exists() {
            if let Some(parent_file) = parent_file {
                return Err(anyhow!(
                    "{parent_file} includes {filename}, which does not exist"
                ));
            } else {
                return Err(anyhow!("{filename} does not exist"));
            }
        }
        let file_content = std::fs::read_to_string(file_path)?.replace("\\", "");

        // do not allow for circular inclusion of files
        // e.g., sui client ptb --file a.ptb, and then have --file a.ptb in a.ptb file.
        if file_content.contains(&format!("--file {filename}")) {
            return Err(anyhow!(
                "Cannot have circular file inclusions. It appears that {filename} self includes itself."
            ));
        }

        let files_to_include = file_content
            .lines()
            .filter(|x| x.starts_with("--file"))
            .map(|x| x.to_string().replace("--file", "").replace(" ", ""))
            .collect::<Vec<_>>();
        if let Some(files) = included_files.get_mut(&current_file) {
            files.extend(files_to_include);
        } else {
            included_files.insert(current_file, files_to_include);
        }

        let edges = included_files.iter().flat_map(|(k, vs)| {
            let vs = vs.iter().map(|v| v.as_str());
            std::iter::repeat(k.as_str()).zip(vs)
        });

        // find if there is a circular file inclusion
        // we use toposort as it will return which file includes a file that was already included
        let graph: DiGraphMap<_, ()> = edges.collect();
        let sort = petgraph::algo::toposort(&graph, None);
        sort.map_err(|x| {
            anyhow!(
                "Cannot have circular file inclusions. It appears that the issue is in the {:?} file",
                x.node_id()
            )
        })?;

        // we also need to resolve $envs
        let lines = file_content
            .lines()
            .flat_map(|x| x.split_whitespace())
            .collect::<Vec<_>>();

        // in a file the first arg will not be the binary's name, so exclude it
        let input = PTB::command().no_binary_name(true);
        // .arg(Arg::new("--gas-budget").required(false));
        // TODO do not require --gas-budget to exist in files???
        // the issue is that we could pass a --gas-budget from the CLI and then a --file
        // and in the file there is no --gas-budget. For now, --gas-budget is always required
        // so we might want to figure out the best way to handle this case
        let args = input.get_matches_from(lines);
        let ptb_commands = self.from_matches(&args, Some(filename.to_string()), included_files)?;
        let len_cmds = ptb_commands.len();

        // add a pseudo command to tag where does the file include start and end
        // this helps with returning errors as we need to point in which file, this occurs
        output.insert(
            start_index,
            PTBCommand {
                name: format!("file-include-start"),
                values: vec![filename.to_string()],
            },
        );
        for (k, v) in ptb_commands.into_iter() {
            output.insert(start_index + k, v);
        }

        // end of file inclusion
        output.insert(
            start_index + len_cmds + 1,
            PTBCommand {
                name: format!("file-include-end"),
                values: vec![filename.to_string()],
            },
        );

        Ok(start_index + len_cmds + 1)
    }

    /// Parses and executes the PTB with the sender as the current active address
    pub async fn execute(self, matches: ArgMatches) -> Result<(), anyhow::Error> {
        let ptb_args_matches = matches
            .subcommand_matches("client")
            .ok_or_else(|| anyhow!("Expected the client command but got a different command"))?
            .subcommand_matches("ptb")
            .ok_or_else(|| anyhow!("Expected the ptb subcommand but got a different command"))?;
        let json = ptb_args_matches.get_flag("json");
        let commands = self.from_matches(ptb_args_matches, None, &mut BTreeMap::new())?;

        // If there are only 2 commands, they are likely the default
        // --preview and --warn-shadows set to false by clap,
        // so we can return early because there's no input
        if commands.len() == 2 {
            if let (Some(a), Some(b)) = (commands.get(&1), commands.get(&2)) {
                if a.name == "preview" && b.name == "warn_shadows" {
                    println!("No PTB to process. See the help menu for more information.");
                    return Ok(());
                }
            };
        }

        // Preview the PTB instead of executing if preview flag is set
        let preview = commands
            .values()
            .find(|x| {
                x.name == "preview" && x.values.iter().find(|x| x.as_str() == "true").is_some()
            })
            .is_some();
        if preview {
            let ptb_preview = PTBPreview {
                cmds: commands.clone().into_values().collect::<Vec<_>>(),
            };
            println!("{}", ptb_preview);
            return Ok(());
        }

        // Build the PTB
        let mut parsed = vec![];
        for command in &commands {
            let p = ParsedPTBCommand::parse(command.1)?;
            parsed.push(p);
        }

        // We need to resolve object IDs, so we need a fullnode to access
        let config_path = sui_config::sui_config_dir()?.join(sui_config::SUI_CLIENT_CONFIG);
        let context = WalletContext::new(&config_path, None, None).await?;

        let client = context.get_client().await?;
        let mut builder = PTBBuilder::new(client.read_api());

        for p in parsed.into_iter() {
            builder.handle_command(p).await?;
        }

        println!("Successfully parsed the PTB");
        let (ptb, budget, _preview) = builder.finish()?;

        // get all the metadata needed for executing the PTB: sender, gas, signing tx
        // get sender's address -- active address
        let Some(sender) = context.config.active_address else {
            anyhow::bail!("No active address, cannot execute PTB");
        };

        // TODO change this logic to actually use the given gas
        // find the gas coins if we have no gas coin given
        let coins = context
            .gas_for_owner_budget(sender, budget, BTreeSet::new())
            .await?;
        // get the gas price
        let gas_price = context
            .get_client()
            .await?
            .read_api()
            .get_reference_gas_price()
            .await?;
        // create the transaction data that will be sent to the network
        let tx_data = TransactionData::new_programmable(
            sender,
            vec![coins.1.object_ref()],
            ptb,
            budget,
            gas_price,
        );
        // sign the tx
        let signature =
            context
                .config
                .keystore
                .sign_secure(&sender, &tx_data, Intent::sui_transaction())?;

        // execute the transaction
        println!("Executing the transaction...");
        let transaction_response = context
            .get_client()
            .await?
            .quorum_driver_api()
            .execute_transaction_block(
                Transaction::from_data(tx_data, vec![signature]),
                SuiTransactionBlockResponseOptions::full_content(),
                Some(ExecuteTransactionRequestType::WaitForLocalExecution),
            )
            .await?;

        println!("Transaction executed");
        if json {
            let json_string =
                serde_json::to_string_pretty(&serde_json::json!(transaction_response))
                    .map_err(|_| anyhow!("Cannot serialize PTB result to json"))?;
            println!("{}", json_string);
        } else {
            println!("{}", transaction_response);
        }

        Ok(())
    }
}

fn insert_value<T>(
    arg_name: &Id,
    matches: &ArgMatches,
    order: &mut BTreeMap<usize, PTBCommand>,
) -> Result<(), anyhow::Error>
where
    T: Clone + Display + Send + Sync + 'static,
{
    let values: ValuesRef<'_, T> = matches
        .get_many(arg_name.as_str())
        .ok_or_else(|| anyhow!("Cannot parse the args for the PTB"))?;
    for (value, index) in values.zip(
        matches
            .indices_of(arg_name.as_str())
            .expect("id came from matches"),
    ) {
        order.insert(
            index,
            PTBCommand {
                name: arg_name.to_string(),
                values: vec![value.to_string()],
            },
        );
    }
    Ok(())
}

impl Display for PTBPreview {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut builder = TableBuilder::default();
        let columns = vec!["command", "from", "value(s)"];
        builder.set_header(columns);
        let mut from = "console";
        let num_cmds = &self.cmds.len();

        for cmd in &self.cmds[0..num_cmds - 2] {
            if cmd.name == "file-include-start" {
                from = cmd.values.get(0).unwrap();
                continue;
            } else if cmd.name == "file-include-end" {
                from = "console";
                continue;
            }
            builder.push_record([
                cmd.name.to_string(),
                from.to_string(),
                cmd.values.join(" ").to_string(),
            ]);
        }
        let mut table = builder.build();
        table.with(TablePanel::header(format!("PTB Preview")));
        table.with(TableStyle::rounded().horizontals([
            HorizontalLine::new(1, TableStyle::modern().get_horizontal()),
            HorizontalLine::new(2, TableStyle::modern().get_horizontal()),
            HorizontalLine::new(2, TableStyle::modern().get_horizontal()),
        ]));
        table.with(tabled::settings::style::BorderSpanCorrection);

        write!(f, "{}", table)
    }
}

impl Display for PTBGas {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let r = match self {
            PTBGas::MIN => "min",
            PTBGas::MAX => "max",
            PTBGas::SUM => "sum",
        };
        write!(f, "{}", r.to_string())
    }
}
