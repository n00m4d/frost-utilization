# FROST Library CLI Example

This CLI demonstrates how threshold multisig can be implemented using the frost_dalek crate.

It includes two commands: create-multisig and sign.

> [!WARNING]  
> This code is for educational purposes only. Multisig wallets should not be created as demonstrated here for production use.

## Create multisig

This command generates new keys for a threshold multisig setup. All private keys are stored on disk in a readable format.

Command example:

```
cargo r -- create-multisig --n 5 --t 3 --group-name group_a
```

This will create a directory keys/group_a containing:

- Five files with individual keys.
- One file with multisig parameters, including the number of participants (n), the threshold (t), and the group public key.

You can also create another multisig setup with different rules. For example, to create a new multisig named group_b:

```
cargo run -- create-multisig --n 10 --t 6 --group-name group_b
```

Each setup is saved in its respective directory under keys/.

## Sign

This command signs a message using the specified participants' keys. You must provide:

- The group name.
- The indices of participants (signers).
- The path to the message file.

After signing:

- The signature is automatically verified.
- If verification fails, the CLI will display an error message.
- If successful, the CLI will output the signature hash.

Command example:

```
cargo r -- sign --group-name group_a --signers 1,2,3,4,5 --message-file ./test_message
```

Successful output example:

```
Compiling frost-utilization v0.1.0 (/frost-utilisation)
Finished dev [unoptimized + debuginfo] target(s) in 2.02s
Running `target/debug/frost-utilization sign --group-name group_a --signers 1,2,3,4,5 --message-file ./test_message`

Signature is verified: "3SmEtZchhypk8h5Wk8CWDf4CAnsLZhkEe9SoHmBVUFD3rqw2tpv9KmFHPJ94zG86zc53VhtiCbjLWZ3LiXYrLVMo"
```

Signature failed output example:

```
Finished dev [unoptimized + debuginfo] target(s) in 0.05s
Running `target/debug/frost-utilization sign --group-name group_a --signers 1,2 --message-file ./test_message`

Signature was NOT verified. Meaning there may be not enough signers or wrong keys signed the message
```