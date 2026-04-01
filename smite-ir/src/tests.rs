//! Tests for IR types.

use rand::SeedableRng;
use rand::rngs::SmallRng;

use super::*;
use generators::OpenChannelGenerator;
use operation::AcceptChannelField;

/// Helper to build a private key with a single distinguishing byte.
fn key(byte: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = byte;
    k
}

fn sample_context() -> ProgramContext {
    ProgramContext {
        target_pubkey: [0x02; 33],
        chain_hash: [0; 32],
        block_height: 800_000,
        target_features: vec![],
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn display_open_channel_program() {
    let instructions = vec![
        // 6 key pairs.
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(2)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![2],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(3)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![4],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(4)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![6],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(5)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![8],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(6)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![10],
        },
        // Channel parameters.
        Instruction {
            operation: Operation::LoadChannelId([0; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(100_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(0),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(546),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(10_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(2500),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(144),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(483),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(vec![]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![]),
            inputs: vec![],
        },
        // Build and send open_channel.
        Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: vec![
                13, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 1, 3, 5, 7, 9, 11, 23, 24, 25,
            ],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![26],
        },
        // Receive accept_channel and extract fields.
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
            inputs: vec![28],
        },
        Instruction {
            operation: Operation::ExtractAcceptChannel(AcceptChannelField::FirstPerCommitmentPoint),
            inputs: vec![28],
        },
    ];

    let program = Program {
        instructions,
        context: sample_context(),
    };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);
    let z32 = "00".repeat(32);

    #[rustfmt::skip]
    let expected: Vec<String> = vec![
        format!("v0 = LoadPrivateKey(0x{z31}01)"),
        "v1 = DerivePoint(v0)".into(),
        format!("v2 = LoadPrivateKey(0x{z31}02)"),
        "v3 = DerivePoint(v2)".into(),
        format!("v4 = LoadPrivateKey(0x{z31}03)"),
        "v5 = DerivePoint(v4)".into(),
        format!("v6 = LoadPrivateKey(0x{z31}04)"),
        "v7 = DerivePoint(v6)".into(),
        format!("v8 = LoadPrivateKey(0x{z31}05)"),
        "v9 = DerivePoint(v8)".into(),
        format!("v10 = LoadPrivateKey(0x{z31}06)"),
        "v11 = DerivePoint(v10)".into(),
        format!("v12 = LoadChannelId(0x{z32})"),
        "v13 = LoadChainHashFromContext()".into(),
        "v14 = LoadAmount(100000)".into(),
        "v15 = LoadAmount(0)".into(),
        "v16 = LoadAmount(546)".into(),
        "v17 = LoadAmount(10000000)".into(),
        "v18 = LoadAmount(1000)".into(),
        "v19 = LoadAmount(1)".into(),
        "v20 = LoadFeeratePerKw(2500)".into(),
        "v21 = LoadU16(144)".into(),
        "v22 = LoadU16(483)".into(),
        "v23 = LoadU8(1)".into(),
        "v24 = LoadBytes()".into(),
        "v25 = LoadFeatures()".into(),
        "v26 = BuildOpenChannel(v13, v12, v14, v15, v16, v17, v18, v19, v20, v21, v22, v1, v3, v5, v7, v9, v11, v23, v24, v25)".into(),
        "SendMessage(v26)".into(),
        "v28 = RecvAcceptChannel()".into(),
        "v29 = ExtractFundingPubkey(v28)".into(),
        "v30 = ExtractFirstPerCommitmentPoint(v28)".into(),
    ];

    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn postcard_roundtrip() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChannelId([0xab; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(50_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(vec![0x01, 0x02]),
                inputs: vec![],
            },
        ],
        context: sample_context(),
    };

    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

// Ensure AcceptChannelField and AcceptChannelField::ALL stay in sync. The
// exhaustive match in this test will fail to compile if a variant is added
// without updating it, and the assertion will fail if the match is updated
// without updating AcceptChannelField::ALL.
#[test]
fn accept_channel_field_all_is_complete() {
    let variant_count = |f: AcceptChannelField| -> usize {
        match f {
            AcceptChannelField::TemporaryChannelId
            | AcceptChannelField::DustLimitSatoshis
            | AcceptChannelField::MaxHtlcValueInFlightMsat
            | AcceptChannelField::ChannelReserveSatoshis
            | AcceptChannelField::HtlcMinimumMsat
            | AcceptChannelField::MinimumDepth
            | AcceptChannelField::ToSelfDelay
            | AcceptChannelField::MaxAcceptedHtlcs
            | AcceptChannelField::FundingPubkey
            | AcceptChannelField::RevocationBasepoint
            | AcceptChannelField::PaymentBasepoint
            | AcceptChannelField::DelayedPaymentBasepoint
            | AcceptChannelField::HtlcBasepoint
            | AcceptChannelField::FirstPerCommitmentPoint
            | AcceptChannelField::UpfrontShutdownScript
            | AcceptChannelField::ChannelType => 16,
        }
    };
    assert_eq!(
        AcceptChannelField::ALL.len(),
        variant_count(AcceptChannelField::ALL[0]),
    );
}

fn generate_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    builder.build(sample_context())
}

// If OpenChannelGenerator completes without panicking, every instruction has
// correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_program_is_type_correct() {
    for seed in 0..100 {
        generate_program(seed);
    }
}

#[test]
fn generated_program_structure() {
    let program = generate_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    // Must end with SendMessage, RecvAcceptChannel.
    assert!(
        matches!(ops[ops.len() - 2], Operation::SendMessage),
        "second-to-last instruction should be SendMessage",
    );
    assert!(
        matches!(ops[ops.len() - 1], Operation::RecvAcceptChannel),
        "last instruction should be RecvAcceptChannel",
    );

    // At least one BuildOpenChannel.
    assert!(
        ops.iter()
            .any(|op| matches!(op, Operation::BuildOpenChannel)),
        "expected at least one BuildOpenChannel",
    );

    // At least 6 DerivePoint instructions (fresh basepoints).
    let derive_count = program
        .instructions
        .iter()
        .filter(|i| matches!(i.operation, Operation::DerivePoint))
        .count();
    assert!(
        derive_count >= 6,
        "expected at least 6 DerivePoint, got {derive_count}"
    );
}

#[test]
fn generated_program_postcard_roundtrip() {
    let program = generate_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generate_fresh_produces_distinct_indices() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    let a = builder.generate_fresh(VariableType::Amount, &mut rng);
    let b = builder.generate_fresh(VariableType::Amount, &mut rng);
    assert_ne!(a, b);
}

#[test]
fn pick_variable_reuses_existing() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();

    // Generate one Amount variable.
    let first = builder.generate_fresh(VariableType::Amount, &mut rng);

    // pick_variable should mostly reuse the existing variable. Over 100 calls,
    // at least some should return the original index.
    let mut reuse_count = 0;
    for _ in 0..100 {
        let idx = builder.pick_variable(VariableType::Amount, &mut rng);
        if idx == first {
            reuse_count += 1;
        }
    }
    assert!(
        reuse_count > 0,
        "pick_variable never reused existing variable"
    );
}

#[test]
#[should_panic(expected = "cannot generate fresh Message")]
fn generate_fresh_message_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::Message, &mut rng);
}

#[test]
#[should_panic(expected = "cannot generate fresh AcceptChannel")]
fn generate_fresh_accept_channel_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::AcceptChannel, &mut rng);
}

#[test]
#[should_panic(expected = "expected 1 inputs, got 0")]
fn append_wrong_input_count_panics() {
    let mut builder = ProgramBuilder::new();
    builder.append(Operation::DerivePoint, &[]);
}

#[test]
#[should_panic(expected = "index 99 out of bounds")]
fn append_out_of_bounds_panics() {
    let mut builder = ProgramBuilder::new();
    builder.append(Operation::DerivePoint, &[99]);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn append_void_reference_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    let program = builder.build(sample_context());
    // SendMessage is second-to-last and has void output.
    let send_idx = program.instructions.len() - 2;
    assert!(
        program.instructions[send_idx]
            .operation
            .output_type()
            .is_none(),
        "expected void operation",
    );
    // Rebuild the same program and try to reference the void instruction.
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    builder.append(Operation::SendMessage, &[send_idx]);
}

#[test]
#[should_panic(expected = "expected PrivateKey, got Amount")]
fn append_type_mismatch_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    let amount = builder.generate_fresh(VariableType::Amount, &mut rng);
    builder.append(Operation::DerivePoint, &[amount]);
}
