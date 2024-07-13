Setup:
rustup component add rustc-codegen-cranelift-preview --toolchain nightly

In sample dir:
cargo clean; cargo rustc --release --lib --target x86_64-unknown-none -- --emit=llvm-ir

Make sure the clif file is generated:
"sample/target/release/deps/sample-31833ae91801d5f5.clif/_ZN6sample3fib17h2cd71bde5d788a96E.opt.clif"

Comment set probestack_func_adjusts_sp=0 line in resulting clif file

cargo run
