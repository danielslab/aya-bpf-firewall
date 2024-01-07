all:
	mkdir -p build
	cargo xtask build-ebpf
	cargo xtask build-ebpf --release
	cargo build
	cargo build --release
	cp target/bpfel-unknown-none/release/aya-bpf-firewall build/ebpf_program
	cp target/release/aya-bpf-firewall build/aya-bpf-firewall
	RUST_LOG=info cargo xtask run -- --iface enx747827b4a955