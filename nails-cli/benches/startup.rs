use clap::Parser;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use nails::cli::Cli;

/// Benchmark CLI argument parsing via `Cli::try_parse_from`.
///
/// Note: this measures clap argument parsing only, NOT actual binary startup
/// time (process spawn, dynamic linking, runtime initialisation, etc.).
fn benchmark_cli_parse(c: &mut Criterion) {
    c.bench_function("cli_parse_time", |b| {
        b.iter(|| {
            let cli = Cli::try_parse_from(black_box(["nails", "status"])).unwrap();
            black_box(cli);
        });
    });
}

criterion_group!(benches, benchmark_cli_parse);
criterion_main!(benches);
