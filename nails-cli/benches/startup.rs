use clap::Parser;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use nails::cli::Cli;

fn benchmark_binary_startup(c: &mut Criterion) {
    c.bench_function("binary_startup", |b| {
        b.iter(|| {
            let cli = Cli::try_parse_from(black_box(["nails", "status"])).unwrap();
            black_box(cli);
        });
    });
}

criterion_group!(benches, benchmark_binary_startup);
criterion_main!(benches);
