use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{thread_rng, Rng, RngCore};

use reck::Deck;

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
type Benchmarker = Criterion;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
type Benchmarker = Criterion<criterion_cycles_per_byte::CyclesPerByte>;

fn bench(c: &mut Benchmarker) {
    let mut group = c.benchmark_group("DeckTink");
    let mut rng = thread_rng();
    let key = rng.gen::<[u8; 32]>();
    let nonce = rng.gen::<[u8; 32]>();

    for e in (10..=22).step_by(4) {
        let size = 1 << e;
        let mut buf = vec![0u8; size];
        rng.fill_bytes(&mut buf);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("wrap", size), |b| {
            let mut deck = Deck::new(&key, &nonce);
            b.iter(|| deck.wrap(black_box(&mut buf)))
        });
        group.bench_function(BenchmarkId::new("unwrap", size), |b| {
            let mut deck = Deck::new(&key, &nonce);
            b.iter(|| deck.unwrap(black_box(&mut buf)))
        });
    }

    group.finish();
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench
);

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(criterion_cycles_per_byte::CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
