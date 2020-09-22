use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn hello_world_digest_bench(c: &mut Criterion) {
	let data = b"Hello, world!";

    c.bench_function("self::Sha1 digest \"Hello, world!\"", |b| {
        b.iter(|| sha1::Sha1::digest(black_box(data)));
    });

    c.bench_function("mitsuhiko Sha1 digest \"Hello world!\"", |b| {
    	b.iter(|| mitsuhiko::Sha1::from(black_box(data)).digest())
    });

    c.bench_function("RustCrypto Sha1 digest \"Hello, world!\"", |b| {
    	use rustcrypto::Digest;
    	b.iter(|| rustcrypto::Sha1::digest(black_box(data)));
    });
}

criterion_group!(benches, hello_world_digest_bench);
criterion_main!(benches);
