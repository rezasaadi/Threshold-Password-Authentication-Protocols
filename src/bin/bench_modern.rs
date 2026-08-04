fn main() -> std::io::Result<()> {
    pastau_bench::benchmark::run(std::env::args().collect())
}
