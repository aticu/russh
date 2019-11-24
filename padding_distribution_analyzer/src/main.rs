use rand::{distributions::Distribution, thread_rng, RngCore};
use rand_distr::Gamma;

const COLUMNS: usize = 5;
const TRIALS: u32 = 1_000_000;
const PERCENTILES: [u32; 6] = [25, 50, 75, 90, 95, 99];

const MIN_PACKET_LEN_ALIGN: usize = 8;
const MAX_EXTRA_PADDING_BLOCKS: usize = 0xff / MIN_PACKET_LEN_ALIGN;

type Distr = Box<dyn FnMut(&mut dyn RngCore) -> u8>;

fn analyze_distr(mut distr: Distr) -> [u32; MAX_EXTRA_PADDING_BLOCKS + 1] {
    let mut rng = thread_rng();

    let mut results = [0u32; MAX_EXTRA_PADDING_BLOCKS + 1];

    for _ in 0..TRIALS {
        results[distr(&mut rng) as usize] += 1;
    }

    results
}

fn print_table_grid() {
    print!("+");
    for _ in 0..COLUMNS {
        print!("-----+---------+");
    }
    println!();
}

fn print_table_header() {
    print!("|");
    for _ in 0..COLUMNS {
        print!(" blk |  chance |");
    }
    println!();
}

fn print_results_for(name: &str, results: [u32; MAX_EXTRA_PADDING_BLOCKS + 1]) {
    println!("# Overview for padding length distribution `{}`:", name);
    println!();
    println!("Measured in {} trials.", TRIALS);
    println!();
    print_table_grid();
    print_table_header();
    print_table_grid();

    let num_lines = results.len() / COLUMNS + (results.len() % COLUMNS == 0) as usize;
    for i in 0..(num_lines + 1) * COLUMNS {
        let idx = i / COLUMNS + (i % COLUMNS) * (num_lines + 1);

        if i % COLUMNS == 0 {
            print!("|");
        }

        if idx < results.len() {
            print!(
                "  {:>2} | {:>6.2}% |",
                idx,
                results[idx] as f64 / TRIALS as f64 * 100f64
            );
        } else {
            print!("     |         |");
        }

        if i % COLUMNS == COLUMNS - 1 {
            println!();
        }
    }

    print_table_grid();
    println!();

    for percentile in PERCENTILES.iter() {
        print_percentile(results, *percentile);
    }
}

fn print_percentile(results: [u32; MAX_EXTRA_PADDING_BLOCKS + 1], percent: u32) {
    let num_blocks =
        (0..results.len()).find(|i| results[..*i].iter().sum::<u32>() > TRIALS / 100 * percent);
    println!(
        ">={:2}% chance to have at most {} additional blocks.",
        percent,
        num_blocks.unwrap()
    );
}

fn default_padding_length_distribution() -> Distr {
    let gamma = Gamma::new(0.5, 3.0).unwrap();

    Box::new(move |rng| {
        let mut float = gamma.sample(rng);
        while float > MAX_EXTRA_PADDING_BLOCKS as f64 {
            float = gamma.sample(rng);
        }

        float.max(0x00 as f64).min(0xff as f64).round() as u8
    })
}

fn zero_padding_length_distribution() -> Distr {
    Box::new(|_| 0)
}

fn main() {
    print_results_for(
        "default_padding_length_distribution",
        analyze_distr(default_padding_length_distribution()),
    );
    println!();
    println!();
    print_results_for(
        "zero_padding_length_distribution",
        analyze_distr(zero_padding_length_distribution()),
    );
}
