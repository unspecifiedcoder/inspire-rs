//! Cost Attribution Estimator - Comparative Table
//!
//! Prints per-component operation counts for all InsPIRe variants
//! across d=2048 and d=4096 parameter sets.
//!
//! Run with: cargo run --example cost_attribution

use inspire::cost::CostEstimator;
use inspire::params::{InspireParams, InspireVariant};

fn main() {
    let entry_size = 32; // Ethereum state entry (32 bytes)
    let variants = [
        ("NoPacking  (^0)", InspireVariant::NoPacking),
        ("OnePacking (^1)", InspireVariant::OnePacking),
        ("TwoPacking (^2)", InspireVariant::TwoPacking),
    ];

    for (dim_label, params) in [
        ("d=2048", InspireParams::secure_128_d2048()),
        ("d=4096", InspireParams::secure_128_d4096()),
    ] {
        println!();
        println!(
            "================================================================================"
        );
        println!(
            "  InsPIRe Cost Attribution  |  {dim_label}  |  entry={entry_size}B  |  l={}",
            params.gadget_len
        );
        println!(
            "================================================================================"
        );

        // Collect breakdowns
        let breakdowns: Vec<_> = variants
            .iter()
            .map(|(_, v)| CostEstimator::new(&params, *v, entry_size).estimate())
            .collect();

        // Header
        let header = variants
            .iter()
            .map(|(name, _)| format!(" {:>16}", name))
            .collect::<String>();
        println!("\n{:<30}{}", "Metric", header);
        let divider = variants
            .iter()
            .map(|_| format!(" {:-<16}", ""))
            .collect::<String>();
        println!("{:-<30}{}", "", divider);

        // Respond phase
        println!("RESPOND PHASE (server)");
        print_row("  External products", &breakdowns, |b| {
            b.respond.external_products
        });
        print_row("  Gadget decompositions", &breakdowns, |b| {
            b.respond.gadget_decompositions
        });
        print_row("  Poly multiplications", &breakdowns, |b| {
            b.respond.poly_multiplications
        });
        print_row("  NTT transforms", &breakdowns, |b| {
            b.respond.ntt_transforms
        });
        print_row("  Poly additions", &breakdowns, |b| {
            b.respond.poly_additions
        });

        // Packing phase
        println!("PACKING (respond sub-phase)");
        print_row("  Key-switches", &breakdowns, |b| b.packing.key_switches);
        print_row("  Automorphisms", &breakdowns, |b| b.packing.automorphisms);
        print_row("  Gadget decompositions", &breakdowns, |b| {
            b.packing.gadget_decompositions
        });
        print_row("  Poly multiplications", &breakdowns, |b| {
            b.packing.poly_multiplications
        });
        print_row("  NTT transforms", &breakdowns, |b| {
            b.packing.ntt_transforms
        });
        print_row("  Poly additions", &breakdowns, |b| {
            b.packing.poly_additions
        });

        // Query phase
        println!("QUERY (client)");
        print_row("  Poly multiplications", &breakdowns, |b| {
            b.query.poly_multiplications
        });
        print_row("  NTT transforms", &breakdowns, |b| b.query.ntt_transforms);

        // Extract phase
        println!("EXTRACT (client)");
        print_row("  Poly multiplications", &breakdowns, |b| {
            b.extract.poly_multiplications
        });
        print_row("  NTT transforms", &breakdowns, |b| {
            b.extract.ntt_transforms
        });

        // Communication
        println!("COMMUNICATION");
        print_row_kb("  Total bytes", &breakdowns, |b| {
            b.total_communication_bytes()
        });

        // Totals
        println!("TOTALS (computation)");
        print_row("  NTT transforms", &breakdowns, |b| {
            b.total().ntt_transforms
        });
        print_row("  Poly multiplications", &breakdowns, |b| {
            b.total().poly_multiplications
        });
        print_row("  External products", &breakdowns, |b| {
            b.total().external_products
        });
        print_row("  Key-switches", &breakdowns, |b| b.total().key_switches);
        print_row("  Automorphisms", &breakdowns, |b| b.total().automorphisms);

        println!();
    }
}

fn print_row<F>(label: &str, breakdowns: &[inspire::cost::CostBreakdown], f: F)
where
    F: Fn(&inspire::cost::CostBreakdown) -> u64,
{
    let vals: Vec<u64> = breakdowns.iter().map(&f).collect();
    // Skip rows where all values are zero
    if vals.iter().all(|v| *v == 0) {
        return;
    }
    let cols = vals
        .iter()
        .map(|v| format!(" {:>16}", v))
        .collect::<String>();
    println!("{:<30}{}", label, cols);
}

fn print_row_kb<F>(label: &str, breakdowns: &[inspire::cost::CostBreakdown], f: F)
where
    F: Fn(&inspire::cost::CostBreakdown) -> u64,
{
    let vals: Vec<u64> = breakdowns.iter().map(&f).collect();
    // Skip rows where all values are zero
    if vals.iter().all(|v| *v == 0) {
        return;
    }
    let cols = vals
        .iter()
        .map(|v| format!(" {:>11.1} KB", *v as f64 / 1024.0))
        .collect::<String>();
    println!("{:<30}{}", label, cols);
}
