use itertools::Itertools;
use num_traits::Zero;
use rand::{thread_rng, RngCore};

use phantom_zone::*;
use std::time::Instant;
use std::any::type_name;

fn print_type_of<T>(_: &T) {
    println!("{}", type_name::<T>());
}

fn main() {
    set_parameter_set(ParameterSelector::NonInteractiveLTE2Party);

    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    set_common_reference_seed(seed);

    let parties = 2;

    let cks = (0..parties).map(|_| gen_client_key()).collect_vec();

    let s_key_shares = cks
        .iter()
        .enumerate()
        .map(|(user_id, k)| gen_server_key_share(user_id, parties, k))
        .collect_vec();

    let server_key = aggregate_server_key_shares(&s_key_shares);
    server_key.set_server_key();

    let n_size = 14;

    // Define n_size boolean values for each party
    let m0: Vec<bool> = (0..n_size).map(|_| rand::random()).collect();
    let m1: Vec<bool> = (0..n_size).map(|_| rand::random()).collect();

    // Convert boolean vectors to binary string representations
    let m0_str: String = m0.iter().map(|&b| if b { '1' } else { '0' }).collect();
    let m1_str: String = m1.iter().map(|&b| if b { '1' } else { '0' }).collect();

    println!("m0: {}", m0_str);
    println!("m1: {}", m1_str);

    // Start timing from here
    let start = Instant::now();

    // Encrypt boolean values using the first client's key
    let c0 = cks[0].encrypt(m0.as_slice());

    // End timing here
    let duration = start.elapsed();
    println!("Encryption Time: {:?}", duration);

    let c1 = cks[1].encrypt(m1.as_slice());

    let zeros = vec![false; 2];
    let enc_zeros = cks[0].encrypt(zeros.as_slice());

    // Start timing from here
    let start = Instant::now();

    // Extract encrypted values
    let enc_m0 = c0.unseed::<Vec<Vec<u64>>>().key_switch(0).extract_all();
    let enc_m1 = c1.unseed::<Vec<Vec<u64>>>().key_switch(1).extract_all();

    
    // Perform XOR operation on encrypted values
    let enc_out: Vec<_> = enc_m0.iter().zip(enc_m1.iter()).map(|(a, b)| a ^ b).collect();

    print_type_of(&enc_out);
    print_type_of(&enc_out[1]);

    // End timing here
    let duration = start.elapsed();
    println!("FHE XOR Time: {:?}", duration);


    // Decrypt the result
    let dec_shares: Vec<_> = enc_out
        .iter()
        .map(|enc_bit| cks.iter().map(|k| k.gen_decryption_share(enc_bit)).collect_vec())
        .collect();

    let out_back: Vec<_> = enc_out
        .iter()
        .zip(dec_shares.iter())
        .map(|(enc_bit, shares)| cks[0].aggregate_decryption_shares(enc_bit, shares))
        .collect();

    // Verify the result
    let expected_out: Vec<_> = m0.iter().zip(m1.iter()).map(|(a, b)| a ^ b).collect();

    // Convert decrypted result to binary string representation
    let out_back_str: String = out_back.iter().map(|&b| if b { '1' } else { '0' }).collect();
    let expected_out_str: String = expected_out.iter().map(|&b| if b { '1' } else { '0' }).collect();

    println!("Expected XOR result: {}", expected_out_str);
    println!("Decrypted XOR result: {}", out_back_str);

    // println!("Expected XOR result: {:?}", expected_out);
    // println!("Decrypted XOR result: {:?}", out_back);

    assert_eq!(expected_out, out_back);

    // Count the number of 1s in enc_out

    let enc_zeros_0 = enc_zeros.unseed::<Vec<Vec<u64>>>().key_switch(0).extract_all();
    
    // Start timing from here
    let start = Instant::now();

    let enc_count = count_ones(&enc_out, &enc_zeros_0);

    // End timing here
    let duration = start.elapsed();
    println!("Time for counting 1s in FHE: {:?}", duration);


    let dec_shares_count: Vec<_> = enc_count
        .iter()
        .map(|enc_bit| cks.iter().map(|k| k.gen_decryption_share(enc_bit)).collect_vec())
        .collect();

    let count_back: Vec<_> = enc_count
        .iter()
        .zip(dec_shares_count.iter())
        .map(|(enc_bit, shares)| cks[0].aggregate_decryption_shares(enc_bit, shares))
        .collect();

        let count_back_str: String = count_back.iter().rev().map(|&b| if b { '1' } else { '0' }).collect();
        let difff = isize::from_str_radix(count_back_str.as_str(), 2).unwrap();


    println!("Number of 1s in encrypted vector: {:?}", difff);

}


fn half_adder(a: &FheBool, b: &FheBool) -> (FheBool, FheBool) {
    let sum = a ^ b;
    let carry = a & b;
    (sum, carry)

    // vec![a ^ b, a & b]
}

fn full_adder(a: &FheBool, b: &FheBool, carry_in: &FheBool) -> (FheBool, FheBool) {
    let (sum1, carry1) = half_adder(a, b);
    let (sum2, carry2) = half_adder(&sum1, carry_in);
    let carry_out = &carry1 | &carry2;
    (sum2, carry_out)
}

fn count_ones_seven_bits(enc_out: &[FheBool]) -> Vec<FheBool> {
    
    let (s1, c1) = full_adder(&enc_out[6], &enc_out[5], &enc_out[4]); 
    let (s2, c2) = full_adder(&enc_out[3], &enc_out[2], &enc_out[1]); 
    let (s3, c3) = full_adder(&s1, &s2, &enc_out[0]); 
    let (s4, c4) = full_adder(&c1, &c2, &c3);

    vec![s3,s4,c4] 
}


fn full_adder_three_bits(a: &[FheBool], b: &[FheBool], carry_in: &FheBool) -> Vec<FheBool> {
    
    let (s1, c1) = full_adder(&a[0], &b[0], carry_in); 
    let (s2, c2) = full_adder(&a[1], &b[1], &c1); 
    let (s3, c3) = full_adder(&a[2], &b[2], &c2); 
    
    vec![s1,s2,s3,c3] 
}

fn count_ones(enc_out: &[FheBool], zeros: &[FheBool]) -> Vec<FheBool> {
    
    let first_bits: Vec<FheBool> = count_ones_seven_bits(&(enc_out.to_vec())[0..7]);
    let second_bits: Vec<FheBool> = count_ones_seven_bits(&(enc_out.to_vec())[7..14]);
    full_adder_three_bits(&first_bits[0..3], &second_bits[0..3], &zeros[0].clone())
    // let mut sum: Vec<FheBool> = vec![zeros[0].clone(); enc_out.len() + 1];
    // sum[0] = zeros[0].clone();

    // let mut carry = zeros[1].clone();

    // let mut index = 0;
    // for bit in enc_out {
    //     let (new_sum, new_carry) = full_adder(bit, &sum[index], &carry);
    //     carry = new_carry;
    //     index += 1;
    //     sum[index] = new_sum;

    // }

    // sum

    // // vec![half_adder(&enc_out[0], &enc_out[1]).0, half_adder(&enc_out[0], &enc_out[1]).1]

    // // half_adder(&enc_out[0], &enc_out[1])

    // vec![
    //         &enc_out[0] ^ &enc_out[1], 
    //         &enc_out[0] ^ &enc_out[2], 
    //         &enc_out[0] ^ &enc_out[3], 
    //         &enc_out[0] ^ &enc_out[4], 
    //         &enc_out[0] ^ &enc_out[5], 
    //         &enc_out[0] ^ &enc_out[6], 
    //         &enc_out[0] ^ &enc_out[7], 
    //         &enc_out[0] & &enc_out[1], 
    //         &enc_out[0] & &enc_out[2], 
    //         &enc_out[0] & &enc_out[3], 
    //         &enc_out[0] & &enc_out[4], 
    //         &enc_out[0] & &enc_out[5], 
    //         &enc_out[0] & &enc_out[6], 
    //         &enc_out[0] & &enc_out[7], 
    //         &enc_out[0] & &enc_out[8]
    //     ]


}
