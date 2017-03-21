use std::mem;
use std::ptr;

use byteorder::{LittleEndian, WriteBytesExt};
use libsodium_sys::crypto_generichash_blake2b_init_salt_personal;
use libsodium_sys::crypto_generichash_blake2b_state;
use libsodium_sys::crypto_generichash_blake2b_update;
use libsodium_sys::crypto_generichash_blake2b_final;
use libsodium_sys::crypto_generichash_statebytes;
use rustc_serialize::hex::ToHex;


struct Node {
    hash: Vec<u8>,
    indices: Vec<u32>,
}


impl Node {
    fn new<'a>(a: &'a mut Node, b: &'a mut Node, trim: usize) -> Self {
        let mut hash = vec![0u8; a.hash.len() - trim];
        let mut indices = Vec::new();
        for i in trim..a.hash.len() {
            hash[i - trim] = a.hash[i] ^ b.hash[i];
        }
        if a.indices_before(b) {
            indices.append(a.indices.as_mut());
            indices.append(b.indices.as_mut());
        } else {
            indices.append(b.indices.as_mut());
            indices.append(a.indices.as_mut());
        }
        Node {
            hash: hash,
            indices: indices,
        }
    }

    fn indices_before(&self, other: &Node) -> bool {
        // Indices are serialized in big-endian so that integer
        // comparison is equivalent to array comparison
        self.indices[0] < other.indices[0]
    }

    fn is_zero(&self, len: usize) -> bool {
        for i in 0..len {
            if self.hash[i] != 0 {
                return false;
            }
        }
        return true;
    }
}

impl Clone for Node {
    fn clone(&self) -> Self {
        Node {
            hash: self.hash.clone(),
            indices: self.indices.clone(),
        }
    }
}

fn create_state() -> *mut crypto_generichash_blake2b_state {
    let mut st = vec![0u8; (unsafe { crypto_generichash_statebytes() })];
    unsafe { mem::transmute::<*mut u8, *mut crypto_generichash_blake2b_state>(st.as_mut_ptr()) }
}

fn initialise_state(n: u32, k: u32, state: *mut crypto_generichash_blake2b_state) -> i32 {
    let personalization: [u8; 16] = ['Z' as u8,
                                     'c' as u8,
                                     'a' as u8,
                                     's' as u8,
                                     'h' as u8,
                                     'P' as u8,
                                     'o' as u8,
                                     'W' as u8,
                                     (n & 255) as u8,
                                     ((n >> 8) & 255) as u8,
                                     ((n >> 16) & 255) as u8,
                                     ((n >> 24) & 255) as u8,
                                     (k & 255) as u8,
                                     ((k >> 8) & 255) as u8,
                                     ((k >> 16) & 255) as u8,
                                     ((k >> 24) & 255) as u8];
    info!("Per: {} ({})",
          personalization.to_hex(),
          personalization.len());
    unsafe {
        crypto_generichash_blake2b_init_salt_personal(state,
                                                      ptr::null(),
                                                      0,
                                                      ((512 / n) * n / 8) as usize,
                                                      ptr::null(),
                                                      &personalization)
    }
}

fn generate_hash(input: &[u8], nonce: &[u8], i: u32, hash: *mut u8, hash_len: usize) {
    let state = create_state();
    initialise_state(96, 5, state);
    let mut lei = vec![];
    lei.write_u32::<LittleEndian>(i).unwrap();
    unsafe {
        crypto_generichash_blake2b_update(state, input.as_ptr(), input.len() as u64);
        crypto_generichash_blake2b_update(state, nonce.as_ptr(), nonce.len() as u64);
        crypto_generichash_blake2b_update(state, lei.as_ptr(), lei.len() as u64);
        crypto_generichash_blake2b_final(state, hash, hash_len);
    }
}

fn has_collision(a: &Node, b: &Node, len: usize) -> bool {
    for i in 0..len {
        if a.hash[i] != b.hash[i] {
            return false;
        }
    }
    return true;
}

fn distinct_indices(a: &Node, b: &Node) -> bool {
    for i in &(a.indices) {
        for j in &(b.indices) {
            if i == j {
                return false;
            }
        }
    }
    return true;
}

fn is_valid_solution_iterative(n: u32,
                               k: u32,
                               input: &[u8],
                               nonce: &[u8],
                               indices: &[u32])
                               -> bool {
    let IndicesPerHashOutput = 512 / n;
    let HashOutput = (IndicesPerHashOutput * n / 8) as usize;
    let CollisionBitLength = (n / (k + 1)) as usize;
    let CollisionByteLength = (CollisionBitLength + 7) / 8;
    let hash_length = ((k as usize) + 1) * CollisionByteLength;

    let mut X = Vec::new();
    for i in indices {
        let mut hash: Vec<u8> = vec![0; HashOutput];
        generate_hash(input,
                      nonce,
                      i / IndicesPerHashOutput,
                      hash.as_mut_ptr(),
                      HashOutput);
        info!("{}", hash.to_hex());
        let start = ((i % IndicesPerHashOutput) * n / 8) as usize;
        let end = start + (n as usize) / 8;
        X.push(Node {
                   hash: hash[start..end].to_vec(),
                   indices: vec![*i],
               });
    }

    let mut hash_len = hash_length;
    while X.len() > 1 {
        let mut Xc = Vec::new();
        for pair in X.chunks(2) {
            let mut a = pair[0].clone();
            let mut b = pair[1].clone();
            if !has_collision(&a, &b, CollisionByteLength) {
                error!("Invalid solution: invalid collision length between StepRows");
                return false;
            }
            if b.indices_before(&a) {
                error!("Invalid solution: Index tree incorrectly ordered");
                return false;
            }
            if !distinct_indices(&a, &b) {
                error!("Invalid solution: duplicate indices");
                return false;
            }
            Xc.push(Node::new(&mut a, &mut b, CollisionByteLength));
        }
        X = Xc;
        hash_len -= CollisionByteLength;
    }

    assert!(X.len() == 1);
    return X[0].is_zero(hash_len);
}

pub fn is_valid_solution(n: u32, k: u32, input: &[u8], nonce: &[u8], indices: &[u32]) -> bool {
    is_valid_solution_iterative(n, k, input, nonce, indices)
}


#[cfg(test)]
mod tests {
    use env_logger;

    use super::is_valid_solution;

    #[test]
    fn equihash_test_cases() {
        env_logger::init().unwrap();

        let input = b"block header";
        let mut nonce = [0 as u8; 32];
        let mut indices = vec![976, 126621, 100174, 123328, 38477, 105390, 38834, 90500, 6411,
                               116489, 51107, 129167, 25557, 92292, 38525, 56514, 1110, 98024,
                               15426, 74455, 3185, 84007, 24328, 36473, 17427, 129451, 27556,
                               119967, 31704, 62448, 110460, 117894];
        assert!(is_valid_solution(96, 5, input, &nonce, &indices));

        indices = vec![1008, 18280, 34711, 57439, 3903, 104059, 81195, 95931, 58336, 118687,
                       67931, 123026, 64235, 95595, 84355, 122946, 8131, 88988, 45130, 58986,
                       59899, 78278, 94769, 118158, 25569, 106598, 44224, 96285, 54009, 67246,
                       85039, 127667];
        assert!(is_valid_solution(96, 5, input, &nonce, &indices));

        nonce[0] = 1;
        assert!(!is_valid_solution(96, 5, input, &nonce, &indices));

        indices = vec![1911, 96020, 94086, 96830, 7895, 51522, 56142, 62444, 15441, 100732, 48983,
                       64776, 27781, 85932, 101138, 114362, 4497, 14199, 36249, 41817, 23995,
                       93888, 35798, 96337, 5530, 82377, 66438, 85247, 39332, 78978, 83015, 123505];
        assert!(is_valid_solution(96, 5, input, &nonce, &indices));

        let input2 = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";
        indices = vec![2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878,
                       76925, 80080, 45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330,
                       68190, 122819, 81830, 91132, 23460, 49807, 52426, 80391, 69567, 114474,
                       104973, 122568];
        assert!(is_valid_solution(96, 5, input2, &nonce, &indices));
    }
}
