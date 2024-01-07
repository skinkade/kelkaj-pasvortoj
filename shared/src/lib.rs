pub mod primitives;
pub mod derivation;
pub mod crypto;
pub mod flows;
pub mod rpc;

pub use rsa;
// pub use pkcs1;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
