use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub struct DHP {
    g: BigUint,
    p: BigUint,
}

impl DHP {
    pub fn secret_key(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let ab = Self::multiplication(&a, &b);
        self.g.modpow(&ab, &self.p)
    }

    pub fn multiplication(a: &BigUint, b: &BigUint) -> BigUint {
        a * b
    }
    pub fn compute_pair(&self, a: &BigUint, b: &BigUint) -> (BigUint, BigUint) {
        let r1 = self.g.modpow(&a, &self.p);
        let r2 = self.g.modpow(&b, &self.p);

        (r1, r2)
    }

    pub fn generate_random_number_below(bound: &BigUint) -> BigUint {
        let mut rng = thread_rng();

        rng.gen_biguint_below(bound)
    }

    /// condition1 = sk == r2^x
    /// condition2 = sk == r1^y
    pub fn verify(
        &self,
        a: &BigUint,
        b: &BigUint,
        r1: &BigUint,
        r2: &BigUint,
        sk: &BigUint,
    ) -> bool {
        let condition1 = *sk == r2.modpow(&a, &self.p);

        let condition2 = *sk == r1.modpow(&b, &self.p);

        condition1 && condition2
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test1() {
        let g = BigUint::from(2u32);
        let p = BigUint::from(10u32);

        let dhp = DHP { g, p };

        let x = BigUint::from(3u32);
        let y = BigUint::from(5u32);

        let (r1, r2) = dhp.compute_pair(&x, &y);

        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(2u32));

        let sk = dhp.secret_key(&x, &y);
        assert_eq!(sk, BigUint::from(8u32));

        let result = dhp.verify(&x, &y, &r1, &r2, &sk);
        assert!(result);

        // fake secret
        let r1_fake = BigUint::from(17u32);
        let sk_fake = dhp.secret_key(&x, &y);

        let result_fake = dhp.verify(&x, &y, &r1_fake, &r2, &sk_fake);
        assert!(!result_fake);
    }

    #[test]
    fn test_large_prime() {
        let g = BigUint::from(627u32);
        let p = BigUint::from(941u32);

        let dhp = DHP { g, p };

        let a = BigUint::from(347u32);
        let b = BigUint::from(781u32);

        let (r1, r2) = dhp.compute_pair(&a, &b);

        assert_eq!(r1, BigUint::from(390u32));
        assert_eq!(r2, BigUint::from(691u32));

        let sk = dhp.secret_key(&a, &b);
        assert_eq!(sk, BigUint::from(470u32));

        let result = dhp.verify(&a, &b, &r1, &r2, &sk);
        assert!(result);

        // fake secret
        let r1_fake = BigUint::from(170u32);
        let sk_fake = dhp.secret_key(&a, &b);

        let result_fake = dhp.verify(&a, &b, &r1_fake, &r2, &sk_fake);
        assert!(!result_fake);
    }

    #[test]
    fn test_random_number() {
        let g = BigUint::from(4999951u32);
        let p = BigUint::from(799999971u32);

        let dhp = DHP { g, p: p.clone() };

        let x = DHP::generate_random_number_below(&p);
        let y = DHP::generate_random_number_below(&p);

        let (r1, r2) = dhp.compute_pair(&x, &y);
        let sk = dhp.secret_key(&x, &y);

        let result = dhp.verify(&x, &y, &r1, &r2, &sk);
        assert!(result);

        // fake secret
        let r1_fake = DHP::generate_random_number_below(&p);
        let sk_fake = dhp.secret_key(&x, &y);

        let result_fake = dhp.verify(&x, &y, &r1_fake, &r2, &sk_fake);
        assert!(!result_fake);
    }
}
