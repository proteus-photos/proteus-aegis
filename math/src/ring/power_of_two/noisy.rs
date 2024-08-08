use crate::{
    decomposer::PowerOfTwoDecomposer,
    modulus::Modulus,
    poly::ffnt::Ffnt,
    ring::{power_of_two, ElemFrom, ElemTo, RingOps},
};
use num_complex::Complex64;

pub type NoisyPowerOfTwoRing<const NATIVE: bool> = power_of_two::PowerOfTwoRing<Ffnt, NATIVE>;

pub type NoisyNativeRing = NoisyPowerOfTwoRing<true>;

pub type NoisyNonNativePowerOfTwoRing = NoisyPowerOfTwoRing<false>;

impl<const NATIVE: bool> RingOps for NoisyPowerOfTwoRing<NATIVE> {
    type Eval = Complex64;
    type EvalPrep = Complex64;
    type Decomposer = PowerOfTwoDecomposer<NATIVE>;

    fn new(modulus: Modulus, ring_size: usize) -> Self {
        Self::new(modulus.try_into().unwrap(), Ffnt::new(ring_size))
    }

    fn ring_size(&self) -> usize {
        self.fft.ring_size()
    }

    fn eval_size(&self) -> usize {
        self.fft.fft_size()
    }

    fn forward(&self, b: &mut [Self::Eval], a: &[Self::Elem]) {
        self.fft.forward(b, a, |a| self.to_i64(*a) as _);
    }

    fn forward_elem_from<T: Copy>(&self, b: &mut [Self::Eval], a: &[T])
    where
        Self: ElemFrom<T>,
    {
        self.fft.forward(b, a, |a| {
            let a: i64 = self.elem_to(self.elem_from(*a));
            a as _
        });
    }

    fn forward_normalized(&self, b: &mut [Self::Eval], a: &[Self::Elem]) {
        self.fft.forward_normalized(b, a, |a| self.to_i64(*a) as _);
    }

    fn backward(&self, b: &mut [Self::Elem], a: &mut [Self::Eval]) {
        self.fft.backward(b, a, |a| self.elem_from(a));
    }

    fn backward_normalized(&self, b: &mut [Self::Elem], a: &mut [Self::Eval]) {
        self.fft.backward_normalized(b, a, |a| self.elem_from(a));
    }

    fn add_backward(&self, b: &mut [Self::Elem], a: &mut [Self::Eval]) {
        self.fft.add_backward(b, a, |b, a| {
            *b = self.reduce(b.wrapping_add(f64_mod_u64(a)))
        });
    }

    fn add_backward_normalized(&self, b: &mut [Self::Elem], a: &mut [Self::Eval]) {
        self.fft.add_backward_normalized(b, a, |b, a| {
            *b = self.reduce(b.wrapping_add(f64_mod_u64(a)))
        });
    }

    fn eval_prepare(&self, b: &mut [Self::EvalPrep], a: &[Self::Eval]) {
        b.copy_from_slice(a)
    }

    fn eval_mul(&self, c: &mut [Self::Eval], a: &[Self::Eval], b: &[Self::Eval]) {
        self.fft.eval_mul(c, a, b)
    }

    fn eval_mul_assign(&self, b: &mut [Self::Eval], a: &[Self::Eval]) {
        self.fft.eval_mul_assign(b, a)
    }

    fn eval_fma(&self, c: &mut [Self::Eval], a: &[Self::Eval], b: &[Self::Eval]) {
        self.fft.eval_fma(c, a, b)
    }

    fn eval_mul_prep(&self, c: &mut [Self::Eval], a: &[Self::Eval], b: &[Self::EvalPrep]) {
        self.eval_mul(c, a, b)
    }

    fn eval_mul_assign_prep(&self, b: &mut [Self::Eval], a: &[Self::EvalPrep]) {
        self.eval_mul_assign(b, a)
    }

    fn eval_fma_prep(&self, c: &mut [Self::Eval], a: &[Self::Eval], b: &[Self::EvalPrep]) {
        self.eval_fma(c, a, b)
    }
}

#[inline(always)]
pub(crate) fn f64_mod_u64(v: f64) -> u64 {
    let bits = v.to_bits();
    let sign = bits >> 63;
    let exponent = ((bits >> 52) & 0x7ff) as i64;
    let mantissa = (bits << 11) | 0x8000000000000000;
    let value = match 1086 - exponent {
        shift @ -63..=0 => mantissa << -shift,
        shift @ 1..=64 => ((mantissa >> (shift - 1)).wrapping_add(1)) >> 1,
        _ => 0,
    };
    if sign == 0 {
        value
    } else {
        value.wrapping_neg()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        distribution::Sampler,
        misc::test::assert_precision,
        modulus::{Modulus, PowerOfTwo},
        poly::ffnt::test::{poly_mul_prec_loss, round_trip_prec_loss},
        ring::{
            power_of_two::noisy::{self, NoisyNativeRing, NoisyNonNativePowerOfTwoRing},
            test::{test_poly_mul, test_round_trip},
            RingOps,
        },
    };
    use num_bigint_dig::BigInt;
    use num_traits::{FromPrimitive, ToPrimitive};
    use rand::{distributions::Uniform, thread_rng};

    #[test]
    fn f64_mod_u64() {
        let expected = |a: f64| {
            let a = BigInt::from_f64(a.round()).unwrap();
            (a % (1i128 << 64)).to_i128().unwrap() as u64
        };
        for exp in -1023..1024 {
            let a = 2f64.powi(exp);
            assert_eq!(noisy::f64_mod_u64(a), expected(a));
            assert_eq!(noisy::f64_mod_u64(a + 0.5), expected(a + 0.5));
            assert_eq!(noisy::f64_mod_u64(a - 0.5), expected(a - 0.5));
            assert_eq!(noisy::f64_mod_u64(-a), expected(-a));
            assert_eq!(noisy::f64_mod_u64(-a + 0.5), expected(-a + 0.5));
            assert_eq!(noisy::f64_mod_u64(-a - 0.5), expected(-a - 0.5));
        }
    }

    #[test]
    fn non_native_round_trip() {
        let mut rng = thread_rng();
        for log_ring_size in 0..10 {
            for log_q in 50..56 {
                let prec_loss = round_trip_prec_loss(log_ring_size, log_q);
                let ring: NoisyNonNativePowerOfTwoRing =
                    RingOps::new(PowerOfTwo(log_q).into(), 1 << log_ring_size);
                for _ in 0..100 {
                    let a = ring.sample_uniform_vec(ring.ring_size(), &mut rng);
                    test_round_trip(&ring, &a, |a, b| assert_precision!(a, b, prec_loss));
                }
            }
        }
    }

    #[test]
    fn native_round_trip() {
        let mut rng = thread_rng();
        for log_ring_size in 0..10 {
            let prec_loss = round_trip_prec_loss(log_ring_size, 64);
            let ring: NoisyNativeRing = RingOps::new(Modulus::native(), 1 << log_ring_size);
            for _ in 0..100 {
                let a = ring.sample_uniform_vec(ring.ring_size(), &mut rng);
                test_round_trip(&ring, &a, |a, b| assert_precision!(a, b, prec_loss));
            }
        }
    }

    #[test]
    fn non_native_poly_mul() {
        let mut rng = thread_rng();
        for log_ring_size in 0..10 {
            for log_q in 50..54 {
                let ring: NoisyNonNativePowerOfTwoRing =
                    RingOps::new(PowerOfTwo(log_q).into(), 1 << log_ring_size);
                for log_b in 12..16 {
                    let prec_loss = poly_mul_prec_loss(log_ring_size, log_q, log_b);
                    let uniform_b = Uniform::new(0, 1u64 << log_b);
                    for _ in 0..100 {
                        let a = ring.sample_uniform_vec(ring.ring_size(), &mut rng);
                        let b = ring.sample_vec(ring.ring_size(), uniform_b, &mut rng);
                        test_poly_mul(&ring, &a, &b, |a, b| assert_precision!(a, b, prec_loss));
                    }
                }
            }
        }
    }

    #[test]
    fn native_poly_mul() {
        let mut rng = thread_rng();
        for log_ring_size in 0..10 {
            let ring: NoisyNativeRing = RingOps::new(Modulus::native(), 1 << log_ring_size);
            for log_b in 12..16 {
                let prec_loss = poly_mul_prec_loss(log_ring_size, 64, log_b);
                let uniform_b = Uniform::new(0, 1u64 << log_b);
                for _ in 0..100 {
                    let a = ring.sample_uniform_vec(ring.ring_size(), &mut rng);
                    let b = ring.sample_vec(ring.ring_size(), uniform_b, &mut rng);
                    test_poly_mul(&ring, &a, &b, |a, b| assert_precision!(a, b, prec_loss));
                }
            }
        }
    }
}