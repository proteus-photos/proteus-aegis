use crate::boolean::{evaluator::BoolEvaluator, FheBool};
use core::{
    array::from_fn,
    borrow::Borrow,
    ops::{BitAndAssign, Not},
};
use itertools::izip;
use std::{borrow::Cow, collections::VecDeque};

/// A wrapper using [`FheBool`] to implement [`u8`] wrapping operations.
pub type FheU8<E> = FheUint<E, 8>;
/// A wrapper using [`FheBool`] to implement [`u16`] wrapping operations.
pub type FheU16<E> = FheUint<E, 16>;
/// A wrapper using [`FheBool`] to implement [`u32`] wrapping operations.
pub type FheU32<E> = FheUint<E, 32>;
/// A wrapper using [`FheBool`] to implement [`u64`] wrapping operations.
pub type FheU64<E> = FheUint<E, 64>;

/// A wrapper using [`FheBool`] to implement unsigned integer wrapping
/// operations, and expose as Rust core operations if available (otherwise
/// expose as functions following the same naming pattern).
#[derive(Debug)]
pub struct FheUint<E: BoolEvaluator, const BITS: usize>([FheBool<E>; BITS]);

impl<E: BoolEvaluator, const BITS: usize> FheUint<E, BITS> {
    /// Wraps [`FheBool`] as little-endian bits.
    pub fn new(bits: [FheBool<E>; BITS]) -> Self {
        Self(bits)
    }

    /// Wraps array of [`BoolEvaluator::Ciphertext`] as little-endian bits with
    /// reference to their corresponding [`BoolEvaluator`].
    pub fn from_cts(evaluator: E, bits: [E::Ciphertext; BITS]) -> Self {
        Self::new(bits.map(|bit| FheBool::new(evaluator.clone(), bit)))
    }

    /// Unwraps and returns underlying array of [`BoolEvaluator::Ciphertext`]
    /// as little-endian bits.
    pub fn into_cts(self) -> [E::Ciphertext; BITS] {
        self.0.map(FheBool::into_ct)
    }

    /// Returns array of reference to underlying [`BoolEvaluator::Ciphertext`]
    /// as little-endian bits.
    pub fn cts(&self) -> [&E::Ciphertext; BITS] {
        self.0.each_ref().map(FheBool::ct)
    }
}

impl<E: BoolEvaluator, const BITS: usize> Clone for FheUint<E, BITS> {
    fn clone(&self) -> Self {
        Self::new(self.0.each_ref().map(|bit| bit.clone()))
    }
}

impl<E: BoolEvaluator, const BITS: usize> Not for FheUint<E, BITS> {
    type Output = FheUint<E, BITS>;

    fn not(mut self) -> Self::Output {
        self.0.each_mut().map(|bit| bit.bitnot_assign());
        self
    }
}

impl<E: BoolEvaluator, const BITS: usize> Not for &FheUint<E, BITS> {
    type Output = FheUint<E, BITS>;

    fn not(self) -> Self::Output {
        FheUint(self.0.each_ref().map(|bit| !bit))
    }
}

impl<E: BoolEvaluator, const BITS: usize> FheUint<E, BITS> {
    pub fn wrapping_neg(&self) -> Self {
        let v = self.0.each_ref();
        let mut carry = !v[0];
        let neg = from_fn(|i| {
            let sum;
            match i {
                0 => sum = v[0].clone(),
                _ => (sum, carry) = (!v[i]).overflowing_add(&carry),
            };
            sum
        });
        Self(neg)
    }

    pub fn wrapping_add(&self, rhs: &Self) -> Self {
        self.overflowing_add(rhs).0
    }

    pub fn wrapping_sub(&self, rhs: &Self) -> Self {
        self.overflowing_sub(rhs).0
    }

    pub fn wrapping_mul(&self, rhs: &Self) -> Self {
        let (lhs, rhs, mut carries) = (
            self.0.each_ref(),
            rhs.0.each_ref(),
            from_fn::<_, BITS, _>(|_| None),
        );
        let product = from_fn(|i| {
            let mut t = (0..=i).map(|j| lhs[j] & rhs[i - j]);
            let mut sum = t.next().unwrap();
            izip!(t, &mut carries).for_each(|(tj, carry)| match carry {
                Some(carry) => *carry = sum.carrying_add_assign(&tj, carry),
                _ => *carry = Some(sum.overflowing_add_assign(&tj)),
            });
            sum
        });
        Self(product)
    }

    pub fn wrapping_div(&self, rhs: &Self) -> Self {
        let (q, _) = self.div_rem(rhs);
        q
    }

    pub fn wrapping_rem(&self, rhs: &Self) -> Self {
        let (_, r) = self.div_rem(rhs);
        r
    }

    pub fn overflowing_add(&self, rhs: &Self) -> (Self, FheBool<E>) {
        let (lhs, rhs, mut carry) = (self.0.each_ref(), rhs.0.each_ref(), None);
        let sum = from_fn(|i| {
            let (sum, carry_out) = match carry.take() {
                Some(carry) => lhs[i].carrying_add(rhs[i], &carry),
                None => lhs[i].overflowing_add(rhs[i]),
            };
            carry = Some(carry_out);
            sum
        });
        (Self(sum), carry.unwrap())
    }

    pub fn overflowing_sub(&self, rhs: &Self) -> (Self, FheBool<E>) {
        let (lhs, rhs, mut borrow) = (self.0.each_ref(), rhs.0.each_ref(), None);
        let sum = from_fn(|i| {
            let (sum, borrow_out) = match borrow.take() {
                Some(borrow) => lhs[i].borrowing_sub(rhs[i], &borrow),
                None => lhs[i].overflowing_sub(rhs[i]),
            };
            borrow = Some(borrow_out);
            sum
        });
        (Self(sum), borrow.unwrap())
    }

    pub fn carrying_add(&self, rhs: &Self, carry: &FheBool<E>) -> (Self, FheBool<E>) {
        let (lhs, rhs, mut carry) = (self.0.each_ref(), rhs.0.each_ref(), Cow::Borrowed(carry));
        let sum = from_fn(|i| {
            let (sum, carry_out) = lhs[i].carrying_add(rhs[i], &carry);
            carry = Cow::Owned(carry_out);
            sum
        });
        (Self(sum), carry.into_owned())
    }

    pub fn borrowing_sub(&self, rhs: &Self, borrow: &FheBool<E>) -> (Self, FheBool<E>) {
        let (lhs, rhs, mut borrow) = (self.0.each_ref(), rhs.0.each_ref(), Cow::Borrowed(borrow));
        let diff = from_fn(|i| {
            let (diff, borrow_out) = lhs[i].borrowing_sub(rhs[i], &borrow);
            borrow = Cow::Owned(borrow_out);
            diff
        });
        (Self(diff), borrow.into_owned())
    }

    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (lhs, neg_rhs) = (self.0.each_ref(), rhs.wrapping_neg().0);
        let [mut q, mut r, mut d] = from_fn(|_| VecDeque::with_capacity(BITS));
        for i in 0..BITS {
            r.push_front(lhs[BITS - 1 - i].clone());
            d.clone_from(&r);

            let mut carry = d[0].overflowing_add_assign(&neg_rhs[0]);
            izip!(1.., &neg_rhs[1..]).for_each(|(j, neg_rhs)| match d.get_mut(j) {
                Some(d) => carry = d.carrying_add_assign(neg_rhs, &carry),
                None => carry.bitand_assign(neg_rhs),
            });

            izip!(&mut r, &d).for_each(|(r, d)| *r = carry.select(r, d));

            q.push_front(carry);
        }
        let [q, r] = [q, r].map(|mut v| Self(from_fn(|_| v.pop_front().unwrap())));
        (q, r)
    }
}

macro_rules! impl_core_op {
    (@ impl $trait:ident<$rhs:ty> for $lhs:ty) => {
        paste::paste! {
            impl<E: BoolEvaluator, const BITS: usize> core::ops::$trait<$rhs> for $lhs {
                type Output = FheUint<E, BITS>;

                fn [<$trait:lower>](self, rhs: $rhs) -> Self::Output {
                    self.[<wrapping_ $trait:lower>](rhs.borrow())
                }
            }
        }
    };
    ($(impl $trait:ident<$rhs:ty> for $lhs:ty),* $(,)?) => {
        $(
            paste::paste! {
                impl<E: BoolEvaluator, const BITS: usize> core::ops::[<$trait Assign>]<&$rhs> for $lhs {
                    fn [<$trait:lower _assign>](&mut self, rhs: &$rhs) {
                        *self = self.[<wrapping_ $trait:lower>](rhs);
                    }
                }
                impl<E: BoolEvaluator, const BITS: usize> core::ops::[<$trait Assign>]<$rhs> for $lhs {
                    fn [<$trait:lower _assign>](&mut self, rhs: $rhs) {
                        *self = self.[<wrapping_ $trait:lower>](&rhs);
                    }
                }
            }
            impl_core_op!(@ impl $trait<$rhs> for $lhs);
            impl_core_op!(@ impl $trait<&$rhs> for $lhs);
            impl_core_op!(@ impl $trait<$rhs> for &$lhs);
            impl_core_op!(@ impl $trait<&$rhs> for &$lhs);
        )*
    }
}

impl_core_op!(
    impl Add<FheUint<E, BITS>> for FheUint<E, BITS>,
    impl Sub<FheUint<E, BITS>> for FheUint<E, BITS>,
    impl Mul<FheUint<E, BITS>> for FheUint<E, BITS>,
    impl Div<FheUint<E, BITS>> for FheUint<E, BITS>,
    impl Rem<FheUint<E, BITS>> for FheUint<E, BITS>,
);

#[cfg(test)]
mod test {
    use crate::boolean::{
        dev::MockBoolEvaluator,
        integer::{FheU16, FheU32, FheU64, FheU8},
        FheBool,
    };
    use core::array::from_fn;
    use rand::{distributions::Uniform, thread_rng, Rng};

    trait CarryingAdd: Sized {
        fn carrying_add(self, rhs: Self, carry: bool) -> (Self, bool);
    }

    trait BorrowingSub: Sized {
        fn borrowing_sub(self, rhs: Self, borrow: bool) -> (Self, bool);
    }

    macro_rules! impl_fhe_uint {
        ($uint:ident, $fhe_uint:ident) => {
            impl From<$uint> for $fhe_uint<MockBoolEvaluator> {
                fn from(a: $uint) -> Self {
                    let bits = from_fn(|i| FheBool::new(MockBoolEvaluator, (a >> i) & 1 == 1));
                    Self::new(bits)
                }
            }

            impl PartialEq<$uint> for $fhe_uint<MockBoolEvaluator> {
                fn eq(&self, other: &$uint) -> bool {
                    self.0
                        .iter()
                        .rev()
                        .fold(0, |acc, bit| (acc << 1) | bit.ct as $uint)
                        == *other
                }
            }

            impl CarryingAdd for $uint {
                fn carrying_add(self, rhs: Self, carry: bool) -> (Self, bool) {
                    match self.overflowing_add(rhs) {
                        (sum, true) => (sum + carry as $uint, true),
                        (sum, false) => sum.overflowing_add(carry as $uint),
                    }
                }
            }

            impl BorrowingSub for $uint {
                fn borrowing_sub(self, rhs: Self, borrow: bool) -> (Self, bool) {
                    match self.overflowing_sub(rhs) {
                        (diff, true) => (diff - borrow as $uint, true),
                        (diff, false) => diff.overflowing_sub(borrow as $uint),
                    }
                }
            }
        };
    }

    impl_fhe_uint!(u8, FheU8);
    impl_fhe_uint!(u16, FheU16);
    impl_fhe_uint!(u32, FheU32);
    impl_fhe_uint!(u64, FheU64);

    #[test]
    #[allow(unstable_name_collisions)]
    fn arith_op() {
        macro_rules! assert_eq2 {
            ($a:expr, $m:expr) => {
                let (a, m) = ($a, $m);
                assert_eq!(a.0, m.0);
                assert_eq!(a.1, m.1);
            };
        }
        macro_rules! run {
            ($fhe_uint:ident, $iter:expr) => {
                for a in $iter.take(256) {
                    for b in $iter.take(256) {
                        let fhe_a = $fhe_uint::from(a);
                        let fhe_b = $fhe_uint::from(b);
                        assert_eq!(fhe_a.wrapping_neg(), a.wrapping_neg());
                        assert_eq!(fhe_a.wrapping_add(&fhe_b), a.wrapping_add(b));
                        assert_eq!(fhe_a.wrapping_sub(&fhe_b), a.wrapping_sub(b));
                        assert_eq!(fhe_a.wrapping_mul(&fhe_b), a.wrapping_mul(b));
                        if b != 0 {
                            assert_eq2!(fhe_a.div_rem(&fhe_b), (a / b, a % b));
                        }
                        for c in [false, true] {
                            let fhe_c = FheBool::from(c);
                            assert_eq2!(fhe_a.carrying_add(&fhe_b, &fhe_c), a.carrying_add(b, c));
                            assert_eq2!(fhe_a.borrowing_sub(&fhe_b, &fhe_c), a.borrowing_sub(b, c));
                            assert_eq2!(fhe_a.overflowing_add(&fhe_b), a.overflowing_add(b));
                            assert_eq2!(fhe_a.overflowing_sub(&fhe_b), a.overflowing_sub(b));
                        }
                    }
                }
            };
        }

        run!(FheU8, 0..u8::MAX);
        run!(FheU16, thread_rng().sample_iter(Uniform::from(0..u16::MAX)));
        run!(FheU32, thread_rng().sample_iter(Uniform::from(0..u32::MAX)));
        run!(FheU64, thread_rng().sample_iter(Uniform::from(0..u64::MAX)));
    }
}
