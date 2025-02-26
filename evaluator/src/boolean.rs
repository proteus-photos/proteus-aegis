use core::ops::Not;

mod evaluator;
mod integer;

pub use evaluator::{fhew, BoolEvaluator};

/// A wrapper to wrap [`BoolEvaluator::Ciphertext`] with reference to its
/// corresponding [`BoolEvaluator`], and expose bitwise operations as Rust core
/// operations if available (otherwise expose as functions following the same
/// naming pattern).
#[derive(Debug)]
pub struct FheBool<E: BoolEvaluator> {
    evaluator: E,
    ct: E::Ciphertext,
}

impl<E: BoolEvaluator> FheBool<E> {
    /// Wraps a [`BoolEvaluator::Ciphertext`] with reference to its
    /// corresponding [`BoolEvaluator`].
    pub fn new(evaluator: E, ct: E::Ciphertext) -> Self {
        Self { evaluator, ct }
    }

    /// Unwraps and returns underlying [`BoolEvaluator::Ciphertext`].
    pub fn into_ct(self) -> E::Ciphertext {
        self.ct
    }

    /// Returns reference to underlying [`BoolEvaluator::Ciphertext`].
    pub fn ct(&self) -> &E::Ciphertext {
        &self.ct
    }

    /// Performs bitwise NOT assignment.
    pub fn bitnot_assign(&mut self) {
        self.evaluator.bitnot_assign(&mut self.ct);
    }

    /// Performs bitwise NAND assignment.
    pub fn bitnand_assign(&mut self, b: &Self) {
        self.evaluator.bitnand_assign(&mut self.ct, &b.ct);
    }

    /// Performs bitwise NAND.
    pub fn bitnand(&self, b: &Self) -> Self {
        let mut a = self.clone();
        a.bitnand_assign(b);
        a
    }

    /// Performs bitwise NOR assignment.
    pub fn bitnor_assign(&mut self, b: &Self) {
        self.evaluator.bitnor_assign(&mut self.ct, &b.ct);
    }

    /// Performs bitwise NOR.
    pub fn bitnor(&self, b: &Self) -> Self {
        let mut a = self.clone();
        a.bitnor_assign(b);
        a
    }

    /// Performs bitwise XNOR assignment.
    pub fn bitxnor_assign(&mut self, b: &Self) {
        self.evaluator.bitxnor_assign(&mut self.ct, &b.ct);
    }

    /// Performs bitwise XNOR.
    pub fn bitxnor(&self, b: &Self) -> Self {
        let mut a = self.clone();
        a.bitxnor_assign(b);
        a
    }

    /// Performs MUX with `self` as control, returns `f` if `false` and `t` if
    /// `true`.
    pub fn select(&self, f: &Self, t: &Self) -> Self {
        (!self & f) | (self & t)
    }

    /// Performs half adder and returns the sum and carry.
    pub fn overflowing_add(&self, b: &Self) -> (Self, Self) {
        let mut a = self.clone();
        let carry = a.overflowing_add_assign(b);
        (a, carry)
    }

    /// Performs half adder assignment and returns the carry.
    pub fn overflowing_add_assign(&mut self, b: &Self) -> Self {
        let carry = self.evaluator.overflowing_add_assign(&mut self.ct, &b.ct);
        Self::new(self.evaluator.clone(), carry)
    }

    /// Performs half subtractor and returns the difference and borrow.
    pub fn overflowing_sub(&self, b: &Self) -> (Self, Self) {
        let mut a = self.clone();
        let borrow = a.overflowing_sub_assign(b);
        (a, borrow)
    }

    /// Performs half subtractor assignment and returns the borrow.
    pub fn overflowing_sub_assign(&mut self, b: &Self) -> Self {
        let borrow = self.evaluator.overflowing_sub_assign(&mut self.ct, &b.ct);
        Self::new(self.evaluator.clone(), borrow)
    }

    /// Performs full adder and returns the sum and carry.
    pub fn carrying_add(&self, b: &Self, carry: &Self) -> (Self, Self) {
        let mut a = self.clone();
        let carry = a.carrying_add_assign(b, carry);
        (a, carry)
    }

    /// Performs full adder assignment and returns the carry.
    pub fn carrying_add_assign(&mut self, b: &Self, carry: &Self) -> Self {
        let carry = self
            .evaluator
            .carrying_add_assign(&mut self.ct, &b.ct, &carry.ct);
        Self::new(self.evaluator.clone(), carry)
    }

    /// Performs full subtractor and returns the difference and borrow.
    pub fn borrowing_sub(&self, b: &Self, borrow: &Self) -> (Self, Self) {
        let mut a = self.clone();
        let borrow = a.borrowing_sub_assign(b, borrow);
        (a, borrow)
    }

    /// Performs full subtractor assignment and returns the borrow.
    pub fn borrowing_sub_assign(&mut self, b: &Self, borrow: &Self) -> Self {
        let borrow = self
            .evaluator
            .borrowing_sub_assign(&mut self.ct, &b.ct, &borrow.ct);
        Self::new(self.evaluator.clone(), borrow)
    }
}

impl<E: BoolEvaluator> Clone for FheBool<E> {
    fn clone(&self) -> Self {
        Self::new(self.evaluator.clone(), self.ct.clone())
    }
}

impl<E: BoolEvaluator> Not for FheBool<E> {
    type Output = FheBool<E>;

    fn not(mut self) -> Self::Output {
        self.evaluator.bitnot_assign(&mut self.ct);
        self
    }
}

impl<E: BoolEvaluator> Not for &FheBool<E> {
    type Output = FheBool<E>;

    fn not(self) -> Self::Output {
        self.clone().not()
    }
}

macro_rules! impl_core_op {
    (@ impl $trait:ident<$rhs:ty> for $lhs:ty; $lhs_convert:expr) => {
        paste::paste! {
            impl<E: BoolEvaluator> core::ops::$trait<$rhs> for $lhs {
                type Output = FheBool<E>;

                fn [<$trait:lower>](self, rhs: $rhs) -> Self::Output {
                    let mut lhs = $lhs_convert(self);
                    lhs.evaluator.[<$trait:lower _assign>](&mut lhs.ct, &rhs.ct);
                    lhs
                }
            }
        }
    };
    ($(impl $trait:ident<$rhs:ty> for $lhs:ty),* $(,)?) => {
        $(
            paste::paste! {
                impl<E: BoolEvaluator> core::ops::[<$trait Assign>]<$rhs> for $lhs {
                    fn [<$trait:lower _assign>](&mut self, rhs: $rhs) {
                        self.evaluator.[<$trait:lower _assign>](&mut self.ct, &rhs.ct);
                    }
                }
                impl<E: BoolEvaluator> core::ops::[<$trait Assign>]<&$rhs> for $lhs {
                    fn [<$trait:lower _assign>](&mut self, rhs: &$rhs) {
                        self.evaluator.[<$trait:lower _assign>](&mut self.ct, &rhs.ct);
                    }
                }
            }
            impl_core_op!(@ impl $trait<$rhs> for $lhs; core::convert::identity);
            impl_core_op!(@ impl $trait<&$rhs> for $lhs; core::convert::identity);
            impl_core_op!(@ impl $trait<$rhs> for &$lhs; <_>::clone);
            impl_core_op!(@ impl $trait<&$rhs> for &$lhs; <_>::clone);
        )*
    }
}

impl_core_op!(
    impl BitAnd<FheBool<E>> for FheBool<E>,
    impl BitOr<FheBool<E>> for FheBool<E>,
    impl BitXor<FheBool<E>> for FheBool<E>,
);

#[cfg(any(test, feature = "dev"))]
pub mod dev {
    use crate::boolean::{evaluator::BoolEvaluator, FheBool};

    #[derive(Clone, Copy, Debug)]
    pub struct MockBoolEvaluator;

    impl BoolEvaluator for MockBoolEvaluator {
        type Ciphertext = bool;

        fn bitnot_assign(&self, a: &mut Self::Ciphertext) {
            *a = !*a;
        }

        fn bitand_assign(&self, a: &mut Self::Ciphertext, b: &Self::Ciphertext) {
            *a &= b;
        }

        fn bitnand_assign(&self, a: &mut Self::Ciphertext, b: &Self::Ciphertext) {
            self.bitand_assign(a, b);
            self.bitnot_assign(a);
        }

        fn bitor_assign(&self, a: &mut Self::Ciphertext, b: &Self::Ciphertext) {
            *a |= b;
        }

        fn bitnor_assign(&self, a: &mut Self::Ciphertext, b: &Self::Ciphertext) {
            self.bitor_assign(a, b);
            self.bitnot_assign(a);
        }

        fn bitxor_assign(&self, a: &mut Self::Ciphertext, b: &Self::Ciphertext) {
            *a ^= b;
        }

        fn bitxnor_assign(&self, a: &mut Self::Ciphertext, b: &Self::Ciphertext) {
            self.bitxor_assign(a, b);
            self.bitnot_assign(a);
        }
    }

    impl From<bool> for FheBool<MockBoolEvaluator> {
        fn from(a: bool) -> Self {
            FheBool::new(MockBoolEvaluator, a)
        }
    }

    impl PartialEq<bool> for FheBool<MockBoolEvaluator> {
        fn eq(&self, other: &bool) -> bool {
            self.ct == *other
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::boolean::FheBool;
    use core::{
        array::from_fn,
        ops::{BitAnd, BitOr, BitXor},
    };

    /// Truth tables for overflowing, carrying and borrowing bit operations.
    #[rustfmt::skip]
    pub mod tt {
        const F: bool = false;
        const T: bool = true;
        pub const OVERFLOWING_ADD: [(bool, bool); 4] = [(F, F), (T, F), (T, F), (F, T)];
        pub const OVERFLOWING_SUB: [(bool, bool); 4] = [(F, F), (T, F), (T, T), (F, F)];
        pub const CARRYING_ADD:    [(bool, bool); 8] = [(F, F), (T, F), (T, F), (F, T), (T, F), (F, T), (F, T), (T, T)];
        pub const BORROWING_SUB:   [(bool, bool); 8] = [(F, F), (T, F), (T, T), (F, F), (T, T), (F, F), (F, T), (T, T)];
    }

    #[test]
    fn bit_op() {
        for m in 0..1 << 1 {
            let m = m == 1;
            let ct = FheBool::from(m);
            assert_eq!((!ct).ct, !m);
        }
        for m in 0..1 << 2 {
            let [a, b] = from_fn(|i| (m >> i) & 1 == 1);
            let [ct_a, ct_b] = &[a, b].map(FheBool::from);
            assert_eq!(ct_a.bitand(ct_b), a & b);
            assert_eq!(ct_a.bitnand(ct_b), !(a & b));
            assert_eq!(ct_a.bitor(ct_b), a | b);
            assert_eq!(ct_a.bitnor(ct_b), !(a | b));
            assert_eq!(ct_a.bitxor(ct_b), a ^ b);
            assert_eq!(ct_a.bitxnor(ct_b), !(a ^ b));
        }
    }

    #[test]
    fn add_sub() {
        macro_rules! assert_eq2 {
            ($a:expr, $m:expr) => {
                let (a, m) = ($a, $m);
                assert_eq!(a.0, m.0);
                assert_eq!(a.1, m.1);
            };
        }
        for m in 0..1 << 2 {
            let [fhe_a, fhe_b] = from_fn(|i| FheBool::from((m >> i) & 1 == 1));
            assert_eq2!(fhe_a.overflowing_add(&fhe_b), tt::OVERFLOWING_ADD[m]);
            assert_eq2!(fhe_a.overflowing_sub(&fhe_b), tt::OVERFLOWING_SUB[m]);
        }
        for m in 0..1 << 3 {
            let [fhe_a, fhe_b, fhe_c] = from_fn(|i| FheBool::from((m >> i) & 1 == 1));
            assert_eq2!(fhe_a.carrying_add(&fhe_b, &fhe_c), tt::CARRYING_ADD[m]);
            assert_eq2!(fhe_a.borrowing_sub(&fhe_b, &fhe_c), tt::BORROWING_SUB[m]);
        }
    }
}
