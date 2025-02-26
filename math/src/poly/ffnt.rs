use crate::{
    izip_eq,
    util::as_slice::{AsMutSlice, AsSlice},
};
use core::{
    f64::consts::PI,
    fmt::{self, Debug, Formatter},
};
use itertools::{izip, Itertools};
use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};
use std::sync::Arc;

/// Implementation of 2021/480.
#[derive(Clone)]
pub struct Ffnt {
    ring_size: usize,
    fft_size: usize,
    fft_scratch_size: usize,
    fft_size_inv: f64,
    fft: Arc<dyn Fft<f64>>,
    ifft: Arc<dyn Fft<f64>>,
    twiddle_res: Vec<f64>,
    twiddle_ims: Vec<f64>,
}

impl Ffnt {
    pub fn new(ring_size: usize) -> Self {
        assert!(ring_size.is_power_of_two());

        let fft_size = (ring_size / 2).max(1);
        let fft = FftPlanner::new().plan_fft_forward(fft_size);
        let ifft = FftPlanner::new().plan_fft_inverse(fft_size);
        let fft_scratch_size = fft.get_inplace_scratch_len();
        debug_assert_eq!(fft_scratch_size, ifft.get_inplace_scratch_len());

        let twiddle = (0..ring_size / 2)
            .map(|i| Complex64::cis((i as f64 * PI) / ring_size as f64))
            .collect_vec();
        let twiddle_res = twiddle.iter().map(|w| w.re).collect();
        let twiddle_ims = twiddle.iter().map(|w| w.im).collect();

        Self {
            ring_size,
            fft_size,
            fft_scratch_size,
            fft_size_inv: 1f64 / fft_size as f64,
            fft,
            ifft,
            twiddle_res,
            twiddle_ims,
        }
    }

    #[inline(always)]
    pub fn ring_size(&self) -> usize {
        self.ring_size
    }

    #[inline(always)]
    pub fn fft_size(&self) -> usize {
        self.fft_size
    }

    #[inline(always)]
    pub fn fft_scratch_size(&self) -> usize {
        self.fft_scratch_size
    }

    pub fn forward<T>(
        &self,
        b: &mut [Complex64],
        a: &[T],
        to_f64: impl FnMut(&T) -> f64,
        scratch: &mut [Complex64],
    ) {
        self.fold_twist(b, a, to_f64);
        self.fft.process_with_scratch(b, scratch);
    }

    pub fn forward_normalized<T>(
        &self,
        b: &mut [Complex64],
        a: &[T],
        to_f64: impl FnMut(&T) -> f64,
        scratch: &mut [Complex64],
    ) {
        self.forward(b, a, to_f64, scratch);
        self.normalize(b);
    }

    pub fn backward<T>(
        &self,
        b: &mut [T],
        a: &mut [Complex64],
        from_f64: impl FnMut(f64) -> T,
        scratch: &mut [Complex64],
    ) {
        self.ifft.process_with_scratch(a, scratch);
        self.unfold_untwist(b, a, from_f64);
    }

    pub fn backward_normalized<T>(
        &self,
        b: &mut [T],
        a: &mut [Complex64],
        from_f64: impl FnMut(f64) -> T,
        scratch: &mut [Complex64],
    ) {
        self.normalize(a);
        self.backward(b, a, from_f64, scratch);
    }

    pub fn add_backward<T>(
        &self,
        b: &mut [T],
        a: &mut [Complex64],
        add_from_f64: impl FnMut(&mut T, f64),
        scratch: &mut [Complex64],
    ) {
        self.ifft.process_with_scratch(a, scratch);
        self.add_unfold_untwist(b, a, add_from_f64);
    }

    pub fn add_backward_normalized<T>(
        &self,
        b: &mut [T],
        a: &mut [Complex64],
        add_from_f64: impl FnMut(&mut T, f64),
        scratch: &mut [Complex64],
    ) {
        self.normalize(a);
        self.add_backward(b, a, add_from_f64, scratch)
    }

    pub fn normalize(&self, a: &mut [Complex64]) {
        a.iter_mut().for_each(|a| *a *= self.fft_size_inv);
    }

    fn fold_twist<T>(&self, b: &mut [Complex64], a: &[T], mut to_f64: impl FnMut(&T) -> f64) {
        debug_assert_eq!(a.len(), self.ring_size);
        debug_assert_eq!(b.len(), self.fft_size);
        if a.len() == 1 {
            b[0] = to_f64(&a[0]).into();
        } else {
            let (lo, hi) = a.split_at_mid();
            izip!(&mut *b, lo, hi, &self.twiddle_res, &self.twiddle_ims).for_each(
                |(b, lo, hi, t_re, t_im)| {
                    *b = Complex64::new(to_f64(lo), to_f64(hi))
                        * Complex64 {
                            re: *t_re,
                            im: *t_im,
                        }
                },
            );
        }
    }

    fn unfold_untwist<T>(&self, b: &mut [T], a: &[Complex64], mut from_f64: impl FnMut(f64) -> T) {
        debug_assert_eq!(a.len(), self.fft_size);
        debug_assert_eq!(b.len(), self.ring_size);
        if b.len() == 1 {
            b[0] = from_f64(a[0].re);
        } else {
            let (lo, hi) = b.split_at_mid_mut();
            izip!(lo, hi, a, &self.twiddle_res, &self.twiddle_ims).for_each(
                |(lo, hi, a, t_re, t_im)| {
                    let a = *a
                        * Complex64 {
                            re: *t_re,
                            im: -t_im,
                        };
                    *lo = from_f64(a.re);
                    *hi = from_f64(a.im);
                },
            );
        }
    }

    fn add_unfold_untwist<T>(
        &self,
        b: &mut [T],
        a: &[Complex64],
        mut add_from_f64: impl FnMut(&mut T, f64),
    ) {
        debug_assert_eq!(a.len(), self.fft_size);
        debug_assert_eq!(b.len(), self.ring_size);
        if b.len() == 1 {
            add_from_f64(&mut b[0], a[0].re);
        } else {
            let (lo, hi) = b.split_at_mid_mut();
            izip!(lo, hi, a, &self.twiddle_res, &self.twiddle_ims).for_each(
                |(lo, hi, a, t_re, t_im)| {
                    let a = *a
                        * Complex64 {
                            re: *t_re,
                            im: -t_im,
                        };
                    add_from_f64(lo, a.re);
                    add_from_f64(hi, a.im);
                },
            );
        }
    }

    pub fn eval_mul(&self, c: &mut [Complex64], a: &[Complex64], b: &[Complex64]) {
        izip_eq!(c, a, b).for_each(|(c, a, b)| *c = a * b);
    }

    pub fn eval_mul_assign(&self, b: &mut [Complex64], a: &[Complex64]) {
        izip_eq!(b, a).for_each(|(b, a)| *b *= a);
    }

    pub fn eval_fma(&self, c: &mut [Complex64], a: &[Complex64], b: &[Complex64]) {
        izip_eq!(c, a, b).for_each(|(c, a, b)| *c += a * b);
    }
}

impl Debug for Ffnt {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ffnt")
            .field("ring_size", &self.ring_size)
            .field("fft_size", &self.fft_size)
            .field("fft_size_inv", &self.fft_size_inv)
            .field(
                "twiddle_res",
                &format_args!("powers(e^{{i*π/{}}}).re", self.ring_size),
            )
            .field(
                "twiddle_ims",
                &format_args!("powers(e^{{i*π/{}}}).im", self.ring_size),
            )
            .finish()
    }
}

impl Default for Ffnt {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
pub(crate) mod test {
    pub fn round_trip_prec_loss(log_ring_size: usize, log_q: usize) -> usize {
        (log_ring_size + log_q).saturating_sub((f64::MANTISSA_DIGITS - 1) as usize)
    }

    pub fn poly_mul_prec_loss(log_ring_size: usize, log_q: usize, log_b: usize) -> usize {
        (log_ring_size + log_q + log_b).saturating_sub((f64::MANTISSA_DIGITS - 1) as usize)
    }
}
