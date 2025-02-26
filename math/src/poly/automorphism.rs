/// Map for `f(X) -> f(X^k)`. The `map` slice contains `sign` bit and
/// pre-image `index` encoded as `index << 1 | sign`.
///
/// # Examples
///
/// ```
/// use phantom_zone_math::poly::automorphism::AutomorphismMap;
///
/// let ring_size = 8;
/// let k = 5;
/// let auto_map = AutomorphismMap::new(ring_size, k);
/// let mut iter = auto_map.iter();
/// assert_eq!(iter.next(), Some((false, 0))); // X^0 =  X^(0*5)
/// assert_eq!(iter.next(), Some((true, 5)));  // X^1 = -X^(5*5)
/// assert_eq!(iter.next(), Some((true, 2)));  // X^2 = -X^(2*5)
/// assert_eq!(iter.next(), Some((false, 7))); // X^3 =  X^(7*5)
/// assert_eq!(iter.next(), Some((false, 4))); // X^4 =  X^(4*5)
/// assert_eq!(iter.next(), Some((false, 1))); // X^5 =  X^(1*5)
/// assert_eq!(iter.next(), Some((true, 6)));  // X^6 = -X^(6*5)
/// assert_eq!(iter.next(), Some((true, 3)));  // X^7 = -X^(3*5)
/// assert_eq!(iter.next(), None);
/// ```
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "SerdeAutomorphismMap", from = "SerdeAutomorphismMap")
)]
pub struct AutomorphismMap {
    map: Vec<usize>,
    k: usize,
}

impl AutomorphismMap {
    pub fn new(ring_size: usize, k: usize) -> Self {
        debug_assert!(ring_size.is_power_of_two());
        debug_assert!(k < 2 * ring_size);
        let mask = ring_size - 1;
        let log_n = ring_size.ilog2();
        let mut map = vec![0; ring_size];
        (0..ring_size).for_each(|i| {
            let j = i * k;
            let sign = (j >> log_n) & 1;
            map[j & mask] = (i << 1) | sign
        });
        Self { map, k }
    }

    pub fn ring_size(&self) -> usize {
        self.map.len()
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn iter(&self) -> impl Clone + Iterator<Item = (bool, usize)> + '_ {
        self.map.iter().map(|v| {
            let sign = (v & 1) == 1;
            let idx = v >> 1;
            (sign, idx)
        })
    }

    pub fn apply<'a, T, F>(&'a self, poly: &'a [T], neg: F) -> impl 'a + Clone + Iterator<Item = T>
    where
        T: Copy,
        F: 'a + Clone + Fn(&T) -> T,
    {
        debug_assert_eq!(self.map.len(), poly.len());
        self.iter()
            .map(move |(sign, idx)| if sign { neg(&poly[idx]) } else { poly[idx] })
    }
}

impl PartialEq for AutomorphismMap {
    fn eq(&self, other: &Self) -> bool {
        (self.ring_size(), self.k()).eq(&(other.ring_size(), other.k()))
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SerdeAutomorphismMap {
    ring_size: usize,
    k: usize,
}

#[cfg(feature = "serde")]
impl From<SerdeAutomorphismMap> for AutomorphismMap {
    fn from(value: SerdeAutomorphismMap) -> Self {
        Self::new(value.ring_size, value.k)
    }
}

#[cfg(feature = "serde")]
impl From<AutomorphismMap> for SerdeAutomorphismMap {
    fn from(value: AutomorphismMap) -> Self {
        Self {
            ring_size: value.ring_size(),
            k: value.k,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::poly::automorphism::AutomorphismMap;
    use core::ops::Neg;
    use itertools::Itertools;

    fn automorphism<T: Copy + Default + Neg<Output = T>>(input: &[T], k: usize) -> Vec<T> {
        assert!(input.len().is_power_of_two());
        assert!(k < 2 * input.len());
        let n = input.len();
        let mut out = vec![T::default(); n];
        (0..n)
            .map(|i| (i, (i * k) % (2 * n)))
            .for_each(|(i, j)| out[j % n] = if j < n { input[i] } else { -input[i] });
        out
    }

    #[test]
    fn automorphism_iter() {
        for log_n in 0..10 {
            let n = 1 << log_n;
            let indices = (0..n as i64).collect_vec();
            for k in (1..2 * n).step_by(2) {
                let auto_map = AutomorphismMap::new(n, k);
                assert_eq!(
                    auto_map.apply(&indices, |i| -i).collect_vec(),
                    automorphism(&indices, k)
                );
            }
        }
    }
}
