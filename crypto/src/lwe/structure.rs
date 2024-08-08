use crate::distribution::SecretKeyDistribution;
use core::iter::repeat_with;
use num_traits::{FromPrimitive, Signed};
use phantom_zone_derive::AsSliceWrapper;
use phantom_zone_math::{
    decomposer::DecompositionParam,
    distribution::DistributionSized,
    misc::{
        as_slice::{AsMutSlice, AsSlice},
        scratch::Scratch,
    },
};
use rand::RngCore;

#[derive(Clone, Copy, Debug, AsSliceWrapper)]
pub struct LweSecretKey<S>(S);

impl<S: AsSlice> LweSecretKey<S> {
    pub fn new(data: S) -> Self {
        Self(data)
    }

    pub fn dimension(&self) -> usize {
        self.as_ref().len()
    }
}

impl<T: Default> LweSecretKey<Vec<T>> {
    pub fn allocate(dimension: usize) -> Self {
        Self::new(repeat_with(T::default).take(dimension).collect())
    }

    pub fn sample(
        dimension: usize,
        sk_distribution: SecretKeyDistribution,
        rng: impl RngCore,
    ) -> Self
    where
        T: Signed + FromPrimitive,
    {
        Self::new(sk_distribution.sample_vec(dimension, rng))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LwePlaintext<T>(pub T);

#[derive(Clone, Copy, Debug, AsSliceWrapper)]
pub struct LweCiphertext<S>(S);

impl<S: AsSlice> LweCiphertext<S> {
    pub fn new(data: S) -> Self {
        Self(data)
    }

    pub fn dimension(&self) -> usize {
        self.as_ref().len() - 1
    }

    pub fn a(&self) -> &[S::Elem] {
        self.a_b().0
    }

    pub fn b(&self) -> &S::Elem {
        self.a_b().1
    }

    pub fn a_b(&self) -> (&[S::Elem], &S::Elem) {
        let (b, a) = self.as_ref().split_last().unwrap();
        (a, b)
    }
}

impl<S: AsMutSlice> LweCiphertext<S> {
    pub fn a_mut(&mut self) -> &mut [S::Elem] {
        self.a_b_mut().0
    }

    pub fn b_mut(&mut self) -> &mut S::Elem {
        self.a_b_mut().1
    }

    pub fn a_b_mut(&mut self) -> (&mut [S::Elem], &mut S::Elem) {
        let (b, a) = self.as_mut().split_last_mut().unwrap();
        (a, b)
    }
}

impl<T: Default> LweCiphertext<Vec<T>> {
    pub fn allocate(dimension: usize) -> Self {
        Self::new(repeat_with(T::default).take(dimension + 1).collect())
    }
}

impl<'a, T> LweCiphertext<&'a mut [T]> {
    pub fn scratch(dimension: usize, scratch: &mut Scratch<'a>) -> Self {
        Self::new(scratch.take_slice(dimension + 1))
    }
}

#[derive(Clone, Copy, Debug, AsSliceWrapper)]
pub struct LweCiphertextList<S> {
    #[as_slice]
    data: S,
    dimension: usize,
}

impl<S: AsSlice> LweCiphertextList<S> {
    pub fn new(data: S, dimension: usize) -> Self {
        debug_assert_eq!(data.len() % (dimension + 1), 0);
        Self { data, dimension }
    }

    pub fn len(&self) -> usize {
        self.data.len() / self.ct_size()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn dimension(&self) -> usize {
        self.dimension
    }

    pub fn ct_size(&self) -> usize {
        self.dimension + 1
    }

    pub fn iter(&self) -> impl Iterator<Item = LweCiphertextView<S::Elem>> {
        let ct_size = self.ct_size();
        self.as_ref().chunks(ct_size).map(LweCiphertext::new)
    }

    pub fn chunks(
        &self,
        chunk_size: usize,
    ) -> impl Iterator<Item = LweCiphertextListView<S::Elem>> {
        let dimension = self.dimension();
        let ct_size = self.ct_size();
        self.as_ref()
            .chunks(chunk_size * ct_size)
            .map(move |ct| LweCiphertextList::new(ct, dimension))
    }
}

impl<S: AsMutSlice> LweCiphertextList<S> {
    pub fn iter_mut(&mut self) -> impl Iterator<Item = LweCiphertextMutView<S::Elem>> {
        let ct_size = self.ct_size();
        self.as_mut().chunks_mut(ct_size).map(LweCiphertext::new)
    }

    pub fn chunks_mut(
        &mut self,
        chunk_size: usize,
    ) -> impl Iterator<Item = LweCiphertextListMutView<S::Elem>> {
        let dimension = self.dimension();
        let ct_size = self.ct_size();
        self.as_mut()
            .chunks_mut(chunk_size * ct_size)
            .map(move |ct| LweCiphertextList::new(ct, dimension))
    }
}

impl<T: Default> LweCiphertextList<Vec<T>> {
    pub fn allocate(dimension: usize, n: usize) -> Self {
        let ct_size = dimension + 1;
        Self::new(
            repeat_with(T::default).take(n * ct_size).collect(),
            dimension,
        )
    }
}

#[derive(Clone, Copy, Debug, AsSliceWrapper)]
pub struct LweKeySwitchKey<S> {
    #[as_slice(nested)]
    cts: LweCiphertextList<S>,
    decomposition_param: DecompositionParam,
}

impl<S: AsSlice> LweKeySwitchKey<S> {
    pub fn new(cts: LweCiphertextList<S>, decomposition_param: DecompositionParam) -> Self {
        Self {
            cts,
            decomposition_param,
        }
    }

    pub fn to_dimension(&self) -> usize {
        self.cts.dimension()
    }

    pub fn from_dimension(&self) -> usize {
        self.cts.len() / self.decomposition_param.level
    }

    pub fn decomposition_param(&self) -> DecompositionParam {
        self.decomposition_param
    }

    pub fn cts_iter(&self) -> impl Iterator<Item = LweCiphertextListView<S::Elem>> {
        let chunk_size = self.decomposition_param.level;
        self.cts.chunks(chunk_size)
    }
}

impl<S: AsMutSlice> LweKeySwitchKey<S> {
    pub fn cts_iter_mut(&mut self) -> impl Iterator<Item = LweCiphertextListMutView<S::Elem>> {
        let chunk_size = self.decomposition_param.level;
        self.cts.chunks_mut(chunk_size)
    }
}

impl<T: Default> LweKeySwitchKey<Vec<T>> {
    pub fn allocate(
        from_dimension: usize,
        to_dimension: usize,
        decomposition_param: DecompositionParam,
    ) -> Self {
        Self::new(
            LweCiphertextList::allocate(to_dimension, from_dimension * decomposition_param.level),
            decomposition_param,
        )
    }
}