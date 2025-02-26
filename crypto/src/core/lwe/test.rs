use crate::{
    core::lwe::{
        self, LweCiphertext, LweCiphertextOwned, LweKeySwitchKey, LweKeySwitchKeyOwned,
        LwePlaintext, LweSecretKey, LweSecretKeyOwned,
    },
    util::{
        distribution::{NoiseDistribution, SecretDistribution},
        rng::{LweRng, StdLweRng},
    },
};
use phantom_zone_math::{
    decomposer::{Decomposer, DecompositionParam},
    distribution::Gaussian,
    izip_eq,
    modulus::{ElemFrom, Modulus, ModulusOps, Native, NonNativePowerOfTwo, Prime},
    ring::{NativeRing, NonNativePowerOfTwoRing, PrimeRing},
};
use rand::{RngCore, SeedableRng};

#[derive(Clone, Copy, Debug)]
pub struct LweParam {
    pub message_modulus: u64,
    pub ciphertext_modulus: Modulus,
    pub dimension: usize,
    pub sk_distribution: SecretDistribution,
    pub noise_distribution: NoiseDistribution,
    pub ks_decomposition_param: DecompositionParam,
}

impl LweParam {
    pub fn dimension(mut self, dimension: usize) -> Self {
        self.dimension = dimension;
        self
    }

    pub fn build<M: ModulusOps>(self) -> Lwe<M> {
        let delta = self.ciphertext_modulus.as_f64() / self.message_modulus as f64;
        let modulus = M::new(self.ciphertext_modulus);
        Lwe {
            param: self,
            delta,
            modulus,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Lwe<M: ModulusOps> {
    pub param: LweParam,
    pub delta: f64,
    pub modulus: M,
}

impl<M: ModulusOps> Lwe<M> {
    pub fn modulus(&self) -> &M {
        &self.modulus
    }

    pub fn dimension(&self) -> usize {
        self.param.dimension
    }

    pub fn encode(&self, m: u64) -> LwePlaintext<M::Elem> {
        assert!(m < self.param.message_modulus);
        LwePlaintext(
            self.modulus
                .elem_from((m as f64 * self.delta).round() as u64),
        )
    }

    pub fn decode(&self, LwePlaintext(pt): LwePlaintext<M::Elem>) -> u64 {
        let pt: u64 = self.modulus.elem_to(pt);
        (pt as f64 / self.delta).round() as u64 % self.param.message_modulus
    }

    pub fn sk_gen(&self, rng: impl RngCore) -> LweSecretKeyOwned<i32> {
        LweSecretKey::sample(self.dimension(), self.param.sk_distribution, rng)
    }

    pub fn sk_encrypt(
        &self,
        sk: &LweSecretKeyOwned<i32>,
        pt: LwePlaintext<M::Elem>,
        rng: &mut LweRng<impl RngCore, impl RngCore>,
    ) -> LweCiphertextOwned<M::Elem> {
        let mut ct = LweCiphertext::allocate(self.dimension());
        lwe::sk_encrypt(
            self.modulus(),
            &mut ct,
            sk,
            pt,
            self.param.noise_distribution,
            rng,
        );
        ct
    }

    pub fn decrypt(
        &self,
        sk: &LweSecretKeyOwned<i32>,
        ct: &LweCiphertextOwned<M::Elem>,
    ) -> LwePlaintext<M::Elem> {
        lwe::decrypt(self.modulus(), sk, ct)
    }

    pub fn ks_key_gen(
        &self,
        sk_from: &LweSecretKeyOwned<i32>,
        sk_to: &LweSecretKeyOwned<i32>,
        rng: &mut LweRng<impl RngCore, impl RngCore>,
    ) -> LweKeySwitchKeyOwned<M::Elem> {
        assert_eq!(self.dimension(), sk_to.dimension());
        let mut ks_key = LweKeySwitchKey::allocate(
            sk_from.dimension(),
            sk_to.dimension(),
            self.param.ks_decomposition_param,
        );
        lwe::ks_key_gen(
            self.modulus(),
            &mut ks_key,
            sk_from,
            sk_to,
            self.param.noise_distribution,
            rng,
        );
        ks_key
    }

    pub fn key_switch(
        &self,
        ks_key: &LweKeySwitchKeyOwned<M::Elem>,
        ct_from: &LweCiphertextOwned<M::Elem>,
    ) -> LweCiphertextOwned<M::Elem> {
        let mut ct_to = LweCiphertext::allocate(ks_key.to_dimension());
        lwe::key_switch(self.modulus(), &mut ct_to, ks_key, ct_from);
        ct_to
    }

    pub fn add(
        &self,
        ct_a: &LweCiphertextOwned<M::Elem>,
        ct_b: &LweCiphertextOwned<M::Elem>,
    ) -> LweCiphertextOwned<M::Elem> {
        let mut ct_c = ct_a.clone();
        self.modulus()
            .slice_add_assign(ct_c.as_mut(), ct_b.as_ref());
        ct_c
    }

    pub fn scalar_fma<'a, T>(
        &self,
        cts: impl IntoIterator<Item = &'a LweCiphertextOwned<M::Elem>>,
        scalars: impl IntoIterator<Item = T>,
    ) -> LweCiphertextOwned<M::Elem>
    where
        M: ElemFrom<T>,
    {
        let modulus = self.modulus();
        let mut ct_fma = LweCiphertext::allocate(self.dimension());
        izip_eq!(cts, scalars).for_each(|(ct, scalar)| {
            modulus.slice_scalar_fma(ct_fma.as_mut(), ct.as_ref(), &modulus.elem_from(scalar))
        });
        ct_fma
    }

    pub fn random_noiseless(
        &self,
        sk: &LweSecretKeyOwned<i32>,
        rng: &mut impl RngCore,
    ) -> (LwePlaintext<M::Elem>, LweCiphertextOwned<M::Elem>) {
        let modulus = self.modulus();
        let mut ct = LweCiphertext::allocate(self.dimension());
        modulus.sample_uniform_into(ct.as_mut(), rng);
        let a_sk = modulus.slice_dot_elem_from(ct.a(), sk.as_ref());
        let pt = LwePlaintext(modulus.sub(ct.b(), &a_sk));
        (pt, ct)
    }

    pub fn noise(
        &self,
        sk: &LweSecretKeyOwned<i32>,
        pt: &LwePlaintext<M::Elem>,
        ct: &LweCiphertextOwned<M::Elem>,
    ) -> i64 {
        let pt_noisy = self.decrypt(sk, ct);
        self.modulus.to_i64(self.modulus.sub(&pt_noisy.0, &pt.0))
    }

    pub fn ks_key_noise(
        &self,
        sk_from: &LweSecretKeyOwned<i32>,
        sk_to: &LweSecretKeyOwned<i32>,
        ks_key: &LweKeySwitchKeyOwned<M::Elem>,
    ) -> Vec<Vec<i64>> {
        let modulus = self.modulus();
        let decomposer = M::Decomposer::new(modulus.modulus(), ks_key.decomposition_param());
        izip_eq!(ks_key.cts_iter(), sk_from.as_ref())
            .map(|(ks_key_i, sk_from_i)| {
                izip_eq!(ks_key_i.iter(), decomposer.gadget_iter())
                    .map(|(ks_key_i_j, beta_j)| {
                        let pt = LwePlaintext(modulus.mul_elem_from(&beta_j, &-sk_from_i));
                        self.noise(sk_to, &pt, &ks_key_i_j.cloned())
                    })
                    .collect()
            })
            .collect()
    }
}

pub fn test_param(ciphertext_modulus: impl Into<Modulus>) -> LweParam {
    LweParam {
        message_modulus: 1 << 6,
        ciphertext_modulus: ciphertext_modulus.into(),
        dimension: 256,
        sk_distribution: Gaussian(3.19).into(),
        noise_distribution: Gaussian(3.19).into(),
        ks_decomposition_param: DecompositionParam {
            log_base: 8,
            level: 6,
        },
    }
}

#[test]
fn encrypt_decrypt() {
    fn run<M: ModulusOps>(param: LweParam) {
        let mut rng = StdLweRng::from_entropy();
        let lwe = param.build::<M>();
        let sk = lwe.sk_gen(&mut rng);
        for m in 0..param.message_modulus {
            let pt = lwe.encode(m);
            let ct = lwe.sk_encrypt(&sk, pt, &mut rng);
            assert_eq!(m, lwe.decode(pt));
            assert_eq!(m, lwe.decode(lwe.decrypt(&sk, &ct)));
        }
    }

    run::<Native>(test_param(Native::native()));
    run::<NonNativePowerOfTwo>(test_param(NonNativePowerOfTwo::new(50)));
    run::<Prime>(test_param(Prime::gen(50, 0)));
    run::<NativeRing>(test_param(Native::native()));
    run::<NonNativePowerOfTwoRing>(test_param(NonNativePowerOfTwo::new(50)));
    run::<PrimeRing>(test_param(Prime::gen(50, 0)));
}

#[test]
fn key_switch() {
    fn run<M: ModulusOps>(param: LweParam) {
        let mut rng = StdLweRng::from_entropy();
        let lwe_from = param.build::<M>();
        let lwe_to = param.dimension(2 * param.dimension).build::<M>();
        let sk_from = lwe_from.sk_gen(&mut rng);
        let sk_to = lwe_to.sk_gen(&mut rng);
        let ks_key = lwe_to.ks_key_gen(&sk_from, &sk_to, &mut rng);
        for m in 0..param.message_modulus {
            let pt = lwe_from.encode(m);
            let ct_from = lwe_from.sk_encrypt(&sk_from, pt, &mut rng);
            let ct_to = lwe_to.key_switch(&ks_key, &ct_from);
            assert_eq!(m, lwe_to.decode(lwe_to.decrypt(&sk_to, &ct_to)));
        }
    }

    run::<Native>(test_param(Native::native()));
    run::<NonNativePowerOfTwo>(test_param(NonNativePowerOfTwo::new(50)));
    run::<Prime>(test_param(Prime::gen(50, 0)));
    run::<NativeRing>(test_param(Native::native()));
    run::<NonNativePowerOfTwoRing>(test_param(NonNativePowerOfTwo::new(50)));
    run::<PrimeRing>(test_param(Prime::gen(50, 0)));
}
