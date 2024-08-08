mod method;
mod structure;

#[cfg(test)]
pub(crate) mod test;

pub(crate) use method::{decomposed_fma, decomposed_fma_prep};

pub use method::{
    auto_key_gen, automorphism_in_place, automorphism_prep_in_place, decrypt, key_switch_in_place,
    key_switch_prep_in_place, ks_key_gen, pk_encrypt, pk_gen, prepare_auto_key, prepare_ks_key,
    sample_extract, sk_encrypt, sk_encrypt_with_pt_in_b,
};
pub use structure::{
    RlweAutoKey, RlweAutoKeyMutView, RlweAutoKeyOwned, RlweAutoKeyView, RlweCiphertext,
    RlweCiphertextList, RlweCiphertextListMutView, RlweCiphertextListOwned, RlweCiphertextListView,
    RlweCiphertextMutView, RlweCiphertextOwned, RlweCiphertextView, RlweKeySwitchKey,
    RlweKeySwitchKeyMutView, RlweKeySwitchKeyOwned, RlweKeySwitchKeyView, RlwePlaintext,
    RlwePlaintextMutView, RlwePlaintextOwned, RlwePlaintextView, RlwePublicKey,
    RlwePublicKeyMutView, RlwePublicKeyOwned, RlwePublicKeyView, RlweSecretKey,
    RlweSecretKeyMutView, RlweSecretKeyOwned, RlweSecretKeyView,
};