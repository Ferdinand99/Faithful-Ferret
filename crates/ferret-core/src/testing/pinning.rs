//! Hand-made manifest views for tests. Behind `test-support`; never part of
//! a release, where the floors can only be seeded from a decrypted manifest.

use crate::error::Error;
use crate::item::Manifest;
use crate::pinning::{MethodManifestView, Pinned};

/// The view of a manifest, as [`Pinned::seed_from_manifest`] builds it.
pub fn view_from_manifest(manifest: &Manifest) -> Result<MethodManifestView, Error> {
    MethodManifestView::from_manifest(manifest)
}

/// Seeds the floors from a view that may have been made by hand.
pub fn seed_from_view(pinned: &mut Pinned, view: &MethodManifestView) -> Result<(), Error> {
    pinned.seed_from_view(view)
}
