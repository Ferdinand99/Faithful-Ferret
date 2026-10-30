//! The vault store: one write transaction per call, on a `&mut Connection`, with
//! no HTTP and no kit in sight. Spec: Fase 1 § 8.1, § 8.3.
