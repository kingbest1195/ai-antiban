//! Active probes of the audit that talk to public services: which DNS resolver sees the
//! requests of this machine (`whoami`) and whether UDP leaves through the same address as HTTP
//! (`stun`). Every network call goes through the replaceable sources of `auditor::seams`.

pub mod stun;
pub mod whoami;
