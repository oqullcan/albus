// extensible dpi evasion strategies

pub mod adaptive;
pub mod disorder;
pub mod fake_ttl;
pub mod split;
pub mod ttl_probe;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BypassMode {
    StealthAuto,
    SniSplit,
    Disorder,
    FakeTtl,
}
