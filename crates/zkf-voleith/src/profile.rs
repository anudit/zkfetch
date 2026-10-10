//! Opt-in stage timings. Only public stage names, durations and circuit sizes.
use serde::Serialize;
use std::cell::RefCell;
use web_time::Instant;
#[derive(Default, Serialize)]
pub struct Profile {
    pub stages: Vec<Stage>,
    pub committed_bits: usize,
    pub constraints: usize,
}
#[derive(Serialize)]
pub struct Stage {
    pub name: &'static str,
    pub ms: f64,
}
thread_local! { static ACTIVE: RefCell<Option<Profile>> = const { RefCell::new(None) }; }
pub fn enable(enabled: bool) {
    ACTIVE.with(|p| *p.borrow_mut() = enabled.then(Profile::default));
}
pub fn take() -> Option<Profile> {
    ACTIVE.with(|p| p.borrow_mut().take())
}
pub fn circuit(bits: usize, constraints: usize) {
    ACTIVE.with(|p| {
        if let Some(p) = p.borrow_mut().as_mut() {
            p.committed_bits = bits;
            p.constraints = constraints;
        }
    });
}
pub struct Lap(Option<Instant>);
impl Lap {
    pub fn new() -> Self {
        Self(ACTIVE.with(|p| p.borrow().is_some().then(Instant::now)))
    }
    pub fn mark(&mut self, name: &'static str) {
        if let Some(at) = self.0.as_mut() {
            let now = Instant::now();
            let ms = now.duration_since(*at).as_secs_f64() * 1000.0;
            *at = now;
            ACTIVE.with(|p| {
                if let Some(p) = p.borrow_mut().as_mut() {
                    p.stages.push(Stage { name, ms });
                }
            });
        }
    }
}
