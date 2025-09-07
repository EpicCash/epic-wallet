use rand::RngCore;
/// A simple deterministic generator: a counter.
///
/// `StepRng` yields an infinite stream of values, starting from `state` and
/// increasing by `step` each time.
#[derive(Debug, Clone)]
pub struct StepRng {
    state: u64,
    step: u64,
}

impl StepRng {
    /// Create a new `StepRng` with the given starting state and step size.
    pub fn new(state: u64, step: u64) -> StepRng {
        StepRng { state, step }
    }
}

impl RngCore for StepRng {
    fn next_u32(&mut self) -> u32 {
        let value = self.state as u32;
        self.state = self.state.wrapping_add(self.step);
        value
    }

    fn next_u64(&mut self) -> u64 {
        let value = self.state;
        self.state = self.state.wrapping_add(self.step);
        value
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest);
    }

}
