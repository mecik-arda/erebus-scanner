use std::time::Duration;

pub struct RateLimiter {
    pub current_concurrency: usize,
    pub min_concurrency: usize,
    pub max_concurrency: usize,
    pub threshold_ms: u64,
}

impl RateLimiter {
    pub fn new(initial: usize, min: usize, max: usize, threshold: u64) -> Self {
        Self {
            current_concurrency: initial,
            min_concurrency: min,
            max_concurrency: max,
            threshold_ms: threshold,
        }
    }

    pub fn adjust(&mut self, average_latency: Duration, packet_loss: bool) -> usize {
        if packet_loss || average_latency.as_millis() as u64 > self.threshold_ms {
            self.current_concurrency = (self.current_concurrency / 2).max(self.min_concurrency);
        } else if self.current_concurrency < self.max_concurrency {
            self.current_concurrency += 10;
        }
        self.current_concurrency
    }
}