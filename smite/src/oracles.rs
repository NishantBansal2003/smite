/// Result of an oracle evaluation
pub enum OracleResult {
    /// The check passed
    Pass,
    /// The check failed with a reason
    Fail(String),
}

/// `Oracle` evaluates a condition against some context
pub trait Oracle<C> {
    /// Evaluate the oracle against the given context
    fn evaluate(&self, context: &C) -> OracleResult;
    /// Return the name of this oracle for logging
    fn name(&self) -> &str;
}
