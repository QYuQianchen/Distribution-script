use thiserror::Error;

/// Error type for validator registration.
#[derive(Debug, Error)]
pub enum ValidatorError {
    /// Error propagated by IO operations.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Error when the validator data file verification fails.
    #[error("validation failed: '{0}'")]
    ValidationError(String),

    /// Serde JSON Error.
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    
    /// Error when the ECDSA signature verification fails.
    #[error("ECDSA verification failed: '{0}'")]
    ECDSAVerficationError(String),

    /// Error when the BLS signature verification fails.
    #[error("BLS verification failed: '{0}'")]
    BLSVerificationError(String),

    /// Error when the other verification fails.
    #[error("Other verification failed: '{0}'")]
    OtherVerificationError(String),
}

/// Error type for subgraph.
#[derive(Debug, Error)]
pub enum SubgraphError {
    /// Error propagated by IO operations.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Error after trying requests with both production and development endpoints.
    #[error("All the subgraph requests failed")]
    AllRequestsFailed,

    /// Error when deduplicating addresses fails.
    #[error("Deduplicate addresses failed")]
    DedupAddressesFailed,
}

/// Application error type.
#[derive(Debug, Error)]
pub enum AppError {
    /// Error when the validator data file verification fails.
    #[error(transparent)]
    ValidatorError(#[from] ValidatorError),
}
