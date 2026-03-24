use crate::errors::AppError;
use crate::insights::InsightsEngine;
use crate::simulation::{SimulationEngine, SimulationResult, SorobanResources};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing;
use utoipa::ToSchema;
use uuid::Uuid;

/// Unique identifier for a job
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct JobId(pub Uuid);

impl JobId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for JobId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Status of a job in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobStatus {
    /// Job is waiting to be processed
    Queued,
    /// Job is currently being processed
    Processing,
    /// Job completed successfully
    Completed,
    /// Job failed with an error
    Failed,
    /// Job was cancelled by user
    Cancelled,
}

/// Type of analysis job
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobType {
    /// Single contract analysis
    Analyze,
    /// Compare two contracts
    Compare,
    /// Optimize resource limits
    OptimizeLimits,
}

/// Payload for different job types
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum JobPayload {
    Analyze {
        contract_id: String,
        function_name: String,
        args: Option<Vec<String>>,
        ledger_overrides: Option<HashMap<String, String>>,
    },
    Compare {
        mode: String,
        current_wasm: Option<Vec<u8>>,
        base_wasm: Option<Vec<u8>>,
        contract_id: Option<String>,
        function_name: Option<String>,
        args: Vec<String>,
    },
    OptimizeLimits {
        contract_id: String,
        function_name: String,
        args: Vec<String>,
        safety_margin: f64,
    },
}

/// Progress information for a job
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobProgress {
    /// Progress percentage (0-100)
    pub percent: u8,
    /// Human-readable status message
    pub message: String,
    /// Timestamp of last update
    pub updated_at: DateTime<Utc>,
}

impl JobProgress {
    pub fn new(percent: u8, message: impl Into<String>) -> Self {
        Self {
            percent,
            message: message.into(),
            updated_at: Utc::now(),
        }
    }
}

/// Result of a completed job
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "status", content = "data")]
pub enum JobResult {
    Success {
        /// Resource report for analyze jobs
        #[serde(skip_serializing_if = "Option::is_none")]
        resources: Option<SorobanResources>,
        /// Full simulation result
        #[serde(skip_serializing_if = "Option::is_none")]
        simulation_result: Option<SimulationResult>,
        /// Optimization report
        #[serde(skip_serializing_if = "Option::is_none")]
        optimization: Option<serde_json::Value>,
        /// Comparison report
        #[serde(skip_serializing_if = "Option::is_none")]
        comparison: Option<serde_json::Value>,
    },
    Failed {
        error: String,
        error_type: String,
    },
}

/// Webhook configuration for job notifications
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebhookConfig {
    /// URL to POST when job completes or fails
    pub callback_url: String,
    /// Optional custom headers to include
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    /// Secret for HMAC signature (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// A job in the queue
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Job {
    pub id: JobId,
    pub job_type: JobType,
    pub status: JobStatus,
    pub payload: JobPayload,
    pub progress: JobProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JobResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<WebhookConfig>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Job timeout in seconds
    pub timeout_secs: u64,
    /// Error message if job failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl Job {
    pub fn new(
        id: JobId,
        job_type: JobType,
        payload: JobPayload,
        webhook: Option<WebhookConfig>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            id,
            job_type,
            status: JobStatus::Queued,
            payload,
            progress: JobProgress::new(0, "Queued"),
            result: None,
            webhook,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            timeout_secs,
            error_message: None,
        }
    }

    pub fn start(&mut self) {
        self.status = JobStatus::Processing;
        self.started_at = Some(Utc::now());
        self.progress = JobProgress::new(10, "Processing started");
    }

    pub fn complete(&mut self, result: JobResult) {
        self.status = JobStatus::Completed;
        self.result = Some(result);
        self.completed_at = Some(Utc::now());
        self.progress = JobProgress::new(100, "Completed");
    }

    pub fn fail(&mut self, error: String, error_type: String) {
        self.status = JobStatus::Failed;
        self.error_message = Some(error.clone());
        self.result = Some(JobResult::Failed {
            error,
            error_type,
        });
        self.completed_at = Some(Utc::now());
        self.progress = JobProgress::new(0, "Failed");
    }

    pub fn cancel(&mut self) {
        self.status = JobStatus::Cancelled;
        self.completed_at = Some(Utc::now());
        self.progress = JobProgress::new(0, "Cancelled");
    }

    pub fn update_progress(&mut self, percent: u8, message: impl Into<String>) {
        self.progress = JobProgress::new(percent, message);
    }
}

/// Errors that can occur in job operations
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("Job not found: {0}")]
    NotFound(JobId),
    #[error("Job cannot be cancelled in status: {0:?}")]
    CannotCancel(JobStatus),
    #[error("Job processing failed: {0}")]
    ProcessingFailed(String),
    #[error("Webhook delivery failed: {0}")]
    WebhookFailed(String),
}

/// Configuration for the job queue
#[derive(Debug, Clone)]
pub struct JobQueueConfig {
    /// Default job timeout in seconds
    pub job_timeout_secs: u64,
    /// How often to run cleanup (seconds)
    pub cleanup_interval_secs: u64,
    /// How long to retain completed jobs (seconds)
    pub retention_secs: u64,
    /// Webhook call timeout (seconds)
    pub webhook_timeout_secs: u64,
    /// Max webhook retry attempts
    pub webhook_max_retries: u32,
}

impl Default for JobQueueConfig {
    fn default() -> Self {
        Self {
            job_timeout_secs: 300,      // 5 minutes
            cleanup_interval_secs: 3600, // 1 hour
            retention_secs: 3600,        // 1 hour
            webhook_timeout_secs: 10,    // 10 seconds
            webhook_max_retries: 3,
        }
    }
}

/// Thread-safe job queue using DashMap
pub struct JobQueue {
    jobs: Arc<DashMap<JobId, Job>>,
    sender: mpsc::Sender<JobId>,
    config: JobQueueConfig,
}

impl JobQueue {
    pub fn new(config: JobQueueConfig) -> (Self, mpsc::Receiver<JobId>) {
        let (sender, receiver) = mpsc::channel(1000);
        let jobs = Arc::new(DashMap::new());

        let queue = Self {
            jobs: Arc::clone(&jobs),
            sender,
            config,
        };

        (queue, receiver)
    }

    /// Submit a new job to the queue
    pub async fn submit(
        &self,
        job_type: JobType,
        payload: JobPayload,
        webhook: Option<WebhookConfig>,
    ) -> JobId {
        let id = JobId::new();
        let job = Job::new(
            id,
            job_type,
            payload,
            webhook,
            self.config.job_timeout_secs,
        );

        self.jobs.insert(id, job);
        
        // Send job ID to worker
        if let Err(e) = self.sender.send(id).await {
            tracing::error!("Failed to send job to worker: {}", e);
        }

        tracing::info!(job_id = %id, "Job submitted");
        id
    }

    /// Get the current status of a job
    pub fn get_status(&self, id: &JobId) -> Option<Job> {
        self.jobs.get(id).map(|entry| entry.clone())
    }

    /// Cancel a job if it's queued or processing
    pub fn cancel(&self, id: &JobId) -> Result<Job, JobError> {
        let mut entry = self.jobs
            .get_mut(id)
            .ok_or(JobError::NotFound(*id))?;

        match entry.status {
            JobStatus::Queued | JobStatus::Processing => {
                entry.cancel();
                tracing::info!(job_id = %id, "Job cancelled");
                Ok(entry.clone())
            }
            status => Err(JobError::CannotCancel(status)),
        }
    }

    /// Update job progress
    pub fn update_progress(&self, id: &JobId, percent: u8, message: impl Into<String>) {
        if let Some(mut entry) = self.jobs.get_mut(id) {
            entry.update_progress(percent, message);
        }
    }

    /// Complete a job with a result
    pub fn complete_job(&self, id: &JobId, result: JobResult) {
        if let Some(mut entry) = self.jobs.get_mut(id) {
            entry.complete(result);
            tracing::info!(job_id = %id, "Job completed");
        }
    }

    /// Mark a job as failed
    pub fn fail_job(&self, id: &JobId, error: String, error_type: String) {
        if let Some(mut entry) = self.jobs.get_mut(id) {
            entry.fail(error.clone(), error_type.clone());
            tracing::error!(job_id = %id, error = %error, "Job failed");
        }
    }

    /// Get a clone of the jobs map for the worker
    pub fn jobs_clone(&self) -> Arc<DashMap<JobId, Job>> {
        Arc::clone(&self.jobs)
    }

    /// Spawn a background cleanup task
    pub fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let jobs = Arc::clone(&self.jobs);
        let interval_secs = self.config.cleanup_interval_secs;
        let retention_secs = self.config.retention_secs as i64;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));
            
            loop {
                interval.tick().await;
                
                let now = Utc::now();
                let to_remove: Vec<JobId> = jobs
                    .iter()
                    .filter(|entry| {
                        let job = entry.value();
                        // Remove completed/failed/cancelled jobs older than retention period
                        if matches!(job.status, JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled) {
                            if let Some(completed_at) = job.completed_at {
                                let age = now.signed_duration_since(completed_at).num_seconds();
                                return age > retention_secs;
                            }
                        }
                        false
                    })
                    .map(|entry| *entry.key())
                    .collect();

                for id in &to_remove {
                    jobs.remove(id);
                    tracing::debug!(job_id = %id, "Cleaned up old job");
                }

                if !to_remove.is_empty() {
                    tracing::info!(count = to_remove.len(), "Cleaned up old jobs");
                }
            }
        })
    }
}

/// Worker that processes jobs from the queue
pub struct JobWorker {
    receiver: mpsc::Receiver<JobId>,
    jobs: Arc<DashMap<JobId, Job>>,
    engine: SimulationEngine,
    insights_engine: InsightsEngine,
    config: JobQueueConfig,
    http_client: Client,
}

impl JobWorker {
    pub fn new(
        receiver: mpsc::Receiver<JobId>,
        jobs: Arc<DashMap<JobId, Job>>,
        engine: SimulationEngine,
        insights_engine: InsightsEngine,
        config: JobQueueConfig,
    ) -> Self {
        Self {
            receiver,
            jobs,
            engine,
            insights_engine,
            config,
            http_client: Client::new(),
        }
    }

    /// Start the worker loop
    pub async fn run(mut self) {
        tracing::info!("Job worker started");

        while let Some(job_id) = self.receiver.recv().await {
            // Clone Arc references for the spawned task
            let jobs = Arc::clone(&self.jobs);
            let engine = self.engine.clone();
            let insights = self.insights_engine.clone();
            let config = self.config.clone();
            let http_client = self.http_client.clone();

            // Spawn a task for each job to isolate failures
            tokio::spawn(async move {
                // Get job and mark as started
                let job = {
                    let mut entry = jobs.get_mut(&job_id);
                    if let Some(ref mut job) = entry {
                        job.start();
                        job.clone()
                    } else {
                        tracing::warn!(job_id = %job_id, "Job not found when starting");
                        return;
                    }
                };

                // Process the job with timeout
                let timeout = Duration::from_secs(job.timeout_secs);
                let result = tokio::time::timeout(
                    timeout,
                    Self::process_job(job.clone(), engine, insights, Arc::clone(&jobs)),
                ).await;

                // Handle result
                match result {
                    Ok(Ok(job_result)) => {
                        // Success
                        if let Some(mut entry) = jobs.get_mut(&job_id) {
                            entry.complete(job_result.clone());
                        }
                        
                        // Send webhook
                        if let Some(webhook) = &job.webhook {
                            Self::send_webhook(
                                http_client,
                                webhook,
                                &job_id,
                                JobStatus::Completed,
                                Some(&job_result),
                                config.webhook_timeout_secs,
                                config.webhook_max_retries,
                            ).await;
                        }
                    }
                    Ok(Err(e)) => {
                        // Processing error
                        let error_msg = e.to_string();
                        if let Some(mut entry) = jobs.get_mut(&job_id) {
                            entry.fail(error_msg.clone(), "ProcessingError".to_string());
                        }
                        
                        if let Some(webhook) = &job.webhook {
                            Self::send_webhook(
                                http_client,
                                webhook,
                                &job_id,
                                JobStatus::Failed,
                                None,
                                config.webhook_timeout_secs,
                                config.webhook_max_retries,
                            ).await;
                        }
                    }
                    Err(_) => {
                        // Timeout
                        let error_msg = format!("Job timed out after {} seconds", job.timeout_secs);
                        if let Some(mut entry) = jobs.get_mut(&job_id) {
                            entry.fail(error_msg.clone(), "Timeout".to_string());
                        }
                        
                        if let Some(webhook) = &job.webhook {
                            Self::send_webhook(
                                http_client,
                                webhook,
                                &job_id,
                                JobStatus::Failed,
                                None,
                                config.webhook_timeout_secs,
                                config.webhook_max_retries,
                            ).await;
                        }
                    }
                }
            });
        }

        tracing::info!("Job worker stopped");
    }

    /// Process a single job
    async fn process_job(
        job: Job,
        engine: SimulationEngine,
        insights_engine: InsightsEngine,
        jobs: Arc<DashMap<JobId, Job>>,
    ) -> Result<JobResult, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(job_id = %job.id, job_type = ?job.job_type, "Processing job");

        match &job.payload {
            JobPayload::Analyze { contract_id, function_name, args, ledger_overrides } => {
                Self::process_analyze_job(
                    job.id,
                    contract_id,
                    function_name,
                    args.clone().unwrap_or_default(),
                    ledger_overrides.clone(),
                    engine,
                    insights_engine,
                    jobs,
                ).await
            }
            JobPayload::Compare { mode, current_wasm, base_wasm, contract_id, function_name, args } => {
                // For now, return a placeholder - full compare implementation would need more refactoring
                Ok(JobResult::Success {
                    resources: None,
                    simulation_result: None,
                    optimization: None,
                    comparison: Some(serde_json::json!({
                        "mode": mode,
                        "status": "Compare jobs not yet fully implemented"
                    })),
                })
            }
            JobPayload::OptimizeLimits { contract_id, function_name, args, safety_margin } => {
                Self::process_optimize_job(
                    job.id,
                    contract_id,
                    function_name,
                    args.clone(),
                    *safety_margin,
                    engine,
                    jobs,
                ).await
            }
        }
    }

    /// Process an analyze job
    async fn process_analyze_job(
        job_id: JobId,
        contract_id: &str,
        function_name: &str,
        args: Vec<String>,
        ledger_overrides: Option<HashMap<String, String>>,
        engine: SimulationEngine,
        insights_engine: InsightsEngine,
        jobs: Arc<DashMap<JobId, Job>>,
    ) -> Result<JobResult, Box<dyn std::error::Error + Send + Sync>> {
        // Update progress
        if let Some(mut entry) = jobs.get_mut(&job_id) {
            entry.update_progress(30, "Running simulation");
        }

        // Run simulation
        let sim_result = engine
            .simulate_from_contract_id(contract_id, function_name, args, ledger_overrides)
            .await?;

        // Update progress
        if let Some(mut entry) = jobs.get_mut(&job_id) {
            entry.update_progress(70, "Generating insights");
        }

        // Generate insights
        let _insights = insights_engine.analyze(&sim_result.resources);

        // Update progress
        if let Some(mut entry) = jobs.get_mut(&job_id) {
            entry.update_progress(90, "Finalizing results");
        }

        Ok(JobResult::Success {
            resources: Some(sim_result.resources.clone()),
            simulation_result: Some(sim_result),
            optimization: None,
            comparison: None,
        })
    }

    /// Process an optimize limits job
    async fn process_optimize_job(
        job_id: JobId,
        contract_id: &str,
        function_name: &str,
        args: Vec<String>,
        safety_margin: f64,
        engine: SimulationEngine,
        jobs: Arc<DashMap<JobId, Job>>,
    ) -> Result<JobResult, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(mut entry) = jobs.get_mut(&job_id) {
            entry.update_progress(30, "Running optimization");
        }

        let report = engine
            .optimize_limits(contract_id, function_name, args, safety_margin)
            .await?;

        if let Some(mut entry) = jobs.get_mut(&job_id) {
            entry.update_progress(90, "Finalizing results");
        }

        Ok(JobResult::Success {
            resources: None,
            simulation_result: None,
            optimization: Some(serde_json::to_value(report)?),
            comparison: None,
        })
    }

    /// Send webhook notification with retry logic
    async fn send_webhook(
        client: Client,
        config: &WebhookConfig,
        job_id: &JobId,
        status: JobStatus,
        result: Option<&JobResult>,
        timeout_secs: u64,
        max_retries: u32,
    ) {
        let payload = serde_json::json!({
            "job_id": job_id.to_string(),
            "status": status,
            "result": result,
            "timestamp": Utc::now().to_rfc3339(),
        });

        let timeout = Duration::from_secs(timeout_secs);
        let mut last_error = None;

        for attempt in 1..=max_retries {
            let request = client
                .post(&config.callback_url)
                .json(&payload)
                .timeout(timeout);

            // Add custom headers if provided
            let request = if let Some(headers) = &config.headers {
                headers.iter().fold(request, |req, (k, v)| req.header(k, v))
            } else {
                request
            };

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        tracing::info!(
                            job_id = %job_id,
                            attempt,
                            "Webhook delivered successfully"
                        );
                        return;
                    } else {
                        let status = response.status();
                        tracing::warn!(
                            job_id = %job_id,
                            attempt,
                            status = %status,
                            "Webhook returned non-success status"
                        );
                        last_error = Some(format!("HTTP {}", status));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        job_id = %job_id,
                        attempt,
                        error = %e,
                        "Webhook delivery failed"
                    );
                    last_error = Some(e.to_string());
                }
            }

            // Exponential backoff before retry
            if attempt < max_retries {
                let backoff = Duration::from_millis(1000 * 2_u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
            }
        }

        tracing::error!(
            job_id = %job_id,
            error = ?last_error,
            "Webhook delivery failed after all retries"
        );
    }
}

/// Request to submit a new job
#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitJobRequest {
    pub job_type: JobType,
    pub payload: JobPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<WebhookConfig>,
    /// Optional custom timeout in seconds (overrides default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

/// Response from submitting a job
#[derive(Debug, Serialize, ToSchema)]
pub struct SubmitJobResponse {
    pub job_id: String,
    pub status: JobStatus,
    pub message: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_id_generation() {
        let id1 = JobId::new();
        let id2 = JobId::new();
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn test_job_id_from_str() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let job_id: JobId = uuid_str.parse().unwrap();
        assert_eq!(job_id.to_string(), uuid_str);
    }

    #[test]
    fn test_job_lifecycle() {
        let mut job = Job::new(
            JobId::new(),
            JobType::Analyze,
            JobPayload::Analyze {
                contract_id: "test".to_string(),
                function_name: "test".to_string(),
                args: None,
                ledger_overrides: None,
            },
            None,
            300,
        );

        assert_eq!(job.status, JobStatus::Queued);
        assert_eq!(job.progress.percent, 0);

        job.start();
        assert_eq!(job.status, JobStatus::Processing);
        assert_eq!(job.progress.percent, 10);
        assert!(job.started_at.is_some());

        job.update_progress(50, "Halfway");
        assert_eq!(job.progress.percent, 50);
        assert_eq!(job.progress.message, "Halfway");

        let result = JobResult::Success {
            resources: None,
            simulation_result: None,
            optimization: None,
            comparison: None,
        };
        job.complete(result);
        assert_eq!(job.status, JobStatus::Completed);
        assert_eq!(job.progress.percent, 100);
        assert!(job.completed_at.is_some());
    }

    #[test]
    fn test_job_cancel() {
        let mut job = Job::new(
            JobId::new(),
            JobType::Analyze,
            JobPayload::Analyze {
                contract_id: "test".to_string(),
                function_name: "test".to_string(),
                args: None,
                ledger_overrides: None,
            },
            None,
            300,
        );

        job.cancel();
        assert_eq!(job.status, JobStatus::Cancelled);
        assert!(job.completed_at.is_some());
    }

    #[test]
    fn test_job_fail() {
        let mut job = Job::new(
            JobId::new(),
            JobType::Analyze,
            JobPayload::Analyze {
                contract_id: "test".to_string(),
                function_name: "test".to_string(),
                args: None,
                ledger_overrides: None,
            },
            None,
            300,
        );

        job.fail("Something went wrong".to_string(), "TestError".to_string());
        assert_eq!(job.status, JobStatus::Failed);
        assert_eq!(job.error_message, Some("Something went wrong".to_string()));
        assert!(job.completed_at.is_some());
    }

    #[tokio::test]
    async fn test_job_queue_submit() {
        let config = JobQueueConfig::default();
        let (queue, _receiver) = JobQueue::new(config);

        let job_id = queue.submit(
            JobType::Analyze,
            JobPayload::Analyze {
                contract_id: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".to_string(),
                function_name: "hello".to_string(),
                args: Some(vec![]),
                ledger_overrides: None,
            },
            None,
        ).await;

        let status = queue.get_status(&job_id);
        assert!(status.is_some());
        assert_eq!(status.unwrap().status, JobStatus::Queued);
    }

    #[tokio::test]
    async fn test_job_queue_cancel() {
        let config = JobQueueConfig::default();
        let (queue, _receiver) = JobQueue::new(config);

        let job_id = queue.submit(
            JobType::Analyze,
            JobPayload::Analyze {
                contract_id: "test".to_string(),
                function_name: "test".to_string(),
                args: None,
                ledger_overrides: None,
            },
            None,
        ).await;

        let cancelled = queue.cancel(&job_id);
        assert!(cancelled.is_ok());
        assert_eq!(cancelled.unwrap().status, JobStatus::Cancelled);

        // Cannot cancel again
        let result = queue.cancel(&job_id);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_job_queue_not_found() {
        let config = JobQueueConfig::default();
        let (queue, _receiver) = JobQueue::new(config);

        let fake_id = JobId::new();
        let result = queue.cancel(&fake_id);
        assert!(matches!(result, Err(JobError::NotFound(_))));
    }
}
