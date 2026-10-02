variable "project_id" {
  description = "Google Cloud Project ID for deploying the SentinelOps ADK Agent."
  type        = string
}

variable "region" {
  description = "Primary Google Cloud region for Vertex AI Agent Engine and Cloud Run."
  type        = string
  default     = "us-central1"
}

variable "agent_name" {
  description = "Kebab-case identifier for the SentinelOps multi-agent application."
  type        = string
  default     = "sentinel-ops-agent"
}

variable "container_image" {
  description = "Artifact Registry container image URI for the ADK agent server."
  type        = string
  default     = "us-central1-docker.pkg.dev/my-gcp-project/agentops/sentinel-ops-agent:latest"
}
