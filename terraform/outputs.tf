output "cloud_run_service_uri" {
  description = "Deployed URL of the SentinelOps ADK Agent service."
  value       = google_cloud_run_v2_service.sentinel_ops_service.uri
}

output "agent_service_account_email" {
  description = "Least-privilege IAM Service Account running the ADK agent."
  value       = google_service_account.sentinel_agent_sa.email
}

output "vertex_search_datastore_id" {
  description = "Vertex AI Search Data Store ID for SRE runbooks."
  value       = google_discovery_engine_data_store.sre_runbooks_datastore.data_store_id
}

output "dlp_deidentify_template_id" {
  description = "Cloud DLP De-identify template resource name."
  value       = google_data_loss_prevention_deidentify_template.pii_redaction_template.id
}
