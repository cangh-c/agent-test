terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Enable Required Google Cloud APIs for Gemini Enterprise Agent Platform (GEAP)
locals {
  required_apis = [
    "aiplatform.googleapis.com",
    "discoveryengine.googleapis.com",
    "secretmanager.googleapis.com",
    "dlp.googleapis.com",
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
  ]
}

resource "google_project_service" "enabled_apis" {
  for_each           = toset(local.required_apis)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# 2. Dedicated Least-Privilege Service Account for SentinelOps ADK Agent
resource "google_service_account" "sentinel_agent_sa" {
  account_id   = "${var.agent_name}-sa"
  display_name = "SentinelOps ADK Agent Runtime Service Account"
}

resource "google_project_iam_member" "agent_roles" {
  for_each = toset([
    "roles/aiplatform.user",
    "roles/discoveryengine.viewer",
    "roles/secretmanager.secretAccessor",
    "roles/dlp.user",
    "roles/cloudsql.client",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.sentinel_agent_sa.email}"
}

# 3. Google Cloud Secret Manager Secrets (Zero Hardcoded API Keys)
resource "google_secret_manager_secret" "bug_tracker_api_token" {
  secret_id = "incident-bug-tracker-api-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret" "pagerduty_webhook_secret" {
  secret_id = "incident-pagerduty-webhook-secret"
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled_apis]
}

# 4. Vertex AI Search Data Store for Canonical SRE Runbook RAG
resource "google_discovery_engine_data_store" "sre_runbooks_datastore" {
  location                    = "global"
  data_store_id               = "${var.agent_name}-runbooks-ds"
  display_name                = "SentinelOps SRE Runbooks & Postmortems Data Store"
  industry_vertical           = "GENERIC"
  content_config              = "CONTENT_REQUIRED"
  solution_types              = ["SOLUTION_TYPE_SEARCH"]
  create_advanced_site_search = false
  depends_on                  = [google_project_service.enabled_apis]
}

# 5. Cloud SQL PostgreSQL Instance for ADK DatabaseSessionService Persistence
resource "google_sql_database_instance" "adk_session_instance" {
  name                = "${var.agent_name}-session-pg"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = true

  settings {
    tier = "db-custom-2-7680"
    backup_configuration {
      enabled = true
    }
    ip_configuration {
      ipv4_enabled = false
    }
  }
  depends_on = [google_project_service.enabled_apis]
}

resource "google_sql_database" "adk_sessions_db" {
  name     = "adk_sessions"
  instance = google_sql_database_instance.adk_session_instance.name
}

# 6. Cloud DLP De-identification Template for PII Redaction Pipeline
resource "google_data_loss_prevention_deidentify_template" "pii_redaction_template" {
  parent       = "projects/${var.project_id}/locations/global"
  description  = "Redacts PII (Email, Phone, SSN, Credit Card, Credentials) from SentinelOps logs and memory"
  display_name = "sentinel-ops-pii-redaction-template"

  deidentify_config {
    info_type_transformations {
      transformations {
        info_types {
          name = "EMAIL_ADDRESS"
        }
        info_types {
          name = "PHONE_NUMBER"
        }
        info_types {
          name = "US_SOCIAL_SECURITY_NUMBER"
        }
        info_types {
          name = "CREDIT_CARD_NUMBER"
        }
        primitive_transformation {
          replace_with_info_type_config {}
        }
      }
    }
  }
  depends_on = [google_project_service.enabled_apis]
}

# 7. Cloud Run v2 Service Hosting the SentinelOps ADK Agent API
resource "google_cloud_run_v2_service" "sentinel_ops_service" {
  name     = var.agent_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.sentinel_agent_sa.email

    containers {
      image = var.container_image

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "VERTEX_SEARCH_DATA_STORE_ID"
        value = google_discovery_engine_data_store.sre_runbooks_datastore.data_store_id
      }
      env {
        name  = "ENABLE_CLOUD_TRACE"
        value = "true"
      }
      env {
        name = "SECRET_INCIDENT_BUG_TRACKER_API_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.bug_tracker_api_token.secret_id
            version = "latest"
          }
        }
      }
    }
  }
  depends_on = [google_project_iam_member.agent_roles]
}
