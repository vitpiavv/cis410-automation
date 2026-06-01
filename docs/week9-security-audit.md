# Week 9 Security Audit — cis410-deploy-sa

**Project: cis410-vp** 

**Date: 6/1/2026** <!-- date completed -->

**Auditor: Vitaliy Piankov** <!-- your name -->

---

## 1. IAM Audit Results

### Before — Week 8 Configuration (over-permissioned)

| Role | Scope | Problem |

|---|---|---|

| roles/run.admin | Project | Overly broad — grants ability to delete services and modify IAM, not just deploy |

| roles/storage.admin | Project | Overly broad — grants access to ALL GCS buckets in the project |

| roles/artifactregistry.writer | Project | Acceptable — scoped to push images only |

| roles/viewer | Project | Acceptable — read-only project metadata |

| roles/iam.serviceAccountUser | Compute SA | Required — needed to act as Compute Engine default SA |

### After — Week 9 Least-Privilege Fix

| Role | Scope | Why Sufficient |

|---|---|---|

| roles/run.developer | Project | Deploy only — cannot delete services or modify IAM |

| roles/storage.admin | tfstate bucket only | Scoped to one bucket — not all storage |

| roles/artifactregistry.writer | Project | Unchanged — push images only |

| roles/viewer | Project | Unchanged — read project metadata |

| roles/iam.serviceAccountUser | Compute SA | Unchanged — required for Cloud Run deployment |

---

## 2. Secret Manager Migration

- **Secret created: my-super-secret-value** `flask-app-secret`

- **Replication:** automatic

- **Access granted to:** `cis410-deploy-sa` — roles/secretmanager.secretAccessor on this secret only

- **Access granted to: 573801145027-compute@developer.gserviceaccount.com** ` — roles/secretmanager.secretAccessor on this secret only (required for Cloud Run runtime access)

- **Cloud Run update:** APP_SECRET environment variable mounted from Secret Manager at runtime

---

## 3. Monitoring Configuration

- **Log-based alert:** `cis410-flask-app-alert` — fires on severity>=WARNING for cis410-flask-app

- **Notification channel: vitpia@students.highline.edu** <!-- your student email -->

- **Billing budget:** `cis410-monthly-budget` — $20 limit, alerts at 50% / 90% / 100%

---

## 4. Reflection

**Q1: Why is roles/run.admin inappropriate for a CI/CD pipeline service account?**

It's too broad which gives too much access. Meaning that if anyone got a hold of the account they'd have too many permissions. The new permission is more restrictive, meaning it gives less permissions. 

---

**Q2: What is the security difference between storing a secret in GitHub Secrets vs. Google Secret Manager?**

With google secrets manager there's a full audit log, fine-grained IAM, automatic versioning, and runtime access. While Github secrets don't have those features by default. Having the full audit trail in google makes it much safer to store secrets vs github's solution. 

---

**Q3: A coworker says "I will clean up IAM permissions after the project launches. For now I need everything to work fast." What is the risk of this approach?**

It's dangerous because people often forget to implement the right permissions after deploying to production. On top of that, scope creep might make it much more difficult to implement correct IAM permissions after everything is done. It's best to implement proper IAM permissions during the build process in order to correctly integrate everything. 