# Infrastructure, Containers, Kubernetes, IaC, CI/CD & Serverless Reference (Module 12)

> OWASP Top 10:2025: A02, A03, A08 · Category lookup: [owasp-mapping.md](./owasp-mapping.md)

> OWASP Cheat Sheets:
> - [Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
> - [Kubernetes Security](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
> - [Infrastructure as Code Security](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
> - [CI/CD Security](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)
> - [GitHub Actions Security](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html)
> - [Serverless FaaS Security](https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html)

Evaluate ONLY the section(s) matching the confirmed infrastructure.

---

## 12A. Docker & Container Security [SKIP IF NOT USING DOCKER]
- [ ] **12A.1** **Non-Root User**: Dockerfile defines and switches to a non-root `USER` (never runs app as UID 0 / `root`).
- [ ] **12A.2** **Drop Capabilities**: Runtime drops all Linux capabilities (`cap_drop: [ALL]`) and adds back only strictly required capabilities.
- [ ] **12A.3** **No Privilege Escalation**: Runtime sets `--security-opt=no-new-privileges:true`.
- [ ] **12A.4** **Never Expose Docker Socket**: `/var/run/docker.sock` is NEVER mounted into application containers (equivalent to root host takeover).
- [ ] **12A.5** **Read-Only Root Filesystem**: Containers use `read_only: true` with explicit tmpfs/volume mounts only for required writable directories.
- [ ] **12A.6** **No Build-Time Secrets in Layers**: Secrets are never baked into `ARG`, `ENV`, or `COPY`; use BuildKit secret mounts (`RUN --mount=type=secret,...`) and `.dockerignore` (exclude `.env`, `.git`, keys).
- [ ] **12A.7** **Minimal, Pinned, Scanned Images**: Multi-stage builds exclude compilers/dev tools; base images use minimal variants (distroless/Alpine) pinned by version/digest and scanned with Trivy/Grype; memory/CPU limits and `HEALTHCHECK` are configured.

## 12B. Kubernetes Security [SKIP IF NOT USING K8S]
- [ ] **12B.1** **Pod Security Standards (Restricted)**: Enforce `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }`, `readOnlyRootFilesystem: true`, and `seccompProfile: RuntimeDefault`. Reject `privileged: true`, `hostNetwork`/`hostPID`, and `hostPath` mounts (scanner `K8S-01`).
- [ ] **12B.2** **RBAC Least Privilege**: Avoid wildcard `*` in Roles/ClusterRoles; avoid `cluster-admin` ServiceAccounts; set `automountServiceAccountToken: false` when pods don't call K8s API.
- [ ] **12B.3** **NetworkPolicies**: Default-deny ingress/egress NetworkPolicies restrict pod-to-pod lateral movement across namespaces.
- [ ] **12B.4** **Secrets Protection**: Sensitive values use External Secrets Operator / KMS-encrypted Secrets (never plain ConfigMaps); `etcd` is encrypted at rest.
- [ ] **12B.5** **Control Plane & Admission**: API server isn't exposed unnecessarily, audit logging is enabled, and admission policies (Kyverno / OPA Gatekeeper) block `:latest`, privileged, or vulnerable images.

## 12C. CI/CD & GitHub Actions Security [LOAD IF USING CI/CD]
- [ ] **12C.1** **Least-Privilege `GITHUB_TOKEN`**: Workflows explicitly set `permissions: read-all` (or minimal `contents: read`) at workflow/job level.
- [ ] **12C.2** **Pin Third-Party Actions by Full Commit SHA**: Use `uses: actions/checkout@<40-char-sha> # v4` instead of mutable `@v4` or `@main` tags.
- [ ] **12C.3** **Script Injection Prevention**: Never interpolate untrusted event context (`${{ github.event.issue.title }}`, `pull_request.title`, `comment.body`, `head_ref`) directly inside `run:` bash blocks — pass via `env:` variables.
- [ ] **12C.4** **Dangerous `pull_request_target` Guard**: Avoid checking out untrusted PR head code inside `pull_request_target` workflows that hold repo secrets.
- [ ] **12C.5** **Secret & Security Gates**: SAST, secret scanning, SCA, container/IaC scans, branch protection, required PR reviews, and OIDC short-lived cloud auth (instead of static long-lived cloud keys) protect production deployments.

## 12D. Infrastructure as Code (IaC) & Cloud [SKIP IF NOT USING]
- [ ] **12D.1** IaC templates (Terraform/OpenTofu/CloudFormation/Pulumi) are scanned in CI (`Checkov`, `Trivy config`, `TFLint`).
- [ ] **12D.2** Terraform state files are stored remotely in encrypted, versioned, locked, private storage (never committed to git — `.tfstate` contains plaintext secrets).
- [ ] **12D.3** Object storage (S3/GCS/Azure Blob) blocks public access by default and enforces encryption at rest + TLS in transit.
- [ ] **12D.4** Cloud IAM avoids `*` actions/resources; workloads use short-lived IAM roles/OIDC instead of static access keys; security groups avoid `0.0.0.0/0` on DB/SSH/admin ports.
- [ ] **12D.5** Cloud metadata endpoints require IMDSv2 (`http_tokens = "required"`) and restrict container/pod access.

## 12E. Serverless / FaaS Security [SKIP IF NOT USING]
- [ ] **12E.1** Each function uses a dedicated minimal IAM execution role (no shared admin wildcard role).
- [ ] **12E.2** All event triggers (API Gateway, S3 object keys, SQS/Kafka payloads, SNS, webhooks) are treated as untrusted input and validated.
- [ ] **12E.3** Warm execution reuse hygiene: `/tmp` and global state never cache user secrets/cross-tenant data across invocations.
- [ ] **12E.4** **Infinite Trigger Loop Defense**: Prevent event recursion loops (e.g., Lambda writes to Bucket A -> S3 trigger invokes same Lambda -> writes to Bucket A -> runaway billing & DoS); configure reserved concurrency, DLQs, and timeouts.
