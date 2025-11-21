# IncidentResponder.AI

**Local Multi-Agent Cloud Security Analyst (with AWS Terraform Infra)**

An end-to-end autonomous SOC Tier-1 analyst system that simulates multi-agent incident response workflows using local AI agents. The system processes AWS GuardDuty findings through a coordinated investigation pipeline and generates comprehensive incident reports with MITRE ATT&CK mappings and remediation recommendations.

## 🎯 Project Overview

IncidentResponder.AI is a fully local, zero-cost security incident analysis system that:

- **Processes GuardDuty findings** through a multi-agent workflow
- **Correlates logs** from CloudTrail and VPC Flow Logs
- **Maps threats** to MITRE ATT&CK techniques using vector search
- **Generates remediation** steps with AWS-specific recommendations
- **Stores reports** in both JSON files and SQLite database
- **Runs entirely locally** with no cloud dependencies or costs
- **Includes Terraform** for future AWS deployment (optional)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GuardDuty Finding (JSON)                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator                              │
│  Coordinates multi-agent workflow and report generation      │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Log        │  │   Threat     │  │  Knowledge   │
│  Forensics   │─▶│ Attribution  │─▶│  Retrieval   │
│   Agent      │  │    Agent     │  │    Agent     │
└──────────────┘  └──────────────┘  └──────────────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Remediation Agent                           │
│         Generates AWS-specific remediation steps             │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   JSON       │  │   SQLite     │  │   Console    │
│   Report     │  │   Database   │  │   Output     │
└──────────────┘  └──────────────┘  └──────────────┘
```

## 🤖 Agents

### 1. Log Forensics Agent
- **Input**: GuardDuty JSON finding
- **Tasks**:
  - Parses GuardDuty finding structure
  - Extracts metadata (instance, region, user, API calls)
  - Correlates with simulated CloudTrail/VPC logs
  - Identifies key security indicators
- **Output**: Structured forensics summary

### 2. Threat Attribution Agent
- **Input**: Forensics summary
- **Tasks**:
  - Classifies threat category (Reconnaissance, C2, Exfiltration, etc.)
  - Maps to initial MITRE ATT&CK techniques
  - Generates reasoning trace
  - Calculates confidence score
- **Output**: Threat classification + MITRE technique candidates

### 3. Knowledge Retrieval Agent
- **Input**: Technique guess from attribution agent
- **Tasks**:
  - Performs vector search over MITRE embeddings
  - Retrieves detailed technique information
  - Returns technique ID, description, tactics, procedures
- **Output**: MITRE structured data with similarity scores

### 4. Remediation Agent
- **Input**: Threat classification + MITRE technique
- **Tasks**:
  - Generates AWS-specific remediation steps
  - Recommends IAM changes, network lockdown, key rotation
  - Provides step-by-step AWS CLI commands
  - Calculates priority and estimated time
- **Output**: Remediation steps with justification

## 📁 Project Structure

```
IncidentResponder-ai/
│
├── agents/
│   ├── __init__.py
│   ├── log_forensics_agent.py          # Log analysis agent
│   ├── threat_attribution_agent.py     # Threat classification agent
│   ├── knowledge_retrieval_agent.py    # MITRE knowledge search agent
│   └── remediation_agent.py           # Remediation planning agent
│
├── orchestrator/
│   ├── __init__.py
│   └── orchestrator.py                 # Main workflow coordinator
│
├── data/
│   ├── sample_guardduty_1.json         # EC2 port scan example
│   ├── sample_guardduty_2.json         # IAM credential exfiltration
│   ├── sample_guardduty_3.json         # S3 data exfiltration
│   ├── sample_guardduty_4.json         # EC2 DoS attack
│   ├── mitre_techniques.json           # MITRE ATT&CK techniques database
│   └── mitre_embeddings.npy            # Generated embeddings (optional)
│
├── logs/
│   ├── simulated_cloudtrail.json       # Sample CloudTrail logs
│   └── simulated_flowlogs.json         # Sample VPC Flow logs
│
├── terraform/
│   ├── main.tf                         # Main Terraform configuration
│   ├── variables.tf                    # Variable definitions
│   ├── lambda.tf                       # Lambda function definitions
│   ├── dynamodb.tf                     # DynamoDB table
│   ├── stepfunctions.tf                # Step Functions workflow
│   ├── iam_roles.tf                    # IAM roles and policies
│   ├── s3.tf                           # S3 buckets
│   └── outputs.tf                      # Terraform outputs
│
├── reports/                            # Generated investigation reports
│
├── utils/
│   ├── __init__.py
│   ├── db.py                           # SQLite database utilities
│   ├── embedding.py                    # MITRE embedding utilities
│   └── build_embeddings.py             # Embedding builder script
│
├── requirements.txt                    # Python dependencies
├── README.md                           # This file
└── incident_reports.db                 # SQLite database (generated)
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd IncidentResponder-ai
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Build MITRE embeddings (optional but recommended):**
   ```bash
   python utils/build_embeddings.py
   ```
   
   **Note**: If you have an OpenAI API key, set it as an environment variable for better embeddings:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"  # Linux/Mac
   set OPENAI_API_KEY=your-api-key-here       # Windows
   ```
   
   If no API key is provided, the system will use a fallback embedding method.

4. **Run the orchestrator:**
   ```bash
   python orchestrator/orchestrator.py data/sample_guardduty_1.json
   ```

## 🤖 LLM Configuration

All LLM interactions flow through the modular `llm/` provider layer. Configure providers via `config.yaml` (checked into the repo) or environment variables (which override the YAML file).

### Configuration Fields (`config.yaml`)

```yaml
ai_provider: "lmstudio"        # Options: openai, anthropic, gemini, lmstudio, ollama, dummy
ai_endpoint: "http://localhost:1234"
ai_api_key: null
model_name: "local-model"
```

### Environment Overrides

| Variable         | Description                                   |
|------------------|-----------------------------------------------|
| `AI_PROVIDER`     | Provider name (`openai`, `anthropic`, etc.)   |
| `AI_API_KEY`      | API key for cloud providers                   |
| `AI_ENDPOINT`     | Custom endpoint for LM Studio / Ollama        |
| `AI_MODEL_NAME`   | Model identifier                              |

### Provider Examples

**Fallback / Rule-Based Mode (default)**
```bash
set AI_PROVIDER=dummy
python orchestrator/orchestrator.py data/sample_guardduty_1.json
```

**LM Studio (local)**
```bash
set AI_PROVIDER=lmstudio
set AI_ENDPOINT=http://localhost:1234
set AI_MODEL_NAME=local-model
python orchestrator/orchestrator.py data/sample_guardduty_1.json
```

**OpenAI**
```bash
set AI_PROVIDER=openai
set AI_API_KEY=sk-your-key
set AI_MODEL_NAME=gpt-4o-mini
python orchestrator/orchestrator.py data/sample_guardduty_1.json
```

**Anthropic**
```bash
set AI_PROVIDER=anthropic
set AI_API_KEY=sk-ant-your-key
set AI_MODEL_NAME=claude-3-sonnet-20240229
```

**Gemini**
```bash
set AI_PROVIDER=gemini
set AI_API_KEY=your-google-key
set AI_MODEL_NAME=gemini-1.5-flash
```

**Ollama**
```bash
set AI_PROVIDER=ollama
set AI_ENDPOINT=http://localhost:11434
set AI_MODEL_NAME=llama3
```

If a provider or API key is missing, the system automatically falls back to the `DummyProvider`, which returns deterministic rule-based messages so the agents can continue operating offline.

### Example Output

```
2025-02-20 12:52:00 - INFO - Processing incident from: data/sample_guardduty_1.json
2025-02-20 12:52:00 - INFO - === Step 1: Log Forensics Analysis ===
2025-02-20 12:52:01 - INFO - Forensics analysis complete. Alert type: Recon:EC2/PortProbeUnprotectedPort
2025-02-20 12:52:01 - INFO - === Step 2: Threat Attribution ===
2025-02-20 12:52:01 - INFO - Threat attribution complete. Primary technique: T1595
2025-02-20 12:52:01 - INFO - === Step 3: MITRE Knowledge Retrieval ===
2025-02-20 12:52:02 - INFO - Knowledge retrieval complete. Found 3 similar techniques
2025-02-20 12:52:02 - INFO - === Step 4: Remediation Planning ===
2025-02-20 12:52:02 - INFO - Generated 5 remediation steps
2025-02-20 12:52:02 - INFO - === Incident Processing Complete ===

============================================================
INCIDENT INVESTIGATION REPORT SUMMARY
============================================================
Alert: Recon:EC2/PortProbeUnprotectedPort
Severity: 5.0
MITRE Technique: T1595 - Active Scanning
Threat Category: Reconnaissance
Confidence: 75.00%
Remediation Priority: Medium
Remediation Steps: 5
============================================================

Full report saved to: reports/2025-02-20T12-52-00Z_report.json
```

## 📊 Report Format

Reports are saved in JSON format with the following structure:

```json
{
  "timestamp": "2025-02-20T12:52:00Z",
  "alert": "Recon:EC2/PortProbeUnprotectedPort",
  "severity": 5.0,
  "parsed_details": {
    "resource": {
      "type": "EC2",
      "instance_id": "i-0123456789abcdef0",
      "ip_address": "10.0.1.100"
    },
    "key_indicators": [
      "Suspicious outbound connection to 198.51.100.42",
      "EC2 instance i-0123456789abcdef0 involved"
    ]
  },
  "threat_classification": {
    "category": "Reconnaissance",
    "subcategory": "Network Scanning",
    "description": "EC2 instance performing network scanning or port probing"
  },
  "mitre_mapping": {
    "primary_technique": "T1595",
    "technique_name": "Active Scanning",
    "technique_description": "Adversaries may scan victim infrastructure...",
    "tactic": "Reconnaissance"
  },
  "reasoning_trace": "...",
  "recommended_actions": [
    {
      "step": 1,
      "action": "Isolate EC2 Instance",
      "description": "...",
      "aws_command": "aws ec2 modify-instance-attribute...",
      "category": "Containment"
    }
  ],
  "confidence": 0.75,
  "analysis_trace": { ... }
}
```

## 🔍 How MITRE Search Works

The Knowledge Retrieval Agent uses vector embeddings to search the MITRE ATT&CK knowledge base:

1. **Embedding Generation**: MITRE techniques are embedded using either:
   - OpenAI `text-embedding-3-small` (if API key provided)
   - Fallback hash-based embeddings (no API key required)

2. **Vector Search**: Query embeddings are compared against technique embeddings using cosine similarity

3. **Result Ranking**: Techniques are ranked by similarity score and returned with metadata

4. **Exact Matching**: The system also attempts exact ID matching (e.g., "T1595")

## 📝 Adding New Logs

### Adding Sample GuardDuty Findings

1. Create a new JSON file in `data/` following the GuardDuty finding format
2. Reference it when running the orchestrator:
   ```bash
   python orchestrator/orchestrator.py data/your_finding.json
   ```

### Adding Simulated Logs

1. **CloudTrail logs**: Add entries to `logs/simulated_cloudtrail.json`
2. **VPC Flow logs**: Add entries to `logs/simulated_flowlogs.json`

The Log Forensics Agent will automatically correlate findings with these logs based on:
- Instance IDs
- IP addresses
- IAM usernames
- Timestamps

## ☁️ Terraform Deployment (Optional)

The Terraform configuration provides an AWS-ready deployment architecture:

### Architecture Components

- **4 Lambda Functions** (one per agent)
- **Step Functions State Machine** (orchestrates workflow)
- **DynamoDB Table** (stores incident reports)
- **S3 Buckets** (log storage and reports)
- **IAM Roles & Policies** (least privilege access)
- **CloudWatch Logs** (monitoring and debugging)

### Deployment Steps

1. **Prerequisites:**
   - AWS CLI configured
   - Terraform installed (>= 1.0)
   - Appropriate AWS permissions

2. **Initialize Terraform:**
   ```bash
   cd terraform
   terraform init
   ```

3. **Review and customize variables:**
   ```bash
   terraform plan
   ```

4. **Deploy infrastructure:**
   ```bash
   terraform apply
   ```

5. **View outputs:**
   ```bash
   terraform output
   ```

### Free Tier Considerations

- **DynamoDB**: On-demand pricing (25 GB storage free, 25 read/write units free)
- **Lambda**: 1M free requests/month, 400,000 GB-seconds compute
- **Step Functions**: 4,000 state transitions free/month
- **S3**: 5 GB storage, 20,000 GET requests, 2,000 PUT requests free
- **CloudWatch Logs**: 5 GB ingestion, 5 GB storage free

**Note**: The Terraform configuration is provided for future deployment. The system runs fully locally without requiring AWS resources.

## 🧪 Testing

Run the orchestrator with different sample findings:

```bash
# EC2 port scan
python orchestrator/orchestrator.py data/sample_guardduty_1.json

# IAM credential exfiltration
python orchestrator/orchestrator.py data/sample_guardduty_2.json

# S3 data exfiltration
python orchestrator/orchestrator.py data/sample_guardduty_3.json

# EC2 DoS attack
python orchestrator/orchestrator.py data/sample_guardduty_4.json
```

## 📊 Database Queries

The SQLite database can be queried directly:

```python
from utils.db import IncidentDB

db = IncidentDB()

# List recent reports
reports = db.list_reports(limit=10)
for report in reports:
    print(f"ID: {report['id']}, Alert: {report['alert_type']}")

# Get specific report
report = db.get_report(report_id=1)
print(report)
```

## 🛠️ Customization

### Adding New MITRE Techniques

1. Edit `data/mitre_techniques.json`
2. Add new technique entries with required fields:
   ```json
   {
     "technique_id": "TXXXX",
     "name": "Technique Name",
     "description": "Description...",
     "tactic": "Tactic Name",
     "platform": "Cloud",
     "data_sources": ["Source1", "Source2"]
   }
   ```
3. Rebuild embeddings:
   ```bash
   python utils/build_embeddings.py
   ```

### Modifying Agent Logic

Each agent is modular and can be customized:

- **Log Forensics Agent**: Modify `_parse_guardduty()` or `_correlate_logs()`
- **Threat Attribution Agent**: Update `_map_to_mitre()` for new technique mappings
- **Knowledge Retrieval Agent**: Adjust `search()` parameters or similarity thresholds
- **Remediation Agent**: Add new remediation steps in `_generate_steps()`

## 📈 Resume Section

### Technical Skills Demonstrated

- **Multi-Agent Systems**: Orchestrated 4 specialized AI agents for incident response
- **Security Analysis**: Implemented GuardDuty finding parsing and log correlation
- **MITRE ATT&CK**: Vector search and technique mapping using embeddings
- **AWS Services**: Terraform infrastructure for Lambda, Step Functions, DynamoDB, S3
- **Python Development**: Modular, production-ready code with error handling
- **Database Design**: SQLite schema for incident report storage
- **DevOps**: Infrastructure as Code with Terraform, IAM policy design

### Project Highlights

- **Zero-Cost Local Execution**: Runs entirely locally with no cloud dependencies
- **Production-Ready Code**: Comprehensive error handling, logging, and documentation
- **Scalable Architecture**: Terraform-ready for AWS deployment
- **Extensible Design**: Modular agents allow easy customization and extension

## 🐛 Troubleshooting

### Embeddings Not Found

If you see warnings about missing embeddings:
```bash
python utils/build_embeddings.py
```

### Import Errors

Ensure you're running from the project root:
```bash
cd IncidentResponder-ai
python orchestrator/orchestrator.py data/sample_guardduty_1.json
```

### Database Locked

If SQLite database is locked, ensure no other process is accessing it.

## 📄 License

This project is provided as-is for educational and demonstration purposes.

## 🤝 Contributing

This is a demonstration project. Feel free to fork and customize for your needs.

## 📧 Contact

For questions or issues, please refer to the project documentation or create an issue in the repository.

---

**Built with ❤️ for autonomous security operations**

