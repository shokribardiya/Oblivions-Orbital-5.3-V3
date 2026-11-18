# Oblivions-Orbital-5.3-
1. What does this software actually do?
2. <img width="1923" height="817" alt="file_000000006b148243a1f387ca609fae5e" src="https://github.com/user-attachments/assets/b011413b-77ab-4787-a969-275d046161a5" />

Orbital takes in data, organizes it, identifies connections within it, performs analysis, and presents the results in an understandable format. For example, imagine you have a file containing information about a thousand cities around the world. Orbital can: Read the data from the file. Import the data into a database. Store the cities as distinct entities. Identify relationships between the data. Search through the data. Visualize these connections as a graph (diagram). Use local artificial intelligence to answer questions about the data. Now, let’s take a look at three of its components.
# OBLIVION ORBITAL 5.3
Bardiya Shokri / Oblivion

**Intelligence. Engineering. Systems.**

Oblivion Orbital 5.3 is a single-file, local-first Python application that brings together a knowledge-graph workspace, code-intelligence utilities, data analysis through UMBRA, and the embedded Web / GOTHAM workspace.

The application is designed to run as a local web interface while keeping its primary application data in SQLite databases and local files.

> **Release:** 5.3  
> **Runtime:** Python 3.10+  
> **Main entry point:** `orbital5.3.py`  
> **Default interface:** `http://127.0.0.1:8080`
<img width="1672" height="941" alt="file_00000000b3b48212b07bc6e4dd54c19b" src="https://github.com/user-attachments/assets/eb3a7d41-5edf-4425-962d-d15f676ffab2" />

---

## Overview

Orbital is organized as three integrated workspaces:

| Module | Purpose |
|---|---|
| **Orbital Core** | Knowledge graphs, document ingestion, code intelligence, platform administration, authentication and audit logging. |
| **UMBRA** | Dataset ingestion, profiling, ontology and entity management, graph analysis, search, analytics, evidence tracking and an optional local-model agent. |
| **Web / GOTHAM** | Embedded web workspace with scoped exposure analysis, threat-intelligence workflows, reporting, exports and the Rasht geospatial atlas. |

The modules are presented through one integrated application shell and run within the same Orbital process.

## Core capabilities
<img width="1708" height="882" alt="Screenshot 2026-11-18 121118" src="https://github.com/user-attachments/assets/e99a0227-fd32-4a8b-876e-e686454cab1b" />

### Orbital Core

- SQLite-backed knowledge graphs with nodes, edges, source files and sentence-level associations.
- Text processing and graph construction from imported documents.
- Graph exploration, search and node-detail inspection.
- Platform records for products, teams, channels, plans and related workspace items.
- User authentication, role-aware access, session handling and audit logging.
- File upload and document extraction for supported formats.
- Embedded code-intelligence utilities for Python diagnostics and completion.
- Optional integrations with Pyflakes, Jedi and Pluggy, with standard-library fallbacks where implemented.
- A subprocess-based code execution path with a timeout and platform-dependent resource limits.

### UMBRA — Data Intelligence
<img width="1706" height="896" alt="Screenshot 2026-11-18 121007" src="https://github.com/user-attachments/assets/284ee929-0722-4dc7-8f8a-4b53ba908702" />

UMBRA is a local-first data and knowledge-graph subsystem. Its pipeline is designed around:

`DATA → INGEST → PROFILE → ONTOLOGY → ENTITIES → GRAPH → SEARCH → ANALYTICS → AI AGENT → EVIDENCE`

Implemented capabilities include:

- Importing CSV, JSON and JSONL datasets.
- Persisting source datasets and records in SQLite.
- Inferring column types and generating dataset profiles.
- Detecting semantic hints such as email, URL, phone, names, addresses, coordinates, timestamps and identifiers.
- Managing object types, link types, objects and relationships.
- Building and traversing a knowledge graph.
- Searching stored objects using a TF-IDF-based retrieval path.
- Finding graph paths and calculating graph centrality.
- Running aggregate statistics and read-only SQL analytics.
- Maintaining evidence and provenance links back to source datasets and records.
- Recording operational events and AI conversations.
- Connecting optionally to a local LM Studio OpenAI-compatible endpoint for model-assisted analysis and tool use.

The agent is designed to use registered tools rather than directly modifying the database. Its available tools include object search, object/evidence inspection, graph traversal, path finding, centrality, dataset inspection, statistics and read-only SQL queries.
![Uploading Screenshot 2026-11-18 120953.png…]()


### Web / GOTHAM

GOTHAM is a scoped exposure-detection and threat-intelligence workspace. Its collection workflow is restricted to domains explicitly added to the configured scope.

Implemented capabilities include:

- An explicit domain allow-list.
- Scoped crawling with depth and request-rate controls.
- `robots.txt` checks.
- Detection patterns for exposed secrets, credentials and selected personal-data formats.
- Masking of detected values in findings.
- Confidence and severity scoring based on collected signals.
- Local IOC-feed correlation.
- Scam / phishing text checks using a small in-project neural-network implementation, with a heuristic fallback when the optional numerical dependency is unavailable.
- Case creation and status management.
- Reports and exports in CSV, JSON and GEXF formats.
- Optional report narration through a locally configured LM Studio endpoint.

GOTHAM is intended for assets that the operator owns or is authorized to assess. Adding a domain to scope is an explicit operator action; the collector is not designed as an unrestricted internet crawler.

### Rasht Atlas

The embedded GOTHAM workspace includes a geospatial atlas for Rasht and its surroundings.

- The configured study-area bounding box is approximately `37.20–37.36° N` and `49.48–49.75° E`.
- The application can request selected OpenStreetMap vector features through an Overpass API endpoint.
- Supported feature categories include roads, waterways, settlements, land-use areas, administrative boundaries and optional building footprints.
- Imported GeoJSON can be stored locally and exported again.
- Atlas metadata records the source, retrieval time, bounding box and feature counts.

**Data and connectivity note:** the source code does not ship with a complete Rasht map extract. The vector dataset must be downloaded or imported. The map's background tile layers use external tile services, so the atlas is not fully offline by default. OpenStreetMap community data may be incomplete and should not be treated as a certified municipal inventory.

---
<img width="1712" height="850" alt="Screenshot 2026-11-18 120910" src="https://github.com/user-attachments/assets/2f0c859d-18c7-4c9e-9b7e-41dd4712f41b" />

## Architecture

```text
OBLIVION ORBITAL 5.3
│
├── Orbital Core
│   ├── HTTP application server
│   ├── Authentication / sessions / roles
│   ├── Audit log and platform store
│   ├── SQLite knowledge graph
│   ├── File ingestion and text extraction
│   └── Code intelligence
│
├── UMBRA
│   ├── Dataset ingestion and profiling
│   ├── Ontology and entity management
│   ├── Graph and search engines
│   ├── Analytics and evidence engines
│   └── Optional LM Studio agent
│
└── Web / GOTHAM
    ├── Scoped collector
    ├── Findings and cases
    ├── Scam / IOC analysis
    ├── Reports and exports
    └── Rasht geospatial atlas
```

The application shell serves the Orbital, UMBRA and Web/GOTHAM interfaces through a single local HTTP process. UMBRA also contains its own internal application components and storage configuration.

## Requirements

- Python **3.10 or newer**.
- No mandatory third-party packages are required by the Orbital core.
- Optional packages can enable enhanced functionality:

```bash
pip install pyflakes jedi pluggy numpy
```

| Package | Optional use |
|---|---|
| `pyflakes` | More detailed Python diagnostics. |
| `jedi` | Context-aware Python completion. |
| `pluggy` | Plugin-hook support. |
| `numpy` | Numerical operations used by selected UMBRA graph, vector and model functions. |

If optional packages are missing, some features use reduced or fallback implementations. The exact feature availability depends on which optional packages are installed.
![Uploading Screenshot 2026-11-18 120846.png…]()

## Getting started

1. Download or clone this repository.
2. Open a terminal in the directory containing the source file.
3. Start Orbital:

```bash
python orbital5.3.py
```

4. Open the local interface:

```text
http://127.0.0.1:8080
```

You can change the bind address and port:

```bash
python orbital5.3.py --host 127.0.0.1 --port 8080
```

To display additional diagnostic logging:

```bash
python orbital5.3.py --verbose
```

To print the application version:

```bash
python orbital5.3.py --version
```

The default bind address is `127.0.0.1`, keeping the interface local to the machine.

## Data storage

The Orbital core creates its working data directory relative to the process working directory:

```text
data/
├── knowledge.db
├── files/
├── gotham_exports/
├── gotham_scam_model.json
├── gotham_ioc_feed.json
└── gotham_rasht/
    ├── rasht_features.geojson
    └── metadata.json
```

UMBRA uses its own home directory, which defaults to:

```text
~/.umbra/
├── config.json
├── umbra.db
├── umbra.log
└── objects/
```

The UMBRA home directory can be changed with the `UMBRA_HOME` environment variable.

Keep backups of the relevant data directories before moving, replacing or upgrading the application source.

## Local model integration

UMBRA and GOTHAM can optionally communicate with a local LM Studio server through an OpenAI-compatible API.

The default LM Studio chat-completions endpoint used by GOTHAM is:

```text
http://localhost:1234/v1/chat/completions
```

The UMBRA configuration supports a local host, port, model selection, generation settings and an optional embedding-model setting. A compatible model must be loaded and the local server must be running before model-assisted functions can work.

LM Studio is optional. Core data ingestion, storage and non-LLM analysis functions are designed to remain available without it.

## Security and operational notes

- Keep the default localhost binding unless remote access is intentionally required.
- Do not expose the application to an untrusted network without reviewing authentication, access controls, firewall rules and deployment configuration.
- Use GOTHAM only for domains and systems for which you have authorization.
- GOTHAM's scope allow-list is an operational boundary; verify the target domain before adding it.
- Findings are pattern-based indicators and require human validation. They are not proof of compromise.
- Local storage does not automatically mean every feature is offline. GOTHAM collection, Overpass map retrieval, external map tiles and optional LM Studio calls have their own connectivity requirements.
- Back up SQLite databases and uploaded source files regularly.

## Project status

Orbital 5.3 is an integrated software build that combines several subsystems in one Python source file. Its capabilities should be evaluated feature by feature in the target environment. Optional dependencies, operating-system differences, local model availability and external data services can affect runtime behavior.

This repository describes the implementation in the 5.3 source. It does not claim that every optional integration is enabled by default or that the application is a production-hardened security platform.

## Data attribution

The Rasht Atlas can use OpenStreetMap data. When using or redistributing OSM-derived data, follow the OpenStreetMap attribution requirements and the Open Database License (ODbL).

- OpenStreetMap copyright and attribution: https://www.openstreetmap.org/copyright
- Overpass API: https://wiki.openstreetmap.org/wiki/Overpass_API

## Credits

**OBLIVION**  
*Intelligence. Engineering. Systems.*

Orbital is developed as part of the Oblivion software and AI engineering initiative.
