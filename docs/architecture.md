# `fuel-telemetry` Architecture Design

This document describes the `fuel-telemetry` architectural design using the [C4 Model](https://c4model.com/).

### Level 1: Context Diagram

The Context Diagram provides a high-level overview of `fuel-telemetry`, its users, and its interactions with external systems.

```mermaid
graph TD
  subgraph Users
    A[Smart Contract Developers]
    B[Frontend Developers]
    C[Node Operators]
  end

  subgraph User-facing External Systems
    D[Rust Binaries]
    E[Non-Rust Binaries]
  end

  subgraph fuel-telemetry
    F[fuel_telemetry API]
    G[FileWatcher]
    H[ProcessWatcher]
    I[SystemInfoWatcher]
  end

  subgraph External Systems
    J[InfluxDB API]
  end

  A -->|Uses| D
  A -->|Uses| E
  B -->|Uses| D
  B -->|Uses| E
  C -->|Uses| D
  C -->|Uses| E

  D -->|Creates tracing subscriber| F

  F -->|"Starts FileWatcher<br />automatically via<br />telemetry_init()"| G
  E -->|"Writes telemetry files<br />via language libraries<br />then starts FileWatcher<br />via fuel-telemetry binary"| G
  D -->|"Starts FileWatcher<br />manually via<br />start()"| G

  G -->|Connects to| J
  G -->|Starts ProcessWatcher| H
  G -->|Starts SystemInfoWatcher| I
```

### Level 2: Container Diagram

The Container Diagram shows the main containers of `fuel-telemetry` and their interactions.

```mermaid
graph TD
  subgraph fuel-telemetry
    A[Externally created<br />telemetry files]
    B[fuel_telemetry API]
    C[FileWatcher]
    D[ProcessWatcher]
    E[SystemInfoWatcher]
  end

    F[Sysinfo API]

  subgraph External Systems
    G[InfluxDB API]
  end

  B -->|"Writes telemetry files via<br />macros eg debug!()"| C
  A -->|"Are ingested and<br />cleaned up by"| C

  C -->|Sends Metrics| G
  C -->|Gathers process<br />telemetry via| D
  C -->|Gathers system<br />telemetry via| E
  D --> F
  E --> F
```

### Level 3: Component Diagram

The Component Diagram breaks down each container into its individual components and shows their interactions.

```mermaid
graph TD
  subgraph fuel-telemetry
    A[fuel_telemetry API]
    B[FileWatcher]
    C[ProcessWatcher]
    D[SystemInfoWatcher]
  end

  subgraph External Systems
    E[InfluxDB API]
    F[Disk]
    G[Sysinfo API]
  end

  A -->|Writes telemetry files| F
  B -->|Ingests and cleans up| F
  C -->|Writes telemetry files| F
  D -->|Writes telemetry files| F

  B -->|Sends Metrics| E
  B -->|Starts| C
  B -->|Starts| D
  C -->|Gathers process telemetry| G
  D -->|Gathers system telemetry| G
```

### Level 4: Code Diagram

The Code Diagram provides a detailed view of the code structure within each component. This level is typically represented using class diagrams, package diagrams, or similar.

```mermaid
classDiagram
  class TelemetryLayer {
   telemetry_init()
   ::new()
   ::new_global_default()
   ::new_global_default_with_filewatcher()
   .set_global_default()
  }

  class FileWatcher {
   ::new()
   .start()
  }

  class ProcessWatcher {
   ::new()
   .start()
  }

  class SystemInfoWatcher {
   ::new()
   .start()
  }

```