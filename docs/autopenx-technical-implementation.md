# AutoPenX Technical Implementation

## Overview

AutoPenX is a CTF/web challenge automation platform built around a multi-phase solve pipeline, a persistent knowledge base, and a browser-friendly UI. The system is designed to move quickly from initial reconnaissance into AI-assisted exploitation while preserving observability and feedback loops.

## Core goals

- Reduce time from target input to high-confidence attack strategy.
- Use deterministic probes first, then escalate to AI workers only when needed.
- Persist successful patterns so later challenges can reuse prior experience.
- Show the full solving process in the UI, including parallel worker activity.
- Keep all learning, routing, and reporting non-blocking so failures degrade gracefully.

## Main mechanisms

### 1. Fast identification and fast-track solving

Purpose:
- Recognize simple challenges quickly.
- Detect visible source code or obvious vulnerability fingerprints.
- Skip unnecessary scanning when a direct AI solve is likely to succeed.

Where it lives:
- `autopnex/ctf/solve_pipeline.py`
- `autopnex/web/api.py`

How it works:
- The pipeline first attempts a lightweight knowledge match.
- If the target looks like a source-exposed single-vulnerability challenge, `_try_fast_track_direct()` launches one high-budget worker immediately.
- This bypasses long exploratory phases and gets the model into the exploit loop faster.

Effect:
- Greatly reduces latency on warm-up, source-leak, and one-shot logic challenges.
- Helps the system spend model budget on reasoning instead of redundant probing.

### 2. Phase 0 knowledge matching

Purpose:
- Reuse previously solved patterns.
- Bias the solver toward historically successful routes.

Where it lives:
- `autopnex/ctf/knowledge_learner.py`
- `autopnex/ctf/solve_pipeline.py`

How it works:
- `KnowledgeLearner` loads `ctf_knowledge.json` via the unified schema layer.
- It compares current blackboard evidence, tech stack, params, and form signatures to stored patterns.
- On a match, the pipeline stores a route hint and exposes it to later phases.

Effect:
- Improves route selection on repeat/variant challenges.
- Reduces blind exploration when the target resembles a prior solve.

Current limitation:
- The `patterns` list is only useful once enough successful solves have been written back. Right now the system is stronger on route weights and payload reuse than on dense pattern memory.

### 3. Parallel route scan

Purpose:
- Produce a fast, deterministic first-pass map of likely attack surfaces.
- Feed the AI with better evidence before it starts reasoning.

Where it lives:
- `autopnex/ctf/solve_pipeline.py`
- `autopnex/ctf/parallel_route_scan.py`

How it works:
- In hybrid or parallel-scan mode, the pipeline runs a short scan phase before the multi-agent orchestration.
- Results are written back into the blackboard and can trigger short-circuit solve behavior.
- Scan results are also used to dynamically assign phase 2 workers.

Effect:
- Faster route prioritization.
- Better prompt quality for AI workers.
- More deterministic coverage of common CTF entry points.

### 4. Three-worker parallel AI racing

Purpose:
- Attack a target from multiple angles concurrently.
- Maximize the chance that at least one worker reaches the winning path quickly.

Where it lives:
- `autopnex/ctf/phase2_runner.py`
- `autopnex/ctf/solve_pipeline.py`

How it works:
- Phase 2 creates three worker threads by default.
- Each worker gets its own session, LLM client, tool router, and strategy hint.
- Workers share a `DiscoveryBroadcast` so one worker’s findings can be injected into others.
- Cancellation is cooperative: once one worker finds a flag, the others are signaled to stop.
- Each worker tracks turns, API calls, tokens, duplicate tool calls, stagnation, discoveries, and tool unlocks.

Effect:
- Best for medium-complexity challenges with several plausible branches.
- The discovery broadcast helps workers avoid isolated exploration.
- The worker summaries are valuable for auditability and later tuning.

Why it matters:
- Without parallelization, a single worker can waste time on an unproductive route.
- With three workers, the platform can simultaneously test different hypotheses, payload families, or route variants.

### 5. Knowledge base automatic sedimentation

Purpose:
- Turn successful solves into reusable memory.
- Adjust route priorities based on what actually worked.

Where it lives:
- `autopnex/ctf/experience_writer.py`
- `autopnex/ctf/knowledge_learner.py`
- `autopnex/ctf/knowledge_schema.py`
- `ctf_knowledge.json`

How it works:
- Successful solves are written through `ExperienceWriter` and `KnowledgeLearner`.
- The schema layer migrates and preserves older fields.
- The solver stores route weights, fast payload templates, fingerprint-to-route mappings, solve history, and extracted patterns.
- The knowledge write path is wrapped in try/except so it never blocks the solve flow.

Effect:
- Later runs can prioritize historically successful routes.
- Winning payload shapes can be reused with less manual work.
- The project gradually becomes more effective as more challenges are solved.

Current status:
- The knowledge base is alive and writing history.
- Route weights and fast payloads are already populated.
- Pattern extraction exists, but the corpus is still sparse, so `patterns` and `fingerprint_route_map` may remain empty until more successful runs accumulate.

### 6. UI observability

Purpose:
- Show the actual internal solve process instead of only the final result.
- Make it obvious when the pipeline is in knowledge matching, scanning, worker racing, or experience writing.

Where it lives:
- `autopnex/web/static/index.html`
- `autopnex/web/static/app.js`
- `autopnex/web/api.py`

How it works:
- The CTF panel shows progress, thinking, logs, and results.
- SSE events stream state transitions, scan summaries, worker assignments, worker summaries, knowledge matches, and experience write events.
- The UI now surfaces the 3-worker parallel activity instead of hiding it behind one generic spinner.

Effect:
- Easier debugging.
- Easier performance tuning.
- Better operator confidence because the system explains what it is doing.

## File-by-file implementation notes

### `autopnex/web/api.py`

Role:
- HTTP entry point for the web UI and CTF solve endpoints.

Important responsibilities:
- Loads and saves runtime settings.
- Validates scan policy and target scope.
- Creates approvals for dangerous capabilities.
- Starts scans and CTF solving jobs.
- Streams solve progress through SSE.
- Builds the autonomous pipeline config.

Why it matters:
- This is the bridge between the browser UI and the solve engine.
- It also defines the runtime defaults that make the pipeline fast and observable.

### `autopnex/web/static/app.js`

Role:
- Browser-side controller for the dashboard and CTF mode.

Important responsibilities:
- Loads settings and capabilities.
- Starts scans and solves.
- Renders streaming events.
- Tracks statistics in localStorage.
- Shows worker summaries, knowledge matches, and experience writes.

Why it matters:
- This is the place where the detailed solve process becomes visible to the user.
- It makes parallel work legible rather than hidden.

### `autopnex/ctf/solve_pipeline.py`

Role:
- Canonical orchestration layer for the CTF solve lifecycle.

Important responsibilities:
- Fast-track direct solving.
- Knowledge matching.
- Parallel route scan.
- Phase transitions between deterministic probing, parallel AI racing, and fallback ReAct.
- Experience write-back after completion.

Why it matters:
- This file is the main control tower for the entire autonomous solve flow.

### `autopnex/ctf/phase2_runner.py`

Role:
- Parallel worker scheduler and racing engine.

Important responsibilities:
- Creates worker sessions.
- Assigns strategies dynamically from scan output.
- Injects shared discoveries.
- Executes tools with timeouts.
- Detects flags and cancels losers.
- Produces worker summaries.

Why it matters:
- This is the main reason the system can explore multiple hypotheses at once.

### `autopnex/ctf/knowledge_schema.py`

Role:
- Unified persistence and migration layer for the knowledge base.

Important responsibilities:
- Loads old and new schemas safely.
- Ensures atomic writes.
- Preserves backward compatibility.
- Migrates legacy records into the unified structure.

Why it matters:
- Prevents schema drift and corrupt writes.
- Makes knowledge accumulation durable.

### `autopnex/ctf/knowledge_learner.py`

Role:
- Pattern extraction and matching.

Important responsibilities:
- Extracts fingerprints, payload family, tech stack, key params, and form signatures.
- Matches current targets against prior successes.
- Records solve history.

Why it matters:
- This is the main mechanism that lets the system improve with use.

### `autopnex/ctf/experience_writer.py`

Role:
- Dual-write experience recorder.

Important responsibilities:
- Updates route weights.
- Stores fast payloads.
- Records fingerprint-to-route mappings.
- Penalizes routes after failures.

Why it matters:
- This is the dynamic tuning layer that changes future route priority.

## Detailed effects of the major mechanisms

### Fast-track direct solve

Best for:
- source visible challenges
- obvious single-vuln CTF pages
- warm-up logic puzzles

Effect on runtime:
- Usually cuts initial exploration dramatically.

Effect on accuracy:
- Strong when the source is explicit and the vuln is clear.
- Risky if detection is too broad, so detection stays conservative.

### Knowledge match

Best for:
- repeated challenge families
- same tech stack with similar fingerprints
- target variants from the same author/source

Effect on runtime:
- Reduces wasted scanning.

Effect on accuracy:
- Better route selection, but depends on prior solve quality.

### Three-worker racing

Best for:
- multi-branch web exploitation
- WAF-heavy or payload-variant tasks
- cases where several attack paths are plausible

Effect on runtime:
- Higher overhead than single-threaded solving.
- Better expected time-to-hit on complex targets.

Effect on accuracy:
- Improves robustness by exploring different hypotheses in parallel.

### Knowledge sedimentation

Best for:
- long-term reuse
- tuning route priorities
- reusing payload templates

Effect on runtime:
- Helps future runs more than current ones.

Effect on accuracy:
- Improves over time as the corpus grows.

## Operational guidance

Recommended decision tree:
1. Try fast identification.
2. If knowledge matches strongly, bias toward that route.
3. If the target is simple and source-visible, use fast-track direct solve.
4. If the target is ambiguous, run parallel route scan.
5. If several routes remain plausible, deploy the 3-worker phase 2 racing layer.
6. Persist the result back into the knowledge base.
7. Expose the whole path in the UI.

## Current assessment

What is working well:
- The pipeline is modular.
- Knowledge persistence is active.
- Parallel worker execution is real and observable.
- The UI now has the hooks to show the detailed process.

What still needs more corpus:
- More successful solves to fill `patterns` and `fingerprint_route_map`.
- More evidence-to-route mapping to make knowledge matching more decisive.

## Summary

AutoPenX is now structured as a layered solve system:
- quick recognition
- knowledge-assisted routing
- deterministic scan
- three-worker parallel reasoning
- experience write-back
- UI telemetry for transparency

That combination makes it both faster to solve and easier to improve over time.
