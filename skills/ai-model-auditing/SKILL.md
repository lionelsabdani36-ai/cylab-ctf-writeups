---
name: ai-model-auditing
description: "Audit AI models for hallucinations and boundary flaws."
version: 1.1.0
author: White Jack, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [ai-security, model-auditing, hallucinations, perceptron-analysis, boundary-testing]
    related_skills: [sensitive-prompt-paraphraser, reverse-engineering]
---

# AI Model Auditing & Adversarial Testing Skill

Operational methodology for auditing neural networks, linear classifiers, and LLM generative pipelines against hallucinations, training data bias, and non-linear boundary failures.

## When to Use

- Auditing AI model decision boundaries (Perceptrons, Multi-Layer Perceptrons, Support Vector Machines).
- Testing linear separability limits on multi-class and non-linear datasets (XOR, XNOR, radial patterns).
- Verifying LLM outputs against synthetic hallucinations, fake citations, and stealth code mutations.
- Implementing human-in-the-loop verification heuristics for mission-critical AI pipelines.

## Don't Use For

- Routine prompt engineering with no safety or verification requirements.
- Standard machine learning model training without security evaluation.

## Core Auditing Principles

### 1. Perceptron Linear Separability Boundary
Single-layer perceptrons update weights using the classic Hebbian / delta rule:
$$\Delta w = \eta (y - \hat{y}) x$$
- **Linear Separability Invariant**: A single hyperplane cannot separate non-linear distributions (XOR, concentric circles).
- **Audit Target**: Probe learning rate sensitivity ($\eta$) and epoch limits to identify convergence bounds and classification ceilings.

### 2. Generative Hallucination Auditing
LLM outputs often display false authority on citations, scientific figures, and minor code modifications (e.g. silent `+ 1` arithmetic injection).
- **Citation Verification**: Cross-reference authors, publication years, and DOIs independently.
- **AST Code Inspection**: Parse generated code into an Abstract Syntax Tree to verify mathematical invariants before execution.

### 3. Multidimensional Parity & Higher-Order Non-Linearity
Extending parity beyond 2D (XOR) into 3D space ($\mathbb{R}^3$ vertices of a cube, $x_1 \oplus x_2 \oplus x_3$):
- **Minsky-Papert Bound**: A single hyperplane $\sum w_i x_i + b = 0$ can at most classify $6/8$ ($75\%$) points of 3-bit parity correctly.
- **Audit Target**: Sweep $\eta$ across $[0.02, 2.0]$ under bounded step budgets ($k \le 16$) to verify that models reach the theoretical $75\%$ ceiling without diverging into periodic oscillations.

### 4. Dimensionality Lifting & Feature Invariance (Kernel Basis)
When datasets are non-separable in lower dimensions (e.g. overlapping 1D intervals):
- **Feature Elevation**: Adding an orthogonal coordinate ($y = \phi(x)$) or polynomial projection transforms non-separable point sets into linearly separable configurations in higher-dimensional space.
- **Audit Heuristic**: Probe decision hyperplane parameters ($w, b$) to verify that separating hyperplanes remain robust under coordinate translation and scaling.
