# d028 Smith-Waterman — public-dataset evaluation

Evidence that d028 moves the needle on standard public benchmarks, captured as 
the first checkbox in [`project_evaluation_matrix.md`](https://doi.org/10.5281/zenodo.19644135).

Both configurations use the same 26-regex baseline with `d022_semantic_classifier` 
off. The only independent variable is `d028_sequence_alignment` (enabled in treatment, 
disabled in control). `threshold=0.7`, scan result counted as a detection if 
`action in {block, flag}` or `risk_score >= 0.5`, matching `tests/benchmark_public_datasets.py`.

## deepset/prompt-injections (116 samples)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | Speed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Control** (26 detectors, no d028) | 1 | 56 | 0 | 59 | 1.000 | 0.017 | **0.033** | 0.491 | 0.000 | 244/s |
| **Treatment** (27 detectors, with d028) | 14 | 56 | 0 | 46 | 1.000 | 0.233 | **0.378** | 0.603 | 0.000 | 88/s |
| **Delta** | +13 | — | +0 | -13 | — | **+21.66 pp** | — | **+11.20 pp** | +0.00 pp | — |

## leolee99/NotInject (339 samples)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | Speed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Control** (26 detectors, no d028) | 0 | 336 | 3 | 0 | 0.000 | 0.000 | **0.000** | 0.991 | 0.009 | 242/s |
| **Treatment** (27 detectors, with d028) | 0 | 326 | 13 | 0 | 0.000 | 0.000 | **0.000** | 0.962 | 0.038 | 81/s |
| **Delta** | +0 | — | +10 | +0 | — | **+0.00 pp** | — | **-2.95 pp** | +2.95 pp | — |

## microsoft/llmail-inject-challenge (Phase1, 1000 subset) (1000 samples)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | Speed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Control** (26 detectors, no d028) | 978 | 0 | 0 | 22 | 1.000 | 0.978 | **0.989** | 0.978 | 0.000 | 73/s |
| **Treatment** (27 detectors, with d028) | 980 | 0 | 0 | 20 | 1.000 | 0.980 | **0.990** | 0.980 | 0.000 | 4/s |
| **Delta** | +2 | — | +0 | -2 | — | **+0.20 pp** | — | **+0.20 pp** | +0.00 pp | — |

## ai-safety-institute/AgentHarm (352 samples)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | Speed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Control** (26 detectors, no d028) | 44 | 120 | 56 | 132 | 0.440 | 0.250 | **0.319** | 0.466 | 0.318 | 86/s |
| **Treatment** (27 detectors, with d028) | 44 | 120 | 56 | 132 | 0.440 | 0.250 | **0.319** | 0.466 | 0.318 | 24/s |
| **Delta** | +0 | — | +0 | +0 | — | **+0.00 pp** | — | **+0.00 pp** | +0.00 pp | — |

## ethz-spylab/agentdojo (v1.2.1) (132 samples)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | Speed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Control** (26 detectors, no d028) | 17 | 86 | 11 | 18 | 0.607 | 0.486 | **0.540** | 0.780 | 0.113 | 163/s |
| **Treatment** (27 detectors, with d028) | 18 | 83 | 14 | 17 | 0.562 | 0.514 | **0.537** | 0.765 | 0.144 | 33/s |
| **Delta** | +1 | — | +3 | -1 | — | **+2.86 pp** | — | **-1.51 pp** | +3.09 pp | — |

## synthetic/indirect-injection (80 samples)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | Speed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Control** (26 detectors, no d028) | 24 | 50 | 0 | 6 | 1.000 | 0.800 | **0.889** | 0.925 | 0.000 | 71/s |
| **Treatment** (27 detectors, with d028) | 30 | 50 | 0 | 0 | 1.000 | 1.000 | **1.000** | 1.000 | 0.000 | 8/s |
| **Delta** | +6 | — | +0 | -6 | — | **+20.00 pp** | — | **+7.50 pp** | +0.00 pp | — |
