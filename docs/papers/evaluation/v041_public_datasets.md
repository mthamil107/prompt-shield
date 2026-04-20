# v0.4.1 public-dataset evaluation (d027 + d028 ablation)

Every configuration keeps d022 semantic classifier off; the delta against baseline isolates the contribution of d027 (stylometric) and d028 (Smith-Waterman) individually and jointly.

## deepset/prompt-injections (116 samples, 60 attack + 56 benign)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **baseline** | 1 | 56 | 0 | 59 | 1.000 | 0.017 | **0.033** | 0.491 | 0.000 |
| **plus_d028** | 14 | 56 | 0 | 46 | 1.000 | 0.233 | **0.378** | 0.603 | 0.000 |
| **plus_d027** | 1 | 56 | 0 | 59 | 1.000 | 0.017 | **0.033** | 0.491 | 0.000 |
| **plus_d027_d028** | 14 | 56 | 0 | 46 | 1.000 | 0.233 | **0.378** | 0.603 | 0.000 |

## leolee99/NotInject (339 samples, 0 attack + 339 benign)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **baseline** | 0 | 336 | 3 | 0 | 0.000 | 0.000 | **0.000** | 0.991 | 0.009 |
| **plus_d028** | 0 | 326 | 13 | 0 | 0.000 | 0.000 | **0.000** | 0.962 | 0.038 |
| **plus_d027** | 0 | 336 | 3 | 0 | 0.000 | 0.000 | **0.000** | 0.991 | 0.009 |
| **plus_d027_d028** | 0 | 326 | 13 | 0 | 0.000 | 0.000 | **0.000** | 0.962 | 0.038 |

## microsoft/llmail-inject-challenge (Phase1, 1000 subset) (1000 samples, 1000 attack + 0 benign)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **baseline** | 978 | 0 | 0 | 22 | 1.000 | 0.978 | **0.989** | 0.978 | 0.000 |
| **plus_d028** | 980 | 0 | 0 | 20 | 1.000 | 0.980 | **0.990** | 0.980 | 0.000 |
| **plus_d027** | 978 | 0 | 0 | 22 | 1.000 | 0.978 | **0.989** | 0.978 | 0.000 |
| **plus_d027_d028** | 980 | 0 | 0 | 20 | 1.000 | 0.980 | **0.990** | 0.980 | 0.000 |

## ai-safety-institute/AgentHarm (352 samples, 176 attack + 176 benign)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **baseline** | 44 | 120 | 56 | 132 | 0.440 | 0.250 | **0.319** | 0.466 | 0.318 |
| **plus_d028** | 44 | 120 | 56 | 132 | 0.440 | 0.250 | **0.319** | 0.466 | 0.318 |
| **plus_d027** | 44 | 120 | 56 | 132 | 0.440 | 0.250 | **0.319** | 0.466 | 0.318 |
| **plus_d027_d028** | 44 | 120 | 56 | 132 | 0.440 | 0.250 | **0.319** | 0.466 | 0.318 |

## ethz-spylab/agentdojo (v1.2.1) (132 samples, 35 attack + 97 benign)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **baseline** | 17 | 86 | 11 | 18 | 0.607 | 0.486 | **0.540** | 0.780 | 0.113 |
| **plus_d028** | 18 | 83 | 14 | 17 | 0.562 | 0.514 | **0.537** | 0.765 | 0.144 |
| **plus_d027** | 17 | 86 | 11 | 18 | 0.607 | 0.486 | **0.540** | 0.780 | 0.113 |
| **plus_d027_d028** | 18 | 83 | 14 | 17 | 0.562 | 0.514 | **0.537** | 0.765 | 0.144 |

## synthetic/indirect-injection (80 samples, 30 attack + 50 benign)

| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **baseline** | 24 | 50 | 0 | 6 | 1.000 | 0.800 | **0.889** | 0.925 | 0.000 |
| **plus_d028** | 30 | 50 | 0 | 0 | 1.000 | 1.000 | **1.000** | 1.000 | 0.000 |
| **plus_d027** | 30 | 50 | 0 | 0 | 1.000 | 1.000 | **1.000** | 1.000 | 0.000 |
| **plus_d027_d028** | 30 | 50 | 0 | 0 | 1.000 | 1.000 | **1.000** | 1.000 | 0.000 |
