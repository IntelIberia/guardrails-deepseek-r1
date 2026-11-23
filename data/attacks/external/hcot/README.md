---
license: cc-by-nc-sa-4.0
dataset_info:
  features:
  - name: Category
    dtype: string
  - name: Goal
    dtype: string
  - name: Request
    dtype: string
  - name: H_CoT
    dtype: string
  - name: Full_Input (H-CoT + Request)
    dtype: string
  splits:
  - name: train
    num_bytes: 659698
    num_examples: 50
  download_size: 208005
  dataset_size: 659698
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train-*
---
