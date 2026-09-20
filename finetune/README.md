# Analyst fine-tuning runbook

This directory fine-tunes the local analyst model on **real stored cases**. It
exists because the vanilla `llama3.2:3b` produces valid but shallow analyses:
the corpus and the job below teach it the exact output contract and grounded
citation behaviour using cases that were actually scanned in this lab.

## What is real here

- `corpus/sft.jsonl` — one JSON object per training example. `prompt` is the
  byte-exact prompt the product builds (`analyst.build_prompt` over the stored
  case). `response` is a supervision assessment that passed the product's
  citation validator (`analyst.validate_analysis`) before being written.
- `assessments/*.json` — supervision assessments per case, authored by a human
  or a stronger reviewer. The builder refuses any assessment citing a finding
  or evidence id that is not in the case (`exit 2`), so the corpus cannot be
  poisoned by invented citations.
- `build_corpus.py` — builder/validator. Grow the corpus by scanning more real
  targets, then running:

  ```
  python finetune/build_corpus.py --run <run> --host <ip> \
      --assessment finetune/assessments/<run>-<ip>.json \
      --out finetune/corpus/sft.jsonl
  ```

## Training job (needs CUDA; this laptop has no GPU)

Run on any 8 GB+ CUDA GPU (a free Colab T4 is enough for a 3B QLoRA). CPU-only
fits in 16 GB RAM but costs on the order of a day per epoch — pilot only.

```python
# train_sft.py — run where a GPU exists
import json, torch
from datasets import Dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

rows = [json.loads(l) for l in open("sft.jsonl")]
ds = Dataset.from_list([{"text": r["prompt"] + r["response"] + "<|eot_id|>"} for r in rows])

bnb = BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_quant_type="nf4"
)
tok = AutoTokenizer.from_pretrained("meta-llama/Llama-3.2-3B-Instruct")
model = AutoModelForCausalLM.from_pretrained(
    "meta-llama/Llama-3.2-3B-Instruct", quantization_config=bnb, device_map="auto"
)
cfg = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    task_type="CAUSAL_LM",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
)
trainer = SFTTrainer(
    model=model,
    train_dataset=ds,
    peft_config=cfg,
    args=SFTConfig(
        num_train_epochs=3,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=2e-4,
        logging_steps=1,
        output_dir="analyst-lora",
    ),
)
trainer.train()
trainer.save_model("analyst-lora")
```

Then merge, convert and quantize with llama.cpp:

```
python convert_hf_to_gguf.py merged/ --outfile analyst-f16.gguf
llama-quantize analyst-f16.gguf analyst-q4.gguf q4_K_M
```

## Bring the trained model into the product

```
ollama create vulnassess-analyst -f Modelfile        # FROM ./analyst-q4.gguf
python -m vulnassess ui --model vulnassess-analyst --db data/vulnassess.db --run reallab
```

The UI's Analyze action uses whatever `--model` names, so the trained model
replaces the vanilla baseline with one flag. Everything stays local.

## Honest limits

- Two verified examples exist today (reallab 14-finding case, demo case). That
  is a pilot, not a trained analyst: grow the corpus before judging quality.
- Supervision provenance must be recorded per example in the assessment file's
  sibling provenance note; keep assessments reviewable like any other evidence.
- Scoring stays deterministic. A fine-tuned analyst still cannot write a
  number that is not already in the case; the validator unchanged.
