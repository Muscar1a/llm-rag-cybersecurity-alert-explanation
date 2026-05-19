## Changes on chunking embedding
1. Use smaller bacth_size = 64 (original 512)
2. Load model on fp16
3. torch.empty_cache() after each kind of source