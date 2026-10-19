# GitHub repository boundary

- The legacy checkout `/home/jaro/Viper-Chat-v1.12.0-backup` has `origin` set to
  `https://github.com/jarohull-ai/Viper-Chat`; it is not a destination for v2.
- The **only** GitHub destination for the new Rust version is the private repository
  `https://github.com/jarohull-ai/Viper-Chat-v2`.
- This checkout is dedicated to v2. Before every push, inspect `git remote -v` and confirm that
  `origin` is exactly `Viper-Chat-v2`. Never push v2 work to `Viper-Chat`.
