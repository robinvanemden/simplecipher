## What does this change?

<!-- One or two sentences describing the change -->

## Checklist

- [ ] `make test-all` passes (all 1062+ tests)
- [ ] Android builds: `cd android && ./gradlew assembleDebug`
- [ ] No new permissions added (or justified in PR description)
- [ ] No new dependencies added (or justified in PR description)
- [ ] `crypto_wipe()` called on all new key/secret buffers
- [ ] Documentation updated if user-facing behavior changed
- [ ] No secrets, keys, or message content in log output
