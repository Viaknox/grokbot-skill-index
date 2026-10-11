---
name: pr-text-check
description: Use when checking a pull request diff for a fail-closed miss.
---
A failed git range must block, not pass as an empty diff. Do not treat green CI as the check if that job does not run.
