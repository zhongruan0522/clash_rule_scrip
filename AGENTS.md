# AGENTS.md

## Project overview

- This repository publishes four stable Clash rule-provider links.
- `custom/` contains maintainable input: local overrides and upstream source declarations.
- `dist/` contains generated output for Clash clients. Do not hand-edit it; GitHub Actions refreshes it.
- `1.yml` is a local-only source and is ignored. Never commit or publish it.

## Layout

```text
custom/
  upstream.yml       # upstream provider URL, behavior, and output target
  block.yaml         # custom reject rules
  clean-node.yaml    # custom clean-node rules
  foreign-line.yaml  # custom foreign-line rules
  china-direct.yaml  # custom China-direct rules
dist/               # generated rule packs; workflow-writable output
scripts/build_rules.py
.github/workflows/build-rules.yml
```

## Commands

- Build all rule packs locally: `python3 scripts/build_rules.py`.
- Install the Python dependency: `python3 -m pip install PyYAML==6.0.3`.
- Trigger a cloud build: `gh workflow run build-rules.yml`.
- Check the latest workflow: `gh run list --workflow build-rules.yml --limit 1`.

## Rules and generation

- Keep source changes in `custom/`. Generated changes belong in `dist/`.
- Custom rules use classical rule syntax without a policy suffix, for example `DOMAIN-SUFFIX,example.com`; append options such as `,no-resolve` when needed.
- Valid upstream targets are `REJECT`, `US-ZJ`, `LSDL`, and `DIRECT`.
- Valid upstream behaviors are `classical`, `domain`, and `ipcidr`.
- Preserve category priority: block first, then clean node, foreign line, and China direct.
- Keep `README.md` at exactly five non-empty lines.

## Workflow

- Scheduled builds run at Asia/Shanghai 08:00, 12:00, 16:00, and 20:00.
- Push builds trigger only for the explicit rule inputs, builder script, and workflow file listed in `build-rules.yml`.
- Documentation-only changes must not trigger the build.
- Before upgrading pinned GitHub Actions or Python libraries, check the latest stable release and validate the workflow run.

## Commit messages

Human and coding-agent source commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<optional scope>): <short imperative summary>
```

Use examples such as `feat(rules): add custom overrides`, `fix(workflow): refresh action versions`, or `docs(readme): simplify links`.

The workflow-generated commit for regenerated `dist/` files is intentionally separate and must remain:

```text
fix(rule): 更新规则-YYYYMMDD-HHMM
```

where the timestamp is in Asia/Shanghai.
