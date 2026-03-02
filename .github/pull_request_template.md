## What does this PR do?

<!-- Brief description of the change -->

## Type of change

<!-- Check all that apply -->

- [ ] 🛡️ New audit rule (`rules/`)
- [ ] ✏️ Improve existing rule (title, description, recommendation, severity)
- [ ] 🚨 Blocklist update (`skills/blocklist/`)
- [ ] 🧱 New firewall pattern (`patterns/`)
- [ ] 🔒 New/updated hardening profile (`profiles/`)
- [ ] 🕵️ Skill scanning rule (`skills/static/`)
- [ ] 🐛 Bug fix
- [ ] 💡 New feature
- [ ] 📄 Documentation only

## For new rules

<!-- Delete this section if not applicable -->

- **Rule ID:** `my_rule_id`
- **Severity:** critical / high / medium / low
- **Config path:** `some.config.path`
- **Auto-fixable:** yes / no
- **CWE:** (if applicable)

## Testing

<!-- How did you verify this works? -->

- [ ] `npm run build` passes
- [ ] Tested with `openclaw-carapace audit --config <test config>`
- [ ] Tested with `openclaw-carapace rules` (rule appears in list)

## Checklist

- [ ] Rule YAML follows the [schema](./rules/schema.yaml)
- [ ] Description explains the _risk_, not just the setting
- [ ] Recommendation tells the user _exactly_ what to change
- [ ] No secrets or personal data in test fixtures
