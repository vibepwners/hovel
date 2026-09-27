# Error recovery

When a Hovel action fails:

1. Preserve and report the exact structured error.
2. Refresh `hovel_operator_identity`, `hovel_workspace_snapshot`, and catalog
   state relevant to the failed action.
3. Distinguish missing context, invalid configuration, stale state, unavailable
   capabilities, and unmet approval policy.
4. Correct only the failed prerequisite, then revalidate.
5. If a throw plan changed, discard assumptions about its old confirmation and
   review and confirm the replacement plan.

Do not retry destructive calls blindly. Do not replace typed calls with
`hovel_command_run` merely because a typed call returned a policy error.

A failed catalog fetch does not establish that installed modules disappeared.
Preserve the last usable context, surface the error, and retry discovery only when
appropriate. A closed session is not permission to recreate its owner or rerun the
operation. Keep received command output distinct from acknowledged persisted
artifacts; missing uncollected output after owner failure is not evidence of
successful collection. Report the exact runtime revision and validation scope
when deciding whether an upstream fix applies to the installed integration.
