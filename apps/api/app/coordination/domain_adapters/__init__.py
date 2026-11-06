"""M38 — domain adapters: wrap another agent's domain module (READ-ONLY) into
the coordination gateway handler contract ``handler(payload, task) ->
{result, provenance}``. Adapters never modify the domain package."""
