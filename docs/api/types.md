# Types

These string enums define vocabulary used by workflows and scenarios. Enum membership does not guarantee a default event trigger implementation; see [events](../reference/events.md). Workflow metadata is read as ordinary JSON and is not automatically validated against these enums.

::: src.benchmark.utils.types
    options:
      members: [ScenarioType, GitHubEvent, WorkflowCategory, AIProvider, DefenseLevel]
