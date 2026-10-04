# Attacks

`AbstractAttack.generate(goal, context)` returns a raw payload. The runner renders that payload into a scenario's templates. `update(score)` receives binary success feedback for valid optimization trials. Adaptive strategies expose `best_payload`.

::: gitinject.attacks.base.AbstractAttack

`StaticAttack` accepts exactly one of `payload` or `payload_file`. `load_attack("static", payload=...)` treats an existing file path as a file, while direct constructor arguments make the choice explicit. Static attacks do not track a best payload.

::: gitinject.attacks.static.StaticAttack
    options:
      members: [__init__, generate]

`AutoInjectAttack` maintains payload/reward experience in memory and uses an OpenAI client for generation. It requires `OPENAI_API_KEY` at construction. Its victim model name conditions generation; actual victim execution belongs to the runner. See [model routing limits](../guides/attacks.md#current-model-routing).

::: gitinject.attacks.autoinject.AutoInjectAttack
    options:
      members: [__init__, generate, update, best_payload]

::: gitinject.attacks.load_attack
