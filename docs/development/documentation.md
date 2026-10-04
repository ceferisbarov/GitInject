# Build and publish the docs

The site uses [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/), with a guide/concept/API layout inspired by [AgentDojo](https://agentdojo.spylab.ai/). Its canonical URL is **https://ceferisbarov.github.io/GitInject/**.

## Build locally

```bash
uv sync --locked --only-group docs
uv run --no-sync mkdocs build --strict
uv run --no-sync mkdocs serve
```

`site/` contains the built HTML and is gitignored. A documentation-only sync omits benchmark dependencies; run `uv sync --locked` again before working on the benchmark.

The build needs no GitHub/provider credentials. mkdocstrings extracts APIs statically with inspection disabled. `docs/_generate.py` reads workflow JSON and scenario ASTs to produce catalogs without executing scenarios. mkdocs-click imports only the CLI's Click declarations.

## Maintain the site

Navigation, canonical URL, theme, plugins, and Markdown extensions are configured in `mkdocs.yml`. Write pages under `docs/` and add them to navigation. API pages use `::: gitinject...` directives, with explanatory prose for behavior not captured in source docstrings.

Generated catalogs are virtual build files; edit workflow metadata or scenario declarations rather than a catalog output. They link to source definitions in the repository. Dynamic declarations may appear as `dynamic`; the CLI listing resolves them by loading trusted scenario code.

Keep future proposals and uncertain historical material under `plans/`, outside the published site. Publish current, implemented behavior in the docs.

## GitHub Pages

The repository's `.github/workflows/docs.yml` builds documentation for pull requests and pushes to `master`. Successful `master` builds upload a Pages artifact and deploy it using GitHub's Pages Actions. A manual workflow dispatch on `master` also deploys.

In the repository's **Settings → Pages**, set **Build and deployment → Source** to **GitHub Actions**. The workflow uses the `github-pages` environment and the `pages: write` / `id-token: write` permissions required by [GitHub's custom Pages workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

The `site_url` includes the `/GitInject/` project path. Internal page links are relative so navigation and assets work under that path. A custom-domain `CNAME` file is unnecessary for this URL.

Pull requests build and validate without deploying. The workflow installs only the locked documentation dependency group and does not run experiments or need benchmark secrets.
