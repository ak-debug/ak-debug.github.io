# ak-debug.github.io

Source for my personal security blog, built with [Hugo](https://gohugo.io/) and the [PaperMod](https://github.com/adityatelange/hugo-PaperMod) theme. Published at <https://ak-debug.github.io/>.

## Local development

```bash
# clone with the theme submodule
git clone --recurse-submodules https://github.com/ak-debug/ak-debug.github.io.git

# live preview at http://localhost:1313
hugo server
```

## Writing a post

```bash
hugo new posts/my-post/index.md
```

Set `draft: false` in the front matter when it's ready. Pushing to `main` triggers the GitHub Actions workflow in `.github/workflows/hugo.yml`, which builds the site and deploys it to GitHub Pages.
